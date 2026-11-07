"""
recovery_bundle.py - a dated, versioned bundle that can rebuild Marty, and a drill that proves it.

    py tools/recovery_bundle.py build --out <zip>        collect the recovery set into one zip
    py tools/recovery_bundle.py drill <zip>              restore into a temp folder, verify, run its selftests
    py tools/recovery_bundle.py prune <dir> --keep 8     keep the newest N bundles in a folder
    py tools/recovery_bundle.py selftest                 offline, temp folders only

Why (audit finding 12, 2026-09-23): backup-marty.ps1 mirrored the vault, the handoff
ciphertext and three config files with robocopy /MIR. None of the custom code was in it
(tools, dashboard, hands, the voice-line changes), nor AGENTS.md, the tool scope, the
Modelfiles or any record of the dependencies, and /MIR keeps no history: a note deleted or
wrecked on the PC was deleted or wrecked on the NAS at the next run. Nobody had ever
restored from it.

What goes in: the code and config under my-agent (tools, dashboard, hands, backtalk,
ai-visualizer, fullstack-agent, deals, ai-memory-vault, .claude, CLAUDE.md, AGENTS.md,
backup-marty.ps1; tools/ carries tools/marty_tools.scope.json and the Modelfiles), the
whole vault, and three generated files:
MANIFEST.json (every file's sha256), DEPENDENCIES.txt (Python packages, Ollama models and
digests, the scanner binaries' hashes, the git commits of the upstream repos) and RESTORE.md.

What stays out, deliberately: private data that must not sit on a LAN-readable share in
plaintext (uploads/ with the files attached in the dashboard, any chat store under dashboard/:
chats/ and test copies such as test-chats/, private/, logs, the hands log, the dashboard's
device-token hashes and activity feed), derived or re-downloadable bulk (the vault index in
vault-index/, tools/bin's checksum-verified binaries, recorded in DEPENDENCIES.txt instead),
dead-copy deploy kits (.rollback-*, .newcode-* and .bak-* folders: backups taken before a
deploy and snapshots of code that went live), and anything whose contents are unknown. How the
private data should be recoverable is Lukas's decision; until then it lives only on this PC.

Staging kits (.staged-* folders) ARE carried, minus the private files above: they hold work
that exists nowhere else (unshipped builds, the browser regression suites, the deploy and
rollback scripts). A dead-copy kit is not guaranteed to be a duplicate either, so every build
hashes what those rules left out and lists each file outside a .rollback-* folder whose bytes
match nothing in the bundle and nothing in a .rollback-* backup: in MANIFEST.json
("skipped_sole_copies" and "warnings"), at the top of the bundle's RESTORE.md, in its printed
result, and as one line per build in my-agent/status/recovery-bundle.txt ("WARNING ..." or
"ok ...", newest last). That list is loud, never a refusal: a stray kit, or a failure of the
check or of the status line, must not stop the weekly backup.

The build refuses to produce a bundle if any included text file looks like it holds a live
credential; it names the file and line, never the value. A regex is a tripwire, not a
secret detector.
"""

import argparse
import bisect
import contextlib
import datetime as dt
import fnmatch
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
VAULT = pathlib.Path("C:/Users/{{WIN_USER}}/marty-vault")
PY312 = r"C:\Users\{{WIN_USER}}\AppData\Local\Programs\Python\Python312\python.exe"

AGENT_DIRS = ["tools", "dashboard", "hands", "backtalk", "ai-visualizer", "fullstack-agent", "deals",
              "ai-memory-vault", ".claude"]
AGENT_FILES = ["CLAUDE.md", "AGENTS.md", "backup-marty.ps1"]
SKIP_DIRS = {".venv", "venv", ".git", "node_modules", "__pycache__", "logs", ".pytest_cache", ".mypy_cache"}
# Any folder under dashboard/ named chats or *-chats is a chat store (the live one, staged and test
# copies such as .staged-mj/test-chats): private, inside a bundled folder, so _skipped() names it.
# Dead-copy deploy kits are skipped at any depth in any bundled folder (2026-09-26, Lukas "Yes to
# both"): .rollback-* (backups taken before a deploy), .newcode-* (snapshots of code that went live)
# and .bak-*. Staging kits (.staged-*) are NOT skipped: they hold sole copies (unshipped builds, the
# browser suites, the deploy scripts); their private files go by the name and chat-store rules.
# uploads/, private/, vault-index/ and jr/ (Marty Jr.'s encrypted history) sit outside AGENT_DIRS
# and are never collected at all.
KIT_PREFIXES = (".bak-", ".rollback-", ".newcode-")
KIT_WHY = "dead-copy kit folder"
SKIP_PREFIXES = ["tools/bin/", "tools/freezer-frames/", "tools/screenshots/", "dashboard/Claude outputs/"]
SKIP_NAMES = ["activity.jsonl", "dashboard-devices.jsonl", "dashboard-devices.lock", "passkeys.jsonl",
              "passkeys-user.json", "hands-log.jsonl", "grant.json", ".backtalk_session", ".voice_*", "*.bak*", "*.pyc",
              "*.log", "*.tmp", "*.lock.tmp"]
# Whole-path patterns: Talk's temp audio (a crashed turn can leave one behind) never reaches the NAS.
SKIP_GLOBS = ["*/runtime/talk/talk-*"]
VAULT_SKIP = [".trash/", ".obsidian/workspace*"]
MAX_FILE = 10 * 1024 * 1024
BUNDLE_RE = re.compile(r"^marty-recovery-\d{4}-\d{2}-\d{2}-\d{4}\.zip$")

# Widened 2026-09-26 after the skeptic: OpenAI project / service-account / admin keys (their bodies carry _ and
# -, which the old pattern missed), GitHub fine-grained tokens, Hugging Face, Tailscale, and JSON / .env style
# assignments ("token": "...", "access_token": "...", OPENAI_API_KEY="..."). Every shape has a must-trip and a
# must-not-trip case in selftest(), built at run time: this file is bundled, so selftest() also scans itself.
# The assignment tail both assignment forms share: an optional closing quote on the name, = or :, then a quoted
# value of 20+ characters with no quote or space that is not WHOLLY a reference (see below).
_QUOTED_VALUE = (r"[\"']?\s*[:=]\s*[\"']"
                 r"(?!(?:\$\{\w+\}|\{\{[^}\"'\s]+\}\}|%\w+%|<[^>\"'\s]+>)[\"'])[^\"'\s]{20,}[\"']")
SECRET_PATTERNS = [
    ("an Anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("an OpenRouter key", re.compile(r"sk-or-v1-[0-9a-f]{20,}")),
    ("an OpenAI-style key", re.compile(r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{32,})")),
    ("an xAI key", re.compile(r"\bxai-[A-Za-z0-9]{30,}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("a GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("a GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9]{30,}")),
    ("a Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("a Tailscale key", re.compile(r"\btskey-(?:[a-z]+-)?[A-Za-z0-9]{6,}-[A-Za-z0-9]{16,}|\btskey-[A-Za-z0-9]{30,}")),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{40,}")),
    # key = "v", "key": "v" (JSON) or KEY="v" (.env). Prefixed names (access_token, client_secret, OPENAI_API_KEY)
    # trip on their last part: the lookbehind only refuses a letter or digit before it, so _ and - are fine. It
    # replaced a prefix group, (?:[a-z0-9]+[_-])*, that went quadratic on runs like "a-a-a-..." (skeptic,
    # 2026-09-26: 80 KB took 97.8 s); selftest() times adversarial text. A value that is WHOLLY a reference
    # (${VAR}, {{var}}, %VAR%, <placeholder>, closing quote right after) does not count; a real value that only
    # starts with $, %, { or < still does. The reference shapes stop at quotes and spaces, so they stay inside
    # the value and cost nothing extra.
    ("a quoted secret assignment", re.compile(
        r"(?i)(?<![a-z0-9])(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|token)" + _QUOTED_VALUE)),
    # camelCase names (accessToken, clientSecret, dbPassword, openaiApiKey), which the lookbehind above rejects
    # for the letter in front: a lowercase-led identifier whose LAST part is one of these, case-sensitive, so
    # tokenizer, passwordHint and csrfTokenName do not count. Linear: it can only start where no letter or
    # digit precedes, and the one backtrack runs over a single identifier (selftest() times 2 MB of one).
    ("a quoted secret assignment", re.compile(
        r"(?<![A-Za-z0-9])[a-z][A-Za-z0-9]*(?:SecretKey|ApiKey|Secret|Password|Passwd|Token)" + _QUOTED_VALUE)),
]


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _skipped(rel):
    """Why a my-agent path stays out of the bundle, or None."""
    parts = rel.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return "excluded folder"
    if any(rel.startswith(p) for p in SKIP_PREFIXES) or (
            parts[0] == "dashboard" and any(p == "chats" or p.endswith("-chats") for p in parts[1:-1])):
        return "excluded folder"
    if any(fnmatch.fnmatch(parts[-1], pat) for pat in SKIP_NAMES) or any(fnmatch.fnmatch(rel, g) for g in SKIP_GLOBS):
        return "excluded file"
    if any(p.startswith(KIT_PREFIXES) for p in parts[:-1]):
        return KIT_WHY                                  # checked last: sole_copies() looks only at these
    return None


def collect(agent=AGENT, vault=VAULT):
    """[(archive name, source path)] plus [(path, why)] for what was left out."""
    take, skipped = [], []
    for rel in AGENT_FILES:
        p = agent / rel
        if p.is_file():
            take.append(("my-agent/" + rel, p))
    for d in AGENT_DIRS:
        base = agent / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(agent).as_posix()
            why = _skipped(rel)
            if why is None and p.stat().st_size > MAX_FILE:
                why = f"larger than {MAX_FILE // (1024 * 1024)} MB"
            if why:
                skipped.append((rel, why))
            else:
                take.append(("my-agent/" + rel, p))
    if vault.is_dir():
        for p in sorted(vault.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(vault).as_posix()
            if any(rel.startswith(v.rstrip("*")) if v.endswith("/") else fnmatch.fnmatch(rel, v) for v in VAULT_SKIP):
                skipped.append(("marty-vault/" + rel, "excluded vault file"))
                continue
            take.append(("marty-vault/" + rel, p))
    return take, skipped


def scan_text(text):
    """[(line number, what it looked like)] for one text, values never included. Newline offsets are found
    once and each hit's line looked up by bisect (counting from the top per hit was quadratic: a 2 MB file
    with 60,606 hits took 18.2 s, skeptic 2026-09-26)."""
    hits, newlines = [], None
    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            if newlines is None:
                newlines = [n.start() for n in re.finditer("\n", text)]
            hits.append((bisect.bisect_left(newlines, m.start()) + 1, label))
    return hits


def secret_hits(take):
    """[(archive name, line number, what it looked like)], values never included."""
    hits = []
    for name, p in take:
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue                                    # binary
        hits += [(name, ln, what) for ln, what in scan_text(raw.decode("utf-8", errors="ignore"))]
    return hits


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        return (r.stdout or "").strip() or (r.stderr or "").strip()
    except Exception as e:
        return f"(unavailable: {type(e).__name__})"


def dependencies(agent=AGENT):
    lines = [f"# Dependencies recorded {dt.datetime.now().isoformat(timespec='seconds')}",
             f"platform: {platform.platform()}", f"python (this build): {sys.version.split()[0]}", ""]
    lines += ["## Python 3.12 packages (pip freeze)", _run([PY312, "-m", "pip", "freeze"]), ""]
    for repo in ("backtalk", "ai-visualizer"):
        d = agent / repo
        if (d / ".git").exists():
            lines.append(f"## {repo}: git {_run(['git', '-C', str(d), 'rev-parse', 'HEAD'])} "
                         f"from {_run(['git', '-C', str(d), 'remote', 'get-url', 'origin'])}; "
                         f"local changes: {_run(['git', '-C', str(d), 'status', '--porcelain']) or 'none'}")
    lines.append("(backtalk's own locked dependencies are in its uv.lock, which is in the bundle)\n")
    lines.append("## Ollama models (name, digest, size)")
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10) as r:
            for m in json.loads(r.read().decode("utf-8")).get("models", []):
                lines.append(f"{m.get('name')}  {m.get('digest')}  {int(m.get('size', 0)) / 1e9:.1f} GB")
    except Exception as e:
        lines.append(f"(Ollama not answering: {type(e).__name__})")
    lines.append("(model recipes are tools/Modelfile.*, in the bundle; weights re-download by tag)\n")
    lines.append("## tools/bin binaries (not bundled; re-download and compare)")
    for p in sorted((agent / "tools" / "bin").glob("*")):
        if p.is_file() and p.suffix.lower() == ".exe":
            lines.append(f"{p.name}  {p.stat().st_size} bytes  sha256 {_sha256(p)}")
    return "\n".join(lines) + "\n"


RESTORE_MD = """# Restoring Marty from this bundle

1. Unzip. `my-agent/` goes to C:/Users/{{WIN_USER}}/my-agent, `marty-vault/` to C:/Users/{{WIN_USER}}/marty-vault.
2. Install Python 3.12 and the packages in DEPENDENCIES.txt (`pip install <name>==<version>` for the ones you need).
3. backtalk and ai-visualizer: `git clone` their origin at the recorded commit, lay the bundled files over them,
   then `uv sync` in backtalk (its uv.lock is here).
4. Ollama: install, `ollama pull` each base model in DEPENDENCIES.txt, then rebuild the custom models from
   tools/Modelfile.* (`ollama create marty-local -f tools/Modelfile.marty-local`). Compare the digests.
5. tools/bin: re-download the scanner binaries and check them against the sha256 values in DEPENDENCIES.txt.
6. Keys are NOT in this bundle. Put them back into Windows Credential Manager with tools/cred.py.
7. NOT in this bundle (private, kept on the PC only): uploads/ (files attached in the dashboard), dashboard/chats/
   (chat history) and test chat stores such as test-chats/, private/, logs, the hands log, the dashboard's device
   tokens (enrol devices again with dashboard/setup_dashboard_auth.py). The vault index is derived:
   `python tools/vault_index.py build` recreates it. Also left out: .rollback-*, .newcode-* and .bak-* folders
   (pre-deploy backups and snapshots of code that went live; older bundles are the history). MANIFEST.json's
   "skipped_sole_copies" names any .newcode-*/.bak-* file whose bytes are neither here nor in a .rollback-*
   backup; it should be empty (when it is not, a WARNING heads this file).
   Staging kits (.staged-* folders) ARE here, minus the private files above.
8. Prove it: `python tools/recovery_bundle.py drill <this zip>` restores into a temp folder, checks every file
   against MANIFEST.json and runs the restored code's own selftests.
"""


# One line per build, newest last, under the agent folder (never bundled: status/ is not in AGENT_DIRS), so the
# board or Marty at boot can read the current state from the last line: "WARNING ..." or "ok ...". Same
# "[YYYY-MM-DD HH:MM:SS] message" shape as logs/backup-marty.log.
STATUS_NOTE = pathlib.PurePosixPath("status") / "recovery-bundle.txt"


def warnings_for(sole, sole_error=None):
    """The sole-copy warning as plain sentences ([] when there is nothing to warn about)."""
    if sole_error:
        return [f"The sole-copy check could not run ({sole_error}), so nothing left out was compared."]
    if sole:
        return [f"{len(sole)} file(s) left out in a .newcode-* or .bak-* folder exist nowhere else (not in this bundle, "
                "not in a .rollback-* backup). Each is still on the PC: move it somewhere the bundle carries, or delete "
                "the kit if it is truly dead, and the next build stops warning. See MANIFEST.json skipped_sole_copies."]
    return []


def restore_md(sole, sole_error=None):
    """RESTORE.md, with the sole-copy warning on top when there is one, so whoever restores sees it first."""
    warn = warnings_for(sole, sole_error)
    if not warn:
        return RESTORE_MD
    lines = ["# WARNING: files left out of this bundle that exist nowhere else", ""] + warn + [""]
    lines += [f"- {rel}" for rel in sole] + ([""] if sole else [])
    return "\n".join(lines) + "\n" + RESTORE_MD


def status_note(agent, bundle, sole, sole_error=None, now=None):
    """Append this build's one-line summary to <agent>/status/recovery-bundle.txt. A warning channel only:
    returns (path, error or None) and never raises, so it can never stop the weekly backup."""
    path = pathlib.Path(agent) / STATUS_NOTE
    stamp = f"[{(now or dt.datetime.now()):%Y-%m-%d %H:%M:%S}]"
    if sole_error:
        line = f"{stamp} WARNING {bundle}: the sole-copy check could not run ({sole_error})"
    elif sole:
        more = f" and {len(sole) - 3} more" if len(sole) > 3 else ""
        line = (f"{stamp} WARNING {bundle}: {len(sole)} file(s) left out exist nowhere else: "
                f"{', '.join(sole[:3])}{more} (MANIFEST.json skipped_sole_copies)")
    else:
        line = f"{stamp} ok {bundle}: no sole copies left out"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line.replace("\n", " ") + "\n")
        return str(path), None
    except Exception as e:
        return str(path), f"{type(e).__name__}: {e}"


def sole_copies(take, skipped, agent=AGENT, digests=None):
    """What a dead-copy kit rule left out that exists nowhere else: files skipped ONLY for sitting in a
    .newcode-* or .bak-* folder whose bytes match no file in the bundle and no file in a .rollback-* folder
    (a pre-deploy backup is dead by definition, and so is a byte-identical copy of one). Compared by
    sha256, never by name or prefix."""
    in_rollback = lambda rel: any(p.startswith(".rollback-") for p in rel.split("/")[:-1])
    dead = [rel for rel, why in skipped if why == KIT_WHY]
    kit = [rel for rel in dead if not in_rollback(rel)]
    if not kit:
        return []
    have = set(digests.values()) if digests else {_sha256(p) for _, p in take}
    have |= {_sha256(agent / rel) for rel in dead if in_rollback(rel)}
    return [rel for rel in kit if _sha256(agent / rel) not in have]


def build(out, agent=AGENT, vault=VAULT, deps=True):
    take, skipped = collect(agent, vault)
    hits = secret_hits(take)
    if hits:
        raise SystemExit("REFUSED: these files look like they hold a live credential, so no bundle was written:\n"
                         + "\n".join(f"  {n}:{ln}  ({what})" for n, ln, what in hits[:20]))
    digests = {name: _sha256(p) for name, p in take}
    try:                                              # a warning, never a refusal: a failed check is reported
        sole, sole_error = sole_copies(take, skipped, agent, digests), None
    except Exception as e:
        sole, sole_error = [], f"{type(e).__name__}: {e}"
    manifest = {"created": dt.datetime.now().isoformat(timespec="seconds"), "host": platform.node(),
                "files": [], "skipped": [{"path": r, "why": w} for r, w in skipped],
                "skipped_sole_copies": sole, "warnings": warnings_for(sole, sole_error)}
    out = pathlib.Path(out)
    tmp = out.with_name(out.name + ".partial")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, p in take:
            z.write(p, name)
            manifest["files"].append({"path": name, "size": p.stat().st_size, "sha256": digests[name]})
        z.writestr("DEPENDENCIES.txt", dependencies(agent) if deps else "(not recorded in this test build)\n")
        z.writestr("RESTORE.md", restore_md(sole, sole_error))
        z.writestr("MANIFEST.json", json.dumps(manifest, indent=1))
    os.replace(tmp, out)                              # a crash mid-build never leaves a half zip under the real name
    # Loud, on stdout (the backup log records this line; stderr would abort backup-marty.ps1 under PS 5.1).
    result = {"bundle": str(out), "files": len(manifest["files"]), "skipped": len(skipped),
              "bytes": out.stat().st_size}
    if sole:
        result["WARNING_sole_copies_skipped"] = {"count": len(sole), "first": sole[:5],
                                                 "see": "MANIFEST.json skipped_sole_copies"}
    if sole_error:
        result["WARNING_sole_copy_check_failed"] = sole_error
    result["status_note"], note_error = status_note(agent, out.name, sole, sole_error)
    if note_error:
        result["status_note_error"] = note_error
    return result


def cli_build(out, agent=AGENT, vault=VAULT, deps=True):
    """The `build` command. Everything goes to STDOUT, then the exit code: backup-marty.ps1 captures stdout
    only ($out = & $py $rb build ...) and logs "failed (exit N): <that output>", so a refusal written only
    to stderr left Sunday's log naming no file. Success: the result as one JSON line, 0. Refused: the
    REFUSED list (file:line:label, never a value), 1. Anything else: one FAILED line, 1 (traceback to stderr,
    which the task does not redirect, for a person at a terminal)."""
    try:
        print(json.dumps(build(out, agent, vault, deps)), flush=True)
        return 0
    except SystemExit as e:                           # build()'s refusal carries its message
        print(e.code if isinstance(e.code, str) else f"REFUSED (exit {e.code})", flush=True)
        return 1
    except Exception as e:
        print(f"FAILED: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        return 1


SELFTESTS = [["tools/vault_index.py", "selftest"], ["tools/switchboard.py", "selftest"],
             ["tools/marty_tools.py", "selftest"], ["tools/media.py", "selftest"],
             ["hands/hands.py", "selftest"], ["dashboard/intake.py", "selftest"]]


def drill(bundle, run_selftests=True, python=PY312):
    """Restore into a temp folder and prove it: zip integrity, every file against MANIFEST.json,
    then the restored code's own offline selftests. Touches nothing outside the temp folder."""
    report = {"bundle": str(bundle), "problems": [], "selftests": {}}
    work = pathlib.Path(tempfile.mkdtemp(prefix="marty-restore-drill-"))
    try:
        with zipfile.ZipFile(bundle) as z:
            bad = z.testzip()
            if bad:
                report["problems"].append(f"corrupt member {bad}")
            z.extractall(work)
        manifest = json.loads((work / "MANIFEST.json").read_text(encoding="utf-8"))
        for f in manifest["files"]:
            p = work / f["path"]
            if not p.is_file():
                report["problems"].append(f"missing {f['path']}")
            elif _sha256(p) != f["sha256"]:
                report["problems"].append(f"checksum mismatch {f['path']}")
        report["files_verified"] = len(manifest["files"])
        if run_selftests:
            root = work / "my-agent"
            for cmd in SELFTESTS:
                if not (root / cmd[0]).is_file():
                    report["selftests"][cmd[0]] = "missing"
                    report["problems"].append(f"selftest script missing {cmd[0]}")
                    continue
                try:
                    r = subprocess.run([python] + [str(root / cmd[0])] + cmd[1:], cwd=str(root),
                                       capture_output=True, text=True, timeout=600, encoding="utf-8", errors="replace")
                    last = [ln for ln in (r.stdout or "").splitlines() if ln.strip()][-1:] or ["(no output)"]
                    report["selftests"][cmd[0]] = ("passed: " if r.returncode == 0 else "FAILED: ") + last[0].strip()
                    if r.returncode != 0:
                        report["problems"].append(f"selftest failed {cmd[0]}")
                except subprocess.TimeoutExpired:
                    report["selftests"][cmd[0]] = "FAILED: timed out"
                    report["problems"].append(f"selftest timed out {cmd[0]}")
    except Exception as e:
        report["problems"].append(f"{type(e).__name__}: {e}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    report["ok"] = not report["problems"]
    return report


def prune(folder, keep):
    """Delete all but the newest `keep` bundles in `folder`. Only files named exactly like this
    tool names its bundles are ever considered; anything else in the folder is left alone."""
    folder = pathlib.Path(folder)
    mine = sorted(p for p in folder.iterdir() if p.is_file() and BUNDLE_RE.match(p.name))
    gone = mine[:-keep] if keep > 0 and len(mine) > keep else []
    for p in gone:
        p.unlink()
    return [p.name for p in gone]


def bundle_name(now=None):
    return f"marty-recovery-{(now or dt.datetime.now()):%Y-%m-%d-%H%M}.zip"


# ---------------------------------------------------------------- selftest

def selftest():
    fails = []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        agent, vault = td / "my-agent", td / "marty-vault"
        files = {
            "CLAUDE.md": "boot", "AGENTS.md": "boot", "tools/switchboard.py": "print('x')\n",
            "tools/Modelfile.marty-local": "FROM base\n", "tools/marty_tools.scope.json": "{}",
            "tools/bin/tool.exe": "MZ binary",
            "tools/freezer-frames/f1.jpg": "jpeg", "dashboard/server.py": "code\n",
            "dashboard/activity.jsonl": "{}\n", "dashboard/dashboard-devices.jsonl": "{}\n",
            "dashboard/server.py.bak-2026-09-22": "old\n", "hands/hands.py": "code\n", "hands/hands-log.jsonl": "{}\n",
            "uploads/video.mp4": "private footage", "uploads/manifest.jsonl": "{}",
            "dashboard/chats/sessions/s1.json": "{}", "dashboard/chats/jobs/j1.json": "{}",
            "vault-index/vault.sqlite": "derived", "private/chats/c.md": "private", "logs/x.log": "log",
            "backtalk/backtalk/brain.py": "code\n", "backtalk/.venv/lib/x.py": "venv", "backtalk/.voice_state": "idle",
            "zip_b64.txt": "unknown", ".claude/settings.json": "{}",
            "dashboard/icons/talk-96.png": "png", "dashboard/runtime/talk/talk-3fa9.webm": "audio",
            "dashboard/dashboard-devices.lock": "", "dashboard/passkeys.jsonl": "{}\n", "dashboard/passkeys-user.json": "{}",
            "dashboard/.staged-mj/dashboard-devices.jsonl": "{}\n", "dashboard/.staged-mj/server.py": "code\n",
            "dashboard/.rollback-mj-20260925_131139/server.py": "old\n", "dashboard/.staged-x/test-chats/chats/j.json": "{}",
        }
        # Dead-copy kits (every shape seen on this PC, 2026-09-26): skipped. One .newcode file duplicates
        # live code; two files exist nowhere else and must be named as sole copies; a unique .rollback-*
        # file is a pre-deploy backup and is not.
        kits = {
            "dashboard/.rollback-board-20260926_094607/server.py": "old rollback only\n",
            "dashboard/.rollback-live-20260926_121509/README.txt": "rollback\n",
            "dashboard/.rollback-mj-20260925_131139/server.py": "old\n",
            "dashboard/.newcode-20260925_2330/server.py": "code\n",
            "dashboard/.newcode-20260925_2330/only-here.py": "unique newcode\n",
            "dashboard/.newcode-20260925_2330/style.css": "old rollback only\n",   # = a .rollback-* file: dead
            "hands/.bak-20260901/notes.py": "unique bak\n",
            "tools/.rollback-smallfixes-20260926_140000/recovery_bundle.py": "old\n",
        }
        sole_expected = ["dashboard/.newcode-20260925_2330/only-here.py", "hands/.bak-20260901/notes.py"]
        # Staging kits are carried (they hold sole copies: unshipped builds, browser suites, deploy scripts),
        # in dashboard/ and elsewhere; their private files still go by the name and chat-store rules.
        staged = {"dashboard/.staged-board/app.js": "staged\n", "dashboard/.staged-live/test_live_browser.py": "suite\n",
                  "dashboard/.staged-outbox/server.py": "unshipped\n", "dashboard/.staged-mj/deploy/deploy.ps1": "deploy\n",
                  "backtalk/.staged-voicefixes/backtalk/mouth.py": "staged\n"}
        staged_private = {"dashboard/.staged-mj/test-chats/jobs/j.json": "{}", "dashboard/.staged-mj/chats/jobs/j.json": "{}",
                          "dashboard/.staged-mj/test-server.out.log": "log", "dashboard/.staged-mj/passkeys.jsonl": "{}"}
        # Near misses that are ordinary code and must stay in: the rule is dot-prefixed FOLDERS only.
        keep = {"dashboard/restaged/keep.py": "code\n", "dashboard/rollback-guide.md": "doc\n",
                "tools/staged_helper.py": "code\n"}
        for group in (kits, staged, staged_private, keep):
            files.update(group)
        for rel, text in files.items():
            (agent / rel).parent.mkdir(parents=True, exist_ok=True)
            (agent / rel).write_text(text, encoding="utf-8")
        (vault / "07 - Resources").mkdir(parents=True)
        (vault / "Active Priorities.md").write_text("# AP\n", encoding="utf-8")
        (vault / "07 - Resources" / "Marty Stack.md").write_text("stack\n", encoding="utf-8")
        (vault / ".trash").mkdir()
        (vault / ".trash" / "old.md").write_text("gone\n", encoding="utf-8")

        print("what goes in, and what stays out")
        take, skipped = collect(agent, vault)
        names = {n for n, _ in take}
        for must in ("my-agent/CLAUDE.md", "my-agent/tools/switchboard.py", "my-agent/tools/Modelfile.marty-local",
                     "my-agent/dashboard/server.py", "my-agent/hands/hands.py", "my-agent/tools/marty_tools.scope.json",
                     "my-agent/backtalk/backtalk/brain.py", "my-agent/.claude/settings.json", "my-agent/dashboard/icons/talk-96.png",
                     "marty-vault/Active Priorities.md", "marty-vault/07 - Resources/Marty Stack.md",
                     *("my-agent/" + k for k in keep), *("my-agent/" + k for k in staged),
                     "my-agent/dashboard/.staged-mj/server.py"):
            check(must in names, f"includes {must}")
        leaked = [n for n in names if any(x in n for x in ("uploads/", "dashboard/chats/", "private/", "vault-index/",
                                                            "logs/", ".log", "activity.jsonl",
                                                            "dashboard-devices", "hands-log", ".bak-", "/.venv/", ".voice_",
                                                            "tools/bin/", "freezer-frames", "zip_b64", ".trash/",
                                                            "runtime/talk/talk-", "passkeys", "/.rollback-",
                                                            "/.newcode-", "/chats/", "-chats/"))]
        check(not leaked, f"private, derived, unknown and dead-copy files stay out ({leaked})")
        why = dict(skipped)
        check(all(why.get(k) == KIT_WHY for k in kits),
              f"every dead-copy kit file ({len(kits)} in .rollback-*, .newcode-*, .bak-* folders) is skipped as one")
        check(all(k in why for k in staged_private),
              "a staging kit's test chats, device tokens and logs stay out")
        check(sole_copies(take, skipped, agent) == sole_expected,
              "sole copies in dead-copy kits are found by hash (duplicates of bundled or .rollback-* files are not)")

        print("the credential tripwire, one shape at a time (every fake is assembled here, at run time)")
        body = lambda unit, n: (unit * n)[:n]           # a fake body of exactly n characters
        q = '"'
        must_trip = [
            ("an OpenAI-style key", "OPENAI = '" + "sk-" + "proj-" + body("Ab3_-x9", 120) + "'",
             "an OpenAI project key whose body carries _ and - (the old pattern missed it)"),
            ("an OpenAI-style key", "k = " + "sk-" + "svcacct-" + body("Q_7-zz", 60), "an OpenAI service-account key"),
            ("an OpenAI-style key", "k = " + "sk-" + "admin-" + body("Q_7-zz", 60), "an OpenAI admin key"),
            ("an OpenAI-style key", "k = " + "sk-" + body("A1b2C3", 48), "a legacy OpenAI key"),
            ("a GitHub fine-grained token", "GH=" + "github_" + "pat_" + body("11AbC", 22) + "_" + body("x9Y", 59),
             "a GitHub fine-grained token"),
            ("a Hugging Face token", "HF_TOKEN=" + "hf" + "_" + body("AbCdEfGhIj", 34), "a Hugging Face token"),
            ("a Tailscale key", "TS_AUTHKEY=" + "tskey" + "-auth-" + "kQ7x9m" + "CNTRL-" + body("Zy8w", 32),
             "a Tailscale auth key"),
            ("a Tailscale key", "k = " + "tskey" + "-api-" + "kQ7x9m" + "CNTRL-" + body("Zy8w", 32), "a Tailscale API key"),
            ("a Tailscale key", "k = " + "tskey" + "-" + body("0a1b2c", 40), "an old-style Tailscale key"),
            ("a quoted secret assignment", "{" + q + "token" + q + ": " + q + body("eyJ9x", 40) + q + "}", 'JSON "token"'),
            ("a quoted secret assignment", "{" + q + "api_key" + q + ":" + q + body("Zq81", 32) + q + "}", 'JSON "api_key"'),
            ("a quoted secret assignment", q + "access_token" + q + ": " + q + body("ya29.Ab", 60) + q,
             'JSON "access_token"'),
            ("a quoted secret assignment", q + "client_secret" + q + ": " + q + body("GOCSPX-a1", 35) + q,
             'JSON "client_secret"'),
            ("a quoted secret assignment", "OPENAI_API_KEY=" + q + body("Rk2p", 40) + q, ".env style OPENAI_API_KEY"),  # secret-scan: allow [export-reviewed]
            ("a quoted secret assignment", "password = '" + body("Tr0ub4dor&3", 24) + "'", "the original key = 'value'"),
            # Real values that only START like a reference still trip (skeptic, 2026-09-26: the first version
            # skipped any value whose first character was $, %, { or <).
            ("a quoted secret assignment", "password = " + q + "$" + body("Xk9#pQ", 23) + q, "a password starting with $"),
            ("a quoted secret assignment", q + "token" + q + ": " + q + "%" + body("Xk9#pQ", 23) + q, "a token starting with %"),
            ("a quoted secret assignment", q + "api_key" + q + ": " + q + "{" + body("Xk9#pQ", 23) + q, "a key starting with {"),
            ("a quoted secret assignment", "secret = '" + "<" + body("Xk9#pQ", 23) + "'", "a secret starting with <"),
            ("a quoted secret assignment", q + "client_secret" + q + ": " + q + "${" + body("Zq81", 28) + q,
             "an unclosed ${ then a real value"),
            ("a quoted secret assignment", q + "access_token" + q + ": " + q + "${VAR}" + body("Zq81", 24) + q,
             "a ${VAR} with a real value after it"),
            ("a quoted secret assignment", "password: " + q + "<b>" + body("Zq81", 24) + q, "a <tag> with a real value after it"),
            # camelCase names (skeptic, 2026-09-26: the lookbehind form let these through).
            ("a quoted secret assignment", "accessToken = " + q + body("ya29.Ab", 40) + q, "camelCase accessToken"),
            ("a quoted secret assignment", "clientSecret: " + q + body("GOCSPX-a1", 35) + q, "camelCase clientSecret"),
            ("a quoted secret assignment", "dbPassword = '" + body("Tr0ub4dor&3", 24) + "'", "camelCase dbPassword"),
            ("a quoted secret assignment", "openaiApiKey = " + q + body("Rk2p", 40) + q, "camelCase openaiApiKey"),
            ("a quoted secret assignment", q + "awsSecretKey" + q + ": " + q + body("wJal9/K7", 40) + q,
             'JSON camelCase "awsSecretKey"'),
        ]
        for label, text, what in must_trip:
            check(scan_text(text) == [(1, label)], f"trips once, as {label}: {what}")
        must_not_trip = [
            ('secret = "CANARY-7731"', "the live_feed.py selftest canary (short)"),  # secret-scan: allow [export-reviewed]
            (q + "token" + q + ": " + q + "<paste your token here>" + q, "a placeholder with spaces"),
            (q + "api_key" + q + ": " + q + "${OPENROUTER_API_KEY_FROM_ENV}" + q, "a ${VAR} reference"),
            (q + "password" + q + ": " + q + "{{vault_password_lookup_value}}" + q, "a {{template}} reference"),
            ("set TOKEN=" + q + "%MARTY_TOKEN_FROM_THE_ENVIRONMENT%" + q, "a %VAR% reference"),
            (q + "token" + q + ": " + q + "<paste_your_token_here_please>" + q, "a <placeholder> with no spaces"),
            ("tokens_used = " + q + body("abcdef", 30) + q, "a key that only starts with token"),
            ("from huggingface_hub import " + "hf" + "_hub_download", "an hf_ identifier"),
            ("x = " + "hf" + "_" + body("abcdefghij", 32) + "_cache", "a long hf_ identifier that runs on with _"),
            ("see " + "sk-" + "proj-... in the docs", "a short sk-proj- placeholder"),
            ("github_" + "pat_... or " + "tskey" + "-auth-... go here", "short GitHub and Tailscale placeholders"),
            ("tokenizer = " + q + "bert-base-uncased-whole-word-masking" + q, "tokenizer (an ordinary word)"),
            ("passwordHint = " + q + "short" + q, "passwordHint (not a secret name, short value)"),
            ("csrfTokenName = " + q + "x" + q, "csrfTokenName (short value)"),
            ("csrfTokenName = " + q + "X-CSRF-Token-Header-Name" + q, "csrfTokenName with a long value (name ends in Name)"),
            ("maxTokens = " + q + body("4096", 24) + q, "maxTokens (ends in Tokens, not Token)"),
            ("accessToken = " + q + "${ACCESS_TOKEN_FROM_THE_ENV}" + q, "camelCase name holding a ${VAR} reference"),
        ]
        for text, what in must_not_trip:
            check(not scan_text(text), f"does not trip: {what}")
        check(not scan_text(pathlib.Path(__file__).read_text(encoding="utf-8")),
              "this file never trips its own tripwire (it is bundled too)")
        # Linear time, every pattern: a text file up to MAX_FILE (10 MB) is scanned, and the first widened
        # assignment pattern took 97.8 s on 80 KB of "a-a-a-...".
        hexdash = "-".join(f"{i:08x}" for i in range(23000))[:200_000]
        for what, text in (("hex-dash text", hexdash), ('"a-" repeated', "a-" * 100_000),
                           ('"a_" repeated', "a_" * 100_000), ("one camelCase run", "aToken" * 34_000)):
            t0 = time.perf_counter()
            scan_text(text)
            took = time.perf_counter() - t0
            check(took < 1.0, f"200 KB of {what} scans in under 1 s with every pattern ({took:.3f} s)")
        for what, text in (("one camelCase run", "aToken" * 340_000),
                           ("camelCase secret names", "accessTokenClientSecretDbPasswordOpenaiApiKey" * 45_000)):
            t0 = time.perf_counter()
            scan_text(text)
            took = time.perf_counter() - t0
            check(took < 2.0, f"2 MB of {what} scans in under 2 s with every pattern ({took:.3f} s)")
        hit_line = "token=" + q + body("Zq81xY", 24) + q + "\n"            # 33 bytes: 60,606 lines is 2 MB  # secret-scan: allow [export-reviewed]
        t0 = time.perf_counter()
        many = scan_text(hit_line * 60_606)
        took = time.perf_counter() - t0
        check(len(many) == 60_606 and many[0][0] == 1 and many[-1][0] == 60_606 and took < 2.0,
              f"2 MB holding 60,606 hits scans in under 2 s, every hit on its own right line ({took:.3f} s)")

        bundle = td / bundle_name(dt.datetime(2026, 9, 23, 8, 0))
        fake = "sk-ant-" + "api03-" + "X" * 40
        (agent / "tools" / "leaky.py").write_text(f"KEY = '{fake}'\n", encoding="utf-8")
        try:
            build(bundle, agent, vault, deps=False)
            check(False, "a planted key refuses the build")
        except SystemExit as e:
            check("tools/leaky.py:1" in str(e) and fake not in str(e) and not bundle.exists(),
                  "a planted key refuses the build, names the file and line, never the value")
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            rc = cli_build(bundle, agent, vault, deps=False)
        said = out_buf.getvalue()
        check(rc == 1 and said.startswith("REFUSED") and "tools/leaky.py:1  (an Anthropic key)" in said
              and fake not in said and fake not in err_buf.getvalue() and not bundle.exists(),
              "the build command puts the refusal on STDOUT (what backup-marty.ps1 logs), exit 1, file:line:label only")
        (agent / "tools" / "leaky.py").unlink()
        (agent / "tools" / "quoted.py").write_text("check('-----BEGIN RSA PRIVATE KEY-----')\npassword = 'short'\n",  # secret-scan: allow [export-reviewed]
                                                  encoding="utf-8")

        print("build, restore drill, tamper")
        r = build(bundle, agent, vault, deps=False)
        check(bundle.exists() and r["files"] == len(collect(agent, vault)[0]),
              f"a test fixture that only mentions a PEM header does not trip it, and the bundle builds ({r['files']} files)")
        with zipfile.ZipFile(bundle) as z:
            zipped = z.namelist()
            man = json.loads(z.read("MANIFEST.json"))
        listed = {s["path"] for s in man["skipped"]}
        check(not [n for n in zipped if any("/" + k in n for k in KIT_PREFIXES)] and set(kits) <= listed
              and all("my-agent/" + k in zipped for k in list(keep) + list(staged)),
              "the zip holds no dead-copy kit file (MANIFEST lists each as skipped), and holds the staging kits")
        check(man.get("skipped_sole_copies") == sole_expected
              and r.get("WARNING_sole_copies_skipped", {}).get("count") == len(sole_expected),
              "the sole copies are named in MANIFEST.json and, loudly, in the printed build result")
        rep = drill(bundle, run_selftests=False)
        check(rep["ok"] and rep["files_verified"] == r["files"], f"the drill verifies every file: {rep['problems']}")
        tampered = td / "tampered.zip"
        with zipfile.ZipFile(bundle) as src, zipfile.ZipFile(tampered, "w") as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename == "my-agent/hands/hands.py":
                    data = b"tampered\n"
                dst.writestr(item, data)
        rep = drill(tampered, run_selftests=False)
        check(not rep["ok"] and any("checksum mismatch my-agent/hands/hands.py" in p for p in rep["problems"]),
              "a changed file fails the drill by name")

        print("the sole-copy warning lands where it is read, and never blocks the build")
        with zipfile.ZipFile(bundle) as z:
            restore = z.read("RESTORE.md").decode("utf-8")
        note = agent / STATUS_NOTE
        lines = note.read_text(encoding="utf-8").splitlines() if note.is_file() else [""]
        check(restore.startswith("# WARNING") and all(f"- {s}" in restore for s in sole_expected)
              and len(man.get("warnings", [])) == 1 and man["warnings"][0].startswith("2 file(s)"),
              "the bundle's RESTORE.md opens with the warning and names each sole copy; MANIFEST.json carries it")
        check(bool(re.match(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] WARNING ", lines[-1])) and bundle.name in lines[-1]
              and all(s in lines[-1] for s in sole_expected) and r.get("status_note") == str(note),
              "one WARNING line naming the bundle and each sole copy lands in status/recovery-bundle.txt")
        note.unlink()
        note.mkdir()                                    # a folder where the status file goes: the append fails
        b2 = td / bundle_name(dt.datetime(2026, 9, 23, 9, 0))
        r2 = build(b2, agent, vault, deps=False)
        check(b2.exists() and "status_note_error" in r2,
              "a status line that cannot be written is reported, and the bundle still builds")
        note.rmdir()
        real_sole_copies = sole_copies

        def crash(*_args, **_kw):
            raise OSError("simulated: a kit file vanished mid-build")

        globals()["sole_copies"] = crash
        try:
            b3 = td / bundle_name(dt.datetime(2026, 9, 23, 10, 0))
            r3 = build(b3, agent, vault, deps=False)
        except Exception as e:
            b3, r3 = None, {"raised": f"{type(e).__name__}: {e}"}
        finally:
            globals()["sole_copies"] = real_sole_copies
        restore3 = ""
        if b3 and b3.exists():
            with zipfile.ZipFile(b3) as z:
                restore3 = z.read("RESTORE.md").decode("utf-8")
        last = note.read_text(encoding="utf-8").splitlines()[-1] if note.is_file() else ""
        check("WARNING_sole_copy_check_failed" in r3 and "could not run" in last and restore3.startswith("# WARNING"),
              f"a sole-copy check that crashes is a warning (result, RESTORE.md, status line); the bundle still builds {r3.get('raised', '')}")
        for s in sole_expected:
            (agent / s).unlink()
        b4 = td / bundle_name(dt.datetime(2026, 9, 23, 11, 0))
        r4 = build(b4, agent, vault, deps=False)
        with zipfile.ZipFile(b4) as z:
            restore4, man4 = z.read("RESTORE.md").decode("utf-8"), json.loads(z.read("MANIFEST.json"))
        lines = note.read_text(encoding="utf-8").splitlines()
        check(len(lines) == 2 and f"] ok {b4.name}:" in lines[-1] and restore4 == RESTORE_MD and man4["warnings"] == []
              and man4["skipped_sole_copies"] == [] and "WARNING_sole_copies_skipped" not in r4,
              "a clean build appends one ok line and carries no warning anywhere")

        print("retention")
        keep_dir = td / "versions"
        keep_dir.mkdir()
        for day in range(1, 12):
            (keep_dir / bundle_name(dt.datetime(2026, 9, day, 3, 0))).write_text("z", encoding="utf-8")
        (keep_dir / "notes.txt").write_text("not mine", encoding="utf-8")
        (keep_dir / "marty-recovery-final.zip").write_text("not mine either", encoding="utf-8")
        gone = prune(keep_dir, 8)
        left = sorted(p.name for p in keep_dir.iterdir())
        check(len(gone) == 3 and gone[0] == bundle_name(dt.datetime(2026, 9, 1, 3, 0)) and len(left) == 10
              and "notes.txt" in left and "marty-recovery-final.zip" in left,
              "prune keeps the newest 8 and never touches a file it did not name")
    print()
    if fails:
        print(f"{len(fails)} FAILED:")
        for f in fails:
            print("  - " + f)
        return 1
    print("all checks passed")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Marty's recovery bundle: build, drill, prune.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--out", required=True)
    d = sub.add_parser("drill"); d.add_argument("bundle"); d.add_argument("--no-selftests", action="store_true")
    p = sub.add_parser("prune"); p.add_argument("folder"); p.add_argument("--keep", type=int, default=8)
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest":
        raise SystemExit(selftest())
    if a.cmd == "build":
        raise SystemExit(cli_build(a.out))
    elif a.cmd == "drill":
        rep = drill(a.bundle, run_selftests=not a.no_selftests)
        print(json.dumps(rep, indent=1))
        raise SystemExit(0 if rep["ok"] else 1)
    elif a.cmd == "prune":
        print(json.dumps({"removed": prune(a.folder, a.keep)}))


if __name__ == "__main__":
    main()
