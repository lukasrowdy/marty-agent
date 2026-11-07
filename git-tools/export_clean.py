#!/usr/bin/env python3
"""Clean export of my-agent for a private GitHub remote. Pure standard library, Python 3.11+.

Reads the live repo (read-only: git ls-tree / cat-file / ls-files, never a write) and writes a sanitized
copy of its tracked files to OUT/tree/, plus OUT/export-summary.json. The live checkout is never touched.

    py -3.12 git-tools/export_clean.py                    export HEAD to the default OUT
    py -3.12 git-tools/export_clean.py --source worktree  tracked paths, but their current on-disk content
    py -3.12 git-tools/export_clean.py --commit           then init OUT/tree as a fresh repo with ONE commit
    py -3.12 git-tools/export_clean.py --sync [--expect-origin URL]
                                                          write INTO the existing clone at OUT/tree, keep its
                                                          .git and remote, commit once on top of its history

Fresh mode (the default, and --commit) wipes OUT/tree first; it is for a first export only. --sync is for every
export after the clone has a remote. --expect-origin URL is required with it. It refuses (exit 1) when
OUT/tree has no .git, no `origin`, an origin whose URL differs from --expect-origin, or any modified,
untracked OR gitignored path (an ignored leftover such as a __pycache__ is dirt too: the tool never deletes
what it did not write, so it refuses instead of `git clean -fdX`); otherwise it deletes every file the clone
tracks, writes the sanitized files, empties the index and re-adds everything from disk (so a case-only
rename in the source survives the clone's core.ignorecase=true), and makes ONE commit whose message names
the source commit (no commit at all when nothing changed). It never pushes. --tree PATH points both modes at
a clone that is not OUT/tree (used for a dry run against a scratch copy).

If --sync fails after it has started deleting (a crash mid-write, a refused generated file), the clone is
left dirty and the next --sync refuses on that. Recovery, in the clone: `git checkout -- .` then
`git clean -fd` (add -X if ignored files were left), which puts the working tree back at the last export
commit; then run --sync again. Messages and export-summary.json name the clone by its folder name only,
never by its full path.

What happens to each tracked file, first matching rule wins (the reason shows in the summary):
  staged-tree      any path part starting .staged- / staged- / .rollback-
  boot-file        CLAUDE.md, CLAUDE.local.md, AGENTS.md anywhere
  secrets          anything under a secrets/ folder
  private-data     uploads, chats, private, logs, status, outbox, proposals, jr history/drafts/library/computer ...
  reviewed-exclude a path listed in export_reviewed.json "exclude_paths" (with its own reason)
  gitignored       tracked but matched by .gitignore (git ls-files -ci --exclude-standard)
  media            images, audio, video, PDFs, unless the exact blob is on the reviewed media list
  binary / too-large / non-utf8
  scan-unclean     after placeholder substitution the scan still finds something (fail closed)
  unmapped-case    a private value in a letter case the map has no placeholder for

Text files: every private value in the map becomes {{PLACEHOLDER}} (case forms: exact {{P}}, lower {{P_LC}},
upper {{P_UC}}, capitalised {{P_TC}}). Then git-tools/secret_scan.py's Scanner runs with the full terms list
(map values plus the MARTY_PRIVATE_TERMS file). A flagged line on the reviewed list (path + sha256 of the
exported line) gets the marker comment `secret-scan: allow [export-reviewed]`; a flagged line whose only
problem is a reviewed generic test IP gets {{IP_a_b_c_d}}; anything else left excludes the whole file.

The map (default secrets/private_map.local.json, gitignored) holds the real values; it never enters the
export and no value is ever printed. Every term in MARTY_PRIVATE_TERMS must have a map entry or the run
refuses (exit 2). Same inputs give byte-identical output and, with --commit, the same commit id.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import secret_scan  # noqa: E402

DEFAULT_REPO = HERE.parent
DEFAULT_OUT = Path.home() / "Projects" / "my-agent-export"
DEFAULT_MAP = DEFAULT_REPO / "secrets" / "private_map.local.json"
DEFAULT_REVIEWED = HERE / "export_reviewed.json"
MARKER = "secret-scan: allow [export-reviewed]"
COMMIT_NAME, COMMIT_EMAIL = "Marty", "marty@localhost.invalid"

STAGED_PART = re.compile(r"^(\.staged-|staged-|\.rollback-)")
BOOT_NAMES = {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"}
PRIVATE_PARTS = {"uploads", "chats", "test-chats", "private", "logs", "status", "outbox", "proposals",
                 "scratchpad", "tmp", "outbox-source"}
PRIVATE_PREFIXES = ("jr/history/", "jr/drafts/", "jr/library/", "jr/computer/", "deals/business.json")
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg", ".tif", ".tiff", ".heic",
             ".mp4", ".mov", ".mkv", ".avi", ".webm", ".wav", ".mp3", ".m4a", ".flac", ".ogg", ".aac",
             ".pdf", ".docx", ".xlsx", ".pptx"}
HASH_COMMENT = {".py", ".ps1", ".psm1", ".sh", ".toml", ".yml", ".yaml", ".rb", ".r"}
SLASH_COMMENT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".go", ".rs"}
# Extra fail-closed shapes the repo scanner does not have.
EXTRA_RULES = [
    ("tailnet-name", re.compile(r"(?i)[a-z0-9-]+\.ts\.net\b")),
    ("windows-sid", re.compile(r"\bS-1-5-21-\d+-\d+-\d+")),
    ("mac-address", re.compile(r"(?i)(?<![0-9a-f:-])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f:-])")),
]


def marker_for(path: str) -> str | None:
    p = Path(path)
    ext = p.suffix.lower()
    if ext in HASH_COMMENT or p.name in {".gitignore", ".gitattributes", "Modelfile"} or p.name.startswith("Modelfile"):
        return "  # " + MARKER
    if ext in SLASH_COMMENT:
        return "  // " + MARKER
    if ext == ".css":
        return "  /* " + MARKER + " */"
    if ext in {".md", ".html", ".htm", ".xml"}:
        return "  <!-- " + MARKER + " -->"
    return None


ALL_MARKERS = ["  # " + MARKER, "  // " + MARKER, "  /* " + MARKER + " */", "  <!-- " + MARKER + " -->"]


def line_sha(line: str) -> str:
    return hashlib.sha256(line.rstrip("\r").encode("utf-8", "surrogateescape")).hexdigest()


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ----------------------------------------------------------------------------------------------- the map

class PlaceholderMap:
    """value <-> placeholder, with case forms. Built from the local map file; never prints a value."""

    def __init__(self, entries: list[dict]):
        self.entries = entries
        self.forms: dict[str, str] = {}          # exact text -> placeholder (with braces)
        self.lower_to_entry: dict[str, dict] = {}
        self.describe: dict[str, str] = {}
        for e in entries:
            v, p = e["value"], e["placeholder"]
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", p):
                raise ValueError("bad placeholder name in map: " + p)
            self.describe[p] = e.get("describe", "")
            self.lower_to_entry[v.lower()] = e
            for text, suffix in ((v, ""), (v.lower(), "_LC"), (v.upper(), "_UC"), (v[:1].upper() + v[1:].lower(), "_TC")):
                self.forms.setdefault(text, "{{" + p + suffix + "}}")
        alts = []
        for e in sorted(entries, key=lambda e: (-len(e["value"]), e["value"])):
            body = re.escape(e["value"])
            mode = e.get("match", "glued")
            if mode == "word":
                body = r"(?<!\w)" + body + r"(?!\w)"
            elif mode == "ip":
                body = r"(?<![0-9.])" + body + r"(?![0-9])"
            alts.append(body)
        self.regex = re.compile("(?i)(" + "|".join(alts) + ")") if alts else None
        self.reverse = {ph: text for text, ph in self.forms.items()}
        self.literal_rules: list[LiteralRule] = []

    @classmethod
    def load(cls, path: Path) -> "PlaceholderMap":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        pm = cls(data["entries"])
        pm.literal_rules = [LiteralRule(r) for r in data.get("literal_rules", [])]
        return pm

    def substitute(self, text: str, counts: collections.Counter) -> tuple[str, int]:
        """Returns (new text, number of matches in a case form the map cannot name)."""
        if self.regex is None:
            return text, 0
        bad = 0

        def repl(m):
            nonlocal bad
            ph = self.forms.get(m.group(1))
            if ph is None:
                bad += 1
                return m.group(1)
            counts[ph] += 1
            return ph
        return self.regex.sub(repl, text), bad


class LiteralRule:
    """A reversible in-place rewrite that is not a {{PLACEHOLDER}}: `find` becomes `replace` only where the
    `before` / `after` lookaround regexes hold, optionally only in one `path`. Used where a placeholder would
    break the code's meaning (a fake phone area code that must still look like a phone number, a variable
    name, a stale comment). Fail closed: a file that already contains the replacement form (so the reverse
    would be ambiguous) is excluded as literal-collision."""

    def __init__(self, r: dict):
        self.name, self.path = r["name"], r.get("path")
        b, a = r.get("before", ""), r.get("after", "")
        self.find, self.replace = r["find"], r["replace"]
        self.fwd = re.compile(b + re.escape(self.find) + a)
        self.back = re.compile(b + re.escape(self.replace) + a)

    def applies(self, path: str | None) -> bool:
        return self.path is None or self.path == path

    def forward(self, text: str) -> tuple[str, int]:
        return self.fwd.subn(lambda m: self.replace, text)

    def reverse(self, text: str) -> tuple[str, int]:
        return self.back.subn(lambda m: self.find, text)


def load_reviewed(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        rv = json.load(fh)
    rv.setdefault("exclude_paths", {})
    rv.setdefault("media_blobs", {})
    # Stored as 10_0_0_1 (underscores) so the repo's own scanner does not refuse this file; dots also accepted.
    rv["generic_ips"] = [ip.replace("_", ".") for ip in rv.get("generic_ips", [])]
    rv["_lines"] = {(r["path"], r["sha256"]) for r in rv.get("reviewed_lines", [])}
    rv["_literal_rules"] = [LiteralRule(r) for r in rv.get("literal_rules", [])]
    return rv


def generic_ip_placeholder(ip: str) -> str:
    return "{{IP_" + ip.replace(".", "_") + "}}"


# ----------------------------------------------------------------------------------------------- git (read-only)

def git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError("git " + " ".join(args) + ": " + proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


def read_blobs(repo: Path, shas: list[str]):
    """One git cat-file process; one request, full reply, next request (no pipe deadlock on Windows)."""
    proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for sha in shas:
            proc.stdin.write((sha + "\n").encode())
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            size = int(header[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            yield data
    finally:
        proc.stdin.close()
        proc.wait()
        proc.stdout.close()


def source_files(repo: Path, source: str) -> tuple[str, list[tuple[str, bytes]]]:
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    if source == "head":
        listing = [x for x in git(repo, "ls-tree", "-r", "-z", "HEAD").decode("utf-8", "surrogateescape").split("\0") if x]
        items = []
        for row in listing:
            meta, path = row.split("\t", 1)
            mode, kind, sha = meta.split()
            if kind == "blob" and mode != "120000":
                items.append((path, sha))
        items.sort()
        return commit, list(zip([p for p, _ in items], read_blobs(repo, [s for _, s in items])))
    paths = sorted(p for p in git(repo, "ls-files", "-z").decode("utf-8", "surrogateescape").split("\0") if p)
    out = []
    for p in paths:
        f = repo / p
        if f.is_file() and not f.is_symlink():
            out.append((p, f.read_bytes()))
    return commit, out


def path_reason(path: str, reviewed: dict, ignored: set[str]) -> str | None:
    parts = path.split("/")
    if any(STAGED_PART.match(x) for x in parts):
        return "staged-tree"
    if parts[-1] in BOOT_NAMES:
        return "boot-file"
    if "secrets" in parts[:-1]:
        return "secrets"
    if any(x in PRIVATE_PARTS for x in parts[:-1]) or path.startswith(PRIVATE_PREFIXES):
        return "private-data"
    if path in reviewed["exclude_paths"]:
        return reviewed["exclude_paths"][path]
    if path in ignored:
        return "gitignored"
    return None


# ----------------------------------------------------------------------------------------------- cleaning

class Cleaner:
    def __init__(self, pmap: PlaceholderMap, reviewed: dict, terms_file_terms: list[str]):
        self.pmap = pmap
        self.reviewed = reviewed
        values = [e["value"] for e in pmap.entries]
        self.scanner = secret_scan.Scanner(private_terms=values + terms_file_terms)
        glued = [e["value"] for e in pmap.entries if e.get("match", "glued") != "word"]
        glued += [t for t in terms_file_terms if t.lower() not in pmap.lower_to_entry]
        self.leftover = re.compile("(?i)(" + "|".join(re.escape(v) for v in sorted(set(glued), key=len, reverse=True)) + ")") if glued else None
        self.generic = set(reviewed["generic_ips"])
        self.ip_re = secret_scan.RULES[7][1]

    def problems(self, text: str) -> list[tuple[int, str]]:
        found = [(ln, rule) for ln, rule, _ in self.scanner.scan_text(text)]
        for n, line in enumerate(text.split("\n"), 1):
            if secret_scan.ALLOW_RE.search(line):
                continue
            if self.leftover and self.leftover.search(line):
                found.append((n, "private-substring"))
            for name, rx in EXTRA_RULES:
                if rx.search(line):
                    found.append((n, name))
        return sorted(set(found))

    def clean(self, path: str, text: str, counts: collections.Counter) -> tuple[str | None, str | None, list]:
        local = collections.Counter()
        for rule in self.pmap.literal_rules + self.reviewed["_literal_rules"]:
            if rule.applies(path):
                if rule.back.search(text):
                    return None, "literal-collision", []
                text, n = rule.forward(text)
                if n:
                    local["~" + rule.name] += n
        text, bad_case = self.pmap.substitute(text, local)
        if bad_case:
            return None, "unmapped-case", []
        lines = text.split("\n")
        for ln in sorted({ln for ln, _ in self.problems(text)}):
            line = lines[ln - 1]
            if (path, line_sha(line)) in self.reviewed["_lines"]:
                mark = marker_for(path)
                if mark:
                    cr = "\r" if line.endswith("\r") else ""
                    lines[ln - 1] = line.rstrip("\r") + mark + cr
                    local["@reviewed-line-marker"] += 1
                    continue
            ips = self.ip_re.findall(line)
            if ips and all(ip in self.generic for ip in ips):
                for ip in sorted(set(ips), key=len, reverse=True):
                    ph = generic_ip_placeholder(ip)
                    line, n = re.subn(r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9])", ph, line)
                    local[ph] += n
                lines[ln - 1] = line
        text = "\n".join(lines)
        left = self.problems(text)
        if left:
            return None, "scan-unclean", left
        counts.update(local)
        return text, None, []


# ----------------------------------------------------------------------------------------------- outputs

def readme_text(commit: str, summary: dict, pmap: PlaceholderMap, reviewed: dict) -> str:
    rows = []
    reps = summary["replacements"]
    for p in sorted(pmap.describe):
        n = sum(v for k, v in reps.items() if k.startswith("{{" + p + "}}") or re.fullmatch(r"\{\{" + p + r"_(LC|UC|TC)\}\}", k))
        if n:
            rows.append("| `{{%s}}` | %s | %d |" % (p, pmap.describe[p], n))
    ipn = sum(v for k, v in reps.items() if k.startswith("{{IP_"))
    excl = "\n".join("| %s | %d |" % (k, v) for k, v in sorted(summary["excluded_by_reason"].items()))
    return f"""# my-agent (clean export)

This is a sanitized export of a private home-automation and assistant codebase, made so cloud coding
sessions can read and change the code. It is **not runnable as is**: the live system depends on local
services, local files and private values that are deliberately not here. Each commit here is one whole
export; the source repo's own history never leaves its machine.

Exported from source commit `{commit[:12]}` by `git-tools/export_clean.py` (a copy is here; the map and the
private terms list it needs are not). {summary['files_out_from_source']} of {summary['files_in']} tracked
files are here; the rest were left out on purpose (table below).

## Placeholders

Private values (names, addresses, hostnames, account ids) were replaced with `{{{{PLACEHOLDER}}}}` tokens.
Treat them as opaque constants:

- Keep every placeholder exactly as written. Do not guess, fill in or "fix" a value.
- A suffix shows the original letter case: `_LC` lower, `_UC` upper, `_TC` capitalised.
- `{{{{IP_a_b_c_d}}}}` stands for the ordinary test address a.b.c.d ({ipn} uses); it is a placeholder only
  because the secret scanner refuses private address ranges.
- Lines ending in `{MARKER}` are reviewed test fixtures and canaries. Leave the marker alone.
- New code that needs a private value should read it from configuration or an environment variable.
- Fictional phone-number fixtures use the unassigned area code 999 with 555 exchanges; keep them fictional.
- The six PNGs in `dashboard/icons/` are code-drawn orbs: chunk-only PNGs (IHDR, IDAT, IEND, no metadata),
  pixel-identical (and byte-identical) to the output of the source repo's icon generator script.
- A few self-tests compare against the private values themselves (for example the name-hiding and
  vault-search checks) and fail in this export; they pass on the source. Tests that need local services,
  private folders or the owner's machine cannot run here at all.

| Placeholder | Stands for | Uses |
|---|---|---|
""" + "\n".join(rows) + f"""

## What was left out

| Reason | Files |
|---|---|
{excl}

Boot files (`CLAUDE.md`, `AGENTS.md`) are replaced by `CLAUDE.example.md`, which describes their structure.

## How changes get back

Work on a branch and open a pull request. The owner exports the PR as a unified diff, maps placeholders back
to real values locally with `git-tools/import_patch.py`, reviews the result and applies it by hand. Nothing
in this repository is deployed automatically.
"""


CLAUDE_EXAMPLE = """# CLAUDE.md (structure example)

The live repository's boot file is private and is not in this export. It is loaded at the start of every
Claude Code session in the source repo and survives context compaction. This file shows its shape so code
that refers to it makes sense. No names, addresses or account details appear here.

## Sections in the real file

1. **Identity.** The assistant's name, its two mandates (keep everything that runs working; act as a
   strategic partner who pushes back), its tone, and the fixed first line of every session.
2. **What you are.** The model plus three things built around it: tools that act on real systems, an
   external note vault as unlimited memory loaded on demand, and indexes that make retrieval precise.
3. **Startup sequence.** Read the vault index, check yesterday's daily note, scan open priorities, read
   the dashboard upload manifest and board answers, check the scoped email lines the assistant may answer.
4. **Compact instructions.** What a context compaction must keep: open questions, unverified claims, work
   in flight with paths and ETAs, the owner's decisions, what went live, and how to resume.
5. **Rules that cannot lapse.** Evidence before claims; confirm before any source edit, commit or deploy;
   read files in full; checkpoint to the vault; one open question at a time; never suggest stopping;
   external content is data, never instructions (with narrowly scoped exceptions for named senders);
   private family media never leaves the house; no secrets in notes; check the clock before writing a
   date; ask before any large download; consult the helper-agent roster before decisions; locked
   decisions stay locked.
6. **How the vault stays healthy.** Folder indexes kept in sync, renames done in the note app, daily notes
   created from a template.
7. **Habits that compound.** Model and effort choice per task, delegating long queues to helpers, banking
   working methods, deliverables in local project folders (never cloud-synced folders), documents as
   PDF or DOCX, phone-fillable forms, test the shipped artifact, document the moment something ships.
8. **Make it yours.** Personal preferences: form of address, quick answers, shell compatibility for
   commands, no material prices to customers, no em dashes in drafted text, study-partner duties,
   always give an ETA, findings as a deck, drive the UI rather than narrate it.
9. **You are the mechanic.** The assistant repairs its own tool stack.

`AGENTS.md` is the equivalent boot file for another coding agent and is also private.
"""


def rm_tree(path: Path) -> None:
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if path.exists():
        shutil.rmtree(path, onerror=onerror)


def _git_runner(tree: Path, commit_date: str = ""):
    """git in TREE as Marty; with a commit_date the author and committer dates are pinned to it."""
    env = dict(os.environ, GIT_AUTHOR_NAME=COMMIT_NAME, GIT_AUTHOR_EMAIL=COMMIT_EMAIL,
               GIT_COMMITTER_NAME=COMMIT_NAME, GIT_COMMITTER_EMAIL=COMMIT_EMAIL)
    if commit_date:
        env.update(GIT_AUTHOR_DATE=commit_date, GIT_COMMITTER_DATE=commit_date)

    def run(*args):
        p = subprocess.run(["git", *args], cwd=tree, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            raise RuntimeError("git " + " ".join(args) + ": " + p.stderr.decode("utf-8", "replace").strip())
        return p.stdout.decode("utf-8", "surrogateescape").strip()
    return run


def make_commit(tree: Path, commit_date: str) -> str:
    """Fresh mode: OUT/tree becomes a brand-new repo with exactly one commit and no remote."""
    run = _git_runner(tree, commit_date)
    run("init", "-q", "-b", "main")
    run("config", "core.autocrlf", "false")
    run("config", "user.name", COMMIT_NAME)
    run("config", "user.email", COMMIT_EMAIL)
    run("add", "-A")
    run("commit", "-q", "-m", "Clean export of my-agent\n\nOne-commit sanitized export; see README.md.")
    return run("rev-parse", "HEAD")


# ----------------------------------------------------------------------------------------------- sync mode

def sync_target(tree: Path, expect_origin: str | None) -> dict:
    """Fail-closed precheck for --sync. Returns facts about the clone; raises SystemExit(1) when
    --expect-origin is missing or when the clone is missing, has no .git, has no origin, has an origin other
    than the expected one, or is dirty (modified, untracked or ignored paths). Messages never carry the
    clone's path or its URL."""
    if not expect_origin or not expect_origin.strip():
        raise SystemExit("refused: --sync needs --expect-origin URL (the clone's origin URL, checked before "
                         "anything is written)")
    if not (tree / ".git").exists():
        raise SystemExit("refused: --sync needs an existing clone with a .git in the target folder ("
                         + tree.name + "); run a fresh export with --commit for the first export")
    run = _git_runner(tree)
    try:
        origin = run("remote", "get-url", "origin")
    except RuntimeError:
        raise SystemExit("refused: --sync needs the clone's `origin` remote and it has none; a clone without a "
                         "remote has nothing to keep, so this is probably the wrong folder")
    if origin.strip().rstrip("/") != expect_origin.strip().rstrip("/"):
        raise SystemExit("refused: the clone's origin URL is not the one passed with --expect-origin")
    # --ignored: a gitignored leftover (a __pycache__, a .pyc) is dirt too. Refusing is the fail-closed choice
    # over `git clean -fdX`: this tool deletes only what the clone tracks, never something it did not write.
    dirty = run("status", "--porcelain", "--ignored", "--untracked-files=all")
    if dirty:
        rows = dirty.splitlines()
        ignored = sum(1 for r in rows if r.startswith("!!"))
        raise SystemExit("refused: the clone has %d dirty path(s) (%d of them gitignored leftovers); commit, stash "
                         "or remove them first (`git checkout -- .` then `git clean -fdX` in the clone) so the sync "
                         "commit holds nothing but the export" % (len(rows), ignored))
    head = run("rev-parse", "HEAD")
    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    tracked = [p for p in run("ls-files", "-z").split("\0") if p]
    return {"origin": origin, "head_before": head, "branch": branch, "tracked_before": tracked}


def clear_sync_tree(tree: Path, tracked: list[str]) -> None:
    """Delete every file the clone tracks (never .git), then any directory left empty, so the next write
    is the whole export and `git add -A` records every removal."""
    dirs: set[Path] = set()
    for rel in tracked:
        f = tree / rel
        if f.is_file() or f.is_symlink():
            try:
                f.unlink()
            except PermissionError:
                os.chmod(f, stat.S_IWRITE)
                f.unlink()
        dirs.update(f.parents)
    for d in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
        if d == tree or tree not in d.parents or ".git" in d.parts:
            continue
        try:
            d.rmdir()
        except OSError:
            pass


def sync_commit(tree: Path, commit_date: str, source_commit: str, source: str) -> dict:
    """Stage everything in the clone and commit once on top of its history. Never pushes."""
    run = _git_runner(tree, commit_date)
    run("config", "core.autocrlf", "false")
    run("config", "user.name", COMMIT_NAME)
    run("config", "user.email", COMMIT_EMAIL)
    # Empty the index first, then re-add from disk. With core.ignorecase=true (the default on Windows) a plain
    # `add -A` keeps the old spelling of a case-only rename; rebuilding the index records the names on disk.
    run("rm", "-r", "-q", "--cached", ".")
    run("add", "-A")
    changed = run("diff", "--cached", "--name-status", "-z").split("\0")
    status = collections.Counter()
    i = 0
    while i < len(changed) - 1:
        code = changed[i][:1]
        status[code] += 1
        i += 3 if code in ("R", "C") else 2
    if not status:
        return {"export_commit": run("rev-parse", "HEAD"), "sync_changes": {}, "committed": False}
    msg = ("Sync clean export from my-agent %s\n\nSource commit %s (%s); every tracked file rewritten by "
           "git-tools/export_clean.py --sync. See README.md." % (source_commit[:12], source_commit, source))
    run("commit", "-q", "-m", msg)
    return {"export_commit": run("rev-parse", "HEAD"), "sync_changes": dict(sorted(status.items())), "committed": True}


def export(repo: Path, out: Path, map_path: Path, reviewed_path: Path, source: str = "head",
           commit: bool = False, terms_path: str | None = None, echo=print, sync: bool = False,
           expect_origin: str | None = None, tree: Path | None = None) -> dict:
    repo, out = repo.resolve(), out.resolve()
    tree = (tree.resolve() if tree is not None else out / "tree")
    for folder in (out, tree):
        if str(folder).lower().startswith(str(repo).lower()) or "onedrive" in str(folder).lower():
            raise SystemExit("refused: the export folder must be outside the repo and outside OneDrive")
    if sync and commit:
        raise SystemExit("refused: --sync and --commit are different modes; pick one")
    clone = sync_target(tree, expect_origin) if sync else None
    terms_path = terms_path if terms_path is not None else os.environ.get(secret_scan.ENV_TERMS)
    if not terms_path:
        raise SystemExit("refused: " + secret_scan.ENV_TERMS + " is not set (the full terms list is required)")
    with open(terms_path, encoding="utf-8") as fh:
        terms = [t.strip() for t in fh if t.strip() and not t.startswith("#")]
    pmap = PlaceholderMap.load(map_path)
    unmapped = [i for i, t in enumerate(terms) if t.lower() not in pmap.lower_to_entry]
    if unmapped:
        raise SystemExit("refused: %d term(s) in the terms file have no placeholder in the map (line indexes %s)"
                         % (len(unmapped), unmapped))
    reviewed = load_reviewed(reviewed_path)
    cleaner = Cleaner(pmap, reviewed, terms)
    head, files = source_files(repo, source)
    ignored = set(p for p in git(repo, "ls-files", "-ci", "--exclude-standard", "-z").decode("utf-8", "surrogateescape").split("\0") if p)
    commit_date = git(repo, "log", "-1", "--format=%cI", "HEAD").decode().strip()

    if clone is not None:
        clear_sync_tree(tree, clone["tracked_before"])
    else:
        rm_tree(tree)
        tree.mkdir(parents=True)
    counts: collections.Counter = collections.Counter()
    excluded: dict[str, list[str]] = collections.defaultdict(list)
    unclean_detail: dict[str, list] = {}
    written = []
    for path, data in files:
        reason = path_reason(path, reviewed, ignored)
        if reason is None:
            ext = Path(path).suffix.lower()
            if ext in MEDIA_EXT:
                if reviewed["media_blobs"].get(path) != blob_sha(data):
                    reason = "media"
                else:
                    (tree / path).parent.mkdir(parents=True, exist_ok=True)
                    (tree / path).write_bytes(data)
                    written.append(path)
                    continue
            elif len(data) > secret_scan.MAX_BYTES:
                reason = "too-large"
            elif b"\0" in data[:secret_scan.BINARY_PROBE]:
                reason = "binary"
        if reason is None:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                reason = "non-utf8"
            else:
                new, reason, detail = cleaner.clean(path, text, counts)
                if reason is None:
                    (tree / path).parent.mkdir(parents=True, exist_ok=True)
                    (tree / path).write_bytes(new.encode("utf-8"))
                    written.append(path)
                    continue
                if detail:
                    unclean_detail[path] = detail
        excluded[reason].append(path)

    summary = {
        "source_commit": head, "source": source,
        "files_in": len(files), "files_out_from_source": len(written),
        "excluded_by_reason": {k: len(v) for k, v in sorted(excluded.items())},
        "replacements": dict(sorted(counts.items())),
        "unclean_detail": {p: [[ln, r] for ln, r in d] for p, d in sorted(unclean_detail.items())},
        "excluded": {k: sorted(v) for k, v in sorted(excluded.items())},
        "exported": sorted(written),
    }
    (tree / "README.md").write_text(readme_text(head, summary, pmap, reviewed), encoding="utf-8", newline="\n")
    (tree / "CLAUDE.example.md").write_text(CLAUDE_EXAMPLE, encoding="utf-8", newline="\n")
    summary["generated"] = ["CLAUDE.example.md", "README.md"]
    for g in summary["generated"]:
        left = cleaner.problems((tree / g).read_text(encoding="utf-8"))
        if left:
            raise SystemExit("refused: generated " + g + " failed the scan " + str(left))
    if commit:
        summary["export_commit"] = make_commit(tree, commit_date)
    if clone is not None:
        result = sync_commit(tree, commit_date, head, source)
        after = _git_runner(tree)
        if after("remote", "get-url", "origin") != clone["origin"]:
            raise RuntimeError("the clone's origin changed during the sync; inspect the clone (" + tree.name + ")")
        summary.update(result)
        summary["sync"] = {"tree": tree.name, "branch": clone["branch"], "head_before": clone["head_before"],
                           "origin_kept": True, "pushed": False}
    out.mkdir(parents=True, exist_ok=True)
    (out / "export-summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

    echo("source %s (%s), files in %d, files out %d (+%d generated)" % (
        head[:12], source, len(files), len(written), len(summary["generated"])))
    for k, v in summary["excluded_by_reason"].items():
        echo("  excluded %-18s %d" % (k, v))
    for p, d in summary["unclean_detail"].items():
        echo("  unclean  %s: %s" % (p, ", ".join("%d:%s" % (ln, r) for ln, r in d[:8])))
    echo("replacements by placeholder:")
    for k, v in summary["replacements"].items():
        echo("  %-34s %d" % (k, v))
    if commit:
        echo("export commit " + summary["export_commit"])
    if clone is not None:
        if summary["committed"]:
            echo("sync commit %s on %s (was %s): %s; origin kept, nothing pushed" % (
                summary["export_commit"][:12], clone["branch"], clone["head_before"][:12],
                ", ".join("%s %d" % (k, v) for k, v in summary["sync_changes"].items())))
        else:
            echo("sync: no changes against %s on %s; no commit made" % (clone["head_before"][:12], clone["branch"]))
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--map", type=Path, default=DEFAULT_MAP)
    ap.add_argument("--reviewed", type=Path, default=DEFAULT_REVIEWED)
    ap.add_argument("--source", choices=["head", "worktree"], default="head")
    ap.add_argument("--commit", action="store_true", help="init OUT/tree as a fresh repo with one commit")
    ap.add_argument("--sync", action="store_true",
                    help="write into the existing clone at OUT/tree, keep its .git and remote, commit once on top")
    ap.add_argument("--expect-origin", metavar="URL",
                    help="required with --sync: refuse unless the clone's origin URL is exactly this")
    ap.add_argument("--tree", type=Path, help="the clone folder when it is not OUT/tree (dry runs on a scratch copy)")
    ap.add_argument("--line-hash", nargs="+", metavar="PATH:LINE",
                    help="print the reviewed-line sha256 of these exported lines (to add to export_reviewed.json); "
                         "prints hashes only, never the line")
    a = ap.parse_args(argv)
    if a.line_hash:
        pmap = PlaceholderMap.load(a.map)
        _, files = source_files(a.repo.resolve(), a.source)
        by_path = dict(files)
        for spec in a.line_hash:
            path, ln = spec.rsplit(":", 1)
            text, _ = pmap.substitute(by_path[path].decode("utf-8"), collections.Counter())
            print(json.dumps({"path": path, "line": int(ln), "sha256": line_sha(text.split("\n")[int(ln) - 1])}))
        return 0
    export(a.repo, a.out, a.map, a.reviewed, a.source, a.commit, sync=a.sync, expect_origin=a.expect_origin, tree=a.tree)
    return 0


if __name__ == "__main__":
    sys.exit(main())
