#!/usr/bin/env python3
"""Pre-commit secret scan for Marty's repos. Pure standard library, Python 3.11+.

Usage:
    secret_scan.py                  scan the files staged for commit (the index, not the worktree)
    secret_scan.py PATH [PATH ...]  scan these files or directories on disk
    secret_scan.py --all-tracked    scan every file git tracks
    secret_scan.py --list-rules     print the rule names and what they catch

Exit 0 when clean, 1 when something was refused (one line per hit: path:line: rule (masked text)),
2 when the scan itself could not run. Rules, the ignore file, the allow comment and the config are
described in the RULES table and the module docstrings below.

Files that never get scanned: binary files (a NUL byte in the first 8 KiB), files over 5 MB, and paths
matching a gitignore-style `.secretscanignore` at the repo root. A line containing `secret-scan: allow`
is never reported (use it on test fixtures that must look like a secret).

Private terms come from the file named by the MARTY_PRIVATE_TERMS environment variable (one term per
line, case-insensitive, whole-word). That file is never in the repo. When the variable is unset the
scan prints one warning and carries on without that rule.

Optional config `.secretscan.json` at the repo root:
    {"allowed_emails": ["someone@example.com"], "allowed_email_domains": ["example.org"]}
"""
from __future__ import annotations

import bisect
import fnmatch
import json
import os
import re
import subprocess
import sys
import time

MAX_BYTES = 5 * 1024 * 1024
BINARY_PROBE = 8192
ALLOW_RE = re.compile(r"secret-scan:\s*allow")
KEYWORD_RE = re.compile(r"(?i)(?<![a-z])(?:key|token|secret)")
PLACEHOLDER_RE = re.compile(r"(?i)\*\*\*|xxxx|placeholder|redacted|changeme")
IGNORE_FILE = ".secretscanignore"
CONFIG_FILE = ".secretscan.json"
ENV_TERMS = "MARTY_PRIVATE_TERMS"
DEFAULT_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example", "localhost", "invalid", "test")

# Each rule: (name, compiled regex, needs_keyword). needs_keyword rules only count on a line that
# mentions key/token/secret. Group 1 (when present) is the text that gets masked in the report.
RULES = [
    ("api-key", re.compile(
        r"(?<![A-Za-z0-9_\-])("
        r"sk-ant-[A-Za-z0-9_\-]{12,}|sk-[A-Za-z0-9_\-]{12,}|tk_[A-Za-z0-9_\-]{12,}|ghp_[A-Za-z0-9]{12,}"
        r"|github_pat_[A-Za-z0-9_]{12,}|xai-[A-Za-z0-9_\-]{12,}|AIza[A-Za-z0-9_\-]{12,}"
        r"|xoxb-[A-Za-z0-9\-]{12,}|r8_[A-Za-z0-9]{12,})"), False),
    ("pem-block", re.compile(r"(-----BEGIN [A-Z0-9 ]{2,40}-----)"), False),
    ("bearer-token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_.=+/\-]{20,})(?![A-Za-z0-9_.=+/\-])"), False),
    ("credential-assignment", re.compile(
        r"(?i)(?<![A-Za-z0-9])(?:password|passphrase|secret|token|api[_\-]?key)s?[\"']?\s*[=:]\s*"
        r"[\"']((?![<$%{])[^\"'\n]{9,})[\"']"), False),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,})"), False),
    ("hex-near-keyword", re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32,})(?![0-9A-Fa-f])"), True),
    ("base64-near-keyword", re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])"), True),
    ("private-ip", re.compile(
        r"(?<![0-9.])("
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}"
        r"|169\.254\.\d{1,3}\.\d{1,3}"
        r")(?![0-9])"), False),
    ("email", re.compile(r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)(?![A-Za-z0-9\-])"), False),
]
RULE_HELP = [
    ("api-key", "sk-, sk-ant-, tk_, ghp_, github_pat_, xai-, AIza, xoxb-, r8_ followed by 12 or more key characters"),
    ("pem-block", "a -----BEGIN ...----- PEM header (private keys, certificates)"),
    ("bearer-token", "Bearer followed by a token of 20+ characters"),
    ("credential-assignment", "password/passphrase/secret/token/api_key = or : a quoted value longer than 8 characters"),
    ("jwt", "a three-part eyJ... JSON web token"),
    ("hex-near-keyword", "a hex string of 32+ characters on a line mentioning key, token or secret"),
    ("base64-near-keyword", "a base64 run of 40+ characters on a line mentioning key, token or secret"),
    ("private-ip", "a private IPv4 address (10/8, 172.16/12, 192.168/16, 100.64/10 tailnet, 169.254/16); loopback and documentation ranges pass"),
    ("email", "an email address not on the allow-list (.secretscan.json; example.com and friends pass)"),
    ("private-term", "a term listed in the file named by " + ENV_TERMS + " (whole word, case-insensitive)"),
]


def mask(text: str) -> str:
    return text[:4] + "****"


def to_posix(path: str) -> str:
    return path.replace("\\", "/")


# ----------------------------------------------------------------------------------------------- ignore file

def _glob_to_regex(pattern: str) -> str:
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


class IgnoreRules:
    """A small gitignore-style matcher: comments, blank lines, negation, anchoring, dir-only, ** globs.
    Paths are repo-relative with forward slashes. The last matching pattern wins."""

    def __init__(self, text: str = ""):
        self.rules: list[tuple[re.Pattern, bool]] = []
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line or line.lstrip().startswith("#"):
                continue
            negate = line.startswith("!")
            if negate:
                line = line[1:]
            if line.startswith("\\") and len(line) > 1:
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.strip("/") if dir_only else line
            anchored = line.startswith("/") or "/" in line.rstrip("/")
            line = line.lstrip("/")
            if not line:
                continue
            body = _glob_to_regex(line)
            tail = "/.*" if dir_only else "(?:/.*)?"
            head = "^" if anchored else "(?:^|.*/)"
            self.rules.append((re.compile(head + body + tail + "$"), negate))

    def ignored(self, relpath: str) -> bool:
        result = False
        for regex, negate in self.rules:
            if regex.match(relpath):
                result = not negate
        return result


# ----------------------------------------------------------------------------------------------- scanner

class Scanner:
    def __init__(self, allowed_emails=(), allowed_domains=(), private_terms=()):
        self.allowed_emails = {e.lower() for e in allowed_emails}
        self.allowed_domains = {d.lower().lstrip(".") for d in DEFAULT_EMAIL_DOMAINS + tuple(allowed_domains)}
        terms = sorted({t.strip() for t in private_terms if t.strip()}, key=len, reverse=True)
        self.terms_re = re.compile(r"(?i)(?<!\w)(" + "|".join(re.escape(t) for t in terms) + r")(?!\w)") if terms else None

    def email_allowed(self, addr: str) -> bool:
        addr = addr.lower()
        if addr in self.allowed_emails:
            return True
        domain = addr.rsplit("@", 1)[1]
        parts = domain.split(".")
        return any(".".join(parts[i:]) in self.allowed_domains for i in range(len(parts)))

    def scan_text(self, text: str) -> list[tuple[int, str, str]]:
        """Returns (line_number, rule, masked_text) for every hit that is not allowed."""
        starts = [0] + [m.end() for m in re.finditer("\n", text)]
        line_cache: dict[int, tuple[str, bool, bool]] = {}

        def line_info(pos: int):
            idx = bisect.bisect_right(starts, pos) - 1
            info = line_cache.get(idx)
            if info is None:
                end = starts[idx + 1] - 1 if idx + 1 < len(starts) else len(text)
                line = text[starts[idx]:end]
                info = (line, bool(ALLOW_RE.search(line)), bool(KEYWORD_RE.search(line)))
                line_cache[idx] = info
            return idx + 1, info

        hits = []
        seen = set()
        for name, regex, needs_keyword in RULES:
            for m in regex.finditer(text):
                lineno, (line, allowed, has_keyword) = line_info(m.start())
                if allowed or (needs_keyword and not has_keyword):
                    continue
                matched = m.group(1) if m.groups() else m.group(0)
                if name == "email" and self.email_allowed(matched):
                    continue
                if name == "credential-assignment" and PLACEHOLDER_RE.search(matched):
                    continue          # a redacted or placeholder value, not a credential
                if name == "base64-near-keyword":
                    if re.fullmatch(r"[0-9A-Fa-f]+=*", matched):
                        continue          # pure hex is the hex rule's business
                    if not (re.search(r"\d", matched) and re.search(r"[a-z]", matched) and re.search(r"[A-Z]", matched)):
                        continue          # a real base64 secret mixes digits and both cases
                key = (lineno, name)
                if key not in seen:
                    seen.add(key)
                    hits.append((lineno, name, mask(matched)))
        if self.terms_re is not None:
            for m in self.terms_re.finditer(text):
                lineno, (line, allowed, _) = line_info(m.start())
                if allowed:
                    continue
                key = (lineno, "private-term")
                if key not in seen:
                    seen.add(key)
                    hits.append((lineno, "private-term", mask(m.group(1))))
        hits.sort()
        return hits

    def scan_bytes(self, data: bytes) -> list[tuple[int, str, str]] | None:
        """None when the content is skipped (binary or too large)."""
        if len(data) > MAX_BYTES or b"\0" in data[:BINARY_PROBE]:
            return None
        return self.scan_text(data.decode("utf-8", errors="replace"))


# ----------------------------------------------------------------------------------------------- git plumbing

def git(root: str | None, *args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(["git", *args], cwd=root, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError("git " + " ".join(args) + " failed: " + proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


def repo_root(start: str) -> str | None:
    try:
        return to_posix(git(start, "rev-parse", "--show-toplevel").decode("utf-8", "replace").strip())
    except (RuntimeError, OSError):
        return None


def staged_paths(root: str) -> list[str]:
    out = git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def tracked_paths(root: str) -> list[str]:
    out = git(root, "ls-files", "-z")
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def staged_contents(root: str, paths: list[str]):
    """Yields (path, bytes_or_None) for the index version of each path, in one git process.

    One request is written and its reply fully read before the next is sent. Writing every request up
    front deadlocks as soon as the replies outgrow the pipe buffer (4 KB on Windows, 64 KB on Linux):
    git blocks on stdout while this side still blocks on stdin."""
    if not paths:
        return
    proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert proc.stdin is not None and proc.stdout is not None
    try:
        for path in paths:
            try:
                proc.stdin.write((":" + path + "\n").encode("utf-8"))
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                yield path, None           # git went away; the caller reads the file from disk instead
                continue
            header = proc.stdout.readline().decode("utf-8", "replace").rstrip("\n")
            parts = header.split()
            if len(parts) != 3 or parts[1] != "blob":
                yield path, None           # missing or not a blob (submodule); nothing to scan
                continue
            size = int(parts[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)            # the trailing newline
            yield path, data
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.wait()


def walk_paths(paths: list[str]) -> list[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = sorted(d for d in dirnames if d != ".git")
                files.extend(os.path.join(dirpath, f) for f in sorted(filenames))
        else:
            files.append(p)
    return files


# ----------------------------------------------------------------------------------------------- main

def load_config(root: str | None) -> tuple[list[str], list[str]]:
    if root is None:
        return [], []
    path = os.path.join(root, CONFIG_FILE)
    if not os.path.isfile(path):
        return [], []
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    return list(cfg.get("allowed_emails", [])), list(cfg.get("allowed_email_domains", []))


def load_ignore(root: str | None) -> IgnoreRules:
    if root is None:
        return IgnoreRules()
    path = os.path.join(root, IGNORE_FILE)
    if not os.path.isfile(path):
        return IgnoreRules()
    with open(path, encoding="utf-8") as fh:
        return IgnoreRules(fh.read())


def load_private_terms(warn) -> list[str]:
    path = os.environ.get(ENV_TERMS)
    if not path:
        warn("warning: " + ENV_TERMS + " is not set; the private-terms rule is off for this run")
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError as exc:
        raise RuntimeError(ENV_TERMS + " points at a file that cannot be read (" + exc.strerror + "): " + path)


def main(argv: list[str] | None = None, stdout=None, stderr=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    for stream in (out, err):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="backslashreplace")
            except (ValueError, AttributeError):
                pass

    def warn(msg: str) -> None:
        print(msg, file=err)

    if "-h" in argv or "--help" in argv:
        print(__doc__, file=out)
        return 0
    if "--list-rules" in argv:
        for name, text in RULE_HELP:
            print(name.ljust(24) + text, file=out)
        return 0
    timing = "--timing" in argv
    all_tracked = "--all-tracked" in argv
    paths = [a for a in argv if a not in ("--all-tracked", "--timing")]
    if paths and all_tracked:
        warn("error: give either --all-tracked or paths, not both")
        return 2

    started = time.perf_counter()
    root = repo_root(os.getcwd())
    try:
        ignore = load_ignore(root)
        allowed_emails, allowed_domains = load_config(root)
        scanner = Scanner(allowed_emails, allowed_domains, load_private_terms(warn))
        if paths:
            items = []
            for p in walk_paths(paths):
                try:
                    rel = to_posix(os.path.relpath(os.path.abspath(p), root)) if root else to_posix(p)
                except ValueError:        # another drive on Windows: no repo-relative name, so no ignore match
                    rel = to_posix(p)
                items.append((to_posix(p), rel, None))
        elif all_tracked:
            if root is None:
                warn("error: --all-tracked needs a git repository")
                return 2
            items = [(p, p, None) for p in tracked_paths(root)]
        else:
            if root is None:
                warn("error: not inside a git repository, so there is nothing staged to scan; give paths instead")
                return 2
            staged = staged_paths(root)
            items = [(p, p, data) for p, data in staged_contents(root, staged)]
    except RuntimeError as exc:
        warn("error: " + str(exc))
        return 2

    hits = 0
    scanned = 0
    for shown, rel, data in items:
        if ignore.ignored(rel):
            continue
        if data is None:
            disk = os.path.join(root, rel) if (root and not paths) else shown
            try:
                if os.path.getsize(disk) > MAX_BYTES:
                    continue
                with open(disk, "rb") as fh:
                    data = fh.read()
            except OSError as exc:
                warn("warning: could not read " + shown + " (" + exc.strerror + ")")
                continue
        found = scanner.scan_bytes(data)
        if found is None:
            continue
        scanned += 1
        for lineno, rule, masked in found:
            print(shown + ":" + str(lineno) + ": " + rule + " (" + masked + ")", file=out)
            hits += 1
    if timing:
        warn("scanned %d files in %.2fs" % (scanned, time.perf_counter() - started))
    if hits:
        print("secret scan: refused " + str(hits) + " line" + ("" if hits == 1 else "s") + " in "
              + str(scanned) + " file" + ("" if scanned == 1 else "s"), file=err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
