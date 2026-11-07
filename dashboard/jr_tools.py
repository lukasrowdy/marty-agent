"""
Marty Jr.'s tools and path fence (MJ Dashboard Phase 2, workstream W2, 2026-09-25).

Jr runs on a local abliterated model, so none of his safety lives in the model. It lives
here, in code the model cannot talk its way around:

  * Registered tools: library_search, vault_search, read_file, calc, save_draft,
    spiderfoot and computer. Host internet tools remain disabled;
    an armed VM session exposes only computer and check_in.
    There is no general shell, email or delete tool, and any
    other tool name is refused. At most MAX_CALLS_PER_TURN calls per turn (the Toolbox
    counts them; jr_lane counts them too).
  * Read roots (read-only): my-agent/jr/library, the Obsidian vault, and
    my-agent/private/business (the ONLY part of private/ Jr may see). Write root:
    my-agent/jr/drafts, new files only, never an overwrite, size-capped.
  * Every path is checked here before anything opens it (Fence.check_read):
      - lexical: no UNC or device paths (\\\\server, \\\\?\\, \\\\.\\, \\??\\), no ':' except
        the drive's (so no alternate data streams and no drive-relative "C:x"), no
        8.3 short names ('~' + digit), no '.' or '..' components, no component ending in
        a dot or space (Windows silently strips those, which would dodge the deny rules),
        no reserved device names (CON, NUL, COM1...), no wildcard characters;
      - containment: the absolute path must sit inside an allowed root (case-insensitive);
      - deny rules inside every root: .env, *.key, *.pem (and other key files), anything
        named like credentials/tokens/secrets/passwords, dashboard-devices.jsonl, Jr's key
        material, my-agent/jr/history, and config folders (.obsidian, .git, .ssh...);
      - links: no component of the path, from the drive down, may be a symlink, junction
        or any other reparse point, and the final real path must equal the checked one;
      - files: text types only, no NUL bytes, no hard-linked files (a hard link is the one
        link that is not a reparse point), and what comes back is capped at READ_CAP_BYTES
        with a note.
  * Nothing here writes a log. vault_search is a plain scan with no query logger (Marty's
    own marty_tools.search_vault logs to logs/marty-tools.log; Jr must never touch it).
    save_draft writes under jr/drafts. SpiderFoot uses temporary working files,
    removed after scans, and external OSINT requests; see jr_spiderfoot.py.

    py jr_tools.py selftest     adversarial fence tests in a temp dir, then real-root checks
"""

from __future__ import annotations

import ast
import fnmatch
import heapq
import json
import math
import operator
import os
import pathlib
import re
import stat
import time
import jr_spiderfoot
import jr_computer
from datetime import datetime

AGENT_ROOT = pathlib.Path(os.environ.get("MARTY_AGENT_ROOT")
                          or pathlib.Path(__file__).resolve().parent.parent)
VAULT_ROOT = pathlib.Path("C:/Users/{{WIN_USER}}/marty-vault")
LIBRARY_ROOT = AGENT_ROOT / "jr" / "library"
BUSINESS_ROOT = AGENT_ROOT / "private" / "business"
DRAFTS_ROOT = AGENT_ROOT / "jr" / "drafts"
HISTORY_DIR = AGENT_ROOT / "jr" / "history"      # W3's encrypted store: never readable by Jr

MAX_CALLS_PER_TURN = 6
READ_CAP_BYTES = 200 * 1024
PATH_MAX = 1024
SEARCH_MAX_HITS = 25
SEARCH_PER_FILE_HITS = 5       # best lines kept per file while scanning
SEARCH_POOL = 200              # best lines kept overall while scanning (trimmed as it goes)
SEARCH_MAX_FILES = 4000
SEARCH_FILE_BYTES = 1024 * 1024
SEARCH_SECONDS = 8
QUERY_MAX = 200
DRAFT_MAX_CHARS = 100_000
DRAFT_TITLE_MAX = 120
DRAFTS_MAX_FILES = 1000
CALC_MAX_CHARS = 200
CALC_MAX_NODES = 200
CALC_MAX_INT_BITS = 4096

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
TEXT_EXTS = {".md", ".markdown", ".txt", ".text", ".csv", ".tsv", ".json", ".yaml", ".yml",
             ".html", ".htm", ".xml", ".rst", ".org", ".tex"}
DENY_NAME_PATTERNS = (".env", ".env.*", "*.env", "*.key", "*.pem", "*.pfx", "*.p12", "*.kdbx",
                      "*.keystore", "*.jks", "*.salt", "id_rsa*", "id_dsa*", "id_ecdsa*",
                      "id_ed25519*", "dashboard-devices.jsonl", "jr-key*", "jr_key*", "jrkey*")
DENY_NAME_WORDS = ("credential", "token", "secret", "password", "passwd", "apikey", "api_key",
                   "api-key", "private_key", "private-key", "privatekey")
DENY_DIR_NAMES = (".obsidian", ".git", ".trash", ".ssh", ".aws", ".gnupg", ".azure", ".kube")
RESERVED_NAMES = {"con", "prn", "aux", "nul", "conin$", "conout$", "clock$"} | \
                 {f"com{i}" for i in range(10)} | {f"lpt{i}" for i in range(10)}
_SHORT_NAME = re.compile(r"~\d")
_BAD_CHARS = set('<>"|?*')
_DRAFT_NAME = re.compile(r"^\d{8}-\d{6}-[a-z0-9-]{1,60}(-\d{1,4})?\.md\Z")


class Refused(Exception):
    """A request the fence or the toolbox will not serve. Reported to the model as a
    REFUSED result, never a crash, and never with file contents in it."""


# ---------------------------------------------------------------------------- the fence

def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _inside(child_nc: str, root_nc: str) -> bool:
    return child_nc == root_nc or child_nc.startswith(root_nc.rstrip("\\/") + os.sep)


def _is_link(st) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool((getattr(st, "st_file_attributes", 0) or 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def lexical(raw) -> str:
    """The path text with forward slashes, or Refused. Pure string checks: nothing on disk
    is touched, so a refused path never even reveals whether it exists."""
    if not isinstance(raw, str):
        raise Refused("the path must be text")
    s = raw.strip()
    if not s:
        raise Refused("empty path")
    if len(s) > PATH_MAX:
        raise Refused("path too long")
    if any(ord(c) < 32 for c in s):
        raise Refused("control characters in the path")
    t = s.replace("\\", "/")
    if t.startswith("//") or "/??/" in t or t.startswith("/??") or "//?/" in t or "//./" in t:
        raise Refused("network and device paths are not allowed")
    if t.startswith("/"):
        raise Refused("give a full path with its drive letter, or a path inside Jr's folders")
    drive = len(t) >= 2 and t[1] == ":" and t[0].isalpha()
    if drive and not (len(t) >= 3 and t[2] == "/"):
        raise Refused("drive-relative paths are not allowed")
    if ":" in (t[2:] if drive else t):
        raise Refused("':' is only allowed after the drive letter (no alternate data streams)")
    parts = [p for p in (t[3:] if drive else t).split("/") if p != ""]
    if not parts:
        raise Refused("that is a drive, not a file")
    for part in parts:
        if part in (".", ".."):
            raise Refused("'.' and '..' are not allowed in paths")
        if part.endswith(".") or part.endswith(" "):
            raise Refused("a path part may not end in a dot or a space")
        if _SHORT_NAME.search(part):
            raise Refused("8.3 short names are not allowed; use the full name")
        if any(c in _BAD_CHARS for c in part):
            raise Refused("wildcard characters are not allowed in paths")
        if part.split(".", 1)[0].lower() in RESERVED_NAMES:
            raise Refused("reserved device names are not allowed")
    return (t[:3] if drive else "") + "/".join(parts)


def denied_name(part: str) -> str | None:
    """Why one path component is denied, or None."""
    low = part.lower()
    if low in DENY_DIR_NAMES:
        return "a config folder Jr may not read"
    if any(fnmatch.fnmatch(low, pat) for pat in DENY_NAME_PATTERNS):
        return "a key, secret or device file"
    if any(word in low for word in DENY_NAME_WORDS):
        return "named like credentials, tokens or secrets"
    return None


class Fence:
    def __init__(self, read_roots, write_root, deny_dirs=()):
        self.read_roots = [os.path.abspath(str(r)) for r in read_roots]
        self.write_root = os.path.abspath(str(write_root))
        self.deny_dirs = [_norm(str(d)) for d in deny_dirs]

    # -- shared pieces
    def root_for(self, full: str) -> str | None:
        nc = os.path.normcase(full)
        for root in self.read_roots:
            if _inside(nc, os.path.normcase(root)):
                return root
        return None

    def _denied(self, full: str, root: str):
        nc = os.path.normcase(full)
        for d in self.deny_dirs:
            if _inside(nc, d):
                raise Refused("that folder is off limits to Jr")
        rel = os.path.relpath(full, root)
        if rel != ".":
            for part in pathlib.PureWindowsPath(rel).parts:
                why = denied_name(part)
                if why:
                    raise Refused(f"refused: {why}")

    @staticmethod
    def no_links(full: str, lstat=os.lstat):
        """Refuse if any existing component, from the drive down, is a symlink, junction or
        other reparse point. A component that does not exist ends the walk (not found is
        reported later)."""
        p = pathlib.PureWindowsPath(full)
        cur = pathlib.PureWindowsPath(p.anchor)
        for part in p.parts[1:]:
            cur = cur / part
            try:
                st = lstat(str(cur))
            except FileNotFoundError:
                return
            except OSError:
                raise Refused("a path component could not be checked")
            if _is_link(st):
                raise Refused("links, junctions and reparse points are not allowed")

    @staticmethod
    def same_real(full: str):
        """The real path must be the path that was checked (catches any redirection the
        component walk could not see, and expands any short name that slipped through)."""
        if os.path.lexists(full) and os.path.normcase(os.path.realpath(full)) != os.path.normcase(full):
            raise Refused("that path resolves somewhere else")

    # -- reads
    def check_read(self, raw) -> pathlib.Path:
        t = lexical(raw)
        if len(t) >= 3 and t[1] == ":":
            full = os.path.abspath(t)
        else:
            cands = [os.path.abspath(os.path.join(r, t)) for r in self.read_roots]
            full = next((c for c in cands if os.path.lexists(c)), cands[0] if cands else "")
            if not full:
                raise Refused("Jr has no readable folders configured")
        root = self.root_for(full)
        if root is None:
            raise Refused("outside Jr's folders (his library, the vault, and the business folder)")
        self._denied(full, root)
        self.no_links(full)
        self.same_real(full)
        return pathlib.Path(full)

    # -- writes
    def check_write_dir(self) -> pathlib.Path:
        root = self.write_root
        for d in self.deny_dirs:
            if _inside(os.path.normcase(root), d):
                raise Refused("the drafts folder is misconfigured")
        self.no_links(root)
        self.same_real(root)
        return pathlib.Path(root)


def default_fence() -> Fence:
    # jr_store honours MARTY_JR_HISTORY (a test server's temp history); deny that folder too.
    deny = [HISTORY_DIR] + ([pathlib.Path(os.environ["MARTY_JR_HISTORY"])] if os.environ.get("MARTY_JR_HISTORY") else [])
    return Fence([LIBRARY_ROOT, VAULT_ROOT, BUSINESS_ROOT], DRAFTS_ROOT, deny_dirs=deny)


# ---------------------------------------------------------------------------- reading

def _check_file(p: pathlib.Path) -> os.stat_result:
    if not os.path.lexists(p):
        raise FileNotFoundError(str(p))
    st = os.stat(p)
    if stat.S_ISDIR(st.st_mode):
        raise IsADirectoryError(str(p))
    if not stat.S_ISREG(st.st_mode):
        raise Refused("not a regular file")
    if p.suffix.lower() not in TEXT_EXTS:
        raise Refused(f"Jr reads text files only ({', '.join(sorted(TEXT_EXTS))})")
    if getattr(st, "st_nlink", 1) > 1:
        raise Refused("hard-linked files are not allowed")
    return st


def _same_file(checked: os.stat_result, opened: os.stat_result) -> bool:
    """The handle that was opened is the file that was checked (closes the gap between the
    fence's checks and open(): a swap to a link or another file in between is refused)."""
    return (checked.st_ino, checked.st_dev) == (opened.st_ino, opened.st_dev) and \
        getattr(opened, "st_nlink", 1) <= 1 and stat.S_ISREG(opened.st_mode)


def _read_text(p: pathlib.Path, cap: int) -> tuple[str, int, bool]:
    """(text, size on disk, truncated). Refused for anything that looks binary."""
    st = _check_file(p)
    with open(p, "rb") as f:
        if not _same_file(st, os.fstat(f.fileno())):
            raise Refused("the file changed while it was being opened")
        data = f.read(cap + 1)
    if b"\x00" in data[:8192]:
        raise Refused("that file looks binary; Jr reads text only")
    truncated = len(data) > cap or st.st_size > cap
    data = data[:cap]
    return data.decode("utf-8-sig", errors="replace"), st.st_size, truncated


def read_file(fence: Fence, path, start_line=None) -> tuple[str, str]:
    """(text for the model, short note). Raises Refused / FileNotFoundError / OSError."""
    p = fence.check_read(path)
    text, size, truncated = _read_text(p, READ_CAP_BYTES)
    lines = text.splitlines()
    first = 1
    if start_line is not None:
        try:
            first = max(1, int(start_line))
        except (TypeError, ValueError):
            raise Refused("start_line must be a whole number")
        lines = lines[first - 1:]
    body = "\n".join(lines)
    head = f"{p} ({size} bytes, lines {first}-{first + max(0, len(lines) - 1)})"
    note = ""
    if truncated:
        note = (f"\n[truncated: the file is {size} bytes; only the first {READ_CAP_BYTES // 1024} KB "
                f"is available to Jr]")
    return f"{head}\n{body}{note}", f"read {len(lines)} lines"


# ---------------------------------------------------------------------------- searching

def _terms(query) -> list[str]:
    if not isinstance(query, str) or not query.strip():
        raise Refused("give a search query")
    if len(query) > QUERY_MAX:
        raise Refused(f"query too long (max {QUERY_MAX} characters)")
    words = [w for w in re.split(r"\s+", query.lower().strip()) if w]
    return words[:8]


def search(fence: Fence, root, query) -> tuple[str, str]:
    """Keyword search of text files under one read root. Lines holding the most query words
    come first. Every file goes through the same fence as read_file; nothing is logged."""
    terms = _terms(query)
    phrase = " ".join(terms)
    root = os.path.abspath(str(root))
    try:
        fence.check_read(root)          # the root itself must be clean (no links on its chain)
    except Refused as e:
        raise Refused(f"that folder is not available: {e}")
    if not os.path.isdir(root):
        return f"no matches: {root} does not exist yet", "0 hits"
    started, scanned, hits, stopped, matched = time.monotonic(), 0, [], "", 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            try:
                if denied_name(d) or _is_link(os.lstat(full)):
                    continue
            except OSError:
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)
        for name in sorted(filenames):
            if time.monotonic() - started > SEARCH_SECONDS:
                stopped = " (search stopped early: time limit)"
                break
            if scanned >= SEARCH_MAX_FILES:
                stopped = " (search stopped early: file limit)"
                break
            full = os.path.join(dirpath, name)
            if pathlib.Path(name).suffix.lower() not in TEXT_EXTS:
                continue
            try:
                p = fence.check_read(full)
                text, _size, _trunc = _read_text(p, SEARCH_FILE_BYTES)
            except (Refused, OSError):
                continue
            scanned += 1
            path_s = str(p)
            file_best = []          # bounded per file: a min-heap of the best SEARCH_PER_FILE_HITS lines
            low_name = name.lower()
            if all(t in low_name for t in terms):
                matched += 1
                heapq.heappush(file_best, (len(terms) + 2, 0, 0, "(file name matches)"))
            for i, line in enumerate(text.splitlines(), 1):
                low = line.lower()
                score = sum(1 for t in terms if t in low)
                if score:
                    if len(terms) > 1 and phrase in low:
                        score += 1
                    matched += 1
                    item = (score, -i, i, line.strip()[:200])       # higher score, then earlier line
                    if len(file_best) < SEARCH_PER_FILE_HITS:
                        heapq.heappush(file_best, item)
                    elif item[:2] > file_best[0][:2]:
                        heapq.heapreplace(file_best, item)
            hits.extend((sc, path_s, ln, tx) for sc, _neg, ln, tx in file_best)
            if len(hits) > SEARCH_POOL:
                hits.sort(key=lambda h: (-h[0], h[1], h[2]))
                del hits[SEARCH_POOL:]
        if stopped:
            break
    hits.sort(key=lambda h: (-h[0], h[1], h[2]))
    top = hits[:SEARCH_MAX_HITS]
    if not top:
        return f"no matches for {query!r} in {root} ({scanned} files searched){stopped}", "0 hits"
    lines = [f"{len(top)} of {matched} matching lines for {query!r} in {root}{stopped}:"]
    for _score, path, line_no, text in top:
        lines.append(f"{path}:{line_no}: {text}" if line_no else f"{path} {text}")
    return "\n".join(lines), f"{len(top)} hit" + ("" if len(top) == 1 else "s")


# ---------------------------------------------------------------------------- calc

_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
        ast.Pow: operator.pow}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _calc_node(node):
    if isinstance(node, ast.Expression):
        return _calc_node(node.body)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _UNARY[type(node.op)](_calc_node(node.operand))
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
        a, b = _calc_node(node.left), _calc_node(node.right)
        if isinstance(node.op, ast.Pow):
            if abs(b) > 1000 or (abs(a) > 1e6 and abs(b) > 64):
                raise ValueError("exponent too large")
        value = _BIN[type(node.op)](a, b)
        if isinstance(value, complex):
            raise ValueError("the result is not a real number")
        if isinstance(value, int) and value.bit_length() > CALC_MAX_INT_BITS:
            raise ValueError("the result is too large")
        return value
    raise ValueError(f"only numbers and + - * / // % ** ( ) are allowed, not {type(node).__name__}")


def calc(expression) -> tuple[str, str]:
    if not isinstance(expression, str) or not expression.strip():
        raise Refused("give an arithmetic expression")
    if len(expression) > CALC_MAX_CHARS:
        raise Refused(f"expression too long (max {CALC_MAX_CHARS} characters)")
    expr = expression.strip().rstrip("=").strip()
    expr = expr.replace("^", "**").replace("\u00d7", "*").replace("\u00f7", "/").replace("\u2212", "-")
    expr = re.sub(r"(?<=\d),(?=\d{3}(?!\d))", "", expr)          # 1,000 -> 1000
    try:
        tree = ast.parse(expr, mode="eval")
        if sum(1 for _ in ast.walk(tree)) > CALC_MAX_NODES:
            raise ValueError("expression too complex")
        value = _calc_node(tree)
    except ZeroDivisionError:
        raise Refused("division by zero")
    except (SyntaxError, ValueError, TypeError, OverflowError, RecursionError, MemoryError) as e:
        raise Refused(f"calc: {e}" if str(e) else "calc: not a valid arithmetic expression")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise Refused("calc: the result is not a finite number")
        out = format(value, ".12g")
    else:
        out = str(value)
    return f"{expression.strip()} = {out}", "done"


# ---------------------------------------------------------------------------- drafts

def _slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return (s[:60].strip("-")) or "draft"


def save_draft(fence: Fence, title, text, now=None) -> tuple[str, str]:
    """Write a NEW markdown file jr/drafts/<YYYYMMDD-HHMMSS>-<slug>.md. Never overwrites
    (exclusive create), never writes anywhere else (the name is built here, not taken from
    the model), and refuses oversized drafts or a full drafts folder."""
    if not isinstance(title, str) or not title.strip():
        raise Refused("give the draft a title")
    if not isinstance(text, str) or not text.strip():
        raise Refused("the draft is empty")
    if len(text) > DRAFT_MAX_CHARS:
        raise Refused(f"draft too long (max {DRAFT_MAX_CHARS} characters)")
    title = " ".join(title.split())[:DRAFT_TITLE_MAX]
    parent = os.path.dirname(fence.write_root)
    if not os.path.isdir(parent):
        raise Refused("the drafts folder's parent is missing")
    fence.no_links(parent)
    os.makedirs(fence.write_root, exist_ok=True)
    root = fence.check_write_dir()
    count = sum(1 for _ in os.scandir(root))
    if count >= DRAFTS_MAX_FILES:
        raise Refused(f"the drafts folder is full ({DRAFTS_MAX_FILES} files); ask Lukas to clear it")
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    base = f"{stamp}-{_slug(title)}"
    body = f"# {title}\n\n{text.rstrip()}\n"
    for n in range(0, 50):
        name = f"{base}.md" if n == 0 else f"{base}-{n + 1}.md"
        if not _DRAFT_NAME.match(name):
            raise Refused("could not build a safe file name")
        path = root / name
        if os.path.normcase(os.path.dirname(os.path.abspath(path))) != os.path.normcase(str(root)):
            raise Refused("could not build a safe file name")
        try:
            with open(path, "x", encoding="utf-8", newline="\n") as f:     # "x": never overwrite
                f.write(body)
        except FileExistsError:
            continue
        return f"saved a new draft: {path} ({len(body)} characters)", "saved"
    raise Refused("too many drafts with that name this second")


# ---------------------------------------------------------------------------- the toolbox

def _tool(name, description, props, required):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": props, "required": required}}}


def schema() -> list[dict]:
    """The tools as Ollama's /api/chat expects them."""
    q = {"query": {"type": "string", "description": "words to look for"}}
    return [
        _tool("check_in", "Pause the VM and give Lukas your results and proposed next five actions. This is never permission to continue.",
              {k:{"type":"string"} for k in ("completed","uncertain","next_steps","reason")},
              ["completed","uncertain","next_steps","reason"]),
        _tool("computer", "Control the dedicated Jr VM only, within the externally enforced five-action approval. First windows, then observe for screenshot and element tokens. Click/type/key/scroll only in listed apps. In filtered browsing use ctrl+l, type a permitted HTTPS address, Return. Coordinates are window-local pixels. Observe to verify results; use check_in when done or paused.",
              {"action": {"type":"string", "enum":["status","windows","observe","click","type","key","scroll"]},
               "window_id":{"type":"integer","description":"For the first observe, copy from windows. Later input defaults to that observed window."}, "element_token":{"type":"string","description":"Copy the token whose label matches the requested control, from the latest observe."},
               "x":{"type":"number"},"y":{"type":"number"},
               "text":{"type":"string"},"key":{"type":"string","description":"One key, such as Return or Tab. For shortcuts use keys."},"keys":{"type":"array","items":{"type":"string"},"description":"A permitted shortcut: Ctrl+L is [\"ctrl\",\"l\"]."},
               "direction":{"type":"string","enum":["up","down","left","right"]},"amount":{"type":"integer"}}, ["action"]),
        _tool("library_search", "Search Jr's own reference library (text files) for lines containing these words.",
              q, ["query"]),
        _tool("vault_search", "Search Lukas's Obsidian notes vault (read-only) for lines containing these words.",
              q, ["query"]),
        _tool("read_file", "Read a text file from Jr's library, the notes vault or the business folder "
                           "(read-only). Use a full path from a search result.",
              {"path": {"type": "string", "description": "full path of the file"},
               "start_line": {"type": "integer", "description": "optional: first line to show, to page through a long file"}},
              ["path"]),
        _tool("calc", "Evaluate arithmetic exactly: numbers, + - * / // % ** and parentheses.",
              {"expression": {"type": "string", "description": "for example (1200 * 0.08) / 12"}}, ["expression"]),
        _tool("save_draft", "Save a NEW markdown draft in Jr's drafts folder on this PC. It never sends, "
                            "publishes or overwrites anything.",
              {"title": {"type": "string", "description": "short title"},
               "text": {"type": "string", "description": "the draft's full text"}}, ["title", "text"]),
        _tool("spiderfoot", "Run the installed SpiderFoot OSINT tool. Use status to check installation/scans; "
              "modules to find module names; start for a scan (returns scan_id immediately); results to read "
              "findings; stop to cancel. Targets go to external sources. Passive is default. Scans have a "
              "180-second limit and are stopped/forgotten when Jr locks. No API keys are configured.",
              {"action": {"type": "string", "enum": ["status", "modules", "start", "results", "stop"]},
               "target": {"type": "string", "description": "One domain, IP, CIDR, ASN number, email, +phone, username, person name or Bitcoin address"},
               "mode": {"type": "string", "enum": ["passive", "footprint", "investigate", "all"], "description": "Default passive; explicit modules override mode. Active scans need an authorized target."},
               "modules": {"type": "array", "items": {"type": "string"}, "description": "Optional installed sfp_ module names, up to 30; use modules action to find names"},
               "scan_id": {"type": "string", "description": "ID returned by start/status"},
               "query": {"type": "string", "description": "Optional search text for modules action"},
               "offset": {"type": "integer", "description": "Pagination offset from next_offset"}}, ["action"]),
    ]


TOOL_NAMES = tuple(t["function"]["name"] for t in schema())


class ToolResult:
    __slots__ = ("name", "status", "note", "text", "images")

    def __init__(self, name, status, note, text, images=None):
        self.name, self.status, self.note, self.text = name, status, note, text
        self.images = images or []

    def event(self) -> dict:
        """What the browser may see: the tool's name and a short status. Never file text."""
        return {"tool": self.name, "status": self.status, "note": self.note}


def _args(raw) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else {}
        except ValueError:
            raise Refused("the tool arguments were not valid JSON")
    if not isinstance(raw, dict):
        raise Refused("the tool arguments must be an object")
    return raw


class Toolbox:
    """One turn's tools. Counts calls and refuses past max_calls; refuses unknown names."""

    def __init__(self, fence: Fence | None = None, max_calls: int = MAX_CALLS_PER_TURN):
        self.fence = fence or default_fence()
        self.max_calls = max_calls
        self.calls = 0
        self.computer_mode = jr_computer.MANAGER.active
        self.computer_thread = None
        self.spiderfoot_owner = None
        self.spiderfoot_turn = None
        self.spiderfoot_epoch = jr_spiderfoot.MANAGER.epoch
        self.spiderfoot_allowed = lambda: False

    def run(self, name, raw_args) -> ToolResult:
        name = name if isinstance(name, str) else repr(name)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:40] or "unknown"
        if name not in TOOL_NAMES:
            return ToolResult(safe_name, "refused", "unknown tool",
                              f"REFUSED: there is no tool named {safe_name!r}. Jr's only tools are "
                              f"{', '.join(TOOL_NAMES)}. There is no general shell, email or delete tool.")
        if name == "check_in":
            try:
                if not self.computer_mode or not self.spiderfoot_allowed():
                    raise Refused("Check-in requires an unlocked computer session")
                report = jr_computer.MANAGER.report(self.spiderfoot_owner, self.computer_thread, _args(raw_args))
                return ToolResult(name,"ok","paused for Lukas",json.dumps(report,ensure_ascii=False))
            except (Refused,ValueError,jr_computer.ComputerError) as e:
                return ToolResult(name,"refused","check-in refused",str(e))
        if self.calls >= self.max_calls:
            return ToolResult(name, "refused", "tool limit",
                              f"REFUSED: the limit of {self.max_calls} tool calls for this turn is used up. "
                              f"Answer with what you have.")
        self.calls += 1
        if name == "spiderfoot" and not jr_computer.INTERNET_ENABLED:
            return ToolResult(name,"refused","internet disabled","REFUSED: Lukas has not enabled internet access. Offline practice only.")
        if self.computer_mode and name != "computer":
            return ToolResult(name,"refused","offline practice","REFUSED: only the VM computer tool and check-in are available in this session")
        try:
            args = _args(raw_args)
            if name == "computer":
                if not self.spiderfoot_allowed():
                    raise Refused("Computer control needs an unlocked, active Jr turn")
                result, images = jr_computer.MANAGER.call(self.spiderfoot_owner, args, self.computer_thread)
                return ToolResult(name,"ok","supervised VM",json.dumps(result,ensure_ascii=False),images)
            if name == "library_search":
                text, note = search(self.fence, self.fence.read_roots[0], args.get("query"))
            elif name == "vault_search":
                text, note = search(self.fence, self.fence.read_roots[1], args.get("query"))
            elif name == "read_file":
                text, note = read_file(self.fence, args.get("path"), args.get("start_line"))
            elif name == "calc":
                text, note = calc(args.get("expression"))
            elif name == "spiderfoot":
                if not self.spiderfoot_allowed():
                    raise Refused("SpiderFoot needs an unlocked Jr conversation")
                result = jr_spiderfoot.MANAGER.call(self.spiderfoot_owner, self.spiderfoot_turn,
                                                   self.spiderfoot_epoch, args)
                text, note = json.dumps(result, ensure_ascii=False), result.get("state", "done")
            else:
                text, note = save_draft(self.fence, args.get("title"), args.get("text"))
            return ToolResult(name, "ok", note, text)
        except (Refused, jr_spiderfoot.ScanError, jr_computer.ComputerError) as e:
            return ToolResult(name, "refused", "refused", f"REFUSED: {e}")
        except FileNotFoundError:
            return ToolResult(name, "error", "not found", "ERROR: no such file")
        except IsADirectoryError:
            return ToolResult(name, "error", "is a folder", "ERROR: that is a folder; search it instead")
        except OSError as e:
            return ToolResult(name, "error", "error", f"ERROR: the file could not be read ({type(e).__name__})")
        except Exception as e:             # a tool bug is a result, never a dead turn
            return ToolResult(name, "error", "error", f"ERROR: {type(e).__name__}")


# ---------------------------------------------------------------------------- selftest

def selftest() -> bool:
    import builtins
    import ctypes
    import shutil
    import tempfile
    import _winapi

    fails, notes = [], []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    def refused(fn, *a, **k):
        try:
            fn(*a, **k)
            return False
        except Refused:
            return True

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="jr-tools-selftest-"))
    links = []                      # junctions to remove before rmtree (never follow them)
    try:
        agent = tmp / "my-agent"
        lib, vault = agent / "jr" / "library", tmp / "vault"
        biz, drafts, hist = agent / "private" / "business", agent / "jr" / "drafts", agent / "jr" / "history"
        chats, jack = agent / "private" / "chats", agent / "jack_marty_local"
        for d in (lib, vault, biz, drafts, hist, chats, jack, vault / "03 - Cyber", lib / "sub"):
            d.mkdir(parents=True, exist_ok=True)
        (lib / "README.md").write_text("Jr library\nthe reference shelf lives here\n", encoding="utf-8")
        (lib / "sub" / "notes.txt").write_text("alpha beta\ngamma\n", encoding="utf-8")
        (vault / "Active Priorities.md").write_text("# Active\nstudy week 5 firewall rules\n", encoding="utf-8")
        (vault / "03 - Cyber" / "Firewalls.md").write_text("firewall rules and NAT\n", encoding="utf-8")
        (biz / "Plan.md").write_text("business plan\n", encoding="utf-8")
        (chats / "private-chat.md").write_text("PRIVATE-CHAT-CANARY\n", encoding="utf-8")
        (jack / "state.md").write_text("JACK-CANARY\n", encoding="utf-8")
        (hist / "t1.bin").write_bytes(b"\x01\x02ciphertext")
        for bad in (".env", "a.key", "b.pem", "credentials.json", "my-tokens.md", "api_key.txt",
                    "dashboard-devices.jsonl", "jr-key.bin", "store.salt", "Secret plan.md"):
            (lib / bad).write_text("DENY-CANARY\n", encoding="utf-8")
        (lib / "secrets").mkdir()
        (lib / "secrets" / "x.md").write_text("DENY-CANARY\n", encoding="utf-8")
        (vault / ".obsidian").mkdir()
        (vault / ".obsidian" / "data.json").write_text('{"token": "DENY-CANARY"}', encoding="utf-8")  # secret-scan: allow [export-reviewed]
        (lib / "blob.md").write_bytes(b"text\x00\x01\x02 binary")
        (lib / "tool.exe").write_bytes(b"MZ")
        (lib / "big.md").write_text("line\n" * 70000, encoding="utf-8")      # 350 KB
        fence = Fence([lib, vault, biz], drafts, deny_dirs=[hist])
        tb = lambda: Toolbox(fence)      # noqa: E731

        print("reads inside the three roots work")
        check("reference shelf" in read_file(fence, str(lib / "README.md"))[0], "library file by full path")
        check("firewall" in read_file(fence, "Active Priorities.md")[0], "vault file by relative path")
        check("business plan" in read_file(fence, str(biz / "Plan.md"))[0], "business folder")
        upper = str(biz / "Plan.md").replace("private", "PRIVATE").replace("business", "Business")
        check("business plan" in read_file(fence, upper)[0], "business folder, any letter case")
        check("gamma" in read_file(fence, str(lib / "sub" / "notes.txt"))[0], "nested file")
        mixed = str(lib / "sub" / "notes.txt").replace("\\", "/")
        check("alpha" in read_file(fence, mixed)[0], "forward slashes")
        paged, _ = read_file(fence, str(lib / "sub" / "notes.txt"), start_line=2)
        check("gamma" in paged and "alpha" not in paged, "start_line pages")

        print("outside the roots is refused, without touching the file")
        for p in (chats / "private-chat.md", jack / "state.md", agent / "private" / "README.txt",
                  hist / "t1.bin", tmp / "vault-evil" / "x.md", agent / "jr" / "library-evil" / "x.md",
                  pathlib.Path("C:/Windows/win.ini")):
            check(refused(fence.check_read, str(p)), f"outside: {p.relative_to(tmp) if tmp in p.parents else p}")
        hist_fence = Fence([agent / "jr"], drafts, deny_dirs=[hist])
        check(refused(hist_fence.check_read, str(hist / "t1.bin")), "jr/history refused even under a read root")

        print("'..', '.', and trailing dot/space tricks are refused")
        for p in (f"{lib}/../../private/chats/private-chat.md", f"{lib}\\..\\..\\jack_marty_local\\state.md",
                  "../private/chats/private-chat.md", f"{lib}/./README.md", f"{lib}/a.key.", f"{lib}/a.key ",
                  f"{lib}/sub./notes.txt"):
            check(refused(fence.check_read, p), f"refused: {p[-40:]}")

        print("UNC, device, NT-object and drive-relative paths are refused")
        for p in (r"\\server\share\x.md", "//server/share/x.md", "\\\\?\\" + str(lib / "README.md"),
                  "\\\\.\\" + str(lib / "README.md"), "//?/" + str(lib / "README.md").replace("\\", "/"),
                  "\\??\\" + str(lib / "README.md"), "C:README.md", "/Users/x/README.md",
                  "\\\\localhost\\c$\\Windows\\win.ini"):
            check(refused(fence.check_read, p), f"refused: {p[:44]}")

        print("alternate data streams are refused")
        ads_target = lib / "README.md"
        try:
            with open(str(ads_target) + ":hidden", "w", encoding="utf-8") as f:
                f.write("ADS-CANARY")
            made_ads = True
        except OSError:
            made_ads = False
        for p in (str(ads_target) + ":hidden", str(ads_target) + "::$DATA", str(ads_target) + ":hidden:$DATA"):
            check(refused(fence.check_read, p), f"refused ADS: {p[-22:]}")
        if not made_ads:
            notes.append("ADS could not be created on this volume; refusal tested lexically only")

        print("8.3 short names are refused")
        longdir = lib / "Long Folder Name For Short"
        longdir.mkdir()
        (longdir / "inside.md").write_text("short name test\n", encoding="utf-8")
        buf = ctypes.create_unicode_buffer(1024)
        short = ctypes.windll.kernel32.GetShortPathNameW(str(longdir / "inside.md"), buf, 1024) and buf.value
        if short and "~" in short:
            check(refused(fence.check_read, short), f"real short name refused ({pathlib.Path(short).parent.name})")
        else:
            notes.append("8.3 names are disabled on this volume; tested the literal pattern")
        check(refused(fence.check_read, f"{lib}/LONGFO~1/inside.md"), "literal FOLDER~1 refused")
        check(refused(fence.check_read, "C:/PROGRA~1/x.md"), "PROGRA~1 refused")

        print("reserved names and wildcards are refused")
        for p in (f"{lib}/CON", f"{lib}/nul.txt", f"{lib}/com1.md", f"{lib}/*.md", f"{lib}/a?.md", f"{lib}/x<y.md"):
            check(refused(fence.check_read, p), f"refused: {p[-10:]}")

        print("deny rules inside the roots")
        for bad in (".env", "a.key", "b.pem", "credentials.json", "my-tokens.md", "api_key.txt",
                    "dashboard-devices.jsonl", "jr-key.bin", "store.salt", "Secret plan.md", "secrets/x.md"):
            check(refused(fence.check_read, str(lib / bad)), f"denied: {bad}")
        check(refused(fence.check_read, str(vault / ".obsidian" / "data.json")), "denied: .obsidian config")

        print("junctions, symlinks and reparse points are refused at any component")
        j_file_dir = lib / "jdir"                          # junction inside the library -> private/chats
        _winapi.CreateJunction(str(chats), str(j_file_dir))
        links.append(j_file_dir)
        check(refused(fence.check_read, str(j_file_dir / "private-chat.md")), "junction in the middle of the path")
        check(refused(fence.check_read, str(j_file_dir)), "junction as the last component")
        j_root = tmp / "jroot"                              # a root that is itself a junction: fails closed
        _winapi.CreateJunction(str(lib), str(j_root))
        links.append(j_root)
        jr_fence = Fence([j_root], drafts)
        check(refused(jr_fence.check_read, str(j_root / "README.md")), "a root reached through a junction")
        j_parent = tmp / "jparent"                          # a junction ABOVE the root
        _winapi.CreateJunction(str(agent), str(j_parent))
        links.append(j_parent)
        above = Fence([j_parent / "jr" / "library"], drafts)
        check(refused(above.check_read, str(j_parent / "jr" / "library" / "README.md")), "a junction above the root")
        try:
            os.symlink(chats / "private-chat.md", lib / "sl.md")
            links.append(lib / "sl.md")
            check(refused(fence.check_read, str(lib / "sl.md")), "real file symlink")
        except OSError:
            notes.append("real symlinks need a privilege this account lacks (WinError 1314); "
                         "the symlink branch is tested with a simulated lstat, junctions cover reparse points")
        fake = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        check(refused(Fence.no_links, str(lib / "README.md"),
                      lstat=lambda p: fake if p.endswith("library") else os.lstat(p)),
              "simulated symlink component (S_IFLNK)")
        check(refused(read_file, fence, str(j_file_dir / "private-chat.md")), "read_file refuses the junction too")

        print("hard links, binaries and non-text types are refused")
        os.link(chats / "private-chat.md", lib / "hard.md")
        check(refused(read_file, fence, str(lib / "hard.md")), "hard link to a private file")
        check(refused(read_file, fence, str(lib / "blob.md")), "NUL bytes (binary)")
        check(refused(read_file, fence, str(lib / "tool.exe")), ".exe type")

        print("the opened file must be the checked file")
        other = lib / "sub" / "notes.txt"
        swapped = os.stat(other)
        check(not _same_file(os.stat(lib / "README.md"), swapped), "a different file (inode) is detected")
        with open(lib / "README.md", "rb") as fh:
            check(_same_file(os.stat(lib / "README.md"), os.fstat(fh.fileno())), "the same file passes")
        real_fstat = os.fstat
        os.fstat = lambda fd: swapped            # simulate a swap between the checks and open()
        try:
            check(refused(read_file, fence, str(lib / "README.md")), "read_file refuses a file swapped after the check")
        finally:
            os.fstat = real_fstat

        print("search hits are trimmed while scanning")
        (lib / "many.md").write_text("needle line\n" * 5000, encoding="utf-8")
        many, _n = search(fence, lib, "needle")
        body_lines = many.splitlines()[1:]
        check(len(body_lines) == SEARCH_PER_FILE_HITS and "5000 matching lines" in many.splitlines()[0],
              f"one file with 5000 matches contributes {len(body_lines)} lines, and the total is still reported")
        check([ln.rsplit(":", 2)[-2] for ln in body_lines] == ["1", "2", "3", "4", "5"], "the earliest lines win ties")
        (lib / "many.md").unlink()

        print("reads are capped with a note")
        big_text, _ = read_file(fence, str(lib / "big.md"))
        check(len(big_text.encode("utf-8")) < READ_CAP_BYTES + 400 and "[truncated" in big_text,
              f"350 KB file -> {len(big_text)} chars, truncated with a note")

        print("searches stay inside the fence and log nothing")
        opened = []
        real_open = builtins.open

        def spy_open(file, mode="r", *a, **k):
            opened.append((str(file), mode))
            return real_open(file, mode, *a, **k)
        builtins.open = spy_open
        try:
            lt, ln = search(fence, lib, "reference shelf")
            vt, vn = search(fence, vault, "firewall rules")
            ranked, _ = search(fence, vault, "firewall nat")
            none, _ = search(fence, vault, "zzzz-no-such-word")
            leaky, _ = search(fence, lib, "DENY-CANARY")
            leaky2, _ = search(fence, vault, "DENY-CANARY")
            leaky3, _ = search(fence, lib, "PRIVATE-CHAT-CANARY")
            calc("2+2")
            read_file(fence, str(lib / "README.md"))
        finally:
            builtins.open = real_open
        check("reference shelf" in lt and ln == "1 hit", f"library_search finds the line ({ln})")
        check("Firewalls.md" in vt and "Active Priorities.md" in vt, "vault_search finds both notes")
        check("Firewalls.md:1:" in ranked.splitlines()[1] and "Active Priorities.md" in ranked,
              "lines holding every word rank first")
        check(none.startswith("no matches"), "a miss says so")
        # (the query is echoed in the header, so check for "no matches", not for the word)
        check(leaky.startswith("no matches") and leaky2.startswith("no matches"),
              "denied files, .obsidian and secrets/ are never searched")
        check(leaky3.startswith("no matches"), "the junction and the hard link to private/chats are never read")
        check(all(m in ("r", "rb") for _f, m in opened), f"only read-mode opens ({len(opened)} opens)")
        check(not any("marty-tools.log" in f or f.endswith(".log") for f, _m in opened), "no log file touched")

        print("calc: arithmetic only")
        for expr, want in (("2+2*3", "8"), ("(1.5+2.5)/2", "2"), ("2^10", "1024"), ("1,200 * 0.08", "96"),
                           ("-3 ** 2", "-9"), ("7 // 2", "3"), ("7 % 4", "3"), ("10/4", "2.5")):
            check(calc(expr)[0].endswith("= " + want), f"{expr} = {want}")
        for bad in ("__import__('os').system('x')", "len('abc')", "a + 1", "lambda: 1", "[1, 2]", "True + 1",
                    "9**9**9", "10**100000", "1/0", "'a' * 3", "(1).__class__", "1e308 * 10", "x" * 300,
                    "2 if 1 else 3", "{}.keys()"):
            check(refused(calc, bad), f"refused: {bad[:30]}")

        print("save_draft: new files in jr/drafts only, never an overwrite")
        t0 = datetime(2026, 9, 25, 14, 0, 0)
        r1, _ = save_draft(fence, "Plan: ../../evil\\name", "first", now=t0)
        r2, _ = save_draft(fence, "Plan: ../../evil\\name", "second", now=t0)
        made = sorted(drafts.iterdir())
        check(len(made) == 2 and all(p.parent == drafts for p in made), "two drafts, both inside jr/drafts")
        first = drafts / "20260925-140000-plan-evil-name.md"      # "-2.md" sorts before ".md"
        check(first.read_text(encoding="utf-8").endswith("first\n"), "the first draft was not overwritten")
        check(all(_DRAFT_NAME.match(p.name) for p in made), f"safe names ({made[0].name})")
        check(not list(agent.glob("evil*")) and not list(tmp.glob("evil*")), "no path escape from the title")
        check(refused(save_draft, fence, "big", "x" * (DRAFT_MAX_CHARS + 1)), "oversized draft refused")
        check(refused(save_draft, fence, "", "text"), "untitled draft refused")
        jd_target = tmp / "elsewhere"
        jd_target.mkdir()
        jdrafts = agent / "jr" / "jdrafts"
        _winapi.CreateJunction(str(jd_target), str(jdrafts))
        links.append(jdrafts)
        check(refused(save_draft, Fence([lib], jdrafts), "t", "x"), "a drafts folder that is a junction")
        check(not list(jd_target.iterdir()), "and nothing was written through it")

        print("the toolbox: allowlist, limit, argument handling")
        box = tb()
        for bad in ("shell", "run_command", "send_email", "delete_file", "web_fetch", "lookup_person",
                    "../read_file", None):
            res = box.run(bad, {})
            check(res.status == "refused" and res.note == "unknown tool", f"unknown tool refused: {bad!r}")
        check(box.calls == 0, "refused unknown tools do not use the budget")
        res = box.run("calc", '{"expression": "6*7"}')
        check(res.status == "ok" and res.text.endswith("= 42"), "arguments as a JSON string")
        res = box.run("read_file", {"path": str(chats / "private-chat.md")})
        check(res.status == "refused" and "PRIVATE-CHAT-CANARY" not in res.text, "a fence refusal carries no content")
        check(res.event() == {"tool": "read_file", "status": "refused", "note": "refused"}, "events carry no paths or text")
        res = box.run("read_file", {"path": str(lib / "missing.md")})
        check(res.status == "error" and res.note == "not found", "missing file -> error")
        res = box.run("read_file", {"path": str(lib / "sub")})
        check(res.status == "error", "a folder -> error")
        res = box.run("library_search", "not json")
        check(res.status == "refused", "bad JSON arguments -> refused")
        for _ in range(6):
            box.run("calc", {"expression": "1+1"})
        res = box.run("calc", {"expression": "1+1"})
        check(res.status == "refused" and res.note == "tool limit" and box.calls == 6, "the 7th call is refused")

        print("the real roots (checked, not read)")
        real = default_fence()
        for p in ("C:/Users/{{WIN_USER}}/my-agent/private/chats/x.md", "C:/Users/{{WIN_USER}}/my-agent/jack_marty_local/x.md",
                  "C:/Users/{{WIN_USER}}/my-agent/dashboard/dashboard-devices.jsonl", "C:/Users/{{WIN_USER}}/my-agent/.env",
                  "C:/Users/{{WIN_USER}}/my-agent/jr/history/index.bin", "C:/Users/{{WIN_USER}}/my-agent/private/README.txt"):
            check(refused(real.check_read, p), f"real layout refuses {p[len('C:/Users/{{WIN_USER}}/'):]}")
        for root in (LIBRARY_ROOT, VAULT_ROOT, BUSINESS_ROOT):
            ok = os.path.isdir(root) and not refused(real.check_read, str(root))
            check(ok, f"real root is reachable and clean: {root}")
        check(not refused(real.check_write_dir) if os.path.isdir(DRAFTS_ROOT) else False,
              f"real drafts folder is clean: {DRAFTS_ROOT}")
    finally:
        for link in reversed(links):
            try:
                if os.path.isdir(link):
                    os.rmdir(link)           # removes the junction itself, never its target
                else:
                    os.unlink(link)
            except OSError:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
        check(not tmp.exists(), "temp dir cleaned up")
    for n in notes:
        print("  note " + n)
    print("\n" + ("jr_tools selftest: all checks passed" if not fails else f"jr_tools selftest: {len(fails)} FAILED"))
    return not fails


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["selftest"]:
        sys.exit(0 if selftest() else 1)
    print("usage: jr_tools.py selftest")
