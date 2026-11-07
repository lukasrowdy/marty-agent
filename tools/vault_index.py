"""
vault_index.py - chunked hybrid retrieval over Lukas's vault, for Marty's search_vault tool.

    py tools/vault_index.py build [--force]     (re)index the vault; incremental unless --force
    py tools/vault_index.py status              what is indexed, with what, and what is stale
    py tools/vault_index.py search "<question>" [-k N]
    py tools/vault_index.py selftest            no network, no writes outside a temp dir

Why this exists (measured 2026-09-22): `search_notes` is a substring grep that returns
200-char lines, and `read_file` then returned the first 6,000 bytes of a note with no way to
page. On a 179 KB daily note that is the frontmatter and the Index block, so the answer was
unreachable and the caller re-read the same file hoping for more. Asked about the family NAS
with 14 steps, a local model burned all 14 and never finished. The fix is retrieval shape,
not more prompt: split every note into passages, embed them with a local model, and hand
back the passages that answer the question.

How: every note under C:/Users/{{WIN_USER}}/marty-vault is split on headings into passages of
about 900 characters (never more than 1,500), each embedded by nomic-embed-text:v1.5 on the
local Ollama server and stored in one SQLite file next to an FTS5 keyword index. A query is
ranked by meaning (cosine over the vectors) and by keywords (BM25) and the two lists are
fused, so a rare identifier like {{NAS_MODEL}} is found by the keyword leg even when the embedding
is vague about it. The index refreshes itself before every search by re-embedding only the
notes whose content hash changed.

Facts the code leans on (skeptic-verified 2026-09-22):
  - nomic-embed-text's effective context in Ollama is 2,048 tokens, not the 8,192 in its
    params blob; /api/embed is called with truncate:false so an oversize passage fails
    loudly (HTTP 400) and is split, never silently cut.
  - The model needs task prefixes that Ollama does not add: "search_document: " on every
    passage, "search_query: " on every query. Omitting them quietly degrades retrieval.
  - Vectors from one Ollama version are not guaranteed to match another's (ollama#14449),
    so the model tag and Ollama version are stored with the index and any mismatch means a
    full rebuild. Vectors from two versions are never mixed.
  - /api/embed returns unit-length vectors, so cosine similarity is a plain dot product.

The embedder is local and the index lives in my-agent/vault-index (no sync path, not in
the NAS job, not in the recovery bundle); it holds only text read_file can already read
under tools/marty_tools.scope.json. What a search returns goes to whichever model called it.
Stdlib only, on purpose - numpy is not installed here and installs need Lukas's yes.
"""

import argparse
import array
import datetime
import fnmatch
import hashlib
import inspect
import json
import operator
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
VAULT = pathlib.Path("C:/Users/{{WIN_USER}}/marty-vault")
INDEX_DIR = AGENT / "vault-index"
DB = INDEX_DIR / "vault.sqlite"
CONFIG = HERE / "marty_tools.scope.json"
OLLAMA = "http://127.0.0.1:11434"

MODEL = "nomic-embed-text:v1.5"
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "
CHUNKER_VERSION = 1

CHUNK_TARGET = 900      # pack blocks up to about this many chars
CHUNK_MAX = 1500        # never more than this; ~400-500 tokens, well under the 2,048 limit
MIN_CHUNK = 40          # fragments smaller than this are merged into a neighbour
SPLIT_FLOOR = 200       # an oversize passage is halved down to this before giving up
BATCH = 32              # passages per /api/embed call (measured 2.1 s for 32 x 1,200 chars)

DEFAULT_K = 5
MAX_K = 8
LEG_TOP = 20            # candidates from each ranking leg before fusion
RRF_K = 60              # reciprocal rank fusion constant
PER_NOTE_CAP = 3        # at most this many passages from one note in the answer
RESULT_BUDGET = 5800    # under marty_tools.py's MAX_TOOL_CHARS = 6000
LOCK_TIMEOUT_S = 0.5
SEARCH_REFRESH_S = 8    # re-embedding one interactive search may do before answering (findings 6, 7)
QUERY_EMBED_TIMEOUT_S = 30   # the question's own embedding; past this the search answers on keywords
EMBED_TIMEOUT_S = 300   # one /api/embed call during a build (32 passages measured at 2.1 s)
BACKGROUND_BUILD_EVERY_S = 300   # at most one detached catch-up build per this many seconds

STOP = {"a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "he",
        "his", "in", "is", "it", "its", "of", "on", "or", "that", "the", "this", "to", "was",
        "what", "which", "who", "with", "about", "does", "do", "did", "how", "why", "when",
        "where", "still", "open", "there", "their", "they", "them", "then", "than"}


# ---------------------------------------------------------------- chunking

class Chunk:
    __slots__ = ("heading", "start_line", "end_line", "text")

    def __init__(self, heading, start_line, end_line, text):
        self.heading = heading
        self.start_line = start_line
        self.end_line = end_line
        self.text = text

    def __repr__(self):
        return f"Chunk({self.heading!r}, {self.start_line}-{self.end_line}, {len(self.text)} chars)"


_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_SENTENCE = re.compile(r"(?<=[.!?;:])\s+")


def _split_oversize(text, limit):
    """Split one block that is longer than `limit`: at line breaks first (tables, lists
    with no blank lines), then at sentence ends, then at whitespace, then hard. Every piece
    is <= limit."""
    if "\n" in text:
        pieces, cur = [], ""
        for line in text.split("\n"):
            if cur and len(cur) + 1 + len(line) > limit:
                pieces.append(cur); cur = ""
            cur = (cur + "\n" + line) if cur else line
        if cur:
            pieces.append(cur)
        out = []
        for p in pieces:
            out.extend([p] if len(p) <= limit else _split_oversize(p.replace("\n", " "), limit))
        return out
    pieces, cur = [], ""
    for sent in _SENTENCE.split(text):
        if not sent:
            continue
        if len(sent) > limit:                       # one giant sentence: whitespace then hard
            if cur:
                pieces.append(cur); cur = ""
            words, wcur = sent.split(" "), ""
            for w in words:
                if len(w) > limit:
                    if wcur:
                        pieces.append(wcur); wcur = ""
                    pieces.extend(w[i:i + limit] for i in range(0, len(w), limit))
                    continue
                if wcur and len(wcur) + 1 + len(w) > limit:
                    pieces.append(wcur); wcur = w
                else:
                    wcur = (wcur + " " + w) if wcur else w
            if wcur:
                pieces.append(wcur)
            continue
        if cur and len(cur) + 1 + len(sent) > limit:
            pieces.append(cur); cur = sent
        else:
            cur = (cur + " " + sent) if cur else sent
    if cur:
        pieces.append(cur)
    return pieces


def _pack(blocks, heading):
    """blocks: [(start_line, end_line, text)] for one section -> [Chunk]."""
    chunks, cur, cur_start, cur_end = [], [], None, None

    def flush():
        nonlocal cur, cur_start, cur_end
        if cur:
            chunks.append(Chunk(heading, cur_start, cur_end, "\n".join(cur)))
        cur, cur_start, cur_end = [], None, None

    for start, end, text in blocks:
        parts = [text] if len(text) <= CHUNK_MAX else _split_oversize(text, CHUNK_MAX)
        for part in parts:
            size = sum(len(x) + 1 for x in cur) + len(part)
            if cur and size > CHUNK_TARGET:
                flush()
            if not cur:
                cur_start = start
            cur.append(part)
            cur_end = end
    flush()
    # merge fragments: a tiny trailing chunk joins its predecessor
    merged = []
    for ch in chunks:
        if merged and len(ch.text.strip()) < MIN_CHUNK and len(merged[-1].text) + len(ch.text) + 1 <= CHUNK_MAX + MIN_CHUNK:
            prev = merged[-1]
            merged[-1] = Chunk(prev.heading, prev.start_line, ch.end_line, prev.text + "\n" + ch.text)
        else:
            merged.append(ch)
    return [c for c in merged if len(c.text.strip()) >= 10]


def chunk_markdown(text, note_name=""):
    """Split one note into passages. Line numbers are 1-based and true to the file;
    the frontmatter block is skipped for text but still counted for lines."""
    lines = text.splitlines()
    i = 0
    if lines and lines[0].strip() == "---":
        for j in range(1, len(lines)):
            if lines[j].strip() == "---":
                i = j + 1
                break
    crumbs = {}                       # level -> heading text
    out, blocks = [], []
    block, block_start = [], None
    in_fence = False

    def crumb():
        parts = [crumbs[k] for k in sorted(crumbs)]
        return " > ".join(parts) if parts else (note_name or "(top)")

    def end_block(last_line):
        nonlocal block, block_start
        if block:
            blocks.append((block_start, last_line, "\n".join(block).strip()))
        block, block_start = [], None

    def end_section():
        nonlocal blocks
        out.extend(_pack(blocks, crumb()))
        blocks = []

    for n in range(i, len(lines)):
        line = lines[n]
        lineno = n + 1
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_fence:
                end_block(lineno - 1)
                block_start = lineno
            block.append(line)
            if in_fence:
                end_block(lineno)
            in_fence = not in_fence
            continue
        if in_fence:
            block.append(line)
            continue
        m = _HEADING.match(line)
        if m:
            end_block(lineno - 1)
            end_section()
            level = len(m.group(1))
            crumbs = {k: v for k, v in crumbs.items() if k < level}
            crumbs[level] = m.group(2).strip()
            continue
        if not stripped:
            end_block(lineno - 1)
            continue
        if block and _LIST_ITEM.match(line):
            end_block(lineno - 1)          # each list item is its own block, blank line or not
        if block_start is None:
            block_start = lineno
        block.append(line)
    end_block(len(lines))
    end_section()
    return out


# ---------------------------------------------------------------- embedding (local Ollama)

def ollama_version():
    with urllib.request.urlopen(f"{OLLAMA}/api/version", timeout=10) as r:
        return json.loads(r.read().decode("utf-8")).get("version", "?")


def _embed_call(inputs, timeout=300):
    body = {"model": MODEL, "input": inputs, "truncate": False, "keep_alive": "1h"}
    req = urllib.request.Request(f"{OLLAMA}/api/embed", data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        j = json.loads(r.read().decode("utf-8"))
    vecs = j.get("embeddings") or []
    if len(vecs) != len(inputs):
        raise RuntimeError(f"/api/embed returned {len(vecs)} vectors for {len(inputs)} inputs")
    return vecs


def _is_too_long(err):
    return isinstance(err, urllib.error.HTTPError) and err.code == 400


def embed_query(text, call=_embed_call):
    return call([QUERY_PREFIX + text])[0]


def embed_passages(items, call=_embed_call):
    """items: [(prefix_text, chunk)] -> [(chunk, vec)]. `call(inputs) -> vecs` is the one
    network primitive (swapped for a stub in selftest). A passage the model rejects as too
    long (400 with truncate:false) is halved and both halves become passages; the split
    stops at SPLIT_FLOOR chars, at which point the error is raised."""
    out = []
    for i in range(0, len(items), BATCH):
        batch = items[i:i + BATCH]
        try:
            vecs = call([p for p, _ in batch])
            out.extend(zip((c for _, c in batch), vecs))
            continue
        except Exception as e:
            if not _is_too_long(e):
                raise
        for prefix_text, ch in batch:               # one at a time; split the offender
            out.extend(_embed_one(prefix_text, ch, call))
    return out


def _embed_one(prefix_text, ch, call):
    try:
        return [(ch, call([prefix_text])[0])]
    except Exception as e:
        if not _is_too_long(e) or len(ch.text) <= SPLIT_FLOOR:
            raise
    mid = len(ch.text) // 2
    cut = ch.text.rfind(" ", 0, mid)
    cut = cut if cut > SPLIT_FLOOR // 2 else mid
    head, tail = ch.text[:cut].strip(), ch.text[cut:].strip()
    prefix = prefix_text[: len(prefix_text) - len(ch.text)]
    res = []
    for part in (head, tail):
        if part:
            sub = Chunk(ch.heading, ch.start_line, ch.end_line, part)
            res.extend(_embed_one(prefix + part, sub, call))
    return res


# ---------------------------------------------------------------- the index

def _f32(vec):
    return array.array("f", vec).tobytes()


def _from_blob(blob):
    a = array.array("f")
    a.frombytes(blob)
    return a


def _dot(a, b):
    return sum(map(operator.mul, a, b))


def _fts_query(question):
    terms = re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", question)
    seen = []
    for t in terms:
        t = t.lower().strip("._-")
        if len(t) < 2 or t in STOP or t in seen:
            continue
        seen.append(t)
    if not seen:
        return None
    return " OR ".join('"' + t.replace('"', "") + '"' for t in seen)


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _log(action, target, verdict, note=""):
    """One line in my-agent/logs/marty-tools.log, the same audit file every other Marty tool
    writes. Lazy import so this module has no import-time dependency on marty_tools.py
    (which imports this one lazily too). Never lets a logging failure break a search."""
    try:
        import marty_tools  # noqa: WPS433
        marty_tools.log(action, str(target)[:100].replace("\n", " ").replace("\t", " "), verdict, note)
    except Exception:
        pass


def _spawn_background_build():
    """Hand the rest of a refresh to a detached `vault_index.py build`, so the search that
    noticed the work can answer now instead of embedding for minutes (audit findings 6, 7).
    At most one per BACKGROUND_BUILD_EVERY_S (a stamp file), and two builds can never
    interleave: a build takes the index's write lock (BEGIN IMMEDIATE) and a second one
    finds it held and skips. Returns True if a build was started."""
    stamp = INDEX_DIR / "background-build.stamp"
    try:
        if stamp.exists() and time.time() - stamp.stat().st_mtime < BACKGROUND_BUILD_EVERY_S:
            return False
        INDEX_DIR.mkdir(parents=True, exist_ok=True)
        stamp.write_text(_now(), encoding="utf-8")
        flags = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == "nt" else 0
        subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), "build"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, creationflags=flags)
        return True
    except Exception:
        return False


class VaultIndex:
    def __init__(self, vault=VAULT, db=DB, config=CONFIG, embed_call=_embed_call,
                 version_fn=ollama_version, log_fn=_log, spawn_fn=_spawn_background_build):
        self.vault = pathlib.Path(vault)
        self.db = pathlib.Path(db)
        self.config = pathlib.Path(config)
        self._call = embed_call             # the one network primitive; a stub in selftest
        self._version = version_fn
        self._log = log_fn
        self._spawn = spawn_fn              # the detached catch-up build; a recorder in selftest
        self._cache = None      # (generation, [ids], [paths], [vecs])
        self._t_end = None      # monotonic deadline of the refresh in progress, if it has one
        try:
            self._call_takes_timeout = "timeout" in inspect.signature(embed_call).parameters
        except (TypeError, ValueError):
            self._call_takes_timeout = False

    def _call_bounded(self, inputs, cap=EMBED_TIMEOUT_S):
        """The embed primitive under a time limit: never more than `cap` per call, and never
        past the deadline of the refresh in progress (audit finding 6: each call had a flat
        300 s, so a refresh of many notes had no total bound)."""
        t = cap
        if self._t_end is not None:
            t = min(cap, self._t_end - time.monotonic())
            if t < 0.5:
                raise TimeoutError("refresh deadline reached")
        return self._call(inputs, timeout=t) if self._call_takes_timeout else self._call(inputs)

    def _embed_passages(self, items):
        return embed_passages(items, self._call_bounded)

    def _embed_query(self, text):
        return embed_query(text, lambda inputs: self._call_bounded(inputs, QUERY_EMBED_TIMEOUT_S))

    # -- storage --------------------------------------------------------

    def connect(self):
        self.db.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(self.db, timeout=LOCK_TIMEOUT_S, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER,
                mtime REAL, nchunks INTEGER, indexed_at TEXT);
            CREATE TABLE IF NOT EXISTS chunks (id INTEGER PRIMARY KEY, path TEXT, ord INTEGER,
                heading TEXT, start_line INTEGER, end_line INTEGER, text TEXT, nchars INTEGER, vec BLOB);
            CREATE INDEX IF NOT EXISTS chunks_path ON chunks(path);
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(text, heading, path UNINDEXED,
                tokenize='unicode61');
        """)
        return c

    def _meta(self, c):
        return dict(c.execute("SELECT key, value FROM meta"))

    def _set_meta(self, c, **kv):
        for k, v in kv.items():
            c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (k, str(v)))

    def _bump_generation(self, c):
        """Move the cache identity inside the same transaction as the chunk rows it describes.
        Until 2026-09-23 it moved only after a whole refresh succeeded, so a refresh that failed
        on its second note left the first note's new rows committed under the OLD generation;
        a process holding a vector cache went on ranking chunk ids that no longer existed, the
        passage fetch came back empty, and the search crashed (audit finding 7)."""
        self._set_meta(c, generation=int(self._meta(c).get("generation", "0")) + 1)

    def _drop_path(self, c, rel):
        c.execute("DELETE FROM chunks_fts WHERE rowid IN (SELECT id FROM chunks WHERE path=?)", (rel,))
        c.execute("DELETE FROM chunks WHERE path=?", (rel,))
        c.execute("DELETE FROM files WHERE path=?", (rel,))
        self._bump_generation(c)

    def _fingerprint(self):
        return {"model": MODEL, "ollama_version": self._version(), "doc_prefix": DOC_PREFIX,
                "chunker_version": str(CHUNKER_VERSION)}

    # -- what to index ---------------------------------------------------

    def _policy(self):
        """The cfg dict marty_tools.authorized() checks paths against, or None if the scope
        file can't be read/parsed. None is distinct from a dict with empty roots: refresh()
        must bail out entirely on None (an unreadable policy must not look like 'every
        file was deleted' and purge the index), while search() treats None as
        deny-everything for that one query, which is safe since it changes nothing on
        disk. Audit finding 2, 2026-09-22."""
        try:
            cfg = json.loads(self.config.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(cfg, dict):
            return None
        cfg.setdefault("allowed_roots", [])
        cfg.setdefault("denied_patterns", [])
        for key in ("allowed_roots", "denied_patterns"):   # a bare string would authorize a whole drive
            v = cfg[key]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return None
        return cfg

    def denied_patterns(self):
        """Kept for callers/tests that only care about the deny list."""
        return [p.lower() for p in (self._policy() or {}).get("denied_patterns", [])]

    def _authorized(self, p, cfg):
        import marty_tools  # noqa: WPS433 (lazy: same reason as _log)
        return cfg is not None and marty_tools.authorized(p, cfg)

    def vault_files(self):
        """Every markdown note that currently exists on disk (minus .obsidian/.trash),
        regardless of authorization. refresh() uses this to know what's present versus
        deleted; if it filtered by policy here too, an unreadable/malformed config would
        make every note look deleted and refresh would purge the whole index. Access
        control is applied separately: to what gets (re-)embedded in refresh(), and to
        what search() returns. Audit finding 2, 2026-09-22."""
        for p in sorted(self.vault.rglob("*.md")):
            if ".obsidian" in p.parts or ".trash" in p.parts:
                continue
            yield p

    # -- refresh ---------------------------------------------------------

    def _replace_file(self, c, rel, text, st):
        name = pathlib.Path(rel).stem
        chunks = chunk_markdown(text, name)
        items = [(DOC_PREFIX + f"{name} > {ch.heading}\n{ch.text}", ch) for ch in chunks]
        pairs = self._embed_passages(items) if items else []
        c.execute("DELETE FROM chunks_fts WHERE rowid IN (SELECT id FROM chunks WHERE path=?)", (rel,))
        c.execute("DELETE FROM chunks WHERE path=?", (rel,))
        dims = None
        for ordn, (ch, vec) in enumerate(pairs):
            dims = len(vec)
            cur = c.execute(
                "INSERT INTO chunks(path, ord, heading, start_line, end_line, text, nchars, vec) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (rel, ordn, ch.heading, ch.start_line, ch.end_line, ch.text, len(ch.text), _f32(vec)))
            c.execute("INSERT INTO chunks_fts(rowid, text, heading, path) VALUES (?,?,?,?)",
                      (cur.lastrowid, ch.text, ch.heading, rel))
        c.execute("INSERT OR REPLACE INTO files(path, sha256, size, mtime, nchunks, indexed_at) "
                  "VALUES (?,?,?,?,?,?)",
                  (rel, hashlib.sha256(text.encode("utf-8")).hexdigest(), st.st_size, st.st_mtime,
                   len(pairs), _now()))
        return len(pairs), dims

    def refresh(self, force=False, deadline_s=None, allow_full=True):
        """Bring the index up to date. Returns a dict of what happened; never raises.
        Full rebuild (force, or a model/version/chunker mismatch) is ONE transaction, so a
        failure leaves the old index intact and vectors from two versions are never mixed.
        Incremental work commits per file, and every committed change moves the generation
        with it (see _bump_generation).

        deadline_s bounds the whole refresh (audit finding 6): notes it has no time for are
        counted in stats["pending"] and left for the next refresh. allow_full=False is how a
        search asks: a full rebuild is never done in the query path, it is reported as
        stats["pending_full"] instead. Revocation does not wait on any of this, because
        search() re-checks authorization on every passage it returns."""
        t0 = time.perf_counter()
        stats = {"changed": 0, "removed": 0, "chunks_added": 0, "full": False, "ms": 0, "pending": 0}
        c = self.connect()
        try:
            try:
                fp = self._fingerprint()
            except Exception as e:
                stats["error"] = f"ollama not answering ({type(e).__name__}: {e})"
                return stats
            policy = self._policy()
            if policy is None:
                # An unreadable/malformed config must not look like "every note was
                # deleted" - bail before touching the index rather than purging it.
                stats["error"] = f"vault policy unreadable at {self.config}; leaving index untouched"
                return stats
            meta = self._meta(c)
            full = force or any(meta.get(k) != v for k, v in fp.items())
            if full and not allow_full:
                stats["pending_full"] = True
                stats["fingerprint_mismatch"] = not force
                return stats
            stats["full"] = bool(full)
            try:
                c.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError:
                stats["skipped_locked"] = True
                return stats
            self._t_end = None if deadline_s is None or full else time.monotonic() + float(deadline_s)
            try:
                existing = {r[0]: r[1:] for r in c.execute("SELECT path, sha256, size, mtime FROM files")}
                if full:
                    c.execute("DELETE FROM chunks_fts"); c.execute("DELETE FROM chunks"); c.execute("DELETE FROM files")
                    existing = {}
                seen = set()
                dims = meta.get("dims")
                for p in self.vault_files():
                    rel = p.relative_to(self.vault).as_posix()
                    seen.add(rel)
                    if not self._authorized(p, policy):
                        # Still on disk but no longer authorized (or policy is currently
                        # unreadable): drop it from the index if it was there, rather than
                        # leaving stale authorized-looking content behind. A file that was
                        # never indexed (e.g. always denied) just stays absent.
                        if rel in existing:
                            self._drop_path(c, rel)
                            stats["removed"] += 1
                        continue
                    st = p.stat()
                    old = existing.get(rel)
                    if old and old[1] == st.st_size and abs((old[2] or 0) - st.st_mtime) < 1e-6:
                        continue
                    text = p.read_text(encoding="utf-8-sig", errors="replace")
                    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
                    if old and old[0] == sha:
                        c.execute("UPDATE files SET size=?, mtime=? WHERE path=?", (st.st_size, st.st_mtime, rel))
                        continue
                    if self._t_end is not None and time.monotonic() >= self._t_end:
                        stats["pending"] += 1                       # no time left: next refresh's job
                        continue
                    if not full:
                        c.execute("COMMIT"); c.execute("BEGIN IMMEDIATE")   # per-file commits when incremental
                    try:
                        n, d = self._replace_file(c, rel, text, st)
                    except TimeoutError:
                        if full:
                            raise
                        c.execute("ROLLBACK"); c.execute("BEGIN IMMEDIATE")   # drop the half-done note only
                        stats["pending"] += 1
                        continue
                    self._bump_generation(c)
                    dims = d or dims
                    stats["changed"] += 1
                    stats["chunks_added"] += n
                for rel in set(existing) - seen:
                    self._drop_path(c, rel)
                    stats["removed"] += 1
                if full or stats["changed"] or stats["removed"]:
                    self._set_meta(c, built_at=_now(), dims=dims or "", **fp)
                    self._bump_generation(c)
                c.execute("COMMIT")
            except Exception as e:
                c.execute("ROLLBACK")
                stats["error"] = f"{type(e).__name__}: {e}"
            finally:
                self._t_end = None
        finally:
            c.close()
            stats["ms"] = int((time.perf_counter() - t0) * 1000)
        if stats["changed"] or stats["removed"] or stats.get("error"):
            self._log("vault_index", f"{stats['changed']} notes re-embedded, {stats['removed']} removed",
                      "ERROR" if stats.get("error") else "OK",
                      (stats.get("error") or f"{stats['chunks_added']} passages, {stats['ms']} ms"
                       + (", full rebuild" if stats["full"] else "")))
        return stats

    # -- search ----------------------------------------------------------

    def _vectors(self, c):
        gen = self._meta(c).get("generation", "0")
        if self._cache and self._cache[0] == gen:
            return self._cache[1:]
        ids, paths, vecs = [], [], []
        for cid, path, blob in c.execute("SELECT id, path, vec FROM chunks"):
            ids.append(cid); paths.append(path); vecs.append(_from_blob(blob))
        self._cache = (gen, ids, paths, vecs)
        return ids, paths, vecs

    def rank(self, c, question, k, semantic=True):
        """Fused ranking -> ([(chunk_id, path)] in answer order with the per-note cap applied,
        how many candidates existed beyond those, why the semantic leg was off or None).

        The two legs stand alone (audit finding 7). The question used to be embedded before
        the keyword leg ran, so an embedder outage took keyword retrieval down with it; now
        a failed or disabled semantic leg is reported and the keyword leg answers alone.
        semantic=False is passed when the stored vectors came from a different model or
        Ollama version, which must never be compared with a fresh query vector."""
        ids, paths, vecs = self._vectors(c)
        scores, degraded = {}, None
        if ids and not semantic:
            degraded = ("semantic ranking off: the index was built with a different Ollama version or model "
                        "and is being rebuilt; keyword results only")
        elif ids:
            try:
                q = array.array("f", self._embed_query(question))
                sims = sorted(((_dot(q, v), i) for i, v in enumerate(vecs)), reverse=True)[:LEG_TOP]
                for rank, (_s, i) in enumerate(sims):
                    scores[ids[i]] = scores.get(ids[i], 0.0) + 1.0 / (RRF_K + rank)
            except Exception as e:
                degraded = f"semantic ranking unavailable ({type(e).__name__}); keyword results only"
        by_id = dict(zip(ids, paths))
        fq = _fts_query(question)
        if fq:
            rows = c.execute("SELECT rowid, path FROM chunks_fts WHERE chunks_fts MATCH ? "
                             "ORDER BY bm25(chunks_fts, 1.0, 2.0) LIMIT ?", (fq, LEG_TOP)).fetchall()
            for rank, (rid, path) in enumerate(rows):
                scores[rid] = scores.get(rid, 0.0) + 1.0 / (RRF_K + rank)
                by_id.setdefault(rid, path)     # keyword hits carry their own path, cache or no cache
        fused = sorted(scores.items(), key=lambda kv: -kv[1])
        picked, per_note = [], {}
        for cid, _s in fused:
            path = by_id.get(cid)
            if path is None:
                continue
            if per_note.get(path, 0) >= PER_NOTE_CAP:
                continue
            per_note[path] = per_note.get(path, 0) + 1
            picked.append((cid, path))
            if len(picked) >= k:
                break
        return picked, max(0, len(fused) - len(picked)), degraded

    def search(self, question, k=DEFAULT_K, budget=RESULT_BUDGET):
        """The tool result, as text, never raising."""
        t0 = time.perf_counter()
        question = (question or "").strip()
        if not question:
            return "ERROR: search_vault needs a question"
        try:
            k = max(1, min(MAX_K, int(k or DEFAULT_K)))
        except (TypeError, ValueError):
            k = DEFAULT_K
        # A bounded refresh only: whatever it has no time for (and any full rebuild) goes to a
        # detached background build, so one question never waits on minutes of embedding.
        r = self.refresh(deadline_s=SEARCH_REFRESH_S, allow_full=False)
        if r.get("pending") or r.get("pending_full"):
            r["background"] = bool(self._spawn())
        c = self.connect()
        try:
            n = c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            if not n:
                msg = "ERROR: the vault index is empty" + (f" ({r['error']})" if r.get("error") else "") + \
                      "; run  py tools/vault_index.py build"
                self._log("search_vault", question, "ERROR", "empty index")
                return msg
            try:
                picked, more, degraded = self.rank(c, question, k, semantic=not r.get("fingerprint_mismatch"))
            except Exception as e:
                self._log("search_vault", question, "ERROR", f"{type(e).__name__}: {e}")
                return f"ERROR: could not run the search ({type(e).__name__}: {e})."
            # Re-checked against the current policy now, not just at last refresh, so a
            # revocation is immediate even when refresh is locked/failed and stale rows
            # are still sitting in the index. Audit finding 2, 2026-09-22.
            policy = self._policy()
            out, used, shown = [], 0, 0
            for cid, path in picked:
                if not self._authorized(self.vault / path, policy):
                    continue
                row = c.execute("SELECT heading, start_line, end_line, text FROM chunks WHERE id=?", (cid,)).fetchone()
                if row is None:
                    continue                # replaced by another process's refresh since ranking
                heading, s, e, text = row
                head = f"[{shown + 1}] {path}:{s}-{e}  ({heading})\n"
                piece = head + text + "\n\n"
                if used + len(piece) > budget:
                    if shown == 0:                              # always return something
                        room = max(0, budget - len(head) - 6)
                        piece = head + text[:room].rstrip() + " ...\n\n"
                    else:
                        more += 1
                        continue
                out.append(piece); used += len(piece); shown += 1
            trailer = (f"({more} further match{'es' if more != 1 else ''} not shown. " if more else "(") + \
                      "For more of a note: read_file(path, start_line=N).)"
            if r.get("error"):
                trailer += f"\n(Index refresh failed, results may be stale: {r['error']})"
            elif r.get("skipped_locked"):
                trailer += "\n(Another process is updating the index; results may be a few minutes stale.)"
            if r.get("pending"):
                trailer += (f"\n({r['pending']} changed note{'s' if r['pending'] != 1 else ''} not re-indexed yet; "
                            "a background build is catching up, so the newest edits may be missing.)")
            if degraded:
                trailer += f"\n({degraded}.)"
            text = "".join(out) + trailer
        finally:
            c.close()
        ms = int((time.perf_counter() - t0) * 1000)
        note = f"{shown} passages, {ms} ms"
        if r.get("changed") or r.get("removed"):
            note += f", refreshed {r['changed']} notes"
        if r.get("pending") or r.get("pending_full"):
            note += f", {'full rebuild' if r.get('pending_full') else str(r['pending']) + ' notes'} left to background"
        if degraded:
            note += ", keyword only"
        self._log("search_vault", question, "OK", note)
        return text[:RESULT_BUDGET + 200]

    def status(self):
        c = self.connect()
        try:
            meta = self._meta(c)
            files = c.execute("SELECT COUNT(*), COALESCE(SUM(nchunks),0) FROM files").fetchone()
            existing = {r[0]: r[1:] for r in c.execute("SELECT path, sha256, size, mtime FROM files")}
            policy = self._policy()
            stale, seen = [], set()
            for p in self.vault_files():
                rel = p.relative_to(self.vault).as_posix(); seen.add(rel)
                if not self._authorized(p, policy):
                    continue    # never embedded (or due for removal) - not "stale", just not in scope
                st = p.stat(); old = existing.get(rel)
                if not old or old[1] != st.st_size or abs((old[2] or 0) - st.st_mtime) >= 1e-6:
                    stale.append(rel)
            gone = sorted(set(existing) - seen)
            return {"db": str(self.db), "notes": files[0], "passages": files[1], "meta": meta,
                    "stale_or_new": stale, "deleted": gone}
        finally:
            c.close()


_DEFAULT = None


def default_index():
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = VaultIndex()
    return _DEFAULT


def search(question, k=DEFAULT_K):
    """What marty_tools.py calls."""
    return default_index().search(question, k)


# ---------------------------------------------------------------- selftest (no network)

def _stub_embedder(max_chars=None):
    """Deterministic bag-of-words hashing into 64 dims, unit length. Overlapping words give
    a high cosine, so ranking tests mean something. Raises the same 400 the real endpoint
    does when a passage is longer than max_chars."""
    def vec(text):
        v = [0.0] * 64
        for w in re.findall(r"[a-z0-9]+", text.lower()):
            v[int(hashlib.md5(w.encode()).hexdigest(), 16) % 64] += 1.0
        n = sum(x * x for x in v) ** 0.5 or 1.0
        return [x / n for x in v]

    def call(inputs):
        # like the real endpoint: the whole batch fails if any input is too long
        for text in inputs:
            if max_chars is not None and len(text) > max_chars:
                raise urllib.error.HTTPError("http://stub/api/embed", 400, "input length exceeds", {}, None)
        return [vec(t) for t in inputs]
    return call, vec


def selftest():
    global SEARCH_REFRESH_S
    fails = []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    print("chunker")
    note = ("---\nstatus: active\nproject: meta\ntype: log\n---\n# Tuesday\n\n## Index\n- one\n\n"
            "## Session 1\n\n### What Got Done\n- " + ("The {{NAS_MODEL}} is the family NAS. " * 60) +
            "\n- short\n\n```\ncode block line 1\ncode block line 2\n```\n\n### Decisions\n- decided x\n")
    chunks = chunk_markdown(note, "2026-09-22")
    check(all(len(c.text) <= CHUNK_MAX for c in chunks), "every chunk <= CHUNK_MAX")
    check(all("status: active" not in c.text for c in chunks), "frontmatter excluded from text")
    check(any(c.heading == "Tuesday > Session 1 > What Got Done" for c in chunks), "breadcrumb H1 > H2 > H3")
    check(any(c.heading == "Tuesday > Session 1 > Decisions" for c in chunks), "sibling H3 replaces the previous H3")
    check(any("code block line 1\ncode block line 2" in c.text for c in chunks), "fenced code kept whole")
    lines = [(c.start_line, c.end_line) for c in chunks]
    check(all(a <= b for a, b in lines) and lines == sorted(lines), "line ranges ordered and sane")
    check(chunks[0].start_line >= 6, "line numbers count the skipped frontmatter")
    big = [c for c in chunks if "family NAS" in c.text]
    check(len(big) >= 2 and all(len(c.text) <= CHUNK_MAX for c in big), "a 1,700-char bullet is split at sentences")
    tight = chunk_markdown("# L\n- first item line 2\n- second item line 3\n- third item line 4\n", "L")
    check(len(tight) == 1 and tight[0].start_line == 2 and tight[0].end_line == 4, "list items without blank lines pack into one chunk with true lines")
    items = "\n".join(f"- item {i} " + ("x" * 700) for i in range(4))
    tight2 = chunk_markdown("# L\n" + items + "\n", "L")
    check(len(tight2) == 4 and [(c.start_line, c.end_line) for c in tight2] == [(2, 2), (3, 3), (4, 4), (5, 5)],
          "long list items without blank lines get per-item line numbers")
    table = "# T\n\n" + "\n".join("| c%d | %s |" % (i, "v" * 300) for i in range(8)) + "\n"
    tchunks = chunk_markdown(table, "T")
    check(all(len(c.text) <= CHUNK_MAX for c in tchunks) and all("\n" in c.text for c in tchunks), "a wide table splits at row boundaries")
    tiny = [c for c in chunks if len(c.text.strip()) < MIN_CHUNK]
    headings = [c.heading for c in chunks]
    check(all(headings.count(c.heading) == 1 for c in tiny),
          "a fragment under MIN_CHUNK survives only when it is its whole section")

    print("fts query")
    q = _fts_query('what "is" {{NAS_MODEL}} * NEAR ({{NAS_IP}}) still open?')
    check(q is not None and '"{{NAS_MODEL_LC}}"' in q and '"{{NAS_IP}}"' in q and "*" not in q and "NEAR" not in q, f"sanitized: {q}")
    check(_fts_query("what is the") is None, "all-stopword question gives no keyword leg")

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        vault, db, cfg = td / "vault", td / "idx" / "vault.sqlite", td / "scope.json"
        (vault / "sub").mkdir(parents=True)
        (vault / ".obsidian").mkdir()
        # allowed_roots covers td itself so every test vault below (vault, vault2, empty)
        # is in scope through one root, the same way marty_tools.scope.json's real roots work.
        cfg.write_text(json.dumps({"allowed_roots": [str(td)], "denied_patterns": ["*password*", "*/.git/*"]}), encoding="utf-8")
        (vault / "nas.md").write_text("# NAS\n\nThe {{NAS_MODEL}} is the Synology NAS at {{NAS_IP}}. Backups run nightly.\n\n## Open\n\nAccount Protection lockout is still open.\n", encoding="utf-8")
        (vault / "sub" / "voice.md").write_text("# Voice\n\nThe ElevenLabs voice id is resolved by id, never by name.\n", encoding="utf-8")
        (vault / "school.md").write_text("# School\n\nOTC classes, twelve credit hours, B average goal.\n", encoding="utf-8")
        (vault / "my-password-list.md").write_text("# secret\n\nhunter2\n", encoding="utf-8")
        (vault / ".obsidian" / "workspace.md").write_text("# nope\n\nnever indexed\n", encoding="utf-8")
        call, vec = _stub_embedder()
        version = {"v": "0.34.2"}
        logged = []
        spawned = []

        def spawn():                    # stands in for the detached build; never touches the real index
            spawned.append(time.time())
            return True
        idx = VaultIndex(vault, db, cfg, call, lambda: version["v"],
                         lambda a, t, v, n="": logged.append((a, v, n)), spawn)

        print("build")
        r = idx.refresh()
        check(r["full"] and r["changed"] == 3 and not r.get("error"), f"first build indexes 3 notes: {r}")
        st = idx.status()
        check(st["notes"] == 3 and st["passages"] >= 4, f"status counts: {st['notes']} notes, {st['passages']} passages")
        check(all("password" not in p for p in [row for row in st["stale_or_new"]]) and st["notes"] == 3, "denied pattern skipped")
        check(st["meta"].get("model") == MODEL and st["meta"].get("ollama_version") == "0.34.2", "meta records model and ollama version")

        print("search")
        out = idx.search("What is {{NAS_MODEL}} on Lukas's network, and what is still open about it?", 5)
        check(out.startswith("[1] nas.md:") , "top hit is the NAS note: " + out.splitlines()[0])
        check("Account Protection" in out, "the 'still open' passage is included")
        check("read_file(path, start_line=N)" in out, "trailer present")
        check(len(out) <= RESULT_BUDGET + 200, "under budget")
        check(logged and logged[-1][0] == "search_vault" and logged[-1][1] == "OK", "search logged OK")
        out2 = idx.search("which voice id does the speaking", 3)
        check(out2.startswith("[1] sub/voice.md:"), "semantic leg finds the voice note without a keyword hit: " + out2.splitlines()[0])

        print("incremental")
        r = idx.refresh()
        check(r["changed"] == 0 and r["removed"] == 0 and not r["full"], f"no-op refresh touches nothing: {r}")
        time.sleep(0.05)
        (vault / "school.md").write_text("# School\n\nOTC classes, twelve credit hours, B average goal.\n\nNew: CIS 101 exam Friday.\n", encoding="utf-8")
        r = idx.refresh()
        check(r["changed"] == 1 and not r["full"], f"one edited note re-embedded: {r}")
        check("CIS 101" in idx.search("when is the exam", 2), "edited content is searchable")
        (vault / "sub" / "voice.md").unlink()
        r = idx.refresh()
        check(r["removed"] == 1, f"deleted note removed: {r}")
        check("voice.md" not in idx.search("ElevenLabs voice id", 3), "deleted note no longer returned")
        (vault / "nas.md").touch()
        r = idx.refresh()
        check(r["changed"] == 0, "touch without content change re-hashes but does not re-embed")

        print("version drift -> full rebuild")
        version["v"] = "0.35.0"
        r = idx.refresh()
        check(r["full"] and r["changed"] == 2 and not r.get("error"), f"ollama version change rebuilds everything: {r}")

        print("oversize passage split")
        big_vault = td / "vault2"; big_vault.mkdir()
        (big_vault / "big.md").write_text("# Big\n\n" + ("alpha beta gamma delta. " * 60) + "\n", encoding="utf-8")
        call2, _ = _stub_embedder(max_chars=700)
        idx2 = VaultIndex(big_vault, td / "idx2" / "v.sqlite", cfg, call2, lambda: "x", lambda *a: None, spawn)
        r = idx2.refresh()
        check(not r.get("error") and r["chunks_added"] >= 2, f"400 on a long passage splits it instead of failing: {r}")
        st2 = idx2.status()
        check(st2["passages"] >= 2, "both halves stored")

        print("locked index")
        other = sqlite3.connect(db, isolation_level=None)
        other.execute("BEGIN IMMEDIATE")
        r = idx.refresh()
        check(r.get("skipped_locked") is True, "refresh skips when another writer holds the lock")
        out = idx.search("{{NAS_MODEL}}", 2)
        check(out.startswith("[1]") and "few minutes stale" in out, "search still answers on the locked index and says so")
        other.execute("ROLLBACK"); other.close()

        print("revocation is immediate, even on a locked/stale index")
        other = sqlite3.connect(db, isolation_level=None)
        other.execute("BEGIN IMMEDIATE")
        original_cfg = cfg.read_text(encoding="utf-8")
        cfg.write_text(json.dumps({"allowed_roots": [str(td)],
                                    "denied_patterns": ["*password*", "*/.git/*", "*nas.md*"]}),
                        encoding="utf-8")
        r = idx.refresh()
        check(r.get("skipped_locked") is True, "refresh still can't run - the index itself is unchanged")
        out = idx.search("{{NAS_MODEL}} NAS Synology", 5)
        check("nas.md" not in out, f"denied note stops appearing immediately, without a successful refresh: {out!r}")
        other.execute("ROLLBACK"); other.close()
        cfg.write_text(original_cfg, encoding="utf-8")

        print("malformed/unreadable policy denies everything, not everything-allowed")
        cfg.write_text("{not valid json", encoding="utf-8")
        out = idx.search("{{NAS_MODEL}}", 5)
        check("nas.md" not in out and "[1]" not in out, f"broken config authorizes nothing: {out!r}")
        cfg.write_text(original_cfg, encoding="utf-8")

        print("failure paths")
        def down():
            raise urllib.error.URLError("connection refused")
        idx3 = VaultIndex(vault, db, cfg, call, down, lambda *a: None, spawn)
        r = idx3.refresh()
        check("error" in r and "ollama" in r["error"], f"ollama down -> refresh reports, does not raise: {r}")
        out = idx3.search("{{NAS_MODEL}}", 2)
        check(out.startswith("[1]") and "results may be stale" in out, "search on a stale index still answers and says why")
        idx4 = VaultIndex(td / "empty", td / "idx4" / "v.sqlite", cfg, call, lambda: "x", lambda *a: None, spawn)
        (td / "empty").mkdir()
        check(idx4.search("anything").startswith("ERROR: the vault index is empty"), "empty index is an ERROR, not 'no matches'")
        check(idx.search("   ").startswith("ERROR"), "blank question refused")

        print("keyword leg survives an embedder outage (audit finding 7)")
        def query_down(inputs):
            if any(t.startswith(QUERY_PREFIX) for t in inputs):
                raise urllib.error.URLError("embedder down")
            return call(inputs)
        idx5 = VaultIndex(vault, db, cfg, query_down, lambda: version["v"], lambda *a: None, spawn)
        out = idx5.search("{{NAS_MODEL}} Synology", 3)
        check(out.startswith("[1] nas.md") and "keyword results only" in out,
              f"embedder down: keyword hits still come back, and it says so: {out[:90]!r}")

        print("a refresh that fails partway keeps every reader's cache honest (finding 7)")
        # SQLite reuses a deleted chunk's rowid, which can hide a stale cache, so the note is
        # made to GROW (the new passage lands on an id the old cache never saw) and then to
        # SHRINK (the cache holds an id that no longer exists). Both went wrong before the fix.
        def explode(inputs):
            if any("EXPLODE" in t for t in inputs):
                raise RuntimeError("embedder fell over")
            return call(inputs)

        def failing_refresh():
            (vault / "zz-second.md").write_text("# Second\n\nEXPLODE here.\n", encoding="utf-8")
            return VaultIndex(vault, db, cfg, explode, lambda: version["v"], lambda *a: None, spawn).refresh()

        def locked_search(reader, question):
            other = sqlite3.connect(db, isolation_level=None)
            other.execute("BEGIN IMMEDIATE")                # keep the reader from refreshing its way out
            try:
                return reader.search(question, 3), None
            except Exception as e:
                return "", e
            finally:
                other.execute("ROLLBACK"); other.close()

        (vault / "course.md").write_text("# Course\n\nOTC classes, twelve credit hours.\n\n## Exams\n\n"
                                         "Final exam in December.\n", encoding="utf-8")
        idx6 = VaultIndex(vault, db, cfg, call, lambda: version["v"], lambda *a: None, spawn)
        idx6.search("OTC classes final exam", 3)            # indexes course.md; this reader now holds a cache
        gen0 = int(idx6.status()["meta"]["generation"])
        (vault / "course.md").write_text("# Course\n\nOTC classes, twelve credit hours.\n\n## Exams\n\n"
                                         "Final exam in December.\n\n## Labs\n\nCIS 202 lab is due Monday.\n",
                                         encoding="utf-8")
        r = failing_refresh()
        check(r.get("error") and r["changed"] == 1 and int(idx6.status()["meta"]["generation"]) > gen0,
              f"the note before the failure is committed WITH a generation bump: {r}")
        out, crashed = locked_search(idx6, "CIS 202 lab due Monday")
        check(crashed is None and "CIS 202" in out,
              f"note grew: the reader with the old cache still finds the new passage ({crashed!r})")
        (vault / "course.md").write_text("# Course\n\nCIS 202 lab only.\n", encoding="utf-8")
        failing_refresh()
        out, crashed = locked_search(idx6, "OTC classes final exam December")
        check(crashed is None and "Final exam" not in out,
              f"note shrank: no crash, and no passage that no longer exists ({crashed!r})")
        (vault / "zz-second.md").unlink()

        print("a search never waits on a big refresh (findings 6, 7)")
        def slow(inputs):
            time.sleep(0.4)
            return call(inputs)
        idx8 = VaultIndex(vault, db, cfg, slow, lambda: version["v"], lambda *a: None, spawn)
        for i in range(6):
            (vault / f"bulk{i}.md").write_text(f"# Bulk {i}\n\nbulk note {i} about zebras.\n", encoding="utf-8")
        spawned.clear()
        saved, SEARCH_REFRESH_S = SEARCH_REFRESH_S, 1
        try:
            t = time.perf_counter()
            out = idx8.search("zebras", 3)
            took = time.perf_counter() - t
        finally:
            SEARCH_REFRESH_S = saved
        check(took < 3.0 and "not re-indexed yet" in out and spawned,
              f"answered in {took:.1f} s with the rest handed to a background build")
        r = idx8.refresh()
        check(r["changed"] >= 1 and not r.get("error") and not r["pending"], f"the catch-up build finishes the job: {r}")

        print("an Ollama upgrade never rebuilds inside a search")
        version["v"] = "0.36.0"
        spawned.clear()
        out = idx.search("{{NAS_MODEL}} Synology", 3)
        check(out.startswith("[1]") and "semantic ranking off" in out and spawned,
              "version drift: keyword answer now, full rebuild handed to the background")
        r = idx.refresh()
        check(r["full"] and not r.get("error"), f"the background build (a plain refresh) does the full rebuild: {r}")

        print("packing")
        out = idx.search("{{NAS_MODEL}} NAS Synology backups open lockout", 8, budget=300)
        check(len(out) <= 300 + 200 and out.startswith("[1]"), "tiny budget still returns the first hit")

    print()
    if fails:
        print(f"{len(fails)} FAILED:"); [print("  - " + f) for f in fails]
        return 1
    print("all checks passed")
    return 0


# ---------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(description="Chunked hybrid retrieval over Lukas's vault, for Marty's search_vault tool.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="index the vault (incremental; --force rebuilds everything)")
    b.add_argument("--force", action="store_true")
    sub.add_parser("status", help="what is indexed and what is stale")
    s = sub.add_parser("search", help="ask the index a question")
    s.add_argument("question"); s.add_argument("-k", type=int, default=DEFAULT_K)
    sub.add_parser("selftest", help="no network, no writes outside a temp dir")
    a = ap.parse_args()
    if a.cmd == "selftest":
        raise SystemExit(selftest())
    idx = default_index()
    if a.cmd == "build":
        r = idx.refresh(force=a.force)
        print(json.dumps(r, indent=2))
        raise SystemExit(1 if r.get("error") else 0)
    if a.cmd == "status":
        print(json.dumps(idx.status(), indent=2))
        return
    if a.cmd == "search":
        print(idx.search(a.question, a.k))


if __name__ == "__main__":
    main()
