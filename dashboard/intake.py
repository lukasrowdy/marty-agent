"""
intake.py - the upload path behind POST /api/upload on the Marty dashboard.

Owns everything about a file arriving from the browser: the caps, filename
sanitisation, the per-upload lock table, the chunk append with resume, the
finalise step (hash, never-overwrite name, manifest row), the legacy single-shot
write, the logic behind the status/abort/note/transcribe endpoints, GC of
abandoned parts, and the detached transcribe worker. server.py routes to these
functions and sends whatever they return; nothing here knows about HTTP beyond
"read n bytes from rfile".

Wire format (the client half lives in dashboard/upload.js): each slice is a
fixed-length body with X-Filename, X-Upload-Id (a sha256 fingerprint of the
file, 64 hex chars), X-Upload-Offset, X-Upload-Total and an optional
X-Chunk-SHA256. A request with no X-Upload-Total is the legacy single-shot
format, still accepted up to UPLOAD_LEGACY_MAX.

On disk, under my-agent/uploads (UPLOAD_DIR):
  .parts/<id>.part   the bytes received so far, appended in order, fsynced
  .parts/<id>.json   {name, original_name, total, committed, handle, created,
                      updated}, plus done/path/sha256/digest/transcript once
                      the file is finished
  manifest.jsonl     one JSON row per event (upload | note | transcript):
                     metadata only, never file content, never a secret

Script entries:
  py dashboard/intake.py transcribe <id>   detached worker, spawned by start_transcribe
  py dashboard/intake.py backfill          manifest rows for files placed by hand
  py dashboard/intake.py selftest          hermetic checks in a temp dir, no network

Stdlib only. The design and the caps table live in the vault Job note
"07 - Resources/Jobs/Ingest a Dashboard Upload.md".
"""

import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from datetime import date, datetime

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
MY_AGENT = os.path.dirname(DASHBOARD_DIR)
# my-agent/uploads: on no sync path, not in the NAS job, not in the recovery bundle, and
# readable by Marty's tools in the dashboard's Claude lane (tools/marty_tools.scope.json).
UPLOAD_DIR = os.path.join(MY_AGENT, "uploads")
PARTS_DIR = os.path.join(UPLOAD_DIR, ".parts")
MANIFEST = os.path.join(UPLOAD_DIR, "manifest.jsonl")
MEDIA_PY = os.path.join(MY_AGENT, "tools", "media.py")

UPLOAD_LEGACY_MAX = 64 * 1024 * 1024            # single-shot format, unchanged cap
UPLOAD_PART_MAX = 32 * 1024 * 1024              # per request: the only body cap on the chunked path
UPLOAD_TOTAL_MAX = 4 * 1024 * 1024 * 1024       # per file
UPLOAD_FREE_RESERVE = 32 * 1024 * 1024 * 1024   # kept free on the drive that holds UPLOAD_DIR
CHUNK_IDLE_SEC = 60                             # socket timeout while a slice body is read
STALE_PART_DAYS = 7                             # abandoned .part/.json swept after this
INGEST_TIMEOUT_SEC = 6 * 3600                   # transcribe worker hard limit
GC_MIN_INTERVAL_SEC = 600                       # status() runs gc opportunistically; not on every poll
PART_CHAR_LIMIT = 5000                          # transcript pieces stay under this (read_file returns 6,000 per call)

MEDIA_EXTS = {
    ".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".wmv", ".flv", ".3gp", ".mts",
    ".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus", ".wma", ".aiff", ".aif", ".amr",
}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic", ".svg", ".tif", ".tiff"}
TEXT_EXTS = {".txt", ".md", ".csv", ".tsv", ".json", ".jsonl", ".log", ".xml", ".yaml", ".yml", ".html", ".htm"}
CAPTURE_EXTS = {".pcap", ".pcapng", ".cap"}
DOCUMENT_EXTS = {".pdf", ".docx", ".pptx", ".xlsx", ".doc", ".ppt", ".xls"}
ID_RE = re.compile(r"^[a-f0-9]{64}$")
SHA_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
SEG_RE = re.compile(r"^\*\*\[(\d+:\d{2})\]\*\*")

READ_CHUNK = 64 * 1024
HASH_CHUNK = 1024 * 1024

_LOCKS_GUARD = threading.Lock()
_LOCKS = {}
_FINALIZE_LOCK = threading.Lock()
_MANIFEST_LOCK = threading.Lock()
_GC_LAST = 0.0


# ---------------------------------------------------------------- small helpers

def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _fwd(p):
    """Forward slashes in anything that goes back to the browser or the manifest."""
    return p.replace("\\", "/") if isinstance(p, str) else p


def _check_id(upload_id):
    """Strict id check before any path join. Raises ValueError on anything else."""
    if not isinstance(upload_id, str) or not ID_RE.match(upload_id):
        raise ValueError("bad upload id")
    return upload_id


def _part_path(upload_id):
    return os.path.join(PARTS_DIR, _check_id(upload_id) + ".part")


def _state_path(upload_id):
    return os.path.join(PARTS_DIR, _check_id(upload_id) + ".json")


def sanitize_name(raw):
    """server.py's original sanitisation, verbatim: unquote, backslash to slash,
    basename, strip, replace anything outside [A-Za-z0-9._ -], drop leading dots.
    Applying it twice gives the same answer, so callers may pass a raw or a clean name."""
    raw = raw or ""
    try:
        raw = urllib.parse.unquote(raw)
    except Exception:
        pass
    name = os.path.basename(raw.replace("\\", "/")).strip()
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).lstrip(".").strip()
    return name


def free_bytes():
    """Free bytes on the drive holding UPLOAD_DIR (walking up to the nearest
    existing ancestor so a first-ever upload does not fail on a missing folder).
    Returns 0 if the drive cannot be measured, which makes every slice a 507:
    refusing is the safe side of not knowing."""
    probe = UPLOAD_DIR
    while probe and not os.path.isdir(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        return int(shutil.disk_usage(probe).free)
    except OSError:
        return 0


def id_lock(upload_id):
    """One threading.Lock per upload id, created on first use. Callers take it
    with acquire(blocking=False) so a second slice for the same id never queues
    behind the first; it gets a 409 and comes back."""
    with _LOCKS_GUARD:
        lk = _LOCKS.get(upload_id)
        if lk is None:
            lk = threading.Lock()
            _LOCKS[upload_id] = lk
        return lk


def _lock_is_held(upload_id):
    with _LOCKS_GUARD:
        lk = _LOCKS.get(upload_id)
    return lk is not None and lk.locked()


# ---------------------------------------------------------------- state files

def load_state(upload_id):
    try:
        with open(_state_path(upload_id), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_state(upload_id, d):
    """JSON to a per-writer tmp file, then os.replace. On Windows the replace can
    hit PermissionError if a reader has the file open for a few microseconds, so
    it retries briefly rather than turning a committed slice into a crashed request."""
    final = _state_path(upload_id)
    os.makedirs(PARTS_DIR, exist_ok=True)
    tmp = f"{final}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    for attempt in range(6):
        try:
            os.replace(tmp, final)
            return
        except PermissionError:
            if attempt == 5:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
            time.sleep(0.05)


def have_bytes(upload_id):
    try:
        return os.path.getsize(_part_path(upload_id))
    except OSError:
        return 0


def repair_tail(upload_id):
    """Make the .part equal the last fsynced offset. A slice that died mid-write
    leaves bytes past state['committed']; they are cut off. Returns the byte count
    the client should resume from."""
    st = load_state(upload_id)
    if st and st.get("done"):
        return have_bytes(upload_id)
    committed = int((st or {}).get("committed") or 0)
    have = have_bytes(upload_id)
    if have > committed:
        with open(_part_path(upload_id), "r+b") as f:
            f.truncate(committed)
            f.flush()
            os.fsync(f.fileno())
        have = committed
    elif have < committed and st is not None:
        st["committed"] = have
        st["updated"] = _now()
        save_state(upload_id, st)
    return have


def drain(rfile, n):
    """Read and discard n bytes in 64 KiB pieces. Returns True when all n arrived.
    Every refusal of a legitimately sized slice drains first so the browser gets
    the JSON instead of a TCP reset (the handler is HTTP/1.0 and closes on exit)."""
    left = int(n)
    while left > 0:
        chunk = rfile.read(min(READ_CHUNK, left))
        if not chunk:
            break
        left -= len(chunk)
    return left == 0


def _drain_ok(rfile, n):
    try:
        return drain(rfile, n)
    except OSError:
        return False


def _truncate_to(path, size):
    try:
        with open(path, "r+b") as f:
            f.truncate(size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass


# ---------------------------------------------------------------- chunk append

def append_chunk(rfile, connection, upload_id, offset, length, total, name, handle,
                 expected_sha=None):
    """One slice. Returns (status, payload) for the handler to send, or None when
    the connection died mid-body and there is nobody to answer.

    Order of checks, as designed: total cap (413), body cap (413), offset+length
    within total (400), disk reserve (507), per-id lock non-blocking (409 'chunk in
    flight'), torn-tail repair, offset must equal what is on disk (409 with bytes),
    then the copy: exactly `length` bytes in 64 KiB reads through sha256, socket
    timeout CHUNK_IDLE_SEC. Short read or timeout: truncate back, None. Hash
    mismatch: truncate back, 422. Else fsync, write the id json, and when the file
    is complete, finalize and return its payload (done: true)."""
    try:
        connection.settimeout(CHUNK_IDLE_SEC)
    except Exception:
        pass
    try:
        length = int(length)
    except (TypeError, ValueError):
        length = -1

    def answer(status, payload):
        # A body the client legitimately sent is drained before any answer; an
        # oversized Content-Length is never drained because the client never sends one.
        if 0 < length <= UPLOAD_PART_MAX and not _drain_ok(rfile, length):
            return None
        return (status, payload)

    try:
        total = int(total)
        offset = int(offset)
    except (TypeError, ValueError):
        return answer(400, {"error": "X-Upload-Offset and X-Upload-Total must be integers"})
    if total > UPLOAD_TOTAL_MAX:
        return answer(413, {"error": f"file too large (max {UPLOAD_TOTAL_MAX // (1024 ** 3)} GiB)"})
    if length <= 0 or length > UPLOAD_PART_MAX:
        return (413, {"error": f"slice must be 1 byte to {UPLOAD_PART_MAX // (1024 * 1024)} MiB"})
    if not isinstance(upload_id, str) or not ID_RE.match(upload_id):
        return answer(400, {"error": "bad upload id"})
    if expected_sha is not None:
        expected_sha = expected_sha.strip().lower()
        if expected_sha and not SHA_RE.match(expected_sha):
            return answer(400, {"error": "bad X-Chunk-SHA256"})
    original = (name or "")[:255]
    name = sanitize_name(name)
    if not name:
        return answer(400, {"error": "missing or unusable X-Filename header"})
    if total <= 0 or offset < 0 or offset + length > total:
        return answer(400, {"error": "offset plus length exceeds total"})
    free = free_bytes()
    if free - (total - offset) < UPLOAD_FREE_RESERVE:
        return answer(507, {"error": "PC disk nearly full", "free": free,
                            "reserve": UPLOAD_FREE_RESERVE})

    lk = id_lock(upload_id)
    if not lk.acquire(blocking=False):
        return answer(409, {"error": "chunk in flight", "bytes": have_bytes(upload_id)})
    try:
        st = load_state(upload_id)
        if st and st.get("done"):
            if st.get("path") and os.path.isfile(st["path"]):
                # Already on the PC: no bytes move.
                return answer(200, {"ok": True, "done": True, "duplicate": True,
                                    "path": _fwd(st["path"]), "name": st.get("name"),
                                    "bytes": st.get("bytes"), "sha256": st.get("sha256")})
            st = None  # finished once, but the file is gone: start over
        if st and int(st.get("total") or 0) != total:
            return answer(400, {"error": "total does not match the upload in progress",
                                "bytes": have_bytes(upload_id)})
        have = repair_tail(upload_id)
        if offset != have:
            return answer(409, {"error": "offset mismatch", "bytes": have})

        os.makedirs(PARTS_DIR, exist_ok=True)
        part = _part_path(upload_id)
        h = hashlib.sha256()
        got = 0
        try:
            with open(part, "ab") as f:
                while got < length:
                    try:
                        chunk = rfile.read(min(READ_CHUNK, length - got))
                    except OSError:      # socket.timeout, reset: same as a short read
                        chunk = b""
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
                if got != length:
                    f.truncate(have)
                    f.flush()
                    os.fsync(f.fileno())
                    return None          # the connection is dead; nobody to answer
                if expected_sha and expected_sha != h.hexdigest():
                    f.truncate(have)
                    f.flush()
                    os.fsync(f.fileno())
                    return (422, {"error": "chunk hash mismatch", "bytes": have})
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            _truncate_to(part, have)
            _drain_ok(rfile, length - got)
            return (500, {"error": f"write failed: {e.__class__.__name__}", "bytes": have_bytes(upload_id)})

        committed = have + length
        now = _now()
        st = st or {}
        st.update({
            "name": st.get("name") or name,
            "original_name": st.get("original_name") or original,
            "total": total,
            "committed": committed,
            "handle": st.get("handle") or handle,
            "created": st.get("created") or now,
            "updated": now,
        })
        save_state(upload_id, st)
        if committed == total:
            return (200, finalize(upload_id, handle))
        return (200, {"ok": True, "done": False, "bytes": committed})
    finally:
        lk.release()


# ---------------------------------------------------------------- finalize

def _sha256_file(path):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def _unique_dest(name):
    """server.py's never-overwrite loop: name, name-1, name-2 ... Callers hold
    _FINALIZE_LOCK so the exists-then-create window is closed."""
    dest = os.path.join(UPLOAD_DIR, name)
    if not os.path.abspath(dest).startswith(os.path.abspath(UPLOAD_DIR) + os.sep):
        raise ValueError("refused: name escapes the uploads folder")
    stem, ext = os.path.splitext(dest)
    n = 1
    while os.path.exists(dest):
        dest = f"{stem}-{n}{ext}"
        n += 1
    return dest


def _digest(path):
    """Cheap facts about a finished file: kind by extension, ffprobe duration for
    media when ffprobe is on PATH, entry count for a zip. Never reads content into
    the manifest."""
    ext = os.path.splitext(path)[1].lower()
    if ext in MEDIA_EXTS:
        kind = "media"
    elif ext in ARCHIVE_EXTS:
        kind = "archive"
    elif ext in IMAGE_EXTS:
        kind = "image"
    elif ext in TEXT_EXTS:
        kind = "text"
    elif ext in CAPTURE_EXTS:
        kind = "capture"
    elif ext in DOCUMENT_EXTS:
        kind = "document"
    else:
        kind = "other"
    d = {"kind": kind, "ext": ext}
    if kind == "media" and shutil.which("ffprobe"):
        try:
            r = subprocess.run(
                ["ffprobe", "-v", "error", "-show_entries", "format=duration",
                 "-of", "default=noprint_wrappers=1:nokey=1", path],
                capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and r.stdout.strip():
                d["duration_sec"] = round(float(r.stdout.strip()), 1)
        except Exception:
            pass
    elif ext == ".zip":
        try:
            with zipfile.ZipFile(path) as z:
                d["entries"] = len(z.namelist())
        except Exception:
            d["entries"] = None
    return d


def finalize(upload_id, handle):
    """The .part is complete: hash it (1 MiB reads, outside the lock), pick a
    never-overwrite name under the finalize lock, move it into UPLOAD_DIR, digest,
    mark the id json done, append one manifest row."""
    part = _part_path(upload_id)
    st = load_state(upload_id) or {}
    name = sanitize_name(st.get("name") or "") or (upload_id[:12] + ".bin")
    size, sha = _sha256_file(part)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with _FINALIZE_LOCK:
        dest = _unique_dest(name)
        os.replace(part, dest)
    info = _digest(dest)
    now = _now()
    st.update({
        "name": name,
        "done": True,
        "path": _fwd(dest),
        "bytes": size,
        "sha256": sha,
        "committed": size,
        "total": st.get("total") or size,
        "handle": st.get("handle") or handle,
        "finished": now,
        "updated": now,
        "digest": info,
    })
    save_state(upload_id, st)
    manifest_append({
        "event": "upload", "ts": now, "handle": st.get("handle") or handle, "id": upload_id,
        "path": _fwd(dest), "name": os.path.basename(dest), "bytes": size, "sha256": sha,
        "digest": info,
    })
    return {"ok": True, "done": True, "path": _fwd(dest), "name": os.path.basename(dest),
            "bytes": size, "sha256": sha}


# ---------------------------------------------------------------- status / abort / note

def _transcript_view(st):
    tr = st.get("transcript")
    if not tr:
        return None
    view = dict(tr)
    if view.get("state") == "running":
        started = float(view.get("started_epoch") or 0)
        if started and time.time() - started > INGEST_TIMEOUT_SEC:
            view["state"] = "failed"
            view["error"] = (f"no result after {INGEST_TIMEOUT_SEC // 3600} h; "
                             "the worker probably died (see its _transcribe.log)")
    return view


def status(upload_id):
    """{bytes, total, done, path, sha256, transcript} from the part/json state.
    The resume protocol and the duplicate check in one call. Unknown id: bytes 0,
    total None, done False. Also sweeps stale parts opportunistically."""
    _check_id(upload_id)
    gc()
    out = {"bytes": 0, "total": None, "done": False, "path": None, "sha256": None, "transcript": None}
    st = load_state(upload_id)
    if not st:
        return out
    if st.get("done"):
        if st.get("path") and os.path.isfile(st["path"]):
            out.update({"bytes": st.get("bytes"), "total": st.get("total"), "done": True,
                        "path": _fwd(st["path"]), "name": st.get("name"),
                        "sha256": st.get("sha256"), "transcript": _transcript_view(st)})
        return out
    committed = int(st.get("committed") or 0)
    out.update({"bytes": min(committed, have_bytes(upload_id)), "total": st.get("total"),
                "name": st.get("name")})
    return out


def abort(upload_id):
    """Delete the .part and the id json. Waits briefly for an in-flight slice so
    Windows does not refuse to delete an open file."""
    _check_id(upload_id)
    lk = id_lock(upload_id)
    got = lk.acquire(timeout=5)
    try:
        removed = []
        for p in (_part_path(upload_id), _state_path(upload_id)):
            try:
                os.remove(p)
                removed.append(os.path.basename(p))
            except FileNotFoundError:
                pass
            except OSError as e:
                return {"ok": False, "removed": removed,
                        "error": f"could not remove {os.path.basename(p)}: {e.__class__.__name__}"}
        return {"ok": True, "removed": removed}
    finally:
        if got:
            lk.release()


def note(upload_id, text, handle):
    """Lukas's own words about an upload, typed into the receipt card, as a
    manifest 'note' row. Explicit and visible; nothing is sniffed from chat."""
    _check_id(upload_id)
    text = (text or "").strip()
    if not text:
        return {"ok": False, "error": "empty note"}
    text = text[:4000]
    st = load_state(upload_id) or {}
    manifest_append({
        "event": "note", "ts": _now(), "handle": handle, "id": upload_id,
        "path": _fwd(st.get("path")), "name": st.get("name"), "sha256": st.get("sha256"),
        "note": text,
    })
    return {"ok": True}


# ---------------------------------------------------------------- legacy single shot

def legacy_write(rfile, length, name, handle):
    """The pre-2026-09-22 format: whole file in one body, no X-Upload-Total.
    Same as server.py's original write with two fixes: a short body is a 400 and
    the partial file is deleted; a success appends a manifest row."""
    name = sanitize_name(name)
    if not name:
        return (400, {"error": "missing or unusable X-Filename header"})
    try:
        length = int(length)
    except (TypeError, ValueError):
        length = 0
    if length <= 0:
        return (400, {"error": "empty body"})
    if length > UPLOAD_LEGACY_MAX:
        return (413, {"error": f"file too large (max {UPLOAD_LEGACY_MAX // (1024 * 1024)} MiB)"})
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    try:
        with _FINALIZE_LOCK:
            dest = _unique_dest(name)
            f = open(dest, "wb")   # created under the lock so a parallel write sees it
    except ValueError:
        return (403, {"error": "refused"})
    remaining, written = length, 0
    h = hashlib.sha256()
    with f:
        while remaining > 0:
            try:
                chunk = rfile.read(min(READ_CHUNK, remaining))
            except OSError:
                chunk = b""
            if not chunk:
                break
            f.write(chunk)
            h.update(chunk)
            written += len(chunk)
            remaining -= len(chunk)
        f.flush()
        os.fsync(f.fileno())
    if written != length:
        try:
            os.remove(dest)
        except OSError:
            pass
        return (400, {"error": "short body", "bytes": written, "expected": length})
    sha = h.hexdigest()
    manifest_append({
        "event": "upload", "ts": _now(), "handle": handle, "path": _fwd(dest),
        "name": os.path.basename(dest), "bytes": written, "sha256": sha,
        "digest": _digest(dest), "mode": "legacy",
    })
    return (200, {"ok": True, "path": _fwd(dest), "name": os.path.basename(dest),
                  "bytes": written, "sha256": sha})


# ---------------------------------------------------------------- gc

def gc(force=False):
    """Sweep .part/.json/.tmp files older than STALE_PART_DAYS. A json for a
    finished upload whose file still exists is kept: it is the duplicate check and
    the transcript state, not an abandoned upload. Throttled to once per
    GC_MIN_INTERVAL_SEC unless forced. Returns the number of files removed."""
    global _GC_LAST
    now = time.time()
    if not force and now - _GC_LAST < GC_MIN_INTERVAL_SEC:
        return 0
    _GC_LAST = now
    if not os.path.isdir(PARTS_DIR):
        return 0
    cutoff = now - STALE_PART_DAYS * 86400
    removed = 0
    for fn in os.listdir(PARTS_DIR):
        full = os.path.join(PARTS_DIR, fn)
        if not os.path.isfile(full):
            continue
        try:
            mtime = os.path.getmtime(full)
        except OSError:
            continue
        if mtime >= cutoff:
            continue
        if fn.endswith(".json"):
            try:
                with open(full, "r", encoding="utf-8") as f:
                    st = json.load(f)
            except (OSError, ValueError):
                st = None
            if st and st.get("done") and st.get("path") and os.path.isfile(st["path"]):
                continue
        elif not (fn.endswith(".part") or fn.endswith(".tmp")):
            continue
        if _lock_is_held(fn.split(".", 1)[0]):
            continue
        try:
            os.remove(full)
            removed += 1
        except OSError:
            pass
    return removed


# ---------------------------------------------------------------- manifest

def manifest_append(row):
    """One JSON line. Rows carry event (upload | note | transcript), ts, handle and
    metadata (path, name, bytes, sha256, a note's text); never file content."""
    row = dict(row)
    row.setdefault("ts", _now())
    line = json.dumps(row, ensure_ascii=False) + "\n"
    with _MANIFEST_LOCK:
        os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
        with open(MANIFEST, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())


def _manifest_rows():
    rows = []
    try:
        with open(MANIFEST, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows


# ---------------------------------------------------------------- transcribe

def start_transcribe(upload_id):
    """Spawn the detached worker for a finished media upload. It survives a
    dashboard restart (own process group, no console), runs at below-normal
    priority so it does not fight the resident Ollama model, and logs to
    <stem>_transcribe.log beside the source."""
    _check_id(upload_id)
    st = load_state(upload_id)
    if not st or not st.get("done") or not st.get("path") or not os.path.isfile(st["path"]):
        return {"ok": False, "error": "upload is not finished"}
    path = st["path"]
    if os.path.splitext(path)[1].lower() not in MEDIA_EXTS:
        return {"ok": False, "error": "not a media file"}
    tr = _transcript_view(st) or {}
    if tr.get("state") in ("running", "done"):
        return {"ok": True, "already": True, "transcript": tr}
    log_path = os.path.splitext(path)[0] + "_transcribe.log"
    st["transcript"] = {"state": "running", "started": _now(), "started_epoch": time.time(),
                        "log": _fwd(log_path)}
    save_state(upload_id, st)
    flags = (getattr(subprocess, "DETACHED_PROCESS", 0)
             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
             | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0))
    with open(log_path, "ab") as logf:
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "transcribe", upload_id],
            cwd=MY_AGENT, stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT,
            creationflags=flags, close_fds=True)
    st = load_state(upload_id) or st
    tr = dict(st.get("transcript") or {})
    if tr.get("state") == "running":   # the worker has not already finished (or failed fast)
        tr["pid"] = proc.pid
        st["transcript"] = tr
        save_state(upload_id, st)
    return {"ok": True, "pid": proc.pid, "transcript": st.get("transcript")}


def split_transcript(transcript_md_path):
    """Split <stem>_transcript.md (as tools/media.py transcribe writes it) into
    <stem>_transcript/00-index.md plus part-NNN.md pieces under PART_CHAR_LIMIT
    chars, cutting only between timestamped segments (lines opening with
    **[mm:ss]**). Each part is headed 'Part n of N, mm:ss to mm:ss'; the index
    lists every part's time range. Re-running replaces the previous pieces."""
    with open(transcript_md_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    starts = [i for i, ln in enumerate(lines) if SEG_RE.match(ln)]
    header = [ln for ln in (lines[:starts[0]] if starts else lines) if ln.strip()]
    segments = []
    for k, i in enumerate(starts):
        j = starts[k + 1] if k + 1 < len(starts) else len(lines)
        block = lines[i:j]
        while block and not block[-1].strip():
            block.pop()
        segments.append((SEG_RE.match(block[0]).group(1), "\n".join(block)))

    budget = PART_CHAR_LIMIT - 120   # room for the heading; a part is never split mid-segment
    groups, cur, cur_len = [], [], 0
    for seg in segments:
        add = len(seg[1]) + 2
        if cur and cur_len + add > budget:
            groups.append(cur)
            cur, cur_len = [], 0
        cur.append(seg)
        cur_len += add
    if cur:
        groups.append(cur)

    out_dir = os.path.splitext(transcript_md_path)[0]
    os.makedirs(out_dir, exist_ok=True)
    for old in os.listdir(out_dir):
        if old == "00-index.md" or re.fullmatch(r"part-\d{3}\.md", old):
            try:
                os.remove(os.path.join(out_dir, old))
            except OSError:
                pass

    n_parts = len(groups)
    source = os.path.basename(transcript_md_path)
    title = source[:-len("_transcript.md")] if source.endswith("_transcript.md") else source
    index = [f"# Transcript index: {title}", "",
             f"Source: {source}. {len(segments)} segments in {n_parts} parts, each under "
             f"{PART_CHAR_LIMIT:,} characters so one read_file call takes a whole part. "
             "Read part-001.md first; every part is headed with its time range.", ""]
    extra = [ln for ln in header if not ln.startswith("#")]
    if extra:
        index.extend(extra + [""])
    files = []
    oversize = 0
    for n, group in enumerate(groups, 1):
        first, last = group[0][0], group[-1][0]
        heading = f"# Part {n} of {n_parts}, {first} to {last}"
        text = heading + "\n\n" + "\n\n".join(s[1] for s in group) + "\n"
        if len(text) >= PART_CHAR_LIMIT:
            oversize += 1   # a single segment longer than the limit; cannot be split honestly
        path = os.path.join(out_dir, f"part-{n:03d}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        files.append(path)
        index.append(f"- part-{n:03d}.md: {first} to {last} ({len(group)} segments, {len(text):,} chars)")
    if not groups:
        index.append("(no timestamped segments found in the transcript)")
    index_path = os.path.join(out_dir, "00-index.md")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(index) + "\n")
    return {"dir": _fwd(out_dir), "index": _fwd(index_path), "parts": n_parts,
            "segments": len(segments), "files": [_fwd(p) for p in files], "oversize": oversize}


def _cmd_transcribe(upload_id):
    """The detached worker. Runs `py tools/media.py transcribe <path> --out <md>` (which
    authorizes the source against tools/marty_tools.scope.json and the output against its
    own work dirs, then writes <stem>_transcript.md beside the upload atomically), splits
    the result, records done/failed in the id json and one manifest row."""
    def say(msg):
        print(f"[{_now()}] {msg}", flush=True)

    try:
        _check_id(upload_id)
    except ValueError:
        say("bad upload id")
        return 2
    st = load_state(upload_id)
    if not st or not st.get("done") or not st.get("path"):
        say("no finished upload for this id")
        return 2
    path = st["path"]
    tr = dict(st.get("transcript") or {})
    tr.update({"state": "running", "pid": os.getpid(),
               "started": tr.get("started") or _now(),
               "started_epoch": tr.get("started_epoch") or time.time()})
    st["transcript"] = tr
    save_state(upload_id, st)

    md = os.path.splitext(path)[0] + "_transcript.md"
    say(f"transcribing {path}")
    error, info = None, None
    t0 = time.time()
    try:
        # --out explicitly: media.py transcribe defaults to my-agent/tmp/media/transcripts/,
        # never beside the source (audit finding 3), and without this every upload
        # transcription would end in "exited 0 but wrote no transcript".
        r = subprocess.run([sys.executable, MEDIA_PY, "transcribe", path, "--out", md], cwd=MY_AGENT,
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=INGEST_TIMEOUT_SEC)
        if r.stdout.strip():
            say("media.py stdout: " + r.stdout.strip()[-2000:])
        if r.stderr.strip():
            say("media.py stderr: " + r.stderr.strip()[-2000:])
        if r.returncode != 0:
            error = (r.stderr.strip() or r.stdout.strip() or f"exit {r.returncode}")[-600:]
        elif not os.path.isfile(md):
            error = "media.py transcribe exited 0 but wrote no transcript"
        else:
            info = split_transcript(md)
    except subprocess.TimeoutExpired:
        error = f"transcribe timed out after {INGEST_TIMEOUT_SEC // 3600} h"
    except Exception as e:
        error = f"{e.__class__.__name__}: {e}"[-600:]
    elapsed = round(time.time() - t0, 1)

    st = load_state(upload_id) or st
    tr = dict(st.get("transcript") or tr)
    now = _now()
    if error:
        tr.update({"state": "failed", "finished": now, "error": error, "elapsed_sec": elapsed})
    else:
        tr.pop("error", None)
        tr.update({"state": "done", "finished": now, "elapsed_sec": elapsed, "transcript": _fwd(md),
                   "dir": info["dir"], "index": info["index"], "parts": info["parts"],
                   "segments": info["segments"]})
    st["transcript"] = tr
    save_state(upload_id, st)
    row = {"event": "transcript", "ts": now, "handle": st.get("handle"), "id": upload_id,
           "path": _fwd(path), "name": st.get("name"), "sha256": st.get("sha256"),
           "status": tr["state"], "elapsed_sec": elapsed}
    if error:
        row["error"] = error
    else:
        row.update({"transcript": _fwd(md), "dir": info["dir"], "parts": info["parts"],
                    "segments": info["segments"]})
    manifest_append(row)
    say(f"{tr['state']} in {elapsed} s" + (f": {error}" if error else f": {info['parts']} parts in {info['dir']}"))
    return 1 if error else 0


# ---------------------------------------------------------------- backfill

def _cmd_backfill():
    """Manifest 'upload' rows for files already sitting in UPLOAD_DIR that were
    placed by hand before the endpoint existed. Skips anything already in the
    manifest and the derived sidecars (transcripts, logs, temp files)."""
    if not os.path.isdir(UPLOAD_DIR):
        print(f"no uploads folder at {UPLOAD_DIR}")
        return 0
    known = {_fwd(r["path"]).lower() for r in _manifest_rows()
             if r.get("event") == "upload" and r.get("path")}
    added = 0
    for fn in sorted(os.listdir(UPLOAD_DIR)):
        full = os.path.join(UPLOAD_DIR, fn)
        if not os.path.isfile(full) or fn.startswith(".") or fn == os.path.basename(MANIFEST):
            continue
        if fn.endswith(("_transcript.md", "_transcribe.log", ".tmp")):
            continue
        if _fwd(full).lower() in known:
            print(f"skip   {fn} (already in the manifest)")
            continue
        size, sha = _sha256_file(full)
        manifest_append({
            "event": "upload", "ts": _now(), "handle": "backfill", "path": _fwd(full), "name": fn,
            "bytes": size, "sha256": sha, "digest": _digest(full),
            "note": f"backfilled {date.today().isoformat()}, placed by hand",
        })
        added += 1
        print(f"added  {fn}  {size:,} bytes  sha256 {sha[:12]}")
    print(f"backfill: {added} row(s) added to {MANIFEST}")
    return 0


# ---------------------------------------------------------------- selftest

def _cmd_selftest():
    """Hermetic: UPLOAD_DIR/PARTS_DIR/MANIFEST point at a temp dir, disk_usage is
    patched, rfile is io.BytesIO, the connection is a stub. No network, nothing
    written outside the temp dir. One line per check, exit 1 on any failure."""
    global UPLOAD_DIR, PARTS_DIR, MANIFEST, _GC_LAST
    results = []

    def check(label, cond, detail=""):
        ok = bool(cond)
        results.append(ok)
        print(("ok    " if ok else "FAIL  ") + label + (f"  [{detail}]" if detail and not ok else ""))

    class Usage:
        def __init__(self, free):
            self.total, self.used, self.free = free * 2, free, free

    class Conn:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, t):
            self.timeouts.append(t)

    class TimeoutRF:
        """Delivers `after` bytes, then raises socket.timeout like a stalled phone."""
        def __init__(self, data, after):
            self.buf, self.after, self.n = io.BytesIO(data), after, 0

        def read(self, n):
            if self.n >= self.after:
                raise socket.timeout("fake idle timeout")
            b = self.buf.read(min(n, self.after - self.n))
            self.n += len(b)
            return b

    def rf(b):
        return io.BytesIO(b)

    def rows():
        return _manifest_rows()

    def part_bytes(uid):
        try:
            with open(_part_path(uid), "rb") as f:
                return f.read()
        except OSError:
            return None

    real_manifest_existed = os.path.exists(MANIFEST)
    real_parts_listing = sorted(os.listdir(PARTS_DIR)) if os.path.isdir(PARTS_DIR) else None
    saved = (UPLOAD_DIR, PARTS_DIR, MANIFEST, shutil.disk_usage, _GC_LAST)
    tmp = tempfile.mkdtemp(prefix="intake-selftest-")
    UPLOAD_DIR = os.path.join(tmp, "uploads")
    PARTS_DIR = os.path.join(UPLOAD_DIR, ".parts")
    MANIFEST = os.path.join(UPLOAD_DIR, "manifest.jsonl")
    fake = {"free": 200 * 1024 ** 3}
    shutil.disk_usage = lambda p: Usage(fake["free"])
    _GC_LAST = 0.0
    conn = Conn()
    ID_A = hashlib.sha256(b"upload a").hexdigest()
    ID_B = hashlib.sha256(b"upload b").hexdigest()
    ID_C = hashlib.sha256(b"upload c").hexdigest()
    ID_D = hashlib.sha256(b"upload d").hexdigest()
    ID_E = hashlib.sha256(b"upload e").hexdigest()
    print(f"selftest in {tmp}")
    try:
        # -- sanitisation, verbatim from server.py
        check("sanitize_name strips directories and traversal",
              sanitize_name("..%2F..%2Fetc%2Fpasswd") == "passwd", sanitize_name("..%2F..%2Fetc%2Fpasswd"))
        check("sanitize_name drops leading dots and backslash paths",
              sanitize_name("C:\\Users\\x\\..hidden.txt") == "hidden.txt")
        check("sanitize_name replaces odd characters and is idempotent",
              sanitize_name("spaced  name?.mp4") == "spaced  name_.mp4"
              and sanitize_name(sanitize_name("100%.txt")) == sanitize_name("100%.txt"))
        check("id_lock returns one lock per id",
              id_lock(ID_A) is id_lock(ID_A) and id_lock(ID_A) is not id_lock(ID_B))

        # -- refusals before any byte lands
        r = rf(b"x" * 10)
        res = append_chunk(r, conn, ID_A, 0, 10, UPLOAD_TOTAL_MAX + 1, "big.bin", "lukas")
        check("413 on total over cap, body drained", res and res[0] == 413 and r.tell() == 10, res)
        check("socket timeout set to CHUNK_IDLE_SEC for the read", CHUNK_IDLE_SEC in conn.timeouts)
        r = rf(b"x")
        res = append_chunk(r, conn, ID_A, 0, UPLOAD_PART_MAX + 1, 100 * 1024 ** 2, "big.bin", "lukas")
        check("413 on part over cap, body not drained", res and res[0] == 413 and r.tell() == 0, res)
        r = rf(b"x" * 10)
        res = append_chunk(r, conn, ID_A, 5, 10, 12, "a.bin", "lukas")
        check("400 on offset+length over total, body drained", res and res[0] == 400 and r.tell() == 10, res)
        fake["free"] = UPLOAD_FREE_RESERVE + 5
        r = rf(b"x" * 10)
        res = append_chunk(r, conn, ID_A, 0, 10, 1000, "a.bin", "lukas")
        check("507 on disk reserve, body drained", res and res[0] == 507 and r.tell() == 10, res)
        fake["free"] = 200 * 1024 ** 3
        r = rf(b"x" * 10)
        res = append_chunk(r, conn, "zz", 0, 10, 100, "a.bin", "lukas")
        check("400 on a bad upload id", res and res[0] == 400 and r.tell() == 10, res)
        r = rf(b"x" * 10)
        res = append_chunk(r, conn, ID_A, 0, 10, 100, "", "lukas")
        check("400 on an unusable filename", res and res[0] == 400 and r.tell() == 10, res)
        check("no .part created by any refusal", have_bytes(ID_A) == 0 and not os.path.exists(_part_path(ID_A)))
        r = rf(b"x" * 5)
        res = append_chunk(r, conn, ID_A, 10, 5, 100, "a.bin", "lukas")
        check("409 on wrong offset for a fresh id, bytes 0",
              res and res[0] == 409 and res[1].get("bytes") == 0 and r.tell() == 5, res)

        # -- a real two-chunk upload with every failure mode in between
        data = bytes(range(256)) * 400          # 102,400 bytes
        total = len(data)
        c1, c2 = data[:60000], data[60000:]
        res = append_chunk(rf(c1), conn, ID_A, 0, len(c1), total, "report.txt", "lukas")
        check("first chunk accepted, done false, bytes 60000",
              res and res[0] == 200 and res[1] == {"ok": True, "done": False, "bytes": 60000}, res)
        st = load_state(ID_A)
        check("id json has the designed keys",
              st and all(k in st for k in ("name", "original_name", "total", "committed", "handle", "created", "updated"))
              and st["committed"] == 60000 and st["total"] == total and st["handle"] == "lukas", st)
        r = rf(b"x" * 5)
        res = append_chunk(r, conn, ID_A, 3, 5, total, "report.txt", "lukas")
        check("409 on wrong offset mid-upload returns the byte count",
              res and res[0] == 409 and res[1].get("bytes") == 60000 and r.tell() == 5, res)
        lk = id_lock(ID_A)
        lk.acquire()
        try:
            r = rf(b"x" * 5)
            res = append_chunk(r, conn, ID_A, 60000, 5, total, "report.txt", "lukas")
        finally:
            lk.release()
        check("409 chunk in flight on a busy lock, body drained",
              res and res[0] == 409 and res[1].get("error") == "chunk in flight"
              and res[1].get("bytes") == 60000 and r.tell() == 5, res)
        with open(_part_path(ID_A), "ab") as f:
            f.write(b"JUNKJUNK")
        check("torn tail visible before repair", have_bytes(ID_A) == 60008)
        check("repair_tail truncates to committed", repair_tail(ID_A) == 60000 and part_bytes(ID_A) == c1)
        res = append_chunk(rf(c2[:12000]), conn, ID_A, 60000, 20000, total, "report.txt", "lukas")
        check("short body returns None and leaves the valid prefix",
              res is None and have_bytes(ID_A) == 60000 and part_bytes(ID_A) == c1
              and load_state(ID_A)["committed"] == 60000, res)
        res = append_chunk(TimeoutRF(c2, 5000), conn, ID_A, 60000, 20000, total, "report.txt", "lukas")
        check("socket timeout returns None and leaves the valid prefix",
              res is None and have_bytes(ID_A) == 60000 and part_bytes(ID_A) == c1, res)
        res = append_chunk(rf(c2), conn, ID_A, 60000, len(c2), total, "report.txt", "lukas",
                           expected_sha="0" * 64)
        check("422 on hash mismatch, bytes unchanged",
              res and res[0] == 422 and res[1].get("bytes") == 60000 and have_bytes(ID_A) == 60000, res)
        r = rf(c2)
        res = append_chunk(r, conn, ID_A, 60000, len(c2), total, "report.txt", "lukas", expected_sha="nothex")
        check("400 on a malformed X-Chunk-SHA256, body drained",
              res and res[0] == 400 and r.tell() == len(c2) and have_bytes(ID_A) == 60000, res)
        r = rf(c2)
        res = append_chunk(r, conn, ID_A, 60000, len(c2), total + 1, "report.txt", "lukas")
        check("400 when total changes mid-upload", res and res[0] == 400 and r.tell() == len(c2), res)
        want = hashlib.sha256(data).hexdigest()
        res = append_chunk(rf(c2), conn, ID_A, 60000, len(c2), total, "report.txt", "lukas",
                           expected_sha=hashlib.sha256(c2).hexdigest().upper())
        check("final chunk with a correct sha finalises with done true and the file sha256",
              res and res[0] == 200 and res[1].get("done") is True and res[1].get("sha256") == want
              and res[1].get("bytes") == total and res[1].get("name") == "report.txt", res)
        final_path = res[1]["path"] if res else ""
        with open(final_path, "rb") as f:
            landed = f.read()
        check("finished file is byte-identical and lives under UPLOAD_DIR with forward slashes",
              landed == data and "\\" not in final_path
              and os.path.abspath(final_path).startswith(os.path.abspath(UPLOAD_DIR)))
        check("no .part left behind after finalize", not os.path.exists(_part_path(ID_A)))
        st = load_state(ID_A)
        check("id json marked done with path and sha256",
              st and st.get("done") is True and st.get("sha256") == want and st.get("path") == final_path, st)
        rs = rows()
        check("exactly one manifest row, event upload, matching sha256",
              len(rs) == 1 and rs[0]["event"] == "upload" and rs[0]["sha256"] == want
              and rs[0]["bytes"] == total and rs[0]["handle"] == "lukas" and rs[0].get("id") == ID_A, rs)
        s = status(ID_A)
        check("status for a done id answers with its path and sha256",
              s["done"] is True and s["path"] == final_path and s["sha256"] == want
              and s["bytes"] == total and s["total"] == total, s)
        r = rf(c1)
        res = append_chunk(r, conn, ID_A, 0, len(c1), total, "report.txt", "lukas")
        check("append on a done id answers done without moving bytes",
              res and res[0] == 200 and res[1].get("done") is True and res[1].get("duplicate") is True
              and r.tell() == len(c1) and not os.path.exists(_part_path(ID_A)), res)

        # -- legacy single shot
        res = legacy_write(rf(b"abc"), 10, "short.txt", "lukas")
        check("legacy short body -> 400 with no file left",
              res[0] == 400 and res[1].get("error") == "short body"
              and not os.path.exists(os.path.join(UPLOAD_DIR, "short.txt")) and len(rows()) == 1, res)
        res = legacy_write(rf(b"x"), UPLOAD_LEGACY_MAX + 1, "huge.bin", "lukas")
        check("legacy over 64 MiB -> 413 before reading", res[0] == 413, res)
        body = b"hello legacy"
        res = legacy_write(rf(body), len(body), "report.txt", "lukas")
        check("legacy success -> 200 with sha256 and a manifest row",
              res[0] == 200 and res[1]["sha256"] == hashlib.sha256(body).hexdigest()
              and res[1]["bytes"] == len(body) and len(rows()) == 2 and rows()[-1]["event"] == "upload"
              and rows()[-1].get("mode") == "legacy", res)
        check("collision suffix: second report.txt lands as report-1.txt", res[1]["name"] == "report-1.txt", res)
        res = legacy_write(rf(body), len(body), "report.txt", "lukas")
        check("collision suffix: third lands as report-2.txt", res[0] == 200 and res[1]["name"] == "report-2.txt", res)
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as z:
            z.writestr("a.txt", "a")
            z.writestr("b/c.txt", "c")
        zb = zbuf.getvalue()
        res = legacy_write(rf(zb), len(zb), "bundle.zip", "lukas")
        check("zip digest records the entry count",
              res[0] == 200 and rows()[-1]["digest"].get("kind") == "archive" and rows()[-1]["digest"].get("entries") == 2, rows()[-1])

        # -- status / abort / note
        s = status(ID_B)
        check("status for an unknown id", s == {"bytes": 0, "total": None, "done": False, "path": None, "sha256": None, "transcript": None}, s)
        res = append_chunk(rf(b"0123456789"), conn, ID_B, 0, 10, 30, "partial.bin", "lukas")
        s = status(ID_B)
        check("status for a partial id reports committed bytes and total",
              res and res[0] == 200 and s["bytes"] == 10 and s["total"] == 30 and s["done"] is False, s)
        res = abort(ID_B)
        check("abort removes part and json",
              res.get("ok") and not os.path.exists(_part_path(ID_B)) and not os.path.exists(_state_path(ID_B))
              and status(ID_B)["bytes"] == 0 and status(ID_B)["total"] is None, res)
        text = "this is the lab pcap, look at it tomorrow"
        res = note(ID_A, text, "lukas")
        last = rows()[-1]
        check("note row carries Lukas's words and the file's path",
              res == {"ok": True} and last["event"] == "note" and last["note"] == text
              and last["path"] == final_path and last["sha256"] == want, last)
        check("empty note refused", note(ID_A, "   ", "lukas").get("ok") is False)
        bad = False
        try:
            status("../../etc")
        except ValueError:
            bad = True
        check("status raises ValueError on a bad id before any path join", bad)

        # -- transcript splitting on a synthetic media.py-style transcript
        seg_lines = []
        for i in range(60):
            mm, ss = divmod(i * 7, 60)
            seg_lines.append(f"**[{mm:02d}:{ss:02d}]** " + ("word " * 58).strip() + f" segment {i}")
            seg_lines.append("")
        md_path = os.path.join(tmp, "Video_transcript.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(["# Transcript: Video.mp4", "",
                               "Model faster-whisper small.en. Language en (0.99). Speakers are not labeled; "
                               "Whisper does not separate voices.", ""] + seg_lines))
        info = split_transcript(md_path)
        parts_dir = os.path.join(tmp, "Video_transcript")
        check("split_transcript writes <stem>_transcript/ with an index and parts",
              info["dir"] == _fwd(parts_dir) and os.path.isfile(os.path.join(parts_dir, "00-index.md"))
              and info["parts"] >= 3 and info["segments"] == 60 and info["oversize"] == 0, info)
        sizes_ok, heads_ok, bounds_ok, stamps = True, True, True, 0
        for n, p in enumerate(info["files"], 1):
            with open(p, "r", encoding="utf-8") as f:
                txt = f.read()
            sizes_ok &= len(txt) < PART_CHAR_LIMIT
            first_body = txt.split("\n\n", 1)[1].splitlines()[0]
            m = re.match(r"# Part (\d+) of (\d+), (\d+:\d\d) to (\d+:\d\d)$", txt.splitlines()[0])
            heads_ok &= bool(m) and int(m.group(1)) == n and int(m.group(2)) == info["parts"]
            bounds_ok &= bool(SEG_RE.match(first_body))
            body_stamps = [ln for ln in txt.splitlines() if SEG_RE.match(ln)]
            stamps += len(body_stamps)
            heads_ok &= bool(m) and SEG_RE.match(body_stamps[0]).group(1) == m.group(3) \
                and SEG_RE.match(body_stamps[-1]).group(1) == m.group(4)
        check("every part is under 5,000 chars", sizes_ok)
        check("every part is headed 'Part n of N, mm:ss to mm:ss' matching its segments", heads_ok)
        check("parts split only between timestamped segments, none lost", bounds_ok and stamps == 60, stamps)
        with open(os.path.join(parts_dir, "00-index.md"), "r", encoding="utf-8") as f:
            idx = f.read()
        check("index lists every part with its time range",
              all(f"part-{n:03d}.md: " in idx for n in range(1, info["parts"] + 1)) and "00:00 to " in idx)
        info2 = split_transcript(md_path)
        check("re-splitting replaces the pieces instead of accreting",
              info2["parts"] == info["parts"]
              and len([x for x in os.listdir(parts_dir) if x.startswith("part-")]) == info["parts"])

        # -- gc of stale parts
        old = time.time() - (STALE_PART_DAYS + 1) * 86400
        append_chunk(rf(b"stale"), conn, ID_C, 0, 5, 50, "stale.bin", "lukas")
        append_chunk(rf(b"fresh"), conn, ID_D, 0, 5, 50, "fresh.bin", "lukas")
        for p in (_part_path(ID_C), _state_path(ID_C), _state_path(ID_A)):
            os.utime(p, (old, old))
        with open(os.path.join(PARTS_DIR, ID_E + ".json.1.2.tmp"), "w") as f:
            f.write("{}")
        os.utime(os.path.join(PARTS_DIR, ID_E + ".json.1.2.tmp"), (old, old))
        removed = gc(force=True)
        check("gc removes stale .part/.json/.tmp and keeps fresh ones and finished state",
              removed == 3 and not os.path.exists(_part_path(ID_C)) and not os.path.exists(_state_path(ID_C))
              and os.path.exists(_part_path(ID_D)) and os.path.exists(_state_path(ID_D))
              and os.path.exists(_state_path(ID_A)), removed)
        check("gc is throttled between forced runs", gc() == 0)

        # -- start_transcribe refusals need no process spawn
        res = start_transcribe(ID_D)
        check("start_transcribe refuses an unfinished upload", res.get("ok") is False, res)
        res = start_transcribe(ID_A)
        check("start_transcribe refuses a non-media file", res.get("ok") is False and "media" in res.get("error", ""), res)

        # -- manifest hygiene
        rs = rows()
        check("manifest rows carry event/ts/handle and never a content field",
              all({"event", "ts", "handle"} <= set(r) for r in rs)
              and not any(k in r for r in rs for k in ("content", "data", "body", "token")), rs)
    finally:
        UPLOAD_DIR, PARTS_DIR, MANIFEST, shutil.disk_usage, _GC_LAST = saved
        shutil.rmtree(tmp, ignore_errors=True)
    real_parts_now = sorted(os.listdir(PARTS_DIR)) if os.path.isdir(PARTS_DIR) else None
    check("nothing written outside the temp dir",
          os.path.exists(MANIFEST) == real_manifest_existed and real_parts_now == real_parts_listing)
    failed = results.count(False)
    print(f"selftest: {len(results)} checks, {failed} failed, temp dir "
          + ("removed" if not os.path.exists(tmp) else f"left at {tmp}"))
    return 1 if failed else 0


# ---------------------------------------------------------------- entry

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "transcribe" and len(sys.argv) == 3:
        sys.exit(_cmd_transcribe(sys.argv[2]))
    elif cmd == "backfill":
        sys.exit(_cmd_backfill())
    elif cmd == "selftest":
        sys.exit(_cmd_selftest())
    else:
        print("usage: intake.py transcribe <upload-id> | backfill | selftest")
        sys.exit(2)
