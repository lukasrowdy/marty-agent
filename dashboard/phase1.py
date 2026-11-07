"""MJ Dashboard Phase 1 helpers.

All file access is confined to the dashboard's own outbox and runtime folders.
Talk audio is written to a random temporary file, transcribed by the existing
local faster-whisper environment, and deleted before the request returns. A
crash mid-transcription cannot delete it, so the server sweeps leftover talk-*
files out of runtime/talk at start (sweep_talk_temp), before the weekly recovery
bundle could copy one to the NAS. Marty Jr.'s microphone (Phase 2, W3) uses the
same function, folder and prefix, plus an abort hook: the server stops his
transcription (kills the transcriber) the moment Jr locks. The transcript only
ever travels through the transcriber's stdout pipe, never through a file.

Jobs reads real sources only, all read-only: live dashboard chat jobs, the
supervisor's status file, the backup log, Marty's Windows scheduled tasks, and
the newest line of the tool-call activity log (Marty working at the PC). Every
row says who is doing it and where. A source that cannot be read shows as
"source unavailable"; it never fails the whole request. The curated half (what
is waiting on Lukas, queued work, what closed out today) is board.py's.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import pathlib
import re
import secrets
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone

import board
import live_feed


CODE_DIR = pathlib.Path(__file__).resolve().parent
DASHBOARD_DIR = pathlib.Path(os.environ.get("MARTY_DASH_ROOT") or CODE_DIR).resolve()
AGENT_ROOT = pathlib.Path(os.environ.get("MARTY_AGENT_ROOT") or DASHBOARD_DIR.parent).resolve()
OUTBOX_DIR = pathlib.Path(os.environ.get("MARTY_OUTBOX_ROOT") or (DASHBOARD_DIR / "outbox")).resolve()
STATUS_PATH = AGENT_ROOT / "logs" / "marty-services.status.json"
ACTIVITY_PATH = DASHBOARD_DIR / "activity.jsonl"      # the PostToolUse hook's feed (log_activity.py)
BACKUP_LOG_PATH = AGENT_ROOT / "logs" / "backup-marty.log"
TALK_DIR = DASHBOARD_DIR / "runtime" / "talk"
TALK_PREFIX = "talk-"
TRANSCRIBER = CODE_DIR / "transcribe_audio.py"
BACKTALK_PYTHON = AGENT_ROOT / "backtalk" / ".venv" / "Scripts" / "python.exe"
MAX_AUDIO = 25 * 1024 * 1024
ALLOWED_AUDIO = {
    "audio/webm": ".webm",
    "audio/mp4": ".mp4",
    "audio/mpeg": ".mp3",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "application/octet-stream": ".webm",
}
TALK_LOCK = threading.Lock()
TRANSCRIBE_TIMEOUT = 180
ABORT_POLL_SECONDS = 0.25     # how often an abortable transcription asks whether to stop


class TranscriberBusy(RuntimeError):
    """Another transcription holds the one local transcriber (Talk and Jr share it)."""


class TranscriptionAborted(RuntimeError):
    """The caller's abort hook said stop (Jr locked); the transcriber was killed."""

# --- Jobs sources -----------------------------------------------------------
JOBS_CACHE_SECONDS = 30
TASK_QUERY_TIMEOUT = 8
BACKUP_LOG_TAIL_BYTES = 64 * 1024
ACTIVITY_TAIL_BYTES = 8 * 1024
# A tool call this recent means a Marty session is working at the PC right now. Every session
# in my-agent logs to the same file, so this is "Marty is working", not which session.
ACTIVITY_ACTIVE_SECONDS = 10 * 60
# Logged runs finish in about a minute (longest single step so far: 24 s). A run
# whose newest line is older than this never logged a finish: it is reported as
# stalled under waiting_on_you, never as running.
BACKUP_STALE_SECONDS = 2 * 60 * 60
_BACKUP_LINE = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (.*)$")
# Marty's tasks live in the Task Scheduler root folder and are named "Marty ...".
TASK_NAME_PREFIX = "Marty"
# The supervisor task re-fires every 5 minutes and stays Running while the PC is
# up. It is infrastructure, not work in progress; its services are reported from
# marty-services.status.json instead.
ALWAYS_ON_TASKS = frozenset({"Marty Services"})
# Tasks whose work the backup log already describes in more detail.
BACKUP_TASKS = frozenset({"Marty Weekly Backup"})
# Read-only query. Get-ScheduledTaskInfo runs only for Running tasks.
_TASK_QUERY = (
    "$ErrorActionPreference = 'Stop'; "
    "$rows = @(Get-ScheduledTask -TaskPath '\\' | "
    "Where-Object { $_.TaskName -like '" + TASK_NAME_PREFIX + "*' } | ForEach-Object { "
    "$s = [string]$_.State; $last = $null; "
    "if ($s -eq 'Running') { $i = $_ | Get-ScheduledTaskInfo; "
    "if ($i.LastRunTime) { $last = $i.LastRunTime.ToString('yyyy-MM-ddTHH:mm:sszzz') } }; "
    "[pscustomobject]@{ name = $_.TaskName; state = $s; last_run = $last } }); "
    "ConvertTo-Json -InputObject $rows -Compress"
)
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()
_REFRESH_LOCKS: dict[str, threading.Lock] = {}


def _utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


def _file_id(path: pathlib.Path) -> str:
    return hashlib.sha256(path.name.encode("utf-8")).hexdigest()[:20]


def list_files() -> list[dict]:
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in OUTBOX_DIR.iterdir():
        if not path.is_file() or path.is_symlink():
            continue
        stat = path.stat()
        rows.append({
            "id": _file_id(path),
            "name": path.name,
            "bytes": stat.st_size,
            "added": _utc_iso(stat.st_mtime),
        })
    return sorted(rows, key=lambda row: row["added"], reverse=True)


def resolve_file(file_id: str) -> pathlib.Path | None:
    if not isinstance(file_id, str) or len(file_id) != 20:
        return None
    for row in list_files():
        if secrets.compare_digest(row["id"], file_id):
            path = (OUTBOX_DIR / row["name"]).resolve()
            if path.parent == OUTBOX_DIR and path.is_file() and not path.is_symlink():
                return path
    return None


def content_type(path: pathlib.Path) -> str:
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def _local_iso(dt: datetime) -> str:
    """ISO time with this PC's UTC offset. Naive values are local clock times."""
    return dt.astimezone().isoformat(timespec="seconds")


def _clock(dt: datetime, now: datetime) -> str:
    """Short local time for the one-line job state, e.g. '3:00 AM' or 'Sep 24 8:44 PM'."""
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    text = f"{dt.hour % 12 or 12}:{dt.minute:02d} {'AM' if dt.hour < 12 else 'PM'}"
    return text if dt.date() == now.date() else f"{dt:%b} {dt.day} {text}"


def _job(name: str, source: str, state: str, **extra) -> dict:
    row = {"name": name, "done": 0, "total": None, "eta": None, "source": source, "state": state}
    row.update(extra)
    return row


def parse_backup_log(text: str, now: datetime) -> dict:
    """Latest backup run from backup-marty.log text.

    Line format (backup-marty.ps1): "[YYYY-MM-DD HH:MM:SS] message", local time.
    A run starts at "Starting Marty backup" and ends at "Marty backup finished..."
    or "FAILED: ...". The log has no progress total and no ETA, so none is shown;
    the count and name of completed steps are real and are shown.
    """
    run = None
    for raw in text.splitlines():
        match = _BACKUP_LINE.match(raw.strip().lstrip("﻿"))
        if not match:
            continue
        try:
            ts = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        message = match.group(2).strip()
        if message == "Starting Marty backup":
            run = {"start": ts, "last": ts, "step": None, "steps": 0, "end": None, "failed": None}
        elif run is None or run["end"] is not None:
            continue
        elif message.startswith("Marty backup finished"):
            run["end"] = ts
        elif message.startswith("FAILED"):
            run["end"], run["failed"] = ts, message
        else:
            run["last"], run["step"] = ts, message.split(":", 1)[0].split(" (", 1)[0]
            run["steps"] += 1
    running, waiting = [], []
    if run is None:
        return {"running": running, "waiting_on_you": waiting}
    if run["end"] is None:
        if (now - run["last"]).total_seconds() <= BACKUP_STALE_SECONDS:
            state = f"started {_clock(run['start'], now)}"
            if run["step"]:
                state += f" · {run['step']}"
            running.append(_job("Marty backup", "backup log", state, done=run["steps"],
                                started=_local_iso(run["start"]), active=True,
                                who="Weekly backup", where="NAS"))
        else:
            waiting.append({"title": f"Backup started {_clock(run['start'], now)} "
                                     "and never logged a finish",
                            "since": _local_iso(run["start"])})
    elif run["failed"]:
        waiting.append({"title": f"Last backup failed: {run['failed'][len('FAILED:'):].strip()[:160]}",
                        "since": _local_iso(run["end"])})
    return {"running": running, "waiting_on_you": waiting}


def _read_backup_tail(path: pathlib.Path) -> str:
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - BACKUP_LOG_TAIL_BYTES))
        data = fh.read()
    if size > BACKUP_LOG_TAIL_BYTES:
        data = data.split(b"\n", 1)[-1]   # drop the partial first line
    return data.decode("utf-8-sig", errors="replace")


def _backup_source() -> dict:
    try:
        text = _read_backup_tail(BACKUP_LOG_PATH)
    except FileNotFoundError:
        return {"running": [], "waiting_on_you": []}   # no backup has ever run
    return parse_backup_log(text, datetime.now())


def parse_task_rows(data, now: datetime) -> list[dict]:
    """Running Marty scheduled tasks from the query's JSON (a list of
    {name, state, last_run}). Raises ValueError on an unexpected shape."""
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("task query returned an unexpected shape")
    rows = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("task query returned an unexpected row")
        name = item["name"]
        if item.get("state") != "Running" or name in ALWAYS_ON_TASKS:
            continue
        state, extra = "running", {}
        try:
            started = datetime.fromisoformat(item.get("last_run") or "")
            state = f"running since {_clock(started, now)}"
            extra["started"] = started.isoformat(timespec="seconds")
        except (TypeError, ValueError):
            pass
        rows.append(_job(name, "Task Scheduler", state, task=name, who="Scheduled task",
                         where="This PC", **extra))
    return rows


def _run_task_query() -> str:
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _TASK_QUERY],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=TASK_QUERY_TIMEOUT, stdin=subprocess.DEVNULL,
        # The dashboard runs hidden; without this every refresh flashes a console.
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"task query exited {proc.returncode}")
    return proc.stdout


def _tasks_source() -> dict:
    return {"running": parse_task_rows(json.loads(_run_task_query() or "[]"), datetime.now()),
            "waiting_on_you": []}


def _guarded(loader) -> dict:
    try:
        result = loader()
        return {"ok": True, "running": list(result.get("running") or []),
                "waiting_on_you": list(result.get("waiting_on_you") or [])}
    except Exception as exc:   # any failure degrades to "source unavailable"
        return {"ok": False, "error": type(exc).__name__, "running": [], "waiting_on_you": []}


def _cached(key: str, loader) -> dict:
    """Cache a source for JOBS_CACHE_SECONDS; one refresh at a time per source."""
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and time.monotonic() - hit[0] < JOBS_CACHE_SECONDS:
            return hit[1]
        lock = _REFRESH_LOCKS.setdefault(key, threading.Lock())
    with lock:
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
            if hit and time.monotonic() - hit[0] < JOBS_CACHE_SECONDS:
                return hit[1]
        value = _guarded(loader)
        with _CACHE_LOCK:
            _CACHE[key] = (time.monotonic(), value)
        return value


def _chat_rows(manager, handle: str) -> list[dict]:
    rows = []
    for jid in list(getattr(manager, "running", ())):
        job = manager.get(handle, jid)
        if not job:
            continue
        # lane is the brain id; the page names it (LANES in app.js)
        step = (getattr(manager, "step_now", None) or {}).get(jid)
        rows.append(_job("Chat reply", "dashboard chat", step or job.get("progress") or "running", job_id=jid,
                         who="Marty", where="Dashboard chat", lane=job.get("brain") or ""))
    return rows


def parse_activity_tail(text: str, now: datetime) -> list[dict]:
    """A 'Marty at the PC' row from the newest activity line, if it is recent enough.

    Line format (log_activity.py): {"ts": UTC ISO, "tool": name, "summary": one line, "desc"?}. Only
    the newest well-formed line counts; a torn last line is skipped, not an error. The row's state is
    live_feed.activity_label(row), the rule GET /api/live and GET /api/activity use (2026-09-26, tool
    privacy): the summary itself can hold a command, a path, a URL, a query or a message body."""
    for raw in reversed(text.splitlines()):
        try:
            row = json.loads(raw)
            ts = datetime.fromisoformat(row["ts"])
        except (ValueError, KeyError, TypeError):
            continue
        if not isinstance(row, dict) or ts.tzinfo is None:
            continue
        age = (now - ts).total_seconds()
        if age > ACTIVITY_ACTIVE_SECONDS or age < -60:
            return []
        summary = live_feed.activity_label(row)[:140]
        return [_job("Marty at the PC", "activity log", summary, who="Marty", where="This PC",
                     started=ts.isoformat(timespec="seconds"), last_step=True)]
    return []


def _activity_source() -> dict:
    try:
        with ACTIVITY_PATH.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - ACTIVITY_TAIL_BYTES))
            text = fh.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return {"running": [], "waiting_on_you": []}
    return {"running": parse_activity_tail(text, datetime.now(timezone.utc)), "waiting_on_you": []}


def _supervisor_source() -> dict:
    # Only surface service work that actually needs attention. Healthy daemons are
    # infrastructure, not pretend jobs, and stale status.json tasks are excluded.
    try:
        status = json.loads(STATUS_PATH.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return {"running": [], "waiting_on_you": []}
    rows = []
    for service in status.get("services") or []:
        state = service.get("state")
        if state in {"starting", "unresponsive", "hung", "down", "held", "foreign"}:
            rows.append(_job(service.get("name") or "service", "Marty Services supervisor",
                             state, eta=service.get("held_until"), who="Service supervisor",
                             where="This PC"))
    return {"running": rows, "waiting_on_you": []}


BOARD_DIR = None      # None = board.py's default (my-agent/status); selftest points it at a temp folder


def jobs_payload(manager, handle: str) -> dict:
    running, waiting, sources = [], [], {}
    results = [("dashboard chat", _guarded(lambda: {"running": _chat_rows(manager, handle)})),
               ("Marty Services supervisor", _guarded(_supervisor_source)),
               ("backup log", _cached("backup log", _backup_source)),
               ("Task Scheduler", _cached("Task Scheduler", _tasks_source)),
               ("activity log", _guarded(_activity_source))]
    backup_active = any(row.get("active") for row in results[2][1]["running"])
    for label, result in results:
        sources[label] = "ok" if result["ok"] else "source unavailable"
        if not result["ok"]:
            running.append(_job(f"Can't check {label}", label, "source unavailable"))
            continue
        for row in result["running"]:
            # One backup, one row: the log row carries the step detail.
            if backup_active and row.get("task") in BACKUP_TASKS:
                continue
            running.append(row)
        waiting.extend(result["waiting_on_you"])
    # A missing or bad board.json comes back as {"ok": False, "error": ...}; anything unexpected
    # is caught here too, so the board can never take the live rows (or the login probe) down.
    try:
        board_view = board.payload(BOARD_DIR)
    except Exception as exc:
        board_view = {"ok": False, "error": f"the board could not be read ({type(exc).__name__})",
                      "waiting": [], "work": [], "done": []}
    sources["board"] = "ok" if board_view["ok"] else "source unavailable"
    return {"running": running, "waiting_on_you": waiting, "sources": sources, "board": board_view}


def _run_transcriber(argv: list, env: dict, abort) -> subprocess.CompletedProcess:
    """Run the transcriber. With no abort hook (Talk) this is the plain subprocess.run it has
    always been. With one (Jr), the child is polled every ABORT_POLL_SECONDS and killed the
    moment abort() is true (TranscriptionAborted) or the timeout passes (TimeoutExpired, as
    subprocess.run raises). Output stays in this process's memory either way."""
    if abort is None:
        return subprocess.run(
            argv, cwd=str(CODE_DIR), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=TRANSCRIBE_TIMEOUT, env=env,
        )
    proc = subprocess.Popen(
        argv, cwd=str(CODE_DIR), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", env=env,
    )
    deadline = time.monotonic() + TRANSCRIBE_TIMEOUT
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=ABORT_POLL_SECONDS)
                return subprocess.CompletedProcess(argv, proc.returncode, out, err)
            except subprocess.TimeoutExpired:
                # Retrying communicate() after its timeout loses no output (subprocess docs).
                if abort():
                    raise TranscriptionAborted("transcription stopped") from None
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv, TRANSCRIBE_TIMEOUT) from None
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.communicate(timeout=10)    # reap it; whatever it printed is dropped
            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass


def transcribe_bytes(body: bytes, content_type_header: str, abort=None) -> dict:
    """Transcribe one recording on this PC. abort: optional no-argument callable; when it returns
    true mid-transcription the transcriber is killed and TranscriptionAborted is raised (Marty
    Jr.'s lock). The temp audio file is deleted in every case."""
    media_type = (content_type_header or "").split(";", 1)[0].strip().lower()
    suffix = ALLOWED_AUDIO.get(media_type)
    if suffix is None:
        raise ValueError("unsupported audio type")
    if not body:
        raise ValueError("empty audio")
    if len(body) > MAX_AUDIO:
        raise ValueError("audio exceeds 25 MB")
    if not BACKTALK_PYTHON.exists():
        raise RuntimeError("local transcription environment is missing")
    if not TALK_LOCK.acquire(blocking=False):
        raise TranscriberBusy("another transcription is already running")
    path = None
    try:
        runtime = TALK_DIR
        runtime.mkdir(parents=True, exist_ok=True)
        path = runtime / f"{TALK_PREFIX}{secrets.token_hex(12)}{suffix}"
        started = time.monotonic()
        path.write_bytes(body)
        env = os.environ.copy()
        env["HF_HUB_OFFLINE"] = "1"
        env["TRANSFORMERS_OFFLINE"] = "1"
        proc = _run_transcriber([str(BACKTALK_PYTHON), str(TRANSCRIBER), str(path)], env, abort)
        try:
            result = json.loads((proc.stdout or "").strip())
        except ValueError as exc:
            raise RuntimeError((proc.stderr or proc.stdout or "transcription failed")[:300]) from exc
        if proc.returncode or not result.get("ok"):
            raise RuntimeError(result.get("error") or "transcription failed")
        return {
            "text": (result.get("text") or "").strip(),
            "seconds": round(time.monotonic() - started, 2),
            "audio_seconds": result.get("audio_seconds"),
        }
    finally:
        if path is not None:
            _unlink_soon(path)
        TALK_LOCK.release()


def _unlink_soon(path: pathlib.Path, tries: int = 20, pause: float = 0.05) -> bool:
    """Delete a Talk temp file, retrying briefly: on Windows a transcriber that was just killed
    can hold the file for a moment. Anything still stuck is left to sweep_talk_temp at start."""
    for attempt in range(tries):
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:
            if attempt + 1 < tries:
                time.sleep(pause)
    return False


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link(st: os.stat_result) -> bool:
    """A symlink, a junction or any other reparse point (from an lstat, never a followed stat)."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def sweep_talk_temp() -> tuple[int, int]:
    """Delete Talk audio a crash left behind: regular files named talk-* directly inside
    runtime/talk, and nothing else. Never follows a link and never recurses: a link, junction
    or folder named talk-* is left alone, and if runtime or runtime/talk is itself a link or
    junction nothing is touched (ValueError). Returns (deleted, could not delete). The server
    calls it once at start, when none of its own transcriptions can be running."""
    for folder in (TALK_DIR.parent, TALK_DIR):
        try:
            st = os.lstat(folder)
        except FileNotFoundError:
            return 0, 0
        if _is_link(st) or not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"{folder.name} is a link or not a folder; nothing swept")
    deleted = stuck = 0
    with os.scandir(TALK_DIR) as entries:
        for entry in entries:
            if not entry.name.startswith(TALK_PREFIX):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if _is_link(st) or not stat.S_ISREG(st.st_mode):
                continue
            try:
                os.unlink(entry.path)       # unlink never follows a link, even if one was swapped in
                deleted += 1
            except OSError:
                stuck += 1
    return deleted, stuck


# Fixture text in the real formats, captured 2026-09-25 (paths shortened).
_FIXTURE_BACKUP_DONE = (
    "﻿[2026-09-17 13:31:13] Starting Marty backup\n"
    "[2026-09-17 13:31:14] Marty backup finished\n"
    "[2026-09-24 20:44:56] Starting Marty backup\n"
    "[2026-09-24 20:44:57] Vault mirrored (robocopy code 1)\n"
    "[2026-09-24 20:44:57] Configs copied\n"
    '[2026-09-24 20:45:04] Recovery bundle built: {"files": 209, "bytes": 21070839}\n'
    "[2026-09-24 20:45:33] Marty backup finished OK\n"
)
_FIXTURE_BACKUP_ACTIVE = (
    "[2026-09-24 20:45:33] Marty backup finished OK\n"
    "not a log line\n"
    "[2026-09-25 03:00:02] Starting Marty backup\n"
    "[2026-09-25 03:00:03] Vault mirrored (robocopy code 1)\n"
    "[2026-09-25 03:00:04] Handoff vault mirrored, ciphertext only (robocopy codes 0 / 0)\n"
)
_FIXTURE_BACKUP_FAILED = (
    "[2026-09-21 10:45:35] Starting Marty backup\n"
    "[2026-09-21 10:45:35] FAILED: NAS share not reachable: \\\\NAS\\share\n"
)
_FIXTURE_TASKS = (
    '[{"name":"Marty Services","state":"Running","last_run":"2026-09-25T12:25:01-05:00"},'
    '{"name":"Marty Weekly Backup","state":"Running","last_run":"2026-09-25T03:00:01-05:00"},'
    '{"name":"Marty Other","state":"Ready","last_run":null}]'
)


def selftest() -> bool:
    import shutil

    root = pathlib.Path(tempfile.mkdtemp(prefix="mj-phase1-"))
    saved = {name: globals()[name] for name in (
        "OUTBOX_DIR", "STATUS_PATH", "BACKUP_LOG_PATH", "_run_task_query", "JOBS_CACHE_SECONDS", "TALK_DIR",
        "BACKTALK_PYTHON", "TRANSCRIBER", "ACTIVITY_PATH", "BOARD_DIR")}
    no_manager = type("M", (), {"running": set()})()
    try:
        globals()["OUTBOX_DIR"] = root
        globals()["STATUS_PATH"] = root / "missing-status.json"
        globals()["BACKUP_LOG_PATH"] = root / "missing-backup.log"
        globals()["ACTIVITY_PATH"] = root / "missing-activity.jsonl"
        globals()["BOARD_DIR"] = root / "board"
        globals()["_run_task_query"] = lambda: "[]"
        _CACHE.clear()
        (root / "report.txt").write_text("phase one", encoding="utf-8")
        rows = list_files()
        assert len(rows) == 1 and rows[0]["name"] == "report.txt"
        assert resolve_file(rows[0]["id"]).read_text(encoding="utf-8") == "phase one"
        assert resolve_file("../report.txt") is None

        # Empty state: nothing running, every live source readable; no board file yet.
        payload = jobs_payload(no_manager, "lukas")
        assert payload["running"] == [] and payload["waiting_on_you"] == [], payload
        assert payload["board"]["ok"] is False and payload["board"]["waiting"] == [], payload
        assert payload["sources"].pop("board") == "source unavailable", payload
        assert set(payload["sources"].values()) == {"ok"}, payload

        # The board rides along, answers attached; a bad board degrades, never raises.
        (root / "board").mkdir()
        (root / "board" / "board.json").write_text(json.dumps({
            "version": 1, "as_of": "2026-09-26T09:50:00-05:00",
            "waiting": [{"id": "q-1", "title": "Pick", "body": "Body", "where": "Test", "choices": ["Yes", "No"]}],
            "work": [{"id": "w-1", "what": "Thing", "who": "Marty", "where": "PC", "state": "queued"}],
            "done": []}), encoding="utf-8")
        board.record_answer("lukas", "q-1", "No", "", root / "board")
        view = jobs_payload(no_manager, "lukas")["board"]
        assert view["ok"] and view["waiting"][0]["answer"]["choice"] == "No", view
        assert view["work"][0]["who"] == "Marty", view
        (root / "board" / "board.json").write_text("{", encoding="utf-8")
        assert jobs_payload(no_manager, "lukas")["board"]["ok"] is False
        real_payload = board.payload
        board.payload = lambda _dir: (_ for _ in ()).throw(PermissionError("locked"))
        try:
            view = jobs_payload(no_manager, "lukas")
            assert view["board"]["ok"] is False and "PermissionError" in view["board"]["error"], view
        finally:
            board.payload = real_payload

        # Activity: the newest well-formed line within ACTIVITY_ACTIVE_SECONDS is "Marty at the PC".
        utc = datetime(2026, 9, 26, 14, 10, 0, tzinfo=timezone.utc)
        fresh = '{"ts": "2026-09-26T14:07:42+00:00", "tool": "Bash", "summary": "Build the board", "desc": "Build the board"}'
        old = '{"ts": "2026-09-26T13:00:00+00:00", "tool": "Read", "summary": "old"}'
        rows = parse_activity_tail(old + "\n" + fresh + '\n{"ts": "2026-09-26T14:0', utc)
        assert len(rows) == 1 and rows[0]["state"] == "Build the board" and rows[0]["who"] == "Marty", rows
        # Only the label (plus a Bash/PowerShell/Agent description) is shown, never the summary.
        for line, want in (('{"ts": "2026-09-26T14:07:42+00:00", "tool": "Bash", "summary": "curl -u me:CANARY-4410"}',
                            "Running a command"),
                           ('{"ts": "2026-09-26T14:07:42+00:00", "tool": "Read", "summary": "Read: C:/CANARY-4410.txt"}',
                            "Reading a file"),
                           ('{"ts": "2026-09-26T14:07:42+00:00", "tool": "WebFetch", "summary": "fetched: https://CANARY-4410"}',
                            "Reading a web page")):
            got = parse_activity_tail(line, utc)
            assert got and got[0]["state"] == want and "CANARY" not in json.dumps(got), got
        assert parse_activity_tail(old, utc) == [], "an old line is not 'working now'"
        assert parse_activity_tail("", utc) == [] and parse_activity_tail("[1]\nnot json", utc) == []
        assert parse_activity_tail('{"ts": "2026-09-26T14:09:00", "summary": "naive"}', utc) == []
        (root / "activity.jsonl").write_text(
            json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "tool": "Edit", "summary": "Now"}) + "\n",
            encoding="utf-8")
        globals()["ACTIVITY_PATH"] = root / "activity.jsonl"
        payload = jobs_payload(no_manager, "lukas")
        assert [r["name"] for r in payload["running"]] == ["Marty at the PC"], payload
        globals()["ACTIVITY_PATH"] = root / "missing-activity.jsonl"

        # Backup log parser, real formats.
        now = datetime(2026, 9, 25, 3, 1, 0)
        assert parse_backup_log(_FIXTURE_BACKUP_DONE, now) == {"running": [], "waiting_on_you": []}
        assert parse_backup_log("", now) == {"running": [], "waiting_on_you": []}
        active = parse_backup_log(_FIXTURE_BACKUP_ACTIVE, now)
        row = active["running"][0]
        assert row["state"] == "started 3:00 AM · Handoff vault mirrored, ciphertext only", row
        assert row["done"] == 2 and row["total"] is None and row["eta"] is None, row
        assert row["started"].startswith("2026-09-25T03:00:02"), row
        stale = parse_backup_log(_FIXTURE_BACKUP_ACTIVE, datetime(2026, 9, 25, 9, 0, 0))
        assert stale["running"] == [], stale
        assert stale["waiting_on_you"][0]["title"] == \
            "Backup started 3:00 AM and never logged a finish", stale
        failed = parse_backup_log(_FIXTURE_BACKUP_FAILED, now)
        assert failed["running"] == [], failed
        assert failed["waiting_on_you"][0]["title"].startswith(
            "Last backup failed: NAS share not reachable"), failed

        # Scheduled task parser: Running only, always-on supervisor excluded.
        tasks = parse_task_rows(json.loads(_FIXTURE_TASKS), now)
        assert [t["name"] for t in tasks] == ["Marty Weekly Backup"], tasks
        assert tasks[0]["state"] == "running since 3:00 AM", tasks
        assert parse_task_rows({"name": "Marty Services", "state": "Running"}, now) == []
        assert parse_task_rows([], now) == []
        for bad in ("oops", [1], [{"state": "Running"}]):
            try:
                parse_task_rows(bad, now)
                raise AssertionError(f"accepted {bad!r}")
            except ValueError:
                pass

        # Integrated: an active backup shows once (log row wins over the task row).
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        (root / "backup.log").write_text(
            _FIXTURE_BACKUP_ACTIVE.replace("2026-09-25 03:00", stamp), encoding="utf-8")
        globals()["BACKUP_LOG_PATH"] = root / "backup.log"
        globals()["_run_task_query"] = lambda: _FIXTURE_TASKS
        _CACHE.clear()
        payload = jobs_payload(no_manager, "lukas")
        assert [r["source"] for r in payload["running"]] == ["backup log"], payload

        # Cache: the task query runs once per JOBS_CACHE_SECONDS, not per request.
        calls = []
        globals()["_run_task_query"] = lambda: calls.append(1) or "[]"
        _CACHE.clear()
        jobs_payload(no_manager, "lukas")
        jobs_payload(no_manager, "lukas")
        assert len(calls) == 1, calls
        globals()["JOBS_CACHE_SECONDS"] = 0
        jobs_payload(no_manager, "lukas")
        assert len(calls) == 2, calls

        # Failures degrade per source, never raise.
        def timed_out():
            raise subprocess.TimeoutExpired("powershell.exe", TASK_QUERY_TIMEOUT)
        globals()["_run_task_query"] = timed_out
        globals()["STATUS_PATH"] = root / "report.txt"   # not JSON
        payload = jobs_payload(no_manager, "lukas")
        assert payload["sources"]["Task Scheduler"] == "source unavailable", payload
        assert payload["sources"]["Marty Services supervisor"] == "source unavailable", payload
        assert payload["sources"]["backup log"] == "ok", payload
        assert {r["state"] for r in payload["running"] if r["name"].startswith("Can't check")} == {
            "source unavailable"}, payload
        globals()["_run_task_query"] = lambda: "not json"
        assert jobs_payload(no_manager, "lukas")["sources"]["Task Scheduler"] == "source unavailable"

        # Talk temp sweep: regular talk-* files directly in runtime/talk go; nothing else does.
        talk = root / "dash" / "runtime" / "talk"
        outside = root / "outside"
        (talk / "talk-dir").mkdir(parents=True)
        outside.mkdir()
        (talk / "talk-dir" / "talk-inner.webm").write_bytes(b"not recursed into")
        (talk / "talk-4f1e2d3c4b5a69788796a5b4.webm").write_bytes(b"left by a crash")
        (talk / "talk-0123456789abcdef01234567.wav").write_bytes(b"left by a crash")
        (talk / "keep.webm").write_bytes(b"not a talk temp file")
        (outside / "talk-victim.webm").write_bytes(b"precious")
        (outside / "victim.txt").write_bytes(b"precious")
        made = []
        try:
            os.symlink(outside / "victim.txt", talk / "talk-link.webm")
            made.append("talk-link.webm")
        except (OSError, NotImplementedError):
            pass                                # needs Developer Mode or admin on Windows
        try:
            import _winapi
            _winapi.CreateJunction(str(outside), str(talk / "talk-junction"))
            made.append("talk-junction")
        except (ImportError, AttributeError, OSError):
            pass
        globals()["TALK_DIR"] = talk
        assert sweep_talk_temp() == (2, 0)
        left = sorted(p.name for p in talk.iterdir())
        assert left == sorted(["keep.webm", "talk-dir"] + made), left
        assert (talk / "talk-dir" / "talk-inner.webm").exists()
        assert (outside / "talk-victim.webm").read_bytes() == b"precious"
        assert (outside / "victim.txt").read_bytes() == b"precious"
        assert sweep_talk_temp() == (0, 0)
        links_tested = list(made)
        if "talk-junction" in made:
            # runtime/talk itself a junction to somewhere else: nothing there is touched.
            jroot = root / "dash2" / "runtime"
            jroot.mkdir(parents=True)
            _winapi.CreateJunction(str(outside), str(jroot / "talk"))
            globals()["TALK_DIR"] = jroot / "talk"
            try:
                sweep_talk_temp()
                raise AssertionError("swept through a junctioned runtime/talk")
            except ValueError:
                pass
            assert (outside / "talk-victim.webm").read_bytes() == b"precious"
            os.rmdir(jroot / "talk")            # removes the junction only
            links_tested.append("runtime/talk junction")
        for name in made:                       # remove the links themselves, never their targets
            (os.rmdir if name == "talk-junction" else os.unlink)(talk / name)
        globals()["TALK_DIR"] = root / "nowhere" / "runtime" / "talk"
        assert sweep_talk_temp() == (0, 0)
        print(f"phase1 selftest: talk sweep checked (links tested: {', '.join(links_tested) or 'none'})")

        # Transcription with a fake transcriber: the plain path (Talk), the abort hook (Jr's lock),
        # busy and failure. The talk-* temp file is gone after every one of them.
        import sys
        fake = root / "fake_transcriber.py"
        fake.write_text(
            "import json, os, pathlib, sys, time\n"
            "data = pathlib.Path(sys.argv[1]).read_bytes()\n"
            "marks = pathlib.Path(os.environ['MJ_FAKE_TRANSCRIBER_DIR'])\n"
            "if data.startswith(b'SLOW'):\n"
            "    (marks / 'started').write_text('x')\n"
            "    time.sleep(20)\n"
            "    (marks / 'finished').write_text('x')\n"
            "if data.startswith(b'FAIL'):\n"
            "    print(json.dumps({'ok': False, 'error': 'fake failure'})); sys.exit(1)\n"
            "print(json.dumps({'ok': True, 'text': ' heard ' + data.decode()[:12], 'audio_seconds': 1.5}))\n",
            encoding="utf-8")
        marks = root / "marks"
        marks.mkdir()
        talk = root / "dash3" / "runtime" / "talk"
        globals().update(BACKTALK_PYTHON=pathlib.Path(sys.executable), TRANSCRIBER=fake, TALK_DIR=talk)
        os.environ["MJ_FAKE_TRANSCRIBER_DIR"] = str(marks)
        try:
            got = transcribe_bytes(b"hello there", "audio/webm;codecs=opus")
            assert got["text"] == "heard hello there" and got["audio_seconds"] == 1.5, got
            got = transcribe_bytes(b"hello again", "audio/wav", abort=lambda: False)
            assert got["text"] == "heard hello again", got
            assert list(talk.iterdir()) == [], "a temp file was left behind"
            for bad, ctype in ((b"x", "text/plain"), (b"", "audio/webm")):
                try:
                    transcribe_bytes(bad, ctype)
                    raise AssertionError(f"accepted {ctype} / {len(bad)} bytes")
                except ValueError:
                    pass
            try:
                transcribe_bytes(b"FAIL now", "audio/webm")
                raise AssertionError("a failed transcription returned")
            except RuntimeError as exc:
                assert str(exc) == "fake failure" and not isinstance(exc, (TranscriberBusy, TranscriptionAborted))
            t0 = time.monotonic()
            try:
                transcribe_bytes(b"SLOW please", "audio/webm",
                                 abort=lambda: (marks / "started").exists() and time.monotonic() - t0 > 0.3)
                raise AssertionError("an aborted transcription returned")
            except TranscriptionAborted:
                pass
            took = time.monotonic() - t0
            assert took < 8, f"abort took {took:.1f} s"
            time.sleep(0.5)
            assert not (marks / "finished").exists(), "the transcriber kept running after the abort"
            assert list(talk.iterdir()) == [], "the aborted run left its temp file"
            assert TALK_LOCK.acquire(blocking=False), "the aborted run kept the transcriber lock"
            try:
                transcribe_bytes(b"busy", "audio/webm")
                raise AssertionError("ran while another transcription held the lock")
            except TranscriberBusy as exc:
                assert isinstance(exc, RuntimeError)       # Talk still answers it as before
            finally:
                TALK_LOCK.release()
            print(f"phase1 selftest: transcriber paths checked (abort stopped it in {took:.2f} s)")
        finally:
            os.environ.pop("MJ_FAKE_TRANSCRIBER_DIR", None)
        print("phase1 selftest: all checks passed")
        return True
    finally:
        globals().update(saved)
        _CACHE.clear()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
