"""
Durable dashboard chat: jobs and conversations (2026-09-23).

Why this exists. /api/chat used to run the whole turn inside the HTTP request and send the
reply down the same connection. A phone that locked, switched apps or reloaded while a
long turn ran dropped that connection, the reply was thrown away with
ConnectionAbortedError 10053, and 19 replies were lost that way on the morning of
2026-09-23. The browser also held the only copy of the conversation, so a reload forgot it.

Now a message becomes a JOB with an id, run on a server thread, saved to disk, and polled
by the browser. Closing the tab does not stop it; reopening shows it. A dashboard restart
marks a running job "interrupted"; the page says so and Lukas sends the message again.

Two kinds of conversation, never mixed:
  - "console": the cloud brains (Claude, Gemini, GPT) share one thread per session id,
    which the page keeps in localStorage;
  - "local": the Local lane (marty-local on this PC). Its turns never leave the machine,
    so they are never part of what a cloud brain is sent, and it keeps its own thread.
The history sent with a turn is question-and-answer text only, newest first, up to
CONTEXT_CHARS; the whole transcript stays on disk.

New conversation (the chat pane's button, POST /api/chat/new): the lane's current
conversation is ARCHIVED, not deleted - its file stays in sessions/ with archived_at set,
it is never shown or continued again, and a fresh empty conversation of the same kind
takes its place. Refused while a turn is running in it, so a reply is never orphaned.

Storage: my-agent/dashboard/chats/ (jobs/, sessions/). Not served by the web server (it
serves only the files it names), not in the NAS job and not in the recovery bundle, because
the NAS share is readable on the LAN. Every write is atomic (temp file, then os.replace).

Two Windows facts shape the file handling (an adversarial review reproduced both,
2026-09-23): a reader that opens a file at the instant another thread replaces it gets
PermissionError, and so can the replace itself. So a read retries a lock and reports
"unreadable" rather than pretending the file is missing, every read-modify-write of a
conversation happens under one lock, and a turn always ends with a terminal status even
if a save fails.

No network and no model here: the brains are passed in as runner functions, which is also
what lets the selftest run the whole flow with stubs.
"""

import json
import os
import pathlib
import re
import secrets
import threading
import time
from datetime import datetime

import live_feed   # step labels: the one rule every surface uses (stdlib only, no network)

ROOT = pathlib.Path(os.getenv("MARTY_CHAT_ROOT") or (pathlib.Path(__file__).resolve().parent / "chats"))  # env override isolates a test server's store
ID_RE = re.compile(r"^[0-9a-f]{16}\Z")
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}\Z")
TERMINAL = ("completed", "failed", "interrupted", "cancelled")
MAX_RUNNING = 3             # jobs running at once, all handles
CONTEXT_CHARS = 24000       # history sent with a turn (~6k tokens); the whole transcript stays on disk
MESSAGE_MAX = 20000
LOCAL_BRAINS = ("local",)   # brains that run on this PC; their turns never reach a cloud brain

# A runner executes on the job thread.  The thread-local context lets streaming
# runners publish real model output and register their subprocess without
# changing the stable runner(brain, messages) interface used by the old server.
_CONTEXT = threading.local()


def emit_current(event, data):
    manager = getattr(_CONTEXT, "manager", None)
    jid = getattr(_CONTEXT, "job_id", None)
    if manager is not None and jid:
        manager.emit(jid, event, data)


def cancel_requested():
    marker = getattr(_CONTEXT, "cancel", None)
    return bool(marker and marker.is_set())


def register_current_process(process):
    manager = getattr(_CONTEXT, "manager", None)
    jid = getattr(_CONTEXT, "job_id", None)
    if manager is not None and jid:
        manager.register_process(jid, process)


class StoreBusy(Exception):
    """A store file stayed locked through the retries (Windows). The server answers 503
    and the page retries; nothing is treated as missing or lost."""


class Unreadable(StoreBusy):
    """A store file exists but could not be read because it is locked. Never treated as
    'missing': that is how a conversation could silently be replaced by an empty one."""


class Busy(Exception):
    def __init__(self, job_id):
        super().__init__(job_id)
        self.job_id = job_id


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _new_id():
    return secrets.token_hex(8)


def kind_for(brain):
    return "local" if brain in LOCAL_BRAINS else "console"


def _write_atomic(path, obj):
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(3)}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=True)   # any text, even a lone surrogate, encodes
        f.flush()
        os.fsync(f.fileno())           # a power cut must not leave a zero-length file behind
    for attempt in range(10):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:        # Windows: a reader holding the target open for a moment
            time.sleep(0.02 * (attempt + 1))
    try:
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise StoreBusy(f"{path.name} could not be saved: {e}")


def _read(path):
    """The file's JSON; None when the file does not exist. A locked file is retried, then
    raises Unreadable (busy, try again). A corrupt file (a torn write, a power cut) is
    moved aside to <name>.corrupt-<time> and treated as missing, so the chat recovers on
    its own instead of answering 'busy' forever; the moved file keeps the evidence."""
    for attempt in range(8):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except PermissionError:
            time.sleep(0.02 * (attempt + 1))
        except ValueError:
            aside = path.with_name(f"{path.name}.corrupt-{datetime.now():%Y%m%d-%H%M%S}")
            try:
                os.replace(path, aside)
                print(f"[chatjobs] {path.name} was corrupt; moved to {aside.name}")
            except OSError:
                raise Unreadable(f"{path.name} is corrupt and could not be moved aside")
            return None
    raise Unreadable(f"{path.name} is locked (still busy after retries)")


def _wire(m):
    return {k: v for k, v in m.items() if not k.startswith("_")}


def _turns(messages):
    """Split a transcript into turns, each starting at a user message."""
    out, cur = [], []
    for m in messages:
        if m.get("role") == "user" and cur:
            out.append(cur)
            cur = []
        cur.append(m)
    if cur:
        out.append(cur)
    return out


def _final_text(turn):
    for m in reversed(turn):
        if m.get("role") == "assistant" and (m.get("content") or "").strip():
            return m["content"]
    return ""


def bounded_context(messages, budget=CONTEXT_CHARS, cloud=True):
    """The history to send with the next turn: each earlier turn as its question and its
    answer (or a note that it failed), newest first until the budget is spent.

    cloud=True keeps only turns a cloud brain answered: a Local turn, and anything without
    a brain on it, never goes to a cloud model, even if it somehow sits in the same
    conversation. cloud=False (the Local lane) keeps every turn."""
    out, used = [], 0
    for t in reversed(_turns(messages)):
        brain = t[0].get("_brain")
        if cloud and (brain is None or brain in LOCAL_BRAINS):
            continue
        pair = [{"role": "user", "content": t[0].get("content") or ""},
                {"role": "assistant", "content": _final_text(t) or "(No reply: that call failed.)"}]
        size = sum(len(m["content"]) for m in pair)
        if used + size > budget:
            break
        out = pair + out
        used += size
    return out


class Store:
    def __init__(self, root=ROOT):
        self.root = pathlib.Path(root)
        self.jobs = self.root / "jobs"
        self.sessions = self.root / "sessions"
        self.jobs.mkdir(parents=True, exist_ok=True)
        self.sessions.mkdir(parents=True, exist_ok=True)

    def job(self, jid):
        return _read(self.jobs / f"{jid}.json") if ID_RE.match(jid or "") else None

    def save_job(self, job):
        job["updated"] = _now()
        _write_atomic(self.jobs / f"{job['id']}.json", job)

    def session(self, sid):
        return _read(self.sessions / f"{sid}.json") if ID_RE.match(sid or "") else None

    def save_session(self, s):
        s["updated"] = _now()
        _write_atomic(self.sessions / f"{s['id']}.json", s)

    def all_jobs(self):
        for p in self.jobs.glob("*.json"):
            try:
                j = _read(p)
            except Unreadable:
                continue
            if j:
                yield j


class Manager:
    """runners: {"cloud": fn(brain, messages) -> result dict,
                 "local": fn(brain, messages) -> result dict}
    A result dict has status ("completed" or "failed"), answer, model, cost_usd, and
    optionally tools (the tool calls the Claude lane made) and error."""

    def __init__(self, runners, store=None, brains=("claude", "gemini", "openrouter", "local")):
        self.store = store or Store()
        self.runners = runners
        self.brains = set(brains)
        self.lock = threading.RLock()
        self.running = set()        # job ids executing in THIS process
        self.client_ids = {}        # (handle, client_id) -> job id, so a resent POST is not a second turn
        self.unsaved = {}           # job id -> finished job whose final save failed; served and retried
        self.events = {}            # live SSE events; final state remains durable in the job file
        self.event_seq = {}
        self.cancels = {}
        self.processes = {}
        self.event_condition = threading.Condition(self.lock)
        self.step_now = {}          # job id -> the step a running reply is on (see emit)
        self.recover()

    def emit(self, jid, event, data):
        """Publish one live event.  Delta events are the exact text received from
        the model transport; the server never manufactures token animation."""
        with self.event_condition:
            seq = self.event_seq.get(jid, 0) + 1
            self.event_seq[jid] = seq
            row = {"seq": seq, "event": str(event), "data": data}
            # The Jobs row shows the current step while the reply runs (memory only; gone at the end).
            if event == "step" and isinstance(data, dict):
                self.step_now[jid] = str(data.get("label") or "working")[:80]
            elif event == "delta" and jid in self.step_now:
                self.step_now[jid] = "replying"          # tools done, the reply is being written
            elif event in ("done", "error") or (event == "state" and isinstance(data, dict)
                                                  and data.get("state") in TERMINAL):
                self.step_now.pop(jid, None)
            bucket = self.events.setdefault(jid, [])
            bucket.append(row)
            if len(bucket) > 4000:
                del bucket[:len(bucket) - 4000]
            self.event_condition.notify_all()

    def events_since(self, handle, jid, after=0, wait=0.0):
        with self.event_condition:
            job = self._job(jid)
            if not job or job.get("handle") != handle:
                return None, []
            rows = [row for row in self.events.get(jid, ()) if row["seq"] > after]
            if not rows and wait and job.get("status") not in TERMINAL:
                self.event_condition.wait(timeout=wait)
                job = self._job(jid) or job
                rows = [row for row in self.events.get(jid, ()) if row["seq"] > after]
            return job, rows

    def register_process(self, jid, process):
        with self.lock:
            self.processes[jid] = process
            if self.cancels.get(jid) and self.cancels[jid].is_set():
                try:
                    process.terminate()
                except Exception:
                    pass

    def cancel(self, handle, jid):
        with self.lock:
            job = self._job(jid)
            if not job or job.get("handle") != handle:
                return None
            if job.get("status") in TERMINAL:
                return job
            marker = self.cancels.setdefault(jid, threading.Event())
            marker.set()
            job["cancel_requested"] = True
            job["progress"] = "cancelling"
            try:
                self.store.save_job(job)
            except StoreBusy:
                self.unsaved[jid] = job
            process = self.processes.get(jid)
            if process is not None:
                try:
                    process.terminate()
                except Exception:
                    pass
            self.emit(jid, "state", {"state": "cancelled"})
            return job

    def _job(self, jid):
        """A job by id: the in-memory copy of a finished job whose final save failed
        (retrying the save now), else the file."""
        j = self.unsaved.get(jid)
        if j is not None:
            try:
                self.store.save_job(j)
                self.unsaved.pop(jid, None)
            except Exception:
                pass
            return j
        j = self.store.job(jid)
        if j and j.get("status") == "running" and jid not in self.running:
            # Possibly a turn in its last moment: _run's finally releases its slot and then
            # saves the final status, all under the lock. Re-check under the lock, so only a
            # job that truly has no thread (recovery could not save it at startup) is shown
            # as interrupted.
            with self.lock:
                j = self.unsaved.get(jid) or self.store.job(jid)
                if j and j.get("status") == "running" and jid not in self.running:
                    j = dict(j, status="interrupted", stop_reason=j.get("stop_reason")
                             or "the dashboard restarted while this turn was running")
        return j

    def _running(self, s):
        """The id of the turn executing in this conversation now, or None. Only a job this
        process is actually running counts, so a stale pointer can never lock a
        conversation (a turn whose final save failed, or one from before a restart)."""
        jid = s.get("running") if s else None
        return jid if jid and jid in self.running else None

    # ------------------------------------------------------------ startup

    def recover(self):
        """Jobs still marked running belong to a server that is gone: mark them interrupted."""
        for job in self.store.all_jobs():
            try:
                self._recover_one(job)
            except Exception as e:
                print(f"[chatjobs] could not recover job {job.get('id')}: {type(e).__name__} {e}")

    def _recover_one(self, job):
        if job.get("client_id"):
            self.client_ids[(job.get("handle"), job["client_id"])] = job["id"]
        if job.get("status") == "running":
            job["status"] = "interrupted"
            job["finished"] = _now()
            job["stop_reason"] = "the dashboard restarted while this turn was running"
            self.store.save_job(job)
            try:
                s = self.store.session(job.get("session"))
            except Unreadable:
                s = None
            if s and s.get("running") == job["id"]:
                s["running"] = None
                self.store.save_session(s)

    # ------------------------------------------------------------ conversations

    def _new_session(self, handle, kind):
        s = {"id": _new_id(), "handle": handle, "kind": kind, "created": _now(),
             "messages": [], "turns": []}
        self.store.save_session(s)
        return s

    def _session(self, handle, kind, session_id):
        """The caller's live conversation of this kind, or None (not theirs, another kind,
        archived by New conversation, or gone)."""
        s = self.store.session(session_id) if session_id else None
        if s is None or s.get("handle") != handle or s.get("kind") != kind or s.get("archived_at"):
            return None
        return s

    def new_conversation(self, handle, brain, session_id=None):
        """Start a fresh conversation for this brain's lane (the cloud brains share one, Local
        has its own). The caller's current conversation of that kind, if session_id names one,
        is archived: kept on disk with archived_at set, never shown or used again. Raises Busy
        while a turn is running in it, ValueError for an unknown brain. Returns
        (new session, archived session id or None)."""
        if brain not in self.brains:
            raise ValueError(f"unknown brain {brain!r}")
        kind = kind_for(brain)
        with self.lock:
            old = self._session(handle, kind, session_id)
            if old is not None:
                running = self._running(old)
                if running:
                    raise Busy(running)
            new = self._new_session(handle, kind)
            if old is not None:
                old["archived_at"] = _now()
                old["archived_for"] = new["id"]
                self.store.save_session(old)
            return new, (old["id"] if old is not None else None)

    # ------------------------------------------------------------ submit / run

    def submit(self, handle, brain, message, *, session_id=None, client_id=None):
        """Start a turn. Returns the job (a dict). Raises Busy when that conversation
        already has a turn running, ValueError on bad input, Unreadable when the store is
        locked (the caller answers 503 and the page retries with the same client id)."""
        message = (message or "").strip()
        if not message:
            raise ValueError("empty message")
        if len(message) > MESSAGE_MAX:
            raise ValueError(f"message too long (max {MESSAGE_MAX} characters)")
        if brain not in self.brains:
            raise ValueError(f"unknown brain {brain!r}")
        if client_id is not None and not CLIENT_ID_RE.match(str(client_id)):
            client_id = None
        with self.lock:
            if len(self.events) >= 128:
                stale = [old for old in self.events if old not in self.running]
                for old in stale[:max(1, len(self.events) - 96)]:
                    self.events.pop(old, None)
                    self.event_seq.pop(old, None)
                    self.cancels.pop(old, None)
            if client_id and (handle, client_id) in self.client_ids:
                j = self.store.job(self.client_ids[(handle, client_id)])
                if j:
                    return j
            kind = kind_for(brain)
            s = self._session(handle, kind, session_id)
            if s is None:
                # No usable conversation id (first message, another device's, or a page
                # loaded before this change): start a fresh one of the right kind. A page
                # that sends its own history is never trusted with it.
                s = self._new_session(handle, kind)
            running = self._running(s)
            if running:
                raise Busy(running)
            if len(self.running) >= MAX_RUNNING:
                raise ValueError("too many turns running at once; wait for one to finish")
            job = {"id": _new_id(), "handle": handle, "brain": brain, "session": s["id"],
                   "message": message, "client_id": client_id, "status": "running",
                   "created": _now(), "started": _now(), "finished": None, "reply": "",
                   "model": None, "cost_usd": 0.0, "tools": [], "stop_reason": None,
                   "error": None, "progress": "starting"}
            self.store.save_job(job)
            s["turns"].append(job["id"])
            s["running"] = job["id"]
            try:
                self.store.save_session(s)
            except StoreBusy:
                job.update(status="failed", finished=_now(), error="the conversation could not be saved; send again")
                try:
                    self.store.save_job(job)
                except StoreBusy:
                    pass
                raise
            if client_id:
                self.client_ids[(handle, client_id)] = job["id"]
            self.running.add(job["id"])
            self.cancels[job["id"]] = threading.Event()
            self.events[job["id"]] = []
            self.event_seq[job["id"]] = 0
        threading.Thread(target=self._run, args=(job,), daemon=True,
                         name=f"chatjob-{job['id']}").start()
        return job

    def _run(self, job):
        jid = job["id"]
        result, new = None, []
        marker = self.cancels.setdefault(jid, threading.Event())
        _CONTEXT.manager = self
        _CONTEXT.job_id = jid
        _CONTEXT.cancel = marker
        self.emit(jid, "state", {"state": "starting"})
        try:
            user = {"role": "user", "content": job["message"], "_job": jid, "_brain": job["brain"],
                    "_turn_user": True}
            local = kind_for(job["brain"]) == "local"
            with self.lock:
                s = self.store.session(job["session"])
                ctx = bounded_context(s["messages"], cloud=not local) + [_wire(user)]
                s["messages"].append(user)
                self.store.save_session(s)
            job["progress"] = "thinking"
            self.emit(jid, "state", {"state": "thinking"})
            result = self.runners["local" if local else "cloud"](job["brain"], ctx)
            if result.get("status") == "completed" and result.get("answer"):
                new = [{"role": "assistant", "content": result["answer"], "_job": jid, "_brain": job["brain"]}]
        except Exception as e:
            result = {"status": "failed", "error": f"{type(e).__name__}: {e}", "answer": ""}
        finally:
            result = result or {"status": "failed", "error": "the turn ended without a result", "answer": ""}
            if marker.is_set():
                result = {"status": "cancelled", "answer": "", "error": None,
                          "model": result.get("model"), "cost_usd": result.get("cost_usd", 0)}
            status = result.get("status") if result.get("status") in ("completed", "failed", "cancelled") else "failed"
            job.update(status=status, finished=_now(), reply=result.get("answer") or "",
                       model=result.get("model"), cost_usd=round(float(result.get("cost_usd") or 0), 6),
                       stop_reason=result.get("stop_reason"), error=result.get("error"), progress="done")
            if result.get("tools") is not None:
                job["tools"] = [dict(t) for t in result["tools"]]
            with self.lock:
                self.running.discard(jid)         # first: nothing can leave a slot or the Busy lock held
                self.processes.pop(jid, None)
                try:
                    self.store.save_job(job)      # the job holds the reply: save it before the conversation
                except Exception as e:
                    # Kept in memory and served from there (and retried) until a save works,
                    # so the page gets the real outcome instead of 'running' forever.
                    self.unsaved[jid] = job
                    print(f"[chatjobs] could not save job {jid} (kept in memory): {type(e).__name__} {e}")
                try:
                    s = self.store.session(job["session"])
                    if s is not None:
                        s["messages"] = [m for m in s["messages"]
                                         if not (m.get("_job") == jid and not m.get("_turn_user"))] + new
                        if s.get("running") == jid:
                            s["running"] = None
                        self.store.save_session(s)
                except Exception as e:
                    print(f"[chatjobs] could not save conversation for job {jid}: {type(e).__name__} {e}")
            self.emit(jid, "done" if status == "completed" else ("state" if status == "cancelled" else "error"),
                      {"state": status, "error": page_error(job), "model": job.get("model")})
            for name in ("manager", "job_id", "cancel"):
                try:
                    delattr(_CONTEXT, name)
                except AttributeError:
                    pass

    # ------------------------------------------------------------ queries

    def get(self, handle, jid):
        j = self._job(jid)
        if not j or j.get("handle") != handle:
            return None
        return j

    def thread(self, handle, brain, session_id=None, limit=40):
        """What a page shows on load: the conversation's recent turns, oldest first,
        plus the id of a turn still running."""
        if brain not in self.brains:
            raise ValueError(f"unknown brain {brain!r}")
        s = self._session(handle, kind_for(brain), session_id)
        if s is None:
            return {"session": None, "turns": [], "running": None}
        turns = []
        for jid in s.get("turns", [])[-limit:]:
            j = self._job(jid)
            if j:
                turns.append(public(j))
        return {"session": s["id"], "turns": turns, "running": self._running(s)}


# What the page may see of a reply's tool calls (2026-09-26): each call's plain label and its
# verdict, nothing else; a step's number is its place in the list. Until this date public() also
# sent the metered lane's tool inputs ("args") and the first 300 characters of each result
# ("result_preview") to the browser, against the promise in app.js and live_feed.py. The job file
# on disk still keeps them for Marty's own logs; they are never served. The filter runs on every
# read, so turns saved before this change come back stripped too.
PAGE_VERDICTS = ("ok", "error", "refused")   # any case: the Max lane saves "error", the metered lane "OK"/"ERROR"/"REFUSED"


def page_tools(tools):
    """A reply's tool calls as the page may see them: [{"tool", "verdict"}], one per call, in order.
    "tool" is live_feed.tool_label(name): the metered lane saves the name the model chose (anything
    at all when the call was refused), so it is mapped to the label the live step line showed, and
    anything unknown reads "Working". A verdict that is not one of PAGE_VERDICTS becomes None."""
    if not isinstance(tools, (list, tuple)):
        return []
    out = []
    for t in tools:
        t = t if isinstance(t, dict) else {}
        verdict = str(t.get("verdict") or "")
        out.append({"tool": live_feed.tool_label(t.get("tool") if isinstance(t.get("tool"), str) else ""),
                    "verdict": verdict if verdict.lower() in PAGE_VERDICTS else None})
    return out


# A failed turn's error as the page may see it (2026-09-26). The subscription (CLI) lanes raise
# LaneError with the CLI's own result text or its stderr, which can quote a tool's input or result.
# For those lanes only our own fixed messages are served; anything else becomes PAGE_ERROR on the
# page. The job file on disk keeps the full text for Marty.
CLI_BRAINS = ("claude_sub", "claude_sub_tools", "codex_sub", "gemini_sub")
# (2026-09-28) The Local lane too: a turn saved before that day carries "local call failed: <type>: <exc>",
# and the exception can name a path on the PC or quote Ollama's error. WITHHELD_BRAINS is the set
# page_error withholds for; CLI_BRAINS stays the CLI set for anything that means exactly that.
WITHHELD_BRAINS = CLI_BRAINS + ("local",)
PAGE_ERROR = "The reply failed on the PC. The full error is saved there for Marty."
_CLI = r"(?:claude|codex)(?:\.(?:exe|cmd|bat|ps1))?"     # the lane's own executable, by name (Windows may upper-case .EXE)
OWN_ERRORS = re.compile(
    r"(?:chat call failed: )?" + _CLI + r" (?:timed out after \d+(?:\.\d+)?s|did not exit within \d+(?:\.\d+)?s"
    r" after its output ended, so it was stopped)(?:\. The reply is incomplete\.)?"
    r"|chat call failed: " + _CLI + r" exited -?\d+|chat call failed: claude not found on PATH"
    r"|chat call failed: codex not found: open the Codex desktop app once, or run  npm i -g @openai/codex"
    r"|the model returned an empty reply|the turn ended without a result|the conversation could not be saved; send again",
    re.IGNORECASE)


def page_error(job):
    """job["error"] as the page may see it: verbatim for the metered and API lanes and for our own
    messages; PAGE_ERROR for any other text from a CLI lane or the Local lane."""
    error = (job or {}).get("error")
    if not error or (job or {}).get("brain") not in WITHHELD_BRAINS:
        return error
    return error if isinstance(error, str) and OWN_ERRORS.fullmatch(error) else PAGE_ERROR


def public(job):
    """A job as the browser sees it."""
    keys = ("id", "brain", "session", "message", "status", "created", "started", "finished",
            "reply", "model", "cost_usd", "stop_reason", "error", "progress", "client_id")
    out = {k: job.get(k) for k in keys}
    out["error"] = page_error(job)
    out["tools"] = page_tools(job.get("tools"))
    try:
        t0 = datetime.fromisoformat(job["started"])
        t1 = datetime.fromisoformat(job["finished"]) if job.get("finished") else datetime.now()
        out["elapsed_s"] = round((t1 - t0).total_seconds(), 1)
    except (KeyError, TypeError, ValueError):
        out["elapsed_s"] = None
    return out


# ---------------------------------------------------------------- selftest (no network)

def selftest():
    import tempfile
    fails = []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    def wait(m, jid, handle="lukas", t=8):
        end = time.time() + t
        while time.time() < end:
            j = m.get(handle, jid)
            if j and j["status"] in TERMINAL:
                return j
            time.sleep(0.02)
        return m.get(handle, jid)

    seen = {"cloud": [], "local": []}
    gate = threading.Event()

    def runner(kind):
        def run(brain, messages):
            seen[kind].append([dict(x) for x in messages])
            q = messages[-1]["content"]
            if q.startswith("slow"):
                gate.wait(5)
            if q == "empty":
                return {"status": "failed", "answer": "", "error": "the model returned an empty reply"}
            if q == "crash":
                raise RuntimeError("runner blew up")
            if q == "tools":
                return {"status": "completed", "answer": "read it", "model": brain, "cost_usd": 0.002,
                        "tools": [{"tool": "read_file", "args": {"path": "x"}, "verdict": "OK", "chars": 9,
                                   "started": _now(), "finished": _now(), "result_preview": "text"}]}
            return {"status": "completed", "answer": f"{brain} says: {q}", "model": brain,
                    "cost_usd": 0.0 if kind == "local" else 0.001}
        return run

    with tempfile.TemporaryDirectory() as td:
        store = Store(td)
        m = Manager({"cloud": runner("cloud"), "local": runner("local")}, store)

        print("a turn is a job: it runs on its own and is saved")
        j = wait(m, m.submit("lukas", "claude", "hello")["id"])
        check(j["status"] == "completed" and j["reply"] == "claude says: hello", "the reply is on the job")
        th = m.thread("lukas", "claude", j["session"])
        check(th["session"] == j["session"] and len(th["turns"]) == 1 and th["turns"][0]["reply"].startswith("claude"),
              "the conversation holds the turn")
        c2 = wait(m, m.submit("lukas", "gemini", "second", session_id=j["session"])["id"])
        check(c2["session"] == j["session"] and any(x.get("content") == "hello" for x in seen["cloud"][-1]),
              "cloud brains share one thread, and the next turn sees the earlier question")

        print("the Local lane keeps its own conversation, and its turns never reach a cloud brain")
        lo = wait(m, m.submit("lukas", "local", "PRIVATE LOCAL QUESTION")["id"])
        check(lo["status"] == "completed" and lo["session"] != j["session"], "local gets a conversation of its own")
        lo2 = wait(m, m.submit("lukas", "local", "and a follow-up", session_id=lo["session"])["id"])
        check(lo2["session"] == lo["session"] and any(x.get("content") == "PRIVATE LOCAL QUESTION" for x in seen["local"][-1]),
              "the local thread remembers its own history")
        cx = m.submit("lukas", "claude", "cloud after local", session_id=lo["session"])
        check(cx["session"] != lo["session"], "a cloud brain handed the local session id starts a cloud thread instead")
        wait(m, cx["id"])
        wait(m, m.submit("lukas", "claude", "third", session_id=j["session"])["id"])
        flat = json.dumps(seen["cloud"])
        check("PRIVATE LOCAL QUESTION" not in flat and "local says" not in flat, "no local text in any cloud context")
        mixed = [{"role": "user", "content": "L", "_brain": "local"}, {"role": "assistant", "content": "LA", "_brain": "local"},
                 {"role": "user", "content": "C", "_brain": "claude"}, {"role": "assistant", "content": "CA", "_brain": "claude"},
                 {"role": "user", "content": "unknown"}, {"role": "assistant", "content": "?"}]
        check([x["content"] for x in bounded_context(mixed)] == ["C", "CA"],
              "even inside one transcript, cloud context drops local and unlabelled turns")
        check(len(bounded_context(mixed, cloud=False)) == 6, "the local lane may see every turn")
        check(m.thread("lukas", "local", j["session"])["turns"] == [], "a cloud session id shows nothing on the local lane")

        print("a turn that used tools carries its steps to the page, never their inputs or results")
        t = wait(m, m.submit("lukas", "claude", "tools", session_id=j["session"])["id"])
        pub = public(t)
        check(pub["tools"] == [{"tool": "Reading a file", "verdict": "OK"}], "each step's label and verdict survive the round trip")
        check(store.job(t["id"])["tools"][0].get("result_preview") == "text", "the job file still keeps the result for Marty's logs")
        legacy = [{"tool": "list_dir", "args": {"path": "SECRET"}, "verdict": "REFUSED", "result_preview": "SECRET"},
                  {"tool": "Reading a file", "verdict": "error"}, {"tool": "x" * 500, "verdict": "SECRET words"}, "junk"]
        shown = page_tools(legacy)
        check("SECRET" not in json.dumps(shown) and [s["verdict"] for s in shown] == ["REFUSED", "error", None, None]
              and [s["tool"] for s in shown] == ["Looking in a folder", "Reading a file", "Working", "Working"],
              "an old saved turn is stripped too; only a label and a known verdict are served")
        cli = {"brain": "claude_sub_tools", "error": "chat call failed: tool said SECRET"}
        check(page_error(cli) == PAGE_ERROR and public(dict(cli, id="x"))["error"] == PAGE_ERROR,
              "a CLI lane's own text never reaches the page")
        own = ["chat call failed: claude.EXE timed out after 600s", "codex.exe did not exit within 1.5s after its output ended,"
               " so it was stopped. The reply is incomplete.", "the model returned an empty reply", "chat call failed: codex exited 2",
               "chat call failed: claude not found on PATH"]
        check([page_error({"brain": "codex_sub", "error": e}) for e in own] == own, "our own lane messages are served as they are")
        check(page_error({"brain": "claude_sub", "error": "chat call failed: sk-SECRET timed out after 5s"}) == PAGE_ERROR,
              "a look-alike of our own message with other text in it is not served")
        check(page_error({"brain": "claude", "error": "chat call failed: HTTP Error 529: Overloaded"})
              == "chat call failed: HTTP Error 529: Overloaded" and page_error({"brain": "claude_sub"}) is None,
              "the metered and API lanes keep their error text; no error stays none")
        check(page_error({"brain": "local", "error": "local call failed: FileNotFoundError: C:/x/Modelfile"}) == PAGE_ERROR
              and page_error({"brain": "local", "error": "the model returned an empty reply"}) == "the model returned an empty reply",
              "a Local turn saved with its raw exception is served as the fixed message; its own text as it is")

        print("a resent POST (same client id) is one turn, not two")
        a = m.submit("lukas", "claude", "once", client_id="abc12345", session_id=j["session"])
        b = m.submit("lukas", "claude", "once", client_id="abc12345", session_id=j["session"])
        check(a["id"] == b["id"], "the same job comes back")
        wait(m, a["id"])

        print("a job's owner is the only one who sees it")
        check(m.get("someone-else", c2["id"]) is None, "another handle gets nothing")
        check(m.thread("someone-else", "claude", c2["session"])["turns"] == [], "nor its conversation")

        print("bad input is refused")
        for args in (("lukas", "claude", "   "), ("lukas", "grok", "hi"), ("lukas", "claude", "x" * (MESSAGE_MAX + 1))):
            try:
                m.submit(*args)
                refused = False
            except ValueError:
                refused = True
            check(refused, f"refused: brain {args[1]!r}, {len(args[2])} chars")
        try:
            m.thread("lukas", "grok")
            refused = False
        except ValueError:
            refused = True
        check(refused, "an unknown brain has no thread")

        print("words that used to be commands are ordinary messages now")
        for q in ("Wipe", "Project: Cinematic cut", "Project?"):
            jj = wait(m, m.submit("lukas", "claude", q, session_id=j["session"])["id"])
            check(jj["reply"] == f"claude says: {q}" and "command" not in jj, f"{q!r} goes to the model")

        print("an empty reply is a failure; a crash is a failure that never stays 'running'")
        e = wait(m, m.submit("lukas", "claude", "empty", session_id=j["session"])["id"])
        check(e["status"] == "failed" and e["reply"] == "", "empty -> failed")
        cr = wait(m, m.submit("lukas", "local", "crash", session_id=lo["session"])["id"])
        check(cr["status"] == "failed" and "runner blew up" in (cr["error"] or ""), "crash -> failed, with the reason")
        check(m._running(store.session(cr["session"])) is None and cr["id"] not in m.running, "no slot or lock left held")
        ctx = bounded_context(store.session(j["session"])["messages"])
        check(any(x["content"] == "(No reply: that call failed.)" for x in ctx), "a failed question stays as context, paired")

        print("one turn at a time per conversation")
        gate.clear()
        s1 = m.submit("lukas", "claude", "slow one", session_id=j["session"])
        try:
            m.submit("lukas", "gemini", "impatient", session_id=j["session"])
            busy = False
        except Busy as bz:
            busy = bz.job_id == s1["id"]
        check(busy, "a second message while one runs is refused, naming the running turn")
        other = wait(m, m.submit("lukas", "local", "meanwhile", session_id=lo["session"])["id"])
        check(other["status"] == "completed", "a different conversation is not blocked")
        gate.set()
        check(wait(m, s1["id"])["status"] == "completed", "and the slow one finishes")

        print("a failed save at the end of a turn still ends it")
        real_save = store.save_session
        calls = {"n": 0}

        def flaky_save(s):
            calls["n"] += 1
            if s.get("running") is None and calls["n"] > 1:
                raise PermissionError("[WinError 5] Access is denied")
            return real_save(s)
        store.save_session = flaky_save
        fj = wait(m, m.submit("lukas", "claude", "final save fails", session_id=j["session"])["id"])
        store.save_session = real_save
        check(fj["status"] == "completed" and fj["id"] not in m.running, "the job is terminal and its slot is free")
        nxt = wait(m, m.submit("lukas", "claude", "next one", session_id=j["session"])["id"])
        check(nxt["status"] == "completed", "the conversation is not left locked (a stale pointer is not Busy)")

        print("a locked file is retried, and never mistaken for a missing one")
        stop_flag = threading.Event()
        errors = []

        def hammer():
            s = store.session(j["session"])
            while not stop_flag.is_set():
                try:
                    store.save_session(s)
                except Exception as ex:
                    errors.append(type(ex).__name__)

        th1 = threading.Thread(target=hammer)
        th1.start()
        lost = unreadable = 0
        t_end = time.time() + 3
        while time.time() < t_end:
            try:
                if m.thread("lukas", "claude", j["session"])["session"] != j["session"]:
                    lost += 1
            except Unreadable:
                unreadable += 1
        stop_flag.set()
        th1.join()
        check(lost == 0, f"the conversation was never reported missing under load (lost {lost}, unreadable {unreadable})")

        print("a restart marks a running turn interrupted")
        s = store.session(j["session"])
        fake = {"id": _new_id(), "handle": "lukas", "brain": "claude", "session": s["id"], "message": "x",
                "status": "running", "started": _now(), "tools": [], "client_id": "restart-probe"}
        store.save_job(fake)
        s["messages"].append({"role": "user", "content": "x", "_job": fake["id"], "_brain": "claude", "_turn_user": True})
        s["turns"].append(fake["id"])
        s["running"] = fake["id"]
        store.save_session(s)
        check(m.get("lukas", fake["id"])["status"] == "interrupted", "a job with no thread already reads as interrupted")
        m2 = Manager({"cloud": runner("cloud"), "local": runner("local")}, store)
        fj = store.job(fake["id"])
        check(fj["status"] == "interrupted" and fj.get("stop_reason"), "recovery saves it as interrupted, with a reason")
        check(store.session(s["id"]).get("running") is None, "the conversation is no longer marked as running")
        check(m2.submit("lukas", "claude", "x", client_id="restart-probe")["id"] == fake["id"],
              "a resent POST after the restart still finds its turn")
        again = wait(m2, m2.submit("lukas", "claude", "after the restart", session_id=s["id"])["id"])
        check(again["status"] == "completed", "and the conversation takes new messages")

        print("history is bounded, newest first")
        big = []
        for i in range(30):
            big += [{"role": "user", "content": f"q{i} " + "x" * 2000, "_brain": "claude"},
                    {"role": "assistant", "content": f"a{i}", "_brain": "claude"}]
        ctx = bounded_context(big)
        check(sum(len(x["content"]) for x in ctx) <= CONTEXT_CHARS and ctx[-1]["content"] == "a29"
              and ctx[0]["role"] == "user", "fits the budget, ends at the newest, starts on a question")
        check(all(not k.startswith("_") for x in ctx for k in x), "bookkeeping keys never reach a model")

        print("a corrupt session file is moved aside and the chat recovers by itself")
        sid = lo["session"]
        (store.sessions / f"{sid}.json").write_text("\x00\x00\x00", encoding="utf-8")
        th = m.thread("lukas", "local", sid)
        check(th["session"] is None and list(store.sessions.glob(f"{sid}.json.corrupt-*")),
              "the corrupt file is kept aside as evidence, and the page gets an empty thread")
        jn = wait(m, m.submit("lukas", "local", "after the corruption", session_id=sid)["id"])
        check(jn["status"] == "completed" and jn["session"] != sid, "the next message starts a fresh conversation")

        print("a failed first save keeps nothing, instead of duplicating the history")
        sid = j["session"]
        before = len(store.session(sid)["messages"])
        real_save = store.save_session
        state = {"armed": False}

        def fail_first_run_save(s):
            if state["armed"] and any(mm.get("content") == "dup probe" for mm in s["messages"]):
                state["armed"] = False
                raise StoreBusy("locked")
            return real_save(s)
        store.save_session = fail_first_run_save
        state["armed"] = True        # submit's own save has no "dup probe" message yet, so only _run's first save fails
        jd = wait(m, m.submit("lukas", "claude", "dup probe", session_id=sid)["id"])
        store.save_session = real_save
        after = store.session(sid)["messages"]
        check(jd["status"] == "failed" and not state["armed"], f"the first save really failed ({jd['status']})")
        check(len(after) == before, f"nothing was appended, no duplicated history ({before} -> {len(after)} messages)")

        print("a failed final job save is served from memory, not 'running' forever")
        real_save_job = store.save_job
        state2 = {"n": 0}

        def fail_terminal(job):
            if job.get("status") in TERMINAL and job.get("message") == "final job save probe" and state2["n"] < 1:
                state2["n"] += 1
                raise StoreBusy("locked")
            return real_save_job(job)
        store.save_job = fail_terminal
        pj = m.submit("lukas", "claude", "final job save probe", session_id=sid)
        time.sleep(0.3)
        store.save_job = real_save_job
        got = m.get("lukas", pj["id"])
        check(got["status"] == "completed" and got["reply"].startswith("claude says"), "the real outcome is served")
        check(store.job(pj["id"])["status"] == "completed", "and the save is retried until it lands")

        print("a failed conversation save in submit leaves no phantom turn")
        turns_before = list(store.session(sid)["turns"])
        real_save = store.save_session
        store.save_session = lambda s: (_ for _ in ()).throw(StoreBusy("locked"))
        try:
            m.submit("lukas", "claude", "phantom probe", session_id=sid)
            raised = False
        except StoreBusy:
            raised = True
        store.save_session = real_save
        check(raised and store.session(sid)["turns"] == turns_before, "503 to the page, and the conversation is unchanged")

        print("startup recovery survives a file it cannot save")
        bad = {"id": _new_id(), "handle": "lukas", "brain": "claude", "session": sid, "status": "running",
               "message": "x", "started": _now(), "tools": []}
        store.save_job(bad)
        real_save_job = store.save_job
        store.save_job = lambda jb: (_ for _ in ()).throw(StoreBusy("locked"))
        try:
            Manager({"cloud": runner("cloud"), "local": runner("local")}, store)
            started = True
        except Exception:
            started = False
        store.save_job = real_save_job
        check(started, "the manager still starts (so the dashboard does)")

        print("New conversation: archive the lane's thread, start an empty one")
        a1 = wait(m, m.submit("lukas", "claude", "OLD CLOUD TOPIC")["id"])
        old_cloud = a1["session"]
        l1 = wait(m, m.submit("lukas", "local", "OLD LOCAL TOPIC")["id"])
        new, archived = m.new_conversation("lukas", "gemini", old_cloud)
        check(archived == old_cloud and new["id"] != old_cloud and new["kind"] == "console",
              "a cloud brain's button archives the shared cloud thread and returns a new one")
        disk = store.session(old_cloud)
        check(disk is not None and disk.get("archived_at") and disk.get("archived_for") == new["id"]
              and len(disk["turns"]) == 1, "the old thread stays on disk, whole, marked archived (not deleted)")
        check(m.thread("lukas", "claude", new["id"]) == {"session": new["id"], "turns": [], "running": None},
              "the new thread is empty")
        check(m.thread("lukas", "claude", old_cloud)["session"] is None, "the archived thread is never shown again")
        nx = wait(m, m.submit("lukas", "claude", "fresh cloud question", session_id=new["id"])["id"])
        check(nx["session"] == new["id"] and "OLD CLOUD TOPIC" not in json.dumps(seen["cloud"][-1]),
              "the next message lands in the new thread and sees none of the old one")
        st2 = wait(m, m.submit("lukas", "claude", "sent with the archived id", session_id=old_cloud)["id"])
        check(st2["session"] not in (old_cloud,) and store.session(old_cloud).get("turns") == disk["turns"],
              "a stale page sending the archived id cannot write into it")
        check(m.thread("lukas", "local", l1["session"])["turns"][0]["message"] == "OLD LOCAL TOPIC",
              "the Local thread is untouched by the cloud button")
        lnew, larch = m.new_conversation("lukas", "local", l1["session"])
        check(larch == l1["session"] and lnew["kind"] == "local" and m.thread("lukas", "local", lnew["id"])["turns"] == [],
              "Local's button archives only the Local thread")
        check(m.thread("lukas", "claude", nx["session"])["turns"][0]["message"] == "fresh cloud question",
              "and leaves the cloud thread alone")
        fresh, none = m.new_conversation("lukas", "claude", None)
        check(none is None and fresh["kind"] == "console", "with no current thread it just starts one")
        other, oa = m.new_conversation("someone-else", "claude", nx["session"])
        check(oa is None and not store.session(nx["session"]).get("archived_at"),
              "another handle cannot archive Lukas's thread by naming its id")
        try:
            m.new_conversation("lukas", "grok", None)
            refused = False
        except ValueError:
            refused = True
        check(refused, "an unknown brain is refused")
        gate.clear()
        run1 = m.submit("lukas", "claude", "slow, still running", session_id=nx["session"])
        try:
            m.new_conversation("lukas", "openrouter", nx["session"])
            blocked = None
        except Busy as bz:
            blocked = bz.job_id
        check(blocked == run1["id"] and not store.session(nx["session"]).get("archived_at"),
              "refused while a turn is running in that thread, naming the turn, and nothing archived")
        lok, _ = m.new_conversation("lukas", "local", lnew["id"])
        check(lok["kind"] == "local", "the other lane's button still works meanwhile")
        gate.set()
        wait(m, run1["id"])
        after, arch = m.new_conversation("lukas", "claude", nx["session"])
        check(arch == nx["session"], "once the turn has finished, the button works")

        print("ids with a trailing newline are refused")
        check(not ID_RE.match(_new_id() + "\n") and not CLIENT_ID_RE.match("abcdefgh\n"), "no '$' loophole")

    print("\n" + ("all checks passed" if not fails else f"{len(fails)} FAILED"))
    return not fails


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["selftest"]:
        sys.exit(0 if selftest() else 1)
    print("usage: chatjobs.py selftest")
