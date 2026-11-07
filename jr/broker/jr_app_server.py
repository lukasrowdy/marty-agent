"""Loopback-only staging shell for the independent Jr app.

CHANGED 2026-09-29 (wave 3h, skeptic wave 3g finding 1): the stop client
timeout rises from 45 s to 55 s. One cable cut really takes up to 15 s, so
the deferred stop path is the loop's 30 s cut hold plus stop's own 15 s cut
(45 s), which met the old timeout; test_wave3g_fixes pins both stop paths.

CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e findings 2 and 3):
- F2: broker_from_config passes BROKER_OP_TIMEOUTS (approve 30 s, stop 45 s)
  to ChannelBrokerClient; poll, status, begin and emergency keep its 10 s.
  The broker's approve and stop budgets are pinned under these by
  test_wave3f_fixes, so the app no longer gives up at 10 s on an approve
  the broker then completes (cable on, no watcher, no synopsis).
- F3: on "cutting" with reason "loop_stale", watch_batch calls stop through
  the client instead of ending the batch as a fault while the broker's own
  phase may still be online. A loop that was only slow (it lost the gate
  race) frees the broker lock, the stop lands, the cable is off, and the
  stopped checkpoint gets a synopsis of the pages seen so far (no Continue:
  the batch is over). The status then reads "stopped", never "online" again
  with a restarted lease timer. If the stop fails (a truly wedged or gone
  broker) the batch ends as a fault checkpoint exactly as before. Chosen
  over "keep watching" because it really ends the batch the cable watchdog
  has already cut, and still gives the synopsis.

CHANGED 2026-09-28 late (wave 3e, skeptic wave 3d finding 6): watch_batch understands the
broker's read-only "cutting" phase. With reason "loop_stale" the broker loop has stalled and
the cable watchdogs own the cut, so the batch ends at once with a fault checkpoint (no
synopsis, no Continue) instead of watching "online" forever. With reason "deadline_passed"
it keeps watching: a live loop cuts on its next turn and the paused checkpoint and synopsis
follow as before, and a dead one turns into "loop_stale". The watcher sleeps
BATCH_POLL_SECONDS (3 s, a module constant so tests can shorten it) between polls, and
make_server exposes watch_batch on the server object for tests, like batch_watchers.

The VM adapter stays in a separate privileged broker reached through a narrow
pipe. Research mutations require owner authentication and a saved checkpoint
before each continuation.

CHANGED 2026-09-28 (Jr overnight build, item 8 "video"), what and why:
- make_server(video=...) takes an injected jr_video.JrVideo (None in production until item
  4's deploy wires the guest fetch). Three owner-authenticated routes: POST /api/video/read
  {url} runs one reading at a time (fetch through the broker stub, frames, transcript,
  local synopsis, history checkpoint; minutes, like /api/plan); POST /api/video/preview
  {thread_id} builds the exact hosted payload from the server-side record (the browser
  never supplies paths); POST /api/video/send {nonce, confirm_text} re-checks the typed
  confirmation server-side through jr_hosted.send_video and returns 403 with the gate's
  reason on refusal. /api/hosted/status now reports the two provider flags.

CHANGED 2026-09-28 (fix helper, after the skeptic's item 8 verdict): the Content-Security-
Policy gains img-src data: (and nothing else) so stage.js can show every sampled frame as a
thumbnail under the abbreviated JSON. Before, the frames were abbreviated to a character
count and the owner confirmed sending up to 12 images never seen; the old policy had no
img-src, so default-src 'none' would have blocked the thumbnails. data: images cannot fetch
anything, so connect-src stays 'self'.

CHANGED 2026-09-28 (Jr overnight build, item 3 "app"), what and why:
- broker_from_config(data_dir) reads the installer's data\\broker-policy.json and
  data\\app-config.json through a handle (reparse points refused, owner must be
  Administrators, size bounded) and builds a jr_broker_client.ChannelBrokerClient; a
  missing, untrusted or damaged policy gives no client and a typed reason instead.
  make_server(broker_reason=..., text_allowed=...) carries that reason and the owner's
  never-send screen. make_server still refuses any broker with a .vm attribute.
- /api/session reports ready, reason and broker state from the client itself
  (available(), then poll() for the typed BrokerUnavailable state); "armed" means the
  broker answers and no batch runs. Every broker call answers BrokerUnavailable with 503
  and the UI_STATES text plus the state key, and BrokerRefused with 409.
- /api/research/stop pops the session in a finally, so a broker exception cannot leave a
  zombie entry, and answers with the broker's own status dict (limit, lease_seconds,
  presence come from the broker, never from constants). watch_batch survives a lost
  broker by recording the state for /api/research/status and ending cleanly; watcher
  threads are kept on server.batch_watchers so tests can join them.
- /api/hosted/preview takes an optional thread_id and refuses never-send text with 403;
  /api/hosted/send passes the screen to jr_hosted and writes the answer to history as a
  hosted entry for that thread.

CHANGED 2026-09-28 (UI QA fixes, from qa	est_ui_qa.py), what and why:
- GET /api/research/status for a signed-in caller with no plan answers 200 with IDLE_STATUS
  ({"state": "idle", ...}) instead of 404, and GET /api/spend with no ledger configured
  answers 200 with empty_spend_summary() (configured False) instead of 503. Both non-errors
  were logged by the browser as SEVERE console lines on every sign-in and after stop. A real
  ledger's summary now carries configured True. Security behaviour is unchanged: no token or
  a bad token is still 401, no broker is still 503, a ledger error is still 503.
"""

from __future__ import annotations

from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlsplit

from jr_auth import AuthError, JrAuth
from jr_broker_client import (ADMINISTRATORS_SID, CHANNEL_FILE, UI_STATES, BrokerRefused,
                              BrokerUnavailable, ChannelBrokerClient)
from jr_history import HistoryError
from jr_model import JrModel, ModelError
from jr_spend import DAILY_CAP_MICRO, MONTHLY_CAP_MICRO, SpendError
from jr_hosted import HostedError, NEVER_SEND_REFUSED, write_key_to_credential_manager
from jr_video import VideoError

# jr_broker_client has already put the bundled pywin32 on sys.path (jr_deps.load()).
import pywintypes
import win32con
import win32file
import win32security


STATIC = Path(__file__).with_name("stage.html")
CSS = Path(__file__).with_name("stage.css")
JS = Path(__file__).with_name("stage.js")

POLICY_FILE = "broker-policy.json"
APP_CONFIG_FILE = "app-config.json"
POLICY_OWNER_SID = ADMINISTRATORS_SID  # module global so tests can patch it; production never does
MAX_INSTALLER_FILE_BYTES = 4096
ARMED_PHASES = {"idle", "stopped"}
BATCH_POLL_SECONDS = 3.0   # watch_batch cadence; module global so tests can shorten it
# Wave 3f F2: client deadlines for the two slow broker ops (seconds).
# Wave 3h: stop 45 to 55 (the loop's 30 s cut hold plus stop's 15 s cut).
BROKER_OP_TIMEOUTS = {"approve": 30.0, "stop": 55.0}
NEVER_SEND_HIT = "That text contains a never-send term. Nothing was sent."
# Signed-in idle for /api/research/status: 200 with this body (was a 404, which the browser
# logged as a console error on every sign-in). "state" marks it; a broker status never has it.
IDLE_STATUS = {"state": "idle", "phase": "idle", "used": 0, "limit": None,
               "current_url": None, "approval_nonce": None}


def empty_spend_summary() -> dict:
    """The /api/spend shape when no ledger is configured: nothing used, the local caps, configured False."""
    return {"configured": False, "day": None, "month": None,
            "daily_used_usd": "0", "monthly_used_usd": "0",
            "daily_cap_usd": str(Decimal(DAILY_CAP_MICRO) / 1_000_000),
            "monthly_cap_usd": str(Decimal(MONTHLY_CAP_MICRO) / 1_000_000),
            "uncertain_requests": 0}


_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND, _ERROR_ACCESS_DENIED = 2, 3, 5
_FILE_SHARE_ALL = (win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE |
                   win32con.FILE_SHARE_DELETE)


class InstallerFileError(Exception):
    """A file the installer writes is absent, untrusted or damaged. `state` is a UI_STATES key."""

    def __init__(self, state: str, detail: str):
        super().__init__(f"{UI_STATES[state]} ({detail})")
        self.state = state
        self.detail = detail


def _read_installer_file(path: Path, what: str) -> bytes:
    """Open through a handle, refuse reparse points, require the installer's owner, bound the size."""
    try:
        handle = win32file.CreateFile(
            str(path), win32con.GENERIC_READ | win32con.READ_CONTROL, _FILE_SHARE_ALL, None,
            win32con.OPEN_EXISTING, win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
    except pywintypes.error as exc:
        if exc.winerror in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
            raise InstallerFileError("missing", f"{what} is absent") from exc
        if exc.winerror == _ERROR_ACCESS_DENIED:
            raise InstallerFileError("untrusted", f"{what} is not readable by the service account") from exc
        raise InstallerFileError("damaged", f"{what} could not be opened") from exc
    try:
        try:
            info = win32file.GetFileInformationByHandle(handle)
            if info[0] & (win32con.FILE_ATTRIBUTE_REPARSE_POINT | win32con.FILE_ATTRIBUTE_DIRECTORY):
                raise InstallerFileError("untrusted", f"{what} is a reparse point or a directory")
            descriptor = win32security.GetSecurityInfo(
                handle, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION)
            owner = descriptor.GetSecurityDescriptorOwner()
            if owner is None or win32security.ConvertSidToStringSid(owner) != POLICY_OWNER_SID:
                raise InstallerFileError("untrusted", f"{what} owner is not Administrators")
            size = (info[5] << 32) | info[6]
            if not 2 <= size <= MAX_INSTALLER_FILE_BYTES:
                raise InstallerFileError("damaged", f"{what} has an implausible size")
            return bytes(win32file.ReadFile(handle, MAX_INSTALLER_FILE_BYTES + 1)[1])
        except pywintypes.error as exc:
            raise InstallerFileError("damaged", f"{what} could not be inspected") from exc
    finally:
        handle.Close()


def _installer_json(path: Path, what: str, keys: set) -> dict:
    try:
        data = json.loads(_read_installer_file(path, what))
    except ValueError as exc:
        raise InstallerFileError("damaged", f"{what} is not JSON") from exc
    if (type(data) is not dict or set(data) != keys or
        type(data.get("version")) is not int or data["version"] != 1):
        raise InstallerFileError("damaged", f"{what} does not have the version 1 shape")
    return data


class BrokerSetup:
    """What broker_from_config found. `client` is None when `reason` says why."""

    def __init__(self, *, client, state, reason, public_origin, policy_path):
        self.client = client
        self.state = state
        self.reason = reason
        self.public_origin = public_origin
        self.policy_path = policy_path


def broker_from_config(data_dir) -> BrokerSetup:
    """Build the broker client from the installer's files in Jr's private data root.

    A missing policy file means no broker (the production default until the installer
    runs). A damaged or untrusted app config raises ValueError, because a wrong public
    origin is a deploy mistake the service must not paper over; a missing one is fine.
    """
    data_dir = Path(data_dir)
    if not data_dir.is_absolute():
        raise ValueError("Jr data root must be an absolute path")
    public_origin = None
    try:
        config = _installer_json(data_dir / APP_CONFIG_FILE, "app config", {"version", "public_origin"})
    except InstallerFileError as exc:
        if exc.state != "missing":
            raise ValueError(f"Jr app config refused: {exc.detail}") from exc
    else:
        origin = config["public_origin"]
        if origin is not None and (type(origin) is not str or not 0 < len(origin) <= 300 or
                                   not origin.isascii() or not origin.isprintable()):
            raise ValueError("Jr app config public_origin must be one HTTPS origin or null")
        public_origin = origin
    policy_path = data_dir / POLICY_FILE
    try:
        policy = _installer_json(policy_path, "broker policy", {"version", "broker_sid", "channel_path"})
        channel = Path(policy["channel_path"]) if type(policy["channel_path"]) is str else None
        if (channel is None or not channel.is_absolute() or channel.name != CHANNEL_FILE or
            channel.parent == channel or not str(channel).isprintable()):
            raise InstallerFileError("damaged", f"broker policy channel_path is not an absolute {CHANNEL_FILE} path")
        try:
            client = ChannelBrokerClient(channel.parent, broker_sid=policy["broker_sid"], service_sid=None,
                                         op_timeouts=BROKER_OP_TIMEOUTS)
        except (ValueError, TypeError) as exc:
            raise InstallerFileError("damaged", "broker policy broker_sid is not a SID") from exc
    except InstallerFileError as exc:
        label = "Broker not installed" if exc.state == "missing" else "Broker policy refused"
        return BrokerSetup(client=None, state=exc.state, reason=f"{label}: {exc.detail}",
                           public_origin=public_origin, policy_path=policy_path)
    return BrokerSetup(client=client, state="configured", reason=None,
                       public_origin=public_origin, policy_path=policy_path)


def make_server(auth: JrAuth, *, port=0, model=None, broker=None, history=None,
                spend=None, hosted=None, admin_token=None, key_writer=write_key_to_credential_manager,
                public_origin=None, pipe_probe=None, video=None, broker_reason=None,
                text_allowed=None):
    model = model or JrModel()
    if broker_reason is not None and type(broker_reason) is not str:
        raise ValueError("broker_reason must be text")
    if text_allowed is not None and not callable(text_allowed):
        raise ValueError("text_allowed must be a callable never-send screen")
    if video is not None and (hasattr(video, "vm") or hasattr(video, "broker")):
        raise ValueError("Jr web service must receive a video reader, never a VM handle")
    video_state = {"busy": False}
    # The production default has no broker. An injected broker is staged only
    # with separate durable history and the narrow authenticated pipe client.
    if broker is not None and hasattr(broker, "vm"):
        raise ValueError("Jr web service must receive a broker client, never a VM broker")
    if broker is not None and history is None:
        raise ValueError("Jr research requires durable independent history")
    if public_origin is not None:
        parsed = urlsplit(public_origin)
        if (parsed.scheme != "https" or not parsed.hostname or
            parsed.username or parsed.password or parsed.path or parsed.query or
            parsed.fragment or public_origin !=
            f"https://{parsed.hostname}" +
            (f":{parsed.port}" if parsed.port is not None else "")):
            raise ValueError("Jr public origin must be one exact HTTPS host")
        public_host = parsed.netloc
    else:
        public_host = None
    sessions = {}
    checkpoint_ready = {}
    sessions_lock = threading.RLock()
    owner = "jr-owner"
    broker_fault = {}      # thread -> UI_STATES key recorded by a watcher that lost the broker
    hosted_threads = {}    # hosted preview nonce -> history thread the answer belongs to
    watchers = []          # live watch_batch threads; tests join them

    def session_key(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def broker_probe():
        """ready, reason and state from the broker itself, never from a constant."""
        if broker is None:
            return {"ready": False, "reason": broker_reason or UI_STATES["missing"], "broker": "missing"}
        try:
            if hasattr(broker, "available") and not broker.available():
                broker.poll()  # available() never names the state; poll() raises the typed one
            phase = broker.poll().get("phase")
        except BrokerUnavailable as exc:
            return {"ready": False, "reason": UI_STATES[exc.state], "broker": exc.state}
        except Exception:
            return {"ready": False, "reason": UI_STATES["unreachable"], "broker": "unreachable"}
        return {"ready": True, "reason": None,
                "broker": "armed" if phase in ARMED_PHASES else str(phase)}

    def start_watcher(thread):
        watcher = threading.Thread(target=watch_batch, args=(thread,), name="jr-batch-poller", daemon=True)
        watchers[:] = [live for live in watchers if live.is_alive()]
        watchers.append(watcher)
        watcher.start()

    def watch_batch(thread):
        # This is host-owned; browser polling and model output cannot keep a
        # batch alive. A lost process also drops the broker's pipe watchdog.
        while True:
            # A status read launches a VirtualBox GuestControl session. A
            # quarter-second loop overloaded VBoxService in the real VM.
            # The guest quota already blocks page six immediately; host cable
            # cutoff follows on this bounded three-second cadence.
            time.sleep(BATCH_POLL_SECONDS)
            try:
                state = broker.poll()
            except BrokerUnavailable as exc:
                # The broker is gone; no Continue is offered and the status route says why.
                with sessions_lock:
                    broker_fault[thread] = exc.state
                return
            except Exception:
                with sessions_lock:
                    broker_fault[thread] = "unreachable"
                return
            stale_stop = False   # wave 3f F3: set only when this watcher stopped a loop_stale batch
            try:
                if state["phase"] == "cutting":
                    # Wave 3e F6. A passed deadline: the loop's own cut and the
                    # synopsis follow, keep watching. A stalled loop: the cable
                    # watchdogs are cutting and no paused state will come, so
                    # the batch ends here as a fault (no Continue is offered).
                    if state.get("reason") != "loop_stale":
                        continue
                    # Wave 3f F3: end the batch for real. A slow loop frees
                    # the lock and the stop lands (stopped, synopsis below);
                    # a wedged or gone broker fails the stop: fault, as before.
                    try:
                        stopped = broker.stop(owner, thread)
                    except Exception:
                        stopped = None
                    if type(stopped) is dict and stopped.get("phase") == "stopped":
                        state, stale_stop = stopped, True
                    else:
                        state = dict(state, phase="fault")
                if state["phase"] != "online":
                    if history is not None and state["phase"] in {"paused", "fault", "stopped"}:
                        try:
                            history.checkpoint(thread, state)
                            if state["phase"] == "paused" or stale_stop:
                                observed = state.get("observed_text", "")
                                if observed:
                                    try:
                                        question = history.get_thread(thread)["question"]
                                        synopsis = model.synopsis(question=question,
                                                                 current_url=state.get("current_url"),
                                                                 observed_text=observed)
                                    except Exception:
                                        synopsis = {"learned": "No reliable synopsis is available.",
                                                    "uncertain": "The page text could not be summarized locally.",
                                                    "next_step": "Review the observed URL or stop."}
                                else:
                                    synopsis = {"learned": "No page text was captured.",
                                                "uncertain": "Page contents cannot be verified from this batch.",
                                                "next_step": "Review the URL before continuing or stop."}
                                history.set_synopsis(thread, synopsis)
                                if not stale_stop:   # a stopped batch offers no Continue
                                    with sessions_lock:
                                        checkpoint_ready[thread] = True
                        except Exception:
                            # A lost checkpoint must not offer an unrecorded
                            # Continue; the cable is already off at this point.
                            try:
                                broker.stop(owner, thread)
                            except Exception:
                                pass
                    return
            except Exception:
                return

    class Handler(BaseHTTPRequestHandler):
        server_version = "JrStage"
        sys_version = ""

        def log_message(self, format, *args):
            # Never log a request body or Authorization header.
            pass

        def _origin(self):
            if public_host and self.headers.get("Host") == public_host:
                return public_origin
            return f"http://127.0.0.1:{self.server.server_port}"

        def _send(self, code, body, content_type="application/json; charset=utf-8"):
            raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(raw)

        def _host_ok(self):
            host = self.headers.get("Host")
            return host == f"127.0.0.1:{self.server.server_port}" or bool(public_host and host == public_host)

        def _bearer(self):
            value = self.headers.get("Authorization", "")
            return value[7:] if value.startswith("Bearer ") else ""

        def _authorized(self):
            return auth.resolve(self._bearer())

        def _broker_failed(self, exc):
            """Honest state for a broker call that raised: typed 503 or 409, never a guess."""
            if isinstance(exc, BrokerUnavailable):
                self._send(503, {"error": UI_STATES[exc.state], "broker": exc.state, "ready": False})
            elif isinstance(exc, BrokerRefused):
                self._send(409, {"error": str(exc)})
            else:
                self._send(503, {"error": "Research gate unavailable; check the cable",
                                 "broker": "unreachable", "ready": False})

        def _admin_authorized(self, supplied):
            # Tailscale/phone requests can reach localhost through a reverse
            # proxy, so source IP alone is not enough: require local Host and
            # Origin as well as the protected-file management token.
            local = f"http://127.0.0.1:{self.server.server_port}"
            return (admin_token is not None and
                    self.client_address[0] == "127.0.0.1" and
                    self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}" and
                    self.headers.get("Origin") == local and
                    type(supplied) is str and
                    hmac.compare_digest(supplied, admin_token))

        def do_GET(self):
            if not self._host_ok():
                self._send(403, {"error": "Host refused"})
                return
            path = urlsplit(self.path).path
            if path == "/":
                self._send(200, STATIC.read_bytes(), "text/html; charset=utf-8")
            elif path == "/stage.css":
                self._send(200, CSS.read_bytes(), "text/css; charset=utf-8")
            elif path == "/stage.js":
                self._send(200, JS.read_bytes(), "text/javascript; charset=utf-8")
            elif path == "/api/session":
                if not self._authorized():
                    self._send(401, {"authenticated": False})
                else:
                    self._send(200, {"authenticated": True, **broker_probe()})
            elif path == "/api/research/status":
                if not self._authorized():
                    self._send(401, {"error": "Jr sign-in required"})
                elif broker is None:
                    self._send(503, {"ready": False, "broker": "missing",
                                     "error": broker_reason or UI_STATES["missing"]})
                else:
                    with sessions_lock:
                        thread = sessions.get(session_key(self._bearer()))
                    if not thread:
                        # Signed in with no plan is a normal state, not a missing resource.
                        self._send(200, dict(IDLE_STATUS))
                    else:
                        try:
                            state = broker.status(owner, thread)
                            with sessions_lock:
                                ready = checkpoint_ready.get(thread, False)
                                fault = broker_fault.get(thread)
                            if fault:
                                state["broker"] = fault
                                state["reason"] = UI_STATES[fault]
                            if not ready:
                                state["approval_nonce"] = None
                            elif state.get("phase") == "paused":
                                record = history.get_thread(thread)
                                if record and record["checkpoints"]:
                                    state["synopsis"] = record["checkpoints"][-1].get("synopsis")
                            self._send(200, state)
                        except (BrokerUnavailable, BrokerRefused) as exc:
                            self._broker_failed(exc)
                        except Exception:
                            self._send(503, {"error": "Research status unavailable"})
            elif path == "/api/history" or path.startswith("/api/history/"):
                if not self._authorized():
                    self._send(401, {"error": "Jr sign-in required"})
                elif history is None:
                    self._send(503, {"error": "Jr history is not configured"})
                else:
                    try:
                        if path == "/api/history":
                            self._send(200, {"threads": history.list_threads()})
                        else:
                            thread_id = path[len("/api/history/"):]
                            if len(thread_id) != 32 or any(c not in "0123456789abcdef" for c in thread_id):
                                self._send(404, {"error": "No such Jr conversation"})
                                return
                            record = history.get_thread(thread_id)
                            self._send(200, record) if record else self._send(404, {"error": "No such Jr conversation"})
                    except HistoryError:
                        self._send(503, {"error": "Jr history is unavailable"})
            elif path == "/api/spend":
                if not self._authorized():
                    self._send(401, {"error": "Jr sign-in required"})
                elif spend is None:
                    # No ledger configured: an empty ledger that says so; hosted sends stay blocked.
                    self._send(200, empty_spend_summary())
                else:
                    try:
                        self._send(200, {**spend.summary(), "configured": True})
                    except SpendError:
                        self._send(503, {"error": "Jr spend ledger is unavailable"})
            elif path == "/api/hosted/status":
                if not self._authorized():
                    self._send(401, {"error": "Jr sign-in required"})
                else:
                    self._send(200, {"configured": bool(hosted and hosted.configured()),
                                     "model": "abliterated-model-large-v2",
                                     "provider_accepts_video": False,
                                     "provider_accepts_frames": bool(hosted and hosted.provider_accepts_frames),
                                     "video_available": video is not None})
            else:
                self._send(404, {"error": "Not found"})

        def do_POST(self):
            if not self._host_ok() or self.headers.get("Origin") != self._origin():
                self._send(403, {"error": "Origin refused"})
                return
            path = urlsplit(self.path).path
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self._send(415, {"error": "JSON required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            maximum = 32768 if path in {"/api/plan", "/api/hosted/preview"} else 4096
            if length < 0 or length > maximum:
                self._send(413, {"error": "Request too large"})
                return
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
                if type(payload) is not dict:
                    raise ValueError()
            except ValueError:
                self._send(400, {"error": "Invalid JSON"})
                return
            if path == "/api/admin/identity":
                if not self._admin_authorized(payload.get("admin_token")) or set(payload) != {"admin_token", "passphrase"}:
                    self._send(403, {"error": "Local Jr administration refused"})
                    return
                try:
                    auth.provision(payload["passphrase"])
                    self._send(200, {"configured": True})
                except (AuthError, OSError):
                    self._send(409, {"error": "Jr identity already exists or was refused"})
                return
            if path == "/api/admin/provider-key":
                if not self._admin_authorized(payload.get("admin_token")) or set(payload) != {"admin_token", "key"}:
                    self._send(403, {"error": "Local Jr administration refused"})
                    return
                if not auth.configured():
                    self._send(409, {"error": "Create Jr's identity first"})
                    return
                try:
                    key_writer(payload["key"])
                    self._send(200, {"configured": True})
                except Exception:
                    self._send(503, {"error": "Jr provider key could not be stored"})
                return
            if path == "/api/admin/pipe-probe":
                if not self._admin_authorized(payload.get("admin_token")) or set(payload) != {"admin_token"}:
                    self._send(403, {"error": "Local Jr administration refused"})
                    return
                if pipe_probe is None:
                    self._send(503, {"error": "Jr pipe probe is unavailable"})
                    return
                try:
                    state = pipe_probe()
                    if type(state) is not dict or state.get("phase") not in {"idle", "paused", "stopped", "online", "fault"}:
                        raise ValueError()
                    self._send(200, {"connected": True, "phase": state["phase"]})
                except Exception:
                    self._send(503, {"error": "Jr broker channel unavailable"})
                return
            if path == "/api/login":
                if set(payload) != {"passphrase"}:
                    self._send(400, {"error": "Invalid sign-in request"})
                    return
                try:
                    token = auth.login(payload["passphrase"])
                except AuthError:
                    self._send(401, {"error": "Sign-in unavailable or refused"})
                    return
                self._send(200, {"token": token})
                return
            if not self._authorized():
                self._send(401, {"error": "Jr sign-in required"})
                return
            if path == "/api/logout":
                with sessions_lock:
                    thread = sessions.pop(session_key(self._bearer()), None)
                    if thread:
                        checkpoint_ready.pop(thread, None)
                if thread and broker is not None:
                    try:
                        broker.stop(owner, thread)
                    except Exception:
                        # The independent watchdog is the final cable cutoff.
                        pass
                auth.revoke(self._bearer())
                self._send(200, {"ok": True})
            elif path == "/api/plan":
                if set(payload) != {"question"} or not isinstance(payload["question"], str):
                    self._send(400, {"error": "Question required"})
                    return
                try:
                    plan = model.plan(payload["question"])
                except ValueError:
                    self._send(400, {"error": "Question must be 1 to 6000 characters"})
                    return
                except ModelError:
                    self._send(503, {"error": "Local Jr model unavailable"})
                    return
                with sessions_lock:
                    if session_key(self._bearer()) in sessions:
                        self._send(409, {"error": "Stop the current research first"})
                        return
                    try:
                        thread = (history.create_plan(payload["question"], plan)
                                  if history is not None else secrets.token_hex(16))
                    except (HistoryError, OSError, ValueError):
                        self._send(503, {"error": "Jr history is unavailable"})
                        return
                    if broker is None:
                        self._send(200, {"plan": plan, "thread_id": thread,
                                         "internet": "off", "approval_available": False})
                        return
                    try:
                        nonce = broker.begin(owner, thread, json.dumps(plan))
                    except (BrokerUnavailable, BrokerRefused) as exc:
                        self._broker_failed(exc)
                        return
                    except Exception:
                        self._send(503, {"error": "Research gate unavailable"})
                        return
                    sessions[session_key(self._bearer())] = thread
                    checkpoint_ready[thread] = True  # first owner approval follows a saved plan
                self._send(200, {"plan": plan, "thread_id": thread, "internet": "off",
                                 "approval_available": True, "approval_nonce": nonce})
            elif path == "/api/hosted/preview":
                if hosted is None or set(payload) not in ({"text"}, {"text", "thread_id"}):
                    self._send(503, {"error": "Jr hosted helper is unavailable"})
                    return
                thread = payload.get("thread_id")
                if thread is not None:
                    # A checkpoint send: the answer is filed under this history thread.
                    if (history is None or type(thread) is not str or len(thread) != 32 or
                        any(c not in "0123456789abcdef" for c in thread)):
                        self._send(404, {"error": "No such Jr conversation"})
                        return
                    try:
                        if history.get_thread(thread) is None:
                            self._send(404, {"error": "No such Jr conversation"})
                            return
                    except HistoryError:
                        self._send(503, {"error": "Jr history is unavailable"})
                        return
                if text_allowed is not None and not text_allowed(payload["text"]):
                    self._send(403, {"error": NEVER_SEND_HIT})
                    return
                try:
                    preview = hosted.preview(session_key(self._bearer()), payload["text"])
                except (HostedError, SpendError):
                    self._send(400, {"error": "Jr hosted preview was refused"})
                    return
                if thread is not None:
                    with sessions_lock:
                        hosted_threads.clear()  # one pending text preview at a time, as in jr_hosted
                        hosted_threads[preview["nonce"]] = thread
                    preview["thread_id"] = thread
                self._send(200, preview)
            elif path == "/api/hosted/send":
                if hosted is None or set(payload) != {"nonce"} or type(payload["nonce"]) is not str:
                    self._send(503, {"error": "Jr hosted helper is unavailable"})
                    return
                with sessions_lock:
                    thread = hosted_threads.pop(payload["nonce"], None)
                try:
                    result = hosted.send(session_key(self._bearer()), payload["nonce"],
                                         text_allowed=text_allowed)
                except HostedError as exc:
                    if str(exc) == NEVER_SEND_REFUSED:
                        self._send(403, {"error": NEVER_SEND_REFUSED})
                    else:
                        self._send(503, {"error": "Jr hosted send was refused; inspect the spend ledger"})
                    return
                except SpendError:
                    self._send(503, {"error": "Jr hosted send was refused; inspect the spend ledger"})
                    return
                if thread is not None and history is not None:
                    try:
                        history.hosted_checkpoint(thread, result)
                        result["history_recorded"] = True
                    except (HistoryError, KeyError, ValueError, OSError):
                        result["history_recorded"] = False
                    result["thread_id"] = thread
                self._send(200, result)
            elif path == "/api/video/read":
                if video is None:
                    self._send(503, {"error": "Jr video reading is not installed"})
                    return
                if set(payload) != {"url"} or type(payload["url"]) is not str:
                    self._send(400, {"error": "Video URL required"})
                    return
                with sessions_lock:
                    if video_state["busy"]:
                        self._send(409, {"error": "A video is already being read"})
                        return
                    video_state["busy"] = True
                try:
                    self._send(200, video.read(payload["url"]))
                except VideoError as exc:
                    self._send(400, {"error": str(exc)})
                except Exception:
                    self._send(503, {"error": "Jr video reading failed"})
                finally:
                    with sessions_lock:
                        video_state["busy"] = False
            elif path == "/api/video/preview":
                if video is None or hosted is None:
                    self._send(503, {"error": "Jr video hosted review is unavailable"})
                    return
                if set(payload) != {"thread_id"} or type(payload["thread_id"]) is not str:
                    self._send(400, {"error": "Video reading id required"})
                    return
                record = video.record_for(payload["thread_id"])
                if record is None:
                    self._send(404, {"error": "No such video reading in this service run"})
                    return
                try:
                    self._send(200, hosted.preview_video(session_key(self._bearer()), record))
                except (HostedError, SpendError) as exc:
                    self._send(400, {"error": str(exc)})
            elif path == "/api/video/send":
                if hosted is None:
                    self._send(503, {"error": "Jr hosted helper is unavailable"})
                    return
                if (set(payload) != {"nonce", "confirm_text"} or
                    type(payload["nonce"]) is not str or type(payload["confirm_text"]) is not str):
                    self._send(400, {"error": "Preview nonce and typed confirmation required"})
                    return
                try:
                    self._send(200, hosted.send_video(session_key(self._bearer()),
                                                      payload["nonce"], payload["confirm_text"]))
                except HostedError as exc:
                    self._send(403, {"error": str(exc)})
                except SpendError:
                    self._send(503, {"error": "Jr hosted send was refused; inspect the spend ledger"})
            elif path.startswith("/api/research/"):
                if broker is None:
                    self._send(503, {"ready": False, "error": "Research broker is not installed"})
                    return
                if path == "/api/research/emergency" and not payload:
                    try:
                        broker.emergency()
                        with sessions_lock:
                            sessions.clear()
                            checkpoint_ready.clear()
                            broker_fault.clear()
                        self._send(200, {"phase": "fault", "poweroff_confirmed": True})
                    except BrokerUnavailable as exc:
                        self._send(503, {"phase": "fault", "poweroff_confirmed": False,
                                         "error": UI_STATES[exc.state], "broker": exc.state})
                    except Exception:
                        self._send(503, {"phase": "fault", "poweroff_confirmed": False,
                                         "error": "Poweroff not confirmed"})
                    return
                with sessions_lock:
                    thread = sessions.get(session_key(self._bearer()))
                if not thread:
                    self._send(409, {"error": "Make an offline plan first"})
                    return
                if path == "/api/research/stop" and not payload:
                    try:
                        state = broker.stop(owner, thread)
                        if type(state) is not dict:
                            state = broker.status(owner, thread)  # a legacy client returns None
                        if history is not None:
                            history.checkpoint(thread, state)
                        state["approval_nonce"] = None
                        self._send(200, state)
                    except (BrokerUnavailable, BrokerRefused) as exc:
                        self._broker_failed(exc)
                    except Exception:
                        self._send(503, {"error": "Research gate unavailable; check the cable"})
                    finally:
                        # Whatever the broker did, this session no longer owns a batch.
                        with sessions_lock:
                            sessions.pop(session_key(self._bearer()), None)
                            checkpoint_ready.pop(thread, None)
                            broker_fault.pop(thread, None)
                    return
                try:
                    if path == "/api/research/approve" and set(payload) == {"nonce"} and isinstance(payload["nonce"], str):
                        with sessions_lock:
                            if not checkpoint_ready.get(thread, False):
                                self._send(409, {"error": "Wait for the saved research checkpoint"})
                                return
                            expected = broker.status(owner, thread).get("approval_nonce")
                            if not expected or payload["nonce"] != expected:
                                self._send(409, {"error": "Approval is missing, spent or stale"})
                                return
                            checkpoint_ready[thread] = False
                            broker_fault.pop(thread, None)
                            broker.approve(owner, thread, payload["nonce"])
                        start_watcher(thread)
                        state = broker.status(owner, thread)
                        state["approval_nonce"] = None
                        self._send(200, state)
                    else:
                        self._send(400, {"error": "Invalid research action"})
                except (BrokerUnavailable, BrokerRefused) as exc:
                    self._broker_failed(exc)
                except Exception:
                    self._send(503, {"error": "Research gate unavailable; check the cable"})
            else:
                self._send(404, {"error": "Not found"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.batch_watchers = watchers
    server.watch_batch = watch_batch   # tests drive it directly (wave 3e F6)
    return server
