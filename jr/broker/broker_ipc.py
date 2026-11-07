"""Narrow authenticated Windows named-pipe protocol for the Jr broker.

CHANGED 2026-09-28 late (wave 3g, skeptic wave 3f finding 1): _handle stamps
time.monotonic() when it takes the connection, before any wait for a slot,
and hands it to approve as received_at (only when approve accepts that
keyword), so approve's time budget counts the slot wait.

CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e findings 6 and 2):
- F6: past MAX_CONCURRENT busy slots the accept loop no longer serves the
  overflow inline (a slow approve or stop there held every later
  connection, an emergency included, past the app's deadline). The overflow
  goes to its own thread: an emergency runs at once without a slot; any
  other op waits up to OVERFLOW_SLOT_WAIT_SECONDS for a slot and is refused
  (the generic refusal) if none frees. Only the owner's authenticated app
  can connect, so the overflow threads are bounded by its own calls.
- F2: approve receives an optional client_alive callable (only when the
  broker's approve accepts that keyword) that reads the pipe with
  PeekNamedPipe: False once the client has closed its end (its deadline
  passed), so the broker can refuse before the cable goes on.

CHANGED 2026-09-28 late (wave 3e, skeptic wave 3d finding 3): serve()
hands each accepted connection to its own thread (at most MAX_CONCURRENT,
16; past that the accept loop serves the overflow itself). The server used
to run one request at a time, so the stage's 1 s status poll, and behind it
the emergency op, queued behind any op waiting on the broker lock while the
loop held it across a guest call of up to 15 s. The six operations, the
request and reply frames and the refusal rules are unchanged.

The web app holds only a pipe address and a random in-memory auth key. It
cannot send commands, paths, VM identifiers, URLs, or guest credentials. The
privileged process owns the fixed VM adapter and independently polls receipts.
This is staged; service-account bootstrap and ACLs are not installed yet.

CHANGED 2026-09-28 (Jr overnight build, helper item 2 "pipe"), from Codex's
2026-09-28 09:48 version. The six operations are unchanged; the request is
still one pipe message of at most MAX_MESSAGE (8192) bytes.
- MAX_REPLY rose from 8192 to 1,048,576. Item 6's status dicts carry up to
  30 receipts with links plus 12,000 characters of observed_text; the
  skeptic measured about 520 KB worst case, and at 8192 every poll() and
  status() would have come back "Broker reply too large".
- Replies are framed explicitly: an 8-byte header (REPLY_MAGIC + little
  endian length) then the payload in pipe messages of at most REPLY_CHUNK
  (8192) bytes. Each chunk fits the smallest pipe buffer, so delivery never
  depends on the pipe file system expanding its quota for a large message,
  and the reader knows the exact size before it reads a byte. send_reply and
  recv_reply are the only framing code; every client uses recv_reply.
- serve() bounds the wait for a request (REQUEST_WAIT_SECONDS) with
  wait_for_message(), which uses PeekNamedPipe and never blocks, so a client
  that connects and then stays silent cannot wedge the single accept loop.
  secure_pipe.py reuses the helper to bound the key handshake.
- serve() no longer dies on an unexpected exception from accept() or from a
  reply; a dead accept loop was one half of a hang found in testing.
- close() wakes a blocked accept() with a bare connect-write-close instead of
  a full authenticated Client(); the old wake-up waited forever for a
  handshake whenever nothing was accepting (the other half of that hang).

CHANGED 2026-09-28 (wave 2 integration, OpenRouter review item): the server
key must be exactly 32 bytes (it accepted anything longer), matching the
channel file parser in jr_broker_channel, which refuses any other length.

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix item 1): a
broker operation may raise BrokerRefusal(code) with a code from the closed
set TYPED_REFUSALS ("navigator_busy"); the reply is then
{"ok": false, "error": code} instead of the generic refusal, so the app can
say why. The code is a fixed constant, never exception text; every other
exception is still the generic refusal. BrokerPipeClient raises PipeError
with the code. The six operations and the frame shapes are unchanged.
"""

from __future__ import annotations

import inspect
import json
from multiprocessing.connection import AuthenticationError, Client, Listener
import secrets
import struct
import threading
import time

import _winapi


MAX_MESSAGE = 8192
MAX_REPLY = 1_048_576
REPLY_MAGIC = b"JRR1"
REPLY_CHUNK = 8192
REQUEST_WAIT_SECONDS = 10.0
MAX_CONCURRENT = 16   # pipe ops served at once, each on its own thread (wave 3e F3)
OVERFLOW_SLOT_WAIT_SECONDS = 10.0   # a non-emergency op past the slots waits this long (wave 3f F6)
EMERGENCY_OP = "emergency"
ALLOWED = {
    "begin": {"owner", "thread", "plan"},
    "approve": {"owner", "thread", "nonce"},
    "status": {"owner", "thread"},
    "stop": {"owner", "thread"},
    "emergency": set(),
    "poll": set(),
}
_REFUSED = b'{"ok":false,"error":"Broker operation refused"}'
# Refusal codes that may cross the pipe verbatim (fixed constants only).
TYPED_REFUSALS = frozenset({"navigator_busy"})
_TOO_LARGE = b'{"ok":false,"error":"Broker reply too large"}'


class PipeError(Exception):
    pass


class BrokerRefusal(Exception):
    """A refusal the pipe reports by its fixed code (ADDED 2026-09-28 late)."""

    def __init__(self, code):
        if code not in TYPED_REFUSALS:
            raise ValueError("Unknown typed broker refusal")
        super().__init__(code)
        self.code = code


class PipeTimeout(OSError):
    """The pipe peer stayed silent past its deadline."""


def peer_connected(handle) -> bool:
    """True while the pipe's other end is still open (ADDED 2026-09-28 late,
    wave 3f F2). PeekNamedPipe fails (broken pipe) once the peer closed."""
    try:
        _winapi.PeekNamedPipe(handle)
    except OSError:
        return False
    return True


def _accepts_keyword(fn, name) -> bool:
    """True when `fn` takes the keyword `name` (or **kwargs); False when unsure."""
    try:
        parameters = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == name and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY) or
               p.kind is p.VAR_KEYWORD for p in parameters)


def wait_for_message(handle, deadline: float) -> None:
    """Return once a message is readable on `handle`; raise PipeTimeout at `deadline`.

    A broken pipe surfaces as OSError from PeekNamedPipe, so a peer that goes
    away does not stall the wait either.
    """
    while True:
        available, _ = _winapi.PeekNamedPipe(handle)
        if available:
            return
        if time.monotonic() >= deadline:
            raise PipeTimeout("Pipe peer stayed silent past its deadline")
        time.sleep(0.02)


def send_reply(connection, payload: bytes) -> None:
    """Write `payload` as a header message followed by chunks of at most REPLY_CHUNK bytes."""
    if not 0 < len(payload) <= MAX_REPLY:
        raise PipeError("Broker reply size is out of range")
    connection.send_bytes(REPLY_MAGIC + struct.pack("<I", len(payload)))
    for start in range(0, len(payload), REPLY_CHUNK):
        connection.send_bytes(payload[start:start + REPLY_CHUNK])


def recv_reply(connection) -> bytes:
    """Read one framed reply; `connection` needs only recv_bytes(maxsize). Raises PipeError."""
    header = connection.recv_bytes(8)
    if len(header) != 8 or header[:4] != REPLY_MAGIC:
        raise PipeError("Broker reply framing is wrong")
    total = struct.unpack("<I", header[4:])[0]
    if not 0 < total <= MAX_REPLY:
        raise PipeError("Broker reply size is out of range")
    parts = []
    received = 0
    while received < total:
        chunk = connection.recv_bytes(REPLY_CHUNK)
        if not chunk or len(chunk) > min(REPLY_CHUNK, total - received):
            raise PipeError("Broker reply framing is wrong")
        parts.append(chunk)
        received += len(chunk)
    return b"".join(parts)


class BrokerPipeServer:
    def __init__(self, broker, *, address=None, authkey=None, listener_factory=None,
                 allow_insecure_test=False):
        self.broker = broker
        self.address = address or rf"\\.\pipe\jr-broker-{secrets.token_hex(12)}"
        self.authkey = authkey or secrets.token_bytes(32)
        if not isinstance(self.authkey, bytes) or len(self.authkey) != 32:
            raise ValueError("A 256-bit broker key is required")
        if listener_factory is None and not allow_insecure_test:
            raise ValueError("A restricted Windows pipe listener is required")
        self.listener = (listener_factory(self.address, authkey=self.authkey)
                         if listener_factory is not None else
                         Listener(self.address, family="AF_PIPE", authkey=self.authkey))
        self.closed = threading.Event()
        self.thread = None
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)   # wave 3e F3

    def start(self):
        if self.thread is not None:
            raise PipeError("Broker pipe already started")
        self.thread = threading.Thread(target=self.serve, name="jr-broker-pipe", daemon=True)
        self.thread.start()
        return self

    def _handle(self, connection, overflow=False) -> bytes:
        """Read one request, run it, and return the encoded reply. Never raises.
        With overflow (wave 3f F6) the connection holds no slot: an emergency
        runs at once, anything else first waits for a slot, bounded."""
        received = time.monotonic()   # wave 3g F1: before any slot wait
        try:
            wait_for_message(connection.fileno(), time.monotonic() + REQUEST_WAIT_SECONDS)
            raw = connection.recv_bytes(MAX_MESSAGE)
            request = json.loads(raw)
            if type(request) is not dict:
                raise ValueError()
            op = request.pop("op", None)
            if op not in ALLOWED or set(request) != ALLOWED[op]:
                raise ValueError()
            if any(type(value) is not str or not value or len(value) > 6000
                   for value in request.values()):
                raise ValueError()
            method = getattr(self.broker, op)
            if op == "approve" and _accepts_keyword(method, "client_alive"):
                handle = connection.fileno()
                request["client_alive"] = lambda: peer_connected(handle)   # wave 3f F2
            if op == "approve" and _accepts_keyword(method, "received_at"):
                request["received_at"] = received                        # wave 3g F1
            if overflow and op != EMERGENCY_OP:
                if not self._slots.acquire(timeout=OVERFLOW_SLOT_WAIT_SECONDS):
                    return _REFUSED
                try:
                    result = method(**request)
                finally:
                    self._slots.release()
            else:
                result = method(**request)
            raw_reply = json.dumps({"ok": True, "result": result}, ensure_ascii=True).encode("ascii")
        except BrokerRefusal as exc:
            code = exc.code if type(exc.code) is str and exc.code in TYPED_REFUSALS else None
            if code is None:
                return _REFUSED
            return json.dumps({"ok": False, "error": code}, ensure_ascii=True).encode("ascii")
        except Exception:
            # Never return an exception that might contain private text.
            return _REFUSED
        if len(raw_reply) > MAX_REPLY:
            return _TOO_LARGE
        return raw_reply

    def _serve_one(self, connection, slot=True, overflow=False):
        """One accepted connection: read, run, reply, close. Never raises."""
        try:
            with connection:
                if self.closed.is_set():
                    return
                reply = self._handle(connection, overflow=overflow)
                try:
                    send_reply(connection, reply)
                except Exception:
                    pass  # the client went away; the server must survive
        except Exception:
            pass
        finally:
            if slot:
                self._slots.release()

    def serve(self):
        """Accept loop. CHANGED 2026-09-28 late (wave 3e, skeptic wave 3d
        finding 3): each accepted connection is served on its own thread, so
        an op waiting on the broker lock (begin, approve, stop, a heartbeat
        write) no longer queues status, poll or emergency behind it. At most
        MAX_CONCURRENT run at once. CHANGED 2026-09-28 late (wave 3f F6):
        past that the next one goes to an overflow thread (never served
        inline here, where a slow op held every later connection): an
        emergency runs at once, any other op waits for a slot, bounded. The
        broker's own lock still orders its ops."""
        while not self.closed.is_set():
            try:
                connection = self.listener.accept()
            except (OSError, EOFError, AuthenticationError):
                if self.closed.is_set():
                    return
                continue
            except Exception:
                if self.closed.is_set():
                    return
                time.sleep(0.1)  # an unexpected failure must not become a hot loop
                continue
            if self.closed.is_set():
                try:
                    connection.close()
                except Exception:
                    pass
                return
            if not self._slots.acquire(blocking=False):
                try:
                    threading.Thread(target=self._serve_one, args=(connection,),
                                     kwargs={"slot": False, "overflow": True},
                                     name="jr-broker-pipe-overflow", daemon=True).start()
                except Exception:
                    self._serve_one(connection, slot=False, overflow=True)   # last resort
                continue
            try:
                threading.Thread(target=self._serve_one, args=(connection,),
                                 name="jr-broker-pipe-op", daemon=True).start()
            except Exception:
                self._serve_one(connection)

    def _wake(self):
        """Open, poke and close a client end so a blocked accept() returns. Never waits."""
        try:
            handle = _winapi.CreateFile(
                self.address, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                _winapi.OPEN_EXISTING, 0, _winapi.NULL)
        except OSError:
            return
        try:
            _winapi.WriteFile(handle, b"bye")
        except OSError:
            pass
        finally:
            _winapi.CloseHandle(handle)

    def close(self):
        self.closed.set()
        if self.thread is not None and self.thread.is_alive():
            self._wake()
            self.thread.join(timeout=2)
        self.listener.close()


class BrokerPipeClient:
    def __init__(self, address, authkey):
        self.address = address
        self.authkey = authkey

    def _call(self, op, **fields):
        if op not in ALLOWED or set(fields) != ALLOWED[op]:
            raise PipeError("Unknown broker operation")
        raw = json.dumps({"op": op, **fields}, ensure_ascii=True).encode("ascii")
        if len(raw) > MAX_MESSAGE:
            raise PipeError("Broker request too large")
        try:
            with Client(self.address, family="AF_PIPE", authkey=self.authkey) as connection:
                connection.send_bytes(raw)
                if not connection.poll(20):
                    raise PipeError("Broker reply timed out")
                reply = json.loads(recv_reply(connection))
        except Exception as exc:
            raise PipeError("Broker channel unavailable") from exc
        if type(reply) is not dict or reply.get("ok") is not True:
            code = reply.get("error") if type(reply) is dict else None
            typed = type(code) is str and code in TYPED_REFUSALS
            raise PipeError(code if typed else "Broker operation refused")
        return reply.get("result")

    def begin(self, owner, thread, plan):
        return self._call("begin", owner=owner, thread=thread, plan=plan)

    def approve(self, owner, thread, nonce):
        return self._call("approve", owner=owner, thread=thread, nonce=nonce)

    def status(self, owner, thread):
        return self._call("status", owner=owner, thread=thread)

    def poll(self):
        return self._call("poll")

    def stop(self, owner, thread):
        return self._call("stop", owner=owner, thread=thread)

    def emergency(self):
        return self._call("emergency")
