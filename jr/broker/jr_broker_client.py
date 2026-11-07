"""Channel-verified, deadline-bounded broker pipe client for the Jr web service.

ADDED 2026-09-28 (Jr overnight build, helper item 2 "pipe").
CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e finding 2): optional
per-op deadlines. ChannelBrokerClient(op_timeouts={"approve": 30, "stop": 45})
gives those ops their own deadline (connect, handshake and reply, as
before); every other op keeps `timeout` (10 s). Kept private
(_op_timeouts) so the client's public surface stays the frozen one. The app passes
jr_app_server.BROKER_OP_TIMEOUTS, so an approve that waits on the guest gate
and makes its guest calls, or a stop behind the loop's guest call, is not
cut off at 10 s while the broker carries on and puts the cable on.
CHANGED 2026-09-28 evening (fix helper, skeptic item 1): the channel file is
accepted as the broker actually writes it (owner broker account, inherited
entries); the directory check is unchanged. See the trust model below.

ChannelBrokerClient is what jr_app_server.make_server() receives as `broker`
once the broker is installed. Its interface is frozen (HELPER-RULES.md):

    begin(owner, thread_id, plan_json) -> nonce (str)
    approve(owner, thread_id, nonce) -> status dict
    status(owner, thread_id) -> dict
    poll() -> dict
    stop(owner, thread_id) -> dict
    emergency() -> dict
    available() -> bool

status() and stop() take (owner, thread_id): the pipe protocol
(broker_ipc.ALLOWED) and ResearchBroker both require the owner, and
jr_app_server already calls them that way. Return shapes are the broker's
own dicts, passed through untouched (so lease_seconds and presence arrive as
the broker sent them). There is never a .vm attribute.

Trust model, checked on every call, never cached:
- The channel directory is opened through a handle (reparse points refused)
  and its owner and DACL are read from that handle. Accepted: owner
  Administrators; allow entries only for SYSTEM, Administrators, the broker
  account (writer) and the service account (reader, no write, delete or ACL
  rights); no other entry of any kind; inheritance disabled (protected DACL,
  no inherited entries), because an open access list can be widened later by
  a change to any parent folder.
- broker-channel.json inside it is then opened the same way and checked
  before any byte is parsed. CHANGED 2026-09-28 (fix helper, skeptic item 1):
  the broker writes the file from a filtered token with mkstemp plus
  os.replace and never sets an ACL, so the file is owned by the broker
  account and carries only entries inherited from the folder. The file check
  therefore accepts owner Administrators or the broker account, and accepts
  inherited entries and an unprotected DACL, because the folder they come
  from was just verified strictly and its protected DACL ends the chain.
  Every entry still has to be an allow entry for one of the four accounts,
  and the service account still gets no write, delete or ACL right.
- The pipe named in the file must be owned by the broker account, checked on
  the opened client handle before the key handshake, so a pipe-name squatter
  never sees the handshake. The client opens the pipe at identification
  level: enough for the broker to read our SID, not enough to act as us.
- One deadline per call (timeout, default 10 s) covers connect, handshake,
  request and reply. Replies use broker_ipc's framed protocol (header plus
  8 KB chunks, up to MAX_REPLY), read through recv_reply. approve, stop and
  emergency issue a second call for the status dict when the broker returns
  None (today's ResearchBroker), so their worst case is two deadlines.

Failures are typed. BrokerUnavailable(state) means no usable broker; `state`
is one of UI_STATES for the page. BrokerRefused means a live broker declined
the operation (stale nonce, wrong owner, cable fault). available() answers
only "is there a trusted channel file and a pipe at its address"; it opens
no connection, and it does not tell the states apart: call poll() and catch
BrokerUnavailable for that.
"""

from __future__ import annotations

import json
from multiprocessing.connection import AuthenticationError, PipeConnection, answer_challenge, deliver_challenge
from pathlib import Path
import time

import jr_deps

jr_deps.load()

import _winapi
import ntsecuritycon
import pywintypes
import win32con
import win32file
import win32security

from broker_ipc import ALLOWED, MAX_MESSAGE, PipeError, PipeTimeout, recv_reply
from jr_broker_channel import MAX_BYTES, MIN_BYTES, ChannelError, parse_channel_row
from secure_pipe import current_user_sid, string_sid


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
EXPECTED_OWNER_SID = ADMINISTRATORS_SID  # module global so tests can patch it; production never does
CHANNEL_FILE = "broker-channel.json"
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 120.0

# Any of these bits on the service account's entry means it could alter the file.
WRITE_RIGHTS = (ntsecuritycon.FILE_WRITE_DATA | ntsecuritycon.FILE_APPEND_DATA |
                ntsecuritycon.FILE_WRITE_EA | ntsecuritycon.FILE_WRITE_ATTRIBUTES |
                ntsecuritycon.FILE_DELETE_CHILD | ntsecuritycon.DELETE |
                ntsecuritycon.WRITE_DAC | ntsecuritycon.WRITE_OWNER |
                ntsecuritycon.GENERIC_WRITE | ntsecuritycon.GENERIC_ALL |
                ntsecuritycon.ACCESS_SYSTEM_SECURITY | ntsecuritycon.MAXIMUM_ALLOWED)

INHERITED_ACE = 0x10  # ACE flag: the entry was propagated from a parent folder
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_SEM_TIMEOUT = 121
ERROR_PIPE_BUSY = 231
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000  # SecurityIdentification << 16
FILE_SHARE_ALL = (win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE |
                  win32con.FILE_SHARE_DELETE)

UI_STATES = {
    "missing": "Broker not installed: the channel file is absent",
    "untrusted": "Broker channel refused: owner or permissions are wrong",
    "damaged": "Broker channel refused: the file contents are invalid",
    "unreachable": "Broker offline: its pipe is absent or refused the connection",
    "timeout": "Broker not responding",
    "protocol": "Broker replied with something that is not the Jr protocol",
}


class ChannelBrokerError(Exception):
    pass


class BrokerUnavailable(ChannelBrokerError):
    """No usable broker. `state` is a UI_STATES key; `detail` is a short reason."""

    def __init__(self, state: str, detail: str):
        if state not in UI_STATES:
            raise ValueError("Unknown broker availability state")
        super().__init__(f"{UI_STATES[state]} ({detail})")
        self.state = state
        self.detail = detail


class BrokerRefused(ChannelBrokerError):
    """A live broker declined the operation."""


def verify_channel_descriptor(descriptor, *, broker_sid: str, service_sid: str,
                              what: str = "channel file", written_by_broker: bool = False) -> None:
    """Raise BrokerUnavailable('untrusted') unless `descriptor` is what the installer sets.

    With written_by_broker=False (the directory, the default) the descriptor
    must be exactly the installer's: owner Administrators, protected DACL, no
    inherited entry. With written_by_broker=True (the channel file, CHANGED
    2026-09-28, fix helper, skeptic item 1) the owner may also be the broker
    account and the entries may be inherited from the directory, which the
    caller has already verified strictly. The entry rules are the same in
    both modes."""
    owner = descriptor.GetSecurityDescriptorOwner()
    if owner is None:
        raise BrokerUnavailable("untrusted", f"{what} has no owner")
    owner_sid = win32security.ConvertSidToStringSid(owner)
    if written_by_broker:
        if owner_sid not in (EXPECTED_OWNER_SID, broker_sid):
            raise BrokerUnavailable("untrusted", f"{what} owner is not Administrators or the broker account")
    elif owner_sid != EXPECTED_OWNER_SID:
        raise BrokerUnavailable("untrusted", f"{what} owner is not Administrators")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise BrokerUnavailable("untrusted", f"{what} has no access list")
    if acl.GetAceCount() == 0:
        raise BrokerUnavailable("untrusted", f"{what} has an empty access list")
    control = descriptor.GetSecurityDescriptorControl()[0]
    if not written_by_broker and not control & win32security.SE_DACL_PROTECTED:
        # An access list still open to inheritance can be widened later by a
        # change to any parent folder; the installer disables inheritance.
        raise BrokerUnavailable("untrusted", f"{what} access list inherits from its folder")
    writers = {SYSTEM_SID, ADMINISTRATORS_SID, broker_sid}
    for index in range(acl.GetAceCount()):
        (ace_type, flags), mask, sid = acl.GetAce(index)
        name = win32security.ConvertSidToStringSid(sid)
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise BrokerUnavailable("untrusted", f"{what} carries a non-allow entry")
        if flags & INHERITED_ACE and not written_by_broker:
            raise BrokerUnavailable("untrusted", f"{what} access list inherits from its folder")
        if name == service_sid:
            if mask & WRITE_RIGHTS:
                raise BrokerUnavailable("untrusted", f"{what} lets the service account write")
        elif name not in writers:
            raise BrokerUnavailable("untrusted", f"{what} grants an unexpected account access")


def _open_checked(path: Path, *, directory: bool, broker_sid: str, service_sid: str,
                  what: str) -> bytes | None:
    """Open `path`, verify it through the handle, return the file's bytes (None for a directory)."""
    flags = win32file.FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= win32file.FILE_FLAG_BACKUP_SEMANTICS
    try:
        handle = win32file.CreateFile(
            str(path), win32con.GENERIC_READ | win32con.READ_CONTROL, FILE_SHARE_ALL,
            None, win32con.OPEN_EXISTING, flags, None)
    except pywintypes.error as exc:
        if exc.winerror in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
            raise BrokerUnavailable("missing", f"{what} is absent") from exc
        if exc.winerror == ERROR_ACCESS_DENIED:
            raise BrokerUnavailable("untrusted", f"{what} is not readable by the service account") from exc
        raise BrokerUnavailable("damaged", f"{what} could not be opened") from exc
    try:
        try:
            info = win32file.GetFileInformationByHandle(handle)
            attributes = info[0]
            if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                raise BrokerUnavailable("untrusted", f"{what} is a reparse point")
            if bool(attributes & win32con.FILE_ATTRIBUTE_DIRECTORY) != directory:
                raise BrokerUnavailable("untrusted", f"{what} is not a {'directory' if directory else 'file'}")
            descriptor = win32security.GetSecurityInfo(
                handle, win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
            verify_channel_descriptor(descriptor, broker_sid=broker_sid, service_sid=service_sid,
                                      what=what, written_by_broker=not directory)
            if directory:
                return None
            size = (info[5] << 32) | info[6]
            if not MIN_BYTES <= size <= MAX_BYTES:
                raise BrokerUnavailable("damaged", f"{what} has an implausible size")
            _rc, raw = win32file.ReadFile(handle, MAX_BYTES + 1)
            return bytes(raw)
        except pywintypes.error as exc:
            raise BrokerUnavailable("damaged", f"{what} could not be inspected") from exc
    finally:
        handle.Close()


class _TimedClientConnection:
    """send_bytes/recv_bytes over an overlapped client handle with one deadline for every read."""

    def __init__(self, connection, deadline: float):
        self._connection = connection
        self._deadline = deadline

    def send_bytes(self, data):
        self._connection.send_bytes(data)

    def recv_bytes(self, maxsize=None):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0 or not self._connection.poll(remaining):
            raise PipeTimeout("Broker stayed silent past the deadline")
        return self._connection.recv_bytes(maxsize)


def _short_error(value) -> str:
    if type(value) is str and 0 < len(value) <= 120 and value.isascii() and value.isprintable():
        return value
    return "Broker operation refused"


class ChannelBrokerClient:
    def __init__(self, channel_dir, *, broker_sid: str, service_sid: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT, op_timeouts=None):
        self.channel_dir = Path(channel_dir)
        if not self.channel_dir.is_absolute():
            raise ValueError("The channel directory must be an absolute path")
        self.broker_sid = string_sid(broker_sid, "The broker account SID")
        self.service_sid = (string_sid(service_sid, "The service account SID")
                            if service_sid is not None else current_user_sid())
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0.1 <= timeout <= MAX_TIMEOUT):
            raise ValueError(f"timeout must be between 0.1 and {MAX_TIMEOUT:g} seconds")
        self.timeout = float(timeout)
        # Wave 3f F2: per-op deadlines, same bounds as `timeout`.
        self._op_timeouts = {}
        for op, value in dict(op_timeouts or {}).items():
            if (op not in ALLOWED or isinstance(value, bool) or
                    not isinstance(value, (int, float)) or not 0.1 <= value <= MAX_TIMEOUT):
                raise ValueError(f"op_timeouts must map broker operations to 0.1 to {MAX_TIMEOUT:g} seconds")
            self._op_timeouts[op] = float(value)

    # -- channel file -------------------------------------------------------

    def _read_channel(self) -> tuple[str, bytes]:
        _open_checked(self.channel_dir, directory=True, broker_sid=self.broker_sid,
                      service_sid=self.service_sid, what="channel directory")
        raw = _open_checked(self.channel_dir / CHANNEL_FILE, directory=False,
                            broker_sid=self.broker_sid, service_sid=self.service_sid,
                            what="channel file")
        try:
            return parse_channel_row(raw)
        except ChannelError as exc:
            raise BrokerUnavailable("damaged", "channel file contents are invalid") from exc

    # -- pipe ---------------------------------------------------------------

    def _connect(self, address: str, deadline: float):
        access = _winapi.GENERIC_READ | _winapi.GENERIC_WRITE
        flags = _winapi.FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
        while True:
            try:
                handle = _winapi.CreateFile(address, access, 0, _winapi.NULL,
                                            _winapi.OPEN_EXISTING, flags, _winapi.NULL)
                break
            except OSError as exc:
                if exc.winerror == ERROR_PIPE_BUSY:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise BrokerUnavailable("timeout", "broker pipe stayed busy") from exc
                    try:
                        _winapi.WaitNamedPipe(address, max(1, int(remaining * 1000)))
                    except OSError as wait_exc:
                        if wait_exc.winerror == ERROR_SEM_TIMEOUT:
                            raise BrokerUnavailable("timeout", "broker pipe stayed busy") from wait_exc
                        raise BrokerUnavailable("unreachable", "broker pipe went away") from wait_exc
                    continue
                if exc.winerror in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                    raise BrokerUnavailable("unreachable", "no broker pipe at the channel address") from exc
                if exc.winerror == ERROR_ACCESS_DENIED:
                    raise BrokerUnavailable("unreachable", "broker pipe refused this account") from exc
                raise BrokerUnavailable("unreachable", f"broker pipe open failed ({exc.winerror})") from exc
        try:
            _winapi.SetNamedPipeHandleState(handle, _winapi.PIPE_READMODE_MESSAGE, None, None)
            try:
                descriptor = win32security.GetSecurityInfo(
                    handle, win32security.SE_KERNEL_OBJECT, win32security.OWNER_SECURITY_INFORMATION)
                owner = descriptor.GetSecurityDescriptorOwner()
                owner_sid = win32security.ConvertSidToStringSid(owner) if owner is not None else None
            except pywintypes.error as exc:
                raise BrokerUnavailable("untrusted", "broker pipe owner could not be read") from exc
            if owner_sid != self.broker_sid:
                raise BrokerUnavailable("untrusted", "broker pipe is not owned by the broker account")
        except BaseException:
            _winapi.CloseHandle(handle)
            raise
        return handle

    def _call(self, op: str, **fields):
        if op not in ALLOWED or set(fields) != ALLOWED[op]:
            raise ValueError("Unknown broker operation")
        if any(type(value) is not str or not value or len(value) > 6000 for value in fields.values()):
            raise ValueError("Broker operation fields must be non-empty strings of at most 6000 characters")
        raw = json.dumps({"op": op, **fields}, ensure_ascii=True).encode("ascii")
        if len(raw) > MAX_MESSAGE:
            raise ValueError("Broker request too large")
        address, key = self._read_channel()
        deadline = time.monotonic() + self._op_timeouts.get(op, self.timeout)
        connection = PipeConnection(self._connect(address, deadline))
        try:
            timed = _TimedClientConnection(connection, deadline)
            try:
                answer_challenge(timed, key)
                deliver_challenge(timed, key)
            except PipeTimeout as exc:
                raise BrokerUnavailable("timeout", "broker did not complete the handshake") from exc
            except AuthenticationError as exc:
                raise BrokerUnavailable("unreachable", "channel key does not match the broker") from exc
            except (OSError, EOFError) as exc:
                raise BrokerUnavailable("unreachable", "broker closed the pipe during the handshake") from exc
            try:
                timed.send_bytes(raw)
                reply_raw = recv_reply(timed)
            except PipeTimeout as exc:
                raise BrokerUnavailable("timeout", "broker did not reply in time") from exc
            except PipeError as exc:
                raise BrokerUnavailable("protocol", "reply framing is wrong") from exc
            except (OSError, EOFError) as exc:
                raise BrokerUnavailable("unreachable", "broker closed the pipe before replying") from exc
        finally:
            connection.close()
        try:
            reply = json.loads(reply_raw)
        except ValueError as exc:
            raise BrokerUnavailable("protocol", "reply is not JSON") from exc
        if type(reply) is not dict or "ok" not in reply:
            raise BrokerUnavailable("protocol", "reply has no ok field")
        if reply["ok"] is not True:
            raise BrokerRefused(_short_error(reply.get("error")))
        return reply.get("result")

    @staticmethod
    def _as_status(result) -> dict:
        if type(result) is not dict or type(result.get("phase")) is not str:
            raise BrokerUnavailable("protocol", "status reply is not a broker status dict")
        return result

    # -- frozen interface ---------------------------------------------------

    def begin(self, owner: str, thread_id: str, plan_json: str) -> str:
        nonce = self._call("begin", owner=owner, thread=thread_id, plan=plan_json)
        if type(nonce) is not str or not nonce:
            raise BrokerUnavailable("protocol", "begin returned no nonce")
        return nonce

    def approve(self, owner: str, thread_id: str, nonce: str) -> dict:
        result = self._call("approve", owner=owner, thread=thread_id, nonce=nonce)
        if result is None:
            return self.status(owner, thread_id)
        return self._as_status(result)

    def status(self, owner: str, thread_id: str) -> dict:
        return self._as_status(self._call("status", owner=owner, thread=thread_id))

    def poll(self) -> dict:
        return self._as_status(self._call("poll"))

    def stop(self, owner: str, thread_id: str) -> dict:
        result = self._call("stop", owner=owner, thread=thread_id)
        if result is None:
            return self.status(owner, thread_id)
        return self._as_status(result)

    def emergency(self) -> dict:
        result = self._call("emergency")
        if result is None:
            return self.poll()
        return self._as_status(result)

    def available(self) -> bool:
        try:
            address, _key = self._read_channel()
        except BrokerUnavailable:
            return False
        try:
            _winapi.WaitNamedPipe(address, 1)
        except OSError as exc:
            return exc.winerror in (ERROR_SEM_TIMEOUT, ERROR_PIPE_BUSY)
        return True
