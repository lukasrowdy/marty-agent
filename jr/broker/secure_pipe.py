"""Windows named-pipe listener pinned to one local client account.

Requires pywin32. The production caller supplies the separate Jr service
account SID as configuration; nothing here names an account. Authentication
still uses multiprocessing's 256-bit challenge, and the account check sits on
top of it.

CHANGED 2026-09-28 (Jr overnight build, helper item 2 "pipe"), from Codex's
2026-09-28 09:47 version:
- After the key handshake the server reads the connecting client's token with
  ImpersonateNamedPipeClient + OpenThreadToken + GetTokenInformation(TokenUser)
  and accepts the connection only when that SID equals the configured client
  SID. Anonymous-level clients cannot be identified and are refused.
- The pipe DACL grants only the owner (the account running the broker) and the
  configured client SID. The SYSTEM and Administrators grants are gone. A deny
  entry for network logons stays and PIPE_REJECT_REMOTE_CLIENTS is set too.
- The handshake is bounded (HANDSHAKE_SECONDS) so a client that connects and
  stays silent cannot wedge the accept loop.
- Pipe buffers are MAX_REPLY out and MAX_MESSAGE in (they were 8192 both),
  matching the 1 MiB reply cap in broker_ipc.
- Every pywin32 error inside accept() is re-raised as an OSError, because
  pywintypes.error is not an OSError and BrokerPipeServer.serve() only
  survives OSError, EOFError and AuthenticationError from accept().
- listener_factory() builds the callable BrokerPipeServer expects.

CHANGED 2026-09-28 (wave 2 integration, OpenRouter review item): the key
must be exactly 32 bytes, as broker_ipc and the channel parser require.

Why the token check uses impersonation rather than GetNamedPipeClientProcessId:
the process-id route needs OpenProcess and OpenProcessToken on the client,
which a non-elevated broker cannot do against a service account's process
(access denied); a process id can be reused after the client exits; and a
pipe handle can be duplicated into a process other than the one that opened
it. Impersonation gives the server the security context that actually opened
the pipe, attached by the kernel to the last message read, and it needs no
privilege. The read-only probe (qa_secure_pipe.py) relied on the DACL alone;
the DACL still applies and this check is added after it. The kernel only
attaches that context once a message has been read, which is why the check
runs after the handshake and not before it (verified 2026-09-28: before any
read, ImpersonateNamedPipeClient fails with ERROR_CANNOT_IMPERSONATE for a
default-level client).
"""

from __future__ import annotations

from multiprocessing.connection import PipeConnection, answer_challenge, deliver_challenge
import time

import jr_deps

jr_deps.load()

import pywintypes
import win32api
import win32con
import win32pipe
import win32security
import winerror

from broker_ipc import MAX_MESSAGE, MAX_REPLY, wait_for_message


PIPE_PREFIX = r"\\.\pipe\jr-broker-"
HANDSHAKE_SECONDS = 10.0
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008  # a dwPipeMode flag
PIPE_MODE = (win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE |
             win32pipe.PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS)
SECURITY_IDENTIFICATION_LEVEL = 1  # SECURITY_IMPERSONATION_LEVEL: SecurityIdentification


class PipeIdentityError(PermissionError):
    """The connecting account is not the configured client."""


def current_user_sid() -> str:
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    return win32security.ConvertSidToStringSid(
        win32security.GetTokenInformation(token, win32security.TokenUser)[0])


def string_sid(value, what: str = "SID") -> str:
    """Return `value` in canonical string form or raise ValueError."""
    if not isinstance(value, str) or not value.startswith("S-1-"):
        raise ValueError(f"{what} must be a string SID")
    try:
        return win32security.ConvertSidToStringSid(win32security.ConvertStringSidToSid(value))
    except pywintypes.error as exc:
        raise ValueError(f"{what} is not a valid SID") from exc


def client_token_sid(handle) -> str:
    """Return the string SID of the account that opened the client end of `handle`.

    Call it only after at least one message has been read from the client.
    Raises PipeIdentityError when the client cannot be identified.
    """
    try:
        win32security.ImpersonateNamedPipeClient(handle)
    except pywintypes.error as exc:
        raise PipeIdentityError("Pipe client could not be identified") from exc
    try:
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
        level = win32security.GetTokenInformation(token, win32security.TokenImpersonationLevel)
        if level < SECURITY_IDENTIFICATION_LEVEL:
            raise PipeIdentityError("Pipe client connected anonymously")
        return win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    except pywintypes.error as exc:
        raise PipeIdentityError("Pipe client token could not be read") from exc
    finally:
        win32security.RevertToSelf()


class _TimedConnection:
    """send_bytes/recv_bytes for the stdlib handshake, with a deadline on every read."""

    def __init__(self, connection, deadline: float):
        self._connection = connection
        self._deadline = deadline

    def send_bytes(self, data):
        self._connection.send_bytes(data)

    def recv_bytes(self, maxsize=None):
        wait_for_message(self._connection.fileno(), self._deadline)
        return self._connection.recv_bytes(maxsize)


class SecurePipeListener:
    def __init__(self, address, *, authkey: bytes, client_sid: str,
                 handshake_seconds: float = HANDSHAKE_SECONDS):
        if not isinstance(address, str) or not address.startswith(PIPE_PREFIX):
            raise ValueError("Unexpected Jr broker pipe name")
        if not isinstance(authkey, bytes) or len(authkey) != 32:
            raise ValueError("A 256-bit broker pipe key is required")
        if (isinstance(handshake_seconds, bool) or not isinstance(handshake_seconds, (int, float))
                or not 0 < handshake_seconds <= 120):
            raise ValueError("handshake_seconds must be between 0 and 120")
        self.client_sid = string_sid(client_sid, "The Jr service account SID")
        self.owner_sid = current_user_sid()
        self.handshake_seconds = float(handshake_seconds)
        # Deny remote-network tokens even if they carry an otherwise allowed
        # SID. No Everyone, Anonymous, SYSTEM or Administrators entry: only
        # the owner (needed for the server's own wake-up connection in
        # BrokerPipeServer.close, which the token check then refuses) and the
        # one configured client account can open the pipe at all.
        grants = "".join(f"(A;;GA;;;{sid})" for sid in dict.fromkeys((self.owner_sid, self.client_sid)))
        sddl = "D:P(D;;GA;;;NU)" + grants
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, win32security.SDDL_REVISION_1)
        self.attributes = pywintypes.SECURITY_ATTRIBUTES()
        self.attributes.SECURITY_DESCRIPTOR = descriptor
        self.address = address
        self.authkey = authkey
        self.next_handle = self._new(first=True)
        self.closed = False

    def _new(self, *, first=False):
        flags = win32pipe.PIPE_ACCESS_DUPLEX
        if first:
            flags |= win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE
        try:
            # Out buffer sized for the largest framed reply (advisory to the
            # pipe file system; the chunked framing in broker_ipc does not
            # depend on it), in buffer sized for the one-message request.
            return win32pipe.CreateNamedPipe(
                self.address, flags, PIPE_MODE,
                win32pipe.PIPE_UNLIMITED_INSTANCES, MAX_REPLY, MAX_MESSAGE, 1000,
                self.attributes)
        except pywintypes.error as exc:
            raise OSError(exc.winerror, "Jr broker pipe instance could not be created") from exc

    def accept(self):
        if self.closed:
            raise OSError("Jr broker pipe is closed")
        handle = self.next_handle
        self.next_handle = self._new()
        try:
            try:
                win32pipe.ConnectNamedPipe(handle, None)
            except pywintypes.error as exc:
                if exc.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise OSError(exc.winerror, "Jr broker pipe connect failed") from exc
            connection = PipeConnection(handle.Detach())
            try:
                timed = _TimedConnection(connection, time.monotonic() + self.handshake_seconds)
                deliver_challenge(timed, self.authkey)
                answer_challenge(timed, self.authkey)
                if client_token_sid(connection.fileno()) != self.client_sid:
                    raise PipeIdentityError("Pipe client is not the configured Jr service account")
                return connection
            except Exception:
                connection.close()
                raise
        finally:
            handle.Close()

    def close(self):
        self.closed = True
        self.next_handle.Close()


def listener_factory(client_sid: str, *, handshake_seconds: float = HANDSHAKE_SECONDS):
    """Return the listener_factory BrokerPipeServer takes, pinned to `client_sid`."""
    client_sid = string_sid(client_sid, "The Jr service account SID")

    def factory(address, authkey):
        return SecurePipeListener(address, authkey=authkey, client_sid=client_sid,
                                  handshake_seconds=handshake_seconds)

    return factory
