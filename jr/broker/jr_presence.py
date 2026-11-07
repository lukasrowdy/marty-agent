"""Presence for Jr's long lease: is the owner at this PC, or did the owner say so in chat?

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix item 4): comments only; the
owner's name is now "the owner" (no personal names in code).

NEW 2026-09-28 (Jr overnight build, item 1 "broker"). Decides which lease a
batch gets. The result is one of:

  "console"  the interactive console session is the broker's own account,
             active, unlocked, and not idle (see thresholds below)
  "grant"    a signed grant file under the grants folder is valid
  "none"     neither; the short lease with checkpoints applies

CONSOLE. What is provable and what is not:
  * Locked or unlocked is provable from software.
    WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session,
    WTSSessionInfoEx) returns WTSINFOEXW; with Level == 1,
    Data.WTSInfoExLevel1.SessionFlags is WTS_SESSIONSTATE_UNLOCK (1) or
    WTS_SESSIONSTATE_LOCK (0) or WTS_SESSIONSTATE_UNKNOWN (0xFFFFFFFF).
    Microsoft documents a code defect on Windows 7 and Windows Server 2008 R2
    (kernel 6.1) where the two values are reversed. This module inverts the
    reading on 6.1 only; Windows 8 (6.2) and later, including the Windows 11
    this runs on, report 1 = unlocked. Two cross-checks must agree, or the
    answer is "not proven": the input desktop opened with OpenInputDesktop
    must be named "Default" (the lock screen runs on the secure "Winlogon"
    desktop, which a normal process cannot open), and GetForegroundWindow
    must return a window. Any disagreement, missing value or API failure is
    "none". Fails closed.
  * "Present" is not provable. The skeptic's probe found the session unlocked
    with 68 minutes idle. So the idle time from GetLastInputInfo is required
    too: under APPROVE_MAX_IDLE (120 s) when a batch is approved and under
    POLL_MAX_IDLE (300 s) at every poll during a long lease. Idle time is
    ADVISORY: synthetic input (anything calling SendInput, including
    my-agent/hands) resets it. That is why a console presence is refused
    outright while a hands grant is active (hands/grant.json, written by
    hands.py grant): hands could otherwise type its way into a long lease.
    Only the lock state is unforgeable from software.
  * The console session must belong to the account the broker runs as: the
    active console session id (WTSGetActiveConsoleSessionId) must equal the
    broker's own session (ProcessIdToSessionId), its WTSConnectState must be
    WTSActive, and its WTSUserName/WTSDomainName must match the broker's
    GetUserNameEx(NameSamCompatible).

GRANT. A JSON file in the grants folder, HMAC-SHA256 signed with the key held
in Windows Credential Manager under GRANT_KEY_TARGET ("jr/grant-key"), read
through my-agent/tools/cred.py exactly as hands/hands.py reads its key. What
the signature proves, plainly: the file was written by a process running in
the broker account's logon session with access to that key. It does NOT
prove a human agreed. It blocks the Jr service account and every other
principal on the machine, which is its job; the human agreement is the owner's
words in chat, recorded in the grant's "quote" field and the append-only
audit log (audit.jsonl in the grants folder) by whoever issues it. Expired,
malformed, wrong-signature, oversize, future-dated grants, and grants longer
than MAX_GRANT_SECONDS (4 h) are refused and the refusal is logged (file
name and reason only; never the signature or the key). No key in the store
means no grant can ever be valid.

Nothing in this file prints, logs or stores the key or a signature.

CHANGED 2026-09-28 evening (fix helper, skeptic finding 9):
  * Nonce replay. The audit log binds each grant's nonce to the file name it
    was first seen under ("issued" and "accepted" rows now carry "nonce"; a
    nonce is signed content, not a secret). scan_grants refuses a grant
    whose nonce the log knows under a different file name, so a copy of a
    valid grant does not outlive the revocation (deletion) of its original.
    The log is read on every scan, bounded to its last MAX_AUDIT_SCAN_BYTES.
  * What console presence cannot detect, stated plainly: synthetic input
    from any automation other than hands.py is NOT detectable. The hands
    grant (hands/grant.json) is the only automation this module knows to
    refuse; anything else that calls SendInput (another agent, a macro
    tool, a remote-control session on the console) resets the idle clock
    and looks like a person. Only the lock state is unforgeable. For runs
    Marty drives, the grant path is preferred: it records the owner's
    words and it is auditable, where "console" only proves an unlocked,
    recently-touched session.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import sys
import time


GRANT_KEY_TARGET = "jr/grant-key"
GRANT_SCOPE = "long-lease"
GRANT_VERSION = 1
MAX_GRANT_SECONDS = 4 * 3600
MAX_GRANT_BYTES = 4096
FUTURE_SKEW_SECONDS = 60
APPROVE_MAX_IDLE = 120.0
POLL_MAX_IDLE = 300.0
AUDIT_NAME = "audit.jsonl"
MAX_AUDIT_SCAN_BYTES = 4 * 1024 * 1024
SIGNED_FIELDS = ("expires_at", "issued_at", "nonce", "quote", "scope", "version")

# WTS constants (wtsapi32.h)
WTS_CURRENT_SERVER_HANDLE = 0
WTSUserName = 5
WTSDomainName = 7
WTSConnectState = 8
WTSSessionInfoEx = 25
WTSActive = 0
WTS_SESSIONSTATE_UNKNOWN = 0xFFFFFFFF
WTS_SESSIONSTATE_LOCK = 0
WTS_SESSIONSTATE_UNLOCK = 1
NameSamCompatible = 2
DESKTOP_READOBJECTS = 0x0001
UOI_NAME = 2

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------- key (same pattern as hands/hands.py) ----------------

def _tools_dir():
    """my-agent/tools, found by walking up from this file, so a staged copy
    finds the same cred.py the live copy uses."""
    d = HERE
    for _ in range(5):
        d = os.path.dirname(d)
        cand = os.path.join(d, "tools")
        if os.path.isfile(os.path.join(cand, "cred.py")):
            return cand
    return os.path.join(os.path.dirname(HERE), "tools")


def _load_cred():
    tools = _tools_dir()
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        import cred  # noqa: E402  (tools/cred.py)
        return cred
    except BaseException:  # noqa: BLE001 - cred.py sys.exit()s off Windows; no store = no key
        return None


def read_grant_key(cred_module=None):
    """The signing secret as bytes, or None when the store has no jr/grant-key
    (or the store cannot be read). None means nothing can ever verify."""
    cred = _load_cred() if cred_module is None else cred_module
    if cred is None:
        return None
    try:
        value = cred.read(GRANT_KEY_TARGET)
    except Exception:  # noqa: BLE001 - a broken key store is a missing key, not a grant
        return None
    if not value or not str(value).strip():
        return None
    return str(value).strip().encode("utf-8")


# ---------------- grant file ----------------

def _canonical(row):
    return json.dumps({k: row[k] for k in SIGNED_FIELDS}, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sign_grant(key, row):
    return hmac.new(key, _canonical(row), hashlib.sha256).hexdigest()


def _finite_number(value):
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value))


def validate_grant(row, key, now, *, min_remaining=0.0):
    """(ok, reason). Every refusal reason is safe to log."""
    if key is None:
        return False, "no grant key in the store"
    if type(row) is not dict:
        return False, "not a JSON object"
    if set(row) != set(SIGNED_FIELDS) | {"sig"}:
        return False, "unexpected fields"
    if row["version"] != GRANT_VERSION:
        return False, "unknown version"
    if row["scope"] != GRANT_SCOPE:
        return False, "wrong scope"
    if not isinstance(row["nonce"], str) or not 16 <= len(row["nonce"]) <= 128:
        return False, "bad nonce"
    if not isinstance(row["quote"], str) or not 1 <= len(row["quote"]) <= 1000:
        return False, "missing quote"
    issued, expires = row["issued_at"], row["expires_at"]
    if not _finite_number(issued) or not _finite_number(expires):
        return False, "non-finite time"
    if issued > now + FUTURE_SKEW_SECONDS:
        return False, "future-dated"
    if expires <= issued:
        return False, "expires before issue"
    if expires - issued > MAX_GRANT_SECONDS:
        return False, "longer than 4 hours"
    if expires <= now:
        return False, "expired"
    if expires - now < min_remaining:
        return False, "too little time left for a long lease"
    sig = row["sig"]
    if not isinstance(sig, str) or len(sig) != 64:
        return False, "missing signature"
    try:
        expected = sign_grant(key, row)
    except (TypeError, ValueError):
        return False, "unsignable content"
    if not hmac.compare_digest(sig, expected):
        return False, "wrong signature"
    return True, "valid"


def _read_grant_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("not a regular file")
    if path.stat().st_size > MAX_GRANT_BYTES:
        raise ValueError("oversize")
    return json.loads(path.read_text(encoding="utf-8"))


def seen_nonces(grants_dir):
    """{nonce: file name} from the audit log's "issued" and "accepted" rows,
    the first name each nonce was seen under. Bounded to the log's last
    MAX_AUDIT_SCAN_BYTES; unreadable lines are skipped; no log, no names."""
    path = Path(grants_dir) / AUDIT_NAME
    try:
        if path.is_symlink() or not path.is_file():
            return {}
        with open(path, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - MAX_AUDIT_SCAN_BYTES))
            raw = stream.read()
    except OSError:
        return {}
    seen = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if (type(row) is not dict or row.get("event") not in {"issued", "accepted"} or
                not isinstance(row.get("nonce"), str) or not isinstance(row.get("file"), str)):
            continue
        seen.setdefault(row["nonce"], row["file"])
    return seen


def scan_grants(grants_dir, key, now, *, min_remaining=0.0, log=None):
    """The first valid grant (as (path, row)) or None. Every refused file is
    logged by name and reason. A grant whose nonce the audit log knows under
    another file name is a replay and is refused."""
    log = log or (lambda message: None)
    directory = Path(grants_dir)
    if not directory.is_dir():
        return None
    seen = None
    for path in sorted(directory.glob("*.json")):
        try:
            row = _read_grant_file(path)
        except (OSError, ValueError, UnicodeError) as exc:
            log(f"grant refused: {path.name}: {exc if isinstance(exc, ValueError) else 'unreadable'}")
            continue
        ok, reason = validate_grant(row, key, now, min_remaining=min_remaining)
        if ok:
            if seen is None:
                seen = seen_nonces(directory)
            first = seen.get(row["nonce"])
            if first is not None and first != path.name:
                reason = f"nonce replayed (first seen as {first})"
            else:
                return path, row
        log(f"grant refused: {path.name}: {reason}")
    return None


def audit(grants_dir, event):
    """Append-only record in the grants folder. Never carries a key or a sig."""
    row = {k: v for k, v in event.items() if k not in {"sig", "key"}}
    row.setdefault("at", time.time())
    row.setdefault("when", time.strftime("%Y-%m-%d %H:%M:%S"))
    directory = Path(grants_dir)
    directory.mkdir(parents=True, exist_ok=True)
    with open(directory / AUDIT_NAME, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, allow_nan=False) + "\n")


def issue_grant(grants_dir, key, *, hours, quote, now=None):
    """Write a signed grant. Only Marty calls this, on the owner's express words in
    chat, which go in `quote`. Returns the file path. Refuses without a key."""
    if key is None:
        raise ValueError("no grant key in the store; nothing granted")
    try:
        hours = float(hours)
    except (TypeError, ValueError) as exc:
        raise ValueError("hours must be a number") from exc
    if not math.isfinite(hours) or hours <= 0 or hours * 3600 > MAX_GRANT_SECONDS:
        raise ValueError("hours must be in (0, 4]")
    if not isinstance(quote, str) or not quote.strip():
        raise ValueError("the grant needs the owner's words in chat as its quote")
    now = time.time() if now is None else now
    row = {"version": GRANT_VERSION, "scope": GRANT_SCOPE, "issued_at": now,
           "expires_at": now + hours * 3600, "nonce": secrets.token_urlsafe(18),
           "quote": quote.strip()[:1000]}
    row["sig"] = sign_grant(key, row)
    directory = Path(grants_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"grant-{int(now)}-{row['nonce'][:8]}.json"
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(row, stream, allow_nan=False)
    audit(grants_dir, {"event": "issued", "file": path.name, "nonce": row["nonce"],
                       "issued_at": now, "expires_at": row["expires_at"], "quote": row["quote"]})
    return path


# ---------------- hands grant (blocks console presence) ----------------

def default_hands_grant_path():
    d = HERE
    for _ in range(5):
        d = os.path.dirname(d)
        cand = os.path.join(d, "hands", "grant.json")
        if os.path.isfile(os.path.join(d, "hands", "hands.py")):
            return cand
    return None


def hands_grant_active(path, now):
    """True when hands/grant.json looks live. Deliberately does not verify the
    hands signature: an unsigned or forged hands grant still means something
    on this PC may be injecting input, so it still blocks console presence."""
    if not path:
        return False
    try:
        with open(path, "r", encoding="utf-8") as stream:
            row = json.load(stream)
    except (OSError, ValueError):
        return False
    if type(row) is not dict:
        return False
    at, exp = row.get("granted_at"), row.get("expires_at")
    if not _finite_number(at) or not _finite_number(exp):
        return False
    return exp > now and at <= now + FUTURE_SKEW_SECONDS


# ---------------- console probe (Windows) ----------------

class _WTSINFOEX_LEVEL1(ctypes.Structure):
    _fields_ = [("SessionId", ctypes.c_uint32),
                ("SessionState", ctypes.c_int),
                ("SessionFlags", ctypes.c_int32),
                ("WinStationName", ctypes.c_wchar * 33),
                ("UserName", ctypes.c_wchar * 21),
                ("DomainName", ctypes.c_wchar * 18),
                ("LogonTime", ctypes.c_int64),
                ("ConnectTime", ctypes.c_int64),
                ("DisconnectTime", ctypes.c_int64),
                ("LastInputTime", ctypes.c_int64),
                ("CurrentTime", ctypes.c_int64),
                ("IncomingBytes", ctypes.c_uint32),
                ("OutgoingBytes", ctypes.c_uint32),
                ("IncomingFrames", ctypes.c_uint32),
                ("OutgoingFrames", ctypes.c_uint32),
                ("IncomingCompressedBytes", ctypes.c_uint32),
                ("OutgoingCompressedBytes", ctypes.c_uint32)]


class _WTSINFOEX_LEVEL(ctypes.Union):
    _fields_ = [("WTSInfoExLevel1", _WTSINFOEX_LEVEL1)]


class _WTSINFOEX(ctypes.Structure):
    _fields_ = [("Level", ctypes.c_uint32), ("Data", _WTSINFOEX_LEVEL)]


class _LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("dwTime", ctypes.c_uint32)]


def _wts_query(wtsapi32, session, info_class):
    buffer = ctypes.c_void_p()
    size = ctypes.c_uint32(0)
    if not wtsapi32.WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session,
                                                info_class, ctypes.byref(buffer),
                                                ctypes.byref(size)):
        return None, 0
    return buffer, size.value


def probe_console():
    """Raw facts about the console session, as a dict. Raises off Windows or
    when an API is unavailable; evaluate_console() turns None/absent into
    'not proven'. No field here is a secret."""
    if sys.platform != "win32":
        raise OSError("console presence needs Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    secur32 = ctypes.WinDLL("secur32", use_last_error=True)
    wtsapi32.WTSQuerySessionInformationW.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
    wtsapi32.WTSQuerySessionInformationW.restype = ctypes.c_int
    wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    kernel32.WTSGetActiveConsoleSessionId.restype = ctypes.c_uint32
    info = {"os_version": tuple(sys.getwindowsversion()[:2])}
    info["console_session"] = kernel32.WTSGetActiveConsoleSessionId()
    own = ctypes.c_uint32(0)
    if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(own)):
        info["own_session"] = own.value
    else:
        info["own_session"] = None
    # Own account as DOMAIN\user.
    size = ctypes.c_uint32(0)
    secur32.GetUserNameExW(NameSamCompatible, None, ctypes.byref(size))
    buf = ctypes.create_unicode_buffer(max(size.value, 1) + 1)
    size = ctypes.c_uint32(len(buf))
    info["own_user"] = (buf.value.lower()
                        if secur32.GetUserNameExW(NameSamCompatible, buf, ctypes.byref(size))
                        else None)
    session = info["console_session"]
    if session == WTS_SESSIONSTATE_UNKNOWN:
        info.update(console_user=None, connect_state=None, session_flags=None, level=None)
    else:
        parts = []
        for info_class in (WTSDomainName, WTSUserName):
            buffer, _ = _wts_query(wtsapi32, session, info_class)
            if buffer:
                parts.append(ctypes.wstring_at(buffer))
                wtsapi32.WTSFreeMemory(buffer)
            else:
                parts.append(None)
        info["console_user"] = (f"{parts[0]}\\{parts[1]}".lower()
                                if parts[0] is not None and parts[1] is not None else None)
        buffer, _ = _wts_query(wtsapi32, session, WTSConnectState)
        if buffer:
            info["connect_state"] = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_int)).contents.value
            wtsapi32.WTSFreeMemory(buffer)
        else:
            info["connect_state"] = None
        buffer, size_bytes = _wts_query(wtsapi32, session, WTSSessionInfoEx)
        if buffer and size_bytes >= ctypes.sizeof(_WTSINFOEX):
            ex = ctypes.cast(buffer, ctypes.POINTER(_WTSINFOEX)).contents
            info["level"] = ex.Level
            info["session_flags"] = (ex.Data.WTSInfoExLevel1.SessionFlags & 0xFFFFFFFF
                                     if ex.Level == 1 else None)
        else:
            info["level"], info["session_flags"] = None, None
        if buffer:
            wtsapi32.WTSFreeMemory(buffer)
    # Cross-check 1: the input desktop's name.
    user32.OpenInputDesktop.restype = ctypes.c_void_p
    user32.GetUserObjectInformationW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                                 ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    user32.CloseDesktop.argtypes = [ctypes.c_void_p]
    desk = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
    info["desktop"] = None
    if desk:
        try:
            name = ctypes.create_unicode_buffer(256)
            needed = ctypes.c_uint32(0)
            if user32.GetUserObjectInformationW(desk, UOI_NAME, name, ctypes.sizeof(name),
                                                ctypes.byref(needed)):
                info["desktop"] = name.value
        finally:
            user32.CloseDesktop(desk)
    # Cross-check 2: a foreground window exists.
    user32.GetForegroundWindow.restype = ctypes.c_void_p
    info["foreground"] = bool(user32.GetForegroundWindow())
    # Idle time in this session (advisory).
    last = _LASTINPUTINFO()
    last.cbSize = ctypes.sizeof(_LASTINPUTINFO)
    if user32.GetLastInputInfo(ctypes.byref(last)):
        tick = kernel32.GetTickCount() & 0xFFFFFFFF
        info["idle_seconds"] = ((tick - last.dwTime) & 0xFFFFFFFF) / 1000.0
    else:
        info["idle_seconds"] = None
    return info


def unlocked_from_flags(session_flags, os_version):
    """Apply the documented 6.1 inversion. Returns True/False, or None when the
    flag is unknown."""
    if session_flags is None or session_flags == WTS_SESSIONSTATE_UNKNOWN:
        return None
    inverted = tuple(os_version or ()) == (6, 1)
    if session_flags == WTS_SESSIONSTATE_UNLOCK:
        return not inverted
    if session_flags == WTS_SESSIONSTATE_LOCK:
        return inverted
    return None


def evaluate_console(info, *, max_idle_seconds, hands_grant_active=False):
    """Pure decision over probe_console()'s dict. (ok, reason); every reason is
    safe to log. Anything missing or contradictory is not proven -> False."""
    if hands_grant_active:
        return False, "hands grant active; synthetic input could spoof presence"
    if type(info) is not dict:
        return False, "console probe unavailable"
    if info.get("console_session") in (None, WTS_SESSIONSTATE_UNKNOWN):
        return False, "no active console session"
    if info.get("own_session") is None or info["console_session"] != info["own_session"]:
        return False, "broker is not running in the console session"
    if not info.get("own_user") or not info.get("console_user"):
        return False, "session account unknown"
    if info["own_user"] != info["console_user"]:
        return False, "console session belongs to another account"
    if info.get("connect_state") != WTSActive:
        return False, "console session is not active"
    unlocked = unlocked_from_flags(info.get("session_flags"), info.get("os_version"))
    if unlocked is None:
        return False, "lock state unknown"
    if not unlocked:
        return False, "session is locked"
    if info.get("desktop") != "Default":
        return False, "input desktop is not Default (lock screen or secure desktop)"
    if not info.get("foreground"):
        return False, "no foreground window"
    idle = info.get("idle_seconds")
    if not _finite_number(idle) or idle < 0:
        return False, "idle time unknown"
    if idle > max_idle_seconds:
        return False, f"idle {idle:.0f}s exceeds {max_idle_seconds:.0f}s"
    return True, "console present"


# ---------------- the decision ----------------

class Presence:
    """Callable(stage) -> "console" | "grant" | "none". stage is "approve"
    (strict idle threshold, grant must cover the whole long lease) or "poll"
    (re-check during a long lease). Every input is injectable for tests."""

    def __init__(self, *, grants_dir, key_reader=read_grant_key, console_probe=probe_console,
                 hands_grant_path=None, clock=time.time, log=None,
                 long_lease_seconds=290.0, audit_grants=True):
        self.grants_dir = grants_dir
        self.key_reader = key_reader
        self.console_probe = console_probe
        self.hands_grant_path = hands_grant_path
        self.clock = clock
        self.log = log or (lambda message: None)
        self.long_lease_seconds = float(long_lease_seconds)
        self.audit_grants = audit_grants
        self.last_reason = None

    def _console(self, stage, now):
        max_idle = APPROVE_MAX_IDLE if stage == "approve" else POLL_MAX_IDLE
        hands = hands_grant_active(self.hands_grant_path, now)
        try:
            info = self.console_probe()
        except Exception:  # noqa: BLE001 - not provable is "none"
            info = None
        ok, reason = evaluate_console(info, max_idle_seconds=max_idle, hands_grant_active=hands)
        return ok, reason

    def _grant(self, stage, now):
        key = self.key_reader()
        if key is None:
            return None, "no grant key in the store; grant presence impossible"
        minimum = self.long_lease_seconds if stage == "approve" else 0.0
        found = scan_grants(self.grants_dir, key, now, min_remaining=minimum, log=self.log)
        if found is None:
            return None, "no valid grant"
        return found, "valid grant"

    def __call__(self, stage):
        if stage not in {"approve", "poll"}:
            stage = "approve"
        now = self.clock()
        ok, reason = self._console(stage, now)
        if ok:
            self.last_reason = reason
            return "console"
        self.log(f"console presence not proven ({stage}): {reason}")
        found, reason = self._grant(stage, now)
        if found is not None:
            path, row = found
            self.last_reason = reason
            if self.audit_grants and stage == "approve":
                try:
                    audit(self.grants_dir, {"event": "accepted", "file": path.name,
                                            "nonce": row["nonce"],
                                            "expires_at": row["expires_at"], "stage": stage})
                except OSError:
                    pass
            return "grant"
        self.log(f"grant presence not proven ({stage}): {reason}")
        self.last_reason = reason
        return "none"


def main(argv):
    """`probe` prints the raw console facts and the decision (no secrets).
    `issue --dir D --hours H --quote "..."` writes a grant; Marty only, on
    the owner's express words, never from a helper or a scheduled task."""
    if not argv or argv[0] not in {"probe", "issue"}:
        print(__doc__)
        return 2
    if argv[0] == "probe":
        try:
            info = probe_console()
        except Exception as exc:  # noqa: BLE001
            print(f"probe failed: {exc}")
            return 1
        ok, reason = evaluate_console(info, max_idle_seconds=APPROVE_MAX_IDLE,
                                      hands_grant_active=hands_grant_active(
                                          default_hands_grant_path(), time.time()))
        for key in sorted(info):
            print(f"  {key}: {info[key]}")
        print(f"console presence: {ok} ({reason})")
        return 0
    import argparse
    parser = argparse.ArgumentParser(prog="jr_presence issue")
    parser.add_argument("issue")
    parser.add_argument("--dir", required=True)
    parser.add_argument("--hours", required=True)
    parser.add_argument("--quote", required=True)
    args = parser.parse_args(argv)
    try:
        path = issue_grant(args.dir, read_grant_key(), hours=args.hours, quote=args.quote)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"grant written: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
