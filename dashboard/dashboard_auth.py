"""
Marty Status Dashboard - device-token authentication.

Same pattern already proven on marty-portal (portal_auth.py) and channel's
store.py before it: per-device bearer tokens, shown exactly once at
enrollment, only a SHA-256 hash kept at rest. A lost token is not
recoverable; revoke the device and enroll again.

Why this exists: when it was written (2026-09-20) the dashboard bound
0.0.0.0 with no auth at all, so the Overview tab, the Chat tab (which
spends real Claude API dollars per message), and the Spend tab were all
readable and usable by anything on the home network. Exactly the pattern
channel/DESIGN.md and the marty-portal pre-auth incident both name as the
one not to repeat. Since 2026-09-21 the server binds loopback and is
reached only over HTTPS on the tailnet; the gate stays because the tailnet
has more than one person on it.

Two ways to present a token, both resolving through the same check:
  Authorization: Bearer <token>    scripts, curl, anything not a browser
  Cookie: dashboard_session=<token>  set by POST /api/session after the
                                     login screen; HttpOnly so page JS
                                     cannot read it, SameSite=Lax so it is
                                     not sent on cross-site requests.

The plain-HTTP-on-the-LAN risk this docstring used to carry is closed as
of 2026-09-21: the server no longer listens on the LAN, and the only route
in is TLS terminated by `tailscale serve` with a real certificate. One
thing that follows: the HTTPS name is a new origin to a browser, so a
device that logged in over the old LAN address needs a fresh token.

Device logins END on the server (2026-09-26, the lost-phone gap a skeptic
found: tokens never expired, the cookie lived a year, and a lost unlocked
phone kept the chat lane's read tools indefinitely):
  * IDLE_DAYS (30) without use, counted from the last use (last_seen_at),
    or from enrollment for a token never used; and
  * MAX_AGE_DAYS (90) after enrollment, however much it is used, so a
    copied token that someone keeps using still dies.
Checked in resolve(), the one function every cookie AND every bearer token
goes through, on every request. Nothing is written for an ended login (no
last-seen bump), so use can never revive it. Expiry is computed, never
stored: an ended row is not "revoked". That matters for passkeys.py, which
refuses a passkey whose PARENT device is revoked; an expired parent keeps
its passkey working, so the fingerprint stays a way back in. Revocation is
unchanged and still instant (the file is read on every request).
Getting back in after a login ends: "Sign in with passkey" on the lock
screen (mints a fresh device login), or a new QR from the PC
(`setup_dashboard_auth.py enroll lukas "S25" --qr`). Both start a new
90-day clock. The session cookie's Max-Age matches MAX_AGE_DAYS.
"""

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from pathlib import Path

ROOT = Path(os.environ.get("DASHBOARD_ROOT", os.path.dirname(os.path.abspath(__file__))))
DEVICES_PATH = ROOT / "dashboard-devices.jsonl"
LOCK_PATH = ROOT / "dashboard-devices.lock"
COOKIE_NAME = "dashboard_session"
HANDLES = ("lukas",)

IDLE_DAYS = 30        # a device login ends after this many days without use
MAX_AGE_DAYS = 90     # and this many days after it was made, used or not
SESSION_MAX_AGE_SEC = MAX_AGE_DAYS * 86400   # the cookie never outlives the login it carries

_lock = threading.RLock()  # threads in this process (re-entrant); _file_lock covers other processes
_held = threading.local()  # per-thread nesting depth of _file_lock


@contextlib.contextmanager
def _file_lock(timeout: float = 5.0):
    """Cross-process lock around every read-modify-write of the devices file.

    Why (2026-09-25, skeptic): _lock only covers the server's own threads. The CLI
    (setup_dashboard_auth.py) and passkeys.py run in other processes, and the server's
    last-seen rewrite could read the file, lose a CLI revoke or enroll that landed in
    between, and write the old rows back. Hold this for read AND write, never just the
    write. Raises TimeoutError if another process holds it past `timeout`.

    Re-entrant within a thread: a nested use (say enroll() called by code that already
    holds the lock) only bumps a thread-local depth. Without that, the inner call would
    open a second handle, fail to lock the byte its own thread holds, spin to the timeout
    and raise. Other threads still wait: the OS lock is taken once per outermost use."""
    depth = getattr(_held, "depth", 0)
    if depth:
        _held.depth = depth + 1
        try:
            yield
        finally:
            _held.depth -= 1
        return
    ROOT.mkdir(parents=True, exist_ok=True)
    fh = open(LOCK_PATH, "a+b")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError("the devices file is locked by another process")
                time.sleep(0.02)
        _held.depth = 1
        try:
            yield
        finally:
            _held.depth = 0
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _read_rows():
    if not DEVICES_PATH.exists():
        return []
    rows = []
    with DEVICES_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def _write_rows(rows):
    """Call only while holding _file_lock. On Windows os.replace fails with
    PermissionError while ANY other handle has the file open, so readers take the lock
    too, and a stray reader outside it gets a short retry rather than a lost write."""
    tmp = DEVICES_PATH.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    for attempt in range(20):
        try:
            os.replace(tmp, DEVICES_PATH)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.025)


def _read_rows_locked(timeout: float = 2.0):
    """A consistent read that also keeps readers from blocking another process's rename."""
    try:
        with _file_lock(timeout=timeout):
            return _read_rows()
    except TimeoutError:
        return _read_rows()   # never refuse a read because another process is slow


def enroll(handle: str, label: str | None = None) -> str:
    """Create a device and return its raw token. Shown once, never stored."""
    if handle not in HANDLES:
        raise ValueError("handle must be one of: " + ", ".join(HANDLES))
    token = secrets.token_urlsafe(32)
    ROOT.mkdir(parents=True, exist_ok=True)
    with _lock, _file_lock():
        rows = _read_rows()
        next_id = max((r.get("id", 0) for r in rows), default=0) + 1
        rows.append({
            "id": next_id,
            "handle": handle,
            "label": label or "",
            "token_sha256": _hash(token),
            "created_at": _now(),
            "last_seen_at": None,
            "revoked_at": None,
        })
        _write_rows(rows)
    return token


def revoke(device_id: int) -> bool:
    with _lock, _file_lock():
        rows = _read_rows()
        hit = False
        for r in rows:
            if r.get("id") == device_id and not r.get("revoked_at"):
                r["revoked_at"] = _now()
                hit = True
        if hit:
            _write_rows(rows)
        return hit


def list_devices():
    return _read_rows_locked()


LAST_SEEN_DEBOUNCE_SEC = 60


CLOCK_SKEW = timedelta(minutes=5)   # how far in the future a stored time may be before it is not believed


def _parse_time(iso):
    """An aware UTC datetime from a stored timestamp, or None if it cannot be read. A time
    written without a zone (naive) is taken as UTC, so it can never raise in a comparison."""
    if not iso or not isinstance(iso, str):
        return None
    try:
        then = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return then if then.tzinfo is not None else then.replace(tzinfo=timezone.utc)


def _older_than(iso: str | None, seconds: int) -> bool:
    """True when the stored time is more than `seconds` ago, unreadable, or implausibly in the
    future (then the next use rewrites it to now). Parses through _parse_time: a naive stamp
    used to raise TypeError here and fail the whole request (skeptic, 2026-09-26)."""
    then = _parse_time(iso)
    if then is None:
        return True
    now = datetime.now(timezone.utc)
    if then - now > CLOCK_SKEW:
        return True
    return (now - then).total_seconds() > seconds


def _last_use(row, born, now):
    """The later of enrollment and last use. A last-use stamp from the future is not believed
    (enrollment counts instead); _older_than makes the next use overwrite it."""
    seen = _parse_time(row.get("last_seen_at"))
    if seen is None or seen - now > CLOCK_SKEW:
        return born
    return max(born, seen)


def expiry(row, now=None) -> str | None:
    """None while a device login is current, else why it ended: "age" (MAX_AGE_DAYS since
    it was made) or "idle" (IDLE_DAYS since it was last used; since it was made if it never
    was). Fail closed: a row whose created_at cannot be read, or lies more than CLOCK_SKEW in
    the future, has ended ("age"); a passkey sign-in or a new enrollment on the PC still gets
    Lukas back in, since both make a fresh row. Revocation is separate (revoked_at) and is
    checked before this."""
    now = now or datetime.now(timezone.utc)
    born = _parse_time(row.get("created_at"))
    if born is None or born - now > CLOCK_SKEW:
        return "age"
    if now - born > timedelta(days=MAX_AGE_DAYS):
        return "age"
    if now - _last_use(row, born, now) > timedelta(days=IDLE_DAYS):
        return "idle"
    return None


def ends_at(row) -> str | None:
    """When a current device login ends if it is not used again (ISO, UTC), or None if it is
    revoked, has already ended, or cannot be read. Use pushes the idle end out; never the
    90-day one."""
    if row.get("revoked_at"):
        return None
    now = datetime.now(timezone.utc)
    born = _parse_time(row.get("created_at"))
    if born is None or expiry(row, now) is not None:
        return None
    end = min(born + timedelta(days=MAX_AGE_DAYS), _last_use(row, born, now) + timedelta(days=IDLE_DAYS))
    return end.isoformat(timespec="seconds")


def device_state(row) -> str:
    """One word or two for listings: active | revoked | expired (idle) | expired (90 days)."""
    if row.get("revoked_at"):
        return "revoked"
    why = expiry(row)
    if why == "idle":
        return "expired (idle)"
    if why == "age":
        return "expired (90 days)"
    return "active"


def resolve_detail(token: str | None):
    """(handle, None) for a live token. (None, "idle" | "age") for a real device login that
    has ended (see expiry()); the server's 401 says so, so the page can tell Lukas to sign
    in again. (None, None) for everything else: missing, junk, unknown or revoked. Never
    raises on junk input. An ended login gets no last-seen write, so use cannot revive it.

    last_seen_at is rewritten at most once per LAST_SEEN_DEBOUNCE_SEC per device, and
    the rewrite can never fail the request. Until 2026-09-22 every authenticated
    request rewrote dashboard-devices.jsonl, and os.replace raises PermissionError on
    Windows when any other handle has the file open (reproduced), which killed the
    request with no response. Harmless at a few requests a minute; chunked uploads
    multiply that by ~128 per GB, so the window had to close."""
    if not token or not isinstance(token, str):
        return None, None
    token = "".join(token.split())
    if not token:
        return None, None
    digest = _hash(token)
    with _lock:
        # Read and the last-seen rewrite happen under the cross-process lock, so the rewrite
        # can never undo a revoke or enroll another process made in between, and this read
        # never holds the file open while another process renames over it.
        try:
            with _file_lock(timeout=2.0):
                rows = _read_rows()
                match = _match(rows, digest)
                if match is None:
                    return None, None
                ended = expiry(match)
                if ended:
                    return None, ended
                if _older_than(match.get("last_seen_at"), LAST_SEEN_DEBOUNCE_SEC):
                    match["last_seen_at"] = _now()
                    try:
                        _write_rows(rows)
                    except OSError:
                        pass    # a valid token stays valid even if the bookkeeping write lost a race
                return match.get("handle"), None
        except TimeoutError:
            match = _match(_read_rows(), digest)   # lock busy: answer, skip the bookkeeping
            if match is None:
                return None, None
            ended = expiry(match)                   # the same expiry rule on this path too
            return (None, ended) if ended else (match.get("handle"), None)


def resolve(token: str | None) -> str | None:
    """Return the handle for a live token, or None (unknown, revoked or ended)."""
    return resolve_detail(token)[0]


def _match(rows, digest):
    for r in rows:
        if r.get("revoked_at"):
            continue
        if hmac.compare_digest(r.get("token_sha256") or "", digest):
            return r
    return None


def any_enrolled() -> bool:
    return any(not r.get("revoked_at") for r in _read_rows_locked())


# --- request helpers -----------------------------------------------------

def token_from_headers(headers) -> str | None:
    auth = headers.get("Authorization", "") or ""
    if auth.startswith("Bearer "):
        candidate = auth[7:].strip()
        if candidate:
            return candidate
    raw = headers.get("Cookie", "") or ""
    if raw:
        try:
            jar = SimpleCookie()
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(COOKIE_NAME)
        if morsel and morsel.value:
            return morsel.value
    return None


def authenticate(headers) -> str | None:
    """The single chokepoint. Returns the caller's handle, or None."""
    return resolve(token_from_headers(headers))


def authenticate_detail(headers):
    """authenticate(), plus why a real device login was refused: (handle, None) or
    (None, "idle" | "age" | None). Bearer and cookie go through the same resolve_detail()."""
    return resolve_detail(token_from_headers(headers))


def session_cookie(token: str) -> str:
    # Secure since 2026-09-22: the only route in is HTTPS via tailscale serve, and
    # Chrome treats http://127.0.0.1 as a secure context so loopback logins still work.
    # Max-Age was a year until 2026-09-26; it now matches the server-side MAX_AGE_DAYS, which
    # is what actually ends the login (the cookie's own lifetime is only tidiness).
    return (
        f"{COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_MAX_AGE_SEC}"
    )


def clear_cookie() -> str:
    return f"{COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
