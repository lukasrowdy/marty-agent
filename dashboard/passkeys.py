"""
Marty Status Dashboard - passkey (WebAuthn) sign-in. MJ Dashboard Phase 2, W5.

A fingerprint (S25, Google Password Manager) or Windows Hello sign-in beside the
device token. It adds no new kind of session. The dashboard has exactly one: a
device token in the dashboard_session cookie (dashboard_auth.py), stored at rest
only as a SHA-256 hash, so an existing token can never be handed back out. A
passkey login therefore MINTS a fresh device token with dashboard_auth.enroll()
and the server sets it with dashboard_auth.session_cookie(), exactly as POST
/api/session does. Everything that works on device rows keeps working on these:
resolve(), revoke(), `py setup_dashboard_auth.py devices | revoke <id>`.

Trust chain (who can do what):
  * A passkey can only be registered from a signed-in device session. It records
    that device as its parent (`device_id`). A session that was itself minted by a
    passkey resolves to that passkey's parent, so parents are always real devices.
  * Revoke the parent device and the passkey dies with it: login is refused at
    once, and the sessions it minted are revoked by the next reconcile
    (maybe_reconcile() runs at most once a minute from the server's auth check).
  * Revoke the passkey (`passkeys.py revoke <id>`) and every session it minted
    is revoked with it.
  * Logging out of a passkey-minted session revokes that device row (on_logout);
    a device-token session is left alone, exactly as today.
  * At most MAX_SESSIONS_PER_PASSKEY live minted sessions per passkey; the oldest
    is revoked past that, so rows cannot pile up when a browser drops its cookie.
  * Every revoke is confirmed by re-reading the devices file and retried
    (_revoke_device); one that never sticks is logged to stderr and parked in
    the row's pending_revoke for reconcile to retry. reconcile() also retires any
    live device labelled "passkey N:" that passkey N does not track (a login whose
    store write failed, a passkey revoked or missing), so no session is orphaned.

CSRF: the four passkey POST routes call origin_ok(headers) first and refuse any
request whose Origin header is not exactly the dashboard's origin. There is no
public status route: the login page decides from the browser and the hostname.

Ceremony rules: rpId {{TAILNET_HOST}}, origin
https://{{TAILNET_HOST}}, userVerification required on both ceremonies,
registration: security key only (cross-platform, resident key discouraged, hint
security-key; 2026-09-30), attestation none, algorithms ES256 / EdDSA / RS256 (Google
Password Manager and Windows Hello). Challenges are 32 random bytes held in memory
for 5 minutes, single use (removed by the first verify, pass or fail), bound to
their purpose and, for registration, to the device session that asked. A sign
count that does not rise, when either side is nonzero, is refused. Login is rate
limited per client IP and in total. crossOrigin (an iframe) is refused.

Storage, beside dashboard-devices.jsonl (DASHBOARD_ROOT, same as dashboard_auth):
  passkeys.jsonl       one row per credential: id, public key (COSE), alg, sign
                       count, transports, label, created/last used, parent device
                       id, minted session ids, revoked_at. Public material only.
  passkeys-user.json   the one random 32-byte user.id (a copy rides on each row).
Every read-modify-write of either file, in the server or the CLI, holds _store_lock: this
process's _lock plus dashboard_auth's cross-process file lock (dashboard-devices.lock), so
the server and the CLI can no longer overwrite each other's rows, and each process writes
its own temp file (passkeys.jsonl.<pid>.tmp). Added 2026-09-28 after the outside audit.
user.name and displayName are the neutral "lukas-dashboard": Google Password
Manager stores those outside its end-to-end encryption.

Fail soft: webauthn is installed only in dashboard/.venv. Under plain system Python
the import fails, available() is False, status() says so, and every ceremony raises
PasskeyError(503). The server hides the passkey UI and nothing else changes.

CLI (run with dashboard/.venv/Scripts/python.exe):
  passkeys.py check          is webauthn importable here, and what is registered
  passkeys.py list           every passkey, active and revoked
  passkeys.py revoke <id>    revoke one passkey and every session it minted; re-reads
                             and re-applies until it sticks (the server may be writing)
  passkeys.py reconcile      revoke sessions whose passkey or parent device is revoked
"""

import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

import dashboard_auth
import fullmarty_stepup   # Full Marty step-up rules (Stage B pick 6), stdlib, copied next to this file

try:
    import webauthn
    from webauthn.helpers import decode_credential_public_key, options_to_json
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AuthenticatorAttachment,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    _IMPORT_ERROR = None
except Exception as _exc:   # ImportError under system Python; any other breakage is also "unavailable"
    webauthn = None
    _IMPORT_ERROR = "%s: %s" % (type(_exc).__name__, _exc)

PROD_RP_ID = "{{TAILNET_HOST}}"
PROD_ORIGIN = "https://" + PROD_RP_ID
JARVIS_ORIGIN = PROD_ORIGIN + ":10443"   # the Marty Jarvis page; same host, same rpId, extra port
RP_NAME = "Marty"
USER_NAME = "lukas-dashboard"          # also the displayName; deliberately nothing personal
HANDLE = "lukas"                       # the dashboard_auth handle a passkey session carries

CHALLENGE_TTL_SEC = 300
CEREMONY_TIMEOUT_MS = 120_000          # browser hint; ends well inside the challenge TTL
MAX_PENDING_CHALLENGES = 256
RATE_WINDOW_SEC = 600
LOGIN_LIMIT_PER_IP = 10                # /login/verify attempts per IP per window, pass or fail
LOGIN_LIMIT_TOTAL = 30                 # all IPs together, a backstop if the IP is ever wrong
OPTIONS_LIMIT_PER_IP = 30              # /login/options per IP per window (bounds the challenge store)
MAX_SESSIONS_PER_PASSKEY = 5
MAX_PASSKEYS = 20
RECONCILE_EVERY_SEC = 60
LABEL_MAX = 60
REVOKE_TRIES = 5                       # _revoke_device: tries, each confirmed by a re-read
SESSION_LABEL_RE = re.compile(r"^passkey (\d+): ")   # the label every minted device row carries

ROOT = dashboard_auth.ROOT
PASSKEYS_PATH = ROOT / "passkeys.jsonl"
USER_PATH = ROOT / "passkeys-user.json"

KNOWN_TRANSPORTS = {"usb", "nfc", "ble", "internal", "hybrid", "cable", "smart-card"}
# Only for a friendlier default label. An unknown or zeroed AAGUID just reads "Passkey".
KNOWN_AAGUIDS = {
    "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
    "53414d53-554e-4700-0000-000000000000": "Samsung Pass",
}

_config = {"rp_id": PROD_RP_ID, "origin": PROD_ORIGIN, "test": False,
           "extra_origins": (JARVIS_ORIGIN,)}   # other ports of the same host allowed to run ceremonies
_clock = time.monotonic                # tests replace this to age challenges and rate windows
_sleep = time.sleep                    # retry pauses; tests replace this
_lock = threading.RLock()              # this process's threads; _store_lock adds the other processes
_ch_lock = threading.Lock()
_challenges = {}                       # b64url challenge -> {"purpose", "expires", "device_id"}
_reconcile_lock = threading.Lock()
_last_reconcile = [None]


class PasskeyError(Exception):
    """status: the HTTP status to answer with. public: the response body's error text
    (login failures are deliberately generic). code: a short reason for tests and
    logs. retry_after: seconds, set on 429 only."""

    def __init__(self, status, code, public, retry_after=None):
        super().__init__("%s [%s]" % (public, code))
        self.status = status
        self.code = code
        self.public = public
        self.retry_after = retry_after


LOGIN_REFUSED = "That passkey was not accepted."
STORE_BUSY = "The passkey store is busy; try again."


@contextlib.contextmanager
def _store_lock(timeout: float = 5.0):
    """Every read-modify-write of passkeys.jsonl and passkeys-user.json runs inside this.

    Why (2026-09-28, the outside audit): _lock only covers this process's threads. The CLI
    (`passkeys.py revoke | reconcile`) runs in another process beside the server, and the
    server's own login or reconcile could read the store, lose the CLI's revoke that landed in
    between, and write the old rows back; both also wrote the same passkeys.jsonl.tmp. This
    holds dashboard_auth's cross-process lock (dashboard-devices.lock, byte 0) for the read AND
    the write. One lock for both stores on purpose: every passkey write also touches device rows
    (dashboard_auth.enroll / revoke / list_devices), so under one lock the pair changes as a unit.

    Lock order, always: _lock, then dashboard_auth._lock, then the file lock. dashboard_auth's own
    paths take its _lock before the file lock, so a thread that holds the file lock always holds
    dashboard_auth._lock too, and no thread in this process can wait on the file lock behind
    another thread here (only behind another process). Re-entrant: nested dashboard_auth calls
    and nested _store_lock uses only bump the per-thread depth. Another process holding it past
    `timeout` is answered with PasskeyError 503 store_busy, never a bare TimeoutError."""
    with _lock, dashboard_auth._lock:
        try:
            with dashboard_auth._file_lock(timeout=timeout):
                yield
        except TimeoutError as exc:
            raise PasskeyError(503, "store_busy", STORE_BUSY) from exc


# --- configuration -------------------------------------------------------

def available() -> bool:
    return webauthn is not None


def rp_id() -> str:
    return _config["rp_id"]


def expected_origin() -> str:
    return _config["origin"]


def expected_origins() -> list:
    """Every origin allowed to run a ceremony: the dashboard origin first, then the
    extra ports of the same host (the Marty Jarvis page on :10443). Test mode clears
    the extras, so a loopback test origin never widens to anything else."""
    return [_config["origin"], *_config.get("extra_origins", ())]


_TEST_ORIGIN_RE = re.compile(r"^https?://localhost:(\d{1,5})$")


def use_test_origin(origin: str) -> None:
    """Tests only: run the ceremonies against a loopback origin with rpId "localhost".
    Refuses anything but http(s)://localhost:<port>, so it can never widen the
    production origin. The server never calls it."""
    m = _TEST_ORIGIN_RE.match(origin or "")
    if not m or not 0 < int(m.group(1)) < 65536:
        raise ValueError("test origin must be http(s)://localhost:<port>")
    _config.update(rp_id="localhost", origin=origin, test=True, extra_origins=())


def use_production_origin() -> None:
    _config.update(rp_id=PROD_RP_ID, origin=PROD_ORIGIN, test=False, extra_origins=(JARVIS_ORIGIN,))


def _algs():
    return [COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.EDDSA,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256]


def _require_available():
    if webauthn is None:
        raise PasskeyError(503, "unavailable", "Passkey sign-in is not available on this server.")


# --- small helpers -------------------------------------------------------

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(text) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", text):
        raise ValueError("not base64url")
    text = text.rstrip("=")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _log(message):
    """stderr only (the supervisor keeps it in dashboard.err.log). Never a token or a body."""
    try:
        print("[passkey] " + message, file=sys.stderr, flush=True)
    except Exception:
        pass


def _clean_label(value, fallback):
    text = value if isinstance(value, str) else ""
    text = " ".join("".join(ch for ch in text if ch.isprintable()).split())[:LABEL_MAX]
    return text or fallback[:LABEL_MAX]


# --- storage -------------------------------------------------------------

def _read_rows():
    if not PASSKEYS_PATH.exists():
        return []
    rows = []
    with PASSKEYS_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def _read_rows_locked(timeout: float = 2.0):
    """A read that waits for a writer in another process (so it never sees a half-renamed file and
    never holds the file open across that process's os.replace); if the lock stays busy, a plain
    read, as dashboard_auth does: a read is never refused because another process is slow."""
    try:
        with _store_lock(timeout=timeout):
            return _read_rows()
    except PasskeyError:
        return _read_rows()


def _atomic_write(path, text):
    """Call only while holding _store_lock. The temp file's name carries this process's id: the old
    shared passkeys.jsonl.tmp let the server and the CLI write into one file at once."""
    ROOT.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("%s.%d.tmp" % (path.name, os.getpid()))
    last = None
    for attempt in range(4):   # Windows: os.replace fails while another handle has the file open
        try:
            with tmp.open("w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)
            return
        except OSError as exc:
            last = exc
            _sleep(0.05 * (attempt + 1))
    try:
        tmp.unlink()
    except OSError:
        pass
    raise PasskeyError(503, "store_busy", STORE_BUSY) from last


def _write_rows(rows):
    _atomic_write(PASSKEYS_PATH, "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))


def _user_id() -> bytes:
    """The one persistent user.id. Created on first use; if the file is lost, recovered
    from the newest passkey row so existing passkeys keep matching."""
    with _store_lock():
        try:
            data = json.loads(USER_PATH.read_text(encoding="utf-8"))
            uid = _unb64u(data.get("user_id"))
            if len(uid) == 32:
                return uid
            raise ValueError("wrong length")
        except FileNotFoundError:
            pass
        except (ValueError, TypeError, AttributeError):
            raise PasskeyError(503, "user_file", "passkeys-user.json is damaged; fix or remove it.")
        recovered = [r.get("user_id") for r in _read_rows() if r.get("user_id")]
        uid = _unb64u(recovered[-1]) if recovered else secrets.token_bytes(32)
        _atomic_write(USER_PATH, json.dumps({"user_id": _b64u(uid), "created_at": _now_iso()}) + "\n")
        return uid


def _public(row):
    return {
        "id": row.get("id"),
        "label": row.get("label"),
        "authenticator": KNOWN_AAGUIDS.get(row.get("aaguid") or "", "Passkey"),
        "created_at": row.get("created_at"),
        "last_used_at": row.get("last_used_at"),
        "transports": row.get("transports") or [],
        "backed_up": bool(row.get("backed_up")),
        "device_type": row.get("device_type"),
        "device_id": row.get("device_id"),
        "revoked_at": row.get("revoked_at"),
    }


# --- device rows (dashboard_auth) ----------------------------------------

def _device_for_token(token):
    """The live device row a raw token belongs to, or None. Same comparison as
    dashboard_auth.resolve(), without its last_seen bookkeeping."""
    if not token or not isinstance(token, str):
        return None
    token = "".join(token.split())
    if not token:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for r in dashboard_auth.list_devices():
        if r.get("revoked_at"):
            continue
        if hmac.compare_digest(r.get("token_sha256") or "", digest):
            return r if r.get("handle") in dashboard_auth.HANDLES else None
    return None


def _live_device_ids():
    return {r.get("id") for r in dashboard_auth.list_devices() if not r.get("revoked_at")}


def _parent_of(device_id, rows):
    for r in rows:
        if device_id in (r.get("session_device_ids") or []):
            return r.get("device_id")
    return device_id


def _revoke_device(device_id) -> bool:
    """Revoke one device row and confirm it stuck by re-reading the devices file.
    Retried: on Windows the file can be briefly held by another handle, and another
    process's stale read-modify-write can undo a revoke. A row that no longer exists
    counts as revoked (nothing live). Returns False, and logs, if it never sticks."""
    last = None
    for attempt in range(REVOKE_TRIES):
        try:
            dashboard_auth.revoke(device_id)
            row = next((r for r in dashboard_auth.list_devices() if r.get("id") == device_id), None)
            if row is None or row.get("revoked_at"):
                return True
        except Exception as exc:
            last = exc
        _sleep(0.05 * (attempt + 1))
    _log("could not revoke device %s after %d tries (%s); reconcile will retry"
         % (device_id, REVOKE_TRIES, type(last).__name__ if last else "did not stick"))
    return False


def _abandon_minted(token):
    """A login minted a device row but could not finish: revoke that row. Found by the
    token's hash, so it works even when the first lookup is what failed."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for attempt in range(REVOKE_TRIES):
        try:
            hit = next((r for r in dashboard_auth.list_devices()
                        if hmac.compare_digest(r.get("token_sha256") or "", digest)), None)
        except Exception:
            _sleep(0.05 * (attempt + 1))
            continue
        if hit is not None and not hit.get("revoked_at") and not _revoke_device(hit.get("id")):
            _log("minted passkey session (device %s) is still live; reconcile will retire it" % hit.get("id"))
        return
    _log("could not look up a minted passkey session; reconcile will retire it")


# --- challenges ----------------------------------------------------------

def _new_challenge(purpose, device_id=None, token_sha=None) -> bytes:
    """token_sha: the Full Marty step-up binds its challenge to the caller's cookie token (hash only)."""
    raw = secrets.token_bytes(32)
    now = _clock()
    with _ch_lock:
        for key in [k for k, v in _challenges.items() if v["expires"] <= now]:
            del _challenges[key]
        while len(_challenges) >= MAX_PENDING_CHALLENGES:
            del _challenges[next(iter(_challenges))]      # oldest first: dicts keep insertion order
        _challenges[_b64u(raw)] = {"purpose": purpose, "expires": now + CHALLENGE_TTL_SEC,
                                   "device_id": device_id, "token_sha": token_sha}
    return raw


def _take_challenge(credential, purpose, ceremony_type, status):
    """Read clientDataJSON, remove its challenge from the store (single use: gone
    whether or not the rest verifies), then check purpose, age, type, origin and
    crossOrigin. Returns (challenge bytes, store entry)."""
    public = LOGIN_REFUSED if purpose == "login" else "The passkey response was not valid."
    try:
        cd = json.loads(_unb64u(credential["response"]["clientDataJSON"]))
        if not isinstance(cd, dict):
            raise ValueError("clientDataJSON is not an object")
        challenge = _unb64u(cd["challenge"])
    except (KeyError, TypeError, ValueError):
        raise PasskeyError(400, "malformed", public)
    with _ch_lock:
        entry = _challenges.pop(_b64u(challenge), None)
    if entry is None:
        raise PasskeyError(status, "challenge_unknown", public)
    if entry["expires"] <= _clock():
        raise PasskeyError(status, "challenge_expired",
                           "That sign-in took too long; try again." if purpose == "login"
                           else "That setup took too long; start again.")
    if entry["purpose"] != purpose:
        raise PasskeyError(status, "challenge_purpose", public)
    if cd.get("type") != ceremony_type:
        raise PasskeyError(status, "type", public)
    if cd.get("origin") not in expected_origins():
        raise PasskeyError(status, "origin", public)
    if cd.get("crossOrigin") is True:
        raise PasskeyError(status, "cross_origin", public)
    return challenge, entry


def _code_for(exc):
    m = str(exc).lower()
    for needle, code in (("rp id", "rp_id"), ("sign count", "sign_count"),
                         ("user verification", "user_verification"), ("not present", "user_presence"),
                         ("user presence", "user_presence"), ("signature", "signature"),
                         ("origin", "origin"), ("challenge", "challenge"), ("alg", "algorithm")):
        if needle in m:
            return code
    return "invalid"


# --- rate limiting -------------------------------------------------------

class _Limiter:
    def __init__(self, per_key, total, window):
        self.per_key, self.total, self.window = per_key, total, window
        self.hits = {}
        self.all = deque()
        self.lock = threading.Lock()

    def hit(self, key):
        now = _clock()
        cutoff = now - self.window
        with self.lock:
            q = self.hits.setdefault(key, deque())
            while q and q[0] <= cutoff:
                q.popleft()
            while self.all and self.all[0] <= cutoff:
                self.all.popleft()
            blocked = None
            if len(q) >= self.per_key:
                blocked = q[0]
            elif self.total and len(self.all) >= self.total:
                blocked = self.all[0]
            if blocked is not None:
                raise PasskeyError(429, "rate_limited",
                                   "Too many passkey sign-in attempts. Try again later.",
                                   retry_after=max(1, int(blocked + self.window - now) + 1))
            q.append(now)
            self.all.append(now)
            if len(self.hits) > 4096:
                for k in [k for k, v in self.hits.items() if not v]:
                    del self.hits[k]

    def reset(self):
        with self.lock:
            self.hits.clear()
            self.all.clear()


_login_limiter = _Limiter(LOGIN_LIMIT_PER_IP, LOGIN_LIMIT_TOTAL, RATE_WINDOW_SEC)
_options_limiter = _Limiter(OPTIONS_LIMIT_PER_IP, 0, RATE_WINDOW_SEC)


def client_ip(peer, headers) -> str:
    """The caller's address, for rate limiting. The server binds loopback and the
    only way in is `tailscale serve`, which sets X-Forwarded-For to the tailnet
    peer, so when the TCP peer is loopback the LAST X-Forwarded-For entry is the
    real client. Anything unparseable falls back to the TCP peer."""
    peer = peer or ""
    try:
        loopback = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        loopback = False
    if loopback and headers is not None:
        last = (headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
        if last:
            try:
                return str(ipaddress.ip_address(last))
            except ValueError:
                pass
    return peer or "unknown"


def origin_ok(headers) -> bool:
    """CSRF guard, called first by all four passkey POST routes: True only when the
    Origin header is exactly the dashboard's origin (the loopback test origin in test
    mode). Browsers send Origin on every POST, so a missing one is refused too."""
    try:
        value = (headers.get("Origin") or "").strip()
    except Exception:
        return False
    return bool(value) and value in expected_origins()


# --- registration (device session required) ------------------------------

def registration_options(token) -> dict:
    """Options for navigator.credentials.create(). `token` is the caller's raw device
    token (dashboard_auth.token_from_headers); the challenge is bound to it."""
    _require_available()
    device = _device_for_token(token)
    if device is None:
        raise PasskeyError(401, "auth", "authentication required")
    active = [r for r in _read_rows_locked() if not r.get("revoked_at")]
    if len(active) >= MAX_PASSKEYS:
        raise PasskeyError(409, "too_many", "Too many passkeys; revoke one first.")
    challenge = _new_challenge("register", device_id=device["id"])
    options = webauthn.generate_registration_options(
        rp_id=_config["rp_id"],
        rp_name=RP_NAME,
        user_name=USER_NAME,
        user_display_name=USER_NAME,
        user_id=_user_id(),
        challenge=challenge,
        timeout=CEREMONY_TIMEOUT_MS,
        attestation=AttestationConveyancePreference.NONE,
        # Security key only (2026-09-30, Lukas's yes). On Android, a create() asking for a
        # discoverable credential goes through Credential Manager, which took the YubiKey's
        # PIN and then failed with "unknown error ... credential manager"; residentKey
        # discouraged goes to Play Services' FIDO2 path, which drives NFC and USB keys.
        # The key is then used through the step-up's allowCredentials, never usernameless.
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        # Exclude every row not known to be synced (keys already registered; a row with no
        # backed_up flag counts as a key, fail closed on duplicates). A synced passkey in
        # Google Password Manager is left out so it cannot block a new key.
        exclude_credentials=[PublicKeyCredentialDescriptor(id=_unb64u(r["credential_id"]))
                             for r in active if not r.get("backed_up")],
        supported_pub_key_algs=_algs(),
    )
    out = json.loads(options_to_json(options))
    out["hints"] = ["security-key"]
    return out


def verify_registration(token, credential, label=None) -> dict:
    """Check navigator.credentials.create()'s result and store the passkey.
    Returns its public record."""
    _require_available()
    device = _device_for_token(token)
    if device is None:
        raise PasskeyError(401, "auth", "authentication required")
    if not isinstance(credential, dict):
        raise PasskeyError(400, "malformed", "The passkey response was not valid.")
    challenge, entry = _take_challenge(credential, "register", "webauthn.create", 400)
    if entry["device_id"] != device["id"]:
        raise PasskeyError(403, "device_mismatch", "This setup was started from another session; start again.")
    try:
        v = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=_config["rp_id"],
            expected_origin=expected_origins(),
            require_user_verification=True,
            supported_pub_key_algs=_algs(),
        )
        alg = int(decode_credential_public_key(v.credential_public_key).alg)
    except PasskeyError:
        raise
    except Exception as exc:
        raise PasskeyError(400, _code_for(exc), "The passkey could not be verified.") from exc
    transports = [t for t in ((credential.get("response") or {}).get("transports") or [])
                  if isinstance(t, str) and t in KNOWN_TRANSPORTS]
    cred_id = _b64u(v.credential_id)
    with _store_lock():
        rows = _read_rows()
        if any(r.get("credential_id") == cred_id for r in rows):
            raise PasskeyError(409, "duplicate", "That passkey is already registered.")
        if sum(1 for r in rows if not r.get("revoked_at")) >= MAX_PASSKEYS:
            raise PasskeyError(409, "too_many", "Too many passkeys; revoke one first.")
        parent = _parent_of(device["id"], rows)
        maker = KNOWN_AAGUIDS.get(v.aaguid, "Passkey")
        where = device.get("label") or "device %s" % parent
        row = {
            "id": max((r.get("id", 0) for r in rows), default=0) + 1,
            "credential_id": cred_id,
            "public_key": _b64u(v.credential_public_key),
            "alg": alg,
            "sign_count": int(v.sign_count),
            "transports": transports,
            "aaguid": v.aaguid,
            "backed_up": bool(v.credential_backed_up),
            "device_type": getattr(v.credential_device_type, "value", str(v.credential_device_type)),
            "label": _clean_label(label, "%s (set up from %s)" % (maker, where)),
            "user_id": _b64u(_user_id()),
            "rp_id": _config["rp_id"],
            "created_at": _now_iso(),
            "last_used_at": None,
            "device_id": parent,
            "session_device_ids": [],
            "pending_revoke": [],
            "revoked_at": None,
        }
        rows.append(row)
        _write_rows(rows)
    return _public(row)


# --- login (public, rate limited) ----------------------------------------

def login_options(ip) -> dict:
    """Options for navigator.credentials.get(). Discoverable credentials: no
    allowCredentials, so nothing about the registered passkeys is disclosed here."""
    _require_available()
    _options_limiter.hit(ip)
    challenge = _new_challenge("login")
    options = webauthn.generate_authentication_options(
        rp_id=_config["rp_id"],
        challenge=challenge,
        timeout=CEREMONY_TIMEOUT_MS,
        allow_credentials=[],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


def verify_login(ip, credential):
    """Check navigator.credentials.get()'s result. On success mint a device token
    (dashboard_auth.enroll) and return (token, public record). The server sets the
    token with dashboard_auth.session_cookie(token), as /api/session does."""
    _require_available()
    _login_limiter.hit(ip)                       # every attempt counts, pass or fail
    if not isinstance(credential, dict):
        raise PasskeyError(400, "malformed", LOGIN_REFUSED)
    challenge, _entry = _take_challenge(credential, "login", "webauthn.get", 401)
    try:
        cred_id = _b64u(_unb64u(credential.get("rawId") or credential.get("id")))
    except ValueError:
        raise PasskeyError(400, "malformed", LOGIN_REFUSED)
    with _store_lock():
        rows = _read_rows()
        row = next((r for r in rows if r.get("credential_id") == cred_id), None)
        if row is None:
            raise PasskeyError(401, "unknown_credential", LOGIN_REFUSED)
        if row.get("revoked_at"):
            raise PasskeyError(401, "revoked", LOGIN_REFUSED)
        if row.get("device_id") not in _live_device_ids():
            raise PasskeyError(401, "parent_revoked", LOGIN_REFUSED)
        handle = (credential.get("response") or {}).get("userHandle")
        if handle:
            try:
                same = hmac.compare_digest(_unb64u(handle), _unb64u(row.get("user_id") or ""))
            except (ValueError, TypeError):
                same = False
            if not same:
                raise PasskeyError(401, "user_handle", LOGIN_REFUSED)
        try:
            v = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=_config["rp_id"],
                expected_origin=expected_origins(),
                credential_public_key=_unb64u(row["public_key"]),
                credential_current_sign_count=int(row.get("sign_count") or 0),
                require_user_verification=True,
            )
        except Exception as exc:
            raise PasskeyError(401, _code_for(exc), LOGIN_REFUSED) from exc

        try:
            token = dashboard_auth.enroll(HANDLE, "passkey %s: %s" % (row["id"], row.get("label") or ""))
        except Exception as exc:
            raise PasskeyError(503, "store_busy", "Sign-in could not be completed; try again.") from exc
        # From here to the store write, ANY failure revokes the row just minted: a live
        # session the passkey store does not track is exactly what must never exist.
        try:
            minted = _device_for_token(token)
            if minted is None:
                raise RuntimeError("the minted device row was not found")
            live = _live_device_ids()
            sessions = [s for s in (row.get("session_device_ids") or []) if s in live] + [minted["id"]]
            pending = list(row.get("pending_revoke") or [])
            while len(sessions) > MAX_SESSIONS_PER_PASSKEY:
                oldest = sessions.pop(0)
                if not _revoke_device(oldest):
                    pending.append(oldest)
            row["session_device_ids"] = sessions
            row["pending_revoke"] = pending
            row["sign_count"] = int(v.new_sign_count)
            row["backed_up"] = bool(v.credential_backed_up)
            row["last_used_at"] = _now_iso()
            _write_rows(rows)
        except Exception as exc:
            _abandon_minted(token)
            _log("login for passkey %s not completed (%s); its minted session was cleaned up"
                 % (row.get("id"), type(exc).__name__))
            raise PasskeyError(503, "store_busy", "Sign-in could not be completed; try again.") from exc
    return token, _public(row)


# --- Full Marty step-up (Stage B, deployed 2026-09-30) --------------------
# A third challenge purpose, "stepup", bound to the calling device row AND the exact cookie token (by
# hash). It mints NOTHING: it only proves the passkey is present for this device session.
# Stage B pick 6 (Lukas 2026-09-29): "Tie it to your enrolled device, and limit tries per device."
# The rules live in fullmarty_stepup.py; STEPUP_DEVICE_BOUND_ONLY is True there.

_stepup_limiter = fullmarty_stepup.DeviceLimiter()          # 5 tries per device row per 10 minutes

STEPUP_NO_PASSKEY = ("No passkey on this device can unlock Full Marty. Full Marty needs a passkey that "
                     "lives only on this phone (not synced to a password manager), enrolled from this phone.")


def _stepup_refusal(exc):
    """fullmarty_stepup.StepupRefused -> PasskeyError. Codes only; nothing about other passkeys."""
    if exc.code == "rate_limited":
        return PasskeyError(429, "rate_limited", "Too many unlock attempts from this device. Try again later.",
                            retry_after=exc.retry_after)
    if exc.code == "auth":
        return PasskeyError(401, "auth", "authentication required")
    if exc.code in ("synced_passkey", "other_device"):
        return PasskeyError(403, exc.code, STEPUP_NO_PASSKEY)
    return PasskeyError(401, exc.code, LOGIN_REFUSED)


def stepup_options(token) -> dict:
    """Options for navigator.credentials.get() to unlock Full Marty on THIS device session.
    Offers ONLY this device's own device-bound passkeys (fullmarty_stepup.eligible_rows)."""
    _require_available()
    device = _device_for_token(token)
    if device is None:
        raise PasskeyError(401, "auth", "authentication required")
    rows = fullmarty_stepup.eligible_rows(_read_rows_locked(), device["id"], _live_device_ids())
    if not rows:
        raise PasskeyError(409, "no_passkey", STEPUP_NO_PASSKEY)
    sha = hashlib.sha256("".join(token.split()).encode("utf-8")).hexdigest()
    challenge = _new_challenge("stepup", device_id=device["id"], token_sha=sha)
    options = webauthn.generate_authentication_options(
        rp_id=_config["rp_id"], challenge=challenge, timeout=CEREMONY_TIMEOUT_MS,
        allow_credentials=[PublicKeyCredentialDescriptor(id=_unb64u(r["credential_id"])) for r in rows],
        user_verification=UserVerificationRequirement.REQUIRED)
    return json.loads(options_to_json(options))


def verify_stepup(ip, token, credential) -> dict:
    """Verify the step-up assertion. Mints NOTHING. Returns the passkey's public record."""
    _require_available()
    _login_limiter.hit(ip)                                   # kept: the shared IP limiter, a second layer
    device = _device_for_token(token)
    if device is None:
        raise PasskeyError(401, "auth", "authentication required")
    try:
        _stepup_limiter.hit(device["id"])                    # pick 6: per device, counted before any check
    except fullmarty_stepup.StepupRefused as exc:
        raise _stepup_refusal(exc)
    if not isinstance(credential, dict):
        raise PasskeyError(400, "malformed", LOGIN_REFUSED)
    challenge, entry = _take_challenge(credential, "stepup", "webauthn.get", 401)
    sha = hashlib.sha256("".join(token.split()).encode("utf-8")).hexdigest()
    if entry.get("device_id") != device["id"] or not hmac.compare_digest(entry.get("token_sha") or "", sha):
        raise PasskeyError(403, "device_mismatch", "This unlock was started from another session.")
    try:
        cred_id = _b64u(_unb64u(credential.get("rawId") or credential.get("id")))
    except ValueError:
        raise PasskeyError(400, "malformed", LOGIN_REFUSED)
    with _store_lock():
        rows = _read_rows()
        row = next((r for r in rows if r.get("credential_id") == cred_id), None)
        try:
            fullmarty_stepup.check_row(row, device["id"], _live_device_ids())   # bound, not synced, this device's
        except fullmarty_stepup.StepupRefused as exc:
            raise _stepup_refusal(exc)
        handle = (credential.get("response") or {}).get("userHandle")
        if handle:
            try:
                same = hmac.compare_digest(_unb64u(handle), _unb64u(row.get("user_id") or ""))
            except (ValueError, TypeError):
                same = False
            if not same:
                raise PasskeyError(401, "user_handle", LOGIN_REFUSED)
        try:
            v = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=_config["rp_id"],
                expected_origin=expected_origins(),
                credential_public_key=_unb64u(row["public_key"]),
                credential_current_sign_count=int(row.get("sign_count") or 0),
                require_user_verification=True,
            )
        except Exception as exc:
            raise PasskeyError(401, _code_for(exc), LOGIN_REFUSED) from exc
        try:
            fullmarty_stepup.check_assertion(v)              # the authenticator says single-device, not backed up
        except fullmarty_stepup.StepupRefused as exc:
            row["backed_up"] = bool(getattr(v, "credential_backed_up", True))   # record what it reported
            _write_rows(rows)
            raise _stepup_refusal(exc)
        row["sign_count"] = int(v.new_sign_count)
        row["last_used_at"] = _now_iso()
        _write_rows(rows)
    _stepup_limiter.success(device["id"])
    return _public(row)


# --- logout, revocation, reconcile ---------------------------------------

def on_logout(token) -> bool:
    """Call from the logout routes BEFORE the cookie is cleared. Revokes the device row
    if a passkey login minted it; a device-token session is left alone. Needs no
    webauthn, so it works even when passkeys are unavailable."""
    device = _device_for_token(token)
    if device is None:
        return False
    with _store_lock():
        rows = _read_rows()
        for r in rows:
            ids = r.get("session_device_ids") or []
            if device["id"] in ids:
                ok = _revoke_device(device["id"])
                r["session_device_ids"] = [i for i in ids if i != device["id"]]
                if not ok:
                    r["pending_revoke"] = (r.get("pending_revoke") or []) + [device["id"]]
                _write_rows(rows)
                return ok
    if SESSION_LABEL_RE.match(device.get("label") or ""):
        return _revoke_device(device["id"])     # an untracked passkey session: retire it too
    return False


def revoke(passkey_id) -> bool:
    """Revoke one passkey and every session it minted. The passkey is marked first (that
    alone stops new logins); a session revoke that never sticks stays listed, and the
    passkey being revoked makes reconcile() retry it."""
    with _store_lock():
        rows = _read_rows()
        hit = next((r for r in rows if r.get("id") == passkey_id and not r.get("revoked_at")), None)
        if hit is None:
            return False
        hit["revoked_at"] = _now_iso()
        _write_rows(rows)
        hit["session_device_ids"] = [sid for sid in (hit.get("session_device_ids") or [])
                                     if not _revoke_device(sid)]
        _write_rows(rows)
    return True


def revoke_confirmed(passkey_id, tries=5, settle=0.3) -> bool:
    """For the CLI, which runs beside the server. Since 2026-09-28 every write in either process
    holds _store_lock, so a stale read-modify-write can no longer undo a revoke; the re-read and
    re-apply loop stays as the confirmation (and covers a store_busy answer, the lock held past
    its timeout, which counts as one failed try). Apply it, pause, re-read, and re-apply until the
    passkey reads revoked AND no live device carries its "passkey N:" label."""
    prefix = "passkey %s: " % passkey_id
    for _ in range(tries):
        row = next((r for r in _read_rows_locked() if r.get("id") == passkey_id), None)
        if row is None:
            return False
        try:
            if not row.get("revoked_at"):
                revoke(passkey_id)
            reconcile()
        except PasskeyError as exc:                     # store_busy: the other process holds the lock
            _log("passkey %s: %s; trying again" % (passkey_id, exc.code))
        _sleep(settle)
        row = next((r for r in _read_rows_locked() if r.get("id") == passkey_id), None)
        stuck = row is not None and bool(row.get("revoked_at"))
        live = [d for d in dashboard_auth.list_devices()
                if not d.get("revoked_at") and (d.get("label") or "").startswith(prefix)]
        if stuck and not live:
            return True
    _log("passkey %s: revocation did not stick after %d tries" % (passkey_id, tries))
    return False


def reconcile() -> int:
    """Bring device rows in line with the passkey store. Returns sessions revoked.
      * sessions of a revoked passkey, or of one whose parent device is revoked
      * ids parked in pending_revoke (a revoke that did not stick earlier)
      * any live device labelled "passkey N:" that passkey N does not track: its login's
        store write failed, or passkey N is revoked or missing from the store
    Ids already revoked are forgotten. A revoke that still fails stays listed for next time."""
    revoked = 0
    with _store_lock():
        rows = _read_rows()
        live = _live_device_ids()
        changed = False
        for r in rows:
            dead = bool(r.get("revoked_at")) or r.get("device_id") not in live
            keep, pending = [], []
            for sid in r.get("session_device_ids") or []:
                if sid not in live:
                    continue
                if not dead:
                    keep.append(sid)
                elif _revoke_device(sid):
                    revoked += 1
                else:
                    keep.append(sid)
            for sid in r.get("pending_revoke") or []:
                if sid not in live:
                    continue
                if _revoke_device(sid):
                    revoked += 1
                else:
                    pending.append(sid)
            if keep != (r.get("session_device_ids") or []) or pending != (r.get("pending_revoke") or []):
                r["session_device_ids"], r["pending_revoke"] = keep, pending
                changed = True
        tracked = {}
        for r in rows:
            if not r.get("revoked_at"):
                tracked.setdefault(r.get("id"), set()).update(r.get("session_device_ids") or [])
        for d in dashboard_auth.list_devices():          # fresh read: the loop above revoked some
            m = SESSION_LABEL_RE.match(d.get("label") or "")
            if d.get("revoked_at") or not m or d.get("id") in tracked.get(int(m.group(1)), ()):
                continue
            if _revoke_device(d.get("id")):
                revoked += 1
        if changed:
            _write_rows(rows)
    return revoked


def maybe_reconcile() -> None:
    """Cheap enough to call from every auth check: runs reconcile() at most once per
    RECONCILE_EVERY_SEC and never raises (a bookkeeping failure must not fail a request)."""
    now = _clock()
    if not _reconcile_lock.acquire(blocking=False):
        return
    try:
        if _last_reconcile[0] is not None and now - _last_reconcile[0] < RECONCILE_EVERY_SEC:
            return
        _last_reconcile[0] = now
        try:
            reconcile()
        except Exception:
            pass
    finally:
        _reconcile_lock.release()


def list_passkeys(include_revoked=False):
    return [_public(r) for r in _read_rows_locked() if include_revoked or not r.get("revoked_at")]


def status() -> dict:
    """For an AUTHENTICATED payload only (WIRING folds it into GET /api/status). There is
    deliberately no public status route: the login page decides from the browser alone."""
    ok = available()
    active = [r for r in _read_rows_locked() if not r.get("revoked_at")]
    out = {"available": ok, "registered": len(active), "rp_id": _config["rp_id"],
           "passkeys": [_public(r) for r in active]}
    if not ok:
        out["reason"] = "webauthn is not installed for this Python; start the dashboard with dashboard/.venv"
    return out


def _reset_for_tests():
    with _ch_lock:
        _challenges.clear()
    _login_limiter.reset()
    _options_limiter.reset()
    _stepup_limiter.hits.clear()
    _last_reconcile[0] = None


# --- CLI -----------------------------------------------------------------

def _cli(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "check":
        print("webauthn available:", available(), "" if available() else "(%s)" % _IMPORT_ERROR)
        print("python:", sys.executable)
        print("store:", PASSKEYS_PATH)
        print("active passkeys:", len(list_passkeys()))
        return 0
    if cmd == "list":
        for p in list_passkeys(include_revoked=True):
            state = "REVOKED" if p["revoked_at"] else "active"
            print("%3s  %-7s  %-45s  created %s  last used %s  parent device %s"
                  % (p["id"], state, p["label"], p["created_at"], p["last_used_at"] or "never", p["device_id"]))
        return 0
    if cmd == "revoke" and len(argv) == 3 and argv[2].isdigit():
        pid = int(argv[2])
        if not any(r.get("id") == pid for r in _read_rows_locked()):
            print("no passkey with id %s" % pid)
            return 1
        if revoke_confirmed(pid):
            print("passkey %s revoked; confirmed after a re-read, no live sessions left" % pid)
            return 0
        print("passkey %s: revocation did NOT stick; run it again" % pid)
        return 1
    if cmd == "reconcile":
        print("revoked %d session(s)" % reconcile())
        return 0
    print("usage: passkeys.py check | list | revoke <id> | reconcile")
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
