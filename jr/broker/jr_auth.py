"""Independent, staged Jr authentication. No shared Marty token or cookie.

The separate Jr service must call provision() from a local owner-only setup
command, never from an HTTP route. A fresh bearer token lives only in this
process and is sent from Jr's own origin in an Authorization header. It is not
a domain cookie, because browser cookies ignore TCP ports and could travel to
another app on the same Tailscale hostname.
"""

from __future__ import annotations

from collections import deque
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time


IDLE_SECONDS = 15 * 60
ABSOLUTE_SECONDS = 8 * 60 * 60
ATTEMPT_WINDOW = 15 * 60
MAX_ATTEMPTS = 5


class AuthError(Exception):
    pass


class JrAuth:
    def __init__(self, path: Path, *, clock=time.monotonic):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.RLock()
        self.sessions: dict[str, tuple[float, float]] = {}
        self.attempts = deque()

    def provision(self, passphrase: str) -> None:
        if not isinstance(passphrase, str) or not 16 <= len(passphrase) <= 1024:
            raise AuthError("Use a unique passphrase of 16 to 1024 characters")
        with self.lock:
            if self.path.exists():
                raise AuthError("Jr identity is already provisioned")
            salt = secrets.token_bytes(32)
            digest = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                                    n=2**14, r=8, p=1)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + "." + secrets.token_hex(8) + ".tmp")
            try:
                with open(temporary, "x", encoding="utf-8") as stream:
                    if os.name != "nt":
                        os.fchmod(stream.fileno(), 0o600)
                    json.dump({"version": 1, "salt": salt.hex(), "digest": digest.hex()}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                temporary.unlink(missing_ok=True)

    def configured(self) -> bool:
        return self.path.is_file()

    def _credential(self):
        try:
            row = json.loads(self.path.read_text(encoding="utf-8"))
            if row.get("version") != 1:
                raise ValueError()
            salt, digest = bytes.fromhex(row["salt"]), bytes.fromhex(row["digest"])
            if len(salt) != 32 or len(digest) != 64:
                raise ValueError()
            return salt, digest
        except (OSError, ValueError, KeyError, TypeError):
            raise AuthError("Jr identity is not available")

    def login(self, passphrase: str) -> str:
        if not isinstance(passphrase, str) or len(passphrase) > 1024:
            raise AuthError("Sign-in failed")
        with self.lock:
            now = self.clock()
            while self.attempts and now - self.attempts[0] > ATTEMPT_WINDOW:
                self.attempts.popleft()
            if len(self.attempts) >= MAX_ATTEMPTS:
                raise AuthError("Too many sign-in attempts; try later")
            self.attempts.append(now)
            salt, expected = self._credential()
            actual = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                                    n=2**14, r=8, p=1)
            if not hmac.compare_digest(actual, expected):
                raise AuthError("Sign-in failed")
            token = secrets.token_urlsafe(48)
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = (now, now)
            return token

    def resolve(self, token: str) -> bool:
        if not isinstance(token, str) or len(token) > 256:
            return False
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            session = self.sessions.get(key)
            if not session:
                return False
            started, touched = session
            now = self.clock()
            if now - touched >= IDLE_SECONDS or now - started >= ABSOLUTE_SECONDS:
                del self.sessions[key]
                return False
            self.sessions[key] = (started, now)
            return True

    def revoke(self, token: str) -> None:
        if not isinstance(token, str):
            return
        with self.lock:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)

    def revoke_all(self) -> None:
        with self.lock:
            self.sessions.clear()
