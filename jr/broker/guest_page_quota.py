"""Staged guest-side document quota for Jr's filtered HTTPS proxy.

CHANGED 2026-09-28 late (wave 3 follow-up, skeptic wave 3 fix item 4): comments only; the
owner's name is now "the owner" (no personal names in code).

CHANGED 2026-09-28 (Jr overnight build, helper item "guest"), why: the owner
removed the allowlist and asked for 5-minute uninterrupted batches, so the
batch shape is no longer a fixed five pages:
- The page limit, request cap, byte cap and lease are batch parameters set at
  arm time. Maxima are enforced here (page_limit <= 30, request_cap <= 1500,
  byte_cap <= 150 MB, lease <= 300 s); the host passes 5/400/30 MB/110 s for a
  short batch and 30/1500/150 MB/300 s for a long one.
- Every finished page now leaves a receipt {number, url, status, text} and,
  on a search results page, an optional "links" list (up to 8 entries of
  {url, title}). Receipt URLs are cut to 200 bytes; link URLs must be https
  and at most 200 bytes; titles at most 80 characters. Control characters are
  refused everywhere so the JSON status has a known worst-case size
  (max_status_bytes()), which the host's stdout cap must exceed.
- State file version is 2. A version-1 file left by the previous install is
  treated as closed and replaced on the next arm (the cable is off then).
- Redirect accounting is unchanged: a 3xx reply is a completed document with
  its status in the receipt, and the browser's follow-up GET is a new slot.

CHANGED 2026-09-28 (skeptic fix 3a): finish() raises StaleReceipt, a
QuotaClosed subclass, for a token this batch never issued, so the proxy Guard
can ignore a completion left over from an earlier batch instead of closing
the current one. Every caller that catches QuotaClosed sees no difference.

CHANGED 2026-09-28 (cloud PR #3 port, 6:40 PM), from the cloud branch's
guest_page_quota hardening (commit d058dd9): _load() refuses a NaN or
infinite expires_at (json.loads accepts both literals, and NaN compares false
against every clock, so a tampered file could have kept a batch open for
ever) and validates every inflight row (dict, int number within 1..used, str
url) at load time instead of trusting it until finish(). Both fail closed as
QuotaClosed like every other malformed state.

CHANGED 2026-09-28 (wave 2 integration, Gemini review item): the lock file
beside the state file is opened with O_NOFOLLOW and O_CLOEXEC where the
platform has them and must be a regular file (fstat), so a lock path swapped
for a symlink or a FIFO by the proxy account can neither redirect the flock
nor block the arm; any failure to open it fails closed as QuotaClosed.

This module has no network access. The installed proxy must call classify()
from Chromium's request headers, then reserve() before forwarding and finish()
when that response ends. Only a root-owned host approval command may arm a
batch. The state path must be in a directory inaccessible to the jr desktop
user and shared by exactly one proxy process. A proxy restart reads the saved
counter; it never grants a fresh batch.
"""

from __future__ import annotations

import json
import math
import os
from contextlib import contextmanager
from pathlib import Path
import secrets
import stat
import threading
import time
from urllib.parse import urlsplit

try:
    import fcntl  # guest Linux: cross-process exclusion during proxy restarts
except ImportError:  # Windows unit tests use the in-process lock
    fcntl = None

try:
    import pwd  # guest Linux: resolve the proxy's actual uid and gid
except ImportError:
    pwd = None


STATE_VERSION = 2
# Short batch defaults (the host passes the long values for a long batch).
LIMIT = 5
DEFAULT_REQUEST_CAP = 400
DEFAULT_BYTE_CAP = 30 * 1024 * 1024
# Hard maxima. arm() refuses anything above these regardless of who asks.
MAX_PAGE_LIMIT = 30
MAX_REQUEST_CAP = 1500
MAX_BYTE_CAP = 150 * 1024 * 1024
MAX_LEASE_SECONDS = 300
MAX_BATCH_ID = 80
MIN_BATCH_ID = 24
MAX_URL = 2048
MAX_RECEIPT_URL_BYTES = 200
MAX_EVIDENCE_PER_PAGE = 300
MAX_EVIDENCE_BYTES = 256
MAX_LINKS = 8
MAX_LINK_URL_BYTES = 200
MAX_LINK_TITLE = 80
DOCUMENT_DEST = {"document", "iframe", "frame"}
STATIC_DEST = {"image", "script", "style", "font", "manifest", "empty"}


class QuotaClosed(Exception):
    pass


class StaleReceipt(QuotaClosed):
    """finish() was called with a token this batch does not hold.

    ADDED 2026-09-28 (skeptic fix 3a): a document reserved in an earlier
    batch whose flow errors after the next batch is armed completes with a
    token the current batch never issued. That is not a receipt-write failure
    and must not close the current batch, so the proxy Guard can tell it apart
    from every other QuotaClosed. It stays a QuotaClosed for every caller.
    """


def classify(method: str, headers) -> str:
    """Return document/subresource or deny ambiguous requests.

    A missing Fetch Metadata destination with an HTML Accept header is charged
    as a document. Unknown destinations fail closed. The existing URL, method,
    DNS, download, cookie and subresource-size filter remains mandatory.
    """
    if method not in {"GET", "HEAD"}:
        raise QuotaClosed("Only public page reads are allowed")
    dest = str(headers.get("sec-fetch-dest", "")).lower()
    if dest in DOCUMENT_DEST:
        return "document"
    if dest in STATIC_DEST:
        return "subresource"
    if not dest and "text/html" in str(headers.get("accept", "")).lower():
        return "document"
    raise QuotaClosed("Unclassifiable browser request")


def _has_control(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _cut_bytes(text: str, limit: int) -> str:
    while len(text.encode("utf-8")) > limit:
        text = text[:-1]
    return text


def valid_link(item) -> bool:
    """A receipt link: https URL of at most 200 bytes, title of at most 80 chars."""
    if type(item) is not dict or set(item) != {"url", "title"}:
        return False
    url, title = item["url"], item["title"]
    if (type(url) is not str or type(title) is not str or
        not url.startswith("https://") or len(url.encode("utf-8")) > MAX_LINK_URL_BYTES or
        _has_control(url) or any(c.isspace() for c in url) or
        len(title) > MAX_LINK_TITLE or _has_control(title)):
        return False
    return True


def valid_receipt(item, used: int) -> bool:
    if type(item) is not dict or not {"number", "url", "status", "text"} <= set(item):
        return False
    if set(item) - {"number", "url", "status", "text", "links"}:
        return False
    if (type(item["number"]) is not int or not 1 <= item["number"] <= used or
        type(item["url"]) is not str or len(item["url"].encode("utf-8")) > MAX_RECEIPT_URL_BYTES or
        _has_control(item["url"]) or
        not (item["status"] is None or (type(item["status"]) is int and 100 <= item["status"] <= 599)) or
        type(item["text"]) is not str or len(item["text"]) > MAX_EVIDENCE_PER_PAGE or
        len(item["text"].encode("utf-8")) > MAX_EVIDENCE_BYTES or _has_control(item["text"])):
        return False
    links = item.get("links")
    if links is not None:
        if type(links) is not list or not 1 <= len(links) <= MAX_LINKS or not all(map(valid_link, links)):
            return False
    return True


def validate_caps(page_limit, request_cap, byte_cap) -> None:
    """Refuse a batch shape above the hard maxima or below one."""
    for name, value, maximum in (("page limit", page_limit, MAX_PAGE_LIMIT),
                                 ("request cap", request_cap, MAX_REQUEST_CAP),
                                 ("byte cap", byte_cap, MAX_BYTE_CAP)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"Batch {name} must be an integer from 1 to {maximum}")


class GuestPageQuota:
    def __init__(self, path: Path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.RLock()

    @contextmanager
    def _locked(self):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self.path.with_name(self.path.name + ".lock")
            flags = (os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0))
            try:
                fd = os.open(lock_path, flags, 0o600)
            except OSError:
                raise QuotaClosed("Quota lock file could not be opened")
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise QuotaClosed("Quota lock path is not a regular file")
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _load(self) -> dict:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if (type(value) is not dict or value.get("version") != STATE_VERSION or
                type(value.get("batch_id")) is not str or
                not MIN_BATCH_ID <= len(value["batch_id"]) <= MAX_BATCH_ID or
                value.get("phase") not in {"open", "draining", "closed"} or
                type(value.get("limit")) is not int or not 1 <= value["limit"] <= MAX_PAGE_LIMIT or
                type(value.get("request_cap")) is not int or not 1 <= value["request_cap"] <= MAX_REQUEST_CAP or
                type(value.get("byte_cap")) is not int or not 1 <= value["byte_cap"] <= MAX_BYTE_CAP or
                type(value.get("used")) is not int or not 0 <= value["used"] <= value["limit"] or
                type(value.get("expires_at")) not in {int, float} or
                not math.isfinite(value["expires_at"]) or
                type(value.get("inflight")) is not dict or
                type(value.get("evidence", [])) is not list or
                len(value.get("evidence", [])) > value["limit"] or
                type(value.get("latest")) is not dict or
                type(value["latest"].get("number")) is not int or
                not 0 <= value["latest"]["number"] <= value["used"] or
                value["latest"].get("url") is not None and
                (not isinstance(value["latest"].get("url"), str) or
                 len(value["latest"]["url"]) > MAX_URL)):
                raise ValueError("invalid quota state")
            for receipt in value.get("evidence", []):
                if not valid_receipt(receipt, value["used"]):
                    raise ValueError("invalid page evidence")
            for row in value["inflight"].values():
                if (type(row) is not dict or type(row.get("number")) is not int or
                    not 1 <= row["number"] <= value["used"] or
                    not isinstance(row.get("url"), str)):
                    raise ValueError("invalid inflight page")
            value.setdefault("evidence", [])
            return value
        except (OSError, ValueError, TypeError):
            raise QuotaClosed("No valid owner-approved page batch")

    def _save(self, value: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            with open(temporary, "x", encoding="utf-8") as stream:
                if os.name != "nt":
                    os.fchmod(stream.fileno(), 0o600)
                json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)

    def arm(self, batch_id: str, expires_at: float, *, page_limit: int = LIMIT,
            request_cap: int = DEFAULT_REQUEST_CAP, byte_cap: int = DEFAULT_BYTE_CAP) -> None:
        """Called only by the root-owned approval helper while cable is off."""
        if os.name != "nt" and os.geteuid() != 0:
            raise PermissionError("Only the guest administrator can arm a page batch")
        if (not isinstance(batch_id, str) or not MIN_BATCH_ID <= len(batch_id) <= MAX_BATCH_ID or
            _has_control(batch_id)):
            raise ValueError("Invalid host batch id")
        if (not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool) or
            not self.clock() < expires_at <= self.clock() + MAX_LEASE_SECONDS):
            raise ValueError(f"Batch lease must expire within {MAX_LEASE_SECONDS} seconds")
        validate_caps(page_limit, request_cap, byte_cap)
        with self._locked():
            if self.path.exists():
                try:
                    previous = self._load()
                except QuotaClosed:
                    previous = None  # unreadable or older-version file: nothing is open
                if (previous is not None and previous["phase"] != "closed" and
                    self.clock() < previous["expires_at"]):
                    raise QuotaClosed("Close the previous batch before rearming")
            self._save({"version": STATE_VERSION, "batch_id": batch_id, "phase": "open",
                        "used": 0, "limit": page_limit, "request_cap": request_cap,
                        "byte_cap": byte_cap, "expires_at": expires_at, "inflight": {},
                        "latest": {"number": 0, "url": None}, "evidence": []})
            if os.name != "nt":
                # The proxy's UID and GID can differ. The desktop user must
                # have no read or write access to this directory.
                account = pwd.getpwnam("jrproxy")
                proxy_uid, proxy_gid = account.pw_uid, account.pw_gid
                # Give only the proxy process the state and lock it must update.
                os.chown(self.path.parent, proxy_uid, proxy_gid)
                os.chmod(self.path.parent, 0o700)
                os.chown(self.path, proxy_uid, proxy_gid)
                os.chmod(self.path, 0o600)
                lock_path = self.path.with_name(self.path.name + ".lock")
                os.chown(lock_path, proxy_uid, proxy_gid)
                os.chmod(lock_path, 0o600)

    def caps(self) -> dict:
        """The open batch's identity and traffic caps for the proxy Guard."""
        with self._locked():
            state = self._load()
            if self.clock() >= state["expires_at"] or state["phase"] == "closed":
                raise QuotaClosed("Owner-approved page batch expired")
            return {"batch_id": state["batch_id"], "limit": state["limit"],
                    "request_cap": state["request_cap"], "byte_cap": state["byte_cap"]}

    def reserve(self, url: str, kind: str) -> str | None:
        with self._locked():
            state = self._load()
            if self.clock() >= state["expires_at"] or state["phase"] == "closed":
                raise QuotaClosed("Owner-approved page batch expired")
            if kind == "subresource":
                # The proxy Guard enforces the batch's request and byte caps.
                return None
            if kind != "document" or state["phase"] != "open" or state["used"] >= state["limit"]:
                raise QuotaClosed("All approved page pulls already reserved")
            if (not isinstance(url, str) or len(url) > MAX_URL or _has_control(url) or
                urlsplit(url).scheme != "https"):
                raise QuotaClosed("Invalid page URL")
            token = secrets.token_urlsafe(18)
            state["used"] += 1
            state["inflight"][token] = {"number": state["used"], "url": url}
            if state["used"] == state["limit"]:
                state["phase"] = "draining"
            self._save(state)  # reserve before any upstream request
            return token

    def finish(self, token: str, evidence: str = "", *, status=None, links=None) -> dict:
        if (type(evidence) is not str or len(evidence) > MAX_EVIDENCE_PER_PAGE or
            len(evidence.encode("utf-8")) > MAX_EVIDENCE_BYTES or _has_control(evidence)):
            raise ValueError("Invalid bounded page evidence")
        if not (status is None or (type(status) is int and 100 <= status <= 599)):
            raise ValueError("Invalid page status")
        if links is not None and (type(links) is not list or len(links) > MAX_LINKS or
                                  not all(map(valid_link, links))):
            raise ValueError("Invalid search result links")
        with self._locked():
            state = self._load()
            row = state["inflight"].pop(token, None)
            if row is None:
                raise StaleReceipt("Unknown or repeated page receipt")
            if row["number"] >= state["latest"]["number"]:
                state["latest"] = row
            receipt = {"number": row["number"], "url": _cut_bytes(row["url"], MAX_RECEIPT_URL_BYTES),
                       "status": status, "text": evidence}
            if links:
                receipt["links"] = list(links)
            state["evidence"].append(receipt)
            state["evidence"].sort(key=lambda item: item["number"])
            if state["phase"] == "draining" and not state["inflight"]:
                state["phase"] = "closed"  # all requests now refused in guest
            self._save(state)
            return self._public(state)

    def close(self) -> dict:
        with self._locked():
            state = self._load()
            state["phase"] = "closed"
            state["inflight"] = {}
            self._save(state)
            return self._public(state)

    def snapshot(self) -> dict:
        with self._locked():
            state = self._load()
            return self._public(state)

    def _public(self, state: dict) -> dict:
        return {"batch_id": state["batch_id"], "phase": state["phase"],
                "used": state["used"], "limit": state["limit"],
                "request_cap": state["request_cap"], "byte_cap": state["byte_cap"],
                "inflight": len(state["inflight"]),
                "current_url": state["latest"]["url"],
                "evidence": state["evidence"],
                "expired": self.clock() >= state["expires_at"]}


def max_status_bytes() -> int:
    """UTF-8 size of the largest status the CLI can print (worst-case escaping).

    Every bounded field is filled with the character that costs the most
    once JSON-encoded with ensure_ascii=False: a double quote (1 byte in,
    2 bytes out) for byte-bounded fields, a 4-byte character for the
    character-bounded title. Control characters are refused, so no field
    can cost 6 bytes per character.
    """
    quote_url = "https://" + '"' * (MAX_RECEIPT_URL_BYTES - 8)
    link = {"url": "https://" + '"' * (MAX_LINK_URL_BYTES - 8), "title": "\U0001f9ed" * MAX_LINK_TITLE}
    receipts = [{"number": MAX_PAGE_LIMIT, "url": quote_url, "status": 599,
                 "text": '"' * MAX_EVIDENCE_BYTES, "links": [dict(link) for _ in range(MAX_LINKS)]}
                for _ in range(MAX_PAGE_LIMIT)]
    status = {"batch_id": "x" * MAX_BATCH_ID, "phase": "draining", "used": MAX_PAGE_LIMIT,
              "limit": MAX_PAGE_LIMIT, "request_cap": MAX_REQUEST_CAP, "byte_cap": MAX_BYTE_CAP,
              "inflight": MAX_PAGE_LIMIT, "current_url": "https://" + '"' * (MAX_URL - 8),
              "evidence": receipts, "expired": False}
    return len((json.dumps(status, ensure_ascii=False) + "\n").encode("utf-8"))
