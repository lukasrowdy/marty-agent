"""Separate Jr conversation history encrypted for its Windows service identity.

Every byte on disk is DPAPI CurrentUser ciphertext. The future Jr service must
run under its own account and keep this directory ACL-private to that account.
There is no fallback to plaintext and no import of Marty's history or key.

CHANGED 2026-09-28 late (wave 3f, skeptic wave 3e finding 3): set_synopsis
also accepts a "stopped" last checkpoint. The app's watcher stops a batch
whose broker loop was reported stale, and the pages seen so far still get a
synopsis; a stopped checkpoint never offers Continue (the app decides that).

CHANGED 2026-09-28 (Jr overnight build, item 8 "video"), what and why:
- create_video(url, title): a thread for a video reading, stored through create_plan with
  a {"kind": "video"} plan so every existing thread rule (100 threads, shape checks,
  encryption) applies unchanged.
- video_checkpoint(thread_id, record, synopsis): a new checkpoint type, phase "video",
  holding the evidence metadata (url, title, file name, duration, size, sha256, frame
  count, transcript source), a transcript excerpt under the same 1,800 character bound as
  observed_text, and the validated learned / uncertain / next_step synopsis. Never the
  frames. The 1,000 checkpoint and 2 MB file limits are unchanged.

CHANGED 2026-09-28 (Jr overnight build, item 3 "app"), what and why:
- checkpoint() validates against the broker's two batch profiles instead of the old fixed
  five pages: used 0 to 30, limit 5 or 30, observed_text up to 12,000 characters (the
  broker's MAX_OBSERVED_TEXT). The event also keeps lease_seconds and presence when the
  status carries them, so a past checkpoint says which lease it ran under.
- hosted_checkpoint(thread_id, result): a new entry kind, phase and kind "hosted", written
  after a checkpoint's text was sent to the hosted model: model, cost (the provider's
  reported charge, or the reservation when unverified), cost_verified, the preview's
  payload sha256 and an answer excerpt under MAX_EXCERPT. Never the outbound text.
"""

from __future__ import annotations

import copy
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import threading
import time


MAX_FILE = 2_000_000
MAGIC = b"JR-INDEPENDENT-HISTORY-1\n"
ENTROPY = b"jr-independent-history-v1"
MAX_EXCERPT = 1800
MAX_VIDEO_FRAMES = 24
MAX_PAGES = 30                      # the long batch profile's page limit
PAGE_LIMITS = {5, 30}               # short and long profiles (research_broker.PROFILES)
MAX_OBSERVED_TEXT = 12000           # research_broker.MAX_OBSERVED_TEXT
LEASE_SECONDS = {110, 290}          # short and long host leases
PRESENCE_VALUES = {"console", "grant", "none"}
SYNOPSIS_KEYS = {"learned", "uncertain", "next_step"}


def _valid_synopsis(synopsis) -> bool:
    return (type(synopsis) is dict and set(synopsis) == SYNOPSIS_KEYS and
            all(type(value) is str and value.strip() and len(value) <= 2000
                for value in synopsis.values()))


class HistoryError(Exception):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class DpapiProtector:
    def __init__(self, entropy=ENTROPY):
        if os.name != "nt":
            raise HistoryError("Jr history requires Windows user-scoped encryption")
        self.entropy = entropy
        self.crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        for name in ("CryptProtectData", "CryptUnprotectData"):
            fn = getattr(self.crypt, name)
            fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p,
                           ctypes.POINTER(_Blob), ctypes.c_void_p,
                           ctypes.c_void_p, wintypes.DWORD,
                           ctypes.POINTER(_Blob)]
            fn.restype = wintypes.BOOL
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.LocalFree.restype = ctypes.c_void_p

    @staticmethod
    def _input(data):
        buffer = ctypes.create_string_buffer(data)
        return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer

    def _call(self, function, data):
        incoming, keep_input = self._input(data)
        entropy, keep_entropy = self._input(self.entropy)
        output = _Blob()
        ok = function(ctypes.byref(incoming), None, ctypes.byref(entropy),
                      None, None, 1, ctypes.byref(output))
        if not ok:
            raise HistoryError("Jr history encryption or decryption failed")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            self.kernel.LocalFree(output.pbData)

    def encrypt(self, data):
        return self._call(self.crypt.CryptProtectData, data)

    def decrypt(self, data):
        return self._call(self.crypt.CryptUnprotectData, data)


class JrHistory:
    def __init__(self, root: Path, *, protector=None, clock=time.time):
        self.root = Path(root)
        self.path = self.root / "history.dpapi"
        self.marker = self.root / "initialized.marker"
        self.protector = protector or DpapiProtector()
        self.clock = clock
        self.lock = threading.RLock()

    def _load(self):
        if not self.path.exists():
            if self.marker.exists():
                raise HistoryError("Jr history is missing")
            return {"version": 1, "threads": {}}
        try:
            encrypted = self.path.read_bytes()
            if not encrypted or len(encrypted) > MAX_FILE:
                raise ValueError()
            plain = self.protector.decrypt(encrypted)
            if not plain.startswith(MAGIC):
                raise ValueError()
            data = json.loads(plain[len(MAGIC):])
            if (type(data) is not dict or data.get("version") != 1 or
                type(data.get("threads")) is not dict):
                raise ValueError()
            for thread_id, row in data["threads"].items():
                if (type(thread_id) is not str or len(thread_id) != 32 or
                    any(c not in "0123456789abcdef" for c in thread_id) or
                    type(row) is not dict or row.get("id") != thread_id or
                    type(row.get("question")) is not str or
                    type(row.get("plan")) is not dict or
                    type(row.get("checkpoints")) is not list or
                    type(row.get("updated")) not in {int, float}):
                    raise ValueError()
            return data
        except (OSError, ValueError, TypeError, HistoryError):
            raise HistoryError("Jr history is unavailable or damaged") from None

    def _save(self, data):
        plain = MAGIC + json.dumps(data, ensure_ascii=True,
                                   separators=(",", ":")).encode("ascii")
        if len(plain) > MAX_FILE:
            raise HistoryError("Jr history reached its size limit")
        encrypted = self.protector.encrypt(plain)
        if len(encrypted) > MAX_FILE:
            raise HistoryError("Jr history reached its size limit")
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = self.root / (".history-" + secrets.token_hex(12) + ".tmp")
        try:
            with open(temporary, "xb") as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if not self.marker.exists():
                with open(self.marker, "x", encoding="ascii") as marker:
                    marker.write("Jr independent history v1\n")
                    marker.flush()
                    os.fsync(marker.fileno())
        finally:
            temporary.unlink(missing_ok=True)

    def create_plan(self, question: str, plan: dict) -> str:
        if (type(question) is not str or not question.strip() or len(question) > 6000 or
            type(plan) is not dict):
            raise ValueError("Invalid Jr plan")
        try:
            json.dumps(plan)
        except (TypeError, ValueError, RecursionError):
            raise ValueError("Invalid Jr plan") from None
        with self.lock:
            data = self._load()
            if len(data["threads"]) >= 100:
                raise HistoryError("Jr history has too many conversations")
            thread_id = secrets.token_hex(16)
            now = self.clock()
            data["threads"][thread_id] = {
                "id": thread_id, "created": now, "updated": now,
                "question": question, "plan": copy.deepcopy(plan), "checkpoints": []}
            self._save(data)
            return thread_id

    def checkpoint(self, thread_id: str, status: dict) -> None:
        if type(status) is not dict:
            raise ValueError("Invalid Jr checkpoint")
        event = {"time": self.clock(), "phase": status.get("phase"),
                 "used": status.get("used"), "limit": status.get("limit"),
                 "current_url": status.get("current_url"),
                 "observed_text": status.get("observed_text", "")}
        if (event["phase"] not in {"paused", "stopped", "fault"} or
            type(event["used"]) is not int or not 0 <= event["used"] <= MAX_PAGES or
            event["limit"] not in PAGE_LIMITS or
            event["current_url"] is not None and
            (type(event["current_url"]) is not str or len(event["current_url"]) > 2048) or
            type(event["observed_text"]) is not str or
            len(event["observed_text"]) > MAX_OBSERVED_TEXT):
            raise ValueError("Invalid Jr checkpoint")
        # The lease fields are optional (a legacy status has neither) but never loose.
        for key, allowed in (("lease_seconds", LEASE_SECONDS), ("presence", PRESENCE_VALUES)):
            if key in status:
                if status[key] not in allowed or isinstance(status[key], bool):
                    raise ValueError("Invalid Jr checkpoint")
                event[key] = status[key]
        with self.lock:
            data = self._load()
            thread = data["threads"].get(thread_id)
            if type(thread) is not dict:
                raise KeyError("No such Jr conversation")
            if len(thread["checkpoints"]) >= 1000:
                raise HistoryError("Jr conversation has too many checkpoints")
            thread["checkpoints"].append(event)
            thread["updated"] = event["time"]
            self._save(data)

    def create_video(self, url: str, title: str) -> str:
        if (type(url) is not str or not url.strip() or len(url) > 2048 or
            type(title) is not str or len(title) > 200):
            raise ValueError("Invalid Jr video thread")
        question = ("Video: " + (title.strip() or url))[:6000]
        return self.create_plan(question, {"kind": "video", "url": url, "title": title})

    def video_checkpoint(self, thread_id: str, record: dict, synopsis: dict) -> None:
        if type(record) is not dict or not _valid_synopsis(synopsis):
            raise ValueError("Invalid Jr video checkpoint")
        event = {"time": self.clock(), "phase": "video", "kind": "video",
                 "url": record.get("url"), "title": record.get("title"),
                 "file_name": record.get("file_name"), "duration": record.get("duration"),
                 "size": record.get("size"), "sha256": record.get("sha256"),
                 "frame_count": record.get("frame_count"),
                 "transcript_source": record.get("transcript_source"),
                 "transcript_excerpt": str(record.get("transcript", ""))[:MAX_EXCERPT],
                 "synopsis": copy.deepcopy(synopsis)}
        if (type(event["url"]) is not str or not 0 < len(event["url"]) <= 2048 or
            type(event["title"]) is not str or len(event["title"]) > 200 or
            type(event["file_name"]) is not str or not 0 < len(event["file_name"]) <= 255 or
            type(event["duration"]) not in {int, float} or not 0 < event["duration"] <= 14400 or
            type(event["size"]) is not int or event["size"] <= 0 or
            type(event["sha256"]) is not str or len(event["sha256"]) != 64 or
            any(c not in "0123456789abcdef" for c in event["sha256"]) or
            type(event["frame_count"]) is not int or
            not 0 <= event["frame_count"] <= MAX_VIDEO_FRAMES or
            event["transcript_source"] not in {"subtitles", "whisper", "none"}):
            raise ValueError("Invalid Jr video checkpoint")
        with self.lock:
            data = self._load()
            thread = data["threads"].get(thread_id)
            if type(thread) is not dict:
                raise KeyError("No such Jr conversation")
            if len(thread["checkpoints"]) >= 1000:
                raise HistoryError("Jr conversation has too many checkpoints")
            thread["checkpoints"].append(event)
            thread["updated"] = event["time"]
            self._save(data)

    def hosted_checkpoint(self, thread_id: str, result: dict) -> None:
        """Record that a checkpoint's text went to the hosted model and what came back."""
        if type(result) is not dict:
            raise ValueError("Invalid Jr hosted checkpoint")
        event = {"time": self.clock(), "phase": "hosted", "kind": "hosted",
                 "model": result.get("model"), "cost_usd": result.get("cost_usd"),
                 "cost_verified": result.get("cost_verified"),
                 "payload_sha256": result.get("payload_sha256"),
                 "answer_excerpt": str(result.get("answer", ""))[:MAX_EXCERPT]}
        if (type(event["model"]) is not str or not 0 < len(event["model"]) <= 80 or
            type(event["cost_usd"]) is not str or not 0 < len(event["cost_usd"]) <= 32 or
            any(c not in "0123456789." for c in event["cost_usd"]) or
            type(event["cost_verified"]) is not bool or
            type(event["payload_sha256"]) is not str or len(event["payload_sha256"]) != 64 or
            any(c not in "0123456789abcdef" for c in event["payload_sha256"]) or
            not event["answer_excerpt"].strip()):
            raise ValueError("Invalid Jr hosted checkpoint")
        with self.lock:
            data = self._load()
            thread = data["threads"].get(thread_id)
            if type(thread) is not dict:
                raise KeyError("No such Jr conversation")
            if len(thread["checkpoints"]) >= 1000:
                raise HistoryError("Jr conversation has too many checkpoints")
            thread["checkpoints"].append(event)
            thread["updated"] = event["time"]
            self._save(data)

    def set_synopsis(self, thread_id: str, synopsis: dict) -> None:
        if not _valid_synopsis(synopsis):
            raise ValueError("Invalid Jr synopsis")
        with self.lock:
            data = self._load()
            thread = data["threads"].get(thread_id)
            if (type(thread) is not dict or not thread["checkpoints"] or
                thread["checkpoints"][-1]["phase"] not in {"paused", "stopped"}):
                raise HistoryError("No paused or stopped Jr checkpoint")
            thread["checkpoints"][-1]["synopsis"] = copy.deepcopy(synopsis)
            thread["updated"] = self.clock()
            self._save(data)

    def list_threads(self):
        with self.lock:
            rows = self._load()["threads"].values()
            return sorted(({"id": row["id"], "title": row["question"][:80],
                            "updated": row["updated"]} for row in rows),
                          key=lambda row: row["updated"], reverse=True)

    def get_thread(self, thread_id: str):
        with self.lock:
            thread = self._load()["threads"].get(thread_id)
            return copy.deepcopy(thread) if thread is not None else None
