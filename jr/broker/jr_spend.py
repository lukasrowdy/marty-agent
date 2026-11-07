"""Jr-only, fail-closed local ledger for owner-approved hosted requests.

This records Jr requests, not the provider account's total bill. Unknown
outcomes keep their full reservation. The provider project spend limit is a
separate control and should be set before any live key is used.

CHANGED 2026-09-28 (Jr overnight build, item 8 "video"), what and why:
- PRICES: a per-model price table. abliteration.ai's pinned text model stays at the
  conservative $5/$5 per 1M; the multimodal abliterated-model (the only one that takes
  image parts) is $1 in / $3 out per 1M (vendor pricing checked tonight). quote() and the
  usage-based settle now price by the request's model. The default stays the pinned model.
- Output ceiling raised from 2048 to 8192 tokens: Large V2 always reasons and reasoning
  tokens count against max_tokens, so 2048 risked an empty, charged answer. The $0.50
  per-request reservation ceiling in reserve() is unchanged; a max-size text request
  reserves about $0.17 under the new math.
- quote(max_bytes=...): a video preview counts base64 frame bytes in the reservation, so
  callers may raise the 32,000 byte request bound up to MAX_QUOTE_BYTES. The default is
  unchanged for text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading

from jr_history import DpapiProtector


MODEL = "abliterated-model-large-v2"
PRICE_INPUT_MICRO_PER_TOKEN = 5   # conservative $5 / 1M input tokens (pinned text model)
PRICE_OUTPUT_MICRO_PER_TOKEN = 5  # $5 / 1M output tokens
# (input micro-USD per token, output micro-USD per token) by model, abliteration.ai.
PRICES = {MODEL: (PRICE_INPUT_MICRO_PER_TOKEN, PRICE_OUTPUT_MICRO_PER_TOKEN),
          "abliterated-model": (1, 3)}
MAX_OUTPUT_TOKENS = 8192          # Large V2 reasons inside max_tokens; 2048 risked empty answers
MAX_QUOTE_BYTES = 4_000_000       # ceiling for quote(max_bytes=...); text keeps 32,000
DAILY_CAP_MICRO = 1_000_000       # $1 local Jr cap per UTC day
MONTHLY_CAP_MICRO = 5_000_000     # $5 local Jr cap per UTC month
MAX_FILE = 500_000
MAGIC = b"JR-INDEPENDENT-SPEND-1\n"
ENTROPY = b"jr-independent-spend-v1"


class SpendError(Exception):
    pass


def quote(outbound: dict, *, max_output_tokens: int, max_bytes: int = 32_000) -> dict:
    """Conservative local reservation, not a guarantee of provider billing."""
    if type(outbound) is not dict or outbound.get("model") not in PRICES:
        raise SpendError("Only Jr's pinned hosted models can be quoted")
    if type(max_output_tokens) is not int or not 1 <= max_output_tokens <= MAX_OUTPUT_TOKENS:
        raise SpendError(f"Hosted output limit must be 1 to {MAX_OUTPUT_TOKENS} tokens")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_QUOTE_BYTES:
        raise SpendError("Hosted request byte bound is invalid")
    raw = json.dumps(outbound, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > max_bytes:
        raise SpendError("Hosted request is too large")
    # UTF-8 byte count plus overhead is deliberately more conservative than
    # a token estimate (base64 frames count byte for byte). It does not
    # replace the provider-side project limit.
    price_in, price_out = PRICES[outbound["model"]]
    input_budget = len(raw) + 1024
    reserved = input_budget * price_in + max_output_tokens * price_out
    return {"model": outbound["model"], "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "input_token_budget": input_budget, "max_output_tokens": max_output_tokens,
            "reserved_micro_usd": reserved,
            "reserved_usd": str(Decimal(reserved) / 1_000_000)}


def _reported_micro(response: dict) -> int | None:
    if type(response) is not dict:
        return None
    amount = response.get("estimated_cost_usd")
    if amount is not None:
        try:
            value = Decimal(str(amount))
            if not value.is_finite() or value < 0:
                return None
            return int((value * 1_000_000).to_integral_value(rounding=ROUND_CEILING))
        except (InvalidOperation, ValueError):
            return None
    usage = response.get("usage")
    if type(usage) is not dict:
        return None
    incoming = usage.get("prompt_tokens", usage.get("input_tokens"))
    outgoing = usage.get("completion_tokens", usage.get("output_tokens"))
    if (type(incoming) is not int or type(outgoing) is not int or
        incoming < 0 or outgoing < 0):
        return None
    price_in, price_out = PRICES.get(response.get("model"), PRICES[MODEL])
    return incoming * price_in + outgoing * price_out


class JrSpend:
    def __init__(self, root: Path, *, protector=None, clock=None):
        self.root = Path(root)
        self.path = self.root / "spend.dpapi"
        self.marker = self.root / "spend.initialized"
        self.protector = protector or DpapiProtector(ENTROPY)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.lock = threading.RLock()

    def _load(self):
        if not self.path.exists():
            if self.marker.exists():
                raise SpendError("Jr spend ledger is missing")
            return {"version": 1, "entries": []}
        try:
            encrypted = self.path.read_bytes()
            if not encrypted or len(encrypted) > MAX_FILE:
                raise ValueError()
            plain = self.protector.decrypt(encrypted)
            if not plain.startswith(MAGIC):
                raise ValueError()
            data = json.loads(plain[len(MAGIC):])
            if (type(data) is not dict or data.get("version") != 1 or
                type(data.get("entries")) is not list or len(data["entries"]) > 2000):
                raise ValueError()
            for entry in data["entries"]:
                if (type(entry) is not dict or set(entry) !=
                    {"id", "day", "month", "payload_sha256", "reserved", "actual", "status"} or
                    type(entry["reserved"]) is not int or entry["reserved"] < 0 or
                    (entry["actual"] is not None and
                     (type(entry["actual"]) is not int or entry["actual"] < 0)) or
                    entry["status"] not in {"reserved", "settled"} or
                    type(entry["id"]) is not str or len(entry["id"]) != 32 or
                    type(entry["day"]) is not str or len(entry["day"]) != 10 or
                    type(entry["month"]) is not str or len(entry["month"]) != 7 or
                    type(entry["payload_sha256"]) is not str or
                    len(entry["payload_sha256"]) != 64):
                    raise ValueError()
            return data
        except Exception:
            raise SpendError("Jr spend ledger is unavailable or damaged") from None

    def _save(self, data):
        plain = MAGIC + json.dumps(data, separators=(",", ":")).encode("ascii")
        if len(plain) > MAX_FILE:
            raise SpendError("Jr spend ledger reached its size limit")
        encrypted = self.protector.encrypt(plain)
        if len(encrypted) > MAX_FILE:
            raise SpendError("Jr spend ledger reached its size limit")
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = self.root / (".spend-" + secrets.token_hex(12) + ".tmp")
        try:
            with open(temporary, "xb") as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if not self.marker.exists():
                with open(self.marker, "x", encoding="ascii") as marker:
                    marker.write("Jr independent spend v1\n")
                    marker.flush()
                    os.fsync(marker.fileno())
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _charge(entry):
        return entry["reserved"] if entry["status"] == "reserved" else entry["actual"]

    def summary(self):
        now = self.clock().astimezone(timezone.utc)
        day, month = now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")
        with self.lock:
            rows = self._load()["entries"]
            daily = sum(self._charge(row) for row in rows if row["day"] == day)
            monthly = sum(self._charge(row) for row in rows if row["month"] == month)
            pending = sum(1 for row in rows if row["status"] == "reserved")
        return {"day": day, "month": month,
                "daily_used_usd": str(Decimal(daily) / 1_000_000),
                "monthly_used_usd": str(Decimal(monthly) / 1_000_000),
                "daily_cap_usd": str(Decimal(DAILY_CAP_MICRO) / 1_000_000),
                "monthly_cap_usd": str(Decimal(MONTHLY_CAP_MICRO) / 1_000_000),
                "uncertain_requests": pending}

    def reserve(self, quoted: dict) -> str:
        if (type(quoted) is not dict or type(quoted.get("reserved_micro_usd")) is not int or
            not 0 < quoted["reserved_micro_usd"] <= 500_000 or
            type(quoted.get("payload_sha256")) is not str or
            len(quoted["payload_sha256"]) != 64):
            raise SpendError("Invalid Jr hosted cost reservation")
        now = self.clock().astimezone(timezone.utc)
        day, month = now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")
        with self.lock:
            data = self._load()
            rows = data["entries"]
            daily = sum(self._charge(row) for row in rows if row["day"] == day)
            monthly = sum(self._charge(row) for row in rows if row["month"] == month)
            amount = quoted["reserved_micro_usd"]
            if daily + amount > DAILY_CAP_MICRO or monthly + amount > MONTHLY_CAP_MICRO:
                raise SpendError("Jr hosted spend cap reached")
            if len(rows) >= 2000:
                raise SpendError("Jr spend ledger is full")
            request_id = secrets.token_hex(16)
            rows.append({"id": request_id, "day": day, "month": month,
                         "payload_sha256": quoted["payload_sha256"],
                         "reserved": amount, "actual": None, "status": "reserved"})
            self._save(data)
            return request_id

    def settle(self, request_id: str, provider_response: dict) -> bool:
        actual = _reported_micro(provider_response)
        if actual is None:
            return False  # Keep the full reservation until manual reconciliation.
        with self.lock:
            data = self._load()
            row = next((r for r in data["entries"] if r["id"] == request_id), None)
            if row is None or row["status"] != "reserved":
                raise SpendError("Unknown or already settled Jr hosted request")
            row["actual"] = actual
            row["status"] = "settled"
            self._save(data)
        return True
