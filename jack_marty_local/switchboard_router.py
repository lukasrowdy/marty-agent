"""Fail-closed routing: redact sensitive text locally before any Marty/cloud handoff."""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
GATEKEEPER_MODEL = "gatekeeper-proxy"
GATEKEEPER_SYSTEM = (
    "Perform deterministic linguistic abstraction on the supplied task. Replace sensitive "
    "identifiers, personal information, infrastructure names, hostnames, IP addresses, "
    "email addresses, paths and other designated details with neutral placeholders. Preserve "
    "the legitimate meaning, structure and formatting. Return only transformed text, without "
    "an introduction or conclusion. This transformation is not authorization and must not "
    "change a refusal or disguise the purpose of a request."
)

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![\w-]|\.[A-Za-z0-9])")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
HOST_RE = re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|local|lan|home|internal|test)(?![\w-]|\.[A-Za-z0-9])")
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]*")
MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
SENSITIVE_WORDS_RE = re.compile(r"(?i)\b(?:private|confidential|local.only|family media|raw footage|source video|credential|api key|password)\b")


@dataclass(frozen=True)
class Authorization:
    allowed: bool
    target_authorized: bool = False
    permissions: tuple[str, ...] = ()
    reason: str = ""


def sensitive_tokens(text: str) -> list[str]:
    found = EMAIL_RE.findall(text) + IP_RE.findall(text) + HOST_RE.findall(text) + WINDOWS_PATH_RE.findall(text) + MAC_RE.findall(text)
    return sorted(set(found), key=str.casefold)


def requires_abstraction(raw_user_prompt: str, designated_target_brain: str, marked_sensitive: bool = False) -> bool:
    if marked_sensitive:
        return True
    if designated_target_brain.casefold() in {"marty", "claude", "cloud"} and sensitive_tokens(raw_user_prompt):
        return True
    return bool(SENSITIVE_WORDS_RE.search(raw_user_prompt)) and designated_target_brain.casefold() in {"marty", "claude", "cloud"}


def call_gatekeeper(prompt: str, model: str = GATEKEEPER_MODEL, timeout: int = 180) -> str:
    body = {
        "model": model,
        "system": GATEKEEPER_SYSTEM,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {"temperature": 0.1, "top_k": 10, "top_p": 0.5, "num_ctx": 4096, "num_predict": 512, "stop": ["<|im_end|>"]},
    }
    req = urllib.request.Request(OLLAMA_ENDPOINT, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))
    transformed = result.get("response")
    if not isinstance(transformed, str) or not transformed.strip():
        raise RuntimeError("gatekeeper returned an empty or malformed response")
    return transformed.strip()


def _failed(reason: str) -> dict:
    return {"status": "blocked", "target": None, "text": None, "error": reason, "abstraction": "failed"}


def evaluate_and_route_security_query(
    raw_user_prompt: str,
    designated_target_brain: str,
    *,
    authorization: Authorization | None = None,
    marked_sensitive: bool = False,
    local_only: bool = False,
    sensitive_identifiers: tuple[str, ...] = (),
    gatekeeper: Callable[[str], str] | None = None,
    target_handler: Callable[[str], object] | None = None,
) -> dict:
    """Check authorization separately, sanitize when required, and fail closed on sanitizer errors."""
    prompt = raw_user_prompt if isinstance(raw_user_prompt, str) else ""
    if not isinstance(designated_target_brain, str):
        return _failed("target brain must be text")
    brain = designated_target_brain.casefold().strip()
    if not prompt.strip():
        return _failed("empty prompt")
    if brain not in {"jack", "marty", "claude", "cloud"}:
        return _failed("target brain is not allowlisted")
    if not isinstance(authorization, Authorization) or not authorization.allowed:
        return _failed(authorization.reason if isinstance(authorization, Authorization) and authorization.reason else "authorization denied")
    if not isinstance(sensitive_identifiers, (tuple, list)) or not all(isinstance(value, str) for value in sensitive_identifiers):
        return _failed("sensitive identifiers must be a list of text values")
    if not authorization.target_authorized:
        return _failed("target authorization is required")
    if brain != "jack" and local_only:
        return _failed("local-only content cannot be handed off")
    if brain != "jack" and "external-handoff" not in authorization.permissions:
        return _failed("authorization does not permit an external handoff")
    if brain == "jack" and marked_sensitive:
        # Explicit local-only processing keeps the original on the local lane.
        if target_handler is None:
            return _failed("local Jack handler is not configured")
        try:
            return {"status": "completed", "target": "jack", "text": target_handler(prompt),
                    "abstraction": "not-needed-local", "authorization": "allowed"}
        except Exception as exc:
            return _failed(f"local processing failed: {type(exc).__name__}")

    needs_cleaning = requires_abstraction(prompt, brain, marked_sensitive) or bool(sensitive_identifiers)
    outgoing = prompt
    abstraction = "not-needed"
    if needs_cleaning:
        try:
            outgoing = (gatekeeper or call_gatekeeper)(prompt)
        except Exception as exc:
            return _failed(f"abstraction unavailable: {type(exc).__name__}")
        if not isinstance(outgoing, str) or not outgoing.strip():
            return _failed("abstraction returned no valid text")
        leftovers = {value.casefold() for value in sensitive_tokens(prompt)}.intersection(
            value.casefold() for value in sensitive_tokens(outgoing))
        leftovers.update(value for value in sensitive_identifiers
                         if value and value.casefold() in outgoing.casefold())
        if leftovers:
            return _failed("abstraction incomplete; sensitive identifiers remain")
        abstraction = "completed"
    if target_handler is None:
        return {"status": "ready", "target": brain, "text": outgoing,
                "abstraction": abstraction, "authorization": "allowed"}
    try:
        response = target_handler(outgoing)
    except Exception as exc:
        return _failed(f"target handoff failed: {type(exc).__name__}")
    return {"status": "completed", "target": brain, "text": response,
            "abstraction": abstraction, "authorization": "allowed"}


def log_terminal_split_view(raw: str, clean: str, target: str, stream=None, *, redact_original: bool = False) -> None:
    """Show a side-by-side comparison without writing either value to disk."""
    stream = stream or sys.stdout
    width = shutil.get_terminal_size((100, 24)).columns
    column = max(20, min(56, (width - 5) // 2))
    color = bool(getattr(stream, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")
    reset, cyan, green, dim = ("\033[0m", "\033[36m", "\033[32m", "\033[2m") if color else ("", "", "", "")
    print(f"{dim}Target: {target}{reset}", file=stream)
    print(f"{cyan}{'ORIGINAL':<{column}} | {'TRANSFORMED':<{column}}{reset}", file=stream)
    left = textwrap.wrap("[redacted by caller]" if redact_original else raw, column) or [""]
    right = textwrap.wrap(clean, column) or [""]
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else ""
        b = right[index] if index < len(right) else ""
        print(f"{a:<{column}} | {green}{b:<{column}}{reset}", file=stream)


def main() -> int:
    print("This module is a restricted library; use agent_adapter.py for authorized processing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
