"""Narrow adapter between local Jack processing, the existing switchboard, and local tools."""
from __future__ import annotations

import json
import os
import sys
import subprocess
import urllib.request
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
AGENT_ROOT = ROOT.parent
TOOLS_DIR = AGENT_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from . import index_vault, switchboard_router
except ImportError:
    import index_vault
    import switchboard_router

JACK_MODEL = os.environ.get("JACK_MODEL", "huihui_ai/qwen3.5-abliterated:35b-a3b").strip()
OLLAMA_GENERATE = "http://127.0.0.1:11434/api/generate"
PRIVATE_EXTENSIONS = {".mp4", ".mov", ".mkv", ".avi", ".jpg", ".jpeg", ".png", ".heic", ".wav", ".mp3", ".m4a"}


def local_jack_text(prompt: str, model: str | None = None, timeout: int = 300) -> str:
    selected = (model or JACK_MODEL).strip()
    if not selected:
        raise RuntimeError("JACK_MODEL is not configured")
    request_body = {"model": selected, "prompt": prompt, "stream": False, "think": False,
                    "options": {"num_ctx": 4096, "num_predict": 768}}
    request = urllib.request.Request(OLLAMA_GENERATE, data=json.dumps(request_body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))
    answer = result.get("response")
    if not isinstance(answer, str) or not answer.strip():
        raise RuntimeError("local model returned no text")
    return answer.strip()


def existing_marty_subscription_handoff(sanitized_text: str) -> str:
    """Reuse the installed subscription CLI; disable all tools and project discovery."""
    import switchboard
    binary = switchboard._which_full("claude")
    if not binary:
        raise RuntimeError("existing Claude subscription CLI is unavailable")
    working = ROOT / "runtime" / "subscription"
    working.mkdir(parents=True, exist_ok=True)
    system = (
        "You are Marty receiving an authorized sanitized task. Answer using only this text. "
        "You have no tools or source media. Do not infer redacted identifiers or ask for private source content."
    )
    args = [binary, "-p", "--model", "sonnet", "--output-format", "json",
            "--tools", "", "--safe-mode", "--strict-mcp-config", "--no-chrome",
            "--no-session-persistence", "--permission-prompts", "none",
            "--system-prompt", system]
    env = os.environ.copy()
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDECODE",
                "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"):
        env.pop(key, None)
    result = subprocess.run(args, input=sanitized_text, cwd=working, env=env,
                            capture_output=True, text=True, encoding="utf-8", timeout=240)
    try:
        value = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("subscription CLI did not return valid JSON") from exc
    if result.returncode or value.get("is_error") or not value.get("result"):
        raise RuntimeError("subscription handoff failed; check local Claude subscription authentication")
    return str(value["result"])


def execute_restricted_tool(operation: str, arguments: dict, authorization: switchboard_router.Authorization) -> dict:
    """Allow only named local indexing and offline capture parsing operations."""
    if not isinstance(authorization, switchboard_router.Authorization) or not authorization.allowed or not authorization.target_authorized:
        return {"status": "denied", "error": "target authorization denied"}
    if not isinstance(arguments, dict):
        return {"status": "denied", "error": "arguments must be an object"}
    if operation in {"index_document", "parse_capture"} and (set(arguments) != {"path"} or not isinstance(arguments.get("path"), str)):
        return {"status": "denied", "error": "the only accepted argument is a local path"}
    if operation == "index_document":
        if "index-technical-documents" not in authorization.permissions:
            return {"status": "denied", "error": "missing index-technical-documents permission"}
        result = index_vault.process_identity_mutations(arguments.get("path", ""))
        return {"status": "completed", "document": result["document"]["id"], "changed": result["changed"]}
    if operation == "parse_capture":
        if "parse-authorized-capture" not in authorization.permissions:
            return {"status": "denied", "error": "missing parse-authorized-capture permission"}
        try:
            from . import watch_pcap
        except ImportError:
            import watch_pcap
        capture = watch_pcap.authorized_capture_path(arguments.get("path", ""))
        endpoints = watch_pcap.parse_capture(capture)
        return {"status": "completed", "endpoints": endpoints}
    return {"status": "denied", "error": "operation is not in the restricted gateway allowlist"}


def process_private_source(
    source_path: str | Path,
    question: str,
    *,
    authorization: switchboard_router.Authorization,
    jack_processor: Callable[[Path, str], str],
    marty_sender: Callable[[str], object] | None = None,
    sanitized_handoff: str | None = None,
    gatekeeper: Callable[[str], str] | None = None,
) -> dict:
    """Keep source bytes on Jack's local handler; only a separate sanitized summary may go to Marty."""
    path = Path(source_path).resolve(strict=True)
    if not path.is_file():
        return {"status": "blocked", "error": "source is not a regular file"}
    if not authorization.allowed or not authorization.target_authorized:
        return {"status": "blocked", "error": authorization.reason or "target authorization denied"}
    try:
        local_result = jack_processor(path, question)
    except Exception as exc:
        return {"status": "failed", "local_result": None, "handoff": None,
                "error": f"Jack local processing failed: {type(exc).__name__}"}
    if not sanitized_handoff:
        return {"status": "completed_local", "local_result": local_result, "handoff": None}
    if marty_sender is None:
        return {"status": "completed_local", "local_result": local_result, "handoff": "not-configured"}
    routed = switchboard_router.evaluate_and_route_security_query(
        sanitized_handoff, "marty", authorization=authorization, marked_sensitive=True,
        gatekeeper=gatekeeper, target_handler=marty_sender,
    )
    if routed["status"] not in {"ready", "completed"}:
        return {"status": "completed_local", "local_result": local_result, "handoff": routed}
    return {"status": "completed", "local_result": local_result, "handoff": routed}


def process_security_message(
    prompt: str,
    target_brain: str,
    *,
    authorization: switchboard_router.Authorization,
    marked_sensitive: bool = False,
    gatekeeper: Callable[[str], str] | None = None,
    handoff: Callable[[str], object] | None = None,
) -> dict:
    selected = target_brain.casefold() if isinstance(target_brain, str) else ""
    if selected not in {"jack", "marty", "claude", "cloud"}:
        return {"status": "blocked", "target": None, "text": None,
                "error": "target brain is not allowlisted", "abstraction": "failed"}
    default_handler = local_jack_text if selected == "jack" else existing_marty_subscription_handoff
    return switchboard_router.evaluate_and_route_security_query(
        prompt, target_brain, authorization=authorization, marked_sensitive=marked_sensitive,
        gatekeeper=gatekeeper,
        target_handler=handoff or default_handler,
    )


def process_local_media_path(source_path: str | Path, question: str, local_media_handler: Callable[[Path, str], str]) -> str:
    """Pass only a local path to Jack's local media handler; never serialize file bytes."""
    path = Path(source_path).resolve(strict=True)
    if path.suffix.casefold() not in PRIVATE_EXTENSIONS:
        raise ValueError("media type is not allowlisted")
    if not path.is_file():
        raise ValueError("media path is not a regular file")
    return local_media_handler(path, question)
