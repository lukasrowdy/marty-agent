"""
PostToolUse hook: appends one short, structured line per tool call to
dashboard/activity.jsonl, so the Marty Status Dashboard's "who's working
now" panel can show genuinely real, automatically-captured activity
instead of a manually-updated status.json blob.

Reads the hook's stdin JSON (tool_name, tool_input, tool_response),
writes one compact summary line, and exits 0 no matter what happens --
a broken or slow logger must never block or fail the tool call it is
observing. No full tool input/output is ever written, only a short
one-line summary, so this stays lightweight and never leaks large
payloads (file contents, command output) into the log.

"desc" (2026-09-26, tool privacy): for Bash, PowerShell, Agent and Task, the one-line description
the call carried, when it had one. The dashboard never serves "summary" (it can hold a command, a
path, a URL, a query or a message body); it serves live_feed.activity_label(row), which may show
"desc" and nothing else of the input. Without "desc" a Bash row's summary could be either the
description or the raw command, so the page could only say "Running a command".
"""
import json
import os
import sys
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "activity.jsonl")
MAX_SUMMARY_LEN = 140
DESCRIBED = ("Bash", "PowerShell", "Agent", "Task")     # the same set as live_feed.DESCRIBED


def _truncate(s, n=MAX_SUMMARY_LEN):
    s = " ".join(str(s).split())  # collapse newlines/whitespace
    return s if len(s) <= n else s[: n - 1] + "…"


def summarize(tool_name, tool_input):
    ti = tool_input or {}
    if tool_name == "Bash":
        return _truncate(ti.get("description") or ti.get("command") or "ran a shell command")
    if tool_name in ("Read", "Glob", "Grep"):
        target = ti.get("file_path") or ti.get("pattern") or ti.get("path") or ""
        return _truncate(f"{tool_name}: {target}")
    if tool_name in ("Edit", "Write", "NotebookEdit"):
        return _truncate(f"{tool_name}: {ti.get('file_path', '')}")
    if tool_name == "Agent":
        return _truncate(f"launched agent: {ti.get('description', '')}")
    if tool_name == "WebFetch":
        return _truncate(f"fetched: {ti.get('url', '')}")
    if tool_name == "WebSearch":
        return _truncate(f"searched: {ti.get('query', '')}")
    # Generic fallback: first string-ish value in the input, else just the tool name.
    for v in ti.values():
        if isinstance(v, str) and v.strip():
            return _truncate(f"{tool_name}: {v}")
    return tool_name


def description(tool_name, tool_input):
    """The call's own one-line description, for DESCRIBED tools only; "" otherwise."""
    if tool_name not in DESCRIBED or not isinstance(tool_input, dict):
        return ""
    desc = tool_input.get("description")
    return _truncate(desc) if isinstance(desc, str) and desc.strip() else ""


def main():
    try:
        payload = json.load(sys.stdin)
        tool_name = payload.get("tool_name", "unknown")
        summary = summarize(tool_name, payload.get("tool_input"))
        row = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": tool_name,
            "summary": summary,
        }
        desc = description(tool_name, payload.get("tool_input"))
        if desc:
            row["desc"] = desc
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass  # logging must never break the tool call it observes
    sys.exit(0)


if __name__ == "__main__":
    main()
