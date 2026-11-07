"""
Read-only MCP adapter for Marty's local tools (2026-09-25).

The dashboard's FREE lane runs on the Claude Max subscription CLI (`claude -p`, $0
marginal). Talk-only, it was safe by having no tools at all (`--tools ""`). To give that
lane Marty's READ-ONLY tools WITHOUT exposing Claude Code's native write/run/edit tools,
this file is a minimal stdio MCP server: the CLI loads it with --mcp-config, and the only
tools it can reach are the ones advertised here. This lane also powers voice, so a
filesystem write or a shell escape through it would be unacceptable - hence read-only,
local, no-network only.

What it does:
  - speaks JSON-RPC 2.0 over stdin/stdout, one message per line (MCP stdio transport);
  - advertises ONLY a fixed READ-ONLY LOCAL allowlist (ALLOWLIST below), taken from
    marty_tools.anthropic_tools() and filtered. web_fetch, recon_lookup and recon_probe
    (network) are excluded on purpose;
  - dispatches every call through marty_tools.execute_tool(name, args, cloud_cfg()), which
    enforces the scope in Python BEFORE any file opens (the same Fence the metered lane
    uses), builds cloud_cfg() FRESH per call, and closes the Secure Folder and the lane log;
  - HARDCODES the scope to marty_tools' own SCOPE_FILE. No scope path is ever read from
    argv or the environment. A missing or malformed scope authorizes nothing (load_scope
    fails closed), so every call is refused rather than let through;
  - never crashes the lane: a bad request, an unknown tool, or an exception inside a tool
    all come back as a REFUSED/ERROR text result, and the loop keeps running.

No external dependencies (the `mcp` SDK is not installed on this PC); the protocol is
hand-rolled. Run by the CLI as:
    <system python> C:/Users/{{WIN_USER}}/my-agent/tools/marty_tools_mcp.py
"""

import json
import sys

import marty_tools   # same folder; on sys.path as this script's own dir

# The ONLY tools this adapter exposes: read-only, local, no network. Anything not here is
# refused even if marty_tools defines it (web_fetch, recon_lookup, recon_probe are omitted).
ALLOWLIST = {
    "read_file", "list_dir", "search_notes", "search_vault",
    "see_image", "transcribe_media", "see_video_frame",
    "avatar_roster", "avatar_cost",
}

PROTOCOL_VERSION = "2025-06-18"   # fallback; we echo the client's requested version when given
SERVER_INFO = {"name": "marty", "version": "1.0.0"}


def _log(msg):
    """Diagnostics go to stderr only. stdout carries JSON-RPC and nothing else."""
    try:
        sys.stderr.write(f"[marty-mcp] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _mcp_tools():
    """The allowlisted tools in MCP shape: input_schema -> inputSchema."""
    out = []
    for t in marty_tools.anthropic_tools():
        if t["name"] not in ALLOWLIST:
            continue
        out.append({
            "name": t["name"],
            "description": t.get("description", ""),
            "inputSchema": t.get("input_schema", {"type": "object", "properties": {}}),
        })
    return out


def _call_tool(name, args):
    """Run one allowlisted tool through marty_tools' Fence. Returns an MCP result dict.
    Never raises: a refused/errored tool comes back as an isError text result, and an
    unexpected exception is caught and returned as text so the lane stays up."""
    if name not in ALLOWLIST:
        return {"content": [{"type": "text",
                             "text": f"REFUSED: {name} is not available in this read-only lane."}],
                "isError": True}
    try:
        # cloud_cfg() FRESH each call, hardcoded to marty_tools.SCOPE_FILE. A missing/malformed
        # scope makes this authorize nothing, so the call is refused, not let through.
        cfg = marty_tools.cloud_cfg()
        result = marty_tools.execute_tool(name, args if isinstance(args, dict) else {}, cfg)
        text = str(result)
    except Exception as e:                       # backstop: never crash the lane
        text = f"ERROR: {type(e).__name__}: {e}"
    is_error = text.startswith("REFUSED:") or text.startswith("ERROR:")
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _handle(msg):
    """Map one JSON-RPC request to a result. Returns the result object for the "result" field,
    or raises _RpcError for a JSON-RPC error. Notifications (no id) return None."""
    method = msg.get("method")
    params = msg.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion")
        return {
            "protocolVersion": requested if isinstance(requested, str) and requested else PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }
    if method in ("notifications/initialized", "initialized"):
        return None                              # notification: no response
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": _mcp_tools()}
    if method == "tools/call":
        name = params.get("name") or ""
        args = params.get("arguments")
        return _call_tool(name, args)
    raise _RpcError(-32601, f"method not found: {method}")


class _RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def _write(obj):
    """One JSON-RPC message, newline-delimited, as UTF-8 bytes on stdout. Bytes (not text
    mode) so Windows never rewrites the newline and nothing but protocol reaches stdout."""
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(data + b"\n")
    sys.stdout.buffer.flush()


def main():
    _log(f"read-only MCP adapter up; tools: {sorted(ALLOWLIST)}")
    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            _write({"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"}})
            continue
        mid = msg.get("id")
        try:
            result = _handle(msg)
        except _RpcError as e:
            if mid is not None:
                _write({"jsonrpc": "2.0", "id": mid, "error": {"code": e.code, "message": e.message}})
            continue
        except Exception as e:                   # never let one bad message kill the loop
            _log(f"unhandled: {type(e).__name__}: {e}")
            if mid is not None:
                _write({"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32603, "message": f"internal error: {type(e).__name__}"}})
            continue
        if mid is None:
            continue                             # notification: nothing to send back
        _write({"jsonrpc": "2.0", "id": mid, "result": result})
    _log("stdin closed; exiting")


if __name__ == "__main__":
    main()
