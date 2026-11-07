"""
Marty Status Dashboard - lightweight local web server.

Serves a single-page dashboard reading:
  - status.json         (current activity, recent activity, scheduled routines)
  - backup-log.txt       (UNC network path, read-only, tolerant of failure)

Uses only the Python standard library (http.server). No external
dependencies, no Node/npm required.

Binds to 127.0.0.1 only (changed 2026-09-21, C2 of the security plan).
Phones reach it over the tailnet at https://{{TAILNET_HOST}},
where `tailscale serve` terminates TLS and proxies to this port. It is
deliberately unreachable from the LAN and from the internet - do not
rebind to 0.0.0.0, port-forward, or Funnel this.
"""

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
import socketserver
import subprocess
import threading
import sys
import time
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler

import chatjobs  # durable chat turns (2026-09-23); see its docstring
import dashboard_auth
try:
    import passkeys   # passkey sign-in (Phase 2, W5). Fails soft: passkeys.available() is False without dashboard/.venv
except Exception:     # passkeys.py itself missing or broken: the dashboard runs, the passkey UI never works
    passkeys = None
import intake   # chunked, resumable uploads (2026-09-22); spec in the vault: Ingest a Dashboard Upload
import jr_lane  # Marty Jr.'s lane (Phase 2, W2): marty-jr on 127.0.0.1:11434 only, fenced tools, in-memory jobs
import jr_store  # his encrypted history, lock and never-send list (Phase 2, W3 + W4)
import jr_teach  # "Teach Jr" (Phase 1): save a Marty answer into Jr's plaintext library (jr/library/taught)
import board  # Lukas's board (the Jobs tab's waiting / work / done), status/board.json + his taps
import live_feed  # Watch Marty work (2026-09-26): narration + step labels from the PC session, never tool data
import phase1
import tonight  # the pack quiz page, merged in from marty-portal 2026-09-21

LIVE_PORT = 8765
_env_port = os.getenv("MARTY_DASH_PORT")
PORT = int(_env_port) if (_env_port or "").isdigit() else LIVE_PORT  # env override for a throwaway test server; junk value falls back


def talk_sweep_allowed(port, environ) -> bool:
    """Only the live server (port 8765), or a server given its own MARTY_DASH_ROOT, sweeps the
    Talk temp folder at start. A throwaway server on another port that shares the live folder
    would otherwise delete the live server's in-flight audio."""
    return port == LIVE_PORT or bool(environ.get("MARTY_DASH_ROOT"))
DASHBOARD_DIR = os.path.abspath(os.environ.get("MARTY_DASH_ROOT") or os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.abspath(os.environ.get("MARTY_WEB_ROOT") or DASHBOARD_DIR)
AGENT_ROOT = os.path.abspath(os.environ.get("MARTY_AGENT_ROOT") or os.path.dirname(DASHBOARD_DIR))
STATUS_FILE = os.path.join(DASHBOARD_DIR, "status.json")
# Read the LOCAL backup log, not the NAS copy (changed 2026-09-21). This used to
# point at \\{{NAS_MODEL}}\home\Marty Backup\backup-log.txt, so every status poll opened an
# SMB connection to the NAS. At one poll per browser every few seconds that is
# constant traffic, and while the stored NAS credential was stale it meant roughly
# 1,900 failed logons overnight - enough to trip Synology's Account Protection and
# keep a corrected password failing. backup-marty.ps1 writes this local file first
# and copies it to the NAS afterwards, so the local one is the fresher of the two.
BACKUP_LOG_PATH = os.path.join(AGENT_ROOT, "logs", "backup-marty.log")
BACKUP_LOG_TAIL_LINES = 15
VOICE_RESULT_PATH = os.path.join(AGENT_ROOT, "logs", "voicecheck.json")
# A voice check older than this is treated as "not checked", not as healthy -
# a check that silently stopped running must be as visible as one that failed.
VOICE_RESULT_STALE_HOURS = 36
ACTIVITY_LOG_PATH = os.path.join(DASHBOARD_DIR, "activity.jsonl")
ACTIVITY_MAX_ROWS = 200  # generous read cap; the API trims to the requested limit
VENDOR_DIR = os.path.join(DASHBOARD_DIR, "vendor")
VENDOR_CONTENT_TYPES = {".js": "application/javascript; charset=utf-8"}

# Chat pane (Marty Console step 2) reuses switchboard's brains directly -- same pricing
# table, same Credential Manager key lookup, same meter.jsonl log.
# Since 2026-09-23 the CLAUDE route has tools (tools/marty_tools.py: read-only tools under
# tools/marty_tools.scope.json, Secure Folder excluded, 6 steps a turn) on Lukas's request.
# Gemini and GPT stay talk-only (CHAT_SYSTEM_PROMPT below), and so does Local (marty-local
# on this PC, see run_local_job). The Claude route used to be talk-only because this
# server sat on the LAN with no auth at all; since 2026-09-21 it is login-gated,
# loopback-bound and reached only over HTTPS on the tailnet, which is what made giving
# it tools a product decision rather than a safety hole. Lukas made it on 2026-09-23.
TOOLS_DIR = os.path.join(AGENT_ROOT, "tools")
sys.path.insert(0, TOOLS_DIR)
import switchboard  # noqa: E402
import marty_tools  # noqa: E402  tools for the chat pane's Claude lane (2026-09-23)
import jr_cloud  # noqa: E402  owner-approved, text-only helper for Jr
import fullmarty_client  # noqa: E402  the Full Marty worker's pipe (stdlib; the worker is its own process)
import speak  # noqa: E402  prepare_text / synthesize / SpeakError / MissingKeyError (Stage C, Marty's voice out)

# ---- Full Marty (Stage B, deployed 2026-09-30) -------------------------------------------------
# The phone lane with real read/write on the PC. Every write or command waits for a tap on an
# approval card. The worker is its own process (dashboard/fullmarty, supervised by
# run-marty-services.ps1, reached over \\.\pipe\marty-fullmarty); this server only gates and relays.
FULL_PIPE = fullmarty_client.DEFAULT_PIPE
FULL_KEY = os.path.join(AGENT_ROOT, "status", "full-marty.key")
FULL_AUDIT = os.path.join(AGENT_ROOT, "logs", "full-marty.log")
FULL_IDLE_SEC = 4 * 3600         # server-side idle lock (the worker enforces the same)
FULL_MAX_SEC = 12 * 3600         # and a hard ceiling
FULL_OWNER_LOGIN = "{{OWNER_GMAIL}}"   # Tailscale-User-Login that may use Full routes (DRAFT 2 item 4)
FULL_JSON_ROUTES = frozenset({"/api/full/unlock/options", "/api/full/unlock/verify", "/api/full/lock",
                              "/api/full/new", "/api/full/turn", "/api/full/answer", "/api/full/stop",
                              "/api/full/speak"})
BACKTALK_CONFIG = os.path.join(AGENT_ROOT, "backtalk", "backtalk.json")


def _speak_voice_id():
    """ElevenLabs voice id for Marty's spoken replies, read live from backtalk.json each call --
    not cached at startup, so a voice change there takes effect on the next reply, and voicecheck.py's
    own lesson (a stale/decoy id drifting silently) can't happen here. None if voice is unconfigured."""
    try:
        with open(BACKTALK_CONFIG, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    el = cfg.get("elevenlabs") or {}
    if not el.get("enabled"):
        return None
    return el.get("voice_id") or None

# device id -> {"epoch", "token_sha", "started", "last", "csrf"}. Hashes and random ids only.
_FULL = {}
_FULL_LOCK = threading.Lock()


def _full_audit(**fields):
    line = datetime.now().isoformat(timespec="seconds") + " " + " ".join(
        f"{k}={re.sub(r'[^A-Za-z0-9_.:@()/ -]', '_', str(v))[:80]}" for k, v in fields.items() if v is not None)
    try:
        with open(FULL_AUDIT, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _cookie_token(headers):
    """The session token from the COOKIE ONLY. Full routes never read Authorization."""
    raw = headers.get("Cookie", "") or ""
    try:
        jar = SimpleCookie()
        jar.load(raw)
    except Exception:
        return None
    m = jar.get(dashboard_auth.COOKIE_NAME)
    return m.value if m and m.value else None


def _device_row_for(token):
    """The live, unexpired device row this token belongs to, else None."""
    if not token:
        return None
    handle, _ended = dashboard_auth.resolve_detail(token)       # refuses revoked and ended logins
    if handle is None:
        return None
    digest = hashlib.sha256("".join(token.split()).encode("utf-8")).hexdigest()
    for r in dashboard_auth.list_devices():
        if not r.get("revoked_at") and hmac.compare_digest(r.get("token_sha256") or "", digest):
            return r
    return None


def _full_lock(device_id=None, why="lock"):
    """End Full unlock(s) here AND in the worker (pending cards deny, running turns stop)."""
    with _FULL_LOCK:
        ids = list(_FULL) if device_id is None else [device_id]
        for d in ids:
            _FULL.pop(d, None)
    try:
        fullmarty_client.call(FULL_KEY, "lock", pipe=FULL_PIPE, device=device_id, reason=why)
    except fullmarty_client.PipeRefused:
        pass                                         # no worker: nothing to stop
    _full_audit(event="lock", device=device_id if device_id is not None else "all", by=why)


def _full_sweep_loop():
    """Every 30 s: a revoked or ended device loses its Full unlock at once, and idle/age limits
    apply even when no request arrives."""
    while True:
        time.sleep(30)
        try:
            live = {r.get("id") for r in dashboard_auth.list_devices()
                    if not r.get("revoked_at") and dashboard_auth.expiry(r) is None}
            now = time.monotonic()
            with _FULL_LOCK:
                stale = [d for d, u in _FULL.items() if d not in live or now - u["last"] > FULL_IDLE_SEC
                         or now - u["started"] > FULL_MAX_SEC]
            for d in stale:
                _full_lock(d, "revoked-or-expired")
        except Exception:
            pass


CHAT_SYSTEM_PROMPT = (
    "You are Marty, Lukas's chief of staff, speaking through the chat pane on his "
    "Status Dashboard (Marty Console, step 2 of the build). This channel is "
    "talk-only for now: you have no tools, no file access, no vault retrieval, and "
    "no hands here -- just this conversation. If Lukas asks for something that "
    "needs real action, tell him plainly that this pane can't do it yet and to use "
    "the terminal/voice session for that until tool-use is wired in here. Files Lukas "
    "attaches in this pane are saved on his PC and logged for the terminal and voice "
    "Marty sessions, which read that log; this pane cannot open them, so acknowledge "
    "the file and say the next Marty session will pick it up."
)
# Tool-aware variant for the claude_sub_tools lane ONLY (2026-09-25). That lane is NOT
# talk-only: it carries the 9 read-only MCP tools (tools/marty_tools_mcp.py), so the
# talk-only CHAT_SYSTEM_PROMPT above ("you have no tools, no file access") is inaccurate
# for it and would make Marty refuse work he can actually do. Still no write, no shell,
# no network: those tools are not on this lane and the spawn has no native tools at all.
CHAT_SYSTEM_PROMPT_TOOLS = (
    "You are Marty, Lukas's chief of staff, speaking through the chat pane on his Status "
    "Dashboard (Marty Console). This lane has a small set of READ-ONLY tools: you can read "
    "files, list folders, search his notes and vault, look at images, transcribe audio or "
    "video, read a single video frame, and check the avatar roster and its cost. That is the "
    "whole toolset. You cannot write or edit files, run shell commands, reach the network or "
    "the web, schedule anything, or take any other action that changes the system, so if Lukas "
    "asks for one of those, tell him plainly and point him to the terminal or voice session. "
    "Your reads are scoped to what Lukas has allowed: some paths, including his Secure Folder "
    "and anything outside the allowed roots, will refuse to open, and that is expected, not a "
    "bug. Files Lukas attaches here are saved on his PC and logged for the terminal and voice "
    "Marty sessions; if one is outside your allowed scope, acknowledge it and say the next "
    "Marty session will pick it up."
)
CHAT_MODEL = switchboard.DEFAULTS["claude"]

# The brains the browser chat pane can talk to. Until 2026-09-22 Gemini, Grok and
# OpenRouter were reachable from the CLI and invisible in the browser, which is the
# documented "a capability that exists only on the command line does not exist"
# failure, third recurrence. It also meant every browser turn billed Claude Sonnet 5
# because nothing cheaper was on screen: the console project alone was $0.2252 of the
# $0.2380 spent on 2026-09-21.
#
# Grok is deliberately NOT here. Its one genuine exclusive is X search, which the chat
# pane cannot use, and on everything else it is beaten on price by Gemini Flash. A lane
# that is strictly dominated is a lane that only invites a wrong click.
#
# "local" is Marty's own local model, marty-local on Ollama (tools/Modelfile.marty-local):
# talk-only, $0, nothing leaves the machine. chatjobs keeps its turns in a conversation of
# their own and never sends them to a cloud brain.
CHAT_BRAINS = {
    "claude":     {"vendor": "claude",     "model": switchboard.DEFAULTS["claude"]},
    "gemini":     {"vendor": "gemini",     "model": switchboard.DEFAULTS["gemini"]},
    "openrouter": {"vendor": "openrouter", "model": switchboard.DEFAULTS["openrouter"]},
    "local":      {"vendor": "ollama",     "model": switchboard.DEFAULTS["ollama"]},
    # Subscription lanes (2026-09-23): frontier models at $0 marginal on Lukas's flat-rate
    # plans. Talk-only (no tools) - the labels say so, so the tools/metered Claude lane above
    # is never picked by mistake. gemini_sub is left out until Antigravity (agy) is installed.
    "claude_sub": {"vendor": "claude_sub", "model": switchboard.DEFAULTS["claude_sub"]},
    "codex_sub":  {"vendor": "codex_sub",  "model": switchboard.DEFAULTS["codex_sub"]},
    # Same Max subscription CLI as claude_sub ($0), but with Marty's READ-ONLY tools wired in
    # through the MCP adapter (tools/marty_tools_mcp.py). Native write/run/edit tools stay off.
    "claude_sub_tools": {"vendor": "claude_sub", "model": switchboard.DEFAULTS["claude_sub"]},
}
DEFAULT_BRAIN = "claude"
CHAT_ASK = {
    "claude": switchboard.ask_claude,
    "gemini": switchboard.ask_gemini,
    "openrouter": switchboard.ask_openrouter,
}
# The old synchronous /api/chat (a page that does not send async:true) waits this long.
CHAT_SYNC_WAIT_SEC = 15 * 60


def _stream_ollama(model, system, messages):
    """Use Ollama's real NDJSON stream and forward only model-emitted text."""
    system = switchboard.ollama_system(model, system)
    body = {"model": model,
            "messages": ([{"role": "system", "content": system}] if system else []) + messages,
            "stream": True}
    req = urllib.request.Request(f"{switchboard.OLLAMA}/api/chat",
                                 data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    parts, reported, usage = [], model, (0, 0)
    with urllib.request.urlopen(req, timeout=600) as response:
        for line in response:
            if chatjobs.cancel_requested():
                return "", reported, usage, True
            row = json.loads(line)
            token = row.get("message", {}).get("content", "")
            if token:
                parts.append(token)
                chatjobs.emit_current("delta", {"text": token})
            if row.get("done"):
                reported = row.get("model", model)
                usage = (row.get("prompt_eval_count", 0), row.get("eval_count", 0))
                break
    return "".join(parts), reported, usage, False


LANE_TIMEOUT = 600   # same ceiling as switchboard._run_cli; a stuck CLI can't hold a job slot
LANE_EXIT_WAIT = 20  # after a lane CLI's output ends, how long it may take to exit before it is stopped


class LaneIncomplete(Exception):
    """A subscription lane's CLI ran out of time (LANE_TIMEOUT) or never exited after its output
    ended (LANE_EXIT_WAIT). Whatever it streamed is kept, and the turn is reported as incomplete,
    never as a success (fast-follow 6, 2026-09-25)."""

    def __init__(self, partial, error, stop_reason):
        super().__init__(error)
        self.partial, self.error, self.stop_reason = partial, error, stop_reason


def _kill_tree(proc):
    """Stop a lane CLI and everything it started (the CLIs are node programs that can spawn
    helpers, and a helper holding the output pipe would keep a reader waiting). Never raises."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=15,
                           stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _popen_lines(argv, prompt, cwd):
    proc = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    chatjobs.register_current_process(proc)
    # Drain stderr on its own thread so a chatty CLI can't fill the pipe and stall stdout.
    proc.stderr_lines, proc.timed_out = [], False

    def _drain():
        for line in proc.stderr:
            if len(proc.stderr_lines) < 200:
                proc.stderr_lines.append(line)

    proc.stderr_thread = threading.Thread(target=_drain, daemon=True)
    proc.stderr_thread.start()

    def _expire():
        if proc.poll() is None:
            proc.timed_out = True
            _kill_tree(proc)

    proc.watchdog = threading.Timer(LANE_TIMEOUT, _expire)
    proc.watchdog.daemon = True
    proc.watchdog.start()
    proc.stdin.write(prompt)
    proc.stdin.close()
    return proc


def _finish_proc(proc):
    """Reap a lane CLI: wait for it, stop its watchdog, return (rc, drained stderr). A CLI still
    running LANE_EXIT_WAIT s after its output ended is stopped with everything it started, reaped,
    and reported as an error (proc.hung), instead of being left running (fast-follow 5)."""
    proc.hung = False
    try:
        rc = proc.wait(timeout=LANE_EXIT_WAIT)
    except subprocess.TimeoutExpired:
        proc.hung = True
        _kill_tree(proc)
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            rc = None
    finally:
        proc.watchdog.cancel()
    proc.stderr_thread.join(timeout=2)
    error = "".join(proc.stderr_lines).strip()
    if proc.timed_out:
        error = f"{os.path.basename(proc.args[0])} timed out after {LANE_TIMEOUT}s"
    elif proc.hung:
        error = f"{os.path.basename(proc.args[0])} did not exit within {LANE_EXIT_WAIT}s after its output ended, so it was stopped"
    return rc, error


def _incomplete(proc, error, partial):
    """The LaneIncomplete for a CLI that timed out or had to be stopped."""
    return LaneIncomplete((partial or "").strip(), error, "timeout" if proc.timed_out else "stopped")


# The read-only MCP adapter (tools/marty_tools_mcp.py) that gives the free Max lane Marty's
# local read-only tools WITHOUT exposing Claude Code's own write/run/edit tools. Full tool
# names are prefixed mcp__<server>__<tool>; the server is "marty" (tools/marty_mcp.json).
SUB_MCP_CONFIG = os.path.join(AGENT_ROOT, "tools", "marty_mcp.json")
SUB_MCP_TOOLS = ["mcp__marty__read_file", "mcp__marty__list_dir", "mcp__marty__search_notes",
                 "mcp__marty__search_vault", "mcp__marty__see_image", "mcp__marty__transcribe_media",
                 "mcp__marty__see_video_frame", "mcp__marty__avatar_roster", "mcp__marty__avatar_cost"]
# Native Claude Code tools, explicitly denied as defense in depth on top of the allowlist above.
# --permission-prompts none already auto-denies anything not allowlisted, but a default-mode CLI
# may auto-allow read-only built-ins (Read/Glob/Grep); --disallowedTools makes read/run/write/web
# a hard no regardless. Extra names that this CLI version does not ship are harmless.
SUB_NATIVE_DENY = ["Bash", "BashOutput", "KillShell", "KillBash", "Write", "Edit", "MultiEdit",
                   "NotebookEdit", "Read", "Glob", "Grep", "WebFetch", "WebSearch", "Task",
                   "TodoWrite", "SlashCommand", "ExitPlanMode", "ListMcpResources", "ReadMcpResource"]


def sub_argv(binary, model, system, tooled):
    """Build the exact argv for a claude_sub / claude_sub_tools spawn. Shared with
    tools/test_sub_tools_lockdown.py so the lockdown probe tests the REAL argv and fails on drift.

    SECURITY (2026-09-25): the tooled lane MUST pass `--tools ""` too. The user settings file
    (C:/Users/{{WIN_USER}}/.claude/settings.json) has an autoMode block, and autoMode is allow-by-default:
    it AUTO-APPROVES any built-in tool that is not explicitly denied, and it loads on every `claude`
    child spawn (--strict-mcp-config only fences MCP servers, not settings). So without `--tools ""`
    a native tool that is neither allow-listed nor deny-listed (CronCreate, ScheduleWakeup, Workflow,
    SendMessage, ...) EXECUTES - proven live: the lane ran CronList with permission_denials=[].
    Neither `--permission-mode manual`, `--setting-sources project,local`, nor a `--settings`
    autoMode override closed this (autoMode defaults to on with ~70 rules; -p mode silently ignores
    a bad settings shape). `--tools ""` removes the entire BUILT-IN tool set (so autoMode never sees
    a native tool to approve, and future native tools are excluded automatically), while the MCP
    tools from --mcp-config stay reachable and gated by --allowedTools. Verified: with `--tools ""`
    CronList is unavailable (no tool_use, model answers DENIED) yet mcp__marty__read_file still works.
    The old comment claimed `--tools ""` would kill the MCP tools too; that was untested and false.
    --allowedTools scopes the MCP surface to the 9; --disallowedTools is now redundant but kept as
    belt and suspenders. Auth (Max OAuth in the config dir) and the $0/plan=max path are untouched."""
    argv = [binary, "-p", "--output-format", "stream-json", "--verbose",
            "--include-partial-messages", "--permission-prompts", "none",
            "--strict-mcp-config", "--no-chrome", "--no-session-persistence",
            "--tools", ""]   # every BUILT-IN (native) tool off; deny-by-default over autoMode
    if tooled:
        # claude_sub_tools lane: Marty's read-only tools via the MCP adapter only. The MCP
        # allowlist is the sole tool surface; the native denylist is belt and suspenders on top
        # of --tools "". cwd stays SUBCLEAN, permission prompts stay off.
        argv += ["--mcp-config", SUB_MCP_CONFIG,
                 "--allowedTools", *SUB_MCP_TOOLS,
                 "--disallowedTools", *SUB_NATIVE_DENY]
    if model:
        argv += ["--model", model]
    if system:
        argv += ["--append-system-prompt", system]
    return argv


def _sub_step(row):
    """(label, tool name) when a stream-json row starts a tool call, else None. Only the tool's NAME is
    used (live_feed.step_label); its inputs never reach the page."""
    event = row.get("event") or {}
    block = event.get("content_block") or {}
    if event.get("type") == "content_block_start" and block.get("type") == "tool_use":
        name = str(block.get("name") or "")
        return live_feed.step_label(name), name, str(block.get("id") or "")
    return None


def _sub_tool_failed(row):
    """The tool_use ids whose results in this stream-json row are marked as errors (empty if none)."""
    if row.get("type") != "user":
        return []
    message = row.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    return [str(b.get("tool_use_id") or "") for b in content
            if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("is_error")]


# Labels for the metered Claude lane's tools (marty_tools names). Most are the same tools as the Max lane's
# MCP set (live_feed labels them as mcp__marty__<name>); these three are metered-only.
METERED_LABELS = {"recon_lookup": "Looking up an address", "recon_probe": "Checking a web server",
                  "web_fetch": "Reading a web page"}


def _metered_label(name):
    """The plain step label for a metered-lane tool name ("read_file" -> "Reading a file")."""
    name = str(name or "")
    return live_feed.LABELS.get("mcp__marty__" + name) or METERED_LABELS.get(name) or live_feed.step_label(name)


class _MeteredSteps:
    """Live steps for the metered Claude lane (2026-09-26 fix). marty_tools.claude_turn runs the whole
    tool loop and only returns its tool list at the end, so until now this lane sent no step events and
    its steps appeared only after a reload. Its injectable `call` is wrapped instead (marty_tools is not
    touched): when a reply asks for tools, each becomes a step at once; when the next call carries their
    results, any marked is_error (REFUSED or ERROR) turns its step red. Only the tool's NAME is used; its
    inputs and results never reach the page. `steps` is a plain record of each, kept for a turn that
    fails before claude_turn returns its own list.

    Fail soft: the steps are a display aid, and the API call is paid for either way. Nothing here may
    raise into claude_turn, which would then skip account(j), fail the turn and leave the tokens off
    the meter. Every piece of bookkeeping is guarded, and call() returns the API's reply untouched.

    A turn that fails part-way (a later API call raises) never returns claude_turn's usage total or
    tool list, so this also keeps (a) the usage of every call that did complete, summed exactly as
    claude_turn's account() sums it (field by field over switchboard.claude_usage's 5-tuple: input,
    output, cache_read, cache_write_5m, cache_write_1h, since the 2026-09-27 meter fix), for
    run_cloud_job to meter, and (b) the conversation claude_turn builds, whose tool results give each
    step its saved verdict (saved())."""

    def __init__(self, api=None):
        self.api = api                  # None: switchboard.claude_messages, looked up at call time
        self.steps, self.ids, self.failed = [], {}, set()
        self.convo = None               # claude_turn's own convo list (it appends to it in place)
        self.usage = [0, 0, 0, 0, 0]    # usage of the calls that completed, as claude_turn's 5-tuple
        self.reported = None            # the model the API reported, as account() keeps it

    @staticmethod
    def _guard(what, fn, *args):
        try:
            fn(*args)
        except Exception as e:           # log the type only: never tool text, never a key
            print(f"[chat] step {what} skipped: {type(e).__name__}")

    def _emit(self, name, n, error=False):
        # The label is worked out inside the guard too, so one bad step never stops the others.
        def send():
            data = {"label": _metered_label(name), "n": n}
            if error:
                data["error"] = True
            chatjobs.emit_current("step", data)
        self._guard("event", send)

    def _mark_failed(self, convo):
        for message in convo:
            if not isinstance(message, dict) or message.get("role") != "user":
                continue
            for tid in _sub_tool_failed({"type": "user", "message": message}):
                idx = self.ids.get(tid)
                if idx is not None and tid not in self.failed:
                    self.failed.add(tid)
                    self.steps[idx]["verdict"] = "ERROR"
                    self._emit(self.steps[idx]["tool"], idx + 1, error=True)

    def _record(self, j, convo):
        # claude_turn runs the tool calls of a reply that stopped for tool_use, except on its last,
        # tool-budget call (the CHECKIN note), whose tool calls it ignores.
        last = convo[-1] if convo else {}
        if (isinstance(j, dict) and j.get("stop_reason") == "tool_use"
                and not (isinstance(last, dict) and last.get("content") == marty_tools.CHECKIN)):
            for block in j.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    now = datetime.now().isoformat(timespec="seconds")
                    name = str(block.get("name") or "")
                    self.steps.append({"tool": name, "args": {}, "verdict": "OK", "chars": None,
                                       "started": now, "finished": now})
                    self.ids[str(block.get("id") or "")] = len(self.steps) - 1
                    self._emit(name, len(self.steps))

    @staticmethod
    def _usage_of(raw):
        """One reply's usage as the 5-tuple claude_turn sums (switchboard.claude_usage); a switchboard
        from before the meter fix has no claude_usage: input and output only, the rest 0."""
        to_tuple = getattr(switchboard, "claude_usage", None)
        if to_tuple is not None:
            return tuple(int(v or 0) for v in to_tuple(raw))[:5]
        u = raw or {}
        return int(u.get("input_tokens", 0) or 0), int(u.get("output_tokens", 0) or 0), 0, 0, 0

    def _count(self, j):
        # The same field-wise sum as claude_turn's account(j); the whole tuple is read before any is added.
        u = self._usage_of(j.get("usage"))
        self.reported = j.get("model", self.reported)
        self.usage = [a + b for a, b in zip(self.usage, u)]

    def saved(self):
        """The steps as a FAILED turn saves them. Each verdict comes from the tool result claude_turn
        recorded for that step (marty_tools._verdict on its text; is_error alone means ERROR), so a
        refused step is saved red even if its live red mark was skipped. A step with no recorded
        result never finished: ERROR. Names and verdicts only: never the tool's input or result text.
        If anything here fails, the live record is returned as it stands."""
        try:
            results = {}
            for message in self.convo or []:
                content = message.get("content") if isinstance(message, dict) and message.get("role") == "user" else None
                for b in content if isinstance(content, list) else []:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        text = b.get("content")
                        verdict = marty_tools._verdict(text) if isinstance(text, str) else "OK"
                        if b.get("is_error") and verdict == "OK":
                            verdict = "ERROR"
                        results[str(b.get("tool_use_id") or "")] = verdict
            id_at = {idx: tid for tid, idx in self.ids.items()}
            out = []
            for idx, step in enumerate(self.steps):
                verdict = results.get(id_at[idx], "ERROR") if idx in id_at else step.get("verdict")
                out.append(dict(step, args={}, verdict=verdict))
            return out
        except Exception as e:
            print(f"[chat] saved steps kept as shown: {type(e).__name__}")
            return self.steps

    def call(self, model, system, convo, key, **kwargs):
        self.convo = convo
        self._guard("bookkeeping", self._mark_failed, convo)
        j = (self.api or switchboard.claude_messages)(model, system, convo, key, **kwargs)
        self._guard("usage", self._count, j)
        self._guard("bookkeeping", self._record, j, convo)
        return j


def _meter_failed_turn(live, vendor, requested):
    """A metered Claude turn that raised part-way: the API calls that completed were paid for, but
    claude_turn's usage total never came back, so meter the sum live kept. Returns the cost (0.0 if
    nothing completed or the meter write fails; a failed write is logged by exception type only)."""
    if live is None or not any(live.usage):
        return 0.0
    # The whole 5-tuple, straight to record_call (it takes 2- or 5-tuples since the meter fix); a
    # switchboard from before it takes (input, output) only.
    usage = tuple(live.usage) if hasattr(switchboard, "claude_usage") else tuple(live.usage[:2])
    try:
        return float(switchboard.record_call(vendor, requested, live.reported or requested, usage,
                                             project="console", private=False) or 0)
    except Exception as e:
        print(f"[chat] meter write failed: {type(e).__name__}")
        return 0.0


def _stream_claude_sub(model, system, messages, tooled=False, steps=None):
    prompt = switchboard._flatten_messages(messages)
    binary = switchboard._which_full("claude")
    if not binary:
        raise switchboard.LaneError("claude not found on PATH")
    switchboard.SUBCLEAN.mkdir(exist_ok=True)
    argv = sub_argv(binary, model, system, tooled)
    proc = _popen_lines(argv, prompt, switchboard.SUBCLEAN)
    chunks, result, step_ids = [], None, {}
    usage, reported, list_cost = (0, 0), model or "claude", None
    for line in proc.stdout:
        if chatjobs.cancel_requested():
            try:
                proc.terminate()
            except OSError:
                pass
            break
        try:
            row = json.loads(line)
        except ValueError:
            continue
        step = _sub_step(row)
        if step is not None:
            now = datetime.now().isoformat(timespec="seconds")
            if steps is not None:
                steps.append({"tool": step[0], "args": {}, "verdict": "OK", "chars": None,
                              "started": now, "finished": now})
                step_ids[step[2]] = len(steps) - 1
            chatjobs.emit_current("step", {"label": step[0], "n": len(steps) if steps is not None else 0})
        elif steps:
            for tid in _sub_tool_failed(row):         # parallel calls: mark the step that failed
                idx = step_ids.get(tid)
                if idx is not None and steps[idx]["verdict"] != "error":
                    steps[idx]["verdict"] = "error"
                    chatjobs.emit_current("step", {"label": steps[idx]["tool"], "n": idx + 1, "error": True})
        event = row.get("event") or {}
        delta = event.get("delta") or {}
        if event.get("type") == "content_block_delta" and delta.get("type") == "text_delta":
            text = delta.get("text") or ""
            if text:
                chunks.append(text)
                chatjobs.emit_current("delta", {"text": text})
        if row.get("type") == "result":
            result = row
            raw_usage = row.get("usage") or {}
            usage = (raw_usage.get("input_tokens", 0), raw_usage.get("output_tokens", 0))
            reported = next(iter(row.get("modelUsage") or {}), None) or reported
            list_cost = row.get("total_cost_usd")
    rc, error = _finish_proc(proc)
    if chatjobs.cancel_requested():
        return "", reported, usage, {"plan": "max", "list_cost_usd": list_cost}, True
    if proc.timed_out or proc.hung:
        # Out of time, or never exited: what streamed is kept and marked incomplete, never
        # passed off as a finished reply (and a result row's text is never an error message).
        raise _incomplete(proc, error, "".join(chunks) or (result or {}).get("result") or "")
    if not result or result.get("is_error") or rc:
        raise switchboard.LaneError((result or {}).get("result") or error or f"claude exited {rc}")
    answer = result.get("result") or "".join(chunks)
    if not chunks and answer:
        chatjobs.emit_current("delta", {"text": answer})
    return answer, reported, usage, {"plan": "max", "list_cost_usd": list_cost}, False


def _stream_codex_sub(model, system, messages):
    import tempfile
    prompt = switchboard._flatten_messages(messages)
    if system:
        prompt = system + "\n\n" + prompt
    binary = switchboard._codex_bin()
    switchboard.SUBCLEAN.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        outfile = os.path.join(temp_dir, "last.txt")
        argv = [binary, "exec", "--skip-git-repo-check", "-s", "read-only", "--ephemeral",
                "--json", "-o", outfile]
        if model:
            argv += ["-m", model]
        proc = _popen_lines(argv, prompt, switchboard.SUBCLEAN)
        chunks = []
        for line in proc.stdout:
            if chatjobs.cancel_requested():
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
            try:
                row = json.loads(line)
            except ValueError:
                continue
            # Current Codex emits completed agent-message items.  Future builds may
            # expose delta events; accept those without changing the API.
            delta = row.get("delta")
            if isinstance(delta, str) and delta:
                chunks.append(delta)
                chatjobs.emit_current("delta", {"text": delta})
            item = row.get("item") or {}
            if row.get("type") == "item.completed" and item.get("type") == "agent_message":
                text = item.get("text") or ""
                if text and not chunks:
                    chunks.append(text)
                    chatjobs.emit_current("delta", {"text": text})
        rc, error = _finish_proc(proc)
        answer = ""
        if os.path.exists(outfile):
            with open(outfile, encoding="utf-8", errors="replace") as stream:
                answer = stream.read().strip()
    if chatjobs.cancel_requested():
        return "", model or "codex-default", (0, 0), {"plan": "plus"}, True
    if proc.timed_out or proc.hung:
        # Until 2026-09-25 a timeout after partial text came back as a success: the streamed
        # chunks were joined and returned. Now it is reported as incomplete, text kept.
        raise _incomplete(proc, error, "".join(chunks) or answer)
    if not answer:
        answer = "".join(chunks).strip()
    if not answer:
        raise switchboard.LaneError(error or f"codex exited {rc}")
    if not chunks:
        chatjobs.emit_current("delta", {"text": answer})
    return answer, model or "codex-default", (0, 0), {"plan": "plus"}, False


def run_local_job(brain, messages):
    """A Local turn: marty-local on this PC through switchboard's ollama brain. No key, no
    network, no tools, $0. The persona is handled exactly as the voice line's private mode
    does it (backtalk/brain.py ask_private_stream): the only system text sent is the cheat
    sheets (switchboard.local_knowledge), and switchboard.ask_ollama puts the Modelfile's
    own SYSTEM block in front of them, because a request system message REPLACES that block
    in Ollama rather than adding to it (switchboard.model_system). messages is the local
    thread's own history; chatjobs never sends these turns to a cloud brain."""
    model = CHAT_BRAINS["local"]["model"]
    question = messages[-1]["content"] if messages else ""
    if os.environ.get("MJ_TEST_MODE") == "1":
        for part in ("test ", "local ", "reply"):
            chatjobs.emit_current("delta", {"text": part})
            time.sleep(0.02)
        return {"status": "completed", "answer": "test local reply", "model": "test-local", "cost_usd": 0.0}
    try:
        system = switchboard.local_knowledge(question)
        answer, reported, usage, cancelled = _stream_ollama(model, system, messages)
    except Exception as e:
        # (2026-09-28) The exception's text can name a path on this PC (the Modelfile, a cheat sheet)
        # or quote Ollama's error; it goes to the server's log, and the page gets chatjobs' one fixed
        # message (the same line the CLI lanes show).
        print(f"[chat] local call failed (withheld from the page): {type(e).__name__}: {e}")
        return {"status": "failed", "answer": "", "error": chatjobs.PAGE_ERROR}
    if cancelled:
        return {"status": "cancelled", "answer": "", "model": reported, "cost_usd": 0.0}
    try:
        switchboard.record_call("ollama", model, reported, usage, project="console", private=True)
    except Exception as e:
        print(f"[chat] meter write failed: {type(e).__name__} {e}")
    answer = (answer or "").strip()
    if not answer:
        return {"status": "failed", "answer": "", "model": reported, "cost_usd": 0.0,
                "error": "the model returned an empty reply"}
    return {"status": "completed", "answer": answer, "model": reported, "cost_usd": 0.0}


def run_cloud_job(brain, messages):
    """A cloud brain's turn. messages is the cloud thread's own history (chatjobs never
    includes a Local turn in it). Claude has tools (marty_tools: the read-only set under
    tools/marty_tools.scope.json, Secure Folder excluded); Gemini and GPT are talk-only."""
    spec = CHAT_BRAINS[brain]
    if os.environ.get("MJ_TEST_MODE") == "1":
        for part in ("test ", brain, " reply"):
            chatjobs.emit_current("delta", {"text": part})
            time.sleep(0.02)
        return {"status": "completed", "answer": f"test {brain} reply", "model": "test", "cost_usd": 0.0, "tools": []}
    vendor, requested = spec["vendor"], spec["model"]
    tools_used = []
    extra = None
    live = None                                   # the metered Claude lane's _MeteredSteps, once it starts
    try:
        if vendor == "claude_sub":
            tooled = (brain == "claude_sub_tools")
            # claude_sub_tools has the 9 read-only MCP tools, so it gets the tool-aware prompt;
            # the plain talk-only claude_sub lane keeps the "no tools" CHAT_SYSTEM_PROMPT.
            sub_system = CHAT_SYSTEM_PROMPT_TOOLS if tooled else CHAT_SYSTEM_PROMPT
            answer, reported, usage, extra, cancelled = _stream_claude_sub(
                requested, sub_system, messages, tooled=tooled, steps=tools_used)
            if cancelled:
                return {"status": "cancelled", "answer": "", "model": reported, "cost_usd": 0.0}
        elif vendor == "codex_sub":
            answer, reported, usage, extra, cancelled = _stream_codex_sub(requested, CHAT_SYSTEM_PROMPT, messages)
            if cancelled:
                return {"status": "cancelled", "answer": "", "model": reported, "cost_usd": 0.0}
        elif vendor in switchboard.SUBS:
            # Flat-rate CLI lane: no API key, $0 marginal, talk-only. Returns a 4-tuple whose
            # last item is meter extras (list_cost_usd/plan). A failure raises LaneError, which
            # this except catches like any other, so a broken lane returns an error and the
            # server keeps running (it used to raise SystemExit, which this would have missed).
            answer, reported, usage, extra = switchboard.ASK_SUB[vendor](requested, CHAT_SYSTEM_PROMPT, messages)
        else:
            key, _key_name = switchboard.key_for(vendor, "itm")
            if brain == "claude":
                live = _MeteredSteps()            # a failed turn saves live.saved(); a finished one claude_turn's list
                answer, reported, usage, tools_used = marty_tools.claude_turn(messages, key, requested, call=live.call)
            else:
                answer, reported, usage = CHAT_ASK[vendor](requested, CHAT_SYSTEM_PROMPT, messages, key)
    except LaneIncomplete as e:
        # Timed out or stopped: never a success. The partial text is the job's reply (the page
        # keeps it and marks it incomplete); stop_reason says which.
        cost = _meter_failed_turn(live, vendor, requested)
        return {"status": "failed", "answer": e.partial, "stop_reason": e.stop_reason, "model": requested,
                "cost_usd": cost, "tools": live.saved() if live is not None else tools_used,
                "error": f"{e.error}. The reply is incomplete." if e.partial else f"chat call failed: {e.error}"}
    except Exception as e:
        failed = {"status": "failed", "answer": "", "error": f"chat call failed: {e}", "tools": tools_used}
        if live is not None:                      # metered Claude: meter what completed, save recorded verdicts
            failed.update(cost_usd=_meter_failed_turn(live, vendor, requested), tools=live.saved())
        return failed
    try:
        cost = switchboard.record_call(vendor, requested, reported, usage, project="console", private=False, extra=extra)
    except Exception as e:
        print(f"[chat] meter write failed: {type(e).__name__} {e}")
        cost = 0.0
    answer = (answer or "").strip()
    if not answer:
        return {"status": "failed", "answer": "", "model": reported, "cost_usd": float(cost or 0),
                "error": "the model returned an empty reply", "tools": tools_used}
    return {"status": "completed", "answer": answer, "model": reported, "cost_usd": float(cost or 0),
            "tools": tools_used}


CHAT_JOBS = None      # the chatjobs.Manager; built on first use (tests swap in their own)
_CHAT_JOBS_LOCK = threading.Lock()


def chat_jobs():
    global CHAT_JOBS
    with _CHAT_JOBS_LOCK:
        if CHAT_JOBS is None:
            CHAT_JOBS = chatjobs.Manager({"cloud": run_cloud_job, "local": run_local_job},
                                         brains=tuple(CHAT_BRAINS))
        return CHAT_JOBS


# Marty Jr. (Phase 2, W2). A lane of his own, separate from CHAT_BRAINS on purpose: it never
# goes through chatjobs (whose store is plaintext on disk), never touches switchboard's meter,
# and has no route to any cloud brain. His jobs are in memory; his threads and never-send list
# are in jr_store.EncryptedJrStore (W3/W4): encrypted at rest under my-agent/jr/history, locked
# at start, unlocked only by Lukas's passphrase (DashboardHandler._jr_gate answers 423 while
# locked). Locking drops the key and, through on_lock, every finished reply the lane holds.
# His microphone (POST /api/jr/talk, W3 voice) is transcribed on this PC by Talk's local Whisper
# behind the same gate, and its text goes back only to his own message box (_handle_jr_talk).
JR = None             # the jr_lane.JrLane; built on first use (tests swap in their own)
_JR_LOCK = threading.Lock()


def jr():
    global JR
    with _JR_LOCK:
        if JR is None:
            JR = jr_lane.JrLane(store=jr_store.EncryptedJrStore())
        return JR


def jr_history():
    """The lane's encrypted store, or None if the lane runs on any other store: the gate then
    fails closed. Makes sure the store's lock also purges the lane's finished replies."""
    lane = jr()
    store = lane.store
    if not isinstance(store, jr_store.EncryptedJrStore):
        return None
    with _JR_LOCK:
        if lane.purge_finished not in store.on_lock:
            store.on_lock.append(lane.purge_finished)
    return store


# Which device sessions typed the passphrase for the CURRENT unlock: sha256 of the session token
# -> the store's epoch (a fresh random id per unlock). Jr's history is one key on this server,
# but opening it on the PC must not open it on the phone: each device types the passphrase.
# Any lock (button, background, idle, logout, restart) starts a new epoch and so closes every
# session at once. Hashes only; the tokens themselves are never kept here.
_JR_SESSIONS = {}
_JR_SESSIONS_LOCK = threading.Lock()


def _jr_session_id(headers):
    token = dashboard_auth.token_from_headers(headers)
    return hashlib.sha256(token.encode("utf-8")).hexdigest() if token else None


def _jr_session_open(headers, store) -> bool:
    sid = _jr_session_id(headers)
    with _JR_SESSIONS_LOCK:
        return sid is not None and store.epoch is not None and _JR_SESSIONS.get(sid) == store.epoch


# Tool-privacy for Jr's cloud tap and practice-VM routes (2026-09-28): the page sees an
# exception's text only when it is one of these fixed messages. Anything else (a new message,
# a wrapped library error, an exception that could quote Jr's or the model's text) gets the
# route's generic line, and only the exception's type name is printed, never its text.
JR_CLOUD_ERRORS = re.compile("|".join(
    [re.escape(m) for m in (
        # jr_cloud.CloudError
        "Select text for the large model first.",
        "Use 1 to 6,000 characters of selected text.",
        "The selected text contains control characters.",
        "The large model's response exceeded the size limit.",
        "Provider returned a different model; the answer was discarded.",
        "The large model's answer exceeded the text limit and was discarded.",
        "The large model sent a response Jr could not verify.",
        "No Abliteration.ai key is connected. The cloud tap is off.",
        "Review a fresh request before sending.",
        "That preview expired or was already used. Review it again.",
        "The selected text is now on the never-send list. Nothing was sent.",
        "The large-model tap is busy or has reached its hourly limit.",
        "The provider key is missing; nothing was sent.",
        # this server's never-send refusal, and jr_store.handoff_check's ValueErrors
        "That text contains a never-send term. Nothing was sent.",
        "text must be a string",
        "units must be 'codepoint' or 'utf16'",
    )] + [
        r"The large model returned HTTP \d{3}; nothing was added to Jr\.",
        r"The large model connection failed \([A-Za-z_]\w{0,60}\)\.",
        r"text too long to check \(max \d{1,9} characters\)",
    ]))
JR_CLOUD_GENERIC = "The large-model tap hit an error on the PC; nothing was added to Jr."

JR_COMPUTER_ERRORS = frozenset((
    # jr_computer.ComputerError literals
    "Approval does not belong to this VM conversation",
    "Arguments must be an object",
    "Check-in does not belong to this session",
    "Choose a scroll direction",
    "Click needs an observed element token or x/y",
    "Computer call belongs to another conversation",
    "Continuation belongs to another VM session",
    "Coordinates must be inside the observed window",
    "Could not disconnect the VM before startup",
    "Driver did not return valid JSON",
    "Driver response exceeded its size limit",
    "Guest browsing guard could not be verified",
    "Guest driver call failed; check the VM practice session",
    "Guest firewall or browser guard changed; browsing refused",
    "Guest sharing is configured; practice is refused",
    "Guest sharing or passthrough is configured; practice is refused",
    "Guest starting",
    "Guest-to-host NAT access or forwarding changed; browsing refused",
    "Invalid element token",
    "Observe this window again for a current element token",
    "Power off the VM before starting a new session",
    "Previous cutoff is still running",
    "Provide completed, uncertain, next_steps and reason",
    "Scroll amount must be 1-10",
    "Stop the existing VM session before starting another",
    "Text must be at most 2000 characters",
    "That key is unavailable in supervised practice",
    "That shortcut is unavailable in supervised practice",
    "The VM account credential could not be unlocked",
    "The dedicated VM configuration changed",
    "The dedicated test VM is unavailable",
    "The guest desktop did not become ready",
    "The practice VM is not running",
    "The selected window changed; list windows again",
    "The supervised browser did not become ready",
    "The test VM could not start",
    "Unsupported action fields",
    "Unsupported offline action",
    "Use the current VM conversation, or stop and start a new session",
    "Use windows first and select a listed practice window",
    "VM controls are disabled",
    "VM could not be safely paused",
    "VM isolation changed; offline practice is refused",
    "VM isolation check failed; controls stopped",
    "VM network cable state could not be verified",
    "VM network disconnect could not be controlled",
    "VM session is not active",
    "VM startup was cancelled",
    # jr_action_checkpoint's CheckpointRequired / ValueError, re-raised as ComputerError
    "This approval belongs to a different task or user",
    "Stop the existing task before opening another",
    "That checkpoint is no longer current",
    "The displayed plan is fixed; request a new checkpoint to revise it",
    "Read a complete check-in before continuing",
    "Continuing could not be verified",
    "Paused for Lukas: explicit approval is required",
    "No running batch to pause",
    "A user and task are required",
    "Each check-in field needs concise, nonempty text",
    # jr_emergency_stop's shutdown_error
    "VM power-off could not be confirmed. Jr controls are disabled. "
    "In VirtualBox, power off Jr-Computer-Lab, then retry Emergency stop VM.",
))
JR_COMPUTER_START_GENERIC = "The practice VM hit an error on the PC; controls remain stopped"
JR_APPROVE_GENERIC = "Approval failed; controls remain stopped"
JR_WINDOW_WITHHELD = "a VM window (title withheld)"
# phase1.transcribe_bytes' own fixed failure texts; POST /api/talk shows any other failure as its
# exception's type name, because the transcriber's stderr/stdout can quote the recording.
TALK_FIXED_ERRORS = frozenset((
    "another transcription is already running",
    "local transcription environment is missing",
    "transcription stopped",
    "transcription failed",
))


def _jr_page_error(exc, route, allowed, generic):
    """The text a Jr cloud/VM route may show for exc: the message itself when it is one of the
    fixed texts in `allowed` (a compiled pattern, fullmatch, or a set), else `generic`. A
    withheld message is never printed; only the route and the exception's type name are."""
    text = str(exc)
    ok = (allowed.fullmatch(text) is not None) if hasattr(allowed, "fullmatch") else text in allowed
    if ok:
        return text
    print(f"[jr] {route}: error withheld from the page ({type(exc).__name__})")
    return generic


def _jr_computer_status_page(status):
    """MANAGER.status() as the page may see it. (2026-09-28) continuation.last_observed_title is the VM's
    own screen (a page title, a file name, a private word), so it reaches the page only when live_feed's
    one description rule (shown_or_none: plain words, no path, URL, secret shape or private name) would
    show it; otherwise the page gets JR_WINDOW_WITHHELD. Only the route and that a title was withheld are
    printed, never the title. Everything else in the status is served as it is."""
    cont = status.get("continuation") if isinstance(status, dict) else None
    if not isinstance(cont, dict):
        return status
    title = cont.get("last_observed_title")
    if title is None:
        return status
    shown = live_feed.shown_or_none(title)
    if shown is None:
        print("[jr] computer status: window title withheld from the page")
        shown = JR_WINDOW_WITHHELD
    return dict(status, continuation=dict(cont, last_observed_title=shown))


def _jr_session_bind(headers, store) -> None:
    sid = _jr_session_id(headers)
    if sid is None:
        return
    with _JR_SESSIONS_LOCK:
        for stale in [k for k, v in _JR_SESSIONS.items() if v != store.epoch]:
            del _JR_SESSIONS[stale]
        _JR_SESSIONS[sid] = store.epoch


def compute_spend(days=30):
    """Same aggregation as switchboard.py's cmd_spend, reused as JSON for the
    dashboard's Spend tab instead of printed to a terminal."""
    if not switchboard.METER.exists():
        return {"days": days, "total": 0.0, "unpriced_calls": 0, "by_brain": [], "by_project": [], "calls": 0}
    cutoff = datetime.now() - timedelta(days=days)
    by_brain, by_project = {}, {}
    total = unpriced = calls = 0
    for line in switchboard.METER.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if datetime.fromisoformat(row["ts"]) < cutoff:
            continue
        calls += 1
        if row["cost_usd"] is None:
            unpriced += 1
            continue
        total += row["cost_usd"]
        by_brain[row["brain"]] = by_brain.get(row["brain"], 0) + row["cost_usd"]
        by_project[row["project"]] = by_project.get(row["project"], 0) + row["cost_usd"]
    return {
        "days": days,
        "total": round(total, 4),
        "unpriced_calls": unpriced,
        "calls": calls,
        "by_brain": sorted(({"name": b, "cost": round(c, 4)} for b, c in by_brain.items()), key=lambda x: -x["cost"]),
        "by_project": sorted(({"name": p, "cost": round(c, 4)} for p, c in by_project.items()), key=lambda x: -x["cost"]),
    }

def read_activity(limit=30):
    """Tail of the real, automatically-captured tool-call log written by the
    PostToolUse hook (dashboard/log_activity.py). Every row here is a real
    action this session actually took -- nothing here is synthesized.

    Served as live_feed.activity_row (2026-09-26, tool privacy): {"ts", "tool",
    "summary"}, where summary is the step's plain label (plus the description
    Marty writes for Bash, PowerShell and helper agents), the rule GET /api/live
    uses. The logged summary itself (a command, a path, a URL, a query or a
    message body) stays in the file for Marty and is never served."""
    if not os.path.exists(ACTIVITY_LOG_PATH):
        return []
    rows = []
    try:
        with open(ACTIVITY_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()[-ACTIVITY_MAX_ROWS:]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = live_feed.activity_row(json.loads(line))
            except json.JSONDecodeError:
                continue
            if row is not None:
                rows.append(row)
    except OSError:
        return []
    rows.reverse()  # newest first
    return rows[:limit]


# CSRF gate (2026-09-25, skeptic gate on Phase 2 W2). Every POST passes _csrf_refusal()
# before anything else runs: Sec-Fetch-Site, when a browser sends it, must be
# "same-origin", and Origin, when present, must be this dashboard's own origin (the tailnet
# name, or loopback on the port this server is running on). Scripts and curl send neither
# header and are unaffected; a browser always sends them, so a page on another site cannot
# post here even if a cookie would ride along. JSON routes also require
# Content-Type: application/json, which a plain cross-site form cannot send; Jr's microphone
# route requires an audio/* type (AUDIO_POST_ROUTES), which a form cannot send either.
PUBLIC_ORIGIN = "https://{{TAILNET_HOST}}"
JARVIS_ORIGIN = PUBLIC_ORIGIN + ":10443"     # the Marty Jarvis page: same host, extra port, allowed to call the API


def allowed_origins():
    """PUBLIC_ORIGIN plus the Marty Jarvis page's :10443. In test mode (MJ_TEST_MODE=1, or the passkey
    tests' loopback origin is set) :10443 is dropped, so a test run never widens to it (review fix 11,
    2026-10-03)."""
    test = os.environ.get("MJ_TEST_MODE") == "1"
    if passkeys is not None:
        try:
            test = test or bool(getattr(passkeys, "_config", {}).get("test"))
        except Exception:
            pass
    return (PUBLIC_ORIGIN,) if test else (PUBLIC_ORIGIN, JARVIS_ORIGIN)
JSON_POST_ROUTES = frozenset({
    "/api/session", "/api/chat", "/api/chat/job", "/api/chat/new", "/api/upload/note", "/api/jr/job",
    "/api/jr/unlock", "/api/jr/never-send", "/api/jr/handoff-check",     # never-send is a PUT
    "/api/jr/computer/start", "/api/jr/computer/approve", "/api/jr/computer/stop",
    "/api/jr/cloud/preview", "/api/jr/cloud/send",
    "/api/jr/missing/dismiss", "/api/jr/teach", "/api/board/answer",
    "/api/passkey/login/options", "/api/passkey/login/verify",
    "/api/passkey/register/options", "/api/passkey/register/verify",
}) | FULL_JSON_ROUTES
# Marty Jr.'s microphone (Phase 2, W3 voice): the body is the recording itself. Only real audio
# types; Talk's application/octet-stream fallback is deliberately not accepted here.
AUDIO_POST_ROUTES = frozenset({"/api/jr/talk"})
JR_AUDIO_TYPES = frozenset(t for t in phase1.ALLOWED_AUDIO if t.startswith("audio/"))
# "Teach Jr": cap on the answer text a single teach may carry. Comfortably above any real
# chat answer, well under _read_json_body's 1 MB body ceiling.
JR_TEACH_MAX_TEXT = 60_000

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json; charset=utf-8"),
    "/sw.js": ("sw.js", "application/javascript; charset=utf-8"),
    "/offline.html": ("offline.html", "text/html; charset=utf-8"),   # the service worker's no-network page
}

# Pages that must show the login screen rather than a broken shell when the
# caller has no valid token. Anything serving an app UI belongs here; adding a
# page and forgetting it is how a page would silently render empty.
GATED_PAGES = ()


def read_status_json():
    """status.json, or {"error": <fixed line>}. (2026-09-28) The page never sees the file's path or the
    parser's detail: those go to the server's log."""
    try:
        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[status] status.json not found at {STATUS_FILE}")
        return {"error": "status.json not found"}
    except json.JSONDecodeError as e:
        print(f"[status] status.json is not valid JSON ({STATUS_FILE}): {e}")
        return {"error": "status.json is not valid JSON"}
    except OSError as e:
        print(f"[status] could not read status.json ({STATUS_FILE}): {type(e).__name__}: {e}")
        return {"error": "could not read status.json"}


def read_backup_log():
    try:
        with open(BACKUP_LOG_PATH, "r", encoding="utf-8-sig", errors="replace") as f:
            lines = f.readlines()
        tail = [line.rstrip("\n") for line in lines[-BACKUP_LOG_TAIL_LINES:]]
        return {"available": True, "path": BACKUP_LOG_PATH, "lines": tail}
    except (OSError, FileNotFoundError) as e:
        return {
            "available": False,
            "path": BACKUP_LOG_PATH,
            "error": f"backup log unavailable ({e.__class__.__name__})",
        }


def read_voice_check():
    """Read what tools/voicecheck.py last wrote. Three states, never two: ok,
    drifted, unknown. 'unknown' means the check could not be completed (no network,
    no key) and says nothing about the voice - reporting that as drift would train
    Lukas to ignore the badge."""
    try:
        with open(VOICE_RESULT_PATH, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
        state = data.get("state") or "unknown"
        ts = data.get("ts") or ""
        stale = False
        try:
            age = datetime.now().astimezone() - datetime.fromisoformat(ts)
            stale = age.total_seconds() > VOICE_RESULT_STALE_HOURS * 3600
        except (ValueError, TypeError):
            stale = True
        return {
            "available": True,
            "path": VOICE_RESULT_PATH,
            "state": state,
            "reason": data.get("reason") or "",
            "ts": ts,
            "stale": stale,
        }
    except (OSError, FileNotFoundError, ValueError) as e:
        return {
            "available": False,
            "path": VOICE_RESULT_PATH,
            "error": f"voice check has never run ({e.__class__.__name__})",
        }


def login_page():
    """Shown to anyone without a valid device token. Deliberately contains
    no dashboard content of any kind - this is what an unauthenticated
    stranger on the LAN sees."""
    enrolled = dashboard_auth.any_enrolled()
    hint = (
        "Paste your device token."
        if enrolled else
        "No devices are enrolled yet. On the machine running this, run:"
        " py setup_dashboard_auth.py enroll lukas"
    )
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Marty Status Dashboard - Locked</title>
<link rel="stylesheet" href="/style.css">
<style>
.login-wrap {{ max-width: 26rem; margin: 4rem auto 0; padding: 0 1.1rem; text-align: center; }}
.login-wrap .lock-sub {{ margin: 4px 0 20px; }}
.login-form {{ display: flex; flex-direction: column; gap: 10px; }}
.login-form input {{
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-primary); font-family: var(--font-sans); font-size: 1rem;
  padding: 10px 12px; text-align: center;
}}
.login-form input:focus {{ outline: none; border-color: var(--accent-cyan); }}
.login-form button {{
  appearance: none; background: var(--accent-cyan); border: 1px solid var(--accent-cyan);
  color: #ffffff; font-family: var(--font-sans); font-size: 0.9rem; font-weight: 600;
  padding: 10px 18px; border-radius: 6px; cursor: pointer;
}}
.login-form button:hover {{ opacity: 0.9; }}
#err {{ min-height: 1.2em; }}
</style>
</head>
<body>
<div class="viz-root">
  <header class="topbar">
    <h1>Marty Status Dashboard</h1>
  </header>
  <div class="login-wrap">
    <p class="lock-sub muted">Locked. {html.escape(hint)}</p>
    <div class="login-form">
      <input id="tok" type="password" autocomplete="off" autocapitalize="off"
             spellcheck="false" placeholder="device token">
      <button type="button" id="go">Unlock</button>
    </div>
    <p class="muted" id="err"></p>
  </div>
</div>
<script>
(function () {{
  var go = document.getElementById('go'), tok = document.getElementById('tok'),
      err = document.getElementById('err');
  function submit(value) {{
    var v = (value || tok.value).trim();
    if (!v) return;
    err.textContent = 'checking...';
    fetch('/api/session', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ token: v }})
    }}).then(function (r) {{ return r.json().then(function (d) {{ return [r.status, d]; }}); }})
      .then(function (p) {{
        if (p[0] === 200) {{ tok.value = ''; location.reload(); }}
        else {{ err.textContent = (p[1] && p[1].error) || 'That token was not accepted.'; }}
      }})
      .catch(function () {{ err.textContent = 'Network error.'; }});
  }}
  go.addEventListener('click', function () {{ submit(); }});
  tok.addEventListener('keydown', function (e) {{ if (e.key === 'Enter') submit(); }});
  // QR enrollment (setup_dashboard_auth.py enroll --qr): the scanned URL carries
  // the token in the fragment, which never reaches the server. Read it, scrub it
  // from the address bar and history BEFORE the request, then log in with it.
  var m = /(?:^#|[#&])token=([A-Za-z0-9_-]{{20,}})/.exec(location.hash || '');
  if (m) {{
    history.replaceState(null, '', location.pathname + location.search);
    submit(m[1]);
  }}
}})();
</script>
</body>
</html>"""


# Early answers (403 cross-site or cross-origin, 415, 401, 404, 501, a 413 on a small body)
# go out before the request body is read, and the connection then closes. A body byte that
# arrives after that close makes Windows answer with a TCP reset, and the reset throws away
# the answer the client has not read yet: the browser (or a test) gets WinError 10053/10054
# instead of the 403. It only needs the client to send its body a moment after its headers,
# which http.client always does (two sends). So finish() reads what is left of a small body,
# at most DRAIN_MAX bytes for at most DRAIN_SECONDS, after the answer has gone out and before
# the close. A bigger leftover is not read: that request is answered and closed as before
# (intake drains its own legitimately sized slices, _drain_body the jr-gated audio).
DRAIN_MAX = 64 * 1024
DRAIN_SECONDS = 2.0


class _CountingReader:
    """The request's rfile once its headers are parsed, counting the body bytes the handler
    reads, so finish() knows how much of the body is left. Every body reader here uses read()."""

    def __init__(self, reader):
        self.reader = reader
        self.consumed = 0

    def read(self, *args):
        data = self.reader.read(*args)
        self.consumed += len(data or b"")
        return data

    def read1(self, *args):
        data = self.reader.read1(*args)
        self.consumed += len(data or b"")
        return data

    def readline(self, *args):
        data = self.reader.readline(*args)
        self.consumed += len(data or b"")
        return data

    def readinto(self, buf):
        n = self.reader.readinto(buf)
        self.consumed += n or 0
        return n

    def __getattr__(self, name):
        return getattr(self.reader, name)


class DashboardHandler(BaseHTTPRequestHandler):
    # HTTP/1.0 on purpose, same as live: one request per connection. Keep-alive plus
    # responses that skip unread bodies (401/413) would let leftover bytes be parsed as
    # a second request behind tailscale serve. finish() drains a small leftover body
    # before the close (see DRAIN_MAX above), so those answers arrive instead of a reset.
    def parse_request(self):
        ok = super().parse_request()
        if ok:
            reader = self.rfile.reader if isinstance(self.rfile, _CountingReader) else self.rfile
            self.rfile = _CountingReader(reader)
        return ok

    def finish(self):
        try:
            self._drain_leftover_body()
        finally:
            if isinstance(self.rfile, _CountingReader):
                self.rfile = self.rfile.reader
            super().finish()

    def _drain_leftover_body(self):
        """Read and drop what is left of a body of at most DRAIN_MAX bytes, for at most
        DRAIN_SECONDS, once the answer has gone out. Never raises."""
        counted = self.rfile
        if not isinstance(counted, _CountingReader):
            return                      # the request line or headers never parsed
        try:
            left = int(self.headers.get("Content-Length") or 0) - counted.consumed
        except (TypeError, ValueError, AttributeError):
            return
        if not 0 < left <= DRAIN_MAX:
            return
        deadline = time.monotonic() + DRAIN_SECONDS
        try:
            self.wfile.flush()          # the answer first; the drain only delays the close
            while left > 0:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    return
                self.connection.settimeout(wait)
                chunk = counted.reader.read1(left)
                if not chunk:
                    return
                left -= len(chunk)
        except (OSError, ValueError):
            return

    def log_message(self, fmt, *args):
        # keep server console output minimal / readable, never log query
        # strings or bodies -- they can carry a token
        print("[%s] %s %s" % (self.log_date_time_string(), self.command,
                              self.path.split("?")[0]))

    _auth_ended = None   # "idle" | "age" when the last _auth() saw a device login that has ended
    _auth_presented = False   # True when the last _auth() saw a bearer token or a session cookie at all

    def _auth(self):
        """Single chokepoint. Returns the caller's handle, or None. Cookie and bearer alike go
        through dashboard_auth.resolve_detail(), which also refuses a device login that has
        ended (30 days unused, or 90 days old; 2026-09-26); the reason is kept for the 401.
        Whether any credential was presented is kept too (a bool, never the token): the refused
        line below is printed only for a credential that was rejected, not for a bare request."""
        if passkeys is not None:
            passkeys.maybe_reconcile()   # at most once a minute, never raises
        self._auth_presented = dashboard_auth.token_from_headers(self.headers) is not None
        handle, self._auth_ended = dashboard_auth.authenticate_detail(self.headers)
        return handle

    def _refused(self, kind, detail):
        """One log line per refused credential, for the C4 watcher's failed-auth rule (2026-09-28):
        "[<request-log stamp>] [auth] refused <kind> <detail>". kinds: bearer (a presented token or
        cookie the data routes rejected), page (a gated page shown the lock screen), session (POST
        /api/session), passkey (a passkey ceremony refused 401/403), jr (Marty Jr.'s passphrase).
        The detail is a fixed word, a route path without its query, or a passkey error code; never
        a token, a passphrase, a query string or a body."""
        print("[%s] [auth] refused %s %s" % (self.log_date_time_string(), kind, detail))

    def _send_auth_required(self):
        """The 401 for every data route. When the token was a real device login that has ended,
        "expired" says why ("idle" or "age"), so the page can say so on its lock screen. Nothing
        else is revealed: an unknown or revoked token gets the plain answer. The refused line is
        printed only when a credential was presented: the app shell's cookieless polls after a
        logout are not refused logins, and printing them would trip the watcher on every lock screen."""
        payload = {"error": "authentication required"}
        if self._auth_ended in ("idle", "age"):
            payload["expired"] = self._auth_ended
        if self._auth_presented:
            self._refused("bearer", "%s %s" % ("ended-" + self._auth_ended if self._auth_ended in ("idle", "age")
                                               else "rejected", self.path.split("?")[0]))
        self._send_json(payload, status=401)

    def _allowed_origins(self):
        port = self.server.server_address[1]
        allowed = {*allowed_origins(), f"http://127.0.0.1:{port}", f"http://localhost:{port}"}   # :10443 only outside test mode
        if passkeys is not None:
            try:
                allowed.update(passkeys.expected_origins())   # the passkey tests' loopback origin, when set
            except Exception:
                pass
        return allowed

    def _csrf_refusal(self, path):
        """None when this POST may proceed, else (status, message). See PUBLIC_ORIGIN above."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site.strip().lower() != "same-origin":
            return 403, "cross-site request refused"
        origin = self.headers.get("Origin")
        if origin is not None and origin.strip() not in self._allowed_origins():
            return 403, "cross-origin request refused"
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if path in JSON_POST_ROUTES and ctype != "application/json":
            return 415, "this route takes Content-Type: application/json"
        if path in AUDIO_POST_ROUTES and ctype not in JR_AUDIO_TYPES:
            return 415, "this route takes an audio Content-Type (audio/webm, audio/mp4, audio/mpeg or audio/wav)"
        return None

    def _send_json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, markup, status=200):
        body = markup.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filename, content_type):
        path = os.path.join(WEB_DIR, filename)
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404, "File not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Without this, these responses carry no Cache-Control, no ETag and no
        # Last-Modified, so browsers fall back to heuristic caching and happily
        # serve a stale app.js. That once hid a newly wired chat button on
        # Lukas's phone: the code was right, the browser was old. This dashboard
        # changes often enough that caching its own files
        # is never worth the confusion. (Vendored Three.js below is pinned and
        # unchanging, so it keeps its cacheability.)
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _send_vendor_file(self):
        # path is /vendor/<...> - resolve under VENDOR_DIR and reject anything that
        # escapes it (no "..", no absolute paths) before touching the filesystem.
        rel = self.path[len("/vendor/"):].split("?")[0]
        full = os.path.abspath(os.path.join(VENDOR_DIR, rel))
        if not full.startswith(os.path.abspath(VENDOR_DIR) + os.sep):
            self.send_error(403, "Forbidden")
            return
        ext = os.path.splitext(full)[1]
        content_type = VENDOR_CONTENT_TYPES.get(ext, "application/octet-stream")
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404, "File not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path.startswith("/icons/") and re.fullmatch(r"/icons/[a-z0-9_-]+\.png", path):
            self._send_file(path.lstrip("/"), "image/png")
            return

        # Tonight (the pack quiz) is rendered per handle, so it is not a static
        # file. Same gate as every other page: no token, login screen, nothing
        # else. It used to be a second server on 8788 with its own device list.
        if path in ("/tonight", "/ideas"):
            handle = self._auth()
            if handle is None:
                if self._auth_presented:   # a cookieless first visit is normal, not a refusal
                    self._refused("page", path)
                self._send_html(login_page(), status=401)
                return
            self._send_html(tonight.page(handle))
            return

        # Static assets carry no data of Lukas's, only presentation code --
        # served open so the login page itself has CSS/JS to render with.
        if path in STATIC_FILES:
            if path in GATED_PAGES and self._auth() is None:
                if self._auth_presented:   # a cookieless first visit is normal, not a refusal
                    self._refused("page", path)
                self._send_html(login_page(), status=401)
                return
            filename, content_type = STATIC_FILES[path]
            self._send_file(filename, content_type)
            return

        if path.startswith("/vendor/"):
            self._send_vendor_file()
            return

        # Full Marty (Stage B): its own gate (cookie only, exact Origin, Tailscale login, passkey
        # step-up, CSRF token), so it goes before the generic data gate.
        if path.startswith("/api/full/"):
            self._handle_full_get(path)
            return

        # Everything else is data. No valid token, no response body.
        if self._auth() is None:
            self._send_auth_required()
            return

        if path.startswith("/api/jr/"):
            self._handle_jr_get(path)
            return

        if path.startswith("/api/chat/stream/"):
            self._handle_chat_stream(path.rsplit("/", 1)[-1])
            return

        if path == "/api/jobs":
            self._send_json(phase1.jobs_payload(chat_jobs(), self._auth()))
            return

        if path == "/api/live":
            self._send_json(live_feed.payload())
            return

        if path == "/api/files":
            self._send_json(phase1.list_files())
            return

        if path.startswith("/api/files/"):
            self._handle_file_download(path.rsplit("/", 1)[-1])
            return

        if path == "/api/upload/status":
            uid = self._query_id()
            if uid is None:
                self._send_json({"error": "bad id"}, status=400)
                return
            intake.gc()          # cheap; sweeps abandoned .part files older than STALE_PART_DAYS
            self._send_json(intake.status(uid))
            return

        if path in ("/api/chat/job", "/api/chat/thread"):
            try:
                self._handle_chat_get(path)
            except chatjobs.StoreBusy:
                # A store file still locked after the retries (Windows): "busy, retry",
                # never "not found", which would make the page give up on a live turn.
                self._send_json({"error": "the chat store is busy; try again"}, status=503)
            return

        if path.startswith("/api/activity"):
            limit = 30
            if "?" in self.path:
                query = self.path.split("?", 1)[1]
                for pair in query.split("&"):
                    if pair.startswith("limit="):
                        try:
                            limit = max(1, min(100, int(pair.split("=", 1)[1])))
                        except ValueError:
                            pass
            self._send_json({"rows": read_activity(limit)})
            return

        if path.startswith("/api/spend"):
            days = 30
            if "?" in self.path:
                query = self.path.split("?", 1)[1]
                for pair in query.split("&"):
                    if pair.startswith("days="):
                        try:
                            days = max(1, int(pair.split("=", 1)[1]))
                        except ValueError:
                            pass
            self._send_json(compute_spend(days))
            return

        if path == "/api/status":
            payload = {
                "server_time": datetime.now().isoformat(timespec="seconds"),
                "status": read_status_json(),
                "backup_log": read_backup_log(),
                "voice": read_voice_check(),
                "passkeys": passkeys.status() if passkeys is not None else {"available": False, "registered": 0},
            }
            self._send_json(payload)
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        path = self.path.split("?")[0]

        # CSRF first, for every POST, public ones included (see PUBLIC_ORIGIN).
        refusal = self._csrf_refusal(path)
        if refusal is not None:
            self._send_json({"error": refusal[1]}, status=refusal[0])
            return

        # The one unauthenticated POST: trading a device token for a
        # session cookie. Everything else requires an already-valid caller.
        if path == "/api/session":
            self._handle_session()
            return

        # Public and rate limited (passkeys.py): the only unauthenticated routes Phase 2 adds.
        if path in ("/api/passkey/login/options", "/api/passkey/login/verify"):
            self._handle_passkey_login(path)
            return

        # Full Marty (Stage B): its own gate; the generic CSRF check above still ran first.
        if path.startswith("/api/full/"):
            self._handle_full_post(path)
            return

        handle = self._auth()
        if handle is None:
            self._send_auth_required()
            return

        if path == "/api/session/logout":
            full_row = _device_row_for(dashboard_auth.token_from_headers(self.headers))   # before the revoke below
            self._passkey_logout()
            self._jr_lock_all()                  # logout locks Marty Jr. (W3)
            if full_row is not None:
                _full_lock(full_row["id"], "logout")    # and Full Marty on this device
            self._send_json({"ok": True},
                             extra_headers=[("Set-Cookie", dashboard_auth.clear_cookie())])
            return

        if path == "/api/logout":
            full_row = _device_row_for(dashboard_auth.token_from_headers(self.headers))   # before the revoke below
            self._passkey_logout()
            self._jr_lock_all()                  # logout locks Marty Jr. (W3)
            if full_row is not None:
                _full_lock(full_row["id"], "logout")    # and Full Marty on this device
            self.send_response(204)
            self.send_header("Set-Cookie", dashboard_auth.clear_cookie())
            self.send_header("Clear-Site-Data", '"cache", "storage"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path.startswith("/api/jr/"):
            self._handle_jr_post(path, handle)
            return

        if path in ("/api/passkey/register/options", "/api/passkey/register/verify"):
            self._handle_passkey_register(path)
            return

        if path == "/api/chat/job":
            self._handle_phase1_chat(handle)
            return

        if path == "/api/board/answer":
            self._handle_board_answer(handle)
            return

        if path.startswith("/api/chat/cancel/"):
            jid = path.rsplit("/", 1)[-1]
            job = chat_jobs().cancel(handle, jid) if chatjobs.ID_RE.match(jid) else None
            if job is None:
                self._send_json({"error": "no such turn"}, status=404)
            else:
                self._send_json({"state": "cancelled", "job_id": jid})
            return

        if path == "/api/talk":
            self._handle_talk()
            return

        if path == "/api/chat/new":
            try:
                self._handle_chat_new(handle)
            except chatjobs.StoreBusy:
                self._send_json({"error": "the chat store is busy; try again"}, status=503)
            return

        if path == "/api/chat":
            try:
                self._handle_chat(handle)
            except chatjobs.StoreBusy:
                self._send_json({"error": "the chat store is busy; try again"}, status=503)
            return

        if path == "/api/upload":
            self._handle_upload(handle)
            return

        if path in ("/api/upload/abort", "/api/upload/note", "/api/upload/transcribe"):
            self._handle_upload_action(path, handle)
            return

        self.send_error(404, "Not found")

    def do_PUT(self):
        """Only Jr's never-send list is PUT. Same order as do_POST: CSRF, then login."""
        path = self.path.split("?")[0]
        refusal = self._csrf_refusal(path)
        if refusal is not None:
            self._send_json({"error": refusal[1]}, status=refusal[0])
            return
        handle = self._auth()
        if handle is None:
            self._send_auth_required()
            return
        if path == "/api/jr/never-send":
            self._handle_jr_put(path, handle)
            return
        self.send_error(404, "Not found")

    def _handle_phase1_chat(self, handle):
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        lane = body.get("lane")
        text = body.get("text")
        thread_id = body.get("thread_id")
        if not isinstance(lane, str) or not isinstance(text, str):
            self._send_json({"error": "lane and text must be strings"}, status=400)
            return
        handoff = body.get("handoff")
        if handoff is not None and not isinstance(handoff, bool):
            self._send_json({"error": "handoff must be true or false"}, status=400)
            return
        # A Send of text handed over from Marty Jr. ("Ask Marty about this") is checked against
        # his never-send list again HERE, on the exact text, not only in the page (W4, skeptic
        # 2026-09-25). Ordinary chat carries no marker and is not touched.
        if handoff and not self._jr_handoff_recheck(handle, text):
            return
        try:
            job = chat_jobs().submit(handle, lane.strip().lower(), text,
                                     session_id=thread_id if isinstance(thread_id, str) else None,
                                     client_id=body.get("client_id") if isinstance(body.get("client_id"), str) else None)
        except chatjobs.Busy as busy:
            self._send_json({"error": "a reply is already running", "job_id": busy.job_id}, status=409)
            return
        except (ValueError, chatjobs.StoreBusy) as exc:
            self._send_json({"error": str(exc)}, status=400 if isinstance(exc, ValueError) else 503)
            return
        self._send_json({"job_id": job["id"], "thread_id": job["session"], "state": "starting"}, status=202)

    def _sse(self, event, data, event_id=None):
        bits = []
        if event_id is not None:
            bits.append(f"id: {event_id}\n")
        bits.append(f"event: {event}\n")
        bits.append("data: " + json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n\n")
        self.wfile.write("".join(bits).encode("utf-8"))
        self.wfile.flush()

    def _handle_chat_stream(self, jid):
        if not chatjobs.ID_RE.match(jid):
            self._send_json({"error": "bad job id"}, status=400)
            return
        handle = self._auth()
        manager = chat_jobs()
        try:
            after = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            after = 0
        job = manager.get(handle, jid)
        if job is None:
            self._send_json({"error": "no such turn"}, status=404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        sent_delta = False
        terminal_sent = False
        try:
            while not terminal_sent:
                job, rows = manager.events_since(handle, jid, after, wait=0.75)
                if job is None:
                    self._sse("error", {"error": "turn disappeared"})
                    break
                for row in rows:
                    after = row["seq"]
                    event = row["event"]
                    if event == "delta":
                        sent_delta = True
                    if event not in {"done", "error"}:
                        self._sse(event, row["data"], after)
                if job.get("status") in chatjobs.TERMINAL:
                    if job.get("status") == "completed":
                        if not sent_delta and job.get("reply"):
                            self._sse("delta", {"text": job["reply"]}, after + 1)
                        self._sse("done", chatjobs.public(job), after + 2)
                    elif job.get("status") == "cancelled":
                        self._sse("done", {"status": "cancelled", "job_id": jid}, after + 2)
                    else:
                        # reply: text a timed-out or stopped lane streamed before it ended (kept,
                        # shown as incomplete); empty for an ordinary failure.
                        # error: chatjobs.page_error, so a CLI lane's own output never reaches the page.
                        self._sse("error", {"status": job.get("status"),
                                            "error": chatjobs.page_error(job) or job.get("stop_reason") or "turn failed",
                                            "reply": job.get("reply") or "", "stop_reason": job.get("stop_reason")},
                                  after + 2)
                    terminal_sent = True
                elif not rows:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.close_connection = True

    # ---------- Marty Jr. (Phase 2, W2) ----------
    # Every /api/jr/* route sits behind the device login in do_GET/do_POST. Nothing here
    # prints: the only console line for a Jr request is log_message's method + path, and a
    # Jr path carries ids, never text. A failure answers a generic 500 without printing,
    # because an exception message could quote Jr's text. The cloud-tap and practice-VM routes
    # show an error's text only when it is a known fixed message (_jr_page_error); otherwise
    # the page gets a generic line and the console one line with the exception's type name.

    def _jr_gate(self, handle, *, touch=True):
        """True when Jr's routes may serve this caller: his history is unlocked (W3) AND this
        device session typed the passphrase for this unlock (_JR_SESSIONS). Otherwise answer 423
        with only what the page needs for its lock screen, and return False. Fails closed: a
        lane on a store with no lock is refused too. A served request counts as use (it resets
        the 15-minute idle lock)."""
        try:
            store = jr_history()
            if store is not None and _jr_session_open(self.headers, store) and (store.touch() if touch else store.is_unlocked()):
                return True
            needs_setup = bool(store is not None and store.needs_setup())
        except Exception:
            self._jr_fail()
            return False
        self._send_json({"error": "Marty Jr. is locked", "locked": True, "needs_setup": needs_setup}, status=423)
        return False

    def _jr_handoff_recheck(self, handle, text):
        """True when a handoff's text may go to Marty. Otherwise answer and return False: 423
        while Jr is locked for this device (the same gate as every Jr route, so it fails closed
        on a lane with no lock too), 400 for text too long to check, 422 with the reasons and
        UTF-16 offsets when the never-send check finds anything, 500 if the check itself fails.
        The answer never quotes a term or the text."""
        if not self._jr_gate(handle):
            return False
        try:
            result = jr_history().handoff_check(text, units="utf16")
        except ValueError as exc:
            self._send_json({"error": f"Not sent: {exc}", "blocked": True}, status=400)
            return False
        except Exception as exc:
            self._jr_fail(exc)
            return False
        if result["ok"]:
            return True
        reasons = sorted({h["reason"] for h in result["hits"]})
        n = len(result["hits"])
        self._send_json({"error": f"Not sent: Marty Jr.'s never-send check found {n} "
                                  f"place{'' if n == 1 else 's'} to edit ({', '.join(reasons)}).",
                         "blocked": True, "reasons": reasons,
                         "hits": [{"start": h["start"], "end": h["end"], "reason": h["reason"]}
                                  for h in result["hits"]]}, status=422)
        return False

    def _jr_fail(self, exc=None):
        # A StoreError's message is fixed text (never a passphrase, term or Jr's words); any
        # other exception is summarised, because its message could quote Jr's text.
        message = (f"Marty Jr.'s history: {exc}" if isinstance(exc, jr_store.StoreError)
                   else "Marty Jr.'s lane hit an error")
        try:
            self._send_json({"error": message}, status=500)
        except Exception:
            pass

    def _jr_lock_all(self):
        """Lock Jr's history and drop his finished replies from memory: the Lock button, the
        page going to the background, and logout. Never fails the request that asked."""
        try:
            jr_cloud.TAP.clear()
            store = jr_history()
            if store is not None:
                store.lock()
            jr().purge_finished()
        except Exception:
            pass

    def _handle_jr_unlock(self):
        """POST /api/jr/unlock {passphrase}: 200 | 400 (setup rules) | 403 | 429. The passphrase
        is never printed, stored or returned; the first unlock ever is the setup."""
        store = jr_history()
        if store is None:
            self._send_json({"error": "Marty Jr.'s encrypted history is not available"}, status=503)
            return
        body = self._read_json_body()
        passphrase = body.get("passphrase") if isinstance(body, dict) else None
        if isinstance(body, dict):
            body.clear()
        if not isinstance(passphrase, str) or not passphrase:
            self._send_json({"error": "type your passphrase"}, status=400)
            return
        try:
            ok = store.unlock(passphrase)
        except jr_store.RateLimited as exc:
            self._send_json({"error": str(exc), "retry_after": exc.retry_after}, status=429,
                            extra_headers=[("Retry-After", str(exc.retry_after))])
            return
        except jr_store.WeakPassphrase as exc:
            self._send_json({"error": str(exc), "needs_setup": True}, status=400)
            return
        finally:
            passphrase = None
        if not ok:
            self._refused("jr", "passphrase")
            self._send_json({"error": "That passphrase did not unlock Marty Jr."}, status=403)
            return
        _jr_session_bind(self.headers, store)
        gone = store.take_missing_found()
        if gone:
            # A count only: never an id or a title. The thread list carries it as "missing".
            print(f"[jr] warning: {gone} of Marty Jr.'s conversation files went missing from his "
                  f"history folder (deleted or moved); the thread list shows the count")
        self._send_json(dict(store.status(), ok=True))

    def _handle_jr_put(self, path, handle):
        if not self._jr_gate(handle):
            return
        try:
            body = self._read_json_body()
            terms = body.get("terms") if isinstance(body, dict) else None
            try:
                saved = jr_history().set_never_send(terms)
            except ValueError as exc:            # names a term by position only, never its text
                self._send_json({"error": str(exc)}, status=400)
                return
            self._send_json({"terms": saved})
        except Exception as exc:
            self._jr_fail(exc)

    def _handle_jr_get(self, path):
        handle = self._auth()
        if path == "/api/jr/status":
            # Is THIS device's unlock still current? Nothing else, and it does not count as use,
            # so a page polling it cannot keep the idle lock away. An open page uses it to drop
            # Jr's text when he was locked elsewhere (another device, idle, logout).
            try:
                store = jr_history()
                is_open = bool(store is not None and store.is_unlocked() and _jr_session_open(self.headers, store))
            except Exception as exc:
                self._jr_fail(exc)
                return
            self._send_json({"open": is_open})
            return
        if not self._jr_gate(handle, touch=path != "/api/jr/computer/status"):
            return
        try:
            if path == "/api/jr/computer/status":
                self._send_json(_jr_computer_status_page(jr_lane.jr_tools.jr_computer.MANAGER.status()))
                return
            if path == "/api/jr/cloud/status":
                self._send_json({"configured": jr_cloud.configured(), "model": jr_cloud.MODEL,
                                 "text_only": True, "price_usd_per_million_tokens": 5.0})
                return
            if path == "/api/jr/never-send":
                self._send_json({"terms": jr_history().get_never_send()})
                return
            if path == "/api/jr/threads":
                # "missing": this handle's threads whose file is gone from disk (jr_store), so a
                # deleted file shows as a count on the page instead of vanishing silently.
                store = jr_history()
                self._send_json({"threads": jr().threads(handle),
                                 "missing": store.missing_threads(handle) if store is not None else 0})
                return
            if path.startswith("/api/jr/thread/"):
                tid = path[len("/api/jr/thread/"):]
                thread = jr().thread(handle, tid) if jr_lane.ID_RE.match(tid) else None
                if thread is None:
                    self._send_json({"error": "no such conversation"}, status=404)
                else:
                    self._send_json(thread)
                return
            if path.startswith("/api/jr/stream/"):
                self._handle_jr_stream(handle, path[len("/api/jr/stream/"):])
                return
        except Exception as exc:
            self._jr_fail(exc)
            return
        self._send_json({"error": "not found"}, status=404)

    def _handle_jr_post(self, path, handle):
        # Unlock and lock are the two Jr routes that work while locked (device login still required).
        if path == "/api/jr/unlock":
            try:
                self._handle_jr_unlock()
            except Exception as exc:
                self._jr_fail(exc)
            return
        if path == "/api/jr/computer/stop":
            self._send_json(jr_lane.jr_tools.jr_computer.MANAGER.stop())
            return
        if path == "/api/jr/lock":
            self._jr_lock_all()
            self._send_json({"ok": True, "unlocked": False})
            return
        if path == "/api/jr/talk":
            self._handle_jr_talk(handle)         # its own gate: it drains a refused recording
            return
        if path == "/api/jr/teach":
            # Teach writes ONLY to Jr's plaintext reference library (jr/library/taught), which
            # jr_tools' library_search reads. It never touches the encrypted history, so it works
            # while Jr is locked - placed here, ahead of the _jr_gate unlock check, like talk.
            # Device login (self._auth in do_POST) is still required.
            self._handle_jr_teach()
            return
        if not self._jr_gate(handle):
            return
        try:
            if path == "/api/jr/cloud/preview":
                body = self._read_json_body()
                text = body.get("text") if isinstance(body, dict) else None
                try:
                    screened = jr_history().handoff_check(text)
                    if not screened["ok"]:
                        raise jr_cloud.CloudError("That text contains a never-send term. Nothing was sent.")
                    result = jr_cloud.TAP.preview(handle, jr_history().epoch, text)
                    self._send_json(result)
                except (jr_cloud.CloudError, ValueError) as exc:
                    self._send_json({"error": _jr_page_error(exc, "cloud preview", JR_CLOUD_ERRORS,
                                                             JR_CLOUD_GENERIC)}, status=400)
                return
            if path == "/api/jr/cloud/send":
                body = self._read_json_body()
                nonce = body.get("preview") if isinstance(body, dict) else None
                store = jr_history(); epoch = store.epoch
                try:
                    result = jr_cloud.TAP.send(
                        handle, epoch, nonce,
                        text_allowed=lambda text: bool(store.handoff_check(text)["ok"]))
                    if not store.is_unlocked() or store.epoch != epoch or not _jr_session_open(self.headers, store):
                        self._send_json({"error": "Jr locked while the helper answered; its reply was discarded."}, status=423)
                    else:
                        self._send_json(result)
                except jr_cloud.CloudError as exc:
                    self._send_json({"error": _jr_page_error(exc, "cloud send", JR_CLOUD_ERRORS,
                                                             JR_CLOUD_GENERIC)}, status=409)
                return
            if path == "/api/jr/computer/start":
                if jr().running:
                    self._send_json({"error":"Wait for Jr to finish his current reply before starting practice"},status=409)
                    return
                try:
                    practice_store=jr_history()
                    practice_epoch=practice_store.epoch
                    jr_lane.jr_tools.jr_spiderfoot.MANAGER.clear()
                    practice_status=jr_lane.jr_tools.jr_computer.MANAGER.enable(handle)
                    if not practice_store.is_unlocked() or practice_store.epoch!=practice_epoch or not _jr_session_open(self.headers,practice_store):
                        jr_lane.jr_tools.jr_computer.MANAGER.stop()
                        self._send_json({"error":"Jr locked during VM startup", "locked":True},status=423)
                        return
                    self._send_json(practice_status)
                except jr_lane.jr_tools.jr_computer.ComputerError as exc:
                    self._send_json({"error":_jr_page_error(exc,"computer start",JR_COMPUTER_ERRORS,
                                                            JR_COMPUTER_START_GENERIC)},status=409)
                return
            if path == "/api/jr/computer/approve":
                body=self._read_json_body()
                if not isinstance(body,dict):
                    self._send_json({"error":"Invalid approval"},status=400);return
                if jr().running:
                    self._send_json({"error":"Wait for Jr's check-in to finish"},status=409);return
                manager=jr_lane.jr_tools.jr_computer.MANAGER
                try:
                    store=jr_history();epoch=store.epoch
                    text,tid=manager.approve(handle,body.get("checkpoint"),body.get("thread_id"))
                    if not store.is_unlocked() or store.epoch!=epoch or not _jr_session_open(self.headers,store):
                        manager.stop()
                        self._send_json({"error":"Jr locked during approval"},status=423);return
                    job=jr().submit(handle,text,tid)
                    self._send_json({"job_id":job["id"],"thread_id":job["thread"]},status=202)
                except Exception as exc:
                    if manager.can_act(handle,body.get("thread_id")): manager.stop()
                    if isinstance(exc,jr_lane.jr_tools.jr_computer.ComputerError):
                        message=_jr_page_error(exc,"computer approve",JR_COMPUTER_ERRORS,JR_APPROVE_GENERIC)
                    else:
                        message=JR_APPROVE_GENERIC
                    self._send_json({"error":message},status=409)
                return
            if path == "/api/jr/missing/dismiss":
                # Lukas says a missing conversation was deleted on purpose: forget the records
                # (this handle's only), so the Jr view's notice goes away and stays away.
                self._send_json({"missing": jr_history().dismiss_missing(handle)})
                return
            if path == "/api/jr/handoff-check":
                # W4: Lukas's own Send is the only way Jr's text reaches Marty; this only says
                # where his never-send terms are, as UTF-16 offsets the page can highlight.
                body = self._read_json_body()
                text = body.get("text") if isinstance(body, dict) else None
                try:
                    result = jr_history().handoff_check(text, units="utf16")
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                    return
                # Offsets and a fixed reason ("never-send term" / "mixed-script word") only: the
                # list itself never goes back to the page from here. The page's Send stays off
                # unless ok is true for the text in the box; the Send is checked again here
                # anyway (_jr_handoff_recheck).
                self._send_json({"ok": result["ok"],
                                 "hits": [{"start": h["start"], "end": h["end"], "reason": h["reason"]}
                                          for h in result["hits"]]})
                return
            if path == "/api/jr/job":
                body = self._read_json_body()
                if not isinstance(body, dict):
                    self._send_json({"error": "bad request body"}, status=400)
                    return
                text, thread_id = body.get("text"), body.get("thread_id")
                if not isinstance(text, str) or (thread_id is not None and not isinstance(thread_id, str)):
                    self._send_json({"error": "text must be a string, and thread_id a string or null"}, status=400)
                    return
                try:
                    job = jr().submit(handle, text, thread_id)
                except jr_lane.Busy as busy:
                    self._send_json({"error": "Marty Jr. is still answering; wait for that reply to finish",
                                     "job_id": busy.job_id}, status=409)
                    return
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=400)
                    return
                self._send_json({"job_id": job["id"], "thread_id": job["thread"], "state": "starting"}, status=202)
                return
            if path.startswith("/api/jr/cancel/"):
                jid = path[len("/api/jr/cancel/"):]
                job = jr().cancel(handle, jid) if jr_lane.ID_RE.match(jid) else None
                if job is None:
                    self._send_json({"error": "no such turn"}, status=404)
                else:
                    self._send_json({"state": "cancelled", "job_id": jid})
                return
        except Exception as exc:
            self._jr_fail(exc)
            return
        self._send_json({"error": "not found"}, status=404)

    def _handle_board_answer(self, handle):
        """POST /api/board/answer. Body: {"id", "choice", "note"?}. Records Lukas's tap on a
        waiting item in status/board-answers.jsonl for Marty to read back. It only records: no
        answer starts anything. The item must be on the board now and the choice one of its
        buttons (board.record_answer checks both against board.json)."""
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        note = body.get("note")
        if note is not None and not isinstance(note, str):
            self._send_json({"error": "note must be a string"}, status=400)
            return
        try:
            row = board.record_answer(handle, body.get("id"), body.get("choice"), note)
        except board.UnknownItem:
            self._send_json({"error": "that item is no longer on the board; refresh"}, status=404)
            return
        except board.BadChoice:
            self._send_json({"error": "that is not one of this item's choices"}, status=400)
            return
        except board.BoardUnavailable as exc:
            self._send_json({"error": str(exc)}, status=503)
            return
        except OSError:
            self._send_json({"error": "could not save that answer; try again"}, status=503)
            return
        self._send_json({"ok": True, "answer": {"id": row["id"], "choice": row["choice"], "at": row["at"],
                                                "note": row["note"]}})

    def _handle_jr_teach(self):
        """POST /api/jr/teach. Body: {"text": required, "title": optional, "context": optional}.
        Distils the answer and saves it as a note in Jr's plaintext library. Returns
        jr_teach.save_taught's dict: {"ok","path","title","preview"}."""
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        text = body.get("text")
        title = body.get("title")
        context = body.get("context")
        if not isinstance(text, str) or not text.strip():
            self._send_json({"error": "text is required and must be a non-empty string"}, status=400)
            return
        if len(text) > JR_TEACH_MAX_TEXT:
            self._send_json({"error": "that answer is too long to teach"}, status=413)
            return
        if title is not None and not isinstance(title, str):
            self._send_json({"error": "title must be a string"}, status=400)
            return
        if context is not None and not isinstance(context, str):
            self._send_json({"error": "context must be a string"}, status=400)
            return
        try:
            result = jr_teach.save_taught(text, title=title, context=context)
        except Exception:
            # No exception message goes back: it could quote the answer text.
            self._send_json({"error": "could not save that to Marty Jr.", "ok": False}, status=500)
            return
        self._send_json(result)

    def _handle_jr_stream(self, handle, jid):
        """Same SSE shape as _handle_chat_stream (event names, id:, Last-Event-ID resume),
        fed from Jr's in-memory events instead of chatjobs. The gate is checked again on every
        pass (skeptic, 2026-09-25): a lock from any device, the idle timer or a logout ends an
        open stream at once with an error event {"locked": true}, instead of letting the rest of
        the reply through."""
        if not jr_lane.ID_RE.match(jid):
            self._send_json({"error": "bad job id"}, status=400)
            return
        lane = jr()
        store = jr_history()

        def still_open():
            return store is not None and store.is_unlocked() and _jr_session_open(self.headers, store)
        try:
            after = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            after = 0
        job = lane.get(handle, jid)
        if job is None:
            self._send_json({"error": "no such turn"}, status=404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        sent_delta = False
        try:
            while True:
                job, rows = lane.events_since(handle, jid, after, wait=0.75)
                if not still_open():
                    self._sse("error", {"error": "Marty Jr. is locked", "locked": True})
                    break
                if job is None:
                    self._sse("error", {"error": "turn disappeared"})
                    break
                for row in rows:
                    after = row["seq"]
                    if row["event"] == "delta":
                        sent_delta = True
                    if row["event"] not in {"done", "error"}:
                        self._sse(row["event"], row["data"], after)
                if job.get("status") in jr_lane.TERMINAL:
                    if job.get("status") == "completed":
                        if not sent_delta and job.get("reply"):
                            self._sse("delta", {"text": job["reply"]}, after + 1)
                        self._sse("done", jr_lane.public(job), after + 2)
                    elif job.get("status") == "cancelled":
                        self._sse("done", {"status": "cancelled", "job_id": jid}, after + 2)
                    else:
                        # the page gets jr_lane.page_error: Ollama's own text can quote the raw tool call
                        self._sse("error", {"status": job.get("status"),
                                            "error": jr_lane.page_error(job.get("error")) or "turn failed"}, after + 2)
                    break
                if not rows:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.close_connection = True

    def _handle_jr_talk(self, handle):
        """POST /api/jr/talk: Marty Jr.'s microphone (Phase 2, W3 voice). The body is the recording
        (an audio/* Content-Type, checked with CSRF in _csrf_refusal); the answer is {"text"} for
        Jr's own message box, where Lukas edits it and presses Send himself. Nothing is sent from
        here. It runs the same local transcriber as Talk (phase1.transcribe_bytes: this PC only,
        HF offline) and writes nothing but Talk's talk-* temp audio, which phase1 deletes before
        this returns (and the start sweep removes if a crash beats it); the text only travels
        through the transcriber's stdout pipe and this response.
        Same gate as every Jr route: 423 while locked, or for a device that did not type the
        passphrase. It is checked again while the transcriber runs, so a lock from anywhere (the
        page going to the background, another device, idle, logout) kills it, and once more before
        answering: a lock during the transcription, even one followed by a fresh unlock (a new
        epoch), drops the text and answers 423. Never prints, and no error quotes the transcriber,
        whose output could echo what was said."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if not self._jr_gate(handle):
            self._drain_body(length, phase1.MAX_AUDIO)   # so the page reads the 423, not a reset
            return
        if length <= 0:
            self._send_json({"error": "empty audio"}, status=400)
            return
        if length > phase1.MAX_AUDIO:
            self._send_json({"error": "audio exceeds 25 MB"}, status=413)
            return
        store = jr_history()
        epoch = store.epoch

        def still_open():
            return store.epoch == epoch and store.is_unlocked() and _jr_session_open(self.headers, store)
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_json({"error": "incomplete audio"}, status=400)
            return
        try:
            result = phase1.transcribe_bytes(body, self.headers.get("Content-Type", ""),
                                             abort=lambda: not still_open())
        except phase1.TranscriptionAborted:
            result = None
        except ValueError as exc:                # fixed text: unsupported type, empty, too large
            self._send_json_late({"error": str(exc)}, status=400)
            return
        except phase1.TranscriberBusy:
            self._send_json_late({"error": "The PC is transcribing another recording. Try again in a moment."},
                                 status=503)
            return
        except Exception:
            self._send_json_late({"error": "Local transcription failed on this PC."}, status=503)
            return
        finally:
            body = None
        if result is None or not still_open():
            result = None                        # locked meanwhile: the words are dropped here
            self._send_json_late({"error": "Marty Jr. is locked", "locked": True, "needs_setup": False}, status=423)
            return
        self._send_json_late({"text": result["text"], "seconds": result["seconds"],
                              "audio_seconds": result["audio_seconds"]})

    def _send_json_late(self, payload, status=200):
        """_send_json for an answer the page may have stopped waiting for: it aborts its upload the
        moment Jr locks, so a closed connection here is expected, not an error to print."""
        try:
            self._send_json(payload, status=status)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def _drain_body(self, length, limit):
        """Read and drop the body of a request that was refused before its body was read, up to
        limit bytes, so the client receives the answer instead of a reset connection."""
        if not 0 < length <= limit:
            return
        try:
            while length > 0:
                chunk = self.rfile.read(min(length, 64 * 1024))
                if not chunk:
                    break
                length -= len(chunk)
        except OSError:
            pass

    def _handle_talk(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._send_json({"error": "empty audio"}, status=400)
            return
        if length > phase1.MAX_AUDIO:
            self._send_json({"error": "audio exceeds 25 MB"}, status=413)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_json({"error": "incomplete audio"}, status=400)
            return
        try:
            self._send_json(phase1.transcribe_bytes(body, self.headers.get("Content-Type", "")))
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            # The transcriber's stderr/stdout can quote the recording: phase1's own fixed texts
            # pass through, anything else becomes its type name. Nothing is printed, so the
            # server log stays method + path (tool-privacy, 2026-09-28).
            text = str(exc)
            detail = text if text in TALK_FIXED_ERRORS else type(exc).__name__
            self._send_json({"error": f"local transcription failed: {detail}"}, status=503)

    def _handle_file_download(self, file_id):
        path = phase1.resolve_file(file_id)
        if path is None:
            self._send_json({"error": "no such file"}, status=404)
            return
        try:
            body = path.read_bytes()
        except OSError:
            self._send_json({"error": "file unavailable"}, status=503)
            return
        safe_name = re.sub(r"[^A-Za-z0-9._ -]", "_", path.name)
        self.send_response(200)
        self.send_header("Content-Type", phase1.content_type(path))
        self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle_session(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"error": "bad request body"}, status=400)
            return
        who, ended = dashboard_auth.resolve_detail(body.get("token"))
        if who is None:
            if ended in ("idle", "age"):
                # An old QR code or a pasted old token: say it ran out and how to get a new one.
                why = ("it was not used for %d days" % dashboard_auth.IDLE_DAYS if ended == "idle"
                       else "it is more than %d days old" % dashboard_auth.MAX_AGE_DAYS)
                self._refused("session", "ended-" + ended)
                self._send_json({"error": "That device token has ended (%s). Sign in with your passkey, "
                                          "or make a new QR code on the PC." % why, "expired": ended}, status=403)
                return
            self._refused("session", "rejected")
            self._send_json({"error": "token not accepted"}, status=403)
            return
        self._send_json(
            {"ok": True, "handle": who},
            extra_headers=[("Set-Cookie", dashboard_auth.session_cookie(body["token"]))],
        )

    # --- passkeys (Phase 2, W5; every rule lives in passkeys.py) ---------------

    def _passkey_precheck(self):
        """Common gate for the four passkey POST routes. True means carry on."""
        if passkeys is None:
            self._send_json({"error": "Passkey sign-in is not available on this server."}, status=503)
            return False
        if not passkeys.origin_ok(self.headers):          # CSRF: Origin must be exactly the dashboard's
            self._send_json({"error": "cross-origin request refused"}, status=403)
            return False
        return True

    # ---------------------------------------------------------------- Full Marty (Stage B)

    def _full_refusal(self, method, need_unlock=True, touch=True):
        """None when this Full request may proceed, else (status, payload). Order matters."""
        if self.headers.get("Authorization"):
            return 401, {"error": "Full Marty does not accept bearer tokens"}
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site != "same-origin":                                  # a missing header is a reject
            return 403, {"error": "cross-site request refused"}
        origin = (self.headers.get("Origin") or "").strip()
        if method == "POST" and origin not in allowed_origins():   # POST: Origin required, exact
            return 403, {"error": "cross-origin request refused"}
        if method == "GET" and origin and origin not in allowed_origins():  # same-origin GET/EventSource omit it
            return 403, {"error": "cross-origin request refused"}
        if (self.headers.get("Tailscale-User-Login") or "").strip().lower() != FULL_OWNER_LOGIN:
            return 403, {"error": "Full Marty is only for Lukas's own tailnet login"}
        token = _cookie_token(self.headers)
        row = _device_row_for(token) if token else None
        if row is None:
            return 401, {"error": "authentication required"}
        self._full_device = row["id"]
        self._full_token_sha = hashlib.sha256("".join(token.split()).encode("utf-8")).hexdigest()
        if not need_unlock:
            return None
        now = time.monotonic()
        with _FULL_LOCK:
            u = _FULL.get(row["id"])
            ok = (u is not None and hmac.compare_digest(u["token_sha"], self._full_token_sha)
                  and now - u["last"] <= FULL_IDLE_SEC and now - u["started"] <= FULL_MAX_SEC)
            if ok and method == "POST" and not hmac.compare_digest(
                    self.headers.get("X-Full-CSRF") or "", u["csrf"]):
                return 403, {"error": "missing or stale Full Marty token; unlock again"}
            if ok and touch:
                u["last"] = now
            self._full_epoch = u["epoch"] if ok else None
        if not ok:
            if u is not None:
                _full_lock(row["id"], "idle-or-age")
            return 423, {"error": "Full Marty is locked", "locked": True}
        return None

    def _full_call(self, op, **fields):
        try:
            return fullmarty_client.call(FULL_KEY, op, pipe=FULL_PIPE, device=self._full_device,
                                         epoch=self._full_epoch, **fields)
        except fullmarty_client.PipeRefused:
            return {"error": "The Full Marty worker is not running on the PC.", "worker": False}

    def _handle_full_get(self, path):
        if path == "/api/full/status":                      # no unlock needed, no touch
            refusal = self._full_refusal("GET", need_unlock=False)
            if refusal:
                self._send_json(refusal[1], status=refusal[0])
                return
            with _FULL_LOCK:
                u = _FULL.get(self._full_device)
                now = time.monotonic()
                live = bool(u and hmac.compare_digest(u["token_sha"], self._full_token_sha)
                            and now - u["last"] <= FULL_IDLE_SEC and now - u["started"] <= FULL_MAX_SEC)
                body = {"unlocked": live}
                if live:
                    body.update(idle_left=int(FULL_IDLE_SEC - (now - u["last"])),
                                max_left=int(FULL_MAX_SEC - (now - u["started"])), csrf=u["csrf"])
            self._send_json(body)
            return
        refusal = self._full_refusal("GET", touch=not path.startswith("/api/full/stream/"))
        if refusal:
            self._send_json(refusal[1], status=refusal[0])
            return
        if path == "/api/full/conversations":
            self._send_json(self._full_call("conversations"))
            return
        if path == "/api/full/history":
            self._send_json(self._full_call("history", conv=self._query_param("conv")))
            return
        if path == "/api/full/pending":
            self._send_json(self._full_call("pending"))
            return
        m = re.fullmatch(r"/api/full/stream/([0-9a-f]{16})/([0-9a-f]{16})", path)
        if m:
            self._handle_full_stream(m.group(1), m.group(2))
            return
        self._send_json({"error": "not found"}, status=404)

    def _handle_full_post(self, path):
        ip = passkeys.client_ip(self.client_address[0], self.headers) if passkeys else self.client_address[0]
        if path in ("/api/full/unlock/options", "/api/full/unlock/verify"):
            refusal = self._full_refusal("POST", need_unlock=False)
            if refusal:
                self._send_json(refusal[1], status=refusal[0])
                return
            if passkeys is None or not passkeys.origin_ok(self.headers):
                self._send_json({"error": "Passkeys are not available"}, status=503)
                return
            token = _cookie_token(self.headers)
            body = self._read_json_body()
            try:
                if path.endswith("/options"):
                    self._send_json(passkeys.stepup_options(token))
                    return
                used = passkeys.verify_stepup(ip, token, (body or {}).get("credential"))
            except passkeys.PasskeyError as err:
                _full_audit(event="unlock_refused", device=self._full_device, by=err.code)
                self._send_passkey_error(err)
                return
            epoch, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            now = time.monotonic()
            with _FULL_LOCK:
                _FULL[self._full_device] = {"epoch": epoch, "token_sha": self._full_token_sha,
                                            "started": now, "last": now, "csrf": csrf}
            # Stage B pick 10 (round 4): the worker is the authority. If it refuses the unlock (its audit
            # log could not be written: fail closed) or cannot be reached, the server-side unlock is
            # rolled back at once, so the page never shows "unlocked" while the worker is locked.
            try:
                res = fullmarty_client.call(FULL_KEY, "unlock", pipe=FULL_PIPE, device=self._full_device, epoch=epoch)
            except fullmarty_client.PipeRefused:
                res = {"error": "The Full Marty worker is not running on the PC.", "worker": False}
            if not isinstance(res, dict) or res.get("ok") is not True:
                with _FULL_LOCK:
                    if (_FULL.get(self._full_device) or {}).get("epoch") == epoch:
                        _FULL.pop(self._full_device, None)
                _full_audit(event="unlock_refused", device=self._full_device, by="worker")
                res = res if isinstance(res, dict) else {}
                body = {"error": res.get("error") or "Full Marty could not be unlocked.", "unlocked": False}
                if res.get("warning"):
                    body["warning"] = res["warning"]           # e.g. the disk is nearly full
                self._send_json(body, status=503)
                return
            _full_audit(event="unlock", device=self._full_device, by="passkey:%s" % used.get("id"))
            body = {"ok": True, "csrf": csrf, "idle": FULL_IDLE_SEC, "max": FULL_MAX_SEC}
            if res.get("warning"):
                body["warning"] = res["warning"]               # pick 10: the disk-space warning
            self._send_json(body)
            return

        if path == "/api/full/lock":                          # "Lock Full Marty now": EVERY unlock
            refusal = self._full_refusal("POST", need_unlock=False)
            if refusal:
                self._send_json(refusal[1], status=refusal[0])
                return
            self._read_json_body()
            _full_lock(None, "lock-now:device:%s" % self._full_device)
            self._send_json({"ok": True, "unlocked": False})
            return

        refusal = self._full_refusal("POST")
        if refusal:
            self._send_json(refusal[1], status=refusal[0])
            return
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        if path == "/api/full/speak":
            text = body.get("text")
            if not isinstance(text, str):
                self._send_json({"error": "bad request body"}, status=400)
                return
            spoken = speak.prepare_text(text)
            if not spoken:
                self._send_json({"error": "nothing to say"}, status=400)
                return
            voice_id = _speak_voice_id()
            if not voice_id:
                self._send_json({"error": "voice is not configured on this server"}, status=503)
                return
            try:
                audio = b"".join(speak.synthesize(spoken, voice_id))
            except speak.MissingKeyError as exc:
                print(f"[speak] {exc}")
                self._send_json({"error": "voice is not configured on this server"}, status=503)
                return
            except speak.SpeakError as exc:
                print(f"[speak] {exc}")
                self._send_json({"error": "text-to-speech failed"}, status=502)
                return
            self.send_response(200)
            self.send_header("Content-Type", "audio/mpeg")
            self.send_header("Content-Length", str(len(audio)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(audio)
            return
        if path == "/api/full/new":
            self._send_json(self._full_call("new"))
            return
        if path == "/api/full/answer":
            allow = body.get("allow")
            if not isinstance(allow, bool):
                self._send_json({"error": "allow must be true or false"}, status=400)
                return
            res = self._full_call("answer", nonce=body.get("nonce"), tool_use_id=body.get("tool_use_id"), allow=allow)
            self._send_json(res, status=200 if res.get("result") == "ok" else 409)
            return
        if path == "/api/full/stop":
            self._send_json(self._full_call("stop", conv=body.get("conv")))
            return
        if path == "/api/full/turn":
            text, conv = body.get("text"), body.get("conv")
            if not isinstance(text, str) or not isinstance(conv, str) or not re.fullmatch(r"[0-9a-f]{16}", conv):
                self._send_json({"error": "conv and text are required"}, status=400)
                return
            try:
                with fullmarty_client.Connection(FULL_KEY, FULL_PIPE) as c:
                    first = next(c.stream("turn", conv=conv, text=text, device=self._full_device,
                                          epoch=self._full_epoch))
            except (fullmarty_client.PipeRefused, StopIteration, EOFError, OSError, ValueError):
                self._send_json({"error": "The Full Marty worker is not running on the PC."}, status=503)
                return
            if first.get("event") != "accepted":
                if first.get("locked"):
                    self._send_json({"error": "Full Marty is locked", "locked": True}, status=423)
                    return
                self._send_json(first, status=409 if "running" in str(first.get("error")) else 400)
                return
            # The turn keeps running in the worker; the page follows it on /api/full/stream.
            self._send_json({"turn": first["turn"], "conv": conv}, status=202)
            return
        self._send_json({"error": "not found"}, status=404)

    def _handle_full_stream(self, conv, turn):
        """SSE, the same event names as /api/chat/stream (state, step, delta, done, error) plus
        approval / approval_closed / warning. Last-Event-ID resumes. The gate is re-checked every pass: a
        lock from anywhere ends the stream with {"locked": true}. Watching never touches the idle timer."""
        try:
            after = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            after = 0
        try:
            conn = fullmarty_client.Connection(FULL_KEY, FULL_PIPE)
        except fullmarty_client.PipeRefused:
            self._send_json({"error": "The Full Marty worker is not running on the PC."}, status=503)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for frame in conn.stream("events", conv=conv, turn=turn, after=after,
                                     device=self._full_device, epoch=self._full_epoch):
                with _FULL_LOCK:
                    u = _FULL.get(self._full_device)
                    still = u is not None and u["epoch"] == self._full_epoch
                if not still:
                    self._sse("error", {"error": "Full Marty is locked", "locked": True})
                    break
                ev = frame.get("event")
                if ev == "keepalive":
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if "error" in frame and not ev:
                    self._sse("error", {"error": frame["error"]})
                    break
                if ev == "end":
                    break
                self._sse(ev, frame.get("data") or {}, frame.get("seq"))
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError, EOFError):
            pass
        finally:
            conn.close()
            self.close_connection = True

    def _send_passkey_error(self, err):
        """Every PasskeyError from the four passkey routes. Only a refused credential (401, 403) is a
        refused login for the watcher; a malformed body (400), a duplicate or a full store (409),
        the rate limit (429) and an unavailable webauthn (503) are not. err.code is the short reason
        (unknown_credential, revoked, signature, ...), never anything from the request."""
        if err.status in (401, 403):
            self._refused("passkey", err.code)
        extra = [("Retry-After", str(err.retry_after))] if err.retry_after else None
        self._send_json({"error": err.public}, status=err.status, extra_headers=extra)

    def _handle_passkey_login(self, path):
        if not self._passkey_precheck():
            return
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        ip = passkeys.client_ip(self.client_address[0], self.headers)
        try:
            if path == "/api/passkey/login/options":
                self._send_json(passkeys.login_options(ip))
                return
            token, used = passkeys.verify_login(ip, body.get("credential"))
        except passkeys.PasskeyError as err:
            self._send_passkey_error(err)
            return
        except Exception as exc:
            print("[passkey] login failed: %s" % type(exc).__name__)
            self._send_json({"error": "passkey sign-in failed"}, status=500)
            return
        self._send_json({"ok": True, "handle": passkeys.HANDLE, "passkey": used["label"]},
                        extra_headers=[("Set-Cookie", dashboard_auth.session_cookie(token))])

    def _handle_passkey_register(self, path):
        if not self._passkey_precheck():
            return
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        token = dashboard_auth.token_from_headers(self.headers)   # the challenge is bound to this session
        try:
            if path == "/api/passkey/register/options":
                self._send_json(passkeys.registration_options(token))
                return
            saved = passkeys.verify_registration(token, body.get("credential"), body.get("label"))
        except passkeys.PasskeyError as err:
            self._send_passkey_error(err)
            return
        except Exception as exc:
            print("[passkey] registration failed: %s" % type(exc).__name__)
            self._send_json({"error": "passkey setup failed"}, status=500)
            return
        self._send_json({"ok": True, "passkey": saved})

    def _passkey_logout(self):
        """A passkey-minted session dies at logout; a device-token session is untouched.
        passkeys.on_logout retries the revoke, logs a failure, and parks it for reconcile.
        Logout itself never fails over this, but a failure is never silent."""
        if passkeys is None:
            return
        try:
            passkeys.on_logout(dashboard_auth.token_from_headers(self.headers))
        except Exception as exc:
            print("[passkey] logout revoke failed (%s); reconcile will retire the session" % type(exc).__name__)

    # Uploads land in my-agent/uploads (intake.UPLOAD_DIR), on no sync path - so a file
    # attached here does not silently end up in OneDrive, Drive or on the NAS. Marty's
    # tools in the Claude lane can read it there. The filename arrives in a header rather
    # than as multipart form data:
    # the body stays a raw byte stream, which means no multipart parser to get wrong.
    # Since 2026-09-22 the body is normally ONE SLICE of a larger file (X-Upload-Id /
    # -Offset / -Total headers, 32 MiB per request, 4 GiB per file, resumable by a
    # client-computed fingerprint); a request without X-Upload-Total is the old
    # single-shot format, still accepted up to intake.UPLOAD_LEGACY_MAX (64 MiB).
    # All of the byte handling lives in dashboard/intake.py so it can be unit-tested
    # without a second server; this class only parses headers and routes.

    def _query_id(self):
        """The ?id= of an upload request, validated against intake.ID_RE, else None."""
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        uid = (qs.get("id") or [""])[0]
        return uid if intake.ID_RE.match(uid) else None

    def _handle_upload(self, handle):
        name = intake.sanitize_name(self.headers.get("X-Filename", ""))
        if not name:
            self._send_json({"error": "missing or unusable X-Filename header"}, status=400)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._send_json({"error": "empty body"}, status=400)
            return
        total_hdr = self.headers.get("X-Upload-Total")
        if total_hdr is None:
            # Legacy single-shot format (curl, older clients): unchanged behaviour
            # except that a short body is now a 400 that leaves no file behind.
            if length > intake.UPLOAD_LEGACY_MAX:
                self._send_json({"error": f"file too large for a single request "
                                          f"(max {intake.UPLOAD_LEGACY_MAX // (1024*1024)} MiB); "
                                          f"use the chunked upload"}, status=413)
                return
            status, payload = intake.legacy_write(self.rfile, length, name, handle)
            self._send_json(payload, status=status)
            return
        # Chunked format. A slice is at most UPLOAD_PART_MAX; anything larger was not
        # sent by our client and gets a 413 with no drain. A legitimately sized slice
        # that fails validation is drained first so the browser receives the JSON
        # instead of a TCP reset (BaseHTTPRequestHandler closes on return).
        if length > intake.UPLOAD_PART_MAX:
            self._send_json({"error": f"slice too large (max {intake.UPLOAD_PART_MAX // (1024*1024)} MiB)"},
                            status=413)
            return
        uid = self.headers.get("X-Upload-Id", "")
        try:
            offset = int(self.headers.get("X-Upload-Offset", ""))
            total = int(total_hdr)
        except ValueError:
            intake.drain(self.rfile, length)
            self._send_json({"error": "X-Upload-Offset and X-Upload-Total must be integers"}, status=400)
            return
        if not intake.ID_RE.match(uid):
            intake.drain(self.rfile, length)
            self._send_json({"error": "bad upload id"}, status=400)
            return
        expected = (self.headers.get("X-Chunk-SHA256") or "").strip().lower() or None
        result = intake.append_chunk(self.rfile, self.connection, uid, offset, length, total,
                                     name, handle, expected)
        if result is None:
            return          # the connection died mid-slice; nothing to answer to
        status, payload = result
        self._send_json(payload, status=status)

    def _handle_upload_action(self, path, handle):
        uid = self._query_id()
        if uid is None:
            self._send_json({"error": "bad id"}, status=400)
            return
        if path == "/api/upload/abort":
            intake.abort(uid)
            self._send_json({"ok": True})
            return
        if path == "/api/upload/transcribe":
            self._send_json(intake.start_transcribe(uid))
            return
        # /api/upload/note: Lukas's own words about the file, typed into the receipt.
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"error": "bad request body"}, status=400)
            return
        text = (body.get("note") or "").strip()
        if not text:
            self._send_json({"error": "empty note"}, status=400)
            return
        self._send_json(intake.note(uid, text[:4000], handle))

    def _query_param(self, name):
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        return (qs.get(name) or [""])[0]

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 1024 * 1024:
                return None           # no chat request is this big; answered as a bad body
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return None

    def _handle_chat_get(self, path):
        handle = self._auth()
        if path == "/api/chat/job":
            jid = self._query_param("id")
            job = chat_jobs().get(handle, jid) if chatjobs.ID_RE.match(jid) else None
            if job is None:
                self._send_json({"error": "no such turn"}, status=404)
                return
            self._send_json(chatjobs.public(job))
            return
        brain = self._query_param("brain").lower() or DEFAULT_BRAIN
        if brain not in CHAT_BRAINS:
            self._send_json({"error": f"unknown brain {brain!r}"}, status=400)
            return
        sid = self._query_param("session")
        self._send_json(chat_jobs().thread(handle, brain, sid if chatjobs.ID_RE.match(sid) else None))

    def _handle_chat_new(self, handle):
        """The chat pane's New conversation button: archive the lane's current conversation
        (kept on disk under dashboard/chats, never shown again) and start an empty one. Body:
        {"brain", "session_id"}. 409 while a turn is running in that conversation."""
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        brain = body.get("brain") if isinstance(body.get("brain"), str) else ""
        sid = body.get("session_id") if isinstance(body.get("session_id"), str) else None
        try:
            new, archived = chat_jobs().new_conversation(handle, brain.strip().lower() or DEFAULT_BRAIN, sid)
        except chatjobs.Busy as b:
            self._send_json({"error": "a reply is still being worked on in this conversation; "
                                      "wait for it to finish, then start a new one", "running": b.job_id}, status=409)
            return
        except ValueError as e:
            self._send_json({"error": str(e)}, status=400)
            return
        self._send_json({"session": new["id"], "kind": new["kind"], "archived": archived})

    def _handle_chat(self, handle):
        """Start a chat turn as a durable job (chatjobs). A page sending async:true gets
        202 and the job at once, then polls /api/chat/job; the turn runs on even if the
        phone locks or reloads, which used to throw the reply away. A page that does not
        send async (one loaded before this change) gets the old synchronous reply, still
        run as a job, so its turn is saved even if that connection drops."""
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "bad request body"}, status=400)
            return
        for field in ("message", "brain", "session_id", "client_id"):
            if body.get(field) is not None and not isinstance(body.get(field), str):
                self._send_json({"error": f"{field} must be a string"}, status=400)
                return
        brain = (body.get("brain") or DEFAULT_BRAIN).strip().lower()
        try:
            job = chat_jobs().submit(
                handle, brain, body.get("message") or "",
                session_id=body.get("session_id") if isinstance(body.get("session_id"), str) else None,
                client_id=body.get("client_id"))
        except chatjobs.Busy as b:
            self._send_json({"error": "the last message is still being worked on; wait for it to finish",
                             "running": b.job_id}, status=409)
            return
        except ValueError as e:
            self._send_json({"error": str(e)}, status=400)
            return
        if body.get("async"):
            self._send_json({"job": chatjobs.public(job)}, status=202)
            return
        deadline = time.monotonic() + CHAT_SYNC_WAIT_SEC
        while job.get("status") not in chatjobs.TERMINAL and time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                job = chat_jobs().get(handle, job["id"]) or job
            except chatjobs.StoreBusy:
                pass                       # locked for a moment; the next pass reads it
        if job.get("status") != "completed":
            self._send_json({"error": chatjobs.page_error(job) or f"turn {job.get('status')}"}, status=502)
            return
        # Steps as name and verdict only (chatjobs.page_tools): a tool's inputs and results never reach the page.
        self._send_json({"reply": job.get("reply"), "model": job.get("model"),
                         "cost_usd": job.get("cost_usd") or 0.0, "brain": job.get("brain"),
                         "tools": chatjobs.page_tools(job.get("tools"))})


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True


# Refreshing the voice check from inside this process, rather than from a scheduled
# task, is deliberate: creating a task needs elevation, and the dashboard is the thing
# that DISPLAYS the badge, so it should own keeping it fresh. Three safety properties:
# it runs in a daemon thread so it can never block request handling or shutdown; it
# shells out to voicecheck.py with a hard subprocess timeout, which is the kill timer
# Task Scheduler's ExecutionTimeLimit would have provided; and the interval is hours,
# not the 5-second poll - the 2026-09-21 NAS bug (about 1,900 failed logons overnight)
# came from putting a network call on the status-poll path, and that is not repeated here.
VOICE_CHECK_FIRST_DELAY_SEC = 90      # let the network settle after a logon restart
HOUSEKEEPING_TICK_SEC = 3600          # spend publish: hourly, costs nothing
VOICE_CHECK_EVERY_TICKS = 6           # voice check: every 6th tick, i.e. 6-hourly
VOICE_CHECK_TIMEOUT_SEC = 120
# Google Drive is mounted at G:, so a local write here is readable by a cloud routine.
SPEND_PUBLISH_PATH = r"G:\My Drive\Marty\spend-yesterday.txt"


def _housekeeping_loop():
    """Two jobs on different clocks, one thread.

    The voice check makes a network call, so it runs every 6 hours. The spend
    publish makes none - it reads meter.jsonl and writes a text file - so it runs
    hourly. That difference matters: the Morning Queue routine fires at 09:00 UTC
    (4am local) and asks for YESTERDAY's number, so a file last written at 11pm
    still says the day before and gets correctly flagged stale. Hourly closes that
    window to at most sixty minutes."""
    script = os.path.join(AGENT_ROOT, "tools", "voicecheck.py")
    time.sleep(VOICE_CHECK_FIRST_DELAY_SEC)
    ticks = 0
    while True:
        try:
            if ticks % VOICE_CHECK_EVERY_TICKS == 0:
                subprocess.run(
                    [sys.executable, "-u", script, "--json", "--quiet"],
                    cwd=AGENT_ROOT,
                    capture_output=True, text=True, timeout=VOICE_CHECK_TIMEOUT_SEC,
                )
            # Every tick: publish yesterday's spend to the mounted
            # Google Drive so the cloud Morning Queue routine can read a number that
            # only exists on this PC. Costs nothing - it reads meter.jsonl, makes no
            # API call - so it rides along rather than earning its own timer.
            subprocess.run(
                [sys.executable, "-u", os.path.join(AGENT_ROOT, "tools", "switchboard.py"),
                 "daily", "--out", SPEND_PUBLISH_PATH],
                cwd=AGENT_ROOT,
                capture_output=True, text=True, timeout=60,
            )
            # And sweep abandoned upload slices (.part files older than a week).
            intake.gc()
        except Exception as e:
            # Never let this kill the thread - a failed check is data, not an outage.
            print(f"[housekeeping] refresh failed: {type(e).__name__} {e}")
        ticks += 1
        time.sleep(HOUSEKEEPING_TICK_SEC)


def start_housekeeping_thread():
    threading.Thread(target=_housekeeping_loop, name="housekeeping", daemon=True).start()


def main():
    addr = ("127.0.0.1", PORT)  # literal, not "localhost": that can resolve to ::1 and miss the serve proxy
    try:
        httpd = ThreadingHTTPServer(addr, DashboardHandler)
    except OSError:
        print(f"Dashboard is already running on port {PORT}. Not starting a second copy.")
        return
    with httpd:
        print(f"Marty dashboard serving on 127.0.0.1:{PORT} (loopback only)")
        print(f"  Tailnet: https://{{TAILNET_HOST}}  (via tailscale serve)")
        print(f"  Status file: {STATUS_FILE}")
        print(f"  Backup log:  {BACKUP_LOG_PATH}")
        print(f"  Voice check: every {VOICE_CHECK_EVERY_TICKS}h -> {VOICE_RESULT_PATH}")
        print(f"  Spend publish: hourly -> {SPEND_PUBLISH_PATH}")
        print(f"  Device logins: end after {dashboard_auth.IDLE_DAYS} days unused or {dashboard_auth.MAX_AGE_DAYS} days old")
        # Talk audio a crash left behind (phase1 deletes it per request; a crash mid-transcription
        # cannot). Only after the bind succeeded, so a second copy never sweeps a live one's file.
        if not talk_sweep_allowed(PORT, os.environ):
            print(f"  Talk temp sweep skipped: port {PORT} is not the live {LIVE_PORT} and MARTY_DASH_ROOT is not set")
        else:
            try:
                swept, stuck = phase1.sweep_talk_temp()
                print(f"  Talk temp files swept at start: {swept}" + (f" ({stuck} could not be deleted)" if stuck else ""))
            except ValueError as exc:        # runtime/talk is a link or junction: left alone
                print(f"  Talk temp sweep skipped: {exc}")
            except Exception as exc:
                print(f"  Talk temp sweep failed: {type(exc).__name__}")
        start_housekeeping_thread()
        threading.Thread(target=_full_sweep_loop, name="full-sweep", daemon=True).start()
        # Load the chat-job store now, not on the first message: this is where turns a
        # previous run left running get marked interrupted, so they show as continuable.
        m = chat_jobs()
        print(f"  Chat jobs: {m.store.root}")
        if passkeys is not None and passkeys.available():
            try:
                retired = passkeys.reconcile()
            except Exception as exc:
                retired = "failed (%s)" % type(exc).__name__
            print(f"  Passkeys: available, rpId {passkeys.rp_id()}; sessions retired at start: {retired}")
        else:
            print("  Passkeys: UNAVAILABLE - start with dashboard\\.venv\\Scripts\\python.exe (passkeys-WIRING.md)")
        print(f"  Marty Jr.: {jr_lane.MODEL} on {jr_lane.OLLAMA_HOST}:{jr_lane.OLLAMA_PORT} only, jobs in memory; "
              f"history encrypted in {jr_store.HISTORY_DIR}, locked until Lukas's passphrase")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")


if __name__ == "__main__":
    main()
