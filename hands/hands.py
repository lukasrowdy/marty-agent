"""
Marty HANDS — direct low-level Windows mouse/keyboard control via ctypes SendInput.

Adapted from the input-synthesis layer in brain-jarvis V7's hands.py (Windows branch),
stripped of the Mac/Quartz code and the autonomous computer-use vision loop — this is
just the primitives: move, click, drag, scroll, type, key.

SAFETY MODEL (this is the part brain-jarvis didn't have):
Every action verb (move/click/drag/scroll/type/key) requires an active, unexpired GRANT.
No grant = refuse, no exceptions. `grant` and `revoke` are deliberately NOT allowlisted in
.claude/settings.json, so activating one still goes through Claude Code's normal permission
prompt — that's the one deliberate human checkpoint left in this system. Once a grant is
active, the action verbs run instantly with no prompt, because the harness allowlists only
those specific subcommands. Every executed action is appended to hands-log.jsonl — with no
per-action prompt, that log is the accountability trail.

Grants self-expire; there is no way to grant "forever" (MAX_GRANT_MINUTES caps it).

Signed 2026-09-28 (outside audit): grant.json used to be a bare json.dump, so anything that
could write a file (a plain Write tool call, a stray script) could forge a grant and skip the
one human checkpoint. Now `grant` signs (granted_at, expires_at) with HMAC-SHA256 under a
secret held in Windows Credential Manager (target `hands/grant-key`, read through
tools/cred.py), and every check verifies that signature. An unsigned, tampered or re-dated
file, or a missing key, is NO grant. The key never appears in this file, the log or a note:
one-time setup is  py tools/cred.py set hands/grant-key  (paste any long random string).

Hardened 2026-09-23 (audit finding 8):
  - a grant must be a finite number of minutes, and a grant FILE that is malformed,
    non-finite or longer than the cap grants nothing (a "NaN" grant used to never expire)
  - the grant is re-checked between bounded batches, so a revoke stops a long type or drag
  - Windows' count of inserted events is checked; blocked input (UIPI, a secure desktop, a
    locked screen) is reported as FAILED, never as success
  - the log records metadata only: the length of typed text, never the text itself
  - what this cannot do: confirm the TARGET application received the input. Hands is blind
    by design; checking the result needs eyes (tools/screenshot.ps1).

Hardened 2026-09-28 (self-audit finding: "hands grant file"):
  - the grant file used to live at hands/grant.json, inside C:/Users/{{WIN_USER}}/my-agent — a
    Claude Code working folder where auto-mode file edits do not prompt. That meant a
    session could write itself a grant (Edit/Write on grant.json is not an ACTION_VERB, so
    it was never behind the settings.json allowlist, and it needed no permission prompt
    either). The one deliberate human checkpoint this file's own docstring describes
    ("`grant` and `revoke` are deliberately NOT allowlisted... so activating one still goes
    through Claude Code's normal permission prompt") only covered the CLI path; a direct
    file write walked around it entirely.
  - the grant file now lives under %LOCALAPPDATA%/Marty, outside every path this or any
    other project's Claude Code session treats as its working folder, with a directory ACL
    restricted to the current user (see the apply steps in
    proposals/2026-09-28/01-hands-grant-file.md).
  - GRANT_FILE is validated at import time: if it resolves to anything inside
    MY_AGENT_ROOT (or any other path listed in _FORBIDDEN_GRANT_ROOTS), every command
    refuses immediately, before any grant is read or written. This is defense in depth —
    it means a future edit that quietly moves GRANT_FILE back under my-agent fails loudly
    instead of silently reopening the hole.

    hands.py selftest              offline checks; stubs SendInput, never moves the real mouse

CLI:
    hands.py grant <minutes>       start/replace a time-boxed grant (max 240 min)
    hands.py revoke                kill the current grant immediately
    hands.py status                show remaining grant time
    hands.py pos                   print the current cursor position
    hands.py move <x> <y>
    hands.py click <x> <y> [button] [count]     button: left|right|middle
    hands.py drag <x1> <y1> <x2> <y2>
    hands.py scroll <dy> [dx]
    hands.py type <text>
    hands.py key <combo>            e.g. "ctrl+a", "enter", "ctrl+shift+t"
"""
import ctypes
import hashlib
import hmac
import json
import math
import os
import sys
import time
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
MY_AGENT_ROOT = os.path.normcase(os.path.abspath(os.path.join(HERE, os.pardir)))

# Any Claude Code working folder a grant file must never live under. Checked case-insensitively
# (NTFS is case-preserving, not case-sensitive) against the GRANT_FILE actually in effect.
_FORBIDDEN_GRANT_ROOTS = [MY_AGENT_ROOT]

_DEFAULT_GRANT_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local"),
    "Marty",
)
# Override only for tests (selftest points this at a tempdir); never set this in normal use.
GRANT_FILE = os.environ.get("HANDS_GRANT_FILE") or os.path.join(_DEFAULT_GRANT_DIR, "hands-grant.json")
LOG_FILE = os.path.join(HERE, "hands-log.jsonl")
MAX_GRANT_MINUTES = 240
# The HMAC key lives in Windows Credential Manager under this target, read through
# tools/cred.py (the same store every API key here uses). Never cached to disk.
GRANT_KEY_TARGET = "hands/grant-key"


def _tools_dir():
    """my-agent/tools, found by walking up from this file (so a staged copy one folder deeper
    than hands/ still finds the same cred.py the live copy uses)."""
    d = HERE
    for _ in range(4):
        d = os.path.dirname(d)
        cand = os.path.join(d, "tools")
        if os.path.isfile(os.path.join(cand, "cred.py")):
            return cand
    return os.path.join(os.path.dirname(HERE), "tools")


_TOOLS_DIR = _tools_dir()
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
try:
    import cred  # noqa: E402  (tools/cred.py)
except Exception:  # noqa: BLE001 - no key store reachable means no grant can ever verify
    cred = None

ACTION_VERBS = {"move", "click", "drag", "scroll", "type", "key", "pos"}
TYPE_BATCH = 16          # characters typed between grant re-checks


def _grant_file_is_safe(path):
    """False if `path` resolves to anywhere under a forbidden root — a Claude Code working
    folder where a file write doesn't need a permission prompt. Fails closed: an unresolvable
    path (e.g. a bad drive) is treated as unsafe, not skipped."""
    try:
        resolved = os.path.normcase(os.path.abspath(path))
    except (OSError, ValueError):
        return False
    return not any(
        resolved == root or resolved.startswith(root + os.sep)
        for root in _FORBIDDEN_GRANT_ROOTS
    )


def _require_safe_grant_file():
    if not _grant_file_is_safe(GRANT_FILE):
        print(f"Refused: GRANT_FILE ({GRANT_FILE}) resolves inside a Claude Code working "
              f"folder ({MY_AGENT_ROOT}); a session could grant itself with no prompt. "
              f"Fix the GRANT_FILE path in hands.py (or HANDS_GRANT_FILE) before running "
              f"anything else.", file=sys.stderr)
        sys.exit(1)


class InputBlocked(Exception):
    """Windows inserted fewer input events than were sent."""


class GrantLapsed(Exception):
    """The grant expired or was revoked in the middle of an action."""

# ---------------- grant lifecycle ----------------

def _read_grant():
    try:
        with open(GRANT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _read_key():
    """The signing secret as bytes, or None when the store has no `hands/grant-key` (or the
    store itself cannot be read). None means nothing can be signed and nothing verifies."""
    if cred is None:
        return None
    try:
        value = cred.read(GRANT_KEY_TARGET)
    except Exception:  # noqa: BLE001 - a broken key store is a missing key, not a grant
        return None
    if not value or not str(value).strip():
        return None
    return str(value).strip().encode("utf-8")


def _canonical(granted_at, expires_at):
    """The bytes that get signed: exactly the two time fields, in a fixed layout, so any change
    to either one (or to a NaN/Infinity that json refuses) breaks the signature."""
    return json.dumps({"expires_at": expires_at, "granted_at": granted_at},
                      sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sign(key, granted_at, expires_at):
    return hmac.new(key, _canonical(granted_at, expires_at), hashlib.sha256).hexdigest()


def _write_grant(data, key=None):
    """Write the grant file, signed when a key is given. An unsigned write is only ever the
    revoke shape (all zeros), which grants nothing whether or not it carries a signature."""
    data = dict(data)
    data.pop("sig", None)
    if key is not None:
        data["sig"] = _sign(key, data["granted_at"], data["expires_at"])
    os.makedirs(os.path.dirname(GRANT_FILE), exist_ok=True)
    with open(GRANT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, allow_nan=False)


def grant(minutes):
    try:
        minutes = float(minutes)
    except (TypeError, ValueError):
        print("Give me a number of minutes, e.g. `hands.py grant 30`.")
        return 1
    if not math.isfinite(minutes):
        # float("nan") passed both bounds checks below and wrote an expiry that never ran out
        print("Minutes must be a finite number.")
        return 1
    if minutes <= 0:
        print("Minutes must be positive.")
        return 1
    if minutes > MAX_GRANT_MINUTES:
        print(f"Capped at {MAX_GRANT_MINUTES} minutes ({MAX_GRANT_MINUTES / 60:.1f} hours) per grant — "
              f"re-run this once it lapses if you need longer.")
        minutes = MAX_GRANT_MINUTES
    key = _read_key()
    if key is None:
        # Fail closed and say why: an unsigned grant would be refused by every action anyway.
        print(f"No signing key in Credential Manager ({GRANT_KEY_TARGET}); nothing granted. "
              f"One-time setup:  py tools/cred.py set {GRANT_KEY_TARGET}", file=sys.stderr)
        return 1
    now = time.time()
    _write_grant({"granted_at": now, "expires_at": now + minutes * 60, "minutes": minutes}, key)
    print(f"Hands access granted for {minutes:.0f} minutes, until "
          f"{time.strftime('%I:%M %p', time.localtime(now + minutes * 60))}.")
    return 0


def revoke():
    _write_grant({"granted_at": 0, "expires_at": 0, "minutes": 0})
    print("Hands access revoked.")
    return 0


def _remaining_seconds():
    """Seconds left on the grant, or 0 for anything that is not a well-formed, finite, SIGNED
    grant no longer than the cap. Fails closed: a hand-edited, truncated or NaN grant file
    grants nothing (audit finding 8), and so does one whose HMAC is missing, wrong, or made
    with a key that is no longer in the store (2026-09-28 audit)."""
    g = _read_grant()
    if not isinstance(g, dict):
        return 0.0
    exp, at = g.get("expires_at"), g.get("granted_at")
    for v in (exp, at):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            return 0.0
    now = time.time()
    if exp - at > MAX_GRANT_MINUTES * 60 + 1 or at > now + 60:
        return 0.0
    sig = g.get("sig")
    key = _read_key()
    if key is None or not isinstance(sig, str) or not sig:
        return 0.0
    if not hmac.compare_digest(sig, _sign(key, at, exp)):
        return 0.0
    return max(0.0, exp - now)


def status():
    rem = _remaining_seconds()
    if rem <= 0:
        print("No active grant. Run `hands.py grant <minutes>` first.")
        return 1
    mins = rem / 60
    print(f"Active grant: {mins:.1f} minutes remaining.")
    return 0


def _require_grant():
    if not _remaining_seconds() > 0:
        print("Refused: no active hands grant (or it expired). Run `hands.py grant <minutes>` first.",
              file=sys.stderr)
        sys.exit(1)


def _check_grant_midway(done_note):
    """Re-checked between bounded batches of a long action, so a revoke takes effect now,
    not after the whole action has run."""
    if not _remaining_seconds() > 0:
        raise GrantLapsed(f"grant expired or was revoked after {done_note}")


def _log(action, args, result="ok"):
    """Metadata only. The typed text itself is never logged: a password typed into a login
    box used to sit in this plaintext file for good (audit finding 8)."""
    row = {"ts": time.time(), "when": time.strftime("%Y-%m-%d %H:%M:%S"),
           "action": action, "args": args, "result": result}
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass


# ---------------- Windows SendInput layer (ported from brain-jarvis hands.py) ----------------

_user32 = ctypes.windll.user32
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        _user32.SetProcessDPIAware()
    except Exception:
        pass

_ULONG_PTR = wintypes.WPARAM


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", _ULONG_PTR)]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", _ULONG_PTR)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


def _send_input(n, arr, size):
    return _user32.SendInput(n, arr, size)


def _send(*inputs):
    """SendInput returns how many events Windows actually inserted. Fewer than sent means the
    input was blocked (UIPI against an elevated window, a secure desktop, a locked screen),
    so this raises instead of letting the command print success (audit finding 8)."""
    arr = (_INPUT * len(inputs))(*inputs)
    got = _send_input(len(inputs), arr, ctypes.sizeof(_INPUT))
    if got != len(inputs):
        raise InputBlocked(f"Windows inserted {got} of {len(inputs)} input events "
                           f"(error {ctypes.GetLastError()}); the input was blocked")


def _mi(dx=0, dy=0, data=0, flags=0):
    return _INPUT(0, _INPUTUNION(mi=_MOUSEINPUT(dx, dy, data & 0xFFFFFFFF, flags, 0, 0)))


def _ki(vk=0, scan=0, flags=0):
    return _INPUT(1, _INPUTUNION(ki=_KEYBDINPUT(vk, scan, flags, 0, 0)))


def _abs_xy(x, y):
    w = _user32.GetSystemMetrics(0) or 1
    h = _user32.GetSystemMetrics(1) or 1
    return int(x * 65535 / max(1, w - 1)), int(y * 65535 / max(1, h - 1))


_WIN_BTN = {"left": (0x0002, 0x0004), "right": (0x0008, 0x0010), "middle": (0x0020, 0x0040)}


def cursor_point():
    pt = wintypes.POINT()
    _user32.GetCursorPos(ctypes.byref(pt))
    return (float(pt.x), float(pt.y))


def move_to(x, y):
    ax, ay = _abs_xy(x, y)
    _send(_mi(ax, ay, 0, 0x0001 | 0x8000))  # MOVE | ABSOLUTE


def click_at(x, y, button="left", count=1):
    down, up = _WIN_BTN[button]
    move_to(x, y)
    time.sleep(0.03)
    for i in range(count):
        if i:
            _check_grant_midway(f"{i} of {count} clicks")
        _send(_mi(0, 0, 0, down))
        _send(_mi(0, 0, 0, up))
        time.sleep(0.04)


def drag(x1, y1, x2, y2):
    move_to(x1, y1)
    time.sleep(0.03)
    _send(_mi(0, 0, 0, 0x0002))  # LEFTDOWN
    time.sleep(0.05)
    steps = 12
    try:
        for i in range(1, steps + 1):
            if i % 4 == 0:
                _check_grant_midway(f"{i} of {steps} drag steps")
            move_to(x1 + (x2 - x1) * i / steps, y1 + (y2 - y1) * i / steps)
            time.sleep(0.012)
    finally:
        _send(_mi(0, 0, 0, 0x0004))  # LEFTUP, always: never leave the button held down


def scroll(dy, dx=0):
    if int(dy):
        _send(_mi(0, 0, int(dy) * 120, 0x0800))
    if int(dx):
        _send(_mi(0, 0, int(-dx) * 120, 0x1000))


def type_text(text):
    for n, ch in enumerate(text):
        if n and n % TYPE_BATCH == 0:
            _check_grant_midway(f"{n} of {len(text)} characters")
        if ch in ("\n", "\r"):
            press_key("enter")
            time.sleep(0.008)
            continue
        if ch == "\t":
            press_key("tab")
            time.sleep(0.008)
            continue
        units = ch.encode("utf-16-le")
        for i in range(0, len(units), 2):
            scan = int.from_bytes(units[i:i + 2], "little")
            _send(_ki(0, scan, 0x0004))            # KEYEVENTF_UNICODE
            _send(_ki(0, scan, 0x0004 | 0x0002))    # ... | KEYUP
        time.sleep(0.008)


WIN_VK = {"return": 0x0D, "enter": 0x0D, "tab": 0x09, "space": 0x20,
          "backspace": 0x08, "delete": 0x2E, "forward_delete": 0x2E,
          "escape": 0x1B, "esc": 0x1B, "left": 0x25, "up": 0x26, "right": 0x27,
          "down": 0x28, "home": 0x24, "end": 0x23, "pageup": 0x21, "page_up": 0x21,
          "pagedown": 0x22, "page_down": 0x22}
for _c in "abcdefghijklmnopqrstuvwxyz0123456789":
    WIN_VK[_c] = ord(_c.upper())
for _i in range(1, 13):
    WIN_VK["f%d" % _i] = 0x6F + _i

# cmd/meta map to Ctrl, never the real Win key — a stray "win+l" locks the machine
WIN_MODS = {"ctrl": 0x11, "control": 0x11, "alt": 0x12, "option": 0x12,
            "shift": 0x10, "cmd": 0x11, "command": 0x11, "meta": 0x11}


def press_key(combo):
    parts = [p.strip().lower() for p in combo.replace(" ", "").split("+") if p.strip()]
    if not parts:
        return
    vk = WIN_VK.get(parts[-1])
    if vk is None:
        return
    mods = [WIN_MODS[m] for m in parts[:-1] if m in WIN_MODS]
    for m in mods:
        _send(_ki(m, 0, 0))
    _send(_ki(vk, 0, 0))
    _send(_ki(vk, 0, 0x0002))
    for m in reversed(mods):
        _send(_ki(m, 0, 0x0002))


# ---------------- CLI ----------------

def main(argv):
    if not argv:
        print(__doc__)
        return 1
    _require_safe_grant_file()
    cmd = argv[0].lower()

    if cmd == "grant":
        return grant(argv[1] if len(argv) > 1 else None)
    if cmd == "revoke":
        return revoke()
    if cmd == "status":
        return status()
    if cmd == "selftest":
        return selftest()

    if cmd not in ACTION_VERBS:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        return 1

    _require_grant()

    if cmd == "pos":
        x, y = cursor_point()
        print(f"{int(x)} {int(y)}")
        _log("pos", {})
        return 0
    args = {}
    try:
        if cmd == "move":
            x, y = float(argv[1]), float(argv[2])
            args = {"x": x, "y": y}
            move_to(x, y)
            done = f"moved to {int(x)},{int(y)}"
        elif cmd == "click":
            x, y = float(argv[1]), float(argv[2])
            button = argv[3] if len(argv) > 3 else "left"
            count = int(argv[4]) if len(argv) > 4 else 1
            args = {"x": x, "y": y, "button": button, "count": count}
            click_at(x, y, button, count)
            done = f"clicked ({button} x{count}) at {int(x)},{int(y)}"
        elif cmd == "drag":
            x1, y1, x2, y2 = (float(a) for a in argv[1:5])
            args = {"x1": x1, "y1": y1, "x2": x2, "y2": y2}
            drag(x1, y1, x2, y2)
            done = f"dragged {int(x1)},{int(y1)} -> {int(x2)},{int(y2)}"
        elif cmd == "scroll":
            dy = float(argv[1])
            dx = float(argv[2]) if len(argv) > 2 else 0
            args = {"dy": dy, "dx": dx}
            scroll(dy, dx)
            done = f"scrolled dy={dy} dx={dx}"
        elif cmd == "type":
            text = " ".join(argv[1:])
            args = {"chars": len(text)}              # never the text itself
            type_text(text)
            done = f"typed {len(text)} chars"
        elif cmd == "key":
            combo = argv[1] if len(argv) > 1 else ""
            args = {"combo": combo}
            press_key(combo)
            done = f"pressed {combo}"
        else:
            return 1
    except (InputBlocked, GrantLapsed) as e:
        _log(cmd, args, result=f"FAILED: {e}")
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    _log(cmd, args)
    print(done)
    return 0


# ---------------- selftest ----------------

def selftest():
    """Offline checks for audit finding 8, on temp grant and log files, with SendInput stubbed:
    the real mouse and keyboard are never touched, and the signing key is a throwaway stub so
    the real Credential Manager entry is never read."""
    import contextlib
    import io
    import tempfile
    global GRANT_FILE, LOG_FILE, _send_input, _read_key
    fails = []
    stub_key = {"value": b"selftest-only-key-never-stored"}

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    sent = {"n": 0, "mode": "ok", "revoke_at": None, "last": None}

    def fake_send(n, arr, size):
        sent["n"] += 1
        sent["last"] = (arr[n - 1].type, arr[n - 1].u.mi.dwFlags)
        if sent["revoke_at"] is not None and sent["n"] >= sent["revoke_at"]:
            _write_grant({"granted_at": 0, "expires_at": 0, "minutes": 0})
        return 0 if sent["mode"] == "blocked" else n

    def run(argv):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                return main(argv)
            except SystemExit as e:
                return e.code

    def log_rows():
        try:
            with open(LOG_FILE, encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except OSError:
            return []

    real = (GRANT_FILE, LOG_FILE, _send_input, _read_key)
    with tempfile.TemporaryDirectory() as td:
        GRANT_FILE, LOG_FILE = os.path.join(td, "grant.json"), os.path.join(td, "log.jsonl")
        _send_input = fake_send
        _read_key = lambda: stub_key["value"]  # noqa: E731
        try:
            print("grants")
            check(run(["grant", "nan"]) == 1 and not _remaining_seconds() > 0, "grant nan is refused")
            check(run(["grant", "inf"]) == 1 and not _remaining_seconds() > 0, "grant inf is refused")
            now = time.time()
            for label, raw in (("NaN expiry", '{"granted_at": 0, "expires_at": NaN}'),
                               ("text expiry", '{"granted_at": 1, "expires_at": "soon"}'),
                               ("boolean expiry", '{"granted_at": 1, "expires_at": true}'),
                               ("a list", "[]"), ("a truncated file", '{"grant'),
                               ("a grant longer than the cap",
                                json.dumps({"granted_at": now, "expires_at": now + 10 * 86400}))):
                with open(GRANT_FILE, "w", encoding="utf-8") as f:
                    f.write(raw)
                check(not _remaining_seconds() > 0 and run(["key", "enter"]) == 1, f"{label} grants nothing")
            check(run(["grant", "5"]) == 0 and 290 < _remaining_seconds() <= 300, "a normal grant works")

            print("signature")
            with open(GRANT_FILE, encoding="utf-8") as f:
                signed = json.load(f)
            check(isinstance(signed.get("sig"), str) and len(signed["sig"]) == 64, "a grant is written signed")
            unsigned = {k: v for k, v in signed.items() if k != "sig"}
            with open(GRANT_FILE, "w", encoding="utf-8") as f:
                json.dump(unsigned, f)
            check(not _remaining_seconds() > 0 and run(["key", "enter"]) == 1,
                  "a plain json.dump of a valid-looking grant (no sig) grants nothing")
            forged = dict(signed, expires_at=signed["expires_at"] + 3600)
            with open(GRANT_FILE, "w", encoding="utf-8") as f:
                json.dump(forged, f)
            check(not _remaining_seconds() > 0 and run(["key", "enter"]) == 1,
                  "a signed grant with a re-dated expiry grants nothing")
            with open(GRANT_FILE, "w", encoding="utf-8") as f:
                json.dump(signed, f)
            check(_remaining_seconds() > 0, "the untouched signed grant still verifies")
            stub_key["value"] = None
            check(not _remaining_seconds() > 0 and run(["key", "enter"]) == 1, "no key in the store = no grant")
            check(run(["grant", "5"]) == 1 and not _remaining_seconds() > 0,
                  "grant refuses to write when the store has no key")
            stub_key["value"] = b"selftest-only-key-never-stored"
            check(run(["grant", "5"]) == 0 and _remaining_seconds() > 0, "with the key back, grant works again")

            print("grant file location guard (self-audit finding, 2026-09-28)")
            check(_grant_file_is_safe(os.path.join(td, "grant.json")),
                  "a tempdir grant file is judged safe")
            check(_grant_file_is_safe(os.path.join(_DEFAULT_GRANT_DIR, "hands-grant.json")),
                  "the real default location (%LOCALAPPDATA%\\Marty) is judged safe")
            under_my_agent = os.path.join(MY_AGENT_ROOT, "hands", "grant.json")
            check(not _grant_file_is_safe(under_my_agent),
                  "a grant file back under my-agent/hands is judged unsafe")
            check(not _grant_file_is_safe(MY_AGENT_ROOT),
                  "my-agent's root itself is judged unsafe (no subpath needed)")
            check(_grant_file_is_safe(MY_AGENT_ROOT + "-sibling" + os.sep + "grant.json"),
                  "a look-alike sibling folder (prefix match, not a real subpath) is not caught by mistake")
            saved_grant_file = GRANT_FILE
            GRANT_FILE = under_my_agent
            try:
                check(run(["status"]) == 1,
                      "main() refuses outright (before reading or writing anything) when GRANT_FILE "
                      "resolves under my-agent")
            finally:
                GRANT_FILE = saved_grant_file

            print("logging")
            check(run(["type", "password:", "hunter2"]) == 0, "typing works under a grant")
            with open(LOG_FILE, encoding="utf-8") as f:
                raw_log = f.read()
            check("hunter2" not in raw_log and log_rows()[-1]["args"] == {"chars": 17},
                  "typed text is logged as a length only, never the text")

            print("blocked input")
            sent["mode"] = "blocked"
            check(run(["key", "enter"]) == 1 and log_rows()[-1]["result"].startswith("FAILED"),
                  "input Windows refused is reported and logged as FAILED, not success")
            sent["mode"] = "ok"

            print("revocation during a long action")
            sent["n"], sent["revoke_at"] = 0, 5
            check(run(["type", "a" * 200]) == 1 and sent["n"] < 60,
                  f"a revoke mid-type stops it within one batch ({sent['n']} of 400 events sent)")
            check("revoked" in log_rows()[-1]["result"], "the lapse is logged")
            run(["grant", "5"])
            sent["n"], sent["revoke_at"] = 0, 3
            check(run(["drag", "10", "10", "200", "200"]) == 1 and sent["last"] == (0, 0x0004),
                  "a revoke mid-drag stops it and still releases the mouse button")
            sent["revoke_at"] = None
        finally:
            GRANT_FILE, LOG_FILE, _send_input, _read_key = real
    print()
    if fails:
        print(f"{len(fails)} FAILED:")
        for f in fails:
            print("  - " + f)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
