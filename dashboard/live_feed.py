"""Watch Marty work (2026-09-26): a read-only feed of what the Claude Code session at the PC is doing.

Lukas: "I would love to be able to see your progress as you make it. Just like you do in this chat."
He picked "Both" on the board: this feed (GET /api/live, shown on the Jobs tab) plus live steps in the
app's own chat replies (server.py uses step_label() for those).

What leaves the transcript, and nothing else:
  - "say": Marty's own narration, the text blocks of his replies (what Lukas reads in the Claude chat);
  - "step": a plain label for each tool call ("Reading a file", "Searching the web"), plus the one-line
    description Marty writes for Bash, PowerShell and helper agents when it is plain words (one that
    names a URL, a host, a path, an IP, email, phone or street address, holds a secret word at all or
    a code or key with a number, any character that is not plain ASCII, or any token that is not a
    plain word, a short number, a time, a date or a file name shows the plain label, and so does one
    naming a family member or a private term such as a device name: see private_names.json).
Never tool results, never tool inputs (no file paths, commands, queries or file contents), never
thinking, never Lukas's own messages, never a helper agent's (sidechain) transcript. The session file is
read from the end only (a bounded tail), parsed per line, and a torn last line is skipped.

Scope of the privacy promise (round 5): it covers TOOL STEP LINES, the "step" events here and every
surface that shows a tool call through step_label() (chat steps, GET /api/activity, the Jobs tab's
"Marty at the PC" row). Marty's own narration ("say", up to SAY_CHARS) and status.json are outside it
by design: they are what Marty chose to say to Lukas, not what a tool was given.

    py live_feed.py selftest
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import threading
import time
import unicodedata
from datetime import datetime, timezone

PROJECTS_DIR = pathlib.Path(os.environ.get("MARTY_LIVE_DIR")
                            or pathlib.Path.home() / ".claude" / "projects" / "C--Users-{{WIN_USER}}-my-agent")
TAIL_BYTES = 2_000_000          # the transcript's tail; tool results make it large, text is small
MAX_TAIL_BYTES = 16_000_000     # read further back (doubling) when a huge line (an image) fills the tail
MIN_EVENTS = 10
# Only Lukas's own Claude Code sessions (the desktop app or the terminal). The voice line's SDK sessions
# ("sdk-py" warm-ups) and scripted runs ("sdk-cli") write into the same folder and are never shown.
ENTRYPOINTS = {"claude-desktop", "cli"}
MAX_EVENTS = 80
SAY_CHARS = 900
STEP_CHARS = 80                 # a description's cap (about 50 of the 3,500 in the session transcripts run longer)
ACTIVE_SECONDS = 10 * 60        # newer than this: "Marty is working"

# Plain labels by tool name. Tools that carry a description Marty writes (DESCRIBED) show it instead.
LABELS = {
    "Read": "Reading a file", "Write": "Writing a file", "Edit": "Editing a file", "MultiEdit": "Editing a file",
    "NotebookEdit": "Editing a notebook", "Grep": "Searching files", "Glob": "Finding files",
    "WebSearch": "Searching the web", "WebFetch": "Reading a web page", "SendUserFile": "Sending you a file",
    "Agent": "Handing work to a helper", "Task": "Handing work to a helper", "SendMessage": "Checking in with a helper",
    "TodoWrite": "Updating the to-do list", "Skill": "Loading a skill", "ToolSearch": "Loading a tool",
    "AskUserQuestion": "Asking you a question", "Artifact": "Publishing a page", "ArtifactData": "Updating a page",
    "ArtifactComments": "Reading page comments", "Monitor": "Watching a task", "ScheduleWakeup": "Setting a reminder",
    "ReadNotifications": "Checking notifications", "TaskStop": "Stopping a task", "Workflow": "Running a workflow",
    "Bash": "Running a command", "PowerShell": "Running a command", "ListAgents": "Checking on helpers",
    # the app's own chat lane (Marty's read-only MCP tools)
    "mcp__marty__read_file": "Reading a file", "mcp__marty__list_dir": "Looking in a folder",
    "mcp__marty__search_notes": "Searching the notes", "mcp__marty__search_vault": "Searching the vault",
    "mcp__marty__see_image": "Looking at an image", "mcp__marty__transcribe_media": "Transcribing audio or video",
    "mcp__marty__see_video_frame": "Looking at a video frame", "mcp__marty__avatar_roster": "Checking the avatar roster",
    "mcp__marty__avatar_cost": "Checking an avatar price",
}
DESCRIBED = {"Bash", "PowerShell", "Agent", "Task"}
# Connected services, by a word in the MCP server's name.
SERVICES = [("claude_browser", "Using the browser"), ("claude-in-chrome", "Using Chrome"),
            ("computer-use", "Using the screen"), ("visualize", "Drawing a picture"),
            ("scheduled-tasks", "Checking scheduled tasks"), ("ccd_", "Updating the app"),
            ("terminal", "Checking the terminal"), ("mcp-registry", "Looking up connectors")]
# Unnamed connector ids seen on this PC (the tool names say what they do).
CONNECTOR_VERBS = [("draft", "Working in Gmail"), ("thread", "Working in Gmail"), ("message", "Working in Gmail"),
                   ("label", "Working in Gmail"), ("event", "Checking the calendar"), ("calendar", "Checking the calendar"),
                   ("file", "Working in Drive"), ("folder", "Working in Drive"), ("batch", "Working on a document"),
                   ("update", "Working on a document"), ("guide", "Working on a document")]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(text: str, limit: int) -> str:
    text = _CONTROL.sub("", str(text or "")).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# (2026-09-26, tool privacy) A description is shown only when it is plain words. Five checks, in order,
# on the text with its look-alikes folded (_fold), before the cap:
#   1. (round 6) _plain_ascii: every character is printable ASCII, or a curly quote, an en or em dash or
#      an ellipsis. No other script, symbol, emoji or invisible character reaches the rules below;
#   2. (round 6) _secret_line, on the text BEFORE times and dates become "when": any secret word at all
#      (password, token, PIN, ...), or a code, key, pw, creds or PIN followed by three or more digits;
#   3. _UNSHOWN, a blocklist of shapes: a URL or a host (host:port too), a path, an IP, email, phone or
#      street address, an environment variable, a key prefix, a JWT, a long opaque or hex string, Greek
#      or Cyrillic letters (also caught by 1; kept so the blocklist stands on its own);
#   4. _plain_words (round 5), an allowlist: every token must be a plain word, a short number, a time,
#      a date, a file name or ordinary punctuation. Whatever shape no blocklist part names (a mixed
#      letter-digit token, a slash, a bracket, a stray colon, a spelled-out domain, a letters-only key)
#      falls back to the label by construction, not by being listed;
#   5. the private-names rule (private_names.json): family names and nicknames per its mode, private
#      terms (device names, the Wi-Fi name, the home town) always.
# Each part has a canary in the selftest.
_TLDS = ("com|net|org|io|dev|ai|app|co|us|me|local|lan|home|internal|arpa|edu|gov|mil|info|biz|xyz|cloud|"
         "online|site|tech|uk|ca|de|tv|gg|ly")           # not sh or so: shell scripts and libraries
_EXTS = ("py|pyw|js|mjs|cjs|ts|tsx|jsx|css|html?|md|json|jsonl|txt|log|ps1|psm1|sh|bat|cmd|ya?ml|toml|ini|cfg|"
         "conf|xml|csv|sql|db|lock|pdf|docx?|pptx?|xlsx?|png|jpe?g|gif|webp|svg|mp4|mov|mp3|wav|m4a|heic|zip")
_SEP = r"(?:\s*[-_.]\s*|\s+|\s*\bdot\b\s*)"              # an address written with spaces, dashes or "dot"
_SEPX = r"(?:\s*[-_.]\s*|\s*\bdot\b\s*)"                 # the same without bare spaces (10.x: lists would match)
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# (round 6, Marty's call on the skeptic's letters-only values) A secret word ANYWHERE withholds the whole
# line: a value can be a plain word ("password BlueSky"), sit anywhere in the line ("Set the password for
# the router 4821") or be a time or date ("PIN 12:34"), so no "next to a value" shape is safe. Round 5
# showed the bare word as study vocabulary ("Count tokens in the prompt"); about 1.3% of the real lines
# now show the plain label instead. The long words match inside other words too (mypassword,
# passwordless); the short ones need a word edge or a CamelCase join (DoorPin, PINcode) so "spinning",
# "pinned" and "tokenizer" stay. And (c): a code, key, pw, creds or PIN followed by three or more digits
# (garage code 4821, Wi-Fi key: 12 34 56). Both run on the folded text BEFORE _dated, so a PIN written as
# 12:34 or 9/24 is still a number.
_EDGE_L = r"(?:(?<![a-z])|(?-i:(?<=[a-z])(?=[A-Z])))"          # a word start, or a CamelCase join
_EDGE_R = r"(?:(?![a-z])|(?-i:(?<=[a-z])(?=[A-Z]))|(?-i:(?<=[A-Z])(?=[a-z])))"   # a word end, or a join:
#                                                        DoorPinCode, PINcode (never inside pinned or spin)
_SECRET_WORD = (r"(?:passw(?:or)?d|passphrase|passcode|credential|api[\s_-]*key|private[\s_-]*key)"
                r"|" + _EDGE_L + r"(?:bearer|tokens?|secrets?|creds?|pwd?s?|pins?|otps?)" + _EDGE_R)
_SECRET_LINE = re.compile(
    _SECRET_WORD
    + r"|" + _EDGE_L + r"(?:codes?|keys?|pwd?|creds?|pins?)(?![a-z])"             # (c) code/key/pw/creds/PIN,
    + r"[^a-z0-9]{0,3}(?:(?:is|was|to|as|of|at|no)[^a-z0-9]{1,3})?"              #     "is", "no." or a mark,
    + r"\d(?:[\s:/.,-]?\d){2,}",                                                #     then 3+ digits
    re.IGNORECASE)
_UNSHOWN_PARTS = [
    r"[a-z][a-z0-9+.-]*://|(?<![\w.])www\.",                                       # a URL
    r"(?<![\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:" + _TLDS + r")(?![\w-])",       # a host or domain (x.ts.net too)  # secret-scan: allow [export-reviewed]
    r"(?<![\w.-])(?![\w.-]*\.(?:" + _EXTS + r"):)(?!\d{4}-\d\d-\d\dT)(?=[\w.-]*[a-z])[\w.-]*\w:\d{2,5}(?![\d:])",
    #   ^ host:port: the host has a letter (4:30 and 16:9 stay) and is not a file:line or an ISO time
    r"(?<![a-z0-9])[a-z]:[\\/]|\\",                                               # a drive path; any backslash (UNC)
    r"[^\s/]*/[^\s/]+/|(?:^|[\s\"'(=:,;<\[{])(?:~|\.{1,2})?/[\w.~-]",              # a/b/c, /unix/path/, /x, ~/x, ./x
    r"(?<![\w.~-])[\w.-]+/[\w.-]*\.(?:" + _EXTS + r")(?![\w-])"                   # one slash: folder/file.ext,
    r"|(?<![\w.~-])[\w.]*[-_.][\w.-]*/(?-i:[A-Z])[\w-]{2,}"                       # marty-vault/Name,
    r"|(?<![\w.~-])(?:marty-vault|my-agent|marty-portal|marty-handoff|users|home|projects|dashboard|vault|"
    r"onedrive|desktop|documents|downloads|pictures|videos|appdata|tmp|temp|logs|uploads|outbox|chats|runtime|"
    r"tools|status|scripts)/[\w-]",                                               # a known folder (pass/fail stays)
    r"%[a-z_][\w()]*%|\$(?:env:)?[a-z_]\w*|\$\{[^}\s]+\}",                        # %VAR%, $HOME, $env:X, ${X}
    r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])",                                # an IPv4 address
    r"(?<![\d.-])(?:100" + _SEP + r"(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|192" + _SEP + r"168|172" + _SEP
    + r"(?:1[6-9]|2\d|3[01]))" + _SEP + r"\d{1,3}" + _SEP + r"\d{1,3}(?![\d.])"    # Tailscale or private, spelled
    r"|(?<![\d.])10" + _SEPX + r"\d{1,3}" + _SEPX + r"\d{1,3}" + _SEPX + r"\d{1,3}(?![\d.])"
    r"|(?<![\d.])" + _OCT + r"(?:[-_]" + _OCT + r"){3}(?![\d.]|[-_]\d)",           # any address with dashes
    r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{1,4}(?![\w:])",                   # an IPv6 address
    r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",                                              # an email address
    r"[\w.+-]+\s*[\[(<{]?\s*\bat\b\s*[\])>}]?\s*[\w-]+(?:\s*[\[(<{]?\s*\bdot\b\s*[\])>}]?\s*[\w-]+)+",  # x at y dot com
    r"(?<![a-z0-9])(?:sk|pk|rk|ghp|gho|ghu|ghs|ghr|github_pat|glpat|xox[abprs])[-_]",   # key prefixes
    r"(?<![a-z0-9])(?:akia|asia)[0-9a-z]{8,}|(?<![a-z0-9])aiza[\w-]{10,}",
    r"(?<![\w-])(?-i:eyJ)[\w-]{6,}",                                              # a JWT
    r"(?<![\w-])(?=[\w-]{16,}(?![\w-]))"                                          # a long opaque string: 16+
    r"(?=[\w-]*?(?<![a-z0-9])(?:[a-z0-9]*\d[a-z0-9]*[a-z]|[a-z]+\d{3}|\d{5}))[\w-]+",   # (not word-2026-09-26)
    r"(?<![\w-])[0-9a-f]{12,}(?![\w-])",                                          # 12+ hex digits
    "[\u0370-\u03ff\u1f00-\u1fff\u0400-\u052f\u1c80-\u1c8f\u2de0-\u2dff\ua640-\ua69f]",   # Greek or Cyrillic letters
    r"(?<![\w+])\+\d[\d\s().-]{6,}\d(?!\w)"                                       # a phone number
    r"|(?<![\w+])(?:1[\s.-]?)?(?:\([2-9]\d\d\)|[2-9]\d\d)[\s.-]?[2-9]\d\d[\s.-]?\d{4}(?!\w)",
    r"(?-i:\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\.?\s+){1,3}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|"
    r"Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place|Ter|Terrace|Cir|Circle|Pkwy|Parkway|Hwy|Highway|Trl|Trail|Loop)\b)"
    r"|\bp\.?\s?o\.?\s+box\s+\d+"                                                 # a street address, a PO box,
    r"|(?-i:\b(?:Hwy|Highway|County Road|Farm Road|State Road|Rural Route|State Hwy)\s+\d{1,5}\b)",   # a rural road
    r"\bdot\s*(?:com|net|org|io)\b",                                              # (round 5) "example dot com"
]
_UNSHOWN = re.compile("|".join("(?:" + part + ")" for part in _UNSHOWN_PARTS), re.IGNORECASE)

# (round 5) The plain-words gate. Times and dates are allowed forms first (4:30, 16:30:05, 4:30pm,
# 9/24, 9/24/2026, 9/14-9/17, 2026-09-26, 2026-09-26T16:30), then every whitespace token, with ordinary
# punctuation trimmed from its ends, must be one of _PLAIN_FORMS. Three or more number tokens in a row
# (a spaced card, phone or key) are withheld.
_TIME = r"(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:[ap]\.?m\.?)?"
_DAY = r"(?:1[0-2]|0?[1-9])/(?:3[01]|[12]\d|0?[1-9])(?:/(?:\d{4}|\d{2}))?"
_WHEN = re.compile(r"(?<![\w:/.-])(?:\d{4}-[01]\d-[0-3]\d(?:T" + _TIME + r")?|" + _DAY
                   + r"(?:-(?:" + _DAY + r"|3[01]|[12]\d|0?[1-9]))?|" + _TIME + r")(?![\w:/-]|\.\d)", re.IGNORECASE | re.ASCII)
_WORD = r"(?:[a-z]+|[A-Z][a-z]+|[A-Z]{1,5}s?)(?:'(?:s|t|d|m|ll|re|ve))?"        # plain, Capitalised, CAPS up to 5
_HUMP = r"(?:[AEIOUY][a-z]+|[A-Z][a-z]*[aeiouy][a-z]*)"                         # one CamelCase part, with a vowel
_NUM = r"\d{1,4}(?:\.\d{1,2})?"                                                  # 12, 2026, 3.5
_UNIT = (r"(?:st|nd|rd|th|s|x|k|K|p|am|pm|AM|PM|GB|MB|KB|TB|gb|mb|kb|ms|fps|Hz|kHz|px|%)")
_NUMBER_FORM = re.compile(r"\$?" + _NUM + _UNIT + r"?|\$" + _NUM + r"[kKmM]?"
                          + r"|(?!\d{3}-\d{4}\Z)\d{1,4}-\d{1,4}", re.ASCII)      # 1st, 24GB, $5, 50%, 100-200 (not 555-0182)
_PLAIN_FORMS = re.compile(
    _WORD                                                                        # a word
    + r"|(?=[A-Za-z']{1,16}\Z)(?:[a-z]{1,4}(?:" + _HUMP + r"){1,3}|(?:" + _HUMP + r"){2,3})(?:'s)?"
    #   ^ CamelCase: PowerShell, YouTube, iPhone; up to three parts, each with a vowel (not KzQmPvTr...)
    + r"|[a-z]+(?:_[a-z]+)+"                                                     # snake_case: jr_lane
    + r"|[A-Za-z][\w-]{0,40}\.(?-i:" + _EXTS.replace("|zip", "").replace("|mov", "") + r")(?::\d{1,5}(?:-\d{1,5})?)?", re.ASCII)
#     ^ a file name (server.py, app.js:1833); not .zip or .mov, which are also web domains
_HYPHEN_PART = re.compile(_WORD + r"|\d{1,4}", re.ASCII)
# (re.ASCII on the gate's patterns: \w and \d mean ASCII letters and digits only, so no other script's
# letters or digits pass as a file name or a number)
_DEVICE = re.compile(r"(?:pc|nas|laptop|desktop|router|server|srv|vm|host|nuc|mbp|imac|macbook|phone|tablet)s?",
                     re.IGNORECASE)
_TRIM_LEFT, _TRIM_RIGHT = "(\"'", ".,;:!?)\"'"
_PUNCT_TOKENS = set("-&+") | {"--", "\u2013", "\u2014", "...", "(", ")", "!", "?", ".", ","}


def _hyphened(core: str) -> bool:
    """A hyphenated compound of plain words (follow-up, re-run, round-4), at most one number part and not
    a device name (marty-pc, nas-box)."""
    parts = core.split("-")
    if len(parts) < 2 or not all(_HYPHEN_PART.fullmatch(p) for p in parts):
        return False
    numbers = sum(p.isdigit() for p in parts)
    return numbers <= 1 and numbers < len(parts) and not _DEVICE.fullmatch(parts[-1])


def _dated(folded: str) -> str:
    """The (folded) text with curly quotes straightened and each time or date as the word "when", so
    neither the blocklist (16:30:05 is not an IPv6 address, 9/24/2026 not a path) nor the gate trips on
    one. Idempotent."""
    return _WHEN.sub(" when ", folded.replace("\u2019", "'").replace("\u2018", "'")
                     .replace("\u201c", '"').replace("\u201d", '"'))


def _plain_words(folded: str) -> bool:
    """True when every token of a (folded) description is an allowed plain form (the gate)."""
    text = _dated(folded)
    run = 0
    for tok in text.split():
        if tok in _PUNCT_TOKENS:
            continue                                  # a lone dash or mark: the number run carries on
        core = tok.lstrip(_TRIM_LEFT).rstrip(_TRIM_RIGHT)
        if not core:
            if all(ch in _TRIM_LEFT + _TRIM_RIGHT for ch in tok):
                continue
            return False
        if _NUMBER_FORM.fullmatch(core):
            run += 1
            if run >= 3:
                return False                          # 4111 1111 1111, 999 555 0182, AB 12 34 56
            continue
        run = 0
        if not (_PLAIN_FORMS.fullmatch(core) or _hyphened(core)):
            return False
    return True


# (round 4) A description naming a family member, and (round 6) one naming a private term. The lists and
# the one setting live in private_names.json next to this file (never in the code or the tests):
#   "names"     family members; "nicknames" their short or pet names (Lukas supplies these; may be empty).
#               Both follow "mode": "off", "with-media" (hidden when the line also has a media or private
#               word) or "any" (hidden whenever it names one; what ships, Lukas's call 2026-09-26: "Hide
#               every family name");
#   "terms"     (round 6) this household's private words, hidden in every mode: the PC's and the NAS's
#               names, the phones' and the tailnet's device names, the home Wi-Fi name, the home town.
#               Filled on the PC from hostname, tailscale status, netsh and the vault; may be empty.
# Every entry is matched the same way (_entry_pattern): its letters and digits in order with any run of
# other characters between them and nothing bounding either end (CamelCase, lower case, glued to another
# word, inside a file name, spaced or dotted out), and spelled backwards too. Re-read when the file
# changes. If it is missing, unreadable, has an unknown mode, an empty "names" list, a missing or
# non-list "nicknames" or "terms", or any blank entry, no description is shown at all (fail closed).
PRIVATE_NAMES = pathlib.Path(__file__).with_name("private_names.json")
PRIVATE_MODES = ("off", "with-media", "any")
PRIVATE_LISTS = ("names", "nicknames", "terms")
SHORT_ENTRY = 3                  # an entry of 3 or fewer letters and digits must stand as a whole word
_MEDIA = re.compile(                                  # a word start: \b, a CamelCase join or after _ (<name>Photos, <name>_photos)
    r"(?:\b|(?-i:(?<=[a-z])(?=[A-Z]))|(?<=_))(?:photo\w*|pics?|picture\w*|image\w*|imgs?|video\w*|vids?|clips?|footage|selfies?|privat\w*|privacy|"
    r"shower\w*|bath\w*|nud(?:e|es|ity)|naked|undress\w*|changing|toilet\w*|tub|tubs|towel\w*|swim\w*|"
    r"bod(?:y|ies)|face\w*|jpe?g|png|heic|gif|mp4|mov|mkv|webm|avi|mp3|audio|voice\s*memos?|"
    r"record(?:s|ed|ing|ings)?|reels?|shots?|snapshots?|screenshots?|movies?|films?|albums?|galler(?:y|ies)|"
    r"cameras?|camera\s*roll|webcams?|stills?|frames?|thumbnails?|thumbs?|portraits?|headshots?|"
    r"contact\s*sheets?|media|render\w*|edit(?:s|ed|ing)?|mask\w*|outfits?|costumes?|capcut)\b"
    r"|(?<![a-z])(?:img|dsc)_|[\U0001F4F7\U0001F4F8\U0001F3A5\U0001F4F9\U0001F39E\U0001F3AC\U0001F5BC]",
    re.IGNORECASE)
_private_cache = {"key": None, "rule": None, "checked": None}
# (2026-09-28) One thread at a time in _private_rule. Without the lock, two requests arriving together on
# a cold cache (the Jobs tab's own /api/live on opening, plus any other) raced: the first set "checked" and
# went off to read the file, the second saw a fresh "checked" with "rule" still None and failed closed, so
# its parse (cached by the transcript's mtime) showed the plain label until the transcript next changed.
_private_lock = threading.Lock()
# Invisible fillers that are letters or symbols, not format characters (Hangul fillers, the Braille blank)
_FILLERS = dict.fromkeys(map(ord, "ᅟᅠㅤﾠ⠀"))
# (round 6) The only characters outside printable ASCII a shown description may hold, after folding.
PLAIN_EXTRA = frozenset("‘’“”–—…")     # curly quotes, en/em dash, ellipsis


def _fold(text: str) -> str:
    """The text with its look-alikes folded, for matching only: compatibility forms to plain (NFKD:
    fullwidth, ligatures), the invisible fillers removed, then combining marks (Mn, Me) and zero-width
    and other format characters (Cf) dropped."""
    text = unicodedata.normalize("NFKD", text).translate(_FILLERS)
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Mn", "Me", "Cf"))


def _plain_ascii(folded: str) -> bool:
    """(round 6) True when every character of the (folded) text is printable ASCII or in PLAIN_EXTRA."""
    return all(" " <= ch <= "~" or ch in PLAIN_EXTRA for ch in folded)


def _secret_line(folded: str) -> bool:
    """(round 6) True when the (folded, NOT dated) text holds a secret word anywhere, or a code, key, pw,
    creds or PIN followed by three or more digits."""
    return bool(_SECRET_LINE.search(folded))


def _entry_pattern(entry: str):
    """One listed name, nickname or term as a pattern that finds it forwards or backwards, or None when it
    has no letters or digits. Between its characters any run of other characters may sit: non-letters
    before a letter (Z o r v e s s a, Zor-vessa, Zor4vessa), non-letters-or-digits before a digit (ds_223).
    A gap can never hold the character after it, so matching stays linear. An entry of SHORT_ENTRY or fewer
    characters must stand as a whole word instead (a gapped two-letter pattern would hide most lines)."""
    chars = re.findall(r"[^\W_]", _fold(entry))
    if not chars:
        return None

    def spelled(seq):
        if len(seq) <= SHORT_ENTRY:
            return r"(?<![^\W_])" + "".join(re.escape(c) for c in seq) + r"(?![^\W_])"
        out = re.escape(seq[0])
        for c in seq[1:]:
            out += (r"[\W_]*" if c.isdigit() else r"[\W\d_]*") + re.escape(c)
        return out
    forward, backward = spelled(chars), spelled(chars[::-1])
    return forward if forward == backward else forward + "|" + backward


def _private_rule():
    """(mode, names-and-nicknames pattern, terms pattern or None) from PRIVATE_NAMES, or None when it is
    missing, unreadable or unusable (see above). The file is looked at no more than every 2 seconds, and
    re-read only when it changed. One caller at a time (_private_lock): a concurrent caller waits for the
    load instead of reading a half-set cache."""
    with _private_lock:
        return _private_rule_locked()


def _private_rule_locked():
    cache, now = _private_cache, time.monotonic()
    if cache["checked"] is not None and now - cache["checked"] < 2.0:
        return cache["rule"]
    cache["checked"] = now
    try:
        st = PRIVATE_NAMES.stat()
    except OSError:
        cache["key"] = cache["rule"] = None
        return None
    key = (str(PRIVATE_NAMES), st.st_mtime_ns, st.st_size)
    if key == cache["key"]:
        return cache["rule"]
    rule = None
    try:
        data = json.loads(PRIVATE_NAMES.read_text(encoding="utf-8"))
        mode = data.get("mode")
        lists = {k: data.get(k) for k in PRIVATE_LISTS}
        if (mode in PRIVATE_MODES and lists["names"]
                and all(isinstance(v, list) and all(isinstance(n, str) for n in v) for v in lists.values())):
            patterns = {k: [_entry_pattern(n) for n in v] for k, v in lists.items()}
            if all(all(p) for p in patterns.values()):   # a blank entry: fail closed, as the deploy gate does
                people = patterns["names"] + patterns["nicknames"]
                terms = patterns["terms"]
                rule = (mode, re.compile("|".join("(?:" + p + ")" for p in people), re.IGNORECASE),
                        re.compile("|".join("(?:" + p + ")" for p in terms), re.IGNORECASE) if terms else None)
    except (OSError, ValueError, AttributeError, re.error):
        rule = None
    cache["key"], cache["rule"] = key, rule
    return rule


def _private_reset() -> None:
    """Forget the cached lists (the selftest, after it swaps PRIVATE_NAMES)."""
    _private_cache.update(key=None, rule=None, checked=None)


def _private_generation():
    """(2026-09-28, the outside audit) The names file as the rule cache last saw it: its (path, mtime,
    size) key, or None when it is missing. payload() folds this into its parse-cache key, because the
    private rule is applied INSIDE parse(): with the transcript unchanged, an edited private_names.json
    used to leave the old descriptions on the page until the transcript next grew. Goes through the
    same 2-second check as the rule itself, so a change shows within 2 s, as the rule does."""
    with _private_lock:
        _private_rule_locked()
        return _private_cache["key"]


def _names_private(folded: str) -> bool:
    """True when the private_names.json rule hides this (folded) description: a private term in any mode,
    a family name or nickname per the mode."""
    rule = _private_rule()
    if rule is None:
        return True                                   # no usable lists: show no description at all
    mode, people, terms = rule
    if terms is not None and terms.search(folded):
        return True
    if mode == "off" or not people.search(folded):
        return False
    return mode == "any" or bool(_MEDIA.search(folded))


def _shown(desc: str) -> bool:
    """True when a description is plain words the page may show: plain ASCII (_plain_ascii), no secret
    (_secret_line, before the dates are replaced), then _UNSHOWN, the _plain_words gate and the
    private-names rule."""
    folded = _fold(desc)
    if not _plain_ascii(folded) or _secret_line(folded):
        return False
    dated = _dated(folded)
    return not _UNSHOWN.search(dated) and _plain_words(dated) and not _names_private(folded)


def shown_or_none(text):
    """(2026-09-28) Text the page may show, or None: control characters removed, then the one description
    rule (_shown) on the whole text, then capped at STEP_CHARS with an ellipsis as step_label does. For text
    that is not a tool description but must pass the same gate (the practice VM's window title on GET
    /api/jr/computer/status)."""
    if not isinstance(text, str):
        return None
    text = _CONTROL.sub("", text).strip()
    return _clean(text, STEP_CHARS) if text and _shown(text) else None


def step_label(name: str, tool_input=None) -> str:
    """A plain label for one tool call. Only DESCRIBED tools may show their own description, and only
    when it is plain words (_shown); anything else gets the tool's plain label."""
    name = str(name or "")
    if name in DESCRIBED and isinstance(tool_input, dict):
        desc = tool_input.get("description")
        if isinstance(desc, str) and desc.strip():
            desc = _CONTROL.sub("", desc).strip()
            if desc and _shown(desc):
                return _clean(desc, STEP_CHARS)
    if name in LABELS:
        return LABELS[name]
    if name.startswith("mcp__"):
        low = name.lower()
        for key, label in SERVICES:
            if key in low:
                return label
        tool = low.rsplit("__", 1)[-1]
        for key, label in CONNECTOR_VERBS:
            if key in tool:
                return label
        return "Using a connected service"
    return "Working"


# ---------------------------------------------------------------- the one rule for every surface
# (2026-09-26, tool privacy) GET /api/live, GET /api/activity, the Jobs tab's "Marty at the PC" row and
# a chat reply's saved steps all show a tool call through step_label() and nothing else, so no
# surface can drift into showing a path, a command, a URL, a query or a message body.

# The metered chat lane's own tool names (marty_tools) that have no mcp__marty__ twin in LABELS.
CHAT_TOOL_LABELS = {"recon_lookup": "Looking up an address", "recon_probe": "Checking a web server",
                    "web_fetch": "Reading a web page"}
# Every fixed label step_label() can return. A name that already is one (the Max lane saves the
# label, not the tool's name) passes through unchanged.
LABEL_TEXTS = frozenset(list(LABELS.values()) + [label for _k, label in SERVICES]
                        + [label for _k, label in CONNECTOR_VERBS] + list(CHAT_TOOL_LABELS.values())
                        + ["Using a connected service", "Working"])
AGENT_PREFIX = "launched agent: "      # log_activity.py's summary for Agent: this prefix, then the description
# GET /api/activity's "tool": a one-word family for each fixed label, never the raw tool name (82 raw
# names are logged, 51 of them mcp__ ids naming a connector). Short enough for the Activity panel's
# narrow uppercase column (96px, 70px on a phone), which shows it whole with no app.js change.
FAMILIES = {
    "Reading a file": "Files", "Writing a file": "Files", "Editing a file": "Files", "Editing a notebook": "Files",
    "Looking in a folder": "Files", "Searching files": "Search", "Finding files": "Search",
    "Searching the notes": "Search", "Searching the vault": "Search",
    "Searching the web": "Web", "Reading a web page": "Web", "Checking a web server": "Web",
    "Looking up an address": "Web", "Sending you a file": "Share",
    "Handing work to a helper": "Helper", "Checking in with a helper": "Helper", "Checking on helpers": "Helper",
    "Updating the to-do list": "Tasks", "Watching a task": "Tasks", "Stopping a task": "Tasks",
    "Running a workflow": "Tasks", "Checking scheduled tasks": "Tasks", "Setting a reminder": "Tasks",
    "Loading a skill": "Setup", "Loading a tool": "Setup", "Asking you a question": "Question",
    "Publishing a page": "Page", "Updating a page": "Page", "Reading page comments": "Page",
    "Checking notifications": "Alerts", "Running a command": "Command",
    "Looking at an image": "Media", "Looking at a video frame": "Media", "Transcribing audio or video": "Media",
    "Drawing a picture": "Media", "Checking the avatar roster": "Avatar", "Checking an avatar price": "Avatar",
    "Using the browser": "Browser", "Using Chrome": "Browser", "Using the screen": "Screen",
    "Updating the app": "App", "Checking the terminal": "Terminal", "Looking up connectors": "Service",
    "Using a connected service": "Service", "Working in Gmail": "Gmail", "Checking the calendar": "Calendar",
    "Working in Drive": "Drive", "Working on a document": "Document", "Working": "Working",
}


def tool_label(name) -> str:
    """The label a chat reply's saved step shows after a reload: the metered lane saves the name the
    model chose ("read_file", or anything at all when the call was refused), the Max lane saves the
    label. The same mapping the live step lines use, so a reload shows what the live lines showed."""
    name = str(name or "")
    if name in LABEL_TEXTS:
        return name
    return LABELS.get("mcp__marty__" + name) or CHAT_TOOL_LABELS.get(name) or step_label(name)


def activity_label(row) -> str:
    """The one line the page may see for an activity.jsonl row (log_activity.py): step_label()'s
    rule, the plain label plus the description Marty writes for Bash, PowerShell and helper agents.
    The row's own summary is never served: for Read, Grep and Glob it is a path or a pattern, for
    WebFetch a URL, for WebSearch a query, for SendMessage a message body, and for Bash the raw
    command whenever the call had no description. A row written by the newer hook carries "desc"
    (the description, when there was one); an older row only has it for Agent, after AGENT_PREFIX."""
    if not isinstance(row, dict):
        return "Working"
    tool = str(row.get("tool") or "")
    desc = row.get("desc")
    if isinstance(desc, str) and desc.strip():
        return step_label(tool, {"description": desc})
    summary = row.get("summary")
    if tool == "Agent" and isinstance(summary, str) and summary.startswith(AGENT_PREFIX):
        return step_label(tool, {"description": summary[len(AGENT_PREFIX):]})
    return step_label(tool)


def tool_family(name) -> str:
    """The one-word family GET /api/activity serves as "tool" (FAMILIES), from the tool's fixed label."""
    return FAMILIES.get(step_label(name), "Working")


def activity_row(row):
    """An activity.jsonl row as GET /api/activity serves it: {"ts", "tool", "summary"}, where tool is
    tool_family() (never the raw name) and summary is activity_label(row). None for a line that is
    not a JSON object."""
    if not isinstance(row, dict):
        return None
    return {"ts": _clean(row.get("ts"), 40), "tool": tool_family(row.get("tool")), "summary": activity_label(row)}


def _parse_ts(value):
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else None


def parse(text: str) -> dict:
    """Events from transcript lines (oldest first), newest MAX_EVENTS; plus the session title."""
    events, title, ai_title = [], "", ""
    lines = text.splitlines()
    for raw in lines:
        # Cheap pre-filter: only assistant rows and titles are ever parsed (tool results are skipped
        # before json.loads, however large they are).
        if '"assistant"' not in raw and 'title"' not in raw:
            continue
        try:
            row = json.loads(raw)
        except ValueError:
            continue                       # the torn first line of a tail, or a torn last line
        if not isinstance(row, dict):
            continue
        kind = row.get("type")
        if kind == "custom-title" and isinstance(row.get("customTitle"), str):
            title = _clean(row["customTitle"], 80)
            continue
        if kind == "ai-title":
            value = row.get("aiTitle") or row.get("title")
            if isinstance(value, str):
                ai_title = _clean(value, 80)
            continue
        if kind != "assistant" or row.get("isSidechain"):
            continue
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue
        message = row.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and str(block.get("text") or "").strip():
                events.append({"ts": ts.isoformat(timespec="seconds"), "kind": "say",
                               "text": _clean(block["text"], SAY_CHARS)})
            elif block.get("type") == "tool_use":
                events.append({"ts": ts.isoformat(timespec="seconds"), "kind": "step",
                               "text": step_label(block.get("name"), block.get("input"))})
    # Collapse runs of the same step ("Reading a file" x5) into one line with a count.
    merged = []
    for ev in events:
        last = merged[-1] if merged else None
        if last and ev["kind"] == "step" and last["kind"] == "step" and last["text"] == ev["text"]:
            last["count"] = last.get("count", 1) + 1
            last["ts"] = ev["ts"]
            continue
        merged.append(dict(ev))
    return {"title": title or ai_title, "events": merged[-MAX_EVENTS:]}


_cache = {"key": None, "value": None}
_cache_lock = threading.Lock()


_entry_cache = {}
_ENTRY = re.compile(rb'"entrypoint"\s*:\s*"([^"]{1,40})"')


def _entrypoint(path) -> str:
    """The session's entrypoint, from its first rows (cached; it never changes)."""
    key = str(path)
    if key not in _entry_cache:
        try:
            with path.open("rb") as fh:
                m = _ENTRY.search(fh.read(262_144))
            found = m.group(1).decode("ascii", "replace") if m else ""
        except OSError:
            return ""
        if not found:
            return ""                       # a brand-new file may not have its entrypoint row yet: ask again next time
        _entry_cache[key] = found
    return _entry_cache[key]


def _newest_session():
    """The most recently written session of Lukas's own (desktop app or terminal)."""
    best, best_mtime = None, -1.0
    for p in PROJECTS_DIR.glob("*.jsonl"):
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue                        # deleted between the listing and the stat (cleanup)
        if mtime > best_mtime and _entrypoint(p) in ENTRYPOINTS:
            best, best_mtime = p, mtime
    return best


def _read_parsed(path, size):
    """Parse the tail; if a huge line (an image row) leaves too few events, read further back."""
    want = TAIL_BYTES
    while True:
        with path.open("rb") as fh:
            fh.seek(max(0, size - want))
            text = fh.read(want).decode("utf-8", errors="replace")
        parsed = parse(text)
        if len(parsed["events"]) >= MIN_EVENTS or want >= size or want >= MAX_TAIL_BYTES:
            return parsed
        want = min(want * 2, MAX_TAIL_BYTES)


def payload(now=None) -> dict:
    """GET /api/live. Never raises: an unreadable transcript is {"ok": False, ...}."""
    now = now or datetime.now(timezone.utc)
    try:
        path = _newest_session()
        if path is None:
            return {"ok": True, "active": False, "title": "", "updated": None, "events": []}
        st = path.stat()
        key = (str(path), st.st_mtime_ns, st.st_size, _private_generation())   # a changed names file re-parses
        with _cache_lock:
            cached = _cache["value"] if _cache["key"] == key else None
        if cached is None:
            cached = _read_parsed(path, st.st_size)
            with _cache_lock:
                _cache["key"], _cache["value"] = key, cached
    except Exception as exc:               # never raises: a bad read is a message on the panel
        return {"ok": False, "error": f"the session log could not be read ({type(exc).__name__})",
                "active": False, "title": "", "updated": None, "events": []}
    events = cached["events"]
    updated = events[-1]["ts"] if events else None
    last = _parse_ts(updated) if updated else None
    active = bool(last and 0 <= (now - last).total_seconds() <= ACTIVE_SECONDS)
    return {"ok": True, "active": active, "title": cached["title"], "updated": updated, "events": events}


# ------------------------------------------------------------------------------------------ selftest

def _selftest() -> int:
    import tempfile
    fails = []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    global PRIVATE_NAMES
    saved_names = PRIVATE_NAMES
    names_dir = pathlib.Path(tempfile.mkdtemp(prefix="live_feed-names-"))
    PRIVATE_NAMES = names_dir / "private_names.json"

    def set_names(mode, names=("Zorvessa", "Quilby", "Brakenridge Tamsel", "Juniperra."), raw=None,       # synthetic
                  nicknames=("Zorvy", "Qb"), terms=("GlimmerHost", "QX417", "Brambleton Wifi", "Oakhurstia")):
        PRIVATE_NAMES.write_text(raw if raw is not None else json.dumps(
            {"mode": mode, "names": list(names), "nicknames": list(nicknames), "terms": list(terms)}), encoding="utf-8")
        _private_reset()
    set_names("any")

    now = datetime.now(timezone.utc)
    ts = now.isoformat().replace("+00:00", "Z")
    secret = "CANARY-7731"  # secret-scan: allow [export-reviewed]
    rows = [
        '{"type":"assistant","timestamp":"' + ts + '","message":{"content":[{"type":"thin',     # torn head
        json.dumps({"type": "custom-title", "customTitle": "{{CUSTOMER_NAME_1}} pitch"}),
        json.dumps({"type": "user", "timestamp": ts, "message": {"content": "Lukas's own words " + secret}}),
        json.dumps({"type": "assistant", "timestamp": ts, "message": {"content": [
            {"type": "thinking", "thinking": "private reasoning " + secret},
            {"type": "text", "text": "Rendering the video now."},
            {"type": "tool_use", "name": "Bash", "input": {"command": "rm -rf " + secret, "description": "Render the final video"}},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "C:/private/" + secret + ".txt"}},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "C:/b.txt"}},
            {"type": "tool_use", "name": "mcp__935044e1__create_draft", "input": {"to": [secret]}},
            {"type": "tool_use", "name": "mcp__Claude_Browser__navigate", "input": {"url": secret}},
            {"type": "tool_use", "name": "WebSearch", "input": {"query": secret}}]}}),
        json.dumps({"type": "user", "timestamp": ts, "message": {"content": [{"type": "tool_result", "content": secret}]},
                    "toolUseResult": secret}),
        json.dumps({"type": "assistant", "isSidechain": True, "timestamp": ts,
                    "message": {"content": [{"type": "text", "text": "helper says " + secret}]}}),
        json.dumps({"type": "assistant", "timestamp": ts, "message": {"content": [
            {"type": "tool_use", "name": "Agent", "input": {"description": "Research the market", "prompt": secret}}]}}),
        '{"type":"assistant","timestamp":"' + ts + '","message":{"content":[{"type":"text","te',     # torn tail
    ]
    out = parse("\n".join(rows))
    blob = json.dumps(out)
    check(secret not in blob, "no tool input, tool result, thinking, user text or helper transcript leaks")
    kinds = [(e["kind"], e["text"], e.get("count", 1)) for e in out["events"]]
    check(kinds == [("say", "Rendering the video now.", 1), ("step", "Render the final video", 1),
                    ("step", "Reading a file", 2), ("step", "Working in Gmail", 1), ("step", "Using the browser", 1),
                    ("step", "Searching the web", 1), ("step", "Research the market", 1)], f"events in order, merged: {kinds}")
    check(out["title"] == "{{CUSTOMER_NAME_1}} pitch", "session title")
    check(step_label("Edit", {"description": "sneaky " + secret}) == "Editing a file", "only Bash/PowerShell/Agent show a description")
    check(step_label("mcp__marty__search_vault") == "Searching the vault", "the chat lane's tools have labels")
    check(step_label("mcp__unknown__zzz") == "Using a connected service" and step_label("Mystery") == "Working", "unknown tools")
    check(STEP_CHARS == 80 and len(step_label("Bash", {"description": "word " * 100})) <= STEP_CHARS,
          "descriptions are capped at 80")
    check(shown_or_none("Untitled - Text Editor") == "Untitled - Text Editor" and shown_or_none(" \x07plain title ") == "plain title"
          and shown_or_none("C:/" + secret + "/notes.md - Editor") is None and shown_or_none("GlimmerHost photos") is None
          and shown_or_none("token " + secret) is None and shown_or_none(None) is None and shown_or_none("   ") is None,
          "shown_or_none: the same gate for text that is not a description (a window title)")
    long_title = shown_or_none("Notes about the plan " * 8)
    check(long_title is not None and len(long_title) <= STEP_CHARS and long_title.endswith("…")
          and long_title.startswith("Notes about the plan"),
          "shown_or_none: a long plain title is capped at 80 with an ellipsis, as step_label does")
    # A description that names a URL, a path, an address or a secret shows the plain label (canaries).
    # unshown: each is caught by the blocklist (_UNSHOWN) itself, so removing any one part fails a check.
    unshown = ["Fetch https://CANARY.example/x", "Open www.canary-site.com", "Check ftp://CANARY",
               r"Read C:\Users\{{WIN_USER}}\CANARY.txt", "Read C:/Users/{{WIN_USER}}/CANARY.txt", "List d:\\CANARY",
               r"Copy to \\nas\share\CANARY", r"Look in logs\CANARY", "Tail /var/log/CANARY.log",
               "Read ~/CANARY/notes", "Open ./CANARY/x", "Scan dashboard/CANARY/x.py", "List /etc",
               "Ping 192.168.1.44 for CANARY", "Probe 10.0.0.1:8765", "Reach fe80::1 CANARY", "Probe ::1",  # secret-scan: allow [export-reviewed]
               "Email canary.person@example.com", "Mail CANARY+x@corp.co.uk",  # secret-scan: allow [export-reviewed]
               "Use sk-CANARY1234", "Use sk_live_CANARY", "Use ghp_CANARY", "Use github_pat_CANARY",
               "Use AKIAABCDEFGHIJKL", "Use AIzaSyCANARY12345", "Use xoxb-CANARY", "Use glpat-CANARY",  # secret-scan: allow [export-reviewed]
               "Paste 27e45fde57d7933a69f6ead1bde9e48e4bc73d8f",
               # round 4: hosts and domains with no scheme, host:port, spelled addresses, 16+ opaque, hex,
               # JWT, one-slash paths, environment variables, Unicode tricks, phone and street addresses
               "Ping nas.local", "Open canary-host.tail1234.ts.net", "Check api.example.com for x", "Fetch CANARY.io",  # secret-scan: allow [export-reviewed]
               "Reach router.lan", "Call printer.home", "Hit svc.internal", "Look up 7.1.168.192.in-addr.arpa",
               "Probe localhost:8765", "Open nas:5000", "Reach marty-pc:11434", "Try db.lan:5432",
               "Ping 100 101 12 7", "Ping 100-101-12-7", "Reach 100.101 dot 12 dot 7", "Probe 192 168 1 44",
               "Probe 172-16-0-9", "Probe 10-0-0-1", "Probe ip-10-0-0-1", "Ping 8-8-4-4",
               "Mail lukas at gmail dot com", "Mail lukas [at] gmail [dot] com", "Mail x (at) corp (dot) co (dot) uk",
               "Use Ab3xY9kQ2mZ7pL4w", "Use key_9f8e7d6c5b4a3210zz", "Use run-8f3k2j9d0s1a7x6c",
               "Check a01306c0a098", "Verify 27e45fde57d7933a", "Paste eyJhbGciOiJIUzI1NiJ9", "Paste eyJhbGciOi",
               "Ping 8.8.8.8", "Reach 203.0.113.9 now", "Mail canary@nas.corp",  # secret-scan: allow [export-reviewed]
               "Read marty-vault/Zorvessa.md", "Open notes/Plan.md", "List marty-vault/Zorvessa", "List Projects/{{CUSTOMER_NAME_1}}",
               "Open dashboard/outbox", "Check %USERPROFILE%", "Echo $HOME", "Read $env:APPDATA", "Expand ${HOME}",
               "Read \u0441\u0435cret notes",
               "Use \u03c4oken", "Open \u0440aypal", "Call 999-555-0182", "Call (999) 555-0182", "Call 999.555.0182",
               "Call +1 999 555 0182", "Call +44 20 7946 0958", "Text 9995550182",
               "Drive to 1204 Oak Ridge Rd", "Ship to 55 W Main St", "Mail PO Box 118", "Mail P.O. Box 118",
               "Visit 9 Elm Court", "Go to County Road 123", "Find Hwy 76 exit",
               # round 5: a spelled-out domain (its secret-word canaries are _secret_line's now: secret_words below)
               "Open example dot com", "Visit canary dotnet"]
    # gated (round 5): plain enough for the blocklist, caught only by the plain-words gate
    gated = ["Ping zq918", "Reach marty-pc", "Wake the Marty-NAS", "Read AB3X Y9KQ", "Use KzQmPvTrXwLbNcYdHs",
             "Call 555-0182", "Check 123-45-6789", "Pay with 4111 1111 1111 1111", "Try AB 12 34 56",
             "Open example [.] com", "List Family/PRIVATE", "Open youtu.be", "Open canary.fr", "Reach canary.corp",
             "Reach 2001:db8::", "Open a\u2215b", "Open a\u2044b", "Open a\u29f8b", "Open a\uff0fb", "Use abc123def",
             "Send Bearer CANARY", "Store the api key CANARY", "Use sk live ABCDEFGH", "Resize to 16:9",
             "Read notes.zip", "Open the canary.mov page", "Use #CANARY", "Set x=1", "Read <CANARY>", "Run {x}",
             "Note: CANARY:1", "Ask \u4e2d\u6587", "Use CANARYKEY", "Use KzqmPvtrXw", "Dial 555-0182-home", "Read a\u6587\u4ef6.py",
             "Enter \u0664\u0668\u0662\u0661 now", "Read 1\u0664\u0668 notes",
             "Use AbracadabraBananaCoconut"]

    def label_everywhere(d):
        return (step_label("Bash", {"description": d}) == "Running a command"
                and step_label("PowerShell", {"description": d}) == "Running a command"
                and step_label("Agent", {"description": d}) == "Handing work to a helper")

    def by_block(d):
        return bool(_UNSHOWN.search(_dated(_fold(_CONTROL.sub("", d)))))

    leaked = [d for d in unshown + gated if not label_everywhere(d)]
    check(not leaked, f"{len(unshown) + len(gated)} URL, path, address, secret and odd-token descriptions show the "
                      f"plain label ({leaked})")
    check(not [d for d in unshown if not by_block(d)],
          f"each of {len(unshown)} blocklist canaries is caught by the blocklist itself "
          f"({[d for d in unshown if not by_block(d)]})")
    gate_miss = [d for d in gated if by_block(d) or _plain_words(_fold(d))]
    check(not gate_miss, f"each of {len(gated)} gate canaries passes the blocklist and is caught by the gate ({gate_miss})")
    # (round 6) Each new rule catches its canaries ITSELF (so removing it fails a check), and each line
    # below was shown by round 5 (the skeptic's probes; synthetic values only).
    #   1. _plain_ascii: whitespace and separators str.split() swallows, which no other rule sees
    ascii_only = ["Build the board\u2028now", "Build the board\u1680now", "Run\x85the check", "Build the board\tnow",
                  "Build the board\nnow", "Check the board\u2029again", "Sort Zor\u1680vessa photos"]
    check(not [d for d in ascii_only if not label_everywhere(d)], "round 6: a separator, tab or newline shows the plain label "
          f"({[d for d in ascii_only if not label_everywhere(d)]})")
    check(not [d for d in ascii_only if _plain_ascii(_fold(d))],
          f"each of {len(ascii_only)} non-ASCII canaries is caught by _plain_ascii itself")
    check(not [d for d in ascii_only[:6] if by_block(d) or not _plain_words(_fold(d)) or _secret_line(_fold(d))],
          "and no other rule catches the first six (the ASCII rule is load-bearing)")
    check(all(_plain_ascii(_fold(d)) for d in ("Plan it \u2013 then \u2014 ship\u2026", "Read \u201cnotes\u201d and Lukas\u2019s",
                                               "Cafe\u0301 menu", "Use \uff54\uff4f\uff4b\uff45\uff4e")),
          "curly quotes, en and em dashes, the ellipsis, accents and fullwidth letters (folded) pass the ASCII rule")
    #   2. _secret_line (d): any secret word, letters-only values, a value anywhere, CamelCase and glued forms
    secret_words = ["Enter password hunter", "Log in with password PurpleMonkey", "Type password bluesky into the login",
                    "Use the passphrase purple monkey dishwasher", "Wi-Fi password SunnyBeach", "Enter pw hunter",
                    "Set the token abcdef", "Paste token QwErTyUiOp", "Set password to BlueSky", "The password is BlueSky",
                    "Use secret MangoTango", "Set the password for the router 4821", "Change the password on the NAS 4821",
                    "Try password then 4821", "Save the api key for later 1234", "Use token ABCDE", "Try PIN then 1234",
                    "Use PassWordOne", "Save mypassword", "Set the DoorPin", "Enter the PINcode", "Enter the OTP",
                    "Count tokens in the prompt", "Check whether sessions bill an API key or the Max plan",
                    "Refresh the access_token", "Read the secret", "Load credentials", "Unlock with the passphrase",
                    "Pin the artifact to the sidebar", "Revoke the test token", "Use creds", "Run pwd",
                    "Send Bearer 7731", "Set the TOKEN to CANARY", "Store the api key 7731", "Set API_KEY=CANARY",
                    "Set apikey: CANARY", "Enter the password CANARY9", "Reset passwd=CANARY", "Use to\u200bken 7731",
                    "Use \uff54\uff4f\uff4b\uff45\uff4e: CANARY", "Use pass\x00word=CANARY", "Use t\u0301oken 7731",
                    "Use to\u0327ken: CANARY", "Enter PIN 4821", "Set password=x", "The token is abc",
                    "Set the password to hunter", "Use the passcode 1234", "Use the private key", "Rotate secrets"]
    #   (c) a code, key, pw, creds or PIN followed by 3+ digits, and (b) checked before times and dates
    #   become "when": each is caught by the code rule, not by a secret word
    code_digits = ["Try the garage code 4821", "Enter door code 1234", "Unlock code 4821", "Enter recovery code 4821 9372",
                   "Wi-Fi key 4821", "Use key: 12 34 56", "Garage code is 4821", "Use the DoorCode 4821", "Try key4821",
                   "Enter door code 12:34", "Gate code 9/24/26", "Alarm code 1-2-3-4", "Use the codes 555 and 1"]
    check(not [d for d in secret_words + code_digits if not label_everywhere(d)],
          "round 6: a secret word anywhere, or a code or key with 3+ digits, shows the plain label "
          f"({[d for d in secret_words + code_digits if not label_everywhere(d)]})")
    check(not [d for d in secret_words + code_digits if not _secret_line(_fold(_CONTROL.sub('', d)))],
          f"each of {len(secret_words) + len(code_digits)} secret canaries is caught by _secret_line itself "
          f"({[d for d in secret_words + code_digits if not _secret_line(_fold(_CONTROL.sub('', d)))]})")
    check(not [d for d in code_digits if re.search(_SECRET_WORD, _fold(d), re.IGNORECASE)],
          "the code canaries hold no secret word (the code rule is load-bearing)")
    check(not [d for d in code_digits[9:11] if _secret_line(_dated(_fold(d)))],
          "a code written as a time or date is only caught before _dated (the order is load-bearing)")
    shown = ["Render the final video", "Run staged jr_lane selftest", "Check server.py syntax",
             "Count the 12 rows in 3 files", "Build the board at 16:30", "Research the market",
             "Apply the jr_lane patch", "Stage the Jr SSE error fix in server.py",
             "Find every Jr error path in server and jr_lane", "Run desk-top task-list check",
             # round 4: what the new shapes must not catch
             "Read notes.md", "Check server.py and app.js", "Meet at 4:30", "Build at 2026-09-26T16:30",
             "Read app.js:1833", "Check server.py:1709-1711", "Look at it again", "Run 3 checks on the way home",
             "Fix 12 files on the drive", "Spend $5 on 50% of it", "Rows 10-20 and 1709-1711",
             "Render the final video for {{CUSTOMER_NAME_1}}", "Run test_deploy_toolprivacy twice",
             "Stage round 4 with 3447 descriptions", "Cafe\u0301 menu update", "Compare base and cand",
             # round 5: times and dates, and the gate's allowed forms (its study vocabulary, "Count tokens in
             # the prompt", holds a secret word: withheld since round 6, see secret_words below)
             "Check whether sessions bill the Max plan", "Meet at 16:30:05", "Build at 4:30pm",
             "Plan 9/24/2026 and 9/14-9/17", "Check for taps newer than 2:11:48", "Set up PowerShell and YouTube",
             "Check LinkedIn, iPhone and CapCut", "Run the follow-up re-run", "Render 4K at 60fps", "Pull 24GB",
             "Take the 1st and 2nd", "It's done, isn't it?", "Check (again) - quickly!", "Read the API docs",
             "Read \u201cnotes\u201d and Lukas\u2019s plan", "Try 3.5 then 2 more", "Price at $4.50 each",
             # round 6: near misses of the secret, code and non-ASCII rules
             "Check the spinning wheel", "Keep the pinned card", "Run the tokenizer", "Scan the barcode 4821",
             "Open the key file", "Press key 5 twice", "Fix error code 12", "Read the secretary notes",
             "Rotate the Wi-Fi key", "Plan it \u2013 then \u2014 ship\u2026", "Run the passport check"]
    check([step_label("Bash", {"description": d}) for d in shown] == shown,
          "plain-word descriptions (file names, numbers, times, dates, study words) are still shown "
          f"({[d for d in shown if step_label('Bash', {'description': d}) != d]})")
    # the family-name rule, from private_names.json (never hard-coded): synthetic names only, here and in
    # every test. The shipped mode is "any".
    media = ["Sort Zorvessa's photos", "Crop the video of Quilby", "Trim Brakenridge Tamsel clip", "Upscale Juniperra pics",
             "Find Zorvessa pictures", "Blur Quilby's face", "Move Brakenridge Tamsel private files",
             "Screen Juniperra bath video", "Tag Zorvessa image set", "Check Quilby selfies", "Sort Z\u0301orvessa's photos",
             # round 5: the widened media list (the real misses were frame, render, outfit, CapCut edits)
             "Render Quilby's frame with the mask off", "Render Zorvessa in the paleontologist outfit",
             "Style-scan all of Quilby's finished CapCut edits", "Make a contact sheet of Zorvessa",
             "Pull Quilby vids", "Save the Zorvessa recording", "Cut a reel for Quilby", "Take a screenshot of Zorvessa",
             "Open Quilby's album", "Check the Zorvessa camera roll", "Crop Quilby headshots", "Grab Zorvessa thumbnails",
             "Play Zorvessa audio", "Find the Quilby stills", "Watch the Zorvessa movie", "Move Quilby webm files",
             "Blur Zorvessa towel shots", "Find Quilby swim footage", "Sort the Zorvessa costume pictures"]
    plain = ["Email Zorvessa the plan", "Check Quilby's school schedule", "Render the final video for {{CUSTOMER_NAME_1}}"]
    variants = ["Sort Zorvessas photos", "Sort Zorvessa_photos", "Sort ZorvessaPhotos", "Sort myZorvessaPhotos",
                "Sort Z o r v e s s a photos", "Sort Zor\u3164vessa photos", "Sort Zor\u2800vessa photos",
                "Sort Zor\u115fvessa photos", "Sort Brakenridge-Tamsel photos", "Sort Brakenridge 2 Tamsel photos",
                "Sort Juniperra photos", "Sort JUNIPERRA's pics", "Sort Zorvessa.photos", "Sort 2Zorvessa photos"]
    hidden = lambda d: step_label("Bash", {"description": d}) == "Running a command"   # noqa: E731
    check(all(hidden(d) for d in media + plain[:2] + variants) and not hidden(plain[2]),
          "any (the shipped mode): every description naming a family member is the plain label, with or without "
          f"a media word, in every spelling ({[d for d in media + plain[:2] + variants if not hidden(d)]})")
    check(all(step_label("Agent", {"description": d}) == "Handing work to a helper"
              and step_label("PowerShell", {"description": d}) == "Running a command" for d in media + plain[:2]),
          "the name rule covers Bash, PowerShell and helper descriptions")
    check(all(_names_private(_fold(d)) for d in media + plain[:2] + variants),
          "each of those is caught by the name rule itself, not only by the gate (fillers, joins, spacing) "
          f"({[d for d in media + plain[:2] + variants if not _names_private(_fold(d))]})")
    check(not hidden("Email Orvessa the plan") and not hidden("Sort the photos"),
          "a name that is not listed, or no name, is not hidden by the rule")
    # (round 6) The matcher: no start-of-word bound, any run of non-letters between a name's letters, and
    # the name spelled backwards; the same for nicknames and the private terms (device names, the Wi-Fi
    # name, the home town). Each of these was shown by round 5, and each is caught by the rule itself.
    loose_names = ["Sort myzorvessa photos", "Sort Bigzorvessa photos", "Open beachzorvessa.jpg",
                   "Open happybdayzorvessa.mp4", "Sort MYZORVESSA photos", "Sort Zorv  -  essa photos",
                   "Sort Zor-v-ess-a photos", "Sort J....uniperra", "Sort J--u--n--iperra", "Sort Zor4vessa photos",
                   "Sort assevroz photos", "Sort ASSEVROZ photos", "Email ybliuq the plan", "Sort lesmaT egdirnekarB",
                   "Email Quil by", "Email Q uilby", "Read notes_zorvessa", "Email Zorvy the plan", "Sort myzorvy pics",
                   "Ask Qb about it"]
    check(all(hidden(d) and _names_private(_fold(d)) for d in loose_names),
          "round 6: a family name or nickname glued, gapped, digit-split or backwards is caught by the name rule "
          f"({[d for d in loose_names if not (hidden(d) and _names_private(_fold(d)))]})")
    check(not hidden("Read the qbit notes") and not hidden("Email Orvessa the plan") and not hidden("Sort the photos"),
          "a short entry (Qb) must stand as a whole word; an unlisted name or no name is not hidden")
    terms_in = ["Restart GlimmerHost", "Wake glimmerhost", "Check GLIMMERHOST disk space", "Open glimmer_host.log",
                "Wake the g l i m m e r h o s t", "Read myglimmerhost notes", "Check tsohremmilg", "Read qx417.log",
                "Read QX417_backup.log", "Ping qx-417", "Open bigqx417 share", "Read q x 4 1 7 notes",
                "Join the Brambleton Wifi", "Join brambletonwifi", "Join BrambletonWiFi now", "Drive to Oakhurstia",
                "Drive to oakhurstiatown", "Plan the aitsruhkao trip"]
    check(all(hidden(d) and _names_private(_fold(d)) for d in terms_in),
          "round 6: a private term (a device, the Wi-Fi, the town) in every form is caught by the terms rule "
          f"({[d for d in terms_in if not (hidden(d) and _names_private(_fold(d)))]})")
    check(not hidden("Check the glimmer of hope") and not hidden("Read the q notes"),
          "a term's own pieces apart from it are not hidden")
    long_line = ("Z 0 r v e s s " * 4000) + ("q_x_4_1_" * 4000) + ("tsohremmil " * 2000)
    t0 = time.monotonic()
    _names_private(_fold(long_line))
    check(time.monotonic() - t0 < 2.0, f"a {len(long_line)}-character near miss goes through the private rule in under 2 s (linear matching)")
    set_names("with-media")
    check(all(hidden(d) for d in media + variants) and not any(hidden(d) for d in plain),
          f"with-media: a family name with a media word is the plain label, a name alone is shown "
          f"({[d for d in media + variants if not hidden(d)] + [d for d in plain if hidden(d)]})")
    check(all(_MEDIA.search(_fold(w)) for w in ("IMG_0042", "DSC_1", "\U0001F4F7", "\U0001F3A5", "clip.mkv", "voice memo",
                                                   "undressing", "the toilet", "gallery", "webcam")),
          "with-media: file prefixes, camera emoji and the rest of the widened list")
    set_names("off")
    check(not any(hidden(d) for d in media[:-1] + plain), "off: the name rule hides nothing")
    set_names("any", names=["{{CUSTOMER_NAME_1}}"])
    check(hidden("Render the final video for {{CUSTOMER_NAME_1}}") and not hidden("Sort Zorvessa's photos"),
          "the names come from the file (a changed list takes effect without a restart)")
    rest = ', "nicknames": [], "terms": ["GlimmerHost"]}'          # each case below breaks one thing only
    for label, raw in (("missing", None), ("not JSON", "{nope"), ("a bad mode", '{"mode": "some", "names": ["Zorvessa"]' + rest),
                       ("names not a list", '{"mode": "any", "names": "Zorvessa"' + rest),
                       ("a blank name", '{"mode": "any", "names": ["Zorvessa", " "]' + rest), ("a list", "[1]"),
                       ("an empty name list", '{"mode": "any", "names": []' + rest),
                       ("a name with no letters", '{"mode": "any", "names": ["Zorvessa", "--"]' + rest),
                       ("no mode", '{"names": ["Zorvessa"]' + rest),
                       # round 6: the nicknames and terms lists
                       ("no terms", '{"mode": "any", "names": ["Zorvessa"], "nicknames": []}'),
                       ("terms not a list", '{"mode": "any", "names": ["Zorvessa"], "nicknames": [], "terms": "GlimmerHost"}'),
                       ("a blank term", '{"mode": "any", "names": ["Zorvessa"], "nicknames": [], "terms": ["GlimmerHost", " "]}'),
                       ("a term with no letters", '{"mode": "any", "names": ["Zorvessa"], "nicknames": [], "terms": ["-"]}'),
                       ("a term not a string", '{"mode": "any", "names": ["Zorvessa"], "nicknames": [], "terms": [7]}'),
                       ("no nicknames", '{"mode": "any", "names": ["Zorvessa"], "terms": []}'),
                       ("a blank nickname", '{"mode": "any", "names": ["Zorvessa"], "nicknames": [""], "terms": []}')):
        if raw is None:
            PRIVATE_NAMES.unlink()
            _private_reset()
        else:
            set_names(None, raw=raw)
        check(hidden("Render the final video") and hidden("Build the board")
              and step_label("Agent", {"description": "Research the market"}) == "Handing work to a helper",
              f"private_names.json {label}: no description is shown at all (fail closed)")
    set_names("any", nicknames=(), terms=())
    check(not hidden("Render the final video") and hidden("Email Zorvessa the plan"),
          "empty nicknames and terms lists are valid (only the names are required to be non-empty)")
    set_names("off")
    check(hidden("Restart GlimmerHost") and not hidden("Email Zorvessa the plan"),
          "mode off: family names show, a private term is still hidden (terms ignore the mode)")
    set_names("any")
    # (2026-09-28) A cold cache read by several threads at once: every one gets the rule, none fails
    # closed. Without _private_lock the losers saw a fresh "checked" with "rule" still None, and their
    # parse of the transcript (cached by its mtime) showed the plain label until the file next changed.
    _private_reset()
    barrier, got = threading.Barrier(8), []
    workers = [threading.Thread(target=lambda: (barrier.wait(), got.append(_names_private(_fold("Render the final video")))))
               for _ in range(8)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    check(len(got) == 8 and not any(got), f"8 threads on a cold cache all get the rule at once, none fails closed ({sum(got)} did)")
    # The real lists live only in the shipped private_names.json: none of its names, nicknames or terms
    # may appear in this source (counted, never printed).
    try:
        shipped = json.loads(saved_names.read_text(encoding="utf-8"))
        real = [n for key in PRIVATE_LISTS for n in (shipped.get(key) or [])]
    except (OSError, ValueError, AttributeError, TypeError):
        real = None
    if real is None:
        print("  (no readable private_names.json next to this file: the no-values-in-source check is skipped)")
    else:
        source = _fold(pathlib.Path(__file__).read_text(encoding="utf-8")).lower()
        found = sum(1 for n in real if isinstance(n, str) and n.strip() and _fold(n.strip()).lower() in source)
        check(found == 0, f"none of the {len(real)} shipped private names, nicknames and terms appears in live_feed.py "
                          f"({found} do)")

    # tool_label: a saved chat step, either lane
    check(tool_label("read_file") == "Reading a file" and tool_label("recon_probe") == "Checking a web server"
          and tool_label("search_vault") == "Searching the vault", "the metered lane's names get the live step labels")
    check(tool_label("Reading a file") == "Reading a file" and tool_label("Using a connected service")
          == "Using a connected service", "a Max-lane step (already a label) passes through")
    check(tool_label("rm_rf_" + secret) == "Working" and tool_label(None) == "Working"
          and tool_label({"x": secret}) == "Working", "a refused or odd name never reaches the page")
    # activity_label / activity_row: GET /api/activity and the Jobs tab
    rows_in = [
        {"ts": ts, "tool": "Bash", "summary": "curl -H 'Authorization: Bearer " + secret + "'"},       # old row, no description
        {"ts": ts, "tool": "Bash", "summary": "Build the board", "desc": "Build the board"},             # new row, description
        {"ts": ts, "tool": "PowerShell", "summary": "PowerShell: Get-Content C:/" + secret},
        {"ts": ts, "tool": "Read", "summary": "Read: C:/Users/" + secret + ".txt"},
        {"ts": ts, "tool": "Grep", "summary": "Grep: " + secret},
        {"ts": ts, "tool": "WebFetch", "summary": "fetched: https://" + secret + ".example/x"},
        {"ts": ts, "tool": "WebSearch", "summary": "searched: " + secret},
        {"ts": ts, "tool": "SendMessage", "summary": "SendMessage: " + secret},
        {"ts": ts, "tool": "Agent", "summary": AGENT_PREFIX + "Research the market"},
        {"ts": ts, "tool": "Edit", "summary": "Edit: C:/" + secret, "desc": "sneaky " + secret},      # desc only for DESCRIBED
        {"ts": ts, "tool": "mcp__935044e1__send_message", "summary": "mcp__935044e1__send_message: " + secret},
    ]
    served = [activity_row(r) for r in rows_in]
    check(secret not in json.dumps(served), "activity rows: no command, path, pattern, URL, query or message body")
    check([r["summary"] for r in served] == ["Running a command", "Build the board", "Running a command", "Reading a file",
                                              "Searching files", "Reading a web page", "Searching the web",
                                              "Checking in with a helper", "Research the market", "Editing a file",
                                              "Working in Gmail"], f"activity rows: live's labels ({[r['summary'] for r in served]})")
    check(all(set(r) == {"ts", "tool", "summary"} for r in served) and activity_row([1]) is None
          and activity_label("x") == "Working", "activity rows: the served shape, and odd lines")
    check([r["tool"] for r in served] == ["Command", "Command", "Command", "Files", "Search", "Web", "Web", "Helper",
                                          "Helper", "Files", "Gmail"], f"activity rows: tool is the family ({[r['tool'] for r in served]})")
    check(set(FAMILIES) == set(LABEL_TEXTS) and all(len(f) <= 9 and "_" not in f for f in FAMILIES.values()),
          "every fixed label has a short family word (no raw name, no __)")
    check(tool_family("mcp__935044e1-e1e2__create_draft") == "Gmail" and tool_family("mcp__zz__" + secret) == "Service"
          and tool_family(secret) == "Working" and tool_family(None) == "Working" and tool_family({"x": 1}) == "Working",
          "an mcp__ id or an odd name never comes back raw")

    with tempfile.TemporaryDirectory() as tmp:
        global PROJECTS_DIR
        saved = PROJECTS_DIR
        PROJECTS_DIR = pathlib.Path(tmp)
        try:
            check(payload()["events"] == [] and payload()["ok"], "no session file: empty, ok")
            desk = json.dumps({"type": "attachment", "entrypoint": "claude-desktop"})
            old = pathlib.Path(tmp) / "old.jsonl"
            old.write_text(desk + "\n" + json.dumps({"type": "assistant", "timestamp": "2026-01-01T00:00:00Z",
                                       "message": {"content": [{"type": "text", "text": "old session"}]}}) + "\n", encoding="utf-8")
            new = pathlib.Path(tmp) / "new.jsonl"
            new.write_text(desk + "\n" + "\n".join(rows[1:-1]) + "\n", encoding="utf-8")
            os.utime(old, (1, 1))
            warm = pathlib.Path(tmp) / "warmup.jsonl"            # the voice line's SDK warm-up, newest of all
            warm.write_text(json.dumps({"type": "attachment", "entrypoint": "sdk-py"}) + "\n" + json.dumps(
                {"type": "assistant", "timestamp": ts, "message": {"content": [{"type": "text", "text": "Warmup ping " + secret}]}}) + "\n",
                encoding="utf-8")
            check("Warmup" not in json.dumps(payload()), "an SDK session is never shown, even when it's newest")
            odd = pathlib.Path(tmp) / "odd.jsonl"
            odd.write_text(desk + "\n" + json.dumps({"type": "assistant", "timestamp": ts, "message": "not a dict"}) + "\n", encoding="utf-8")
            check(payload()["ok"], "an odd message shape doesn't break the feed")
            odd.unlink()
            p = payload()
            check(p["active"] and p["events"][0]["text"] == "Rendering the video now.", "the newest session file, active")
            p2 = payload(now=datetime(2030, 1, 1, tzinfo=timezone.utc))
            check(not p2["active"], "quiet after ten minutes")
            big = pathlib.Path(tmp) / "new.jsonl"
            with big.open("ab") as fh:
                fh.write(b"x" * (TAIL_BYTES + 10) + b"\n")
                fh.write((json.dumps({"type": "assistant", "timestamp": ts, "message": {"content": [
                    {"type": "text", "text": "after a huge line"}]}}) + "\n").encode())
            p3 = payload()
            check(p3["events"] and p3["events"][-1]["text"] == "after a huge line", "a tail past a huge line still parses")
            with big.open("ab") as fh:                               # now the NEWEST line is the huge one
                fh.write(b'{"type":"user","toolUseResult":"' + b"y" * (TAIL_BYTES * 2) + b'"}\n')
            p4 = payload()
            check(p4["events"] and p4["events"][-1]["text"] == "after a huge line", "a huge newest line: it reads further back")
            # (2026-09-28, the outside audit) The private rule runs inside parse(), and parse is cached by the
            # transcript's (path, mtime, size). With the transcript untouched, a changed private_names.json must
            # still change what is served: the names file's identity is part of the cache key now.
            with big.open("ab") as fh:
                fh.write((json.dumps({"type": "assistant", "timestamp": ts, "message": {"content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "x", "description": "Email Quilby the plan"}}]}})
                    + "\n").encode())
            set_names("any", names=["Zorvessa"])                 # Quilby is not listed: the description shows
            p5 = payload()
            set_names("any", names=["Zorvessa", "Quilby"])       # the transcript is unchanged; only the names file
            p6 = payload()
            check(p5["events"][-1]["text"] == "Email Quilby the plan" and p6["events"][-1]["text"] == "Running a command",
                  f"a changed private_names.json re-parses the cached transcript ({p5['events'][-1]['text']!r} -> "
                  f"{p6['events'][-1]['text']!r})")
        finally:
            PROJECTS_DIR = saved
    PRIVATE_NAMES = saved_names
    _private_reset()
    try:
        for leftover in names_dir.iterdir():
            leftover.unlink()
        names_dir.rmdir()
    except OSError:
        pass
    print("live_feed selftest: " + ("all passed" if not fails else f"{len(fails)} FAILED"))
    return 0 if not fails else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        sys.exit(_selftest())
    print(json.dumps(payload(), indent=1)[:3000])
