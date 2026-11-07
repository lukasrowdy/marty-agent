"""
Teach Jr (MJ Dashboard, "Teach Jr" Phase 1, 2026-09-25).

A way for Lukas to save a good Marty answer into Marty Jr.'s memory. Memory here is
RETRIEVAL, not retraining: the answer is condensed into a plain markdown note under Jr's
reference library (jr/library/taught), which jr_tools' library_search + read_file already
scan. So a note written here is findable by Jr immediately, even while his encrypted
history is locked.

This is a SERVER-SIDE action, separate from Jr's own fenced toolset (jr_tools). Jr never
calls it; the dashboard does, on Lukas's click. The only write anywhere in this module is
one new file under TAUGHT_ROOT:

  * the filename is built here (slug of the title + a random short id), never taken from
    the model or the caller, so a title cannot steer the path;
  * writes are exclusive-create ("x"), so an existing note is never overwritten;
  * the final path is checked to sit inside TAUGHT_ROOT before anything opens it;
  * the body is size-capped, and the whole note is stripped of em dashes (Lukas's rule:
    no em dashes in anything drafted for him).

Distillation runs on the FREE Claude subscription lane (switchboard.ask_claude_sub), so
teaching costs $0 metered. If that call fails or returns nothing usable, save_taught falls
back to a truncated raw save titled from the answer's first line, so a teach never fails
just because the model was unavailable.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import sys
from datetime import datetime

import jr_tools  # same folder; reused only for AGENT_ROOT / LIBRARY_ROOT (read-only)

# switchboard lives in my-agent/tools. The dashboard server already puts it on sys.path;
# add it here too so this module (and its tests) import cleanly on their own.
_TOOLS_DIR = jr_tools.AGENT_ROOT / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
import switchboard  # noqa: E402

# The one write root: Jr's plaintext reference shelf, in a folder of its own so taught notes
# are easy to see, prune, or exclude later. Tests point this at a temp dir.
TAUGHT_ROOT = jr_tools.LIBRARY_ROOT / "taught"

DISTILL_MODEL = switchboard.DEFAULTS["claude_sub"]      # "sonnet": capable, $0 on the Max plan
MAX_INPUT_CHARS = 12_000        # how much of the answer is sent to the distiller
MAX_CONTEXT_CHARS = 2_000       # how much of the question is sent as context
MAX_BODY_CHARS = 8_000          # cap on the saved note body
TITLE_MAX = 120
SHORT_ID_BYTES = 3              # 6 hex chars of uniqueness on the filename
PREVIEW_CHARS = 200

# Em dash and en dash: replaced everywhere before a note is written (Lukas's no-em-dash rule).
_DASHES = {"—": ", ", "–": "-"}


def _no_dashes(text: str) -> str:
    """Text with em/en dashes removed, doubled spaces collapsed. Guarantees the output holds
    no em dash character, whatever the distiller returned."""
    if not text:
        return ""
    for bad, good in _DASHES.items():
        text = text.replace(bad, good)
    return re.sub(r"[ \t]{2,}", " ", text)


def _slug(title: str) -> str:
    """A safe filename stem: lowercase, only [a-z0-9-], never empty. Any path characters in the
    title (slashes, dots, '..') are dropped here, so a title can never steer the write path."""
    s = re.sub(r"[^a-z0-9]+", "-", (title or "").lower()).strip("-")
    return (s[:60].strip("-")) or "taught"


def _clean_title(title) -> str:
    if not isinstance(title, str):
        return ""
    return _no_dashes(" ".join(title.split()))[:TITLE_MAX].strip()


def _first_line_title(answer_text: str) -> str:
    for line in (answer_text or "").splitlines():
        line = line.strip().lstrip("#*->-• ").strip()
        if line:
            return _clean_title(line) or "Taught note"
    return "Taught note"


def _keywords(raw) -> list[str]:
    """Normalise the distiller's keywords into a short list of clean, lowercase terms."""
    items = []
    if isinstance(raw, str):
        items = re.split(r"[,\n]", raw)
    elif isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    out = []
    for kw in items:
        kw = _no_dashes(str(kw)).strip().strip("#").lower()
        kw = re.sub(r"\s+", " ", kw)
        if kw and kw not in out:
            out.append(kw)
        if len(out) >= 8:
            break
    return out


def _parse_json_object(text: str) -> dict:
    """Read the JSON object the distiller was asked for, tolerant of code fences or stray prose
    around it. Raises ValueError if no object is found."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty distiller output")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        obj = json.loads(text[start:end + 1])
        if isinstance(obj, dict):
            return obj
    raise ValueError("distiller output was not a JSON object")


DISTILL_SYSTEM = (
    "You condense one answer into a single, self-contained reference note for a local "
    "assistant's memory library. Output ONLY a JSON object with exactly these keys: "
    '"title", "keywords", "body". '
    "title: a short descriptive name, at most 12 words. "
    "keywords: a JSON array of 3 to 8 lowercase search terms. "
    "body: the answer rewritten tight and standalone in plain markdown, about 200 words or "
    "fewer, keeping the facts, steps and reasoning while dropping greetings and chat filler. "
    "The note must stand on its own, since the reader will not have the original conversation. "
    "Do not use em dashes anywhere; use commas or shorter sentences instead. "
    "Do not wrap the JSON in code fences and write nothing outside the JSON object."
)


def distill(answer_text, context=None) -> dict:
    """Condense an answer into {"title","keywords","body"} using the free Claude subscription
    lane. Raises on any failure (network, empty or unparseable output); save_taught catches
    that and falls back to a raw save."""
    src = (answer_text or "").strip()[:MAX_INPUT_CHARS]
    if not src:
        raise ValueError("nothing to distill")
    user = src
    if context:
        user = ("Question that prompted this answer:\n" + str(context)[:MAX_CONTEXT_CHARS]
                + "\n\nAnswer to condense into a reference note:\n" + src)
    result = switchboard.ask_claude_sub(DISTILL_MODEL, DISTILL_SYSTEM,
                                        [{"role": "user", "content": user}])
    # ask_claude_sub returns (text, model_reported, usage, extra); other lanes return 3.
    text = result[0] if isinstance(result, (list, tuple)) else result
    obj = _parse_json_object(text)
    title = _clean_title(obj.get("title"))
    body = obj.get("body")
    if not title or not isinstance(body, str) or not body.strip():
        raise ValueError("distiller output was missing a title or body")
    return {
        "title": title,
        "keywords": _keywords(obj.get("keywords")),
        "body": _no_dashes(body).strip()[:MAX_BODY_CHARS],
    }


def _fallback_note(answer_text: str) -> dict:
    """A raw, truncated save used when distillation is unavailable. Title from the first line,
    no keywords, the answer itself as the (capped) body."""
    return {
        "title": _first_line_title(answer_text),
        "keywords": [],
        "body": _no_dashes(answer_text).strip()[:MAX_BODY_CHARS],
    }


def _taught_root() -> pathlib.Path:
    """The write root as an absolute path, created if missing. Read at call time so tests may
    point TAUGHT_ROOT elsewhere."""
    root = pathlib.Path(TAUGHT_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return pathlib.Path(os.path.realpath(root))


def _write_note(note: dict, context=None) -> dict:
    """Write the note as a NEW file under TAUGHT_ROOT. Never overwrites, never escapes the root."""
    root = _taught_root()
    title = _clean_title(note.get("title")) or "Taught note"
    body = _no_dashes(str(note.get("body") or "")).strip()[:MAX_BODY_CHARS]
    keywords = _keywords(note.get("keywords"))

    prov_context = _no_dashes(" ".join(str(context or "chat").split()))[:200] or "chat"
    header = [f"# {title}", ""]
    if keywords:
        header.append("keywords: " + ", ".join(keywords))
    header.append(f"Taught by Marty, {datetime.now():%Y-%m-%d}, from: {prov_context}")
    header.append("")
    content = _no_dashes("\n".join(header) + "\n" + body).rstrip() + "\n"

    slug = _slug(title)
    for _ in range(50):
        name = f"{slug}-{secrets.token_hex(SHORT_ID_BYTES)}.md"
        path = pathlib.Path(os.path.realpath(root / name))
        # The built name has no separators, but prove the final path stays inside the root
        # before opening it (defence in depth against any future change to naming).
        if path.parent != root:
            raise ValueError("refused: the taught note path escaped its folder")
        try:
            with open(path, "x", encoding="utf-8", newline="\n") as f:   # "x": never overwrite
                f.write(content)
        except FileExistsError:
            continue
        preview = body.strip().replace("\n", " ")[:PREVIEW_CHARS]
        return {"ok": True, "path": str(path), "title": title, "preview": preview}
    raise ValueError("could not find a free filename for the taught note")


def save_taught(answer_text, title=None, context=None) -> dict:
    """Distill an answer and save it to Jr's library. Returns
    {"ok","path","title","preview"}. A caller-supplied title overrides the distilled one.
    Falls back to a raw truncated save if distillation fails, so a teach never dies on the
    model being down."""
    if not isinstance(answer_text, str) or not answer_text.strip():
        raise ValueError("nothing to teach: the answer text is empty")
    try:
        note = distill(answer_text, context=context)
    except Exception:
        note = _fallback_note(answer_text)
    override = _clean_title(title)
    if override:
        note["title"] = override
    return _write_note(note, context=context)
