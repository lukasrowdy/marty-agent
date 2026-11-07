#!/usr/bin/env python3
"""gen_boot.py - generate Marty's per-host boot files from the one master.

The master is CLAUDE.md in my-agent. It is the authored, compaction-safe file
for Claude Code and is NEVER written by this tool, only read. Every other host
reads a copy that is identical to the master except for a few declared, host-
specific spans (the intro, the compaction line, the confer rule) plus an
appended host note. Authoring the identity and rules once, here, is what stops
the copies from drifting the way the hand-maintained AGENTS.md did
("it's just you and Codex", ".Codex/agents/").

Design guarantees:
  - Faithful by default: anything not explicitly transformed is copied verbatim,
    so a new rule added to CLAUDE.md reaches every host with no extra work.
  - Refuses to emit a broken file: each transform is anchored on a substring that
    must occur exactly once in the master. If an anchor is missing or ambiguous
    (the master changed shape), that host is aborted and the anchor is named.
  - Anti-drift guard: after transforming, the output must NOT still contain any
    host-specific phrase the profile was supposed to remove (e.g. a Codex copy
    must not say "every Claude Code session"). If it does, the profile is
    incomplete and the file is refused.

Usage:
  py tools/gen_boot.py                # write the active host files (backs up any that differ)
  py tools/gen_boot.py --check        # write nothing; exit 1 if any target is stale/missing
  py tools/gen_boot.py --diff         # show what would change, write nothing
  py tools/gen_boot.py --gemini       # also emit ~/.gemini/AGENTS.md (for Antigravity)
  py tools/gen_boot.py --only codex   # restrict to one profile

Run --check at every checkpoint; wire it into the supervisor or a pre-commit hook
so a CLAUDE.md edit that never regenerated the copies fails loudly.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import hashlib
import os
import sys
from pathlib import Path

# UTF-8 out, so the cp1252 console never kills a run on an em dash in the diff.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MY_AGENT = Path(__file__).resolve().parents[1]
MASTER = MY_AGENT / "CLAUDE.md"
CODEX_HOME = Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))
GEMINI_HOME = Path.home() / ".gemini"


# ---- host-specific replacement text -----------------------------------------

CODEX_INTRO = (
    "This is Marty's boot file, generated from the master `CLAUDE.md` in "
    "`C:/Users/{{WIN_USER}}/my-agent`. Codex loads this file (`~/.codex/AGENTS.md`) at the "
    "start of every thread, whatever folder the thread opens in, so identity and the "
    "rules that can't lapse are always present. It is a generated copy: never hand-edit "
    "it, edit the master and regenerate with `py tools/gen_boot.py`. The full operating "
    "manual is VAULT-INDEX.md at the vault root - read it at startup. The vault is at "
    "`C:/Users/{{WIN_USER}}/marty-vault`."
)
CODEX_COMPACTION = (
    "**Re-apply after compaction.** Codex re-applies this file at request boundaries, so "
    "identity persists; VAULT-INDEX.md does not. If your context was summarized or "
    "compacted mid-session, re-read VAULT-INDEX.md before continuing."
)
GEMINI_INTRO = (
    "This is Marty's boot file, generated from the master `CLAUDE.md` in "
    "`C:/Users/{{WIN_USER}}/my-agent`. Antigravity loads this file (`~/.gemini/AGENTS.md`) as a "
    "global rule, so identity and the rules that can't lapse are always present. It is a "
    "generated copy: never hand-edit it, edit the master and regenerate with "
    "`py tools/gen_boot.py --gemini`. The full operating manual is VAULT-INDEX.md at the "
    "vault root - read it at startup. The vault is at `C:/Users/{{WIN_USER}}/marty-vault`."
)
GEMINI_COMPACTION = (
    "**Re-apply after compaction.** Your host reloads this rule file, so identity persists; "
    "VAULT-INDEX.md does not. If your context was summarized or compacted mid-session, "
    "re-read VAULT-INDEX.md before continuing."
)
# The confer rule, rewritten so a host without the Claude Code sub-agent roster keeps the
# intent (don't decide alone; break your own claim; second pass on load-bearing calls) and
# is honest that the named roster is not native to it.
CONFER_PORTABLE = (
    "- **Confer before you decide. Don't decide alone.** Lukas wants a partner that argues "
    "and verifies, not one voice deciding alone. Before any solid decision, recommendation, "
    'or "it\'s healthy" claim: gather the evidence yourself, and try to break your own claim '
    "before you ship it (hallucinated names, advice that assumes the wrong hardware, an "
    "abandoned tool described as live, optimistic numbers, version drift). For anything "
    "expensive, irreversible, or load-bearing, get a genuine second pass before committing "
    "rather than trusting your first read. **Note on the roster:** the named specialist "
    "agents - **scout** (find it on disk), **log-reader** (what actually happened, with "
    "timestamps), **skeptic** (try to break the claim), **researcher** (external primary "
    "sources), **vault-keeper** (map drift) - live in Claude Code's `.claude/agents/` and "
    "are not native to this host. Meet the same standard with your own tools and reasoning; "
    "when a decision is load-bearing enough to warrant the roster, say so and hand that "
    "check to the Claude Code side rather than skipping it. Consulting silently, or skipping "
    "the check because it's inconvenient, counts as not conferring."
)

CODEX_HOST_NOTE = """## Host note (Codex-specific)
- You are running as **Codex**. Your flat-rate lane is `codex exec` on Lukas's ChatGPT Plus plan; it draws on the plan's usage windows unless `CODEX_API_KEY` is set, which switches to API billing.
- A **Goal** in Codex (`/goal`) is a scoped, thread-level completion contract: an outcome, a verification surface, constraints, boundaries, an iteration policy, and a blocked-stop condition. Marty's identity (this file) is never a Goal - it is permanent. Each build or engagement is its own Goal with a finish line, audited against evidence before it closes. Set a budget with `[goals] max_goal_token_budget` in `~/.codex/config.toml`; there is no way to raise it once a goal caps, so size it up front.
- The full portability and routing design is the vault Job note [[Wrap Marty Around Any LLM]]. The switchboard (`my-agent/tools/switchboard.py`) is Marty's one door to every model; prefer local (`ollama`/`marty-local`, $0) and flat-rate subscription lanes first, metered API only as overflow."""

GEMINI_HOST_NOTE = """## Host note (Gemini / Antigravity-specific)
- You are running under **Antigravity** (`agy`) on Lukas's Gemini subscription, a flat-rate lane with a capped weekly quota. Above quota it falls back to metered credits, so treat it as subscription-first, not unlimited.
- Antigravity reads this file natively as a global rule and truncates any single rule file over 24,000 bytes, so keep the master under that.
- The plain Gemini CLI is metered-API-only since the personal-account login was retired 2026-06-18; do not assume a free Gemini CLI lane.
- The full portability and routing design is the vault Job note [[Wrap Marty Around Any LLM]]. The switchboard (`my-agent/tools/switchboard.py`) is Marty's one door to every model; prefer local (`ollama`/`marty-local`, $0) and flat-rate subscription lanes first, metered API only as overflow."""


PROFILES = {
    "codex": {
        "title": "# Boot Config (Codex)",
        "intro": CODEX_INTRO,
        "compaction": CODEX_COMPACTION,
        "confer": CONFER_PORTABLE,
        "host_note": CODEX_HOST_NOTE,
        # phrases that must NOT survive into this host's copy
        "forbidden": ["every Claude Code session", 'it\'s just you and Claude"'],
        "targets": [CODEX_HOME / "AGENTS.md", MY_AGENT / "AGENTS.md"],
        "always": True,
    },
    "gemini": {
        "title": "# Boot Config (Gemini / Antigravity)",
        "intro": GEMINI_INTRO,
        "compaction": GEMINI_COMPACTION,
        "confer": CONFER_PORTABLE,
        "host_note": GEMINI_HOST_NOTE,
        "forbidden": ["every Claude Code session", 'it\'s just you and Claude"'],
        "targets": [GEMINI_HOME / "AGENTS.md"],
        "always": False,  # only with --gemini or when ~/.gemini exists
    },
}

# Spans: (name, start_anchor, end_anchor, profile_key). The span from start to the
# end of end_anchor (inclusive) is replaced by PROFILES[profile][profile_key].
SPANS = [
    ("intro",
     "This is the pinned boot file,",
     "The vault is at `C:/Users/{{WIN_USER}}/marty-vault`.",
     "intro"),
    ("compaction",
     "**Re-read after compaction.**",
     "re-read VAULT-INDEX.md before continuing.",
     "compaction"),
    ("confer",
     "- **Confer before you decide. The roster is not optional.**",
     "asked for conferring to be the model.)",
     "confer"),
]

TITLE_ANCHOR = "# Boot Config"


class GenError(Exception):
    pass


def _require_once(text: str, needle: str, label: str) -> None:
    n = text.count(needle)
    if n != 1:
        raise GenError(
            f"anchor for '{label}' occurs {n} times in CLAUDE.md (need exactly 1): "
            f"{needle!r}. The master changed shape; update gen_boot.py before regenerating."
        )


def render(master: str, profile_key: str) -> str:
    p = PROFILES[profile_key]
    out = master

    # Title (first line only; the startswith check pins the exact H1).
    if not out.startswith(TITLE_ANCHOR + "\n"):
        raise GenError(f"CLAUDE.md does not start with {TITLE_ANCHOR!r} on its own line")
    out = p["title"] + out[len(TITLE_ANCHOR):]

    # Declared spans.
    for name, start, end, key in SPANS:
        _require_once(out, start, f"{name} start")
        _require_once(out, end, f"{name} end")
        i = out.index(start)
        j = out.index(end, i)
        if j < i:
            raise GenError(f"span '{name}': end anchor precedes start anchor")
        out = out[:i] + p[key] + out[j + len(end):]

    # Append the host note.
    out = out.rstrip() + "\n\n" + p["host_note"] + "\n"

    # Anti-drift guard.
    for bad in p["forbidden"]:
        if bad in out:
            raise GenError(
                f"forbidden phrase survived into the {profile_key} copy: {bad!r}. "
                f"CLAUDE.md gained a host-specific line this profile does not transform."
            )
    return out


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def active_profiles(args) -> list[str]:
    if args.only:
        return [args.only]
    names = [k for k, v in PROFILES.items() if v["always"]]
    if args.gemini or GEMINI_HOME.exists():
        if "gemini" not in names:
            names.append("gemini")
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Marty's per-host boot files from CLAUDE.md.")
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 if any target is stale or missing")
    ap.add_argument("--diff", action="store_true", help="show what would change; write nothing")
    ap.add_argument("--gemini", action="store_true", help="also emit ~/.gemini/AGENTS.md")
    ap.add_argument("--only", choices=list(PROFILES), help="restrict to one profile")
    args = ap.parse_args()

    if not MASTER.exists():
        print(f"FATAL: master not found: {MASTER}", file=sys.stderr)
        return 2
    master = MASTER.read_text(encoding="utf-8")

    stale = False
    wrote = []
    for prof in active_profiles(args):
        try:
            rendered = render(master, prof)
        except GenError as e:
            print(f"REFUSED [{prof}]: {e}", file=sys.stderr)
            return 3
        for target in PROFILES[prof]["targets"]:
            current = target.read_text(encoding="utf-8") if target.exists() else None
            same = current == rendered
            tag = "ok" if same else ("MISSING" if current is None else "STALE")
            print(f"[{prof}] {target}  {tag}  ({len(rendered)} bytes, sha {_sha(rendered)})")
            if not same:
                stale = True
                if args.diff:
                    d = difflib.unified_diff(
                        (current or "").splitlines(keepends=True),
                        rendered.splitlines(keepends=True),
                        fromfile=str(target) + " (current)",
                        tofile=str(target) + " (generated)",
                    )
                    sys.stdout.writelines(d)
                    print()
            if not (args.check or args.diff) and not same:
                target.parent.mkdir(parents=True, exist_ok=True)
                if current is not None:
                    bak = target.with_name(target.name + ".bak-" + _dt.date.today().isoformat())
                    if not bak.exists():
                        bak.write_text(current, encoding="utf-8")
                target.write_text(rendered, encoding="utf-8")
                wrote.append(str(target))

    if args.check:
        print("DRIFT" if stale else "clean")
        return 1 if stale else 0
    if args.diff:
        return 0
    if wrote:
        print("wrote:\n  " + "\n  ".join(wrote))
    else:
        print("nothing to write; all copies already current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
