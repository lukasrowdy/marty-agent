"""
feed_local.py - condense a vault note into a short cheat sheet marty-local can
actually use, by asking Claude to write it.

Marty-local (Ollama, Mistral Nemo, 16k context) cannot hold the whole vault, and
switchboard.py's --vault retrieval is a crude keyword search over full notes. This
writes a short, dense summary of one note instead, using Claude while the Max plan
is paying for it. switchboard.py then loads every file here automatically on every
ollama call, so marty-local always has them, no flag needed.

Does not fine-tune anything. No GPU here, so no weights change. This is retrieval
feeding, not training - see the GPU decision in Active Priorities for the real thing.

    C:/Users/{{WIN_USER}}/my-agent/backtalk/.venv/Scripts/python.exe tools/feed_local.py run
    C:/Users/{{WIN_USER}}/my-agent/backtalk/.venv/Scripts/python.exe tools/feed_local.py run --note "07 - Resources/Marty Stack.md"
    C:/Users/{{WIN_USER}}/my-agent/backtalk/.venv/Scripts/python.exe tools/feed_local.py list

Output: my-agent/tools/local_knowledge/<slug>.md, one file per source note,
overwritten each run so it stays current rather than accumulating stale copies.
Each sheet carries a provenance line (source note, its sha256, when it was written);
switchboard.local_knowledge() checks it on every load and banners a sheet whose note
has changed since as STALE (audit finding 14). `list` shows which are fresh.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import switchboard  # noqa: E402

VAULT = pathlib.Path(r"C:/Users/{{WIN_USER}}/marty-vault")
OUT_DIR = HERE / "local_knowledge"

# The brain that does the condensing. See the note in condense_one for why this is
# not Claude any more, and why it is not Gemini either.
DEFAULT_BRAIN = "openrouter"
DEFAULT_MODEL = "openai/gpt-5.6-luna"

# Curated on purpose, not "every note" - these are the ones worth a standing
# cheat sheet. Daily notes and one-off project files are not: they go stale
# and vault_context()'s live keyword search already reaches them on demand.
SEED_NOTES = [
    "VAULT-INDEX.md",
    "Active Priorities.md",
    "07 - Resources/Marty Stack.md",
    "07 - Resources/Jobs/Video Walkthrough to Inventory.md",
]


def slug(rel_path):
    return re.sub(r"[^a-z0-9]+", "-", rel_path.lower()).strip("-") + ".md"


def condense_one(rel_path, project, brain=DEFAULT_BRAIN, model=DEFAULT_MODEL):
    path = VAULT / rel_path
    if not path.exists():
        print(f"skip (not found): {rel_path}")
        return None
    raw = path.read_bytes()             # hashed as read, so the sheet vouches for this exact text
    text = raw.decode("utf-8", errors="replace")
    prov = {"source": rel_path, "sha256": hashlib.sha256(raw).hexdigest(),
            "source_mtime": dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")}
    prompt = (
        f"This is Lukas's vault note '{rel_path}', in full:\n\n{text}\n\n"
        "Condense this into a cheat sheet for yourself (Marty) to keep in your own "
        "working memory - the facts, decisions, and open items you'd actually need "
        "to act correctly, not a summary for a reader. Plain text, no markdown "
        "headers needed, dense, under 600 words. Skip anything that's pure log/history "
        "with no bearing on a future decision."
    )
    # Routed off Claude 2026-09-22. Condensing a markdown note into a cheat sheet is
    # bulk drudgery, not hard reasoning, and billing it to a $2/$10 model made this the
    # second-largest line in meter.jsonl - $0.1351 across four calls - which is the only
    # reason scheduling this loop was ever parked on a spend decision. gpt-5.6-luna is
    # $0.20/$1.20, roughly a tenth the input rate, for the same job.
    #
    # Deliberately NOT Gemini, which is cheaper still: it is unresolved whether itm/google
    # sits on a billed project, and on Google's unpaid tier content is used to develop
    # their products and human reviewers may read it. These notes are Lukas's vault -
    # family, finances, home network. Do not route them there until the tier is confirmed.
    args = argparse.Namespace(to=brain, model=model, system="", private=False, vault=False,
                               log=None, key="itm", project=project)
    answer = switchboard.run_one(args, prompt)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / slug(rel_path)
    prov.update({"generated": dt.datetime.now().isoformat(timespec="seconds"), "by": f"{brain}/{model}"})
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(f"# Cheat sheet: {rel_path}\n<!-- feed_local {json.dumps(prov)} -->\n"
                   f"(condensed by {brain}/{model} for marty-local, regenerate with feed_local.py)\n\n{answer}\n",
                   encoding="utf-8")
    os.replace(tmp, out_path)            # atomic: a crash mid-write never leaves a torn sheet
    print(f"wrote: {out_path}")
    return out_path


def cmd_run(a):
    notes = [a.note] if a.note else SEED_NOTES
    for rel_path in notes:
        condense_one(rel_path, a.project, a.to, a.model)


def cmd_list(_a):
    if not OUT_DIR.exists():
        print("nothing fed yet"); return
    for f in sorted(OUT_DIR.glob("*.md")):
        _src, written, fresh = switchboard.sheet_freshness(f)
        state = {True: "fresh", False: "STALE (source note changed since)", None: "freshness unknown"}[fresh]
        print(f"{f.name}  written {written}  {state}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--note", help="one vault-relative path; default: the seed list")
    r.add_argument("--project", default="ollama-feed")
    r.add_argument("--to", default=DEFAULT_BRAIN,
                   help=f"which brain condenses (default {DEFAULT_BRAIN}; NOT gemini until its tier is confirmed)")
    r.add_argument("--model", default=DEFAULT_MODEL, help=f"model id (default {DEFAULT_MODEL})")
    r.set_defaults(fn=cmd_run)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
