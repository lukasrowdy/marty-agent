"""
vimax.py - launch ViMax with its keys injected from Windows Credential Manager.

ViMax reads VIMAX_IMAGE_API_KEY / VIMAX_VIDEO_API_KEY from the environment. This
wrapper reads the OpenRouter key out of Credential Manager and sets those vars for
the ViMax process ONLY - so the key never lands in configs/agent.local.yaml, never
enters shell history, and never appears in a transcript. Same rule as every other
key in this stack.

    py tools/vimax.py check                 what is configured, what is missing
    py tools/vimax.py agent [args...]       main_agent.py
    py tools/vimax.py idea2video [args...]  main_idea2video.py
    py tools/vimax.py script2video [args...] main_script2video.py

First time, store the key (it prompts; the paste shows nothing, which is normal):

    py tools/cred.py set openrouter

Two things this deliberately does NOT do:

  - It does not start Ollama. ViMax's LLM layer points at Ollama's own
    OpenAI-compatible endpoint, http://127.0.0.1:11434/v1, with model marty-local
    (configs/agent.local.yaml). `check` warns if that endpoint is down or the
    model is not installed.
  - It does not cap spend. OpenRouter calls are real money and separate from the
    Higgsfield credits already bought. Set a hard limit on the OpenRouter account
    itself; a wrapper script is not a spending control.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cred  # noqa: E402

VIMAX = pathlib.Path("C:/Users/{{WIN_USER}}/code/ViMax")
VENV_PY = VIMAX / ".venv" / "Scripts" / "python.exe"
LLM_MODELS = "http://127.0.0.1:11434/v1/models"   # Ollama's OpenAI-compatible model list
LLM_MODEL = "marty-local"                            # must match llm.model in configs/agent.local.yaml
KEY_TARGET = "openrouter"

ENTRYPOINTS = {
    "agent": "main_agent.py",
    "idea2video": "main_idea2video.py",
    "script2video": "main_script2video.py",
}


def llm_state():
    """'ok', 'no-model' (Ollama answers but marty-local is not installed) or 'down'.
    Lists installed models only; it never loads one."""
    try:
        with urllib.request.urlopen(LLM_MODELS, timeout=5) as r:
            ids = {m.get("id", "") for m in json.loads(r.read().decode("utf-8")).get("data", [])}
    except Exception:
        return "down"
    return "ok" if LLM_MODEL in ids or f"{LLM_MODEL}:latest" in ids else "no-model"


def cmd_check(a):
    ok = True
    print(f"ViMax:        {VIMAX}  {'OK' if VIMAX.is_dir() else 'MISSING'}")
    print(f"venv python:  {'OK' if VENV_PY.exists() else 'MISSING - run: uv venv --python 3.12 && uv sync'}")
    cfg = VIMAX / "configs" / "agent.local.yaml"
    print(f"config:       {'OK' if cfg.exists() else 'MISSING'}  {cfg}")

    key = cred.read(KEY_TARGET)
    if key:
        print(f"openrouter:   OK  ({cred.redacted(key)})")
    else:
        ok = False
        print("openrouter:   MISSING - store it with:  py tools/cred.py set openrouter")
        print("              (get one at openrouter.ai; set a hard spend cap on the account)")

    state = llm_state()
    if state == "ok":
        print(f"local LLM:    OK  {LLM_MODEL} on 127.0.0.1:11434/v1")
    elif state == "no-model":
        ok = False
        print(f"local LLM:    Ollama is up but {LLM_MODEL} is not installed:")
        print(f"              ollama create {LLM_MODEL} -f tools/Modelfile.{LLM_MODEL}")
    else:
        ok = False
        print("local LLM:    DOWN - Ollama is not answering on 127.0.0.1:11434; start the Ollama app")
    print("\nready" if ok else "\nnot ready - fix the items above")
    return 0 if ok else 1


def cmd_run(a):
    if not VENV_PY.exists():
        raise SystemExit(f"ViMax venv missing at {VENV_PY}")
    key = cred.read(KEY_TARGET)
    if not key:
        raise SystemExit(
            "no OpenRouter key stored.\n"
            "  py tools/cred.py set openrouter\n"
            "  Marty will not prompt for it here - the prompt keeps it out of this transcript."
        )
    if llm_state() != "ok":
        print(f"WARNING: {LLM_MODEL} is not answering on 127.0.0.1:11434/v1, so ViMax's LLM calls will fail.",
              file=sys.stderr)
        print("         run: py tools/vimax.py check", file=sys.stderr)

    env = dict(os.environ)
    # per-process only; nothing is written anywhere
    env["VIMAX_IMAGE_API_KEY"] = key
    env["VIMAX_VIDEO_API_KEY"] = key
    script = ENTRYPOINTS[a.which]
    print(f"running {script} with OpenRouter key injected ({cred.redacted(key)})\n")
    return subprocess.call([str(VENV_PY), script] + a.args, cwd=str(VIMAX), env=env)


def main():
    ap = argparse.ArgumentParser(description="Run ViMax with keys from Credential Manager.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    for name in ENTRYPOINTS:
        p = sub.add_parser(name)
        p.add_argument("args", nargs=argparse.REMAINDER)
        p.set_defaults(fn=cmd_run, which=name)
    a = ap.parse_args()
    raise SystemExit(a.fn(a))


if __name__ == "__main__":
    main()
