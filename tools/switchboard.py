"""
switchboard.py - one door to every brain Lukas owns, with a private lane.

    py -3 tools/switchboard.py status
    py -3 tools/switchboard.py ask --private "question"            # local only, logged to the private folder
    py -3 tools/switchboard.py ask --to ollama|claude|grok|gemini|openrouter "question"
    py -3 tools/switchboard.py ask --to ollama --model marty-local --vault "question"   # local + vault context
    py -3 tools/switchboard.py interview --to gemini --log "<folder>" "question"      # receipt-grade transcript
    py -3 tools/switchboard.py chat --private                       # interactive local chat, logged privately

Brains:
    ollama   local server at 127.0.0.1:11434. Nothing leaves the machine.
    claude   Anthropic API. Key: Credential Manager 'itm/anthropic' (or --key channel for 'channel/anthropic').
    grok     xAI API. Key: 'itm/xai' (or --key channel for 'channel/xai').
    gemini   Google Gemini API. Key: 'itm/google'.
    openrouter  OpenAI-shape gateway to ~440 models. Key: 'openrouter'.

Subscription lanes (flat-rate CLIs, $0 marginal cost - they consume a plan's usage
window, not dollars, so metered spend stays near zero; see [[Wrap Marty Around Any LLM]]):
    claude_sub  Claude Code `claude -p` on the Max plan. Loads CLAUDE.md (Marty), talk-only
                (tool prompts auto-denied). Logs the LIST cost the API would have charged.
    codex_sub   Codex `codex exec` on ChatGPT Plus. Read-only sandbox; loads ~/.codex/AGENTS.md.
    gemini_sub  Gemini via Antigravity `agy -p`. Dormant until Antigravity is installed.

Rules built in:
    --private forces ollama, refuses any cloud brain, and writes the log ONLY to
        C:/Users/{{WIN_USER}}/my-agent/private/chats/ (not synced by OneDrive, Google Drive, or the NAS backup).
    interview logs are receipt-grade: model, version, date, exact prompt, exact answer, in the folder you name.
    Keys are read at call time from Windows Credential Manager via tools/cred.py and never printed or logged.
    Nothing here posts, sends, or acts. It asks a model a question and writes down the answer.
"""

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import tempfile
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
MY_AGENT = HERE.parent  # the agent root; a subscription CLI runs here so CLAUDE.md (Marty) loads
sys.path.insert(0, str(HERE))
import cred  # noqa: E402  (tools/cred.py)

# Windows consoles default to cp1252, which cannot encode plenty of characters a
# model routinely uses (en/em dashes, arrows, smart quotes) - printing one used to
# crash the whole call with UnicodeEncodeError after the API had already been
# billed. UTF-8 with a replace fallback means a stray glyph degrades instead of
# taking the process down.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

PRIVATE_DIR = pathlib.Path(r"C:/Users/{{WIN_USER}}/my-agent/private/chats")
VAULT = pathlib.Path(r"C:/Users/{{WIN_USER}}/marty-vault")
OLLAMA = "http://127.0.0.1:11434"
DEFAULTS = {"ollama": "marty-local", "claude": "claude-sonnet-5", "grok": "grok-4.6", "gemini": "gemini-3.8-flash",
            # Cheap on purpose. --to openrouter without --model is for bulk work; the
            # flagship costs 50x and should be asked for by name, not arrived at by default.
            "openrouter": "openai/gpt-5.6-luna",
            # Subscription lanes. claude_sub defaults to Sonnet (capable, lower list cost than
            # Opus on the same flat plan). The other two use their CLI's own configured model
            # when left blank, so "" means "don't pass -m/--model".
            "claude_sub": "sonnet", "codex_sub": "", "gemini_sub": ""}
KEYS = {"claude": ("itm/anthropic", "channel/anthropic"), "grok": ("itm/xai", "channel/xai"), "gemini": ("itm/google", None),
        "openrouter": ("openrouter", None)}
CLOUD = {"claude", "grok", "gemini", "openrouter"}
# Subscription lanes shell out to an already-signed-in CLI. No key from cred, no metered
# dollars (price_for returns 0), but each call still spends that plan's usage window.
SUBS = {"claude_sub", "codex_sub", "gemini_sub"}
METER = HERE / "meter.jsonl"

# $ per million tokens (input, output). Verified 2026-09-20, see
# Desktop/Projects/14 - Marty Console/SPENDING - options.md. Matched by substring
# against the model name the vendor actually reports, longest match wins.
PRICING = {
    "claude-opus-5": (5, 25), "claude-sonnet-5": (2, 10), "claude-haiku-4-5": (1, 5), "claude-fable-5-1": (10, 50),
    # Opus 5.5 is CHEAPER than Opus 5. Without its own row, longest-substring match fell
    # through to "claude-opus-5" and billed it 25% high (found 2026-09-26). Verified
    # 2026-09-27 against https://platform.claude.com/docs/en/about-claude/pricing
    "claude-opus-5-5": (4, 20),
    # Gemini 3, Developer API, Standard tier, paid. Read from the raw pricing page
    # 2026-09-21 (page stamp 2026-09-16) and re-verified figure by figure by a
    # second pass. The 2.5 line is RETIRED for new API keys (404 "no longer
    # available to new users") so it has no rows. The three 3.x Flash rows are the
    # rate through 2026-12-31; price_for doubles them from 2027-01-01 (INTRO_MODELS).
    # 3.1 Pro bills the whole request at (4, 18) above 200k input tokens; record_call
    # logs those unpriced (LONG_CONTEXT_TIERED). 3.1-flash-lite audio input is 0.50,
    # not metered because nothing here sends audio to it. Pin versions, never the
    # -latest aliases: they move without notice, and model_reported is what matches.
    "gemini-3.8-flash": (0.75, 3.75), "gemini-3.7-flash": (0.75, 3.75), "gemini-3.6-flash": (0.75, 3.75),
    "gemini-3.5-flash": (1.50, 9.00), "gemini-3.5-flash-lite": (0.30, 2.50), "gemini-3.1-flash-lite": (0.25, 1.50),
    "gemini-3.1-pro-preview": (2.00, 12.00),
    "grok-4.6": (2, 6),
    # OpenRouter, read live from its own /models endpoint 2026-09-22 and converted
    # from per-token to per-million. Only the rows actually used are listed; any
    # other OpenRouter model logs tokens with cost None rather than a guessed price.
    # NOTE these are the FLAT rates: gpt-6-astra goes to (20, 75) above 272k prompt
    # tokens and luna to (0.40, 1.80); that override is not modelled here yet.
    "gpt-6-astra-pro": (10, 50), "gpt-6-astra": (10, 50),
    "gpt-5.6-luna-pro": (0.20, 1.20), "gpt-5.6-luna": (0.20, 1.20),
}


# Google sells the 3.x Flash line at a lower rate through 2026-12-31 and doubles it
# on 2027-01-01. A static tuple cannot know that, so the flip is dated here and
# price_for applies it itself; otherwise the meter would silently under-report from
# New Year's Day with nothing visibly breaking.
INTRO_DOUBLES_ON = dt.date(2027, 1, 1)
INTRO_MODELS = ("gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash")
# Pro is tiered by prompt size: above this many input tokens the WHOLE request bills
# at a higher rate the tuple cannot express, so record_call logs cost None for those
# calls (honest) rather than roughly half the true price.
LONG_CONTEXT_TIERED = ("gemini-3.1-pro-preview",)
LONG_CONTEXT_TOKENS = 200_000

# Anthropic prompt caching, as multipliers of the model's base input price. Verified
# 2026-09-27 against https://platform.claude.com/docs/en/about-claude/pricing
# ("Prompt caching" table): 5-minute write 1.25x, 1-hour write 2x, cache read 0.1x -
# EXCEPT reads on Opus 5.5 (0.05x, $0.20/MTok) and Fable 5.1 / Mythos 5.1 (0.025x,
# $0.25/MTok). Reads are matched by substring like PRICING, longest wins.
# Anthropic's usage block reports input_tokens as the UNCACHED remainder only; the cached
# part arrives in cache_read_input_tokens and cache_creation_input_tokens (the latter
# split by TTL in usage.cache_creation.ephemeral_5m/1h_input_tokens). Reading only
# input_tokens, as the meter did until this fix, under-counts every cached call.
CACHE_WRITE_5M_MULT = 1.25
CACHE_WRITE_1H_MULT = 2.0
CACHE_READ_MULT_DEFAULT = 0.1
CACHE_READ_MULT = {"claude-opus-5-5": 0.05, "claude-fable-5-1": 0.025, "claude-mythos-5-1": 0.025}


def cache_read_mult(model_reported):
    for name, m in sorted(CACHE_READ_MULT.items(), key=lambda kv: -len(kv[0])):
        if name in str(model_reported):
            return m
    return CACHE_READ_MULT_DEFAULT


def claude_usage(u):
    """Anthropic usage dict -> (input, output, cache_read, cache_write_5m, cache_write_1h).
    Every field may be absent or null (older responses, no caching); each counts as 0.
    A write total with no TTL breakdown is treated as 5-minute, the API default."""
    u = u or {}
    n = lambda v: int(v or 0)  # noqa: E731
    cc = u.get("cache_creation") or {}
    w1h = n(cc.get("ephemeral_1h_input_tokens"))
    w_total = n(u.get("cache_creation_input_tokens")) or (n(cc.get("ephemeral_5m_input_tokens")) + w1h)
    w1h = min(w1h, w_total)
    return (n(u.get("input_tokens")), n(u.get("output_tokens")),
            n(u.get("cache_read_input_tokens")), w_total - w1h, w1h)


def spent_since(start_date, project=None):
    """Sum real dollars from the meter on or after start_date (YYYY-MM-DD); with project=,
    only rows tagged with that project (the consult lane's daily arithmetic uses this).

    A spend CAP was built here 2026-09-22 and removed the same hour on Lukas's
    instruction: let it run a month and see where it lands, rather than guess a
    ceiling before there is data. Nothing in this stack refuses a call on cost.
    What replaced it is observation - see cmd_daily, reported each morning.

    Rows with cost None (an unpriced model) count as zero. They are unknown, not
    free, so any total here is a floor, not a ceiling."""
    total = 0.0
    for row in _meter_rows():
        ts = str(row.get("ts", ""))[:10]
        if project is not None and row.get("project") != project:
            continue
        if ts >= start_date and row.get("cost_usd"):
            total += float(row["cost_usd"])
    return total


def _meter_rows():
    """Every parseable row of the meter, in file order. The ONE parser every reader here uses
    (spent_since, spend, daily): a torn or half-written line, which is what a crash mid-append
    leaves behind, is skipped rather than taking the report down (audit finding 14; cmd_daily
    used to re-parse every line unguarded, and cmd_spend never guarded at all)."""
    try:
        with open(METER, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    yield row
    except OSError:
        return


def price_for(brain, model_reported, today=None):
    if brain == "ollama" or brain in SUBS:
        return 0.0, 0.0  # local, or a flat-rate subscription: no metered dollars
    # OpenRouter marks its no-cost models with a :free suffix. Pricing them from the
    # substring table would charge for them at the paid model's rate.
    if brain == "openrouter" and str(model_reported).endswith(":free"):
        return 0.0, 0.0
    for name, (i, o) in sorted(PRICING.items(), key=lambda kv: -len(kv[0])):
        if name in model_reported:
            if name in INTRO_MODELS and (today or dt.date.today()) >= INTRO_DOUBLES_ON:
                return i * 2, o * 2
            return i, o
    return None, None  # unknown model: cost left unrecorded rather than guessed


def record_call(brain, model_requested, model_reported, usage, project, private, extra=None, customer=None):
    """Append one cost-tracking line. No question/answer text goes in here, ever --
    that keeps it safe to write even for a --private call, whose transcript never
    leaves the private folder. `extra` adds fields a subscription lane knows that the
    others don't: list_cost_usd (what a claude_sub call would have cost on the API,
    which is the value the Max plan is delivering) and plan (which subscription paid).

    usage is (input, output) - every lane's shape - or claude_usage()'s 5-tuple
    (input, output, cache_read, cache_write_5m, cache_write_1h); missing tail = 0.
    input_tokens stays the UNCACHED input as the API reports it; cache fields are
    added to the row only when non-zero, so an uncached row keeps its old shape."""
    usage = tuple(usage) + (0,) * (5 - len(tuple(usage)))
    in_tok, out_tok, c_read, c_w5, c_w1h = (int(x or 0) for x in usage[:5])
    in_price, out_price = price_for(brain, model_reported)
    if in_tok > LONG_CONTEXT_TOKENS and any(n in model_reported for n in LONG_CONTEXT_TIERED):
        in_price = out_price = None  # tiered rate the table cannot express; see LONG_CONTEXT_TIERED
    cached = c_read or c_w5 or c_w1h
    if cached and in_price and "claude" not in str(model_reported):
        in_price = out_price = None  # only Anthropic's cache multipliers are known; unpriced beats guessed
    if in_price is None:
        cost = None
    else:
        read_price = in_price * cache_read_mult(model_reported)
        cost = round((in_tok * in_price + out_tok * out_price + c_read * read_price
                      + c_w5 * in_price * CACHE_WRITE_5M_MULT + c_w1h * in_price * CACHE_WRITE_1H_MULT)
                     / 1_000_000, 6)
    row = {
        "ts": dt.datetime.now().isoformat(timespec="seconds"),
        "brain": brain, "model_requested": model_requested, "model_reported": model_reported,
        "project": project, "input_tokens": in_tok, "output_tokens": out_tok,
        "cost_usd": cost, "private": private,
    }
    if customer:
        row["customer"] = str(customer).strip().lower()  # who the spend is for (spend ledger); absent = map by project
    if c_read:
        row["cache_read_input_tokens"] = c_read
    if c_w5 or c_w1h:
        row["cache_creation_input_tokens"] = c_w5 + c_w1h
    if c_w1h:
        row["cache_creation_1h_input_tokens"] = c_w1h
    for k, v in (extra or {}).items():
        if v is not None:
            row[k] = v
    with open(METER, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    return cost


def _http(url, headers, body=None, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def key_for(brain, prefer):
    itm, chan = KEYS[brain]
    order = [chan, itm] if prefer == "channel" else [itm, chan]
    for name in order:
        if name:
            v = cred.read(name)
            if v:
                return v, name
    raise SystemExit(f"no key for {brain}: store one with  py tools\\cred.py set {itm}")


# ---------------------------------------------------------------- brains

_MODEL_SYSTEM_CACHE = {}


def model_system(model):
    """The SYSTEM block baked into a model's Modelfile, read from Ollama itself.

    Ollama's /api/chat REPLACES that block with any system message the request
    carries; it does not append. Measured 2026-09-22 on this box: marty-local
    evaluates 294 prompt tokens with no system message and 205 with a 200-token
    one; a second local model, 858 and 218. Appending would have given ~494 and ~1058.

    That mattered because the callers below pass the vault cheat sheets in the
    system slot, which silently deleted Marty's persona on every local call. On
    the voice private lane (backtalk/brain.py) the sheets were the ENTIRE system,
    so spoken private mode had no persona at all. Re-sending the model's own
    block ahead of whatever we add fixes all three call sites at once.

    Cached per process. Any failure returns "", which is exactly the old
    behaviour, so a broken /api/show degrades instead of killing the turn.
    """
    if model not in _MODEL_SYSTEM_CACHE:
        block = ""
        try:
            req = urllib.request.Request(
                f"{OLLAMA}/api/show", data=json.dumps({"model": model}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                block = (json.loads(r.read().decode("utf-8")).get("system") or "").strip()
        except Exception:
            block = ""
        _MODEL_SYSTEM_CACHE[model] = block
    return _MODEL_SYSTEM_CACHE[model]


def ollama_system(model, system):
    """The system prompt exactly as ask_ollama sends it: the model's own Modelfile SYSTEM block
    first (see model_system), then ours. One function for both the request and the receipt,
    so a receipt can never drift from what was actually sent (audit finding 14)."""
    if system:
        base = model_system(model)
        if base and not system.startswith(base):
            return base + "\n\n" + system
    return system


def ask_ollama(model, system, messages, stream=True, _retry=True, think=None, format=None):
    # think=False matters enormously on hybrid reasoning models. Measured on
    # qwen3.6 35B-A3B: a one-sentence answer took 58.8s and 879 tokens
    # with thinking on, and 6.2s with 23 tokens with it off. Same answer quality.
    # Older non-thinking models (mistral-nemo, and so marty-local) reject the field,
    # so a rejection falls back to a plain call rather than failing the turn.
    # Keep the Modelfile persona. See model_system(): a request system message
    # REPLACES it, so anything we add has to carry it along explicitly.
    system = ollama_system(model, system)
    body ={"model": model, "messages": ([{"role": "system", "content": system}] if system else []) + messages, "stream": stream}
    if think is not None:
        body["think"] = think
    if format is not None:
        body["format"] = format   # Ollama native structured output: a JSON schema constrains the decode
    req = urllib.request.Request(f"{OLLAMA}/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    out = []
    try:
        r = urllib.request.urlopen(req, timeout=600)
    except urllib.error.HTTPError as e:
        # Ollama can answer 500 for a few seconds right after loading a model (its runner
        # port is not accepting yet). One retry after a short wait covers it.
        if e.code == 500 and _retry:
            import time; time.sleep(6)
            return ask_ollama(model, system, messages, stream, _retry=False, think=think, format=format)
        if e.code == 400 and think is not None:
            # model has no thinking capability; ask again without the field
            return ask_ollama(model, system, messages, stream, _retry=_retry, think=None, format=format)
        raise
    with r:
        if not stream:
            j = json.loads(r.read().decode())
            usage = (j.get("prompt_eval_count", 0), j.get("eval_count", 0))
            return j["message"]["content"], j.get("model", model), usage
        for line in r:
            j = json.loads(line)
            tok = j.get("message", {}).get("content", "")
            if tok:
                out.append(tok); print(tok, end="", flush=True)
            if j.get("done"):
                print()
                usage = (j.get("prompt_eval_count", 0), j.get("eval_count", 0))
                return "".join(out), j.get("model", model), usage
    return "".join(out), model, (0, 0)


def claude_messages(model, system, messages, key, max_tokens=2048, timeout=180, extra=None):
    """One door for every Claude request in this stack: the raw /v1/messages response dict.
    `extra` is merged into the body (e.g. {"output_config": {"effort": "high"}}). No tools
    key is ever added here, so a caller that wants a talk-only lane gets one by default.
    Split out of ask_claude 2026-09-22 for callers that need the stop_reason and a real
    timeout and must not print into the dashboard log (tools/marty_tools.py uses it)."""
    body = {"model": model, "max_tokens": max_tokens, **({"system": system} if system else {}),
            "messages": messages, **(extra or {})}
    return _http("https://api.anthropic.com/v1/messages",
                 {"x-api-key": key, "anthropic-version": "2023-06-01"}, body, timeout=timeout)


def _walk_schema(node, fn):
    """Apply fn to every dict node in a JSON-schema tree (depth-first)."""
    if isinstance(node, dict):
        fn(node)
        for v in node.values():
            _walk_schema(v, fn)
    elif isinstance(node, list):
        for v in node:
            _walk_schema(v, fn)


def _schema_for_gemini(schema):
    """Gemini's responseSchema rejects `additionalProperties` outright (400 "Unknown name"),
    so strip it. One user schema then works on gemini as well as the other lanes."""
    s = copy.deepcopy(schema)
    _walk_schema(s, lambda d: d.pop("additionalProperties", None))
    return s


def _schema_closed(schema):
    """Close every object for OpenAI/xAI strict mode, which 400s unless each object sets
    additionalProperties:false AND lists every property in `required`. This makes a normal
    schema (optional fields, open objects) usable under --strict without hand-editing it;
    the cost is that optional fields become required, a strict-mode limitation, not ours."""
    s = copy.deepcopy(schema)

    def close(d):
        if d.get("type") == "object" and isinstance(d.get("properties"), dict):
            d["additionalProperties"] = False
            d["required"] = list(d["properties"].keys())
    _walk_schema(s, close)
    return s


def _openai_response_format(schema, strict=False):
    """The OpenAI-shape structured-output field, used by grok and openrouter. strict=True is a
    hard guarantee but demands a closed schema (see _schema_closed); default is non-strict, which
    strongly guides the model without 400-ing on ordinary schemas with optional fields."""
    sch = _schema_closed(schema) if strict else schema
    return {"type": "json_schema", "json_schema": {"name": "out", "schema": sch, "strict": strict}}


#   "tool_choice types any and tool return a 400 error (tool_choice: type "tool" and "any" are
#    not supported for this model.) ... Use auto with strict tool use or structured outputs,
#    and say in the prompt when the tool applies."
#   - https://platform.claude.com/docs/en/models/opus-5-5/migration-guide (same rule for Fable 5.1
#     and Mythos 5.1: https://platform.claude.com/docs/en/models/fable-5-1/migration-guide)
# So on these models --schema sends tool_choice auto and says so in the system prompt. strict:true
# and output_config.format are NOT used: both demand additionalProperties:false on every object,
# and --schema accepts open schemas on purpose. ask_claude's existing "no tool_use block" error
# is the check that the call actually happened. Every other model keeps the forced tool, unchanged.
NO_FORCED_TOOL_CHOICE = ("claude-opus-5-5", "claude-fable-5-1", "claude-mythos-5-1")
EMIT_INSTRUCTION = ("Give your answer by calling the emit tool exactly once. Its input is your whole "
                    "answer; do not answer in plain text.")


def claude_schema_request(model, system):
    """(tool_choice, system) for ask_claude --schema. One function for the request and the
    receipt, so run_one logs the system prompt exactly as sent."""
    if any(n in str(model) for n in NO_FORCED_TOOL_CHOICE):
        return {"type": "auto"}, ((system + "\n\n") if system else "") + EMIT_INSTRUCTION
    return {"type": "tool", "name": "emit"}, system


def ask_claude(model, system, messages, key, schema=None, strict=False):
    if schema:
        # Anthropic has no response_format; the stable way to constrain output is a single
        # forced tool whose input_schema IS the schema, then read the tool_use input back
        # (tool_choice auto plus an instruction on models that reject forcing; see above).
        # Higher max_tokens here: a truncated tool input is invalid JSON against the very
        # schema requested, so give the structured answer room and refuse a truncated one.
        tool = {"name": "emit", "description": "Return the answer strictly in this schema.", "input_schema": schema}
        choice, system = claude_schema_request(model, system)
        j = claude_messages(model, system, messages, key, max_tokens=8192,
                            extra={"tools": [tool], "tool_choice": choice})
        if j.get("stop_reason") == "max_tokens":
            raise SystemExit("claude --schema: output hit the token cap and would be truncated (invalid JSON). "
                             "Ask for less, or split the request.")
        blk = next((b for b in j.get("content", []) if b.get("type") == "tool_use"), None)
        if blk is None:
            raise SystemExit(f"claude --schema: model returned no structured output (stop_reason={j.get('stop_reason')}).")
        text = json.dumps(blk["input"])
        print(text)
        return text, j.get("model", model), claude_usage(j.get("usage"))
    j = claude_messages(model, system, messages, key)
    text = "".join(b.get("text", "") for b in j.get("content", []) if b.get("type") == "text")
    print(text)
    return text, j.get("model", model), claude_usage(j.get("usage"))


def ask_grok(model, system, messages, key, schema=None, strict=False):
    body = {"model": model, "messages": ([{"role": "system", "content": system}] if system else []) + messages}
    if schema:
        body["response_format"] = _openai_response_format(schema, strict)
    j = _http("https://api.x.ai/v1/chat/completions", {"Authorization": f"Bearer {key}"}, body)
    text = j["choices"][0]["message"]["content"]; print(text)
    u = j.get("usage", {})
    return text, j.get("model", model), (u.get("prompt_tokens", 0), u.get("completion_tokens", 0))


def ask_openrouter(model, system, messages, key, schema=None, strict=False):
    """OpenRouter speaks the OpenAI chat-completions shape, so this is ask_grok with a
    different door. One key reaches OpenAI, Anthropic, Google, xAI and ~440 others,
    including two dozen that cost nothing - which is what makes it the right lane for
    bulk work that should never have been billed to the flagship."""
    body = {"model": model, "messages": ([{"role": "system", "content": system}] if system else []) + messages}
    if schema:
        body["response_format"] = _openai_response_format(schema, strict)
        # Many OpenRouter models don't support structured output; require_parameters makes
        # OpenRouter route to a provider that does (or error clearly) instead of silently
        # dropping the constraint. Most models here are not OpenAI-shape structured-capable.
        body["provider"] = {"require_parameters": True}
    try:
        j = _http("https://openrouter.ai/api/v1/chat/completions", {"Authorization": f"Bearer {key}"}, body)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            # Verified 2026-09-22: the :free models rate-limit aggressively and 429 on
            # back-to-back calls. Free is fine for a one-off, not for scheduled bulk
            # work - use a cheap paid model for that and say so plainly here.
            raise SystemExit(
                f"openrouter rate-limited {model} (HTTP 429). "
                "Free (:free) models throttle hard and are not dependable for batch "
                "work - use a cheap paid model instead, e.g. "
                "--model openai/gpt-5.6-luna (about $0.20 per million input tokens)."
            )
        raise
    text = j["choices"][0]["message"]["content"]; print(text)
    u = j.get("usage", {})
    return text, j.get("model", model), (u.get("prompt_tokens", 0), u.get("completion_tokens", 0))


def ask_gemini(model, system, messages, key, schema=None, strict=False):
    contents = [{"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]} for m in messages]
    body = {"contents": contents, **({"systemInstruction": {"parts": [{"text": system}]}} if system else {})}
    if schema:
        # Gemini's responseSchema is always closed-by-construction, so it needs no strict flag;
        # it just cannot accept additionalProperties, which _schema_for_gemini strips.
        body["generationConfig"] = {"responseMimeType": "application/json", "responseSchema": _schema_for_gemini(schema)}
    j = _http(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}", {}, body)
    text = "".join(p.get("text", "") for p in j["candidates"][0]["content"]["parts"]); print(text)
    u = j.get("usageMetadata", {})
    # Google bills output as candidates + thinking ("Output price (including thinking
    # tokens)"), and thoughtsTokenCount is a sibling of candidatesTokenCount, not part
    # of it (totalTokenCount = prompt + thoughts + candidates). Counting candidates
    # alone under-reported Pro ~20x on a live probe: 9 answer tokens, 180 thinking.
    out_tok = u.get("candidatesTokenCount", 0) + u.get("thoughtsTokenCount", 0)
    return text, j.get("modelVersion", model), (u.get("promptTokenCount", 0), out_tok)


class LaneError(RuntimeError):
    """A subscription-lane failure that CALLERS can catch. The lanes used to raise SystemExit
    (a BaseException), which the dashboard's `except Exception` would miss, crashing the chat
    thread. LaneError is an ordinary Exception, so a failing lane degrades to an error message
    on any surface. main() catches it for the CLI so the shell still exits cleanly."""


# ---------------------------------------------------------------- subscription lanes (flat-rate CLIs, $0 marginal)
#
# These do not hit a metered API. They shell out to a CLI already signed in on one of
# Lukas's flat-rate subscriptions, so the marginal dollar cost is $0 and the meter
# records it as such - but each call still consumes that plan's usage window. The
# contract is the same as every other lane: ask a model a question, get text back.
# Nothing is granted write or exec access (claude auto-denies tool prompts; codex runs
# read-only-sandboxed). Prompts go in on stdin so nothing has to be shell-quoted. Each
# returns a 4-tuple (text, model_reported, usage, extra) - extra carries plan/list_cost
# for the meter. Legal note: these shell out to the UNMODIFIED vendor binary and never
# read or forward a subscription token, which is what keeps personal use within terms.

CODEX_BIN_DIR = pathlib.Path(os.environ.get("LOCALAPPDATA", r"C:/Users/{{WIN_USER}}/AppData/Local")) / "OpenAI" / "Codex" / "bin"
# An empty working dir with NO CLAUDE.md/AGENTS.md anywhere in its ANCESTRY, so a subscription
# CLI answers as a raw model instead of booting the full Marty persona + startup ritual (which is
# expensive and wrong for a model door). The first try put this under tools/, but my-agent/CLAUDE.md
# is a parent of tools/, so claude -p loaded the whole boot config from there (caught by the skeptic
# 2026-09-23). The OS temp dir has no CLAUDE.md in its parent chain (verified), so it is genuinely
# clean. Persona, when a caller wants it, arrives through --system like every other lane here.
SUBCLEAN = pathlib.Path(tempfile.gettempdir()) / "marty-subclean"


def _which_full(name):
    """Full path to an executable, so subprocess (no shell) also finds a Windows .cmd/.ps1 shim
    that a bare name would miss under CreateProcess - which is how `status` could say 'ready'
    while the call failed with 'not found' (skeptic MEDIUM-2)."""
    import shutil
    return shutil.which(name)


def _flatten_messages(messages):
    """A subscription CLI takes a single prompt string, so fold a multi-turn chat history into one
    (the pane's sub lanes share the cloud thread; without this they'd answer each turn with no
    context). A single-turn call - the CLI's own switchboard usage - returns that turn unchanged."""
    if not messages:
        return ""
    if len(messages) == 1:
        return messages[0].get("content", "")
    prior = "\n\n".join(("User: " if m.get("role") == "user" else "Assistant: ") + m.get("content", "")
                        for m in messages[:-1])
    return "Conversation so far:\n" + prior + "\n\nUser: " + messages[-1].get("content", "")


def _codex_bin():
    """Newest bundled codex.exe. The desktop app installs it under a per-version hash dir
    that changes on update, so resolve it fresh rather than pinning the path. Falls back to
    a `codex` on PATH (an npm install) if the bundle is not found."""
    cands = sorted(CODEX_BIN_DIR.glob("*/codex.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
    if cands:
        return str(cands[0])
    from shutil import which
    w = which("codex")
    if w:
        return w
    raise LaneError("codex not found: open the Codex desktop app once, or run  npm i -g @openai/codex")


def _run_cli(argv, prompt, cwd, timeout=600):
    """Run a subscription CLI with the prompt on stdin. A missing binary or a timeout becomes
    a clean SystemExit, never a traceback that would take down a dashboard turn."""
    try:
        p = subprocess.run(argv, input=prompt, cwd=str(cwd), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except FileNotFoundError:
        raise LaneError(f"not found on PATH: {argv[0]}")
    except subprocess.TimeoutExpired:
        raise LaneError(f"{argv[0]} timed out after {timeout}s")
    return p.stdout, p.stderr, p.returncode


# The lockdown flags every claude_sub spawn carries, mirrored from dashboard/server.py sub_argv()
# (2026-09-28 outside audit, skeptic-confirmed). `--permission-prompts none` alone is NOT
# talk-only: the user settings file has an autoMode block that AUTO-APPROVES any built-in tool
# not explicitly denied, so a native tool (CronList, SendMessage, ...) executed with
# permission_denials=[] (proven live 2026-09-25 on the dashboard lane). `--tools ""` removes the
# whole built-in tool set; `--strict-mcp-config` keeps every MCP server in the user settings out
# (this lane passes no --mcp-config, so it has no tools at all); `--no-session-persistence` and
# `--no-chrome` match the dashboard spawn so a raw-model door leaves no session on disk.
CLAUDE_SUB_LOCKDOWN = ["--permission-prompts", "none", "--strict-mcp-config", "--no-chrome",
                       "--no-session-persistence", "--tools", ""]


def claude_sub_argv(binary, model, system):
    """The exact argv ask_claude_sub spawns, in one place so a test can assert the lockdown flags
    on the real builder rather than on a copy (the way tools/test_sub_tools_lockdown.py leans on
    server.sub_argv). Output stays `json`: this lane parses one result blob, not a stream."""
    argv = [binary, "-p", "--output-format", "json", *CLAUDE_SUB_LOCKDOWN]
    if model:
        argv += ["--model", model]
    if system:
        argv += ["--append-system-prompt", system]
    return argv


def ask_claude_sub(model, system, messages, _key=None):
    """`claude -p` on the Max plan, as a raw-model door: run from an empty dir (SUBCLEAN) so no
    CLAUDE.md loads and the answer is a clean model reply, not the full Marty agent reading the
    vault and fanning out to subagents (skeptic MEDIUM-1). Persona, if wanted, comes from the
    caller's --system (appended on top). Talk-only is enforced by CLAUDE_SUB_LOCKDOWN (see
    claude_sub_argv): `--tools ""` plus `--strict-mcp-config`, not just `--permission-prompts none`,
    which autoMode in the user settings overrides for undenied native tools. Needs Claude Code
    v2.1.259+ for those flags. $0 marginal; reports the list cost the API would have charged as
    extra['list_cost_usd']."""
    prompt = _flatten_messages(messages)
    binp = _which_full("claude")
    if not binp:
        raise LaneError("claude not found on PATH: install Claude Code")
    SUBCLEAN.mkdir(exist_ok=True)
    argv = claude_sub_argv(binp, model, system)
    out, err, rc = _run_cli(argv, prompt, SUBCLEAN)
    try:
        j = json.loads(out)
    except ValueError:
        raise LaneError(f"claude -p returned no JSON (rc={rc}): {(err or out)[:300]}")
    if j.get("is_error"):
        raise LaneError(f"claude -p error: {j.get('result') or err or 'unknown'}")
    text = j.get("result", "")
    print(text)
    u = j.get("usage", {})
    usage = (u.get("input_tokens", 0), u.get("output_tokens", 0))
    reported = next(iter(j.get("modelUsage") or {}), None) or model or "claude"
    return text, reported, usage, {"list_cost_usd": j.get("total_cost_usd"), "plan": "max"}


def ask_codex_sub(model, system, messages, _key=None):
    """`codex exec` on ChatGPT Plus. Read-only sandbox (cannot write or run risky commands),
    --ephemeral (no persisted session), run from home so only the global ~/.codex/AGENTS.md
    (Marty) loads. The final message is written to a temp file with -o and read back."""
    import tempfile
    flat = _flatten_messages(messages)
    prompt = (system + "\n\n" + flat) if system else flat
    binp = _codex_bin()
    SUBCLEAN.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        outfile = pathlib.Path(td) / "last.txt"
        # Run from an empty dir, not home: read-only sandbox scopes reads to the workspace, so
        # this stops codex from reading the whole vault under ~ while following AGENTS.md's
        # startup ritual (skeptic MEDIUM-1/LOW-5). The global ~/.codex/AGENTS.md still loads
        # (no flag suppresses it), so answers may carry Marty's voice; that is acceptable.
        argv = [binp, "exec", "--skip-git-repo-check", "-s", "read-only", "--ephemeral", "-o", str(outfile)]
        if model:
            argv += ["-m", model]
        out, err, rc = _run_cli(argv, prompt, SUBCLEAN)
        text = outfile.read_text(encoding="utf-8", errors="replace").strip() if outfile.exists() else ""
    if not text:
        raise LaneError(f"codex exec produced no output (rc={rc}): {(err or out)[:300]}")
    print(text)
    return text, model or "codex-default", (0, 0), {"plan": "plus"}


def ask_gemini_sub(model, system, messages, _key=None):
    """`agy -p` (Antigravity) on the Gemini subscription. Dormant until Antigravity is
    installed: a missing `agy` returns the one-line install command instead of a traceback."""
    binp = _which_full("agy")
    if not binp:
        raise LaneError(
            "Antigravity (agy) is not installed - the Gemini subscription lane is dormant.\n"
            "  Install:  powershell -c \"irm https://antigravity.google/cli/install.ps1 | iex\"\n"
            "  Then:     py tools/gen_boot.py --gemini   (writes ~/.gemini/AGENTS.md so agy boots Marty)")
    flat = _flatten_messages(messages)
    prompt = (system + "\n\n" + flat) if system else flat
    SUBCLEAN.mkdir(exist_ok=True)
    argv = [binp, "-p", "--output-format", "text"]
    if model:
        argv += ["--model", model]
    out, err, rc = _run_cli(argv, prompt, SUBCLEAN)
    text = (out or "").strip()
    if not text:
        raise LaneError(f"agy produced no output (rc={rc}): {(err or '')[:300]}")
    print(text)
    return text, model or "agy-default", (0, 0), {"plan": "gemini-sub"}


ASK_SUB = {"claude_sub": ask_claude_sub, "codex_sub": ask_codex_sub, "gemini_sub": ask_gemini_sub}


# ---------------------------------------------------------------- vault context (keyword retrieval, no embeddings yet)

STOP = {"what", "that", "this", "with", "from", "have", "does", "which", "when", "where", "about", "there", "their", "your", "will", "into", "them", "then", "than", "keep", "keeps", "rule", "quick", "answer"}


def _under_any(rel, prefixes):
    """True when a vault-relative posix path IS one of the prefixes or sits inside one as a
    whole path component. A bare startswith() let "07 - Resources" also match a folder named
    "07 - Resources Old" (audit finding 10), which matters because include= is the fence
    that keeps daily notes out of the consult lane."""
    for p in prefixes:
        p = str(p).strip("/")
        if rel == p or rel.startswith(p + "/"):
            return True
    return False


def vault_context(question, max_notes=4, max_chars=6000, include=None):
    """Keyword retrieval over the vault's markdown, pure Python, no index. Ranks
    notes by how many distinct question words they contain, then by hits.
    include= restricts the search to notes whose vault-relative path starts with one of
    the given prefixes (the consult lane passes the operational folders so daily notes,
    with family and finances in them, never leave through it). None = every note."""
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9'-]{3,}", question)]
    words = [w for w in dict.fromkeys(words) if w not in STOP][:10]
    if not words:
        return ""
    scored = []
    for path in VAULT.rglob("*.md"):
        if ".obsidian" in path.parts or ".trash" in path.parts:
            continue
        if include is not None and not _under_any(path.relative_to(VAULT).as_posix(), include):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        distinct = sum(1 for w in words if w in low)
        if distinct == 0:
            continue
        hits = sum(low.count(w) for w in words)
        scored.append((distinct, hits, path, text))
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    top = scored[:max_notes]
    chunks = []
    for _d, _h, path, text in top:
        # take the window around the first keyword hit rather than the file head
        low = text.lower()
        first = min((low.find(w) for w in words if w in low), default=0)
        start = max(0, first - 400)
        piece = text[start: start + max_chars // max(1, len(top))]
        chunks.append(f"### {path.relative_to(VAULT)}\n{piece}")
    return "\n\n".join(chunks)


LOCAL_KNOWLEDGE_DIR = HERE / "local_knowledge"
LOCAL_KNOWLEDGE_BUDGET = 20000      # chars of cheat sheet per local call, about 5k of a 16k-token context
PROVENANCE_RE = re.compile(r"^<!-- feed_local (\{.*\}) -->[ \t]*\n?", re.M)


def sheet_freshness(sheet_path, text=None):
    """(source note, when written, fresh) for one cheat sheet; fresh is True, False, or None
    when it cannot be told. Sheets written by feed_local.py since 2026-09-23 carry a
    provenance line with their source note's sha256; older ones only have their
    '# Cheat sheet: <path>' title, so they are judged by file times instead."""
    text = sheet_path.read_text(encoding="utf-8", errors="replace") if text is None else text
    m = PROVENANCE_RE.search(text)
    if m:
        try:
            prov = json.loads(m.group(1))
        except ValueError:
            prov = {}
        src = prov.get("source")
        if src:
            try:
                current = hashlib.sha256((VAULT / src).read_bytes()).hexdigest()
            except OSError:
                return src, prov.get("generated"), None
            return src, prov.get("generated"), current == prov.get("sha256")
    t = re.match(r"# Cheat sheet: (.+)", text)
    written = dt.datetime.fromtimestamp(sheet_path.stat().st_mtime).isoformat(timespec="minutes")
    if not t:
        return None, written, None
    src = t.group(1).strip()
    try:
        return src, written, (VAULT / src).stat().st_mtime <= sheet_path.stat().st_mtime
    except OSError:
        return src, written, None


def local_knowledge(question=None, budget_chars=LOCAL_KNOWLEDGE_BUDGET):
    """Cheat sheets tools/feed_local.py condensed for marty-local's own use (see its
    SEED_NOTES), loaded on every ollama call rather than searched like vault_context().

    Each sheet is checked against its source note first (audit finding 14). Until
    2026-09-23 a sheet written on 9/20 was loaded as current on 9/23, so three-day-old
    open items sat in standing context as if they were today's. A sheet whose note has
    changed since is still loaded, because most of what it holds stays true, but under a
    banner telling the model its statuses may be out of date. Loading stops at
    budget_chars: fresh sheets first, then those sharing the most words with the question."""
    if not LOCAL_KNOWLEDGE_DIR.exists():
        return ""
    words = set(re.findall(r"[a-z][a-z0-9'-]{3,}", (question or "").lower())) - STOP
    items = []
    for f in sorted(LOCAL_KNOWLEDGE_DIR.glob("*.md")):
        text = f.read_text(encoding="utf-8", errors="replace")
        src, written, fresh = sheet_freshness(f, text)
        body = PROVENANCE_RE.sub("", text).strip()
        if fresh is False:
            body = (f"[STALE CHEAT SHEET: written {written}; its source note '{src}' has changed since. "
                    "Open items and statuses below may be out of date. Say so if you rely on them, "
                    "and prefer the vault itself.]\n" + body)
        elif fresh is None:
            body = f"[Cheat sheet of unknown freshness, written {written}.]\n" + body
        relevance = sum(1 for w in words if w in body.lower())
        items.append((fresh is True, relevance, body))
    items.sort(key=lambda t: (t[0], t[1]), reverse=True)
    out, used = [], 0
    for _fresh, _rel, body in items:
        cost = len(body) + (2 if out else 0)        # the blank line joining it counts too
        if used + cost > budget_chars:
            continue
        out.append(body)
        used += cost
    return "\n\n".join(out)


# ---------------------------------------------------------------- logging

def write_log(folder, brain, model_reported, model_requested, system, question, answer, private, meta=None):
    folder = pathlib.Path(folder); folder.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now()
    # Microseconds plus a random tail, created exclusively ("x"): names used to stop at the
    # second and open with "w", so two calls in one second shared a name and the second
    # silently overwrote the first transcript (audit finding 14).
    fn = folder / f"{ts:%Y-%m-%d-%H%M%S-%f}-{secrets.token_hex(2)}-{brain}.md"
    with open(fn, "x", encoding="utf-8") as f:
        f.write(f"# {'PRIVATE ' if private else ''}{brain} transcript\n\n")
        f.write(f"- date: {ts:%Y-%m-%d %H:%M:%S} local\n- brain: {brain}\n- model requested: {model_requested}\n- model reported: {model_reported}\n")
        for k, v in (meta or {}).items():
            f.write(f"- {k}: {v}\n")
        f.write("\n## System prompt\n\n" + (system or "(none)") + "\n\n## Prompt, verbatim\n\n" + question + "\n\n## Answer, verbatim\n\n" + answer + "\n")
    return fn


# ---------------------------------------------------------------- commands

def cmd_status(_a):
    try:
        v = _http(f"{OLLAMA}/api/version", {}); tags = _http(f"{OLLAMA}/api/tags", {})
        print(f"ollama: up, version {v.get('version')}, models: {', '.join(m['name'] for m in tags.get('models', []))}")
    except Exception as e:  # noqa: BLE001
        print(f"ollama: DOWN ({e}); start the Ollama app")
    for brain, (itm, chan) in KEYS.items():
        have = [n for n in (itm, chan) if n and cred.read(n)]
        print(f"{brain}: key {'present (' + ', '.join(have) + ')' if have else 'MISSING (py tools\\cred.py set ' + itm + ')'}")
    from shutil import which
    def _codex_ok():
        try:
            return _codex_bin()
        except SystemExit:
            return None
    for lane, present, how in (
        ("claude_sub (Max)", which("claude"), "install Claude Code"),
        ("codex_sub (Plus)", _codex_ok(), "open the Codex desktop app once, or npm i -g @openai/codex"),
        ("gemini_sub (Antigravity)", which("agy"), 'irm https://antigravity.google/cli/install.ps1 | iex'),
    ):
        print(f"{lane}: {'ready' if present else 'DORMANT (' + how + ')'}")
    print(f"private folder: {PRIVATE_DIR} ({'exists' if PRIVATE_DIR.exists() else 'will be created on first private ask'})")


def run_one(a, question):
    brain = "ollama" if a.private else a.to
    if a.private and a.to and a.to != "ollama":
        raise SystemExit("--private means local only; the cloud brains are refused on purpose")
    if brain in CLOUD and a.private:
        raise SystemExit("refusing: private lane cannot use a cloud brain")
    model = a.model or DEFAULTS[brain]
    system = a.system or ""
    ctx = vault_context(question) if a.vault else ""
    if ctx:
        system = (system + "\n\n" if system else "") + "Relevant notes from Lukas's vault (use if helpful, cite the note name):\n\n" + ctx
    if brain == "ollama":
        lk = local_knowledge(question)
        if lk:
            system = (system + "\n\n" if system else "") + "Cheat sheets you (Marty) wrote for yourself, from the vault:\n\n" + lk
    messages = [{"role": "user", "content": question}]
    schema = None
    if getattr(a, "schema", None):
        try:
            schema = json.loads(pathlib.Path(a.schema).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise SystemExit(f"--schema: could not read a JSON schema from {a.schema}: {e}")
        if not isinstance(schema, dict) or not schema:
            raise SystemExit(f"--schema: {a.schema} must be a non-empty JSON object (a JSON Schema), "
                             f"got {type(schema).__name__}. An empty '{{}}' would silently constrain nothing.")
    strict = getattr(a, "strict", False)
    key_name = None
    extra = None
    if brain == "ollama":
        answer, reported, usage = ask_ollama(model, system, messages, format=schema)
    elif brain in SUBS:
        # Flat-rate CLI: no key, $0 marginal, prompt sent to the vendor (so never a private lane).
        # Structured output on the CLI lanes is a later step (codex has --output-schema); the
        # schema flag is ignored here rather than silently dropped without warning.
        if schema:
            print("[note] --schema is not wired to the subscription lanes yet; ignoring it", file=sys.stderr)
        answer, reported, usage, extra = ASK_SUB[brain](model, system, messages)
    else:
        key, key_name = key_for(brain, a.key)
        answer, reported, usage = {"claude": ask_claude, "grok": ask_grok, "gemini": ask_gemini, "openrouter": ask_openrouter}[brain](model, system, messages, key, schema, strict)
    cost = record_call(brain, model, reported, usage, a.project, a.private, extra=extra, customer=getattr(a, "customer", None))
    folder = PRIVATE_DIR if a.private else (a.log or None)
    if folder:
        meta = {"lane": "private, local only" if a.private else "standard", "key used": key_name or "none (local)", "vault context": "yes" if ctx else "no"}
        # The receipt carries the system prompt exactly as sent, vault context included. It
        # used to log a placeholder for vault-assisted calls, so the "receipt-grade"
        # transcript was missing the one part that varies (audit finding 14).
        sent = ollama_system(model, system) if brain == "ollama" else system
        if brain == "claude" and schema:
            sent = claude_schema_request(model, system)[1]   # carries the emit instruction when added
        fn = write_log(folder, brain, reported, model, sent, question, answer, a.private, meta)
        print(f"\n[logged: {fn}]", file=sys.stderr)
    if cost is not None:
        print(f"[{brain} {reported}: {usage[0]}+{usage[1]} tok, ${cost:.4f}, project={a.project}]", file=sys.stderr)
    else:
        print(f"[{brain} {reported}: {usage[0]}+{usage[1]} tok, cost unknown (unpriced model), project={a.project}]", file=sys.stderr)
    return answer


def cmd_ask(a):
    run_one(a, a.question)


def cmd_interview(a):
    if not a.log:
        raise SystemExit("interview needs --log <folder>: receipts are the point")
    a.private = False
    run_one(a, a.question)


def cmd_chat(a):
    brain = "ollama" if a.private else a.to
    model = a.model or DEFAULTS[brain]
    if brain != "ollama":
        raise SystemExit("interactive chat is local-only in this version; use ask for cloud brains")
    print(f"[{model}, {'PRIVATE lane' if a.private else 'local'}; blank line to quit]")
    history = []
    while True:
        try:
            q = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not q:
            break
        history.append({"role": "user", "content": q})
        print("marty> ", end="", flush=True)
        lk = local_knowledge(q)
        chat_system =(a.system + "\n\n" if a.system else "") + ("Cheat sheets you (Marty) wrote for yourself, from the vault:\n\n" + lk if lk else "")
        answer, reported, usage = ask_ollama(model, chat_system, history)
        history.append({"role": "assistant", "content": answer})
        record_call(brain, model, reported, usage, a.project, a.private, customer=getattr(a, "customer", None))
        if a.private or a.log:
            write_log(PRIVATE_DIR if a.private else a.log, brain, reported, model, a.system or "", q, answer, a.private)


def cmd_spend(a):
    if not METER.exists():
        print("no calls logged yet"); return
    cutoff = dt.datetime.now() - dt.timedelta(days=a.days)
    by_brain, by_project = {}, {}
    total = unpriced = 0
    for row in _meter_rows():
        try:
            if dt.datetime.fromisoformat(str(row.get("ts"))) < cutoff:
                continue
        except ValueError:
            continue
        if row.get("cost_usd") is None:
            unpriced += 1
            continue
        c = float(row["cost_usd"])
        total += c
        by_brain[row.get("brain", "?")] = by_brain.get(row.get("brain", "?"), 0) + c
        by_project[row.get("project", "?")] = by_project.get(row.get("project", "?"), 0) + c
    print(f"last {a.days} days: ${total:.2f} total" + (f"  ({unpriced} calls unpriced, model not in the table)" if unpriced else ""))
    print("by brain:")
    for b, c in sorted(by_brain.items(), key=lambda kv: -kv[1]):
        print(f"  {b}: ${c:.2f}")
    print("by project:")
    for pr, c in sorted(by_project.items(), key=lambda kv: -kv[1]):
        print(f"  {pr}: ${c:.2f}")


def _emit(a, lines):
    """Print the block, and mirror it to --out if asked.

    The mirror target is normally the mounted Google Drive (G:), which is how a
    number that only exists on this PC reaches a routine that runs in the cloud.
    A failed write must never take down the caller - the dashboard thread calls
    this, and a missing G: drive is not a reason to lose the dashboard."""
    text = '\n'.join(lines)
    sys.stdout.write(text + '\n')
    if getattr(a, "out", None):
        try:
            out = pathlib.Path(a.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + '\n', encoding="utf-8")
        except OSError as e:
            sys.stderr.write("[daily] could not write %s: %s" % (a.out, e) + '\n')

def cmd_daily(a):
    _lines = []
    def print(*args, **kw):  # noqa: A001 - capture, then emit and optionally mirror
        _lines.append(" ".join(str(x) for x in args))
    """One short block for the Morning Queue: what yesterday cost, and where.

    Exists because Lukas declined a spend cap 2026-09-22 in favour of watching the
    real number for a month first. A cap guesses a ceiling before there is data;
    this reports the data. Deliberately terse - it is one section of a morning
    brief, not a report anybody opens on purpose.

    Cents, not dollars, in the headline: this stack's daily spend rounds to $0.00
    at two decimal places, and a brief that always says $0.00 teaches the reader
    to skip it."""
    day = a.date or (dt.date.today() - dt.timedelta(days=1)).isoformat()
    if not METER.exists():
        print(f"SPEND {day}: no meter file yet"); _emit(a, _lines); return
    by_brain, by_project, rows = {}, {}, 0
    total = unpriced = free = 0
    sub_calls = 0            # calls that ran on a flat-rate subscription lane ($0 metered)
    sub_value = 0.0          # what those would have cost on the API (list_cost_usd), i.e. the value the plan delivered
    for row in _meter_rows():
        if str(row.get("ts", ""))[:10] != day:
            continue
        rows += 1
        if row.get("brain") == "ollama":
            free += 1
        if row.get("brain") in SUBS:
            sub_calls += 1
            if row.get("list_cost_usd"):
                sub_value += float(row["list_cost_usd"])
        if row.get("cost_usd") is None:
            unpriced += 1
            continue
        c = float(row["cost_usd"])
        total += c
        by_brain[row.get("brain", "?")] = by_brain.get(row.get("brain", "?"), 0) + c
        by_project[row.get("project", "?")] = by_project.get(row.get("project", "?"), 0) + c
    if not rows:
        print(f"SPEND {day}: nothing ran. $0.00"); _emit(a, _lines); return
    month_start = dt.date.fromisoformat(day).replace(day=1).isoformat()
    mtd = spent_since(month_start)
    print(f"SPEND {day}: ${total:.4f} across {rows} calls  |  month to date ${mtd:.4f}")
    if unpriced:
        print(f"  NOTE {unpriced} call(s) unpriced - model not in the PRICING table, so the real figure is higher")
    if by_brain:
        print("  brain:   " + ",  ".join(f"{b} ${c:.4f}" for b, c in sorted(by_brain.items(), key=lambda kv: -kv[1])))
    if by_project:
        print("  project: " + ",  ".join(f"{pr} ${c:.4f}" for pr, c in sorted(by_project.items(), key=lambda kv: -kv[1])[:5]))
    if free:
        print(f"  {free} of those {rows} ran locally for $0.00")
    if sub_calls:
        print(f"  {sub_calls} ran on subscription lanes for $0.00 metered"
              + (f" (~${sub_value:.4f} of API value delivered by the plans)" if sub_value else ""))
    _emit(a, _lines)


def selftest():
    """No network, no real vault, no real meter: temp fixtures for the fixes from audit
    findings 10 (the include= fence) and 14 (transcripts, receipts, the meter parser, cheat
    sheet freshness)."""
    import contextlib
    import io
    import tempfile
    global VAULT, METER, LOCAL_KNOWLEDGE_DIR, ask_ollama
    fails = []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    real = (VAULT, METER, LOCAL_KNOWLEDGE_DIR, ask_ollama)
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        VAULT, METER, LOCAL_KNOWLEDGE_DIR = td / "vault", td / "meter.jsonl", td / "lk"
        try:
            print("vault_context include= is a path-component fence")
            for folder in ("07 - Resources", "07 - Resources Old", "01 - Daily Notes"):
                (VAULT / folder).mkdir(parents=True)
            (VAULT / "07 - Resources" / "ops.md").write_text("zorblatt appliance notes", encoding="utf-8")
            (VAULT / "07 - Resources Old" / "leak.md").write_text("zorblatt family finances", encoding="utf-8")
            (VAULT / "01 - Daily Notes" / "day.md").write_text("zorblatt daily", encoding="utf-8")
            (VAULT / "Active Priorities.md").write_text("zorblatt open item", encoding="utf-8")
            (VAULT / "Active Priorities.md.old.md").write_text("zorblatt old copy", encoding="utf-8")
            ctx = vault_context("zorblatt", 10, 6000, include=["07 - Resources", "Active Priorities.md"])
            names = sorted(n.replace("\\", "/") for n in re.findall(r"^### (.+)$", ctx, flags=re.M))
            check(names == ["07 - Resources/ops.md", "Active Priorities.md"],
                  f"only whole path components match, not look-alike names ({names})")

            print("transcripts never overwrite each other")
            logs = td / "logs"
            t1 = write_log(logs, "claude", "m", "m", "sys", "question one", "a1", False)
            t2 = write_log(logs, "claude", "m", "m", "sys", "question two", "a2", False)
            check(t1 != t2 and "question one" in t1.read_text(encoding="utf-8")
                  and "question two" in t2.read_text(encoding="utf-8"), "two transcripts in the same second are two files")

            print("receipts carry the system prompt as sent")
            seen = {}

            def fake_ollama(model, system, messages, stream=True, _retry=True, think=None, format=None):
                seen["system"] = system
                return "fine", model, (10, 5)
            ask_ollama = fake_ollama
            _MODEL_SYSTEM_CACHE["selftest-model"] = "PERSONA-BLOCK baked into the Modelfile"
            a = argparse.Namespace(private=False, to="ollama", model="selftest-model", system="", vault=True,
                                   log=str(logs), key="itm", project="selftest")
            with contextlib.redirect_stderr(io.StringIO()):
                run_one(a, "what about the zorblatt appliance")
            receipt = [p for p in logs.glob("*.md") if "what about the zorblatt appliance" in p.read_text(encoding="utf-8")]
            body = receipt[0].read_text(encoding="utf-8") if receipt else ""
            check("zorblatt appliance notes" in body and seen.get("system", "\x00") in body
                  and "(system + vault context; see file)" not in body,
                  "the receipt holds the system prompt, vault context included")
            check(body.find("PERSONA-BLOCK") != -1 and body.find("PERSONA-BLOCK") < body.find("zorblatt appliance notes"),
                  "an ollama receipt includes the Modelfile persona block that ask_ollama puts in front")

            print("one meter parser; a torn row is skipped, not fatal")
            METER.write_text('{"ts": "2026-09-22T10:00:00", "brain": "claude", "project": "x", "cost_usd": 0.5}\n'
                             '{"ts": "2026-09-22T10:01:00", "brain": "ollama", "project": "x", "cost_usd": 0.0}\n'
                             '{"ts": "2026-09-22T10:0\n', encoding="utf-8")
            check(abs(spent_since("2026-09-22") - 0.5) < 1e-9, "spent_since skips the torn row")
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    cmd_daily(argparse.Namespace(date="2026-09-22", out=None))
                    cmd_spend(argparse.Namespace(days=100000))
                crashed = None
            except Exception as e:
                crashed = e
            out = buf.getvalue()
            check(crashed is None and "SPEND 2026-09-22: $0.5000 across 2 calls" in out and "1 of those 2 ran locally" in out,
                  f"the daily report survives a torn row ({crashed!r})")
            check(crashed is None and "$0.50 total" in out, "the spend report survives a torn row")

            print("cheat sheets are checked against their source note")
            LOCAL_KNOWLEDGE_DIR.mkdir()
            src = VAULT / "Active Priorities.md"
            prov = {"source": "Active Priorities.md", "sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                    "generated": "2026-09-23T07:00:00"}
            (LOCAL_KNOWLEDGE_DIR / "active-priorities-md.md").write_text(
                f"# Cheat sheet: Active Priorities.md\n<!-- feed_local {json.dumps(prov)} -->\nOpen: the zorblatt item.\n",
                encoding="utf-8")
            lk = local_knowledge("zorblatt")
            check("Open: the zorblatt item." in lk and "STALE" not in lk and "feed_local {" not in lk,
                  "a fresh sheet loads clean, provenance line stripped")
            src.write_text("zorblatt open item, now closed", encoding="utf-8")
            check("[STALE CHEAT SHEET" in local_knowledge("zorblatt"), "a sheet whose source changed loads under a STALE banner")
            legacy = LOCAL_KNOWLEDGE_DIR / "legacy.md"
            legacy.write_text("# Cheat sheet: 07 - Resources/ops.md\nold facts\n", encoding="utf-8")
            os.utime(legacy, (1, 1))
            full = local_knowledge()
            check(full.count("[STALE CHEAT SHEET") == 2, "an old-format sheet older than its source is judged by file times")
            part = local_knowledge(budget_chars=len(full) - 1)
            check(len(part) <= len(full) - 1 and part.count("# Cheat sheet") < full.count("# Cheat sheet"),
                  "the character budget drops a sheet rather than overflowing")

            print("subscription lanes: $0 metered, JSON parsing, private refused")
            check(price_for("claude_sub", "sonnet") == (0.0, 0.0) and price_for("codex_sub", "x") == (0.0, 0.0),
                  "subscription lanes price at $0 (flat-rate, not metered)")
            # a claude_sub call is metered at $0 but keeps the list cost and plan
            import unittest.mock as _mock
            fake = json.dumps({"result": "hi there", "is_error": False, "total_cost_usd": 0.021,
                               "usage": {"input_tokens": 12, "output_tokens": 7},
                               "modelUsage": {"claude-haiku-4-5-20251001": {}}})
            with _mock.patch.object(subprocess, "run", return_value=_mock.Mock(stdout=fake, stderr="", returncode=0)):
                with contextlib.redirect_stdout(io.StringIO()):
                    txt, rep, usage, extra = ask_claude_sub("haiku", "be brief", [{"role": "user", "content": "hi"}])
            check(txt == "hi there" and usage == (12, 7) and extra["list_cost_usd"] == 0.021
                  and extra["plan"] == "max" and rep.startswith("claude-haiku"),
                  "ask_claude_sub parses result, usage, list cost and reported model")
            a2 = argparse.Namespace(private=True, to="claude_sub", model=None, system="", vault=False,
                                    log=None, key="itm", project="selftest")
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    run_one(a2, "should be refused")
                refused = False
            except SystemExit:
                refused = True
            check(refused, "a subscription lane is refused under --private (the prompt would leave the box)")
            check("claude_sub" in DEFAULTS and "claude_sub" in SUBS and "claude_sub" not in CLOUD,
                  "claude_sub is wired as a subscription lane, not a metered cloud one")

            print("meter prices Opus 5.5 and counts prompt-cache tokens")
            check(price_for("claude", "claude-opus-5-5") == (4, 20) and price_for("claude", "claude-opus-5") == (5, 25),
                  "Opus 5.5 is $4/$20, not Opus 5's $5/$25 by substring fall-through")
            check(claude_usage({"input_tokens": 10, "output_tokens": 2, "cache_read_input_tokens": 300,
                                "cache_creation_input_tokens": 50,
                                "cache_creation": {"ephemeral_5m_input_tokens": 30, "ephemeral_1h_input_tokens": 20}})
                  == (10, 2, 300, 30, 20) and claude_usage({}) == (0, 0, 0, 0, 0)
                  and claude_usage({"input_tokens": 5, "output_tokens": 1, "cache_read_input_tokens": None})
                  == (5, 1, 0, 0, 0), "claude_usage reads cache fields, missing or null = 0")
            METER.write_text("", encoding="utf-8")
            c = record_call("claude", "m", "claude-sonnet-5", (1_000_000, 0, 1_000_000, 1_000_000, 1_000_000), "t", False)
            row = json.loads(METER.read_text(encoding="utf-8").splitlines()[-1])
            check(abs(c - (2 + 0.2 + 2.5 + 4)) < 1e-9 and row["cache_read_input_tokens"] == 1_000_000
                  and row["cache_creation_input_tokens"] == 2_000_000 and row["cache_creation_1h_input_tokens"] == 1_000_000,
                  f"cache read 0.1x, 5m write 1.25x, 1h write 2x, recorded on the row (${c})")
            c55 = record_call("claude", "m", "claude-opus-5-5", (0, 0, 1_000_000), "t", False)
            check(abs(c55 - 0.20) < 1e-9, f"Opus 5.5 cache read is 0.05x ($0.20/MTok), per the pricing page (${c55})")
            record_call("claude", "m", "claude-haiku-4-5", (100, 10), "t", False)
            old = json.loads(METER.read_text(encoding="utf-8").splitlines()[-1])
            check(not any(k.startswith("cache_") for k in old), "an uncached call writes the old row shape")
            check(record_call("gemini", "m", "gemini-3.8-flash", (10, 1, 5), "t", False) is None,
                  "cache tokens on a non-Anthropic model are left unpriced, not guessed")

            print("structured output normalizes one schema per provider")
            import sys as _sys
            import unittest.mock as _mock
            mod = _sys.modules[__name__]
            cap = {}
            claude_stop = {"reason": "end_turn"}

            def fake_http(url, headers, body=None, timeout=180):
                cap["url"], cap["body"] = url, body
                if "anthropic" in url:
                    return {"content": [{"type": "tool_use", "name": "emit", "input": {"ok": True}}],
                            "usage": {"input_tokens": 1, "output_tokens": 1}, "model": "m",
                            "stop_reason": claude_stop["reason"]}
                if "generativelanguage" in url:
                    return {"candidates": [{"content": {"parts": [{"text": "{}"}]}}], "usageMetadata": {}, "modelVersion": "m"}
                return {"choices": [{"message": {"content": "{}"}}], "usage": {}, "model": "m"}  # openai shape

            # A realistic schema: an OPTIONAL field (note) and an OPEN object (additionalProperties True) -
            # the exact shape that used to 400 (gemini forbids additionalProperties; OpenAI strict demands it).
            sch = {"type": "object", "properties": {"ok": {"type": "boolean"}, "note": {"type": "string"}},
                   "required": ["ok"], "additionalProperties": True}
            with _mock.patch.object(mod, "_http", fake_http), contextlib.redirect_stdout(io.StringIO()):
                ctext, _, _ = ask_claude("m", "", [{"role": "user", "content": "x"}], "k", sch)
                claude_body = cap["body"]
                ask_claude("claude-opus-5-5", "sys", [{"role": "user", "content": "x"}], "k", sch); o55_body = cap["body"]
                ask_gemini("m", "", [{"role": "user", "content": "x"}], "k", sch); gemini_body = cap["body"]
                ask_grok("m", "", [{"role": "user", "content": "x"}], "k", sch); grok_body = cap["body"]
                ask_openrouter("m", "", [{"role": "user", "content": "x"}], "k", sch); or_body = cap["body"]
                ask_grok("m", "", [{"role": "user", "content": "x"}], "k", sch, True); grok_strict = cap["body"]
            check(claude_body["tools"][0]["input_schema"] is sch and ctext == '{"ok": true}',
                  "claude schema uses a forced tool and returns the tool input as JSON")
            check(claude_body["tool_choice"] == {"type": "tool", "name": "emit"}
                  and o55_body["tool_choice"] == {"type": "auto"} and o55_body["system"].endswith(EMIT_INSTRUCTION)
                  and o55_body["system"].startswith("sys"),
                  "Opus 5.5 --schema sends tool_choice auto plus the emit instruction (forcing 400s there)")
            gsch = gemini_body["generationConfig"]["responseSchema"]
            check("additionalProperties" not in gsch and gsch["required"] == ["ok"],
                  "gemini schema is stripped of additionalProperties (which gemini would 400 on)")
            check(grok_body["response_format"]["json_schema"]["strict"] is False
                  and grok_body["response_format"]["json_schema"]["schema"]["required"] == ["ok"],
                  "grok non-strict passes the schema through (optional fields survive, no 400)")
            check(or_body["provider"]["require_parameters"] is True,
                  "openrouter asks for require_parameters so an unsupported model errors, not silently drops")
            gs = grok_strict["response_format"]["json_schema"]
            check(gs["strict"] is True and gs["schema"]["additionalProperties"] is False
                  and sorted(gs["schema"]["required"]) == ["note", "ok"],
                  "--strict auto-closes the schema for the OpenAI lanes (all fields required, no extras)")
            # claude truncation must fail loudly, not return partial JSON
            claude_stop["reason"] = "max_tokens"
            try:
                with _mock.patch.object(mod, "_http", fake_http), contextlib.redirect_stdout(io.StringIO()):
                    ask_claude("m", "", [{"role": "user", "content": "x"}], "k", sch)
                trunc_raised = False
            except SystemExit:
                trunc_raised = True
            check(trunc_raised, "claude --schema raises on a truncated (max_tokens) response instead of returning partial JSON")
            claude_stop["reason"] = "end_turn"
            # no schema -> none of the fields appear (additive, existing behaviour untouched)
            with _mock.patch.object(mod, "_http", fake_http), contextlib.redirect_stdout(io.StringIO()):
                ask_grok("m", "", [{"role": "user", "content": "x"}], "k"); plain = cap["body"]
            check("response_format" not in plain and "provider" not in plain,
                  "no --schema leaves the request exactly as before")
            # an empty/no-op schema file is refused rather than silently constraining nothing
            (td / "empty.json").write_text("{}", encoding="utf-8")
            ea = argparse.Namespace(private=False, to="gemini", model="m", system="", vault=False,
                                    log=None, key="itm", project="selftest", schema=str(td / "empty.json"), strict=False)
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    run_one(ea, "x")
                empty_refused = False
            except SystemExit:
                empty_refused = True
            check(empty_refused, "an empty '{}' schema is refused, not treated as a silent no-op")
        finally:
            VAULT, METER, LOCAL_KNOWLEDGE_DIR, ask_ollama = real
            _MODEL_SYSTEM_CACHE.pop("selftest-model", None)
    print()
    if fails:
        print(f"{len(fails)} FAILED:")
        for f in fails:
            print("  - " + f)
        return 1
    print("all checks passed")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("selftest", help="offline checks, temp fixtures").set_defaults(fn=lambda _a: sys.exit(selftest()))
    sp = sub.add_parser("spend", help="report cost from the meter")
    sp.add_argument("--days", type=int, default=30)
    sp.set_defaults(fn=cmd_spend)
    dp = sub.add_parser("daily", help="yesterday's cost in one block, for the Morning Queue")
    dp.add_argument("--date", help="YYYY-MM-DD; default yesterday")
    dp.add_argument("--out", help="also write the block to this file (use the mounted "
                                  "Google Drive path so a cloud routine can read it)")
    dp.set_defaults(fn=cmd_daily)
    for name, fn in (("ask", cmd_ask), ("interview", cmd_interview), ("chat", cmd_chat)):
        s = sub.add_parser(name)
        s.add_argument("question", nargs="?" if name == "chat" else None)
        s.add_argument("--to", choices=["ollama", "claude", "grok", "gemini", "openrouter",
                                        "claude_sub", "codex_sub", "gemini_sub"], default="ollama")
        s.add_argument("--model")
        s.add_argument("--system", help="system prompt text")
        s.add_argument("--private", action="store_true", help="local only, log only to the private folder")
        s.add_argument("--vault", action="store_true", help="add matching vault notes as context (keyword search)")
        s.add_argument("--schema", help="path to a JSON schema; constrains the model to emit JSON matching it "
                                        "(ollama/claude/grok/gemini/openrouter; not the subscription lanes yet). "
                                        "The schema is normalized per provider so one file works on every lane.")
        s.add_argument("--strict", action="store_true", help="with --schema, demand a hard guarantee on the "
                                        "OpenAI-shape lanes (grok/openrouter): the schema is auto-closed "
                                        "(additionalProperties:false, all fields required). Off by default so "
                                        "ordinary schemas with optional fields don't 400.")
        s.add_argument("--log", help="folder for a receipt-grade transcript")
        s.add_argument("--project", default="general", help="tag for the spend meter (e.g. 'itm', 'ugc', 'console')")
        s.add_argument("--customer", help="who this spend is for (e.g. '{{CONTACT_NAME_1_LC}}'); default: mapped from --project")
        s.add_argument("--key", choices=["itm", "channel"], default="itm", help="which Credential Manager key family to use")
        s.set_defaults(fn=fn)
    a = p.parse_args()
    try:
        a.fn(a)
    except LaneError as e:
        print(f"lane error: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
