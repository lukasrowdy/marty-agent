"""
voicecheck.py - preflight for Marty's voice. Answers "will he sound like himself?"
before the answer arrives out loud in the wrong voice.

This exists because of a real failure on 2026-09-20: the voice_id in backtalk.json
was a Voice Design *preview* id that was never saved to the permanent library, so
every ElevenLabs call failed and mouth.py silently degraded to Kokoro. The design is
degrade-never-mute, which is correct for a live conversation and terrible for
noticing - Marty kept talking, just as somebody else. Only the log knew.

THREE STATES, NOT TWO. A preflight that only says pass/fail launders "the network is
down" into "your voice is broken", and an operator learns to ignore it inside a week.

    ok       the configured ElevenLabs voice resolves and will be the voice that speaks
    drifted  Marty will NOT sound like himself - wrong id, unsaved id, or ElevenLabs
             switched off so every reply comes out in the Kokoro fallback
    unknown  the check could not be completed - no network, no key, key rejected.
             Says nothing about the voice either way, and must never be reported as drift.

    py tools/voicecheck.py                 check config + resolve the voice (free)
    py tools/voicecheck.py --json          also write logs/voicecheck.json for the dashboard
    py tools/voicecheck.py --tts           also make one real 3-word TTS call (costs credits)
    py tools/voicecheck.py --quiet         one line on ok; drifted/unknown always speak up

Exit 0 = ok, 1 = drifted, 2 = unknown. Unattended callers branch on these; anything
that treats non-zero as "voice broken" will cry wolf every time the WAN blips.

Two things learned the hard way, kept here so they are not re-learned:

  * Resolve by ID, never by NAME. The account carries retired voices literally named
    "Marty" - see KNOWN_DECOYS. A name lookup finds the wrong one.
  * An unknown voice id comes back HTTP 400, NOT 404, even when well formed (verified
    against the live API 2026-09-22). The status code cannot tell a typo from a real
    preview id that was never saved; the SHAPE of the id is what separates them.

Timeouts are deliberately short. urllib's timeout is per-socket-operation, not a total
deadline, so DNS + connect + TLS + each recv each get their own. Against a black-holed
route that compounds into minutes, which is why nothing should ever block on this.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

REPO = pathlib.Path(__file__).resolve().parent.parent
CONFIG_PATH = pathlib.Path(
    os.environ.get("BACKTALK_CONFIG") or (REPO / "backtalk" / "backtalk.json")
)
RESULT_PATH = REPO / "logs" / "voicecheck.json"

# The live voice, as picked 2026-09-20. A tripwire, not a source of truth -
# backtalk.json is the source of truth. If these disagree, say so and let a human
# decide which one moved.
EXPECTED_VOICE_ID = "{{VOICE_ID_LIVE}}"

# Retired voices still sitting on the account. The first is NAMED "Marty", which is
# exactly why nothing here ever looks a voice up by name.
KNOWN_DECOYS = {
    "{{VOICE_ID_DECOY_1}}": "retired original, named plain 'Marty'",
    "{{VOICE_ID_DECOY_2}}": "saved candidate, soft-upbeat-british-c, never used",
}

API = "https://api.elevenlabs.io/v1"

# ElevenLabs voice ids are 20 alphanumeric characters.
WELL_FORMED_ID = re.compile(r"^[A-Za-z0-9]{20}$")

# Short on purpose - see the module docstring on per-socket timeouts.
LOOKUP_TIMEOUT = 8
TTS_TIMEOUT = 30

OK, DRIFTED, UNKNOWN = "ok", "drifted", "unknown"
EXIT = {OK: 0, DRIFTED: 1, UNKNOWN: 2}


class Result:
    def __init__(self):
        self.state = OK
        self.reason = "the voice that will speak is the voice that is supposed to speak"
        self.notes = []

    def set(self, state, reason):
        # drifted outranks unknown outranks ok: a definite answer wins over a
        # non-answer, so a key problem never masks a real drift found earlier.
        rank = {OK: 0, UNKNOWN: 1, DRIFTED: 2}
        if rank[state] > rank[self.state]:
            self.state, self.reason = state, reason
        return self


def api_get(path, key, timeout=LOOKUP_TIMEOUT):
    req = urllib.request.Request(API + path, headers={"xi-api-key": key})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def check(do_tts):
    r = Result()

    if not CONFIG_PATH.exists():
        return r.set(UNKNOWN, f"no config at {CONFIG_PATH}")

    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return r.set(UNKNOWN, f"{CONFIG_PATH} is not valid JSON ({e})")

    el = cfg.get("elevenlabs") or {}
    voice_id = el.get("voice_id") or ""
    fallback = cfg.get("voice") or "(none)"
    r.notes.append(f"config    {CONFIG_PATH}")
    r.notes.append(f"fallback  Kokoro {fallback}")

    # Deliberately DRIFTED, not ok. Whether somebody turned it off on purpose or a
    # bad write did it, the answer to "will he sound like himself" is no. Reporting
    # that as a pass is the silent-Kokoro failure this tool exists to catch.
    if not el.get("enabled"):
        return r.set(DRIFTED, f"ElevenLabs is switched off - every reply will speak "
                              f"in the Kokoro fallback voice ({fallback}), not Marty's")

    if not voice_id:
        return r.set(DRIFTED, "elevenlabs.enabled is true but voice_id is empty")

    if voice_id in KNOWN_DECOYS:
        r.set(DRIFTED, f"configured voice_id {voice_id} is a KNOWN DECOY "
                       f"({KNOWN_DECOYS[voice_id]}) - somebody resolved the voice by name")
    elif voice_id != EXPECTED_VOICE_ID:
        r.notes.append(f"voice_id {voice_id} is not the expected {EXPECTED_VOICE_ID} - "
                       "fine if the voice was deliberately changed, worth a look if not")

    key = os.environ.get("ELEVENLABS_API_KEY", "")
    if not key:
        # UNKNOWN, not DRIFTED. The key is absent from THIS process's environment,
        # which says nothing about the voice and is routinely true for a process
        # launched outside the user's interactive session.
        return r.set(UNKNOWN, "ELEVENLABS_API_KEY is not set in this environment - "
                              "cannot verify the voice from here")

    try:
        v = api_get(f"/voices/{voice_id}", key)
        r.notes.append(f"voice     {voice_id} resolves -> {v.get('name')} ({v.get('category')})")
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            if WELL_FORMED_ID.match(voice_id):
                r.set(DRIFTED, f"voice_id {voice_id} is not in the account library "
                               f"(HTTP {e.code}) - the 2026-09-20 failure exactly: a Voice "
                               "Design preview id never saved to the permanent library. Fix "
                               "with POST /v1/text-to-voice/create-voice-from-preview")
            else:
                r.set(DRIFTED, f"voice_id {voice_id!r} is not shaped like a voice id "
                               f"(expected 20 alphanumeric characters), rejected HTTP {e.code} "
                               "- a bad value written into the config")
        elif e.code == 401:
            r.set(UNKNOWN, "ELEVENLABS_API_KEY was rejected (401) - the key, not the voice")
        else:
            r.set(UNKNOWN, f"lookup of {voice_id} failed: HTTP {e.code} {e.reason}")
        return r
    except Exception as e:
        r.set(UNKNOWN, f"could not reach ElevenLabs: {type(e).__name__} {e}")
        return r

    if do_tts:
        try:
            req = urllib.request.Request(
                f"{API}/text-to-speech/{voice_id}/stream?output_format=mp3_44100_128",
                data=json.dumps({"text": "Voice check passes."}).encode(),
                headers={"xi-api-key": key, "Content-Type": "application/json"},
            )
            audio = urllib.request.urlopen(req, timeout=TTS_TIMEOUT).read()
            if len(audio) < 1000:
                r.set(DRIFTED, f"TTS returned only {len(audio)} bytes - not real audio")
            else:
                r.notes.append(f"tts       real call OK, {len(audio):,} bytes of audio")
        except Exception as e:
            r.set(UNKNOWN, f"TTS call failed: {type(e).__name__} {e}")

    return r


def write_result(r):
    """One small JSON file the dashboard can read. Includes the timestamp so a check
    that silently STOPPED running is as visible as one that failed."""
    try:
        RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(json.dumps({
            "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "state": r.state,
            "reason": r.reason,
        }, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"warn  could not write {RESULT_PATH}: {e}")


def main():
    ap = argparse.ArgumentParser(description="Preflight Marty's voice configuration.")
    ap.add_argument("--tts", action="store_true",
                    help="also make one real short TTS call (spends credits)")
    ap.add_argument("--json", action="store_true",
                    help=f"write {RESULT_PATH.name} for the dashboard to read")
    ap.add_argument("--quiet", action="store_true",
                    help="one line on ok; drifted and unknown always print in full")
    args = ap.parse_args()

    r = check(args.tts)
    if args.json:
        write_result(r)

    # quiet suppresses the detail on a clean pass only. It can never suppress a
    # non-ok state - that is how the old version reported silent Kokoro as a pass.
    if r.state == OK:
        print(f"OK    {r.reason}" if not args.quiet else "OK    voice verified")
        if not args.quiet:
            for n in r.notes:
                print(f"  {n}")
    else:
        print(f"{r.state.upper()}  {r.reason}")
        for n in r.notes:
            print(f"  {n}")

    sys.exit(EXIT[r.state])


if __name__ == "__main__":
    main()
