"""
avatar.py - stylized avatar generation, gated on a consent roster.

Lukas's ask: absurdly muscled, stretchy, cartoon-physics avatars with stylized
voices, for family entertainment content. All of that is fine. The one thing that
needs a control is WHOSE likeness goes in.

The boundary here is consent, not identity. "Self only" was the original limit and
it is the wrong one - it would block family members who agreed to take part. So
instead: a named roster, recorded with who consented and when, enforced in Python
before any likeness operation runs. Same shape as recon.scope.json and
marty_tools.scope.json, for the same reason: a model will cheerfully accept a name
it was handed, and a file will not.

    py tools/avatar.py roster                       who is on it, and on what basis
    py tools/avatar.py add <name> --consent "..."   add someone, recording the basis
    py tools/avatar.py train <name> <image...>      train a Soul Character (Higgsfield)
    py tools/avatar.py voice <name> --style "..."   DESIGN a stylized voice (never a clone)
    py tools/avatar.py clip <name> --prompt "..."   generate a stylized clip
    py tools/avatar.py cost <kind>                  free estimate before spending credits

Two rules baked in rather than left to judgement:

  1. Voices are DESIGNED, never CLONED. ElevenLabs Voice Design invents a voice from
     a text description - a cartoon strongman rumble - which is what "stylized voice"
     actually means here. Cloning someone's real voice is a different capability with
     a different risk profile, and this tool does not do it. See the RSMo 407.020 item
     in Active Priorities for why that line is worth keeping bright.
  2. Every output is stylized by construction. The prompt builder always carries
     cartoon/exaggerated styling, because the stated goal is content that is obviously
     not real footage. This tool is not a route to photoreal video of a person.

Higgsfield spend rule (from the Job note): run `cost` first, get Lukas's yes, then run.
"""

import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
ROSTER_FILE = HERE / "avatar.scope.json"
OUT = AGENT / "private" / "avatar"           # designed voice takes: on no sync path, not in the NAS job
LOG = AGENT / "logs" / "marty-tools.log"     # the same audit log as Marty's other tools"

DEFAULT_ROSTER = {
    "_comment": "Consent roster for likeness generation. A name not on this list is refused before any API call. Add with 'avatar.py add', which forces a consent basis to be recorded.",
    "_rules": [
        "Voices are DESIGNED from a description, never cloned from a real recording.",
        "Every generation is styled as obviously-unreal cartoon content.",
        "Minors are on here by parental consent, recorded as such. That consent is Lukas's to give for his own children and nobody else's.",
        "Consent is withdrawable. 'avatar.py revoke <name>' removes someone immediately; nobody has to justify changing their mind.",
        "IF ANYTHING IS PUBLISHED: synthetic footage or voice of a real person needs an in-video disclosure. Lukas's own UGC research (2026-09-20) found AI captions and editing are exempt, but synthetic footage and synthetic voice are NOT, under FTC 16 CFR 255. The roster governs whose likeness may be used; it does not satisfy the disclosure requirement.",
        "The roster controls WHOSE face, not WHAT they are made to appear to do. Consent to a cartoon is not consent to anything the prompt might say.",
    ],
    "people": [
        {"name": "lukas", "consent": "self", "recorded": "2026-09-21", "minor": False},
    ],
}

STYLE_FLOOR = ("highly stylized 3D cartoon, exaggerated proportions, obviously not "
               "photoreal, bright saturated cartoon lighting, comedic")


def load_roster():
    if ROSTER_FILE.exists():
        return json.loads(ROSTER_FILE.read_text(encoding="utf-8"))
    ROSTER_FILE.write_text(json.dumps(DEFAULT_ROSTER, indent=2), encoding="utf-8")
    return json.loads(json.dumps(DEFAULT_ROSTER))


def log(action, subject, verdict, note=""):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{stamp}\tavatar:{action}\t{verdict}\t{subject}" + (f"\t{note}" if note else "") + "\n")


def check_subject(name, roster):
    key = name.strip().lower()
    for p in roster.get("people", []):
        if p["name"].lower() == key:
            return p
    log("scope", key, "DENIED", "not on consent roster")
    raise SystemExit(
        f"refused: '{name}' is not on the consent roster.\n"
        f"  roster: {ROSTER_FILE}\n"
        f"  This gate exists so a likeness is never generated for someone who has not\n"
        f"  agreed to it. If they have agreed, record it:\n"
        f"    py tools/avatar.py add {key} --consent \"how and when they agreed\"\n"
        f"  Marty will not add a name on the model's say-so."
    )


def hf(args, check=True):
    exe = shutil.which("higgsfield")
    if not exe:
        # the app's shells inherit a stale PATH until it is restarted; look directly
        cand = pathlib.Path(os.environ.get("APPDATA", "")) / "npm" / "higgsfield.cmd"
        exe = str(cand) if cand.exists() else None
    if not exe:
        raise SystemExit("higgsfield CLI not found. Restart the Claude app (stale PATH) "
                         "or check `npm ls -g @higgsfield/cli`.")
    r = subprocess.run([exe] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        raise SystemExit(f"higgsfield failed ({r.returncode}):\n{(r.stderr or r.stdout)[-1500:]}")
    return (r.stdout or "") + (r.stderr or "")


def cmd_roster(a, roster):
    print("Likeness generation is refused for anyone not listed here.\n")
    for p in roster.get("people", []):
        tag = " (minor, parental consent)" if p.get("minor") else ""
        print(f"  {p['name']:<12} {p['consent']}{tag}   recorded {p.get('recorded','?')}")
    print("\nrules:")
    for r in roster.get("_rules", []):
        print(f"  - {r}")
    print(f"\nroster file: {ROSTER_FILE}")


def cmd_add(a, roster):
    key = a.name.strip().lower()
    if any(p["name"].lower() == key for p in roster.get("people", [])):
        raise SystemExit(f"{key} is already on the roster.")
    roster.setdefault("people", []).append({
        "name": key, "consent": a.consent,
        "recorded": datetime.date.today().isoformat(), "minor": a.minor,
    })
    ROSTER_FILE.write_text(json.dumps(roster, indent=2), encoding="utf-8")
    log("add", key, "ADDED", a.consent)
    print(f"added {key}\n  consent basis: {a.consent}" + ("\n  recorded as a minor (parental consent)" if a.minor else ""))


def cmd_revoke(a, roster):
    """Consent withdrawn. No justification required and none is recorded - asking
    someone to explain why they changed their mind is its own kind of pressure."""
    key = a.name.strip().lower()
    before = len(roster.get("people", []))
    roster["people"] = [p for p in roster.get("people", []) if p["name"].lower() != key]
    if len(roster["people"]) == before:
        raise SystemExit(f"{key} is not on the roster.")
    roster.setdefault("_revoked", []).append(
        {"name": key, "revoked": datetime.date.today().isoformat()})
    ROSTER_FILE.write_text(json.dumps(roster, indent=2), encoding="utf-8")
    log("revoke", key, "REVOKED")
    print(f"removed {key} from the roster. Further likeness generation for them is refused.")
    print("Note: this stops NEW generation. Anything already produced or published is a"
          "\nseparate cleanup that this tool cannot do for you.")


def cmd_cost(a, roster):
    print(hf(["generate", "cost", "--model", a.model], check=False))


def cmd_train(a, roster):
    p = check_subject(a.name, roster)
    for img in a.images:
        if not pathlib.Path(img).is_file():
            raise SystemExit(f"no such image: {img}")
    log("train", p["name"], "OK", f"{len(a.images)} images")
    print(f"# consent on file for {p['name']}: {p['consent']} (recorded {p.get('recorded')})",
          file=sys.stderr)
    print("# Training a Soul Character. This is a one-time cost and returns a reference id.",
          file=sys.stderr)
    args = ["soul", "train", "--name", f"avatar-{p['name']}"]
    for img in a.images:
        args += ["--image", str(pathlib.Path(img).resolve())]
    print(hf(args))


def cmd_voice(a, roster):
    p = check_subject(a.name, roster)
    OUT.mkdir(parents=True, exist_ok=True)
    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        raise SystemExit("ELEVENLABS_API_KEY is not set in this shell's environment.")
    import urllib.request
    # Voice Design INVENTS a voice from a description. It takes no audio sample and
    # cannot reproduce a real person's voice. That is the point.
    body = json.dumps({
        "voice_description": f"{a.style}. Exaggerated cartoon character voice, comedic, clearly not a real person.",
        "text": a.text,
    }).encode()
    req = urllib.request.Request(
        "https://api.elevenlabs.io/v1/text-to-voice/design",
        data=body, headers={"xi-api-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read().decode())
    except Exception as e:
        raise SystemExit(f"Voice Design call failed: {e}")
    previews = data.get("previews", [])
    log("voice", p["name"], "OK", f"{len(previews)} designed previews")
    import base64
    for i, pv in enumerate(previews, 1):
        audio = pv.get("audio_base_64") or pv.get("audio_base64")
        if not audio:
            continue
        dest = OUT / f"voice-{p['name']}-take{i}.mp3"
        dest.write_bytes(base64.b64decode(audio))
        print(f"  {dest}")
    print(f"\n{len(previews)} designed takes. None of these is a clone of anyone's real voice.")
    print("Pick one, then it has to be SAVED to the permanent voice library before it will")
    print("work in backtalk - a raw preview id 404s. That trap already cost a session once.")


def cmd_clip(a, roster):
    p = check_subject(a.name, roster)
    log("clip", p["name"], "OK", a.prompt[:100])
    prompt = f"{a.prompt}. {STYLE_FLOOR}"
    print(f"# consent on file for {p['name']}: {p['consent']}", file=sys.stderr)
    print(f"# styling floor applied automatically: {STYLE_FLOOR}", file=sys.stderr)
    print("# run `avatar.py cost` first and get Lukas's yes before spending credits.",
          file=sys.stderr)
    args = ["generate", "--model", a.model, "--prompt", prompt]
    if a.soul_id:
        args += ["--soul-id", a.soul_id]
    print(hf(args))


def main():
    ap = argparse.ArgumentParser(description="Stylized avatar generation, consent-gated.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("roster").set_defaults(fn=cmd_roster)

    p = sub.add_parser("add"); p.add_argument("name")
    p.add_argument("--consent", required=True, help="how and when they agreed")
    p.add_argument("--minor", action="store_true", help="record as parental consent")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("revoke", help="withdraw consent; no reason required")
    p.add_argument("name"); p.set_defaults(fn=cmd_revoke)

    p = sub.add_parser("cost"); p.add_argument("--model", default="seedance_2_5")
    p.set_defaults(fn=cmd_cost)

    p = sub.add_parser("train"); p.add_argument("name"); p.add_argument("images", nargs="+")
    p.set_defaults(fn=cmd_train)

    p = sub.add_parser("voice"); p.add_argument("name")
    p.add_argument("--style", required=True, help="e.g. 'booming cartoon strongman, deep and silly'")
    p.add_argument("--text", default="Look at these muscles! I can stretch my arms across the whole room!")
    p.set_defaults(fn=cmd_voice)

    p = sub.add_parser("clip"); p.add_argument("name")
    p.add_argument("--prompt", required=True); p.add_argument("--soul-id")
    p.add_argument("--model", default="seedance_2_5")
    p.set_defaults(fn=cmd_clip)

    a = ap.parse_args()
    a.fn(a, load_roster())


if __name__ == "__main__":
    main()
