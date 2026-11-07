"""
media.py - Marty's local media tools: look at an image, pull one frame out of a video and
look at it, transcribe the speech in audio or video. Everything runs on this PC: ffmpeg
for the pixels and the audio, faster-whisper (the backtalk venv, cached small.en model)
for the words, and a local vision model on Ollama for the looking - when one is
configured. Today none is (vision_model is null in tools/marty_tools.scope.json), so
look_at and see_video_frame answer with NO_VISION before anything runs: no ffmpeg, no
Ollama call, and never a cloud call in its place.

    py tools/media.py transcribe <video-or-audio> [--out <file.md>] [--model small.en]
    py tools/media.py selftest

Used by tools/marty_tools.py (see_image, see_video_frame, transcribe_media in the
dashboard's Claude lane, which checks the path against its scope first) and by
dashboard/intake.py (the Transcribe button on an upload, which runs the CLI with --out).

Audit finding 3 (2026-09-22) is why the file handling looks the way it does:
  - every job works in its own fresh directory under WORK (my-agent/tmp/media), made by
    mkdtemp, and removed afterwards. The only file ever written beside a source is an
    upload's transcript, which intake asks for inside my-agent/uploads (an OUT_ROOT), so a
    source folder (a read-only mount, a Drive folder, someone's Downloads) is byte-for-byte
    unchanged after any operation here;
  - the CLI authorizes the source (tools/marty_tools.scope.json) and the output path
    (inside OUT_ROOTS) BEFORE any subprocess runs, and refuses otherwise;
  - the transcript is written to a temporary name beside its destination and renamed into
    place, so a crash can never leave a half-written transcript at the final path.
Every CLI call is one line in my-agent/logs/marty-tools.log (tools/marty_tools.py log()).

Transcript format (dashboard/intake.py split_transcript parses it):
    # Transcript: <name>
    <blank>
    Model faster-whisper <model>. Language <lang> (<p>). Speakers are not labeled; ...
    <blank>
    **[mm:ss]** <text>
    <blank>
"""

import argparse
import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
sys.path.insert(0, str(HERE))
import marty_tools  # noqa: E402  (scope and log; it imports this module only lazily)

WORK = AGENT / "tmp" / "media"                  # per-job temp dirs; nothing here outlives its job
TRANSCRIPTS = WORK / "transcripts"              # the CLI's default output
OUT_ROOTS = (AGENT / "uploads", WORK)           # the only places the CLI may write a transcript
VENV_PY = AGENT / "backtalk" / ".venv" / "Scripts" / "python.exe"
OLLAMA = "http://127.0.0.1:11434"
VISION_MODEL = None                             # none installed; marty_tools passes vision_model from its scope file
NO_VISION = ("ERROR: No local vision model is installed, so I can't describe images here. Ask in the "
             "terminal session, or install a vision model and set vision_model in "
             "tools/marty_tools.scope.json.")
MAX_TOOL_CHARS = 6000

WHISPER_ROWS = (
    "import sys, json\n"
    "from faster_whisper import WhisperModel\n"
    "m = WhisperModel(sys.argv[2], device='cpu', compute_type='int8')\n"
    "segs, info = m.transcribe(sys.argv[1], vad_filter=True, beam_size=5)\n"
    "rows = [{'s': s.start, 'e': s.end, 't': s.text.strip()} for s in segs]\n"
    "print(json.dumps({'lang': info.language, 'p': info.language_probability, 'rows': rows}))\n"
)


# ---------------------------------------------------------------- job directories

def job_temp_dir(prefix):
    """A fresh, unique directory for one job's throwaway media, always under WORK - never
    beside a source file. mkdtemp is atomic, so two concurrent jobs (or a name collision
    with something already there) can't stomp each other. The caller removes it
    (shutil.rmtree) when the job is done.

    Before this, looking at an image and transcribing wrote a same-named sibling next to
    the original with ffmpeg -y (overwrite) and then deleted it - if the source lives in a
    read-only mount, or a same-named temp file already existed there for an unrelated
    reason, that was an unauthorized write and a destroyed file. Audit finding 3."""
    WORK.mkdir(parents=True, exist_ok=True)
    return pathlib.Path(tempfile.mkdtemp(prefix=f"{prefix}-", dir=WORK))


def out_authorized(path, scope):
    """True iff an output path resolves inside one of OUT_ROOTS and matches none of the
    scope's denied patterns. Checked before anything runs."""
    return marty_tools.authorized(path, {"allowed_roots": [str(r) for r in OUT_ROOTS],
                                         "denied_patterns": (scope or {}).get("denied_patterns") or []})


# ---------------------------------------------------------------- looking

def _ollama_chat(payload, timeout=900):
    """The one network call in this module: a vision request to the local Ollama server.
    Swapped for a stub in the selftest."""
    req = urllib.request.Request(f"{OLLAMA}/api/chat", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def look_at(path, question, model=None):
    """Make a separate vision call and return WORDS. A tool result is text, so the tool
    does the looking and hands back a description.

    Two measured rules from benchmarking this box:
      - Downscale to 1024px wide first. Full-size costs 3-4x the time for no gain.
      - One frame per call, never a contact sheet. On a 4x3 sheet a local VLM emitted the
        same caption twelve times - sheets are a human artifact.
    """
    model = model or VISION_MODEL
    if not model:
        return NO_VISION          # before any subprocess or model call; there is no fallback
    path = pathlib.Path(path)
    job = job_temp_dir("see")
    small = job / (path.stem + ".1024.jpg")
    try:
        r = subprocess.run(["ffmpeg", "-y", "-i", str(path), "-vf", "scale=1024:-1", str(small)],
                           capture_output=True, text=True)
        src = small if small.exists() and r.returncode == 0 else path
        b64 = base64.b64encode(src.read_bytes()).decode()
        out = _ollama_chat({"model": model, "stream": False, "think": False,
                            "messages": [{"role": "user", "content": question, "images": [b64]}]})
        return (out.get("message", {}).get("content") or "").strip() or "(no description returned)"
    except urllib.error.HTTPError as e:
        return f"ERROR: vision call failed ({e.code}). Does '{model}' advertise a vision capability?"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"
    finally:
        shutil.rmtree(job, ignore_errors=True)


def see_video_frame(path, seconds, question, model=None):
    """One frame out of a video, described. Pairs with transcribe_media: the transcript is
    what was said, the frame is what was on screen."""
    if not (model or VISION_MODEL):
        return NO_VISION          # checked before the frame grab, so nothing runs for nothing
    path = pathlib.Path(path)
    if not shutil.which("ffmpeg"):
        return "ERROR: ffmpeg not on PATH"
    job = job_temp_dir("frame")
    frame = job / f"{path.stem}.f{int(seconds)}.jpg"
    try:
        r = subprocess.run(["ffmpeg", "-y", "-ss", str(seconds), "-i", str(path),
                            "-frames:v", "1", "-vf", "scale=1024:-1", str(frame)],
                           capture_output=True, text=True)
        if r.returncode != 0 or not frame.exists():
            return (f"ERROR: could not grab a frame at {seconds}s. Is the file a video, "
                    f"and is it longer than {seconds}s?")
        return f"[frame at {seconds:g}s of {path.name}]\n" + look_at(frame, question, model)
    finally:
        shutil.rmtree(job, ignore_errors=True)


# ---------------------------------------------------------------- listening

def transcribe_media(path):
    """Speech out of audio or video, as text a model can actually read (the tool form:
    timestamps and text, capped at MAX_TOOL_CHARS).

    A model cannot watch a video - but a video's speech is the bulk of its meaning, and
    faster-whisper plus the cached small.en model is already on this machine in the
    backtalk venv."""
    path = pathlib.Path(path)
    if not VENV_PY.exists():
        return f"ERROR: the backtalk venv is missing ({VENV_PY}); that is where faster-whisper lives."
    if not shutil.which("ffmpeg"):
        return "ERROR: ffmpeg not on PATH"
    job = job_temp_dir("transcribe")
    wav = job / (path.stem + ".wav")
    try:
        r = subprocess.run(["ffmpeg", "-y", "-i", str(path), "-vn", "-ac", "1",
                            "-ar", "16000", str(wav)], capture_output=True, text=True)
        if r.returncode != 0 or not wav.exists():
            return f"ERROR: could not extract audio. Does the file have an audio track?\n{(r.stderr or '')[-400:]}"
        r = subprocess.run([str(VENV_PY), "-c", WHISPER_ROWS, str(wav), "small.en"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return f"ERROR: transcription failed:\n{(r.stderr or '')[-600:]}"
        rows = json.loads(r.stdout.strip().splitlines()[-1])["rows"]
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"
    finally:
        shutil.rmtree(job, ignore_errors=True)
    if not rows:
        return "No speech found in that file. It may be silent, music-only, or have no audio track."
    out = [f"Transcript of {path.name} ({len(rows)} segments). Speakers are not labeled."]
    for row in rows:
        mm, ss = divmod(int(row["s"]), 60)
        out.append(f"[{mm:02d}:{ss:02d}] {row['t']}")
    return "\n".join(out)[:MAX_TOOL_CHARS]


def cmd_transcribe(a, scope):
    """The CLI: a whole transcript to a markdown file. Raises SystemExit on a refusal or a
    failure, prints '<n> segments -> <path>' on success."""
    try:
        p = marty_tools.check(a.path, scope)
    except marty_tools.Refused as e:
        raise SystemExit(str(e))
    if not p.is_file():
        raise SystemExit(f"not a file: {p}")
    # Output authorization before anything runs - an --out outside the authorized work
    # dirs must be refused up front, not discovered after ffmpeg has already run.
    out = pathlib.Path(a.out).resolve() if a.out else (TRANSCRIPTS / (p.stem + "_transcript.md")).resolve()
    if not out_authorized(out, scope):
        marty_tools.log("scope", out.as_posix(), "DENIED", "transcript output not inside an authorized work dir")
        raise SystemExit(
            f"refused: {out}\n"
            f"  not authorized: a transcript may only be written under "
            + ", ".join(r.as_posix() for r in OUT_ROOTS) + "."
        )
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg not on PATH")
    if not VENV_PY.exists():
        raise SystemExit(f"the backtalk venv is missing ({VENV_PY}); that is where faster-whisper lives.")
    job = job_temp_dir("transcribe-cli")
    wav = job / (p.stem + ".wav")
    try:
        r = subprocess.run(["ffmpeg", "-y", "-i", str(p), "-vn", "-ac", "1", "-ar", "16000", str(wav)],
                           capture_output=True, text=True)
        if r.returncode != 0 or not wav.exists():
            raise SystemExit(f"could not extract audio. Does the file have an audio track?\n{(r.stderr or '')[-1500:]}")
        r = subprocess.run([str(VENV_PY), "-c", WHISPER_ROWS, str(wav), a.model],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        shutil.rmtree(job, ignore_errors=True)
    if r.returncode != 0:
        marty_tools.log("transcribe", p.as_posix(), "ERROR", f"whisper exit {r.returncode}")
        raise SystemExit(f"transcribe failed:\n{(r.stderr or '')[-2000:]}")
    data = json.loads(r.stdout.strip().splitlines()[-1])
    lines = [f"# Transcript: {p.name}", "",
             f"Model faster-whisper {a.model}. Language {data['lang']} ({data['p']:.2f}). "
             "Speakers are not labeled; Whisper does not separate voices.", ""]
    for row in data["rows"]:
        mm, ss = divmod(int(row["s"]), 60)
        lines.append(f"**[{mm:02d}:{ss:02d}]** {row['t']}")
        lines.append("")
    # Atomic promotion: write beside the real destination, then rename, so a crash
    # mid-write can never leave a half-written transcript at the final path.
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = out.with_name(out.name + f".partial-{os.getpid()}")
    try:
        tmp_out.write_text("\n".join(lines), encoding="utf-8")
        tmp_out.replace(out)
    finally:
        if tmp_out.exists():
            tmp_out.unlink()
    marty_tools.log("transcribe", p.as_posix(), "OK", f"{len(data['rows'])} segments -> {out.as_posix()}")
    print(f"{len(data['rows'])} segments -> {out}")


# ---------------------------------------------------------------- selftest (no network, no model)

def _hash_tree(root):
    """sha256 of every file under root, keyed by relative path - proves a folder is
    byte-for-byte unchanged before/after a media operation. Audit finding 3."""
    import hashlib
    return {f.relative_to(root).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted(root.rglob("*")) if f.is_file()}


def selftest():
    """Finding 3 regression: inspecting media must never write into or modify the source
    folder, an unauthorized output path (or source) must be refused before any subprocess
    runs, a transcript lands atomically in the format intake.py parses, and with no vision
    model configured the looking tools refuse before anything runs. The vision call is
    stubbed and whisper is never started on real audio: no model runs here. ffmpeg may
    or may not be on PATH; the checks hold either way."""
    import re
    import types
    global WORK, TRANSCRIPTS, OUT_ROOTS, VENV_PY, _ollama_chat
    fails = []

    def ok(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    saved = (WORK, TRANSCRIPTS, OUT_ROOTS, VENV_PY, _ollama_chat, marty_tools.LOG, subprocess.run)
    vision_calls = []
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        agent = td / "my-agent"
        source = td / "source"; source.mkdir()
        (source / "clip.mp4").write_bytes(b"not a real video, just bytes")
        (source / "photo.jpg").write_bytes(b"not a real jpg, just bytes")
        uploads = agent / "uploads"; uploads.mkdir(parents=True)
        WORK = agent / "tmp" / "media"
        TRANSCRIPTS = WORK / "transcripts"
        OUT_ROOTS = (uploads, WORK)
        marty_tools.LOG = td / "logs" / "marty-tools.log"
        fake_venv = td / "venv-python.exe"; fake_venv.write_bytes(b"")
        VENV_PY = fake_venv
        _ollama_chat = lambda payload, timeout=900: (vision_calls.append(payload["model"])
                                                     or {"message": {"content": "a stub description"}})
        scope = {"allowed_roots": [str(source), str(uploads)], "denied_patterns": ["*password*"]}
        try:
            print("job_temp_dir")
            j1, j2 = job_temp_dir("t"), job_temp_dir("t")
            ok(j1 != j2 and j1.is_dir() and j2.is_dir(), "two calls give two distinct, existing directories")
            ok(j1.parent == WORK and not str(j1).startswith(str(source)),
               "job dir lives under the media work dir, never beside a source file")
            shutil.rmtree(j1, ignore_errors=True); shutil.rmtree(j2, ignore_errors=True)

            print("see_image never touches the source folder")
            before = _hash_tree(source)
            said = look_at(source / "photo.jpg", "describe it", "test-vision")
            ok(_hash_tree(source) == before, "source folder byte-for-byte unchanged after see_image")
            ok(sorted(p.name for p in source.iterdir()) == ["clip.mp4", "photo.jpg"], "nothing new beside the source image")
            ok(said == "a stub description" and vision_calls == ["test-vision"], "the (stubbed) vision call got the configured model")
            ok(not any(WORK.glob("see-*")), "the job dir is gone afterwards")

            print("no vision model configured: an honest error, and nothing runs")
            ran = []
            real_run = subprocess.run
            subprocess.run = lambda cmd, *a, **k: ran.append(cmd) or types.SimpleNamespace(returncode=0, stdout="", stderr="")
            vision_calls.clear()
            try:
                jobs_before = sorted(p.name for p in WORK.iterdir()) if WORK.exists() else []
                r1 = look_at(source / "photo.jpg", "describe it")
                r2 = look_at(source / "photo.jpg", "describe it", "")
                r3 = see_video_frame(source / "clip.mp4", 2, "what is on screen")
                r4 = see_video_frame(source / "clip.mp4", 2, "what is on screen", None)
            finally:
                subprocess.run = real_run
            ok(r1 == r2 == r3 == r4 == NO_VISION and NO_VISION.startswith("ERROR: No local vision model is installed"),
               "see_image and see_video_frame both say no vision model is installed")
            ok("vision_model in tools/marty_tools.scope.json" in NO_VISION and "terminal session" in NO_VISION,
               "and say what to do about it")
            ok(not ran and not vision_calls, "no ffmpeg, no Ollama call, no fallback of any kind")
            ok((sorted(p.name for p in WORK.iterdir()) if WORK.exists() else []) == jobs_before,
               "no job dir was even created")

            print("see_video_frame and transcribe_media never touch the source folder")
            before = _hash_tree(source)
            see_video_frame(source / "clip.mp4", 1, "what is on screen", "test-vision")
            transcribe_media(source / "clip.mp4")      # fake bytes: ffmpeg refuses, whisper never starts
            ok(_hash_tree(source) == before, "source folder byte-for-byte unchanged")
            ok(sorted(p.name for p in source.iterdir()) == ["clip.mp4", "photo.jpg"], "no wav or frame sibling left behind")

            print("the CLI refuses before any subprocess runs")
            spawned = []

            def recorder(cmd, *args, **kw):
                spawned.append(cmd)
                return types.SimpleNamespace(returncode=1, stdout="", stderr="stub")
            subprocess.run = recorder
            a = types.SimpleNamespace(path=str(source / "clip.mp4"), out=str(td / "outside" / "t.md"), model="small.en")
            try:
                cmd_transcribe(a, scope)
                refused = False
            except SystemExit as e:
                refused = "not authorized" in str(e)
            ok(refused and not spawned, "an --out outside the work dirs is refused, nothing spawned")
            ok(not (td / "outside").exists(), "the rejected output directory was never created")
            a = types.SimpleNamespace(path=str(source / "clip.mp4"), out=str(uploads / "my-password.md"), model="small.en")
            try:
                cmd_transcribe(a, scope)
                refused = False
            except SystemExit as e:
                refused = "not authorized" in str(e)
            ok(refused and not spawned, "an --out matching a denied pattern is refused too")
            (td / "elsewhere").mkdir()
            (td / "elsewhere" / "v.mp4").write_bytes(b"x")
            a = types.SimpleNamespace(path=str(td / "elsewhere" / "v.mp4"), out=str(uploads / "v_transcript.md"), model="small.en")
            try:
                cmd_transcribe(a, scope)
                refused = False
            except SystemExit as e:
                refused = "not authorized" in str(e)
            ok(refused and not spawned, "a source outside the scope is refused, nothing spawned")
            logged = marty_tools.LOG.read_text(encoding="utf-8") if marty_tools.LOG.exists() else ""
            ok(logged.count("\tscope\tDENIED\t") == 3, "each refusal is one DENIED line in the tools log")

            print("the default output lands in the work dir, not beside the source")
            a = types.SimpleNamespace(path=str(source / "clip.mp4"), out=None, model="small.en")
            try:
                cmd_transcribe(a, scope)       # the stubbed ffmpeg "fails", so it stops at the audio step
            except SystemExit:
                pass
            ok(not list(source.glob("*_transcript.md")), "no transcript written beside the source video")
            ok(not any(WORK.glob("transcribe-cli-*")), "the job dir is removed even when the job fails")

            print("a successful transcript is atomic and in the format intake.py parses")

            def fake_run(cmd, *args, **kw):
                if cmd[0] == "ffmpeg":
                    pathlib.Path(cmd[-1]).write_bytes(b"RIFF fake wav")
                    return types.SimpleNamespace(returncode=0, stdout="", stderr="")
                return types.SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(
                    {"lang": "en", "p": 0.99, "rows": [{"s": 1.2, "e": 2.0, "t": "hello there"},
                                                       {"s": 65.0, "e": 66.0, "t": "second line"}]}))
            subprocess.run = fake_run
            before = _hash_tree(source)
            out = uploads / "clip_transcript.md"
            cmd_transcribe(types.SimpleNamespace(path=str(source / "clip.mp4"), out=str(out), model="small.en"), scope)
            text = out.read_text(encoding="utf-8") if out.exists() else ""
            seg = re.compile(r"^\*\*\[(\d+:\d{2})\]\*\*")
            stamps = [seg.match(ln).group(1) for ln in text.splitlines() if seg.match(ln)]
            ok(text.startswith("# Transcript: clip.mp4\n\nModel faster-whisper small.en. Language en (0.99).")
               and stamps == ["00:01", "01:05"], f"header and **[mm:ss]** segments ({stamps})")
            ok(not list(uploads.glob("*.partial-*")), "no partial file left beside the transcript")
            ok(_hash_tree(source) == before, "source folder still byte-for-byte unchanged")
            cmd_transcribe(types.SimpleNamespace(path=str(source / "clip.mp4"), out=None, model="small.en"), scope)
            ok((TRANSCRIPTS / "clip_transcript.md").is_file(), "the default output is <work>/transcripts/<stem>_transcript.md")
            ok(" -> " in marty_tools.LOG.read_text(encoding="utf-8").splitlines()[-1]
               and "\ttranscribe\tOK\t" in marty_tools.LOG.read_text(encoding="utf-8"), "a success is logged OK")
        finally:
            WORK, TRANSCRIPTS, OUT_ROOTS, VENV_PY, _ollama_chat, marty_tools.LOG, subprocess.run = saved

    print()
    if fails:
        print(f"{len(fails)} FAILED:"); [print("  - " + f) for f in fails]
        return 1
    print("all checks passed")
    return 0


# ---------------------------------------------------------------- cli

def main():
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Marty's local media tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("transcribe", help="speech to a markdown transcript")
    p.add_argument("path"); p.add_argument("--out"); p.add_argument("--model", default="small.en")
    sub.add_parser("selftest", help="no network, no model; proves finding-3 media isolation")
    a = ap.parse_args()
    if a.cmd == "selftest":
        raise SystemExit(selftest())
    cmd_transcribe(a, marty_tools.load_scope())


if __name__ == "__main__":
    main()
