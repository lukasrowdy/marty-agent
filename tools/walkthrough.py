"""
walkthrough.py - turn a phone video walkthrough into things Marty can read and look at.

Marty cannot watch video. It can read text and look at still images. This tool
converts a video into both: a timestamped transcript, a captions file, a
captioned copy of the video, still frames on a schedule, and contact sheets of
those frames (a grid of stamped stills, one image per dozen frames) so a whole
walkthrough can be inspected in a few image reads.

Run it with the voice line's Python, which already has faster-whisper and the
cached small.en model (no new installs):

    C:/Users/{{WIN_USER}}/my-agent/backtalk/.venv/Scripts/python.exe tools/walkthrough.py "<video>" [--every 8] [--out <dir>]

Outputs, in <out> (default: a folder next to the video named <video-stem>_out):
    transcript.md     timestamped paragraphs, one per spoken segment
    transcript.txt    the plain text, no timestamps
    captions.srt      closed captions, short lines, word-timed
    captioned.mp4     the video with captions burned in (max 1080 px wide)
    frames/f_*.jpg    one still every --every seconds
    frames/s_*.jpg    one still at the start of each spoken segment
    sheets/sheet_*.png contact sheets of the scheduled stills, timestamped
    index.md          what was produced, durations, counts

ffmpeg must be on PATH (it is, via winget). No network needed.
"""

import argparse
import json
import math
import os
import pathlib
import shutil
import subprocess
import sys
import time


def run(cmd, cwd=None, quiet=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=quiet, text=True)
    if r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(cmd)}\n{r.stderr[-2000:] if r.stderr else ''}")
    return r


def probe_duration(path):
    r = run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)])
    return float(json.loads(r.stdout)["format"]["duration"])


def hms(t, srt=False):
    h = int(t // 3600); m = int((t % 3600) // 60); s = t % 60
    if srt:
        return f"{h:02d}:{m:02d}:{int(s):02d},{int(round((s - int(s)) * 1000)):03d}"
    return f"{h:02d}:{m:02d}:{int(s):02d}" if h else f"{m:02d}:{int(s):02d}"


def transcribe(wav, model_name):
    from faster_whisper import WhisperModel
    model = WhisperModel(model_name, device="cpu", compute_type="int8")
    segments, info = model.transcribe(str(wav), word_timestamps=True, vad_filter=True, beam_size=5)
    out = []
    for seg in segments:
        words = [{"w": w.word, "s": w.start, "e": w.end} for w in (seg.words or [])]
        out.append({"start": seg.start, "end": seg.end, "text": seg.text.strip(), "words": words})
    return out, info


def caption_chunks(segments, max_words=8):
    """Short caption lines from word timestamps; falls back to whole segments."""
    chunks = []
    for seg in segments:
        words = seg["words"]
        if not words:
            chunks.append((seg["start"], seg["end"], seg["text"])); continue
        for i in range(0, len(words), max_words):
            grp = words[i:i + max_words]
            chunks.append((grp[0]["s"], grp[-1]["e"], "".join(w["w"] for w in grp).strip()))
    # never let a caption vanish instantly
    fixed = []
    for s, e, t in chunks:
        if e - s < 0.7:
            e = s + 0.7
        fixed.append((s, e, t))
    return fixed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("video")
    ap.add_argument("--every", type=float, default=8.0, help="seconds between scheduled stills")
    ap.add_argument("--out", default=None)
    ap.add_argument("--model", default="small.en")
    ap.add_argument("--no-burn", action="store_true", help="skip the captioned video")
    a = ap.parse_args()

    video = pathlib.Path(a.video).resolve()
    if not video.exists():
        raise SystemExit(f"no such file: {video}")
    out = pathlib.Path(a.out).resolve() if a.out else video.with_name(video.stem + "_out")
    frames = out / "frames"; sheets = out / "sheets"
    for d in (out, frames, sheets):
        d.mkdir(parents=True, exist_ok=True)
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg not on PATH")

    t0 = time.time()
    dur = probe_duration(video)
    print(f"video: {video.name}  duration {hms(dur)}")

    # 1. audio
    wav = out / "audio.wav"
    run(["ffmpeg", "-y", "-i", str(video), "-vn", "-ac", "1", "-ar", "16000", str(wav)])

    # 2. transcript
    print("transcribing with faster-whisper", a.model, "...")
    segs, info = transcribe(wav, a.model)
    print(f"  {len(segs)} segments, language {info.language} ({info.language_probability:.2f})")

    with open(out / "transcript.md", "w", encoding="utf-8") as f:
        f.write(f"# Transcript: {video.name}\n\nDuration {hms(dur)}. Model faster-whisper {a.model}. "
                f"Speakers are not labeled; Whisper does not separate voices.\n\n")
        for s in segs:
            f.write(f"**[{hms(s['start'])}]** {s['text']}\n\n")
    with open(out / "transcript.txt", "w", encoding="utf-8") as f:
        f.write(" ".join(s["text"] for s in segs) + "\n")

    # 3. captions
    chunks = caption_chunks(segs)
    with open(out / "captions.srt", "w", encoding="utf-8") as f:
        for i, (s, e, t) in enumerate(chunks, 1):
            f.write(f"{i}\n{hms(s, True)} --> {hms(e, True)}\n{t}\n\n")

    # 4. captioned video (relative srt path with cwd=out avoids Windows path escaping)
    if not a.no_burn:
        print("burning captions ...")
        run(["ffmpeg", "-y", "-i", str(video),
             "-vf", "scale='min(1080,iw)':-2,subtitles=captions.srt:force_style='FontName=Segoe UI,FontSize=20,Bold=1,Outline=2,MarginV=40'",
             "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k",
             "captioned.mp4"], cwd=out)

    # 5. stills: scheduled, timestamp-stamped
    print("extracting stills ...")
    for f in frames.glob("*.jpg"):
        f.unlink()
    stamp = "drawtext=text='%{pts\\:hms}':fontfile='C\\:/Windows/Fonts/consolab.ttf':fontsize=28:fontcolor=white:box=1:boxcolor=black@0.6:boxborderw=8:x=12:y=12"  # secret-scan: allow [export-reviewed]
    run(["ffmpeg", "-y", "-i", str(video), "-vf", f"fps=1/{a.every},scale='min(720,iw)':-2,{stamp}", "-q:v", "3",
         str(frames / "f_%04d.jpg")])
    # per-segment stills at segment starts
    for i, s in enumerate(segs, 1):
        run(["ffmpeg", "-y", "-ss", f"{s['start']:.2f}", "-i", str(video), "-frames:v", "1",
             "-vf", "scale='min(720,iw)':-2", "-q:v", "3", str(frames / f"s_{i:03d}_{hms(s['start']).replace(':', '')}.jpg")])

    # 6. contact sheets of the scheduled stills, 12 per sheet, stamped.
    #    Portrait video gets 4 columns of narrow tiles, landscape 3 columns, so
    #    a sheet stays roughly square and readable in one image view.
    sched = sorted(frames.glob("f_*.jpg"))
    for f in sheets.glob("*.png"):
        f.unlink()
    pr = run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height",
              "-of", "json", str(video)])
    st = json.loads(pr.stdout)["streams"][0]
    portrait = st.get("height", 0) > st.get("width", 0)
    cols, tile_w = (4, 270) if portrait else (3, 360)
    per = 12
    n_sheets = max(1, math.ceil(len(sched) / per))
    for k in range(n_sheets):
        batch = sched[k * per:(k + 1) * per]
        if not batch:
            continue
        rows = math.ceil(len(batch) / cols)
        lst = out / f"_sheet_{k+1}.txt"
        with open(lst, "w", encoding="utf-8") as f:
            for p in batch:
                f.write(f"file '{p.as_posix()}'\n")
        run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(lst),
             "-vf", f"scale={tile_w}:-2,tile={cols}x{rows}:padding=6:margin=6:color=0x222222", "-frames:v", "1",
             str(sheets / f"sheet_{k+1:02d}.png")])
        lst.unlink()

    # 7. index
    with open(out / "index.md", "w", encoding="utf-8") as f:
        f.write(f"# Walkthrough outputs for {video.name}\n\n")
        f.write(f"- Duration: {hms(dur)}\n- Segments: {len(segs)}\n- Captions: {len(chunks)} lines\n")
        f.write(f"- Scheduled stills: {len(sched)} (every {a.every:g} s) in `frames/f_*.jpg`\n")
        f.write(f"- Segment stills: {len(segs)} in `frames/s_*.jpg`\n- Contact sheets: {n_sheets} in `sheets/`\n")
        f.write(f"- Captioned video: {'captioned.mp4' if not a.no_burn else 'skipped'}\n")
        f.write(f"- Produced {time.strftime('%Y-%m-%d %H:%M')} in {time.time()-t0:.0f} s\n")
    wav.unlink(missing_ok=True)
    print(f"done in {time.time()-t0:.0f} s -> {out}")


if __name__ == "__main__":
    main()
