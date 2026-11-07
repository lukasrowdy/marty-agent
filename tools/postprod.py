"""
postprod.py - measured post-production: grade, mix, and finish a clip.

The plan this was built from is a good one, but it is written for DaVinci Resolve,
which is not installed on this machine - and more importantly it says things like
"adjust Lift, Gamma and Gain to match the histogram" without ever saying what the
histogram IS. Every number in it is a rule of thumb applied by eye.

This does the opposite. It MEASURES the footage first, then applies corrections
derived from that measurement, and prints both so nothing is a guess:

    py tools/postprod.py analyze <file>     what the footage actually is
    py tools/postprod.py grade   <file>     colour, from the measurement
    py tools/postprod.py audio   <file>     dialogue chain + loudness normalise
    py tools/postprod.py finish  <file>     both, hardware encoded
    py tools/postprod.py cuts    <file>     detect scene changes (pacing)

Everything runs on ffmpeg, which is already here, and encodes with h264_amf on the
Radeon 780M - measured at about 13.6x realtime at 1080p versus software x264.

What maps to the plan:
    Primary correction  -> measured levels + eq/colorbalance
    Contrast S-curve    -> curves=preset=increase_contrast (real S-curve)
    Dialogue EQ         -> highpass 80Hz + presence lift at 3kHz
    Compression 4:1     -> acompressor ratio=4
    De-noise            -> afftdn
    Music ducking       -> sidechaincompress (a real sidechain, not volume keyframes)
    Loudness targets    -> loudnorm, EBU R128 two-pass
    Transitions         -> xfade, 50+ types (see `transitions`)

What it deliberately does NOT do: creative grading by eye, Power Windows, foley
placement. Those are judgement calls that need a human looking at the frame. This
handles the measurable half so the human half starts from a clean plate.
"""

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Broadcast-ish targets. -14 LUFS is the streaming/YouTube norm; -23 is EBU R128
# broadcast. Dialogue peaks around -6 to -12 dBTP per the plan's own guidance.
TARGET_LUFS = -14.0
TARGET_TP = -1.5
TARGET_LRA = 11.0
# Sample-peak limiting alone does not hold a true-peak ceiling: inter-sample peaks
# plus AAC encoder overshoot measured 2.3 dB above the limiter setting on real
# footage. This is the margin that covers both.
TP_HEADROOM = 2.5


def need_ffmpeg():
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg not on PATH")


def run(cmd, quiet=True):
    return subprocess.run(cmd, capture_output=quiet, text=True,
                          encoding="utf-8", errors="replace")


def probe(path):
    r = run(["ffprobe", "-v", "error", "-show_streams", "-show_format",
             "-of", "json", str(path)])
    return json.loads(r.stdout or "{}")


def measure_audio(path):
    """EBU R128 two-pass, pass one. These are the numbers the plan assumes you
    already know by looking at a meter."""
    r = run(["ffmpeg", "-hide_banner", "-i", str(path),
             "-af", "loudnorm=I=%s:TP=%s:LRA=%s:print_format=json" % (TARGET_LUFS, TARGET_TP, TARGET_LRA),
             "-f", "null", "-"])
    m = re.search(r"\{[^{}]*\"input_i\"[^{}]*\}", r.stderr or "", re.S)
    return json.loads(m.group(0)) if m else None


def bit_depth(path):
    """signalstats reports luma in the SOURCE bit depth, not always 0-255. A 10-bit
    file returns 0-1023, which silently makes every threshold in this tool wrong -
    a 10-bit clip measured 'YAVG 470' and got called overexposed when 470/1023 is
    actually slightly dark. Found by testing on real 10-bit HEVC footage."""
    info = probe(path)
    v = next((s for s in info.get("streams", []) if s.get("codec_type") == "video"), {})
    pix = (v.get("pix_fmt") or "").lower()
    for n in (16, 14, 12, 10):
        if f"p{n}" in pix or pix.endswith(str(n)):
            return n
    return 8


def measure_video(path, samples=60):
    """Real luma statistics, normalised to 0-255 whatever the source bit depth.

    Samples ACROSS THE WHOLE FILE rather than the opening seconds. Measuring only
    the head was a real bug: a 13-minute phone video that starts dark, or before
    the shot is framed, reported YMAX 54 of 255 and would have had a large false
    brightness correction applied to the entire clip. One frame every duration/60
    gives a representative spread for a couple of seconds of extra work."""
    dur = 0.0
    try:
        dur = float(probe(path).get("format", {}).get("duration", 0))
    except Exception:
        pass
    vf = "signalstats,metadata=print:file=-"
    if dur > samples:
        # one frame every N seconds, across the entire runtime
        vf = f"fps=1/{max(1, int(dur // samples))}," + vf
    r = run(["ffmpeg", "-hide_banner", "-i", str(path), "-vf", vf, "-f", "null", "-"])
    depth = bit_depth(path)
    scale = 255.0 / ((2 ** depth) - 1)
    vals = {"_depth": depth}
    for key in ("YMIN", "YLOW", "YAVG", "YHIGH", "YMAX", "SATAVG"):
        found = re.findall(rf"lavfi\.signalstats\.{key}=([0-9.]+)", r.stdout or "")
        if found:
            nums = [float(x) for x in found]
            vals[key] = (sum(nums) / len(nums)) * scale
    return vals


def cmd_analyze(a):
    need_ffmpeg()
    p = pathlib.Path(a.file).resolve()
    if not p.is_file():
        raise SystemExit(f"no such file: {p}")
    info = probe(p)
    v = next((s for s in info.get("streams", []) if s.get("codec_type") == "video"), {})
    aud = next((s for s in info.get("streams", []) if s.get("codec_type") == "audio"), None)
    dur = float(info.get("format", {}).get("duration", 0))

    print(f"FILE   {p.name}   {dur:.1f}s   {int(info.get('format',{}).get('size',0))/1e6:.1f} MB")
    print(f"VIDEO  {v.get('width')}x{v.get('height')}  {v.get('codec_name')}  "
          f"{eval(v.get('r_frame_rate','0/1')) if '/' in str(v.get('r_frame_rate','')) else '?':.2f} fps"
          if v else "VIDEO  none")

    vs = measure_video(p)
    print(f"\n--- EXPOSURE (measured, normalised to 0-255 from "
          f"{vs.get('_depth', 8)}-bit source) ---")
    if vs:
        print(f"  black point  YMIN {vs.get('YMIN',0):.0f}   "
              f"{'crushed - shadows are clipping' if vs.get('YMIN',0) < 2 else 'ok'}")
        print(f"  white point  YMAX {vs.get('YMAX',0):.0f}   "
              f"{'clipped - highlights are blown' if vs.get('YMAX',255) > 253 else 'ok'}")
        print(f"  average      YAVG {vs.get('YAVG',0):.0f}   "
              f"{'underexposed' if vs.get('YAVG',128) < 90 else 'overexposed' if vs.get('YAVG',128) > 165 else 'well exposed'}")
        print(f"  saturation   {vs.get('SATAVG',0):.0f}      "
              f"{'flat / log-ish, will take a grade well' if vs.get('SATAVG',0) < 40 else 'already saturated'}")
        print(f"\n  -> grade will {'lift shadows, ' if vs.get('YMIN',0) < 2 else ''}"
              f"{'recover highlights, ' if vs.get('YMAX',255) > 253 else ''}"
              f"apply an S-curve and a small saturation lift.")
    else:
        print("  (signalstats returned nothing - unusual codec?)")

    print("\n--- AUDIO (EBU R128) ---")
    if not aud:
        print("  no audio track.")
        return
    m = measure_audio(p)
    if not m:
        print("  could not measure.")
        return
    i, tp, lra = float(m["input_i"]), float(m["input_tp"]), float(m["input_lra"])
    thr = float(m["input_thresh"])
    print(f"  integrated   {i:6.1f} LUFS   target {TARGET_LUFS}    "
          f"{'TOO QUIET by %.1f dB' % (TARGET_LUFS - i) if i < TARGET_LUFS - 1 else 'TOO LOUD by %.1f dB' % (i - TARGET_LUFS) if i > TARGET_LUFS + 1 else 'on target'}")
    print(f"  true peak    {tp:6.1f} dBTP   target {TARGET_TP}    "
          f"{'CLIPPING' if tp > -0.1 else 'ok'}")
    print(f"  range (LRA)  {lra:6.1f} LU     "
          f"{'very dynamic - compression will help a lot' if lra > 14 else 'already tight' if lra < 6 else 'reasonable'}")
    print(f"  noise floor  {thr:6.1f} LUFS   "
          f"{'audible hiss likely - de-noise is worth running' if thr > -45 else 'clean'}")
    gain_needed = TARGET_LUFS - i
    print(f"\n  -> audio chain will high-pass 80Hz, de-noise, gain-stage, "
          f"compress 4:1, and limit.")
    if gain_needed > 20:
        # Corrected after measuring the real output. An earlier version of this
        # warning claimed a lift this large could not reach target and would land
        # at -18 to -22. It was wrong: the reordered chain hit -14.2 LUFS on a
        # 13-minute clip needing 25 dB. The prediction came from a 40-second slice,
        # whose statistics differ from a gated full-file measurement.
        # The COST is the part that was real, so warn about that instead.
        print(f"\n  ** {gain_needed:.0f} dB of lift will reach the target, but it costs dynamics. **")
        print(f"     Measured on a clip like this: loudness range fell from {lra:.0f} LU to")
        print(f"     under 4 LU - the quiet parts come up to meet the loud ones and the")
        print(f"     recording ends up flat. Fine for speech and vlogs, wrong for music")
        print(f"     or anything where the quiet moments carry meaning.")
        print(f"     Use --target -18 to keep more of the range.")


def cmd_cuts(a):
    """Scene detection - the objective half of 'analyse the pacing'."""
    need_ffmpeg()
    p = pathlib.Path(a.file).resolve()
    r = run(["ffmpeg", "-hide_banner", "-i", str(p),
             "-vf", f"select='gt(scene,{a.threshold})',metadata=print:file=-",
             "-an", "-f", "null", "-"])
    times = [float(t) for t in re.findall(r"pts_time:([0-9.]+)", r.stdout or "")]
    if not times:
        print(f"No scene changes above {a.threshold}. Lower --threshold, or this is one continuous take.")
        return
    print(f"{len(times)} scene changes above {a.threshold}:\n")
    prev = 0.0
    for t in times:
        mm, ss = divmod(t, 60)
        print(f"  {int(mm):02d}:{ss:05.2f}   shot ran {t-prev:5.1f}s")
        prev = t
    gaps = [b - a2 for a2, b in zip([0.0] + times, times)]
    print(f"\n  average shot length {sum(gaps)/len(gaps):.1f}s  "
          f"({'fast cutting' if sum(gaps)/len(gaps) < 3 else 'slow, contemplative' if sum(gaps)/len(gaps) > 8 else 'conventional'})")


def grade_filter(vs, look="natural"):
    """Corrections DERIVED from measurement, not preset by taste.

    Two looks, because the first version had only one and it was too much. It
    stacked a full levels stretch, a gamma lift up to 1.6, ffmpeg's
    increase_contrast preset AND a 20% saturation boost - four aggressive moves
    compounding. On real footage saturation went 38 to 56 and it read as cartoon.

      natural - the default. Restrained tone work plus micro-contrast. What
                actually reads as "realistic" is DETAIL, not contrast and colour:
                gentle curves, near-neutral saturation, and unsharp to bring out
                texture. Highlights and shadows keep their detail.
      punchy  - the original. Social-media grade, heavy contrast and saturation.
    """
    parts = []
    ymin, ymax = vs.get("YMIN", 16), vs.get("YMAX", 235)
    yavg, sat = vs.get("YAVG", 128), vs.get("SATAVG", 60)

    if look == "punchy":
        if ymin > 20 or ymax < 235:
            parts.append(f"colorlevels=rimin={ymin/255:.4f}:gimin={ymin/255:.4f}:bimin={ymin/255:.4f}"
                         f":rimax={ymax/255:.4f}:gimax={ymax/255:.4f}:bimax={ymax/255:.4f}")
        if yavg < 90:
            parts.append(f"eq=gamma={min(1.6, 1.0 + (90-yavg)/120):.2f}")
        elif yavg > 165:
            parts.append(f"eq=gamma={max(0.7, 1.0 - (yavg-165)/150):.2f}")
        parts.append("curves=preset=increase_contrast")
        if sat < 45:
            parts.append("eq=saturation=1.20")
        return ",".join(parts)

    # ---- natural ----
    # Leave headroom at both ends rather than stretching to 0-255. Clipping the
    # extremes is most of what makes a grade look synthetic.
    if ymin > 24 or ymax < 225:
        lo = max(0.0, (ymin - 8) / 255)
        hi = min(1.0, (ymax + 8) / 255)
        parts.append(f"colorlevels=rimin={lo:.4f}:gimin={lo:.4f}:bimin={lo:.4f}"
                     f":rimax={hi:.4f}:gimax={hi:.4f}:bimax={hi:.4f}")
    # Gentler exposure: capped at 1.25, and aiming for 105 rather than 128 so
    # dim footage stays dim-but-readable instead of being flattened into daylight.
    if yavg < 85:
        parts.append(f"eq=gamma={min(1.25, 1.0 + (85 - yavg) / 220):.3f}")
    elif yavg > 170:
        parts.append(f"eq=gamma={max(0.85, 1.0 - (yavg - 170) / 260):.3f}")
    # A hand-built shallow S-curve. The increase_contrast preset is far stronger
    # than this and is what crushed the blacks.
    parts.append("curves=all='0/0 0.25/0.22 0.5/0.5 0.75/0.78 1/1'")
    # Micro-contrast is the actual "hyper real" lever: local detail, not global
    # contrast. Mild denoise first so sharpening lifts texture, not grain.
    parts.append("hqdn3d=1.5:1.5:6:6")
    parts.append("unsharp=luma_msize_x=5:luma_msize_y=5:luma_amount=0.8"
                 ":chroma_msize_x=5:chroma_msize_y=5:chroma_amount=0.0")
    # Saturation stays near neutral. Only nudged if the source is genuinely flat.
    if sat < 35:
        parts.append("eq=saturation=1.06")
    return ",".join(parts)


def audio_filter(measured):
    """The plan's dialogue chain, in order, with real numbers."""
    # ORDER MATTERS, and getting it wrong is invisible until you measure.
    # The obvious order - compress, then normalise - fails on quiet source. This
    # footage averages -39 LUFS, so a -18 dB compressor threshold sits ABOVE
    # almost the entire signal and never engages; loudnorm then has to lift a
    # still-uncompressed 36 dB crest factor and the limiter crushes the peaks.
    # Measured that way: -24 LUFS out against a -14 target.
    # Gain-staging first, then compressing, means the compressor sees the signal
    # at a level its threshold was designed for.
    chain = [
        "highpass=f=80",                       # rumble, per the plan's 80-100Hz
        "afftdn=nf=-25",                       # de-noise
        "equalizer=f=3000:t=q:w=1.2:g=3",      # presence lift for clarity
    ]
    if measured:
        chain.append(
            "loudnorm=I=%s:TP=%s:LRA=%s:measured_I=%s:measured_TP=%s:measured_LRA=%s"
            ":measured_thresh=%s:offset=%s:linear=true" % (
                TARGET_LUFS, TARGET_TP, TARGET_LRA,
                measured["input_i"], measured["input_tp"], measured["input_lra"],
                measured["input_thresh"], measured.get("target_offset", "0.0")))
    else:
        chain.append(f"loudnorm=I={TARGET_LUFS}:TP={TARGET_TP}:LRA={TARGET_LRA}")
    # NOW compress - the signal is finally at a level where a -18 dB threshold
    # means something. 4:1 as the plan specifies, with makeup gain to recover
    # what the gain reduction costs.
    chain.append("acompressor=threshold=-18dB:ratio=4:attack=5:release=120:makeup=2")
    # Hard backstop, and it is NOT redundant with loudnorm's own TP setting:
    # loudnorm is measured on the RAW file but applied at the END of this chain,
    # after the presence lift and compressor have already changed the signal, so
    # its linear-mode gain math works from stale numbers and overshoots. Measured
    # on a real 13-minute clip: +0.5 dBTP against a -1.5 target.
    #
    # The ceiling is set BELOW the target on purpose. alimiter clamps SAMPLE peak;
    # loudnorm reports TRUE peak, which is oversampled and counts inter-sample
    # peaks, and the AAC encoder adds its own overshoot on top. A limiter set to
    # exactly -1.5 dBFS still measured +0.8 dBTP after encoding. TP_HEADROOM is
    # what covers that gap.
    ceiling_db = TARGET_TP - TP_HEADROOM
    chain.append(f"alimiter=limit={10 ** (ceiling_db / 20):.4f}:level=disabled")
    return ",".join(chain)


def render(p, out, vf, af, hw=True):
    cmd = ["ffmpeg", "-y", "-hide_banner", "-i", str(p)]
    if vf:
        cmd += ["-vf", vf]
    if af:
        cmd += ["-af", af]
    if vf is not None:
        cmd += ["-c:v", "h264_amf", "-quality", "quality", "-rc", "cqp", "-qp_i", "20", "-qp_p", "22"] \
            if hw else ["-c:v", "libx264", "-preset", "slow", "-crf", "18"]
    else:
        cmd += ["-c:v", "copy"]
    # +faststart moves the moov atom (the index) to the FRONT of the file. Without
    # it ffmpeg writes it last, behind all the video data, so a streaming player or
    # a cloud transcoder has to read the entire file before it can start. Measured:
    # a 306 MB render sat in Google Drive's "still being processed for playback"
    # state for many minutes purely because of this. It costs one extra pass over
    # the file at write time and it is never wrong to include.
    # -ar 48000 is NOT cosmetic. loudnorm works internally at a very high sample
    # rate, and without an explicit output rate that leaks into the encode: a
    # 44.1 kHz phone recording came out as 96 kHz AAC. ffmpeg plays it happily,
    # which is exactly why it went unnoticed - but Google Drive's transcoder sat
    # on it indefinitely with "still being processed for playback". 48 kHz is the
    # standard rate for video audio and every transcoder expects it.
    cmd += ["-c:a", "aac", "-ar", "48000", "-b:a", "192k",
            "-movflags", "+faststart", str(out)]
    r = run(cmd)
    if r.returncode != 0 and hw:
        print("  hardware encode failed, falling back to x264...", file=sys.stderr)
        return render(p, out, vf, af, hw=False)
    if r.returncode != 0:
        raise SystemExit(f"render failed:\n{(r.stderr or '')[-900:]}")
    return out


def cmd_grade(a):
    need_ffmpeg()
    p = pathlib.Path(a.file).resolve()
    vs = measure_video(p)
    vf = grade_filter(vs, a.look)
    out = pathlib.Path(a.out) if a.out else p.with_name(p.stem + "_graded.mp4")
    print(f"measured: YMIN {vs.get('YMIN',0):.0f} YAVG {vs.get('YAVG',0):.0f} "
          f"YMAX {vs.get('YMAX',0):.0f} SAT {vs.get('SATAVG',0):.0f}")
    print(f"filter:   {vf}\nrendering -> {out}")
    render(p, out, vf, None)
    print("done.")


def cmd_audio(a):
    need_ffmpeg()
    p = pathlib.Path(a.file).resolve()
    m = measure_audio(p)
    af = audio_filter(m)
    out = pathlib.Path(a.out) if a.out else p.with_name(p.stem + "_mixed.mp4")
    if m:
        print(f"measured: {float(m['input_i']):.1f} LUFS, peak {float(m['input_tp']):.1f} dBTP, "
              f"LRA {float(m['input_lra']):.1f}")
    print(f"chain:    {af}\nrendering -> {out}")
    render(p, out, None, af)
    print(f"done. normalised to {TARGET_LUFS} LUFS.")


def cmd_finish(a):
    need_ffmpeg()
    p = pathlib.Path(a.file).resolve()
    vs, m = measure_video(p), measure_audio(p)
    vf, af = grade_filter(vs, a.look), audio_filter(m)
    out = pathlib.Path(a.out) if a.out else p.with_name(p.stem + "_final.mp4")
    print(f"video:  {vf}\naudio:  {af}\nrendering -> {out}")
    render(p, out, vf, af)
    print("done.")


def cmd_transitions(a):
    need_ffmpeg()
    r = run(["ffmpeg", "-hide_banner", "-h", "filter=xfade"])
    names = re.findall(r"^\s+(\w+)\s+\d+\s+\.+", r.stdout or "", re.M)
    print("xfade transition types available:\n")
    print("  " + ", ".join(sorted(set(names))) if names else (r.stdout or "")[-1200:])
    print("\n  usage: ffmpeg -i a.mp4 -i b.mp4 -filter_complex "
          "\"xfade=transition=smoothleft:duration=1:offset=4\" out.mp4")


def main():
    ap = argparse.ArgumentParser(description="Measured post-production on ffmpeg.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, helptxt in [
        ("analyze", cmd_analyze, "measure exposure and loudness"),
        ("grade", cmd_grade, "colour correct from the measurement"),
        ("audio", cmd_audio, "dialogue chain + loudness normalise"),
        ("finish", cmd_finish, "grade + audio, hardware encoded"),
    ]:
        p = sub.add_parser(name, help=helptxt)
        p.add_argument("file")
        if name != "analyze":
            p.add_argument("--out")
        if name in ("grade", "finish"):
            p.add_argument("--look", choices=["natural", "punchy"], default="natural",
                           help="natural = restrained + micro-contrast (default); "
                                "punchy = heavy contrast and saturation")
        p.set_defaults(fn=fn)
    p = sub.add_parser("cuts", help="scene-change detection for pacing")
    p.add_argument("file"); p.add_argument("--threshold", type=float, default=0.3)
    p.set_defaults(fn=cmd_cuts)
    sub.add_parser("transitions", help="list xfade transition types").set_defaults(fn=cmd_transitions)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
