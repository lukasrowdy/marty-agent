"""Offline audio-file transcription for the MJ Dashboard Talk endpoint."""

import json
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "one audio path required"}))
        return 2
    path = pathlib.Path(sys.argv[1]).resolve()
    try:
        from faster_whisper import WhisperModel

        model = WhisperModel("small.en", device="cpu", compute_type="int8",
                             local_files_only=True)
        segments, info = model.transcribe(str(path), language="en", temperature=0.0,
                                          vad_filter=True)
        text = "".join(segment.text for segment in segments).strip()
        print(json.dumps({"ok": True, "text": text,
                          "audio_seconds": round(float(info.duration or 0), 2)}))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False,
                          "error": f"{type(exc).__name__}: {exc}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
