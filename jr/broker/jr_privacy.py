"""The local privacy screen hook for Jr's hosted video sends.

NEW FILE, 2026-09-28 (Jr overnight build, item 8 "video"). The family-media rule
(CLAUDE.md, the owner, 2026-09-24): before any photo or video goes to ANY outside service it
passes the local-only nudity and privacy screen on this PC, and anything flagged never
leaves. This module is the wiring, not the screen.

CHANGED 2026-09-28 (fix helper, after the skeptic's item 8 verdict), what and why:
- PrivacyScreen.from_config(tools, ...) takes the screen's python and script from the
  tools config as absolute paths (keys screen_python, screen_script) and a missing one is
  a VideoError naming the key; check() re-validates at any time. The service account has
  no access to the owner's profile, where both live today, and the old wiring answered
  that with a silent "flagged" and no clue why.
- The runner timeout scales with the total video seconds (TIMEOUT_PER_VIDEO_SECOND times
  the sum of secs, never under the configured floor): a flat 1,800 s while jr_video allowed
  four hours meant a long clip timed out to "flagged" silently. jr_hosted refuses anything
  over 60 minutes before the screen runs at all.
- No owner names in code.

The screen that exists on this PC is my-agent/private/NAS sort/tools/privacy_screen.py,
run with FaceFusion's venv python (my-agent/facefusion/.venv/Scripts/python.exe). Its CLI:
    python privacy_screen.py MANIFEST.json OUT.jsonl [--only NAME,...] [--workers N]
MANIFEST is a JSON list of {"key", "name", "src", "secs"}; OUT.jsonl gets one record per
file with "tier" in PRIVATE / LOCAL_ONLY / UNSCREENED / CLEAR. It reads frames into memory
and writes none. Nothing in this module runs it in tests: the runner is injected.

Verdict mapping, fail closed: every item must come back CLEAR for "ok". PRIVATE,
LOCAL_ONLY (bathroom, changing, bed), UNSCREENED (short read, read error), a missing record,
a non-zero exit, a timeout or any exception is "flagged". No screen wired is "flagged" too.
"""

from __future__ import annotations

import json
import math
import secrets
import shutil
import subprocess
from pathlib import Path

from jr_video import VideoError, tool_path


OK = "ok"
FLAGGED = "flagged"
DEFAULT_TIMEOUT = 1800
TIMEOUT_PER_VIDEO_SECOND = 2     # the screen samples 2 fps with a heavy pass every 8th frame


def _run(argv, timeout):
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def screen_paths(agent_root) -> dict:
    """Where the real screen lives today, relative to the my-agent folder. For writing the
    tools config, not for wiring: production goes through PrivacyScreen.from_config so the
    paths are absolute, checked, and can point anywhere the service account can read."""
    root = Path(agent_root)
    return {"script": root / "private" / "NAS sort" / "tools" / "privacy_screen.py",
            "python": root / "facefusion" / ".venv" / "Scripts" / "python.exe"}


def verdict_from_records(items: list, records: list) -> str:
    """Pure: the tier lines the screen wrote, against the items we asked about."""
    tiers = {}
    for record in records:
        if type(record) is dict and type(record.get("key")) is str:
            tiers[record["key"]] = record.get("tier")
    for item in items:
        if tiers.get(item["key"]) != "CLEAR":
            return FLAGGED
    return OK


class PrivacyScreen:
    def __init__(self, *, script, python, work_root, runner=_run, timeout=DEFAULT_TIMEOUT,
                 workers=1):
        self.script = Path(script)
        self.python = Path(python)
        self.work_root = Path(work_root)
        self.runner = runner
        self.timeout = timeout
        self.workers = workers

    @classmethod
    def from_config(cls, tools, *, work_root, runner=_run, timeout=DEFAULT_TIMEOUT, workers=1):
        """The production constructor: both paths from the tools config, checked now."""
        python = tool_path(tools, "screen_python")
        script = tool_path(tools, "screen_script")
        return cls(script=script, python=python, work_root=work_root, runner=runner,
                   timeout=timeout, workers=workers)

    def check(self) -> None:
        """Raise a VideoError naming what the service cannot see, for a start-up check."""
        tool_path({"screen_python": str(self.python), "screen_script": str(self.script)},
                  "screen_python")
        tool_path({"screen_python": str(self.python), "screen_script": str(self.script)},
                  "screen_script")

    @staticmethod
    def timeout_for(floor, rows) -> int:
        """The floor, or TIMEOUT_PER_VIDEO_SECOND times the total seconds when that is more."""
        total = sum(row.get("secs") or 0 for row in rows if type(row) is dict)
        return max(int(floor), int(math.ceil(total * TIMEOUT_PER_VIDEO_SECOND)))

    @staticmethod
    def manifest(items) -> list:
        rows = []
        for index, item in enumerate(items):
            if isinstance(item, (str, Path)):
                item = {"src": str(item)}
            if type(item) is not dict or type(item.get("src")) is not str or not item["src"]:
                raise ValueError("Privacy screen item must name a file")
            src = Path(item["src"])
            if src.is_symlink() or not src.is_file():
                raise ValueError("Privacy screen item is missing or is a link")
            secs = item.get("secs")
            if secs is not None and (type(secs) not in {int, float} or secs <= 0):
                raise ValueError("Privacy screen item duration is invalid")
            rows.append({"key": f"item{index:03d}", "name": src.name, "src": str(src),
                         "secs": secs})
        if not rows:
            raise ValueError("Privacy screen needs at least one file")
        return rows

    def __call__(self, items) -> str:
        """ok only when the real screen ran to completion and cleared every item."""
        job = None
        try:
            rows = self.manifest(items)
            if not self.script.is_file() or not self.python.is_file():
                return FLAGGED
            self.work_root.mkdir(parents=True, exist_ok=True)
            job = self.work_root / ("screen-" + secrets.token_hex(8))
            job.mkdir()
            manifest = job / "manifest.json"
            out = job / "screen.jsonl"
            manifest.write_text(json.dumps(rows), encoding="utf-8")
            result = self.runner([str(self.python), str(self.script), str(manifest), str(out),
                                  "--workers", str(self.workers)],
                                 self.timeout_for(self.timeout, rows))
            if result.returncode != 0 or not out.is_file():
                return FLAGGED
            records = []
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    records.append(json.loads(line))
                except ValueError:
                    return FLAGGED
            return verdict_from_records(rows, records)
        except Exception:
            return FLAGGED
        finally:
            if job is not None:
                shutil.rmtree(job, ignore_errors=True)
