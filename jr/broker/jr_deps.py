"""Locate the bundled pywin32 for Jr code that may run from a staging copy.

ADDED 2026-09-28 (Jr overnight build, helper item 2 "pipe"). The production
layout keeps pywin32 in a ".deps" folder beside each module (the pattern
jr_private_root.py uses inline). A staged copy has no ".deps" of its own, so
this module also honours JR_DEPS_DIR, which the test command points at the
read-only bundle. It adds nothing else to sys.path, never the dashboard
folder. When neither location exists it does nothing and the normal import
path applies.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

_state: dict = {"loaded": False, "dll_directory": None, "path": None}


def deps_dir() -> Path | None:
    candidates = [Path(__file__).with_name(".deps")]
    configured = os.environ.get("JR_DEPS_DIR")
    if configured:
        candidates.append(Path(configured))
    for candidate in candidates:
        if (candidate / "pywin32_system32").is_dir():
            return candidate
    return None


def load() -> Path | None:
    """Put the bundled pywin32 on sys.path once and return where it was found."""
    if _state["loaded"]:
        return _state["path"]
    _state["loaded"] = True
    found = deps_dir()
    if found is not None:
        entries = [str(found), str(found / "win32"), str(found / "win32" / "lib")]
        sys.path[:0] = [entry for entry in entries if entry not in sys.path]
        _state["dll_directory"] = os.add_dll_directory(str(found / "pywin32_system32"))
        _state["path"] = found
    return found
