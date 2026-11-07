#!/usr/bin/env python3
"""Point this repo's core.hooksPath at git-tools/hooks so the pre-commit secret scan and the commit-msg
check run on every commit. Pure standard library; runs on Windows (py -3.12) and elsewhere (python3).

    python3 git-tools/install_hooks.py            install for the repo that contains the current directory
    python3 git-tools/install_hooks.py --check    report without changing anything (exit 1 if not installed)

Idempotent: running it again reports what is already in place. The hooks path is stored relative
(git-tools/hooks), so it keeps working when the repo moves and inside git worktrees, which run hooks
from their own top level. Exit 0 when the hooks are installed and verified, 1 otherwise.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys

HOOKS_PATH = "git-tools/hooks"
HOOK_NAMES = ("pre-commit", "commit-msg")


def git(root: str | None, *args: str) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    check_only = "--check" in argv
    code, root = git(None, "rev-parse", "--show-toplevel")
    if code != 0:
        print("install_hooks: not inside a git repository (" + root + ")")
        return 1
    root = root.replace("\\", "/")
    hooks_dir = os.path.join(root, *HOOKS_PATH.split("/"))
    problems = []
    for name in HOOK_NAMES:
        path = os.path.join(hooks_dir, name)
        if not os.path.isfile(path):
            problems.append("missing hook file: " + path)
            continue
        with open(path, "rb") as fh:
            head = fh.read(4096)
        if b"\r\n" in head:
            problems.append(name + " has CRLF line endings (core.autocrlf?). Run: git checkout -- " + HOOKS_PATH
                            + " after making sure .gitattributes marks the hooks eol=lf")
        if os.name != "nt":
            mode = os.stat(path).st_mode
            if not mode & stat.S_IXUSR:
                if check_only:
                    problems.append(name + " is not executable")
                else:
                    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    print("made executable: " + path)
    if problems:
        for p in problems:
            print("install_hooks: " + p)
        return 1

    _, current = git(root, "config", "--get", "core.hooksPath")
    if current.replace("\\", "/").rstrip("/") == HOOKS_PATH:
        print("core.hooksPath is already " + HOOKS_PATH)
    elif check_only:
        print("install_hooks: core.hooksPath is " + (repr(current) if current else "unset") + ", expected " + HOOKS_PATH)
        return 1
    else:
        if current:
            print("replacing core.hooksPath " + repr(current))
        code, out = git(root, "config", "core.hooksPath", HOOKS_PATH)
        if code != 0:
            print("install_hooks: git config failed: " + out)
            return 1
        print("set core.hooksPath = " + HOOKS_PATH)

    code, verified = git(root, "config", "--get", "core.hooksPath")
    if code != 0 or verified.replace("\\", "/").rstrip("/") != HOOKS_PATH:
        print("install_hooks: verification failed, git config --get core.hooksPath returned " + repr(verified))
        return 1
    print("verified: git config --get core.hooksPath -> " + verified)
    print("hooks active for " + root + ": " + ", ".join(HOOK_NAMES))
    if os.name == "nt":
        print("on Windows the hooks run under Git Bash via their #! line; no chmod needed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
