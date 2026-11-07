#!/usr/bin/env python3
"""Map a patch made against the clean export back to real values. Pure standard library, Python 3.11+.

    py -3.12 git-tools/import_patch.py CLOUD.diff                 writes CLOUD.mapped.patch next to it
    py -3.12 git-tools/import_patch.py CLOUD.diff -o OUT.patch

Takes a unified diff (git diff / git format-patch / a PR's .diff) made against the export from
git-tools/export_clean.py and writes a patch for the live repo:
  - every {{PLACEHOLDER}} (and its _LC/_UC/_TC case forms) becomes the real value from the local map;
  - every {{IP_a_b_c_d}} becomes a.b.c.d when that address is on the reviewed generic list;
  - the exporter's `secret-scan: allow [export-reviewed]` marker comments are stripped again.
Line counts never change, so hunk headers stay valid.

It applies nothing. Marty reviews the output, checks it with `git apply --check`, and applies it by hand.
Warnings (never values): unknown placeholders, files the export had left out, binary patches, whole-file
deletions, and any private value the cloud side typed in literally. Exit 0 clean, 1 with warnings, 2 error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import export_clean as ec  # noqa: E402

PH_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")
FILE_RE = re.compile(r"^(?:\+\+\+|---) (?:[ab]/)?(.+?)\s*$")


def build_reverse(pmap: ec.PlaceholderMap, reviewed: dict) -> dict[str, str]:
    rev = dict(pmap.reverse)
    for ip in reviewed.get("generic_ips", []):
        rev[ec.generic_ip_placeholder(ip)] = ip
    return rev


def strip_marker(body: str) -> tuple[str, bool]:
    cr = "\r" if body.endswith("\r") else ""
    core = body[:-1] if cr else body
    for m in ec.ALL_MARKERS:
        if core.endswith(m):
            return core[: -len(m)] + cr, True
    return body, False


def map_patch(text: str, pmap: ec.PlaceholderMap, reviewed: dict, summary: dict | None = None):
    """Returns (mapped text, stats, warnings). Warnings never contain a private value."""
    rev = build_reverse(pmap, reviewed)
    stats = {"placeholders_restored": {}, "markers_stripped": 0, "files": []}
    warnings: list[str] = []
    excluded = set()
    if summary:
        for paths in summary.get("excluded", {}).values():
            excluded.update(paths)
    literal = pmap.regex          # the exporter's own matcher: whole-word names stay whole-word

    def restore(s: str) -> str:
        def repl(m):
            ph = m.group(0)
            if ph in rev:
                stats["placeholders_restored"][ph] = stats["placeholders_restored"].get(ph, 0) + 1
                return rev[ph]
            return ph
        return PH_RE.sub(repl, s)

    out = []
    current = None
    for n, line in enumerate(text.split("\n"), 1):
        if line.startswith("diff --git ") or line.startswith("rename from ") or line.startswith("rename to ") \
                or line.startswith("copy from ") or line.startswith("copy to "):
            out.append(restore(line))
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            new = restore(line)
            m = FILE_RE.match(new)
            if m and m.group(1) != "/dev/null":
                current = m.group(1)
                if current not in stats["files"]:
                    stats["files"].append(current)
                if current in excluded:
                    warnings.append("touches a file the export left out: " + current)
            if line.startswith("+++ /dev/null"):
                warnings.append("deletes a whole file: " + (current or "?"))
            out.append(new)
            continue
        if line.startswith("GIT binary patch") or line.startswith("Binary files "):
            warnings.append("binary patch for " + (current or "?") + " (review by hand)")
            out.append(line)
            continue
        if line[:1] in (" ", "+", "-") and not line.startswith("--- ") and not line.startswith("+++ "):
            body, stripped = strip_marker(line[1:])
            if stripped:
                stats["markers_stripped"] += 1
            if line[:1] == "+":
                if literal and literal.search(body):
                    warnings.append("line %d: the cloud side typed a private value literally (check it)" % n)
                for ph in PH_RE.findall(body):
                    if "{{" + ph + "}}" not in rev:
                        warnings.append("line %d: unknown placeholder {{%s}} left as is" % (n, ph))
            body = restore(body)
            for rule in pmap.literal_rules + reviewed.get("_literal_rules", []):
                if rule.applies(current):
                    body, k = rule.reverse(body)
                    if k:
                        stats["literal_rules_reversed"] = stats.get("literal_rules_reversed", 0) + k
            out.append(line[0] + body)
            continue
        out.append(line)
    return "\n".join(out), stats, warnings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("patch", type=Path)
    ap.add_argument("-o", "--out", type=Path)
    ap.add_argument("--map", type=Path, default=ec.DEFAULT_MAP)
    ap.add_argument("--reviewed", type=Path, default=ec.DEFAULT_REVIEWED)
    ap.add_argument("--summary", type=Path, default=ec.DEFAULT_OUT / "export-summary.json",
                    help="the exporter's summary, used to warn about files the export left out")
    a = ap.parse_args(argv)
    try:
        text = a.patch.read_bytes().decode("utf-8")
        pmap = ec.PlaceholderMap.load(a.map)
        reviewed = ec.load_reviewed(a.reviewed)
        summary = json.loads(a.summary.read_text(encoding="utf-8")) if a.summary and a.summary.is_file() else None
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    mapped, stats, warnings = map_patch(text, pmap, reviewed, summary)
    out = a.out or a.patch.with_name(a.patch.stem + ".mapped.patch")
    if out.resolve() == a.patch.resolve():
        print("error: refusing to overwrite the input patch", file=sys.stderr)
        return 2
    out.write_bytes(mapped.encode("utf-8"))
    print("wrote %s: %d file(s), %d placeholder(s) restored, %d marker(s) stripped" % (
        out, len(stats["files"]), sum(stats["placeholders_restored"].values()), stats["markers_stripped"]))
    for f in stats["files"]:
        print("  file " + f)
    for ph, n in sorted(stats["placeholders_restored"].items()):
        print("  restored %-30s %d" % (ph, n))
    for w in warnings:
        print("WARNING " + w)
    print("Not applied. Review it, then: git apply --check \"%s\" in the live repo, then apply by hand." % out)
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
