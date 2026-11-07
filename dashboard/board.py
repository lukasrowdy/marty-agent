"""Lukas's board: what is waiting on him, what is being worked on (by whom, where), and what
closed out today. The Jobs tab renders it; Lukas answers the waiting items with a tap.

Two files, both in my-agent/status (MARTY_BOARD_DIR overrides, for test servers):

  board.json          Written by Marty (by hand, then `board.py validate`). The curated half of
                      the Jobs tab. Schema below; anything unknown or malformed is refused whole,
                      so a typo shows as "the board has a problem" instead of half a board.
  board-answers.jsonl Written by the dashboard only, one line per tap, append-only. Marty reads
                      it back (`board.py answers`) and then clears the item from board.json.

A tap RECORDS an answer. It never runs anything: no route here starts a job, a download or a
deploy. The answer is data for Marty to act on, the same as a chat message.

board.json schema (version 1):
  {"version": 1, "as_of": ISO time, "note": optional str,
   "waiting": [{"id", "title", "body", "where", "tag"?, "flag"?: bool, "choices": [1-4 str]}],
   "work":    [{"id", "what", "who", "where", "state": running|queued|blocked, "eta"?, "detail"?}],
   "done":    [{"what", "who", "where", "at": ISO time, "detail"?}]}
Body and detail text may mark **bold** spans; the page renders everything else as plain text.
Rule for Marty: a new question gets a new id, so an old answer never attaches to it.

CLI (run with any Python 3.10+, from the dashboard folder):
  py board.py validate          check board.json, exit 1 on any problem
  py board.py answers [--all]   answers still waiting for Marty (latest per item still on the
                                board); --all prints the whole log
  py board.py selftest          offline tests in a temp folder
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import threading
from datetime import datetime

CODE_DIR = pathlib.Path(__file__).resolve().parent
AGENT_ROOT = pathlib.Path(os.environ.get("MARTY_AGENT_ROOT") or CODE_DIR.parent).resolve()
BOARD_DIR = pathlib.Path(os.environ.get("MARTY_BOARD_DIR") or (AGENT_ROOT / "status")).resolve()
BOARD_NAME = "board.json"
ANSWERS_NAME = "board-answers.jsonl"

VERSION = 1
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
STATES = ("running", "queued", "blocked")
MAX_BOARD_BYTES = 256 * 1024
MAX_ANSWERS_TAIL = 512 * 1024
NOTE_MAX = 1000
LIMITS = {"waiting": 30, "work": 60, "done": 40}
# field -> (required, max length); every string field of every section is listed here
WAITING_FIELDS = {"id": (True, 48), "title": (True, 140), "body": (True, 1200), "where": (True, 60),
                  "tag": (False, 30)}
WORK_FIELDS = {"id": (True, 48), "what": (True, 160), "who": (True, 40), "where": (True, 60),
               "state": (True, 10), "eta": (False, 40), "detail": (False, 600)}
DONE_FIELDS = {"what": (True, 160), "who": (True, 40), "where": (True, 60), "at": (True, 40),
               "detail": (False, 600)}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Times the page's JavaScript Date can also read: date, "T", time, and an explicit offset or Z.
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:\d{2})$")
_APPEND_LOCK = threading.Lock()


class BoardUnavailable(Exception):
    """board.json is missing, unreadable or fails validation."""


class UnknownItem(Exception):
    """No waiting item with that id is on the board right now."""


class BadChoice(Exception):
    """The choice is not one of that item's buttons."""


def paths(board_dir: pathlib.Path | None = None) -> tuple[pathlib.Path, pathlib.Path]:
    base = pathlib.Path(board_dir) if board_dir else BOARD_DIR
    return base / BOARD_NAME, base / ANSWERS_NAME


def _iso_ok(value) -> bool:
    if not isinstance(value, str) or not _ISO_RE.match(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _check_fields(where: str, item, spec: dict, problems: list, extra_ok=()) -> None:
    if not isinstance(item, dict):
        problems.append(f"{where}: must be an object")
        return
    for key in item:
        if key not in spec and key not in extra_ok:
            problems.append(f"{where}: unknown field '{key}'")
    for key, (required, limit) in spec.items():
        value = item.get(key)
        if value is None:
            if required:
                problems.append(f"{where}: '{key}' is required")
            continue
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{where}: '{key}' must be a non-empty string")
        elif len(value) > limit:
            problems.append(f"{where}: '{key}' is longer than {limit} characters")


def validate(data) -> list[str]:
    """Every problem with a parsed board.json, in order. Empty list = valid."""
    problems: list[str] = []
    if not isinstance(data, dict):
        return ["the board must be a JSON object"]
    for key in data:
        if key not in ("version", "as_of", "note", "waiting", "work", "done"):
            problems.append(f"unknown top-level field '{key}'")
    if data.get("version") != VERSION:
        problems.append(f"'version' must be {VERSION}")
    if not _iso_ok(data.get("as_of")):
        problems.append("'as_of' must be an ISO time, e.g. 2026-09-26T09:50:00-05:00")
    note = data.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 300):
        problems.append("'note' must be a string of at most 300 characters")
    seen: set[str] = set()
    for section, spec in (("waiting", WAITING_FIELDS), ("work", WORK_FIELDS), ("done", DONE_FIELDS)):
        rows = data.get(section, [])
        if not isinstance(rows, list):
            problems.append(f"'{section}' must be a list")
            continue
        if len(rows) > LIMITS[section]:
            problems.append(f"'{section}' has {len(rows)} items; the limit is {LIMITS[section]}")
        for i, item in enumerate(rows):
            where = f"{section}[{i}]"
            extra = ("flag", "choices") if section == "waiting" else ()
            _check_fields(where, item, spec, problems, extra)
            if not isinstance(item, dict):
                continue
            if "id" in spec:
                ident = item.get("id")
                if isinstance(ident, str) and not ID_RE.match(ident):
                    problems.append(f"{where}: id '{ident}' must be lowercase letters, digits and dashes")
                elif isinstance(ident, str):
                    if ident in seen:
                        problems.append(f"{where}: id '{ident}' is used twice")
                    seen.add(ident)
            if section == "waiting":
                if "flag" in item and not isinstance(item["flag"], bool):
                    problems.append(f"{where}: 'flag' must be true or false")
                choices = item.get("choices")
                if (not isinstance(choices, list) or not 1 <= len(choices) <= 4
                        or not all(isinstance(c, str) and c.strip() and len(c) <= 40 for c in choices)):
                    problems.append(f"{where}: 'choices' must be 1 to 4 non-empty strings of at most 40 characters")
                elif len(set(choices)) != len(choices):
                    problems.append(f"{where}: 'choices' has a duplicate")
            if section == "work" and isinstance(item.get("state"), str) and item["state"] not in STATES:
                problems.append(f"{where}: 'state' must be one of {', '.join(STATES)}")
            if section == "done" and item.get("at") is not None and not _iso_ok(item.get("at")):
                problems.append(f"{where}: 'at' must be an ISO time")
    return problems


def load(board_path: pathlib.Path) -> dict:
    """The validated board. Raises BoardUnavailable with a one-line reason."""
    try:
        raw = board_path.read_bytes()
    except FileNotFoundError:
        raise BoardUnavailable("there is no board file yet") from None
    except OSError as exc:
        raise BoardUnavailable(f"the board file can't be read ({type(exc).__name__})") from None
    if len(raw) > MAX_BOARD_BYTES:
        raise BoardUnavailable("the board file is too big")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:   # RecursionError: absurd nesting
        raise BoardUnavailable(f"the board file is not valid JSON ({exc.__class__.__name__})") from None
    problems = validate(data)
    if problems:
        raise BoardUnavailable(f"the board file has a problem: {problems[0]}")
    for section in ("waiting", "work", "done"):
        data.setdefault(section, [])
    return data


def read_answers(answers_path: pathlib.Path) -> list[dict]:
    """Every well-formed answer row, oldest first (the last MAX_ANSWERS_TAIL bytes only).

    Rows are split on b"\\n" only. str.splitlines() would also split on U+2028, U+2029 and U+0085,
    which pasted text can carry, and lose the row. Rows are written ASCII-escaped anyway, so a raw
    newline or separator can never appear inside one; this is the belt to that brace."""
    try:
        with answers_path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - MAX_ANSWERS_TAIL))
            data = fh.read()
    except OSError:          # missing, unreadable or a folder: no answers, never an exception
        return []
    if size > MAX_ANSWERS_TAIL:
        data = data.split(b"\n", 1)[-1]
    rows = []
    for raw in data.split(b"\n"):
        try:
            row = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, RecursionError):
            continue
        if isinstance(row, dict) and isinstance(row.get("id"), str) and isinstance(row.get("choice"), str):
            rows.append(row)
    return rows


def latest_answers(answers_path: pathlib.Path) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for row in read_answers(answers_path):
        latest[row["id"]] = row          # file order: a later tap replaces an earlier one
    return latest


def clean_note(note) -> str:
    if not isinstance(note, str):
        return ""
    return _CONTROL.sub("", note).strip()[:NOTE_MAX]


def record_answer(handle: str, item_id, choice, note, board_dir: pathlib.Path | None = None) -> dict:
    """Append one answer. The item must be on the board now and the choice one of its buttons."""
    board_path, answers_path = paths(board_dir)
    board = load(board_path)
    if not isinstance(item_id, str) or not ID_RE.match(item_id):
        raise UnknownItem(item_id)
    item = next((w for w in board["waiting"] if w["id"] == item_id), None)
    if item is None:
        raise UnknownItem(item_id)
    if not isinstance(choice, str) or choice not in item["choices"]:
        raise BadChoice(choice)
    row = {"at": datetime.now().astimezone().isoformat(timespec="seconds"), "handle": str(handle),
           "id": item_id, "title": item["title"], "choice": choice, "note": clean_note(note)}
    # ASCII-escaped: no raw U+2028/U+2029/U+0085 or newline can ever sit inside a row.
    line = (json.dumps(row, ensure_ascii=True) + "\n").encode("ascii")
    with _APPEND_LOCK:
        answers_path.parent.mkdir(parents=True, exist_ok=True)
        with answers_path.open("a+b") as fh:
            fh.seek(0, os.SEEK_END)
            if fh.tell():
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":      # a torn last line (crash mid-write) must not swallow this tap
                    line = b"\n" + line
            fh.write(line)                   # append mode: always lands at the end
            fh.flush()
            os.fsync(fh.fileno())
    return row


def payload(board_dir: pathlib.Path | None = None) -> dict:
    """The board for /api/jobs. Never raises: a bad board is {"ok": False, "error": reason}."""
    board_path, answers_path = paths(board_dir)
    try:
        board = load(board_path)
    except BoardUnavailable as exc:
        return {"ok": False, "error": str(exc), "waiting": [], "work": [], "done": []}
    answers = latest_answers(answers_path)
    waiting = []
    for item in board["waiting"]:
        row = dict(item)
        answer = answers.get(item["id"])
        if answer and answer.get("choice") in item["choices"]:
            row["answer"] = {"choice": answer["choice"], "at": answer.get("at"),
                             "note": answer.get("note") or ""}
        waiting.append(row)
    return {"ok": True, "as_of": board["as_of"], "note": board.get("note") or "",
            "waiting": waiting, "work": board["work"], "done": board["done"]}


# --- CLI ------------------------------------------------------------------------------------

def _cmd_validate(board_dir=None) -> int:
    board_path, _ = paths(board_dir)
    try:
        raw = board_path.read_bytes()
        data = json.loads(raw.decode("utf-8-sig"))
    except FileNotFoundError:
        print(f"PROBLEM: no board file at {board_path}")
        return 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"PROBLEM: {board_path} is not readable JSON: {exc}")
        return 1
    problems = validate(data)
    if len(raw) > MAX_BOARD_BYTES:
        problems.append("the board file is too big")
    if problems:
        for p in problems:
            print("PROBLEM:", p)
        return 1
    print(f"OK: {len(data.get('waiting', []))} waiting, {len(data.get('work', []))} work, "
          f"{len(data.get('done', []))} done, as of {data['as_of']}")
    return 0


def _cmd_answers(show_all: bool, board_dir=None) -> int:
    board_path, answers_path = paths(board_dir)
    rows = read_answers(answers_path)
    if show_all:
        chosen = rows
    else:
        try:
            on_board = {w["id"] for w in load(board_path)["waiting"]}
        except BoardUnavailable as exc:
            print(f"PROBLEM: {exc}; showing the whole log instead")
            on_board = None
        latest = {}
        for row in rows:
            latest[row["id"]] = row
        chosen = [r for r in latest.values() if on_board is None or r["id"] in on_board]
    if not chosen:
        print("No answers waiting for Marty." if not show_all else "No answers logged.")
        return 0
    for r in chosen:
        note = f"  note: {r['note']}" if r.get("note") else ""
        print(f"{r.get('at')}  [{r.get('handle')}]  {r['id']}: {r['choice']}  ({r.get('title', '')}){note}")
    return 0


def _selftest() -> int:
    import tempfile
    ok = 0
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        good = {"version": 1, "as_of": "2026-09-26T09:50:00-05:00", "note": "test",
                "waiting": [{"id": "a-1", "title": "Pick one", "body": "**Bold** and <b>not html</b>",
                             "where": "Test", "flag": True, "choices": ["Yes", "No"]}],
                "work": [{"id": "w-1", "what": "Thing", "who": "Marty", "where": "PC", "state": "running",
                          "eta": "~5 min"}],
                "done": [{"what": "Done thing", "who": "Marty", "where": "PC", "at": "2026-09-26T07:24:00-05:00"}]}
        assert validate(good) == [], validate(good); ok += 1
        bad = json.loads(json.dumps(good))
        bad["waiting"][0]["choices"] = ["Yes", "Yes"]
        bad["work"][0]["state"] = "maybe"
        bad["work"].append(dict(bad["work"][0]))           # duplicate id
        bad["done"][0]["colour"] = "red"                   # unknown field
        bad["waiting"][0]["id"] = "Has Space"
        problems = validate(bad)
        for needle in ("duplicate", "'state' must be", "used twice", "unknown field 'colour'", "lowercase"):
            assert any(needle in p for p in problems), (needle, problems)
        ok += 1
        assert validate([]) == ["the board must be a JSON object"]; ok += 1
        # payload before the file exists, then with it
        assert payload(d)["ok"] is False; ok += 1
        (d / BOARD_NAME).write_text(json.dumps(good), encoding="utf-8")
        p = payload(d)
        assert p["ok"] and p["waiting"][0].get("answer") is None and p["work"][0]["who"] == "Marty"; ok += 1
        # answers: good tap, latest wins, refusals
        row = record_answer("lukas", "a-1", "Yes", "  first\x07 note ", d)
        assert row["note"] == "first note" and row["choice"] == "Yes"; ok += 1
        record_answer("lukas", "a-1", "No", "", d)
        assert payload(d)["waiting"][0]["answer"]["choice"] == "No"; ok += 1
        for args, exc in ((("lukas", "nope", "Yes", ""), UnknownItem), (("lukas", "a-1", "Maybe", ""), BadChoice),
                          (("lukas", "../x", "Yes", ""), UnknownItem), (("lukas", None, "Yes", ""), UnknownItem),
                          (("lukas", "a-1", ["Yes"], ""), BadChoice)):
            try:
                record_answer(*args, board_dir=d)
            except exc:
                ok += 1
            else:
                raise AssertionError(f"{args} should raise {exc.__name__}")
        assert len(record_answer("lukas", "a-1", "Yes", "x" * 5000, d)["note"]) == NOTE_MAX; ok += 1
        # a bad board refuses taps and degrades the payload, never raises
        (d / BOARD_NAME).write_text("{not json", encoding="utf-8")
        assert payload(d)["ok"] is False; ok += 1
        try:
            record_answer("lukas", "a-1", "Yes", "", d)
        except BoardUnavailable:
            ok += 1
        # an answer whose choice is no longer a button is not attached
        changed = json.loads(json.dumps(good))
        changed["waiting"][0]["choices"] = ["Later"]
        (d / BOARD_NAME).write_text(json.dumps(changed), encoding="utf-8")
        assert "answer" not in payload(d)["waiting"][0]; ok += 1
        # a torn last line in the log is skipped, and the next tap after it still lands
        with (d / ANSWERS_NAME).open("ab") as fh:
            fh.write(b'{"id": "a-1", "choi')
        assert len(read_answers(d / ANSWERS_NAME)) == 3; ok += 1     # Yes, No, the long note
        (d / BOARD_NAME).write_text(json.dumps(good), encoding="utf-8")
        record_answer("lukas", "a-1", "Yes", "after the tear", d)
        assert payload(d)["waiting"][0]["answer"]["note"] == "after the tear"; ok += 1
        # pasted line/paragraph separators survive the round trip (they used to lose the row)
        for sep in (" ", " ", "\u0085"):
            record_answer("lukas", "a-1", "No", f"line one{sep}line two", d)
            got = payload(d)["waiting"][0]["answer"]
            assert got["choice"] == "No" and got["note"] == f"line one{sep}line two", (repr(sep), got); ok += 1
        assert all(b < 128 for b in (d / ANSWERS_NAME).read_bytes()); ok += 1   # rows are ASCII-escaped
        # strict times: JavaScript must be able to read them
        for bad_time in ("20260926T095000", "2026-W39-6", "2026-09-26 09:50", "2026-09-26", "2026-09-26T09:50:00"):
            probe = json.loads(json.dumps(good))
            probe["as_of"] = bad_time
            assert any("as_of" in p for p in validate(probe)), bad_time
        ok += 1
        probe = json.loads(json.dumps(good))
        probe["as_of"] = "2026-09-26T14:50:00Z"
        assert validate(probe) == []; ok += 1
        # absurd nesting and an unreadable answers log degrade, never raise
        (d / BOARD_NAME).write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        assert payload(d)["ok"] is False; ok += 1
        (d / BOARD_NAME).write_text(json.dumps(good), encoding="utf-8")
        (d / ANSWERS_NAME).unlink()
        (d / ANSWERS_NAME).mkdir()                                   # a folder where the log should be
        assert payload(d)["ok"] is True and "answer" not in payload(d)["waiting"][0]; ok += 1
    print(f"board selftest: {ok} checks passed")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "validate":
        return _cmd_validate()
    if argv[0] == "answers":
        return _cmd_answers("--all" in argv[1:])
    if argv[0] == "selftest":
        return _selftest()
    print(f"unknown command {argv[0]!r}; try validate, answers or selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
