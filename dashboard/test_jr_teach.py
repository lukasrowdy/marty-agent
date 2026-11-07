"""
Unit tests for jr_teach ("Teach Jr" Phase 1). No network: the Claude subscription lane
(switchboard.ask_claude_sub) is stubbed in every test. Run with the system Python:

    C:/Users/{{WIN_USER}}/AppData/Local/Programs/Python/Python312/python.exe -m unittest test_jr_teach -v

The write root (jr_teach.TAUGHT_ROOT) is pointed at a temp dir per test, so the real
jr/library/taught is never touched.
"""

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jr_teach  # noqa: E402

EM_DASH = "\u2014"
EN_DASH = "\u2013"


def stub_ok(title="Firewall basics", keywords=("firewall", "nat", "rules"),
            body="A firewall filters traffic by rules. NAT rewrites addresses."):
    """A stubbed ask_claude_sub that returns a well-formed JSON note as its 4-tuple."""
    payload = json.dumps({"title": title, "keywords": list(keywords), "body": body})

    def _fake(model, system, messages, _key=None):
        return payload, "sonnet", (0, 0), {"plan": "max"}
    return _fake


def stub_raises(exc=RuntimeError("lane down")):
    def _fake(model, system, messages, _key=None):
        raise exc
    return _fake


class TeachTests(unittest.TestCase):
    def setUp(self):
        self._orig_ask = jr_teach.switchboard.ask_claude_sub
        self._orig_root = jr_teach.TAUGHT_ROOT
        self._orig_token = jr_teach.secrets.token_hex
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="jr-teach-test-"))
        # Mirror the real layout so "under jr/library/taught" is a meaningful assertion.
        self.lib = self.tmp / "jr" / "library"
        self.root = self.lib / "taught"
        jr_teach.TAUGHT_ROOT = self.root

    def tearDown(self):
        jr_teach.switchboard.ask_claude_sub = self._orig_ask
        jr_teach.TAUGHT_ROOT = self._orig_root
        jr_teach.secrets.token_hex = self._orig_token
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # 1. save writes a file under jr/library/taught, with header + provenance
    def test_save_writes_file_in_taught(self):
        jr_teach.switchboard.ask_claude_sub = stub_ok()
        result = jr_teach.save_taught("How do firewalls work?  (a long real answer here)",
                                      context="explain firewalls")
        self.assertTrue(result["ok"])
        path = pathlib.Path(result["path"])
        self.assertTrue(path.exists(), "the note file was written")
        self.assertEqual(path.parent, pathlib.Path(os.path.realpath(self.root)),
                         "the note sits directly inside jr/library/taught")
        self.assertEqual(path.suffix, ".md")
        content = path.read_text(encoding="utf-8")
        self.assertIn("# Firewall basics", content)
        self.assertIn("Taught by Marty,", content)
        self.assertIn("from: explain firewalls", content)
        self.assertIn("keywords: firewall, nat, rules", content)

    # 2. path traversal in a title is neutralized (no file escapes the root)
    def test_title_traversal_is_neutralized(self):
        jr_teach.switchboard.ask_claude_sub = stub_ok()
        result = jr_teach.save_taught("some answer text that is long enough",
                                      title="../../evil/passwd", context="ctx")
        path = pathlib.Path(result["path"])
        self.assertEqual(path.parent, pathlib.Path(os.path.realpath(self.root)),
                         "the file stays inside the taught root")
        # The dangerous parts became a plain slug; no traversal happened.
        self.assertNotIn("..", path.name)
        self.assertRegex(path.name, r"^[a-z0-9-]+\.md$")
        # Nothing leaked above the root.
        self.assertFalse((self.tmp / "evil").exists())
        self.assertFalse((self.lib / "evil").exists())
        self.assertFalse(any(p.name == "passwd" for p in self.tmp.rglob("*")))

    # 3. never overwrites an existing note
    def test_no_overwrite(self):
        jr_teach.switchboard.ask_claude_sub = stub_ok(title="Same Name", body="first body content")
        jr_teach.secrets.token_hex = lambda n=3: "abc123"   # force an identical filename each time
        first = jr_teach.save_taught("first answer long enough to save", context="c")
        first_path = pathlib.Path(first["path"])
        original = first_path.read_text(encoding="utf-8")
        # A second save that would land on the same name must NOT clobber the first.
        jr_teach.switchboard.ask_claude_sub = stub_ok(title="Same Name", body="SECOND body content")
        with self.assertRaises(Exception):
            jr_teach.save_taught("second answer long enough to save", context="c")
        self.assertEqual(first_path.read_text(encoding="utf-8"), original,
                         "the first note was left untouched")

    # 4. oversized body is capped
    def test_body_is_capped(self):
        huge = "x" * (jr_teach.MAX_BODY_CHARS + 50_000)
        jr_teach.switchboard.ask_claude_sub = stub_ok(title="Big", keywords=(), body=huge)
        result = jr_teach.save_taught("teach this big answer", context="c")
        body_written = pathlib.Path(result["path"]).read_text(encoding="utf-8")
        # File = small header + capped body; nowhere near the 60k input.
        self.assertLessEqual(len(body_written), jr_teach.MAX_BODY_CHARS + 500)
        self.assertLessEqual(len(result["preview"]), jr_teach.PREVIEW_CHARS)

    # 5. distill failure falls back to a raw truncated save
    def test_distill_failure_falls_back(self):
        jr_teach.switchboard.ask_claude_sub = stub_raises()
        answer = "First line becomes the title\nThen the rest of the raw answer body follows here."
        result = jr_teach.save_taught(answer, context="c")
        self.assertTrue(result["ok"])
        content = pathlib.Path(result["path"]).read_text(encoding="utf-8")
        self.assertIn("# First line becomes the title", content)
        self.assertIn("the rest of the raw answer body", content)

    def test_distill_failure_still_caps_body(self):
        jr_teach.switchboard.ask_claude_sub = stub_raises()
        huge = "raw " * 40_000        # ~160k chars, far over the cap
        result = jr_teach.save_taught(huge, context="c")
        content = pathlib.Path(result["path"]).read_text(encoding="utf-8")
        self.assertLessEqual(len(content), jr_teach.MAX_BODY_CHARS + 500)

    # 6. the produced note contains no em dash, even when the model returns them
    def test_no_em_dash(self):
        jr_teach.switchboard.ask_claude_sub = stub_ok(
            title=f"Firewalls {EM_DASH} a primer",
            keywords=(f"nat{EM_DASH}rules",),
            body=f"A firewall {EM_DASH} the gatekeeper {EM_DASH} filters traffic{EN_DASH}by rules.")
        result = jr_teach.save_taught("teach me firewalls", context=f"why {EM_DASH} firewalls")
        content = pathlib.Path(result["path"]).read_text(encoding="utf-8")
        self.assertNotIn(EM_DASH, content, "no em dash survives into the saved note")
        self.assertNotIn(EM_DASH, result["title"])

    # empty text is refused before any file is written
    def test_empty_text_refused(self):
        jr_teach.switchboard.ask_claude_sub = stub_ok()
        with self.assertRaises(ValueError):
            jr_teach.save_taught("   ", context="c")
        with self.assertRaises(ValueError):
            jr_teach.save_taught(None, context="c")


if __name__ == "__main__":
    unittest.main(verbosity=2)
