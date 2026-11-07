"""Tests for install_hooks.py and the two hooks, run inside a temp git repo that gets its own copy of
git-tools. Real commits are attempted so the hooks run the way git runs them.
Run with: python3 -m unittest test_install_hooks"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
GIT = shutil.which("git")
PY = sys.executable


@unittest.skipUnless(GIT, "git is not on PATH")
class InstallHooks(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="hooks test "))
        self.repo = self.tmp / "my agent"
        shutil.copytree(HERE, self.repo / "git-tools", ignore=shutil.ignore_patterns("__pycache__"))
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        self.env = dict(os.environ)
        self.env.pop("MARTY_PRIVATE_TERMS", None)
        self.env.pop("GIT_DIR", None)
        self.env.pop("GIT_WORK_TREE", None)
        self.env.pop("GIT_INDEX_FILE", None)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args, check=True):
        proc = subprocess.run([GIT, *args], cwd=self.repo, env=getattr(self, "env", None), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        if check:
            self.assertEqual(0, proc.returncode, proc.stdout)
        return proc.returncode, proc.stdout

    def install(self, *args):
        proc = subprocess.run([PY, str(self.repo / "git-tools" / "install_hooks.py"), *args], cwd=self.repo,
                              env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        return proc.returncode, proc.stdout

    def commit_file(self, name, content, message):
        (self.repo / name).write_text(content, encoding="utf-8")
        self.git("add", name)
        return self.git("commit", "-q", "-m", message, check=False)

    def test_install_verify_and_idempotent(self):
        code, out = self.install("--check")
        self.assertEqual(1, code, out)
        self.assertIn("unset", out)
        code, out = self.install()
        self.assertEqual(0, code, out)
        self.assertIn("set core.hooksPath = git-tools/hooks", out)
        self.assertIn("verified: git config --get core.hooksPath -> git-tools/hooks", out)
        _, value = self.git("config", "--get", "core.hooksPath")
        self.assertEqual("git-tools/hooks", value.strip())
        code, out = self.install()
        self.assertEqual(0, code, out)
        self.assertIn("already git-tools/hooks", out)
        self.assertNotIn("set core.hooksPath", out)
        code, out = self.install("--check")
        self.assertEqual(0, code, out)

    def test_replaces_other_hooks_path_and_restores_exec_bit(self):
        self.git("config", "core.hooksPath", ".githooks")
        if os.name != "nt":
            os.chmod(self.repo / "git-tools" / "hooks" / "pre-commit", 0o644)
        code, out = self.install()
        self.assertEqual(0, code, out)
        self.assertIn("replacing core.hooksPath '.githooks'", out)
        if os.name != "nt":
            self.assertIn("made executable", out)
            self.assertTrue(os.access(self.repo / "git-tools" / "hooks" / "pre-commit", os.X_OK))

    def test_missing_hook_file_is_reported(self):
        (self.repo / "git-tools" / "hooks" / "commit-msg").unlink()
        code, out = self.install()
        self.assertEqual(1, code)
        self.assertIn("missing hook file", out)
        _, value = self.git("config", "--get", "core.hooksPath", check=False)
        self.assertEqual("", value.strip())

    def test_crlf_hook_is_reported(self):
        path = self.repo / "git-tools" / "hooks" / "pre-commit"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        code, out = self.install()
        self.assertEqual(1, code)
        self.assertIn("CRLF", out)

    def test_hooks_block_and_allow_commits(self):
        code, out = self.install()
        self.assertEqual(0, code, out)
        code, out = self.commit_file("clean.txt", "nothing secret\n", "Add a clean file")
        self.assertEqual(0, code, out)
        code, out = self.commit_file("leak.py", 'KEY = "sk-abcdefghijklmnopqrstuvwxyz0123"\n', "Add a key")   # secret-scan: allow
        self.assertNotEqual(0, code)
        self.assertIn("leak.py:1: api-key (sk-a****)", out)
        self.assertIn("git commit --no-verify", out)
        self.assertIn("only Lukas", out)
        self.assertNotIn("bcdefghijklmnop", out)
        (self.repo / "leak.py").write_text("KEY = None\n", encoding="utf-8")
        self.git("add", "leak.py")
        code, out = self.git("commit", "-q", "-m", "Add a key \u2014 with a dash", check=False)
        self.assertNotEqual(0, code)
        self.assertIn("em dash", out)
        code, out = self.git("commit", "-q", "-F", os.devnull, check=False)
        self.assertNotEqual(0, code)
        self.assertIn("subject line is empty", out)
        code, out = self.git("commit", "-q", "-m", "# only a comment line\n\n", check=False)
        self.assertNotEqual(0, code)
        long_subject = "Add a key with a subject that is far longer than the sixty character convention allows"
        code, out = self.git("commit", "-q", "-m", long_subject + "\n\nBody says why.", check=False)
        self.assertEqual(0, code, out)
        self.assertIn("warning, the subject is", out)
        _, log = self.git("log", "--format=%s")
        self.assertEqual([long_subject, "Add a clean file"], log.splitlines())

    def test_missing_scanner_blocks_commit(self):
        self.install()
        self.git("commit", "-q", "--allow-empty", "-m", "Seed")
        (self.repo / "git-tools" / "secret_scan.py").unlink()
        code, out = self.commit_file("x.txt", "x\n", "Add x")
        self.assertNotEqual(0, code)
        self.assertIn("secret_scan.py is missing", out)


if __name__ == "__main__":
    unittest.main()
