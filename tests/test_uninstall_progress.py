"""`repo-guard uninstall` and the progress spinner."""

import io
import os
import subprocess
import sys
import time
import unittest
from unittest import mock

from tests import ROOT
from tests.helpers import TempDirTest
from tests.test_protection import BOOT, global_get
from repo_guard import allow, hooks, progress, uninstall as un


class Uninstall(TempDirTest):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(hooks, "self_command", return_value=BOOT)
        p.start()
        self.addCleanup(p.stop)
        self.home = self.path("home")
        os.makedirs(self.home)
        self.zshrc = os.path.join(self.home, ".zshrc")
        with open(self.zshrc, "w") as fh:
            fh.write("export A=1\n%s\nfunction git { :; }\n%s\nalias ll='ls -l'\n" % (un.BEGIN, un.END))
        os.chmod(self.zshrc, 0o600)

    def test_detects_install_method(self):
        self.assertEqual(un.install_method("/x/bin/repo-guard", "/Users/u/.local/pipx/venvs/git-repo-guard")[0],
                         "pipx")
        self.assertEqual(un.install_method("/x", "/opt/homebrew/Cellar/repo-guard/1.0.0/libexec")[0], "brew")
        self.assertEqual(un.removal_command("pipx", ""), ["pipx", "uninstall", "git-repo-guard"])

    def test_removes_everything(self):
        with mock.patch("sys.stdout", io.StringIO()):
            hooks.setup()
        with open(allow.allow_path(), "w") as fh:
            fh.write("* *\n")
        self.assertTrue(global_get("init.templateDir"))
        calls = []
        with mock.patch.object(un, "install_method", return_value=("pipx", "/p")):
            code = un.uninstall(yes=True, home=self.home, out=io.StringIO(),
                                run=lambda cmd: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0))
        self.assertEqual(code, 0)
        self.assertEqual(calls, [["pipx", "uninstall", "git-repo-guard"]])
        self.assertIsNone(global_get("init.templateDir"))
        self.assertFalse(os.path.exists(allow.config_dir()))
        with open(self.zshrc) as fh:
            self.assertEqual(fh.read(), "export A=1\nalias ll='ls -l'\n")
        if os.name != "nt":
            self.assertEqual(os.stat(self.zshrc).st_mode & 0o777, 0o600)

    def test_keep_allowlist_and_decline(self):
        os.makedirs(allow.config_dir(), exist_ok=True)
        with open(os.path.join(allow.config_dir(), "allow"), "w") as fh:
            fh.write("* *\n")
        out = io.StringIO()
        with mock.patch.object(un, "install_method", return_value=("source", "")):
            self.assertEqual(un.uninstall(home=self.home, out=out, inp=io.StringIO("n\n")), 1)
            with open(self.zshrc) as fh:
                self.assertIn(un.BEGIN, fh.read())
            self.assertEqual(un.uninstall(yes=True, keep_allowlist=True, home=self.home, out=out), 0)
        self.assertTrue(os.path.exists(os.path.join(allow.config_dir(), "allow")))
        os.remove(os.path.join(allow.config_dir(), "allow"))

    def test_zipapp_is_deleted(self):
        if os.name == "nt":
            self.skipTest("Windows defers to install.ps1 -Uninstall")
        pyz = self.path("repo-guard")
        subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "build_pyz.py"), pyz], check=True)
        with mock.patch.object(un, "install_method", return_value=("zipapp", pyz)):
            un.uninstall(yes=True, home=self.home, out=io.StringIO())
        self.assertFalse(os.path.exists(pyz))


class FakeTty(io.StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


class Progress(unittest.TestCase):
    def test_spinner_on_tty_only(self):
        tty = FakeTty()
        with mock.patch.dict(os.environ, {"CI": "", "REPO_GUARD_NO_PROGRESS": "", "TERM": "xterm"}):
            with progress.spinning("scanning x", stream=tty):
                progress.status("files 3")
                time.sleep(0.35)
        text = tty.getvalue()
        self.assertIn("scanning x · files 3", text)
        self.assertTrue(text.endswith("\r\033[K"))  # line cleared before results print
        plain = io.StringIO()
        with progress.spinning("scanning x", stream=plain):
            progress.status("files 3")
        self.assertEqual(plain.getvalue(), "")

    def test_disabled_by_env(self):
        tty = FakeTty()
        with mock.patch.dict(os.environ, {"REPO_GUARD_NO_PROGRESS": "1"}):
            with progress.spinning("x", stream=tty):
                time.sleep(0.15)
        self.assertEqual(tty.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
