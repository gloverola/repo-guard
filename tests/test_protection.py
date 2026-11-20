"""Milestone 3: template hooks (setup), hardened clone, pre-commit."""

import os
import subprocess
import sys
import unittest
from unittest import mock

from tests import SRC
from tests.helpers import TempDirTest, captured, chdir, git_run, make_repo
from repo_guard import hooks
from repo_guard.clone import clone, parse_args
from repo_guard.fixtures import bad_files, clean_files
from repo_guard.gitutil import git_env

BOOT = [sys.executable, "-I", "-c",
        "import sys; sys.path.insert(0, %r); from repo_guard.cli import main; sys.exit(main())" % SRC]


def global_get(key):
    r = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, env=git_env())
    return r.stdout.decode().strip() or None


class Setup(TempDirTest):
    def setUp(self):
        super().setUp()
        self.addCleanup(lambda: subprocess.run(["git", "config", "--global", "--unset", "init.templateDir"],
                                               capture_output=True))
        p = mock.patch.object(hooks, "self_command", return_value=BOOT)
        p.start()
        self.addCleanup(p.stop)

    def test_setup_merges_existing_template_and_uninstall_restores(self):
        mine = self.path("my-template")
        os.makedirs(os.path.join(mine, "hooks"))
        with open(os.path.join(mine, "description"), "w") as fh:
            fh.write("mine\n")
        with open(os.path.join(mine, "hooks", "post-checkout"), "w", newline="\n") as fh:
            fh.write("#!/bin/sh\necho chained-ran > \"$(git rev-parse --show-toplevel)/chained.txt\"\n")
        os.chmod(os.path.join(mine, "hooks", "post-checkout"), 0o755)
        subprocess.run(["git", "config", "--global", "init.templateDir", mine], check=True)

        with captured():
            self.assertEqual(hooks.setup(), 0)
            self.assertEqual(hooks.setup(), 0)  # idempotent: keeps the original previous dir
        tdir = hooks.template_dir()
        self.assertEqual(global_get("init.templateDir"), tdir)
        self.assertTrue(os.path.isfile(os.path.join(tdir, "description")))
        self.assertTrue(os.path.isfile(os.path.join(tdir, "hooks", "post-checkout.chained")))
        self.assertTrue(hooks.is_own_hook(os.path.join(tdir, "hooks", "pre-commit")))

        # A plain clone of a clean repo: our hook passes, then the chained user hook runs.
        src = self.path("src")
        make_repo(src, clean_files())
        subprocess.run(["git", "clone", "-q", src, self.path("c1")], check=True, capture_output=True, env=git_env())
        self.assertTrue(os.path.exists(self.path("c1", "src", "index.js")))
        self.assertTrue(os.path.exists(self.path("c1", "chained.txt")))

        with captured():
            hooks.uninstall()
        self.assertEqual(global_get("init.templateDir"), mine)
        self.assertFalse(os.path.exists(tdir))

    def test_quarantine_on_plain_clone(self):
        with captured():
            hooks.setup()
        src = self.path("src")
        make_repo(src, bad_files())
        r = subprocess.run(["git", "clone", "-q", src, self.path("c")], capture_output=True, env=git_env())
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(sorted(os.listdir(self.path("c"))), [".git", hooks.QUARANTINE_FILE])
        self.assertIn(b"QUARANTINED", r.stderr)
        # the user can still restore after review
        git_run(self.path("c"), "reset", "-q", "--hard")
        self.assertTrue(os.path.exists(self.path("c", "eslint.config.js")))

    def test_off_switch(self):
        with captured():
            hooks.setup()
        src = self.path("src")
        make_repo(src, bad_files())
        subprocess.run(["git", "clone", "-q", src, self.path("c")], capture_output=True,
                       env=git_env({"REPO_GUARD_OFF": "1"}))
        self.assertTrue(os.path.exists(self.path("c", "eslint.config.js")))

    def test_status(self):
        with captured():
            self.assertEqual(hooks.status(), 1)
            hooks.setup()
            self.assertEqual(hooks.status(), 0)


class PostMerge(TempDirTest):
    def test_pull_of_infected_change_warns(self):
        src = self.path("src")
        make_repo(src, {"a.txt": b"hi\n"})
        git_run(self.tmp, "clone", "-q", src, self.path("c"))
        data, _ = bad_files()["eslint.config.js"]
        with open(os.path.join(src, "eslint.config.js"), "wb") as fh:
            fh.write(data)
        git_run(src, "add", "-A")
        git_run(src, "commit", "-q", "-m", "x")
        git_run(self.path("c"), "pull", "-q", "--ff-only")
        with chdir(self.path("c")), captured() as (_, err):
            self.assertEqual(hooks.hook_post_merge(["0"]), 0)
        self.assertIn("hidden-code", err.getvalue())


class PreCommit(TempDirTest):
    def test_blocks_infected_and_passes_clean(self):
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        with open(os.path.join(repo, "ok.js"), "w") as fh:
            fh.write("export const a = 1;\n")
        git_run(repo, "add", "ok.js")
        with chdir(repo), captured():
            self.assertEqual(hooks.pre_commit(), 0)
        data, _ = bad_files()["eslint.config.js"]
        with open(os.path.join(repo, "eslint.config.js"), "wb") as fh:
            fh.write(data)
        with chdir(repo), captured():
            self.assertEqual(hooks.pre_commit(), 0)  # not staged yet
        git_run(repo, "add", "eslint.config.js")
        with chdir(repo), captured() as (_, err):
            self.assertEqual(hooks.pre_commit(), 1)
            self.assertEqual(hooks.pre_commit(["ok.js"]), 0)  # pre-commit framework passes file names
        self.assertIn("commit blocked", err.getvalue())

    def test_staged_secret_blocks(self):
        repo = self.path("r")
        make_repo(repo, {}, commit=False)
        data, _ = bad_files()["src/keys.js"]
        os.makedirs(os.path.join(repo, "src"))
        with open(os.path.join(repo, "src", "keys.js"), "wb") as fh:
            fh.write(data)
        git_run(repo, "add", "-A")
        with chdir(repo), captured():
            self.assertEqual(hooks.pre_commit(), 1)


class HardenedClone(TempDirTest):
    def test_parse_args_drops_submodules(self):
        opts, passthru, pos, dropped = parse_args(["--recurse-submodules", "-b", "dev", "u", "d", "--force"])
        self.assertEqual(passthru, ["-b", "dev"])
        self.assertEqual(pos, ["u", "d"])
        self.assertEqual(dropped, ["--recurse-submodules"])
        self.assertTrue(opts["force"])

    def test_infected_branch_blocks_checkout(self):
        src = self.path("src")
        make_repo(src, clean_files())
        git_run(src, "checkout", "-q", "-b", "evil")
        data, _ = bad_files()[".vscode/tasks.json"]
        with open(os.path.join(src, ".vscode", "tasks.json"), "wb") as fh:
            fh.write(data)
        git_run(src, "commit", "-q", "-am", "x")
        git_run(src, "checkout", "-q", "main")
        with captured() as (out, _):
            code = clone([src, self.path("c"), "-q"], out=sys.stdout)
        self.assertEqual(code, 1)
        self.assertEqual(os.listdir(self.path("c")), [".git"])
        self.assertIn("auto-run-task", out.getvalue())
        with captured():
            self.assertEqual(clone([src, self.path("c2"), "-q", "--fail-on", "never"], out=sys.stdout), 0)
        self.assertTrue(os.path.exists(self.path("c2", "src", "index.js")))


if __name__ == "__main__":
    unittest.main()
