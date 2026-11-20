import os
import unittest

from tests.helpers import TempDirTest, git_run, make_repo, rules_of
from repo_guard.findings import INFO, MEDIUM
from repo_guard.fixtures import bad_files, clean_files
from repo_guard.scanner import check_history, scan_refs, scan_repo, scan_worktree

J = "".join


class RefsScan(TempDirTest):
    def test_infected_branch_found_without_checkout(self):
        repo = self.path("r")
        make_repo(repo, {"src/a.js": b"export const a = 1;\n"})
        git_run(repo, "checkout", "-q", "-b", "evil")
        data, _ = bad_files()["eslint.config.js"]
        with open(os.path.join(repo, "eslint.config.js"), "wb") as fh:
            fh.write(data)
        git_run(repo, "add", "-A")
        git_run(repo, "commit", "-q", "-m", "x")
        git_run(repo, "checkout", "-q", "main")
        self.assertNotIn("hidden-code", rules_of(scan_worktree(repo)))
        findings, nrefs = scan_refs(repo)
        self.assertEqual(nrefs, 2)
        hit = [f for f in findings if f.rule == "hidden-code"]
        self.assertEqual(hit[0].where, ["evil"])

    def test_same_blob_under_two_names(self):
        js, _ = bad_files()["public/fonts/x.woff2"]
        repo = self.path("r")
        make_repo(repo, {"lib/ok.js": js, "fonts/a.woff2": js})
        found = [f for f in scan_refs(repo)[0] if f.rule == "fake-asset"]
        self.assertEqual([f.path for f in found], ["fonts/a.woff2"])

    def test_unreadable_ref_is_an_error_not_clean(self):
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        with open(os.path.join(repo, ".git", "refs", "heads", "broken"), "w") as fh:
            fh.write("1" * 40 + "\n")
        findings, _ = scan_refs(repo)
        self.assertIn("scan-error", rules_of(findings))
        self.assertTrue(any(f.sev == MEDIUM for f in findings if f.rule == "scan-error"))

    def test_clean_repo(self):
        repo = self.path("r")
        make_repo(repo, clean_files())
        findings, _ = scan_repo(repo)
        self.assertEqual([f for f in findings if f.sev != INFO], [])


class LocalGit(TempDirTest):
    def test_hooks_and_config(self):
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        os.makedirs(os.path.join(repo, ".git", "hooks"), exist_ok=True)
        with open(os.path.join(repo, ".git", "hooks", "post-merge"), "w") as fh:
            fh.write("#!/bin/sh\necho hi\n")
        git_run(repo, "config", "core.fsmonitor", "./x")
        found = rules_of(scan_worktree(repo))
        self.assertIn("local-git-hook", found)
        self.assertIn("local-git-config", found)

    def test_own_hook_not_flagged(self):
        from repo_guard.hooks import render_hook
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        os.makedirs(os.path.join(repo, ".git", "hooks"), exist_ok=True)
        with open(os.path.join(repo, ".git", "hooks", "post-checkout"), "w", newline="\n") as fh:
            fh.write(render_hook("post-checkout", ["/opt/somewhere/repo-guard"]))
        self.assertNotIn("local-git-hook", rules_of(scan_worktree(repo)))
        with open(os.path.join(repo, ".git", "hooks", "post-checkout"), "a") as fh:
            fh.write("curl x\n")  # tampered copy
        self.assertIn("local-git-hook", rules_of(scan_worktree(repo)))

    def test_force_push_reflog(self):
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        logs = os.path.join(repo, ".git", "logs", "refs", "remotes", "origin")
        os.makedirs(logs)
        with open(os.path.join(logs, "main"), "w") as fh:
            fh.write("a b c <d> 1 +0000\tfetch: forced-update\n")
        hit = [f for f in scan_worktree(repo) if f.rule == "force-push"]
        self.assertEqual(hit[0].sev, MEDIUM)


class History(TempDirTest):
    def test_rewritten_commit_touching_flagged_file(self):
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        data, _ = bad_files()["eslint.config.js"]
        with open(os.path.join(repo, "eslint.config.js"), "wb") as fh:
            fh.write(data)
        git_run(repo, "add", "-A")
        env = {"GIT_AUTHOR_DATE": "2026-01-01T10:00:00+0100", "GIT_COMMITTER_DATE": "2026-11-18T03:00:00-0500"}
        git_run(repo, "commit", "-q", "-m", "update", env=env)
        out = check_history(repo, {"eslint.config.js"})
        self.assertEqual([(f.rule, f.sev, f.path) for f in out], [("rewritten-commit", MEDIUM, "eslint.config.js")])
        self.assertEqual([f.sev for f in check_history(repo, set())], [INFO])

    def test_normal_history_quiet(self):
        repo = self.path("r")
        make_repo(repo, {"a.txt": b"hi\n"})
        self.assertEqual(check_history(repo, set()), [])


if __name__ == "__main__":
    unittest.main()
