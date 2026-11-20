import json
import os
import unittest

from tests import ROOT
from tests.helpers import TempDirTest, captured, make_repo
from repo_guard.cli import main
from repo_guard.fixtures import bad_files, clean_files


def run(*argv):
    with captured() as (out, err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Scan(TempDirTest):
    def setUp(self):
        super().setUp()
        self.bad, self.clean = self.path("bad"), self.path("clean")
        make_repo(self.bad, bad_files())
        make_repo(self.clean, clean_files())

    def test_exit_codes(self):
        self.assertEqual(run("scan", self.clean)[0], 0)
        self.assertEqual(run("scan", self.bad)[0], 1)
        self.assertEqual(run("scan", self.path("missing"))[0], 2)
        self.assertEqual(run("scan", self.clean, "--fail-on", "info")[0], 1)  # install-script INFO
        self.assertEqual(run("scan", self.bad, "--fail-on", "never")[0], 0)

    def test_json(self):
        code, out, _ = run("scan", self.bad, "--format", "json")
        doc = json.loads(out)
        self.assertEqual(code, 1)
        res = doc["results"][0]
        self.assertGreater(res["summary"]["high"], 5)
        self.assertTrue(all({"severity", "rule", "path", "message"} <= set(f) for f in res["findings"]))

    def test_sarif(self):
        out_file = self.path("r.sarif")
        code, _, _ = run("scan", self.bad, "--format", "sarif", "--output", out_file)
        self.assertEqual(code, 1)
        with open(out_file) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["version"], "2.1.0")
        run0 = doc["runs"][0]
        ids = [r["id"] for r in run0["tool"]["driver"]["rules"]]
        for res in run0["results"]:
            self.assertEqual(ids[res["ruleIndex"]], res["ruleId"])
            self.assertIn(res["level"], ("error", "warning", "note"))
            self.assertFalse(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/"))

    def test_user_allowlist(self):
        allow_file = os.environ["REPO_GUARD_ALLOW_FILE"]
        self.addCleanup(lambda: os.path.exists(allow_file) and os.remove(allow_file))
        with open(allow_file, "w") as fh:
            fh.write("# test\n* *  %s\n" % self.bad.replace("\\", "/"))
        code, out, _ = run("scan", self.bad)
        self.assertEqual(code, 0)
        self.assertIn("hidden by your allowlist", out)
        with open(allow_file, "w") as fh:
            fh.write("* *  /some/other/repo\n")
        self.assertEqual(run("scan", self.bad)[0], 1)

    def test_repo_cannot_allowlist_itself(self):
        for name in (".repo-guard-allow", ".repo-guard/allow", "allow", ".config/repo-guard/allow"):
            p = os.path.join(self.bad, *name.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write("* *\n")
        self.assertEqual(run("scan", self.bad)[0], 1)

    def test_scan_all(self):
        code, out, _ = run("scan-all", self.tmp)
        self.assertEqual(code, 1)
        self.assertIn("2 repos scanned", out)
        self.assertIn(self.bad, out)
        self.assertNotIn("repo-guard: " + self.clean + "\n", out)

    def test_rules_and_version(self):
        code, out, _ = run("rules", "--format", "json")
        self.assertEqual(code, 0)
        self.assertGreater(len(json.loads(out)), 30)
        with self.assertRaises(SystemExit):
            run("--version")


class SelfScan(unittest.TestCase):
    def test_repo_guard_never_flags_itself(self):
        from repo_guard.scanner import scan_worktree
        bad = [f for f in scan_worktree(ROOT) if f.sev != "INFO" and not f.path.startswith(".git")
               and f.rule not in ("local-git-hook", "local-git-config", "force-push")]
        self.assertEqual(bad, [])


class Docs(unittest.TestCase):
    def test_every_rule_documented(self):
        from repo_guard.rules import RULES
        with open(os.path.join(ROOT, "docs", "rules.md"), encoding="utf-8") as fh:
            doc = fh.read()
        for rid in RULES:
            self.assertIn("\n### %s\n" % rid, doc)

    def test_version_in_changelog(self):
        from repo_guard import __version__
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
            self.assertIn("## [%s]" % __version__, fh.read())


class SelfTest(unittest.TestCase):
    def test_selftest_passes(self):
        code, out, _ = run("selftest")
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
