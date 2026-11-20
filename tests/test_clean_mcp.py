"""`repo-guard clean` and the MCP server."""

import io
import json
import os
import unittest

from tests.helpers import TempDirTest, captured, git_run, make_repo
from repo_guard import mcp
from repo_guard.clean import clean, plan_clean
from repo_guard.fixtures import bad_files
from repo_guard.scanner import scan_worktree

J = "".join
PAD = " " * 300


def infect(repo):
    """Write a PolinRider-style infection into a clean, committed repo."""
    files = {
        "eslint.config.js": "export default [];\n" + PAD + J(["glo", 'bal.i="A11";eval(1)']) + "\n",
        "init": bad_files()["init"][0].decode(),
        "package.json": '{\n  "scripts": {\n    "dev": "%s vite",\n    "build": "vite build"\n  }\n}\n'
                        % J(["no", "de init &&"]),
        ".vscode/tasks.json": J(['{"tasks":[{"label":"x","command":"node init","runOptions":{"runOn":"folder',
                                 'Open"}}]}']),
        ".gitignore": J(["node_modules\ntemp_auto_", "push.bat\nbranch_struct", "ure.json\nconfig.bat\n"]),
    }
    for rel, text in files.items():
        full = os.path.join(repo, *rel.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", newline="\n") as fh:
            fh.write(text)


class Clean(TempDirTest):
    def setUp(self):
        super().setUp()
        self.repo = self.path("r")
        make_repo(self.repo, {"eslint.config.js": b"export default [];\n", "package.json":
                              b'{\n  "scripts": {\n    "dev": "vite",\n    "build": "vite build"\n  }\n}\n',
                              ".gitignore": b"node_modules\n.env\n.vscode/\n"})
        infect(self.repo)
        git_run(self.repo, "add", "-A", "-f")
        git_run(self.repo, "commit", "-q", "-m", "infected")

    def read(self, rel):
        with open(os.path.join(self.repo, rel), "rb") as fh:
            return fh.read()

    def test_plan(self):
        plan = plan_clean(self.repo)
        self.assertEqual(sorted(plan.deletes), [".vscode/tasks.json", "init"])
        self.assertEqual(plan.changes["eslint.config.js"], b"export default [];\n")
        self.assertIn(b'"dev": "vite"', plan.changes["package.json"])
        gi = plan.changes[".gitignore"].decode()
        self.assertNotIn("push.bat", gi)
        self.assertNotIn("config.bat", gi)
        self.assertIn(".env", gi.split())       # restored from history
        self.assertIn(".vscode/", gi.split())

    def test_no_confirmation_changes_nothing(self):
        before = self.read("eslint.config.js")
        out = io.StringIO()
        self.assertEqual(clean(self.repo, out=out, inp=io.StringIO("n\n")), 1)
        self.assertEqual(self.read("eslint.config.js"), before)
        self.assertIn("delete  init", out.getvalue())
        self.assertIn("Nothing changed", out.getvalue())

    def test_confirm_applies_and_rescans_clean(self):
        out = io.StringIO()
        self.assertEqual(clean(self.repo, out=out, inp=io.StringIO("y\n")), 0, out.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self.repo, "init")))
        self.assertEqual([f for f in scan_worktree(self.repo) if f.sev != "INFO"], [])

    def test_nothing_to_do(self):
        clean_repo = self.path("ok")
        make_repo(clean_repo, {"a.js": b"export const a = 1;\n"})
        with captured():
            self.assertEqual(clean(clean_repo, yes=True), 0)


class Mcp(TempDirTest):
    def call(self, *msgs):
        inp = io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))
        out = io.StringIO()
        mcp.serve(inp, out)
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_handshake_and_tools(self):
        r = self.call({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "0"}}},
                      {"jsonrpc": "2.0", "method": "notifications/initialized"},
                      {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                      {"jsonrpc": "2.0", "id": 3, "method": "nope"})
        self.assertEqual(len(r), 3)  # no reply to the notification
        self.assertEqual(r[0]["result"]["protocolVersion"], "2025-06-18")
        names = {t["name"] for t in r[1]["result"]["tools"]}
        self.assertEqual(names, {"check_github_repo", "scan_local_repo", "safe_clone", "list_rules"})
        self.assertEqual(r[2]["error"]["code"], -32601)

    def test_scan_local_repo(self):
        repo = self.path("bad")
        make_repo(repo, bad_files())
        r = self.call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "scan_local_repo", "arguments": {"path": repo}}})
        res = r[0]["result"]
        self.assertFalse(res["isError"])
        self.assertEqual(res["structuredContent"]["verdict"], "infected")
        self.assertIn("INFECTED", res["content"][0]["text"])

    def test_bad_calls(self):
        r = self.call({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}},
                      {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "scan_local_repo", "arguments": {}}})
        self.assertEqual(r[0]["error"]["code"], -32602)
        self.assertTrue(r[1]["result"]["isError"])

    def test_safe_clone(self):
        src = self.path("src")
        make_repo(src, bad_files())
        r = self.call({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "safe_clone", "arguments": {"url": src, "directory": self.path("c")}}})
        res = r[0]["result"]
        self.assertEqual(res["structuredContent"]["exit_code"], 1)
        self.assertEqual(os.listdir(self.path("c")), [".git"])


if __name__ == "__main__":
    unittest.main()
