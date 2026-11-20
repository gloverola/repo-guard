"""`check <github-url>` (archive scan, network mocked) and `--deps` (OSV, mocked)."""

import io
import json
import tarfile
import unittest
from unittest import mock

import tests  # noqa: F401
from tests.helpers import captured
from repo_guard import deps, remote
from repo_guard.cli import main
from repo_guard.fixtures import bad_files, clean_files


def tarball(files, prefix="repo-abc123/"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, data in files.items():
            if isinstance(data, tuple):
                data = data[0]
            info = tarfile.TarInfo(prefix + path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo(prefix + "evil-link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tar.addfile(link)
    return buf.getvalue()


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class ParseUrl(unittest.TestCase):
    def test_forms(self):
        p = remote.parse_github
        self.assertEqual(p("owner/repo"), ("owner", "repo", None))
        self.assertEqual(p("https://github.com/owner/repo.git"), ("owner", "repo", None))
        self.assertEqual(p("https://github.com/owner/repo/tree/feature/x"), ("owner", "repo", "feature/x"))
        self.assertEqual(p("git@github.com:owner/repo.git"), ("owner", "repo", None))
        with self.assertRaises(remote.CheckError):
            p("https://gitlab.com/a/b")


class Check(unittest.TestCase):
    def fake_open(self, archives):
        calls = []

        def _open(url, timeout=60):
            calls.append(url)
            if "/branches" in url:
                return FakeResp(json.dumps([{"name": "main"}, {"name": "evil"}]).encode())
            ref = url.rsplit("/", 1)[-1][:-len(".tar.gz")]
            return FakeResp(archives[ref])
        return _open, calls

    def test_infected_branch_found(self):
        archives = {"HEAD": tarball(clean_files()), "main": tarball(clean_files()), "evil": tarball(bad_files())}
        _open, calls = self.fake_open(archives)
        with mock.patch.object(remote, "_open", _open):
            findings, n, label = remote.check("o/r", all_branches=True)
        self.assertEqual(label, "o/r")
        self.assertEqual(n, 2)
        self.assertTrue(all(c.startswith("https://") for c in calls))
        hidden = [f for f in findings if f.rule == "hidden-code"]
        self.assertEqual(hidden[0].where, ["evil"])
        self.assertIn("committed-secret", {f.rule for f in findings})

    def test_cli_exit_codes(self):
        _open, _ = self.fake_open({"HEAD": tarball(clean_files())})
        with mock.patch.object(remote, "_open", _open), captured() as (out, _):
            self.assertEqual(main(["check", "o/r"]), 0)
        self.assertIn("nothing cloned", out.getvalue())
        _open, _ = self.fake_open({"HEAD": tarball(bad_files())})
        with mock.patch.object(remote, "_open", _open), captured():
            self.assertEqual(main(["check", "https://github.com/o/r", "--format", "json"]), 1)

    def test_archive_size_limit(self):
        _open, _ = self.fake_open({"HEAD": tarball(clean_files())})
        with mock.patch.object(remote, "_open", _open), mock.patch.object(remote, "MAX_ARCHIVE", 100):
            with self.assertRaises(remote.CheckError):
                remote.check("o/r")

    def test_download_error_is_reported(self):
        def boom(url, timeout=60):
            raise OSError("network down")
        with mock.patch.object(remote, "_open", boom):
            findings, n, _ = remote.check("o/r")
        self.assertEqual(n, 0)
        self.assertEqual([f.rule for f in findings], ["scan-error"])


J = "".join
LOCKS = {
    "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/@scope/evil": {"version": "6.6.6"}}}).encode(),
    "pnpm-lock.yaml": b"lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {}\n"
                      b"  '@scope/evil@6.6.6':\n    resolution: {}\n",
    "yarn.lock": b'"@scope/evil@^6.0.0":\n  version "6.6.6"\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n',
    "requirements.txt": b"requests==2.32.3\nevil-pkg[extra]==0.0.1  # pinned\n-e .\n",
    "poetry.lock": b'[[package]]\nname = "evil-pkg"\nversion = "0.0.1"\n\n[[package]]\nname = "ok"\nversion = "1"\n',
}


class Deps(unittest.TestCase):
    def test_parsers(self):
        self.assertIn(("npm", "@scope/evil", "6.6.6"), deps.parse("package-lock.json", LOCKS["package-lock.json"]))
        self.assertIn(("npm", "@scope/evil", "6.6.6"), deps.parse("pnpm-lock.yaml", LOCKS["pnpm-lock.yaml"]))
        self.assertIn(("npm", "left-pad", "1.3.0"), deps.parse("pnpm-lock.yaml", LOCKS["pnpm-lock.yaml"]))
        self.assertEqual(deps.parse("yarn.lock", LOCKS["yarn.lock"]),
                         {("npm", "@scope/evil", "6.6.6"), ("npm", "left-pad", "1.3.0")})
        self.assertEqual(deps.parse("requirements.txt", LOCKS["requirements.txt"]),
                         {("PyPI", "requests", "2.32.3"), ("PyPI", "evil-pkg", "0.0.1")})
        self.assertIn(("PyPI", "evil-pkg", "0.0.1"), deps.parse("poetry.lock", LOCKS["poetry.lock"]))

    def test_only_malware_advisories_reported(self):
        def fake_post(url, payload, timeout=30):
            self.assertEqual(url, deps.OSV_BATCH)
            results = []
            for q in payload["queries"]:
                if q["package"]["name"] in ("@scope/evil", "evil-pkg"):
                    results.append({"vulns": [{"id": "MAL-2026-1"}, {"id": "GHSA-x"}]})
                elif q["package"]["name"] == "requests":
                    results.append({"vulns": [{"id": "GHSA-not-malware"}]})
                else:
                    results.append({})
            return {"results": results}
        with mock.patch.object(deps, "_post_json", fake_post):
            out = deps.check_files(LOCKS)
        bad = [f for f in out if f.sev == "HIGH"]
        self.assertEqual({f.path for f in bad}, set(LOCKS))
        self.assertTrue(all("MAL-2026-1" in f.detail and "GHSA" not in f.detail for f in bad))

    def test_network_failure_is_not_silent(self):
        def boom(*a, **k):
            raise OSError("offline")
        with mock.patch.object(deps, "_post_json", boom):
            out = deps.check_files({"requirements.txt": b"a==1\n"})
        self.assertEqual([f.rule for f in out], ["scan-error"])


if __name__ == "__main__":
    unittest.main()
