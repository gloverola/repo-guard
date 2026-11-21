"""`repo-guard check <github-url>`: scan a repo before cloning it. Downloads the source
archive over HTTPS and reads it in memory. No git, nothing extracted, nothing run."""

import json
import os
import re
import tarfile
import urllib.parse
import urllib.request

from .findings import INFO, MEDIUM, Finding
from .progress import status
from .rules import MAX_BLOB, SKIP_DIRS, scan_content

MAX_ARCHIVE = 300 * 1024 * 1024
MAX_BRANCHES = 30
USER_AGENT = "repo-guard (+https://github.com/gloverola/repo-guard)"


class CheckError(Exception):
    pass


def parse_github(spec):
    """Return (owner, repo, ref or None)."""
    s = spec.strip()
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/(.+?))?/?$", s) or \
        re.match(r"^git@github\.com:([\w.-]+)/([\w.-]+?)(?:\.git)?()$", s) or \
        re.match(r"^([\w.-]+)/([\w.-]+?)()$", s)
    if not m:
        raise CheckError("not a GitHub repository: %s (use owner/repo or https://github.com/owner/repo)" % spec)
    return m.group(1), m.group(2), m.group(3) or None


def _headers():
    h = {"User-Agent": USER_AGENT}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


def _open(url, timeout=60):
    return urllib.request.urlopen(urllib.request.Request(url, headers=_headers()), timeout=timeout)  # noqa: S310


class _Limited:
    """File wrapper that stops reading past MAX_ARCHIVE bytes."""

    def __init__(self, fh, limit):
        self.fh, self.left = fh, limit

    def read(self, n=-1):
        if self.left <= 0:
            raise CheckError("archive is larger than %d MB; clone it with `repo-guard clone` instead"
                             % (MAX_ARCHIVE // 1048576))
        n = self.left if n is None or n < 0 else min(n, self.left)
        data = self.fh.read(n)
        self.left -= len(data)
        return data


def iter_archive(fileobj):
    """Yield (path, bytes) for each regular file in a .tar.gz stream, without extracting."""
    with tarfile.open(fileobj=fileobj, mode="r|gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            path = member.name.split("/", 1)[1] if "/" in member.name else member.name
            if not path or any(part in SKIP_DIRS for part in path.split("/")[:-1]):
                continue
            if member.size > MAX_BLOB:
                continue
            fh = tar.extractfile(member)
            if fh is not None:
                yield path, fh.read()


def scan_archive(fileobj, label, want_deps=False):
    from .deps import is_lockfile
    findings, locks = [], {}
    n = 0
    for path, data in iter_archive(fileobj):
        n += 1
        status("%s: scanned %d files" % (label, n))
        for f in scan_content(path, data, committed=True):
            f.where = [label]
            findings.append(f)
        if want_deps and is_lockfile(path.rsplit("/", 1)[-1]):
            locks[path] = data
    return findings, locks, n


def list_branches(owner, repo):
    url = "https://api.github.com/repos/%s/%s/branches?per_page=100" % (owner, repo)
    with _open(url) as resp:
        return [b["name"] for b in json.loads(resp.read().decode())]


def check(spec, refs=None, all_branches=False, want_deps=False):
    """Return (findings, refs_scanned, target_label)."""
    owner, repo, ref = parse_github(spec)
    wanted = list(refs or [])
    if ref:
        wanted.append(ref)
    names = []
    if all_branches:
        try:
            names = list_branches(owner, repo)
        except (OSError, ValueError) as e:
            raise CheckError("could not list branches: %s" % e)
        wanted += names[:MAX_BRANCHES]
    wanted = wanted or ["HEAD"]
    findings, locks, scanned = [], {}, 0
    for r in dict.fromkeys(wanted):
        status("downloading %s/%s@%s" % (owner, repo, r))
        url = "https://github.com/%s/%s/archive/%s.tar.gz" % (owner, repo, urllib.parse.quote(r, safe=""))
        try:
            with _open(url) as resp:
                f, lk, _ = scan_archive(_Limited(resp, MAX_ARCHIVE), r, want_deps)
        except (OSError, tarfile.TarError) as e:
            findings.append(Finding(MEDIUM, "scan-error", r, "could not download or read the archive: %s"
                                    % str(e)[:120]))
            continue
        findings += f
        for p, d in lk.items():
            locks.setdefault(p, d)
        scanned += 1
    if len(names) > MAX_BRANCHES:
        findings.append(Finding(INFO, "scan-error", "(branches)", "only the first %d branches were scanned"
                                % MAX_BRANCHES))
    if want_deps and locks:
        from .deps import check_files
        findings += check_files(locks)
    return findings, scanned, "%s/%s" % (owner, repo)
