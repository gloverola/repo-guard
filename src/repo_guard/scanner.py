"""Where files come from: the working tree, every branch and tag in git's object store,
the local git config and hooks, and commit history."""

import os
import re

from .findings import INFO, MEDIUM, Finding
from .progress import status
from .gitutil import BlobReader, blob_sizes, git, git_dir, is_git_repo
from .rules import MAX_BLOB, SKIP_DIRS, scan_content

NULL_SHA = "0" * 40


def scan_worktree(root):
    findings = []
    root = os.path.abspath(root)
    n = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            n += 1
            status("working files: %d" % n)
            try:
                if os.path.islink(full) or os.path.getsize(full) > MAX_BLOB:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            findings.extend(scan_content(rel, data))
    if is_git_repo(root):
        findings.extend(check_local_git(root))
    return findings


SUSPICIOUS_CONFIG = ("core.fsmonitor", "core.sshcommand", "core.pager", "core.editor",
                     "diff.external", "core.gitproxy", "sequence.editor")


def check_local_git(root):
    from .hooks import is_own_hook, is_template_hook  # late import: hooks imports this module

    out = []
    gd = git_dir(root)
    hooks = os.path.join(gd, "hooks")
    if os.path.isdir(hooks):
        for h in sorted(os.listdir(hooks)):
            full = os.path.join(hooks, h)
            if h.endswith(".sample") or not os.path.isfile(full) or is_own_hook(full) or is_template_hook(full):
                continue
            out.append(Finding(MEDIUM, "local-git-hook", ".git/hooks/" + h,
                               "active git hook (not part of the repo; check you installed it)"))
    cfg = git(root, "config", "--local", "--list", check=False).stdout.decode("utf-8", "replace")
    for line in cfg.splitlines():
        k = line.split("=", 1)[0].lower()
        if k in SUSPICIOUS_CONFIG or k.endswith(".insteadof") or k.startswith("credential.") or \
                k.startswith("alias.") or re.match(r"(?:filter|diff|merge)\.[^.]+\.(?:clean|smudge|process|"
                                                   r"textconv|command|driver)$", k):
            if k.startswith("filter.lfs."):
                continue
            out.append(Finding(MEDIUM, "local-git-config", ".git/config",
                               "%s is set locally (can run commands or redirect pushes)" % k))
    out.extend(check_force_pushes(gd))
    return out


def list_refs(repo):
    refs = git(repo, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes", "refs/tags") \
        .stdout.decode().split()
    refs = [r for r in refs if not r.endswith("/HEAD")]
    if not refs and git(repo, "rev-parse", "--verify", "-q", "HEAD", check=False).returncode == 0:
        refs = ["HEAD"]
    return refs


def short_ref(ref):
    return ref.replace("refs/remotes/", "").replace("refs/heads/", "").replace("refs/tags/", "tag:")


def scan_refs(repo, refs=None):
    """Scan every branch and tag tip from the object store (no checkout needed).

    Returns (findings, number_of_refs)."""
    refs = list_refs(repo) if refs is None else refs
    # sha -> {path: [refs]}. Every path is kept: rules depend on the file name, and the
    # same bytes can sit under a harmless name in one place and a disguised one in another.
    blobs = {}
    findings = []
    for i, ref in enumerate(refs, 1):
        short = short_ref(ref)
        status("listing branches and tags: %d/%d" % (i, len(refs)))
        # No -l: asking for sizes would lazily download missing blobs in a partial clone.
        r = git(repo, "ls-tree", "-r", "-z", "--full-tree", ref, check=False)
        if r.returncode != 0:
            # Never let an unreadable branch pass as clean.
            findings.append(Finding(MEDIUM, "scan-error", short, "could not list files: "
                                    + r.stderr.decode("utf-8", "replace").strip()[:120]))
            continue
        for entry in r.stdout.split(b"\x00"):
            if not entry:
                continue
            meta, _, p = entry.partition(b"\t")
            parts = meta.split()
            if len(parts) < 3 or parts[1] != b"blob":
                continue
            path = p.decode("utf-8", "replace")
            if any(part in SKIP_DIRS for part in path.split("/")[:-1]):
                continue
            where = blobs.setdefault(parts[2].decode(), {}).setdefault(path, [])
            if short not in where:
                where.append(short)
    findings.extend(scan_blobs(repo, blobs))
    return findings, len(refs)


def scan_blobs(repo, blobs):
    """blobs: sha -> {path: [refs]}. Reads each blob once and runs every rule for each path."""
    findings = []
    if not blobs:
        return findings
    missing = 0
    for sha, size in blob_sizes(repo, list(blobs)).items():
        if size is None:
            missing += 1
            blobs.pop(sha, None)
        elif size > MAX_BLOB:
            blobs.pop(sha, None)
    if missing:
        findings.append(Finding(INFO, "not-fetched", "(partial clone)",
                                "%d files weren't downloaded (partial clone) and were not scanned" % missing))
    total = len(blobs)
    with BlobReader(repo) as reader:
        for i, (sha, paths) in enumerate(blobs.items(), 1):
            status("reading files from git: %d/%d" % (i, total))
            data = reader.read(sha)
            if data is None:
                continue
            for path, where in paths.items():
                for f in scan_content(path, data, committed=True):
                    f.where = list(where)
                    findings.append(f)
    return findings


def check_history(repo, flagged_paths, limit=500):
    """Rewritten commits: committer date differs from author date. Reported as INFO, or
    MEDIUM when the rewritten commit changed a file that has findings."""
    status("checking commit history")
    r = git(repo, "log", "--all", "--no-merges", "-n", str(limit),
            "--format=%x01%H%x09%at%x09%ai%x09%ct%x09%ci%x09%ce", "--name-only", check=False)
    if r.returncode != 0:
        return []
    out, rewritten = [], 0
    for chunk in r.stdout.decode("utf-8", "replace").split("\x01")[1:]:
        lines = chunk.strip("\n").split("\n")
        head = lines[0].split("\t")
        if len(head) < 6:
            continue
        sha, at, ai, ct, ci, ce = head[:6]
        if "noreply@github.com" in ce:
            continue  # merges and squashes made on github.com
        at, ct = int(at), int(ct)
        tz_a, tz_c = ai.rsplit(" ", 1)[-1], ci.rsplit(" ", 1)[-1]
        if abs(ct - at) < 600 and tz_a == tz_c:
            continue
        rewritten += 1
        files = [f for f in lines[1:] if f]
        hit = [f for f in files if f in flagged_paths]
        if hit:
            out.append(Finding(MEDIUM, "rewritten-commit", hit[0],
                               "commit %s was rewritten after it was authored (author %s, committer %s) and "
                               "changed this flagged file" % (sha[:10], ai, ci)))
    if rewritten and not out:
        out.append(Finding(INFO, "rewritten-commit", "(history)",
                           "%d of the last %d commits were rewritten after authoring (rebase, amend or "
                           "cherry-pick are normal causes)" % (rewritten, limit)))
    return out


def check_force_pushes(gd):
    out = []
    logs = os.path.join(gd, "logs", "refs", "remotes")
    for dirpath, _, files in os.walk(logs):
        for fn in files:
            full = os.path.join(dirpath, fn)
            branch = os.path.relpath(full, logs).replace(os.sep, "/")
            try:
                with open(full, "rb") as fh:
                    n = sum(1 for line in fh if b"forced-update" in line)
            except OSError:
                continue
            if n:
                main = branch.split("/", 1)[-1] in ("main", "master", "develop", "trunk")
                out.append(Finding(MEDIUM if main else INFO, "force-push", branch,
                                   "remote branch was force-pushed %d time(s) (seen in your fetch reflog)" % n))
    return out


def scan_repo(path, mode="both", history=True):
    """Full scan of a local directory. Returns (findings, number_of_refs)."""
    findings, nrefs = [], 0
    if mode in ("both", "worktree"):
        findings += scan_worktree(path)
    if mode in ("both", "refs") and is_git_repo(path):
        rf, nrefs = scan_refs(path)
        findings += rf
        if history:
            flagged = {f.path for f in findings if f.sev != INFO}
            findings += check_history(path, flagged)
    return findings, nrefs
