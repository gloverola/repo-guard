"""Hardened clone: no checkout, no hooks, no submodules, no LFS smudge, no fsmonitor.
Every branch and tag is scanned from git's object store before any file is written."""

import os
import subprocess
import sys

from . import allow
from .findings import INFO, Finding, fails
from .gitutil import GIT_SAFE, git, git_env
from .report import Result, color, emit
from .scanner import check_history, scan_refs

VALUE_OPTS = {"-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference",
              "--reference-if-able", "--separate-git-dir", "-j", "--jobs", "--filter", "--template",
              "-u", "--upload-pack", "--shallow-since", "--shallow-exclude", "--server-option",
              "--bundle-uri", "--ref-format"}
DROPPED = {"--recurse-submodules", "--recursive", "--shallow-submodules", "--remote-submodules",
           "--no-checkout", "-n"}
HARDEN = ["-c", "submodule.recurse=false", "-c", "core.symlinks=false"] if os.name == "nt" else \
    ["-c", "submodule.recurse=false"]
HARD_ENV = {"GIT_LFS_SKIP_SMUDGE": "1"}


def default_dir(url):
    name = url.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return name[:-4] if name.endswith(".git") else name


def parse_args(args):
    opts = {"force": False, "fail_on": "medium", "format": "text"}
    passthru, positional, dropped = [], [], []
    it = iter(args)
    for a in it:
        if a == "--force":
            opts["force"] = True
        elif a == "--fail-on":
            opts["fail_on"] = next(it, "medium")
        elif a.startswith("--fail-on="):
            opts["fail_on"] = a.split("=", 1)[1]
        elif a in DROPPED or a.startswith("--recurse-submodules="):
            dropped.append(a)
        elif a in VALUE_OPTS:
            passthru += [a, next(it, "")]
        elif a.startswith("-"):
            passthru.append(a)
        else:
            positional.append(a)
    return opts, passthru, positional, dropped


def clone(args, out=None):
    out = out or sys.stdout
    opts, passthru, positional, dropped = parse_args(args)
    if not positional:
        sys.stderr.write("usage: repo-guard clone URL [DIR] [git clone options] [--force] [--fail-on LEVEL]\n")
        return 2
    if opts["fail_on"] not in ("high", "medium", "info", "never"):
        sys.stderr.write("repo-guard: --fail-on must be high, medium, info or never\n")
        return 2
    url = positional[0]
    target = positional[1] if len(positional) > 1 else default_dir(url)
    out.write(color("repo-guard: cloning %s without checking out files...\n" % url, "1", out))
    if dropped:
        out.write("  (ignored %s: submodules are never cloned automatically; scan and clone them one by one)\n"
                  % " ".join(dropped))
    r = subprocess.run(["git", *GIT_SAFE, *HARDEN, "clone", "--no-checkout", *passthru, url, target],
                       env=git_env(HARD_ENV))
    if r.returncode != 0:
        return r.returncode
    findings, nrefs = scan_refs(target)
    findings += check_history(target, {f.path for f in findings if f.sev != INFO})
    gm = git(target, "show", "HEAD:.gitmodules", check=False)
    if gm.returncode == 0:
        urls = [ln.split("=", 1)[1].strip() for ln in gm.stdout.decode("utf-8", "replace").splitlines()
                if ln.strip().startswith("url")]
        findings.append(Finding(INFO, "submodules", ".gitmodules",
                                "submodules were not cloned or scanned: " + ", ".join(urls[:5])))
    abs_target = os.path.abspath(target)
    kept, allowed = allow.apply(findings, abs_target)
    result = Result(abs_target, kept, nrefs, allowed, "%d branches/tags, before checkout" % nrefs)
    emit([result], opts["format"])
    blocked = fails(kept, opts["fail_on"])
    if blocked and not opts["force"]:
        out.write(color("\n  Files were NOT checked out. The repo is at %s (git data only).\n" % target, "1;31", out))
        out.write("  Review the findings above. To check out anyway:\n")
        out.write("    git -C %s reset --hard\n" % target)
        return 1
    checkout = subprocess.run(["git", *GIT_SAFE, *HARDEN, "-C", target, "reset", "--hard", "-q"],
                              env=git_env(HARD_ENV))
    if checkout.returncode == 0:
        out.write(color("  OK  checked out into %s\n" % target, "32", out))
    return (1 if blocked else 0) or checkout.returncode
