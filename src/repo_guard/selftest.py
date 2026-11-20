"""`repo-guard selftest`: prove detection and blocking work on this machine."""

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

from . import __version__
from .fixtures import COMMITTED_ONLY, IDENT, bad_files, clean_files, git_run, make_repo
from .findings import INFO
from .gitutil import git_env
from .report import color
from .scanner import scan_refs, scan_worktree


def run(out=None):
    out = out or sys.stdout
    results = []
    tmp = tempfile.mkdtemp(prefix="repo-guard-selftest-")
    try:
        bad = bad_files()
        expected = {rule for _, rule in bad.values()}
        bad_dir, clean_dir = os.path.join(tmp, "bad"), os.path.join(tmp, "clean")
        make_repo(bad_dir, bad)
        make_repo(clean_dir, clean_files())

        found = {f.rule for f in scan_refs(bad_dir)[0]}
        results.append(("detects every rule in branches", expected <= found, ", ".join(sorted(expected - found))))
        found_wt = {f.rule for f in scan_worktree(bad_dir)}
        missing = expected - COMMITTED_ONLY - found_wt
        results.append(("detects every rule in working files", not missing, ", ".join(sorted(missing))))
        noisy = [f for f in scan_refs(clean_dir)[0] + scan_worktree(clean_dir) if f.sev != INFO]
        results.append(("clean repo passes", not noisy, ", ".join("%s:%s" % (f.rule, f.path) for f in noisy)))

        from .clone import clone
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            blocked = clone([bad_dir, os.path.join(tmp, "c-bad"), "-q"], out=buf)
            allowed = clone([clean_dir, os.path.join(tmp, "c-clean"), "-q"], out=buf)
        left = sorted(os.listdir(os.path.join(tmp, "c-bad")))
        results.append(("infected clone is not checked out", blocked == 1 and left == [".git"], str(left)))
        results.append(("clean clone is checked out", allowed == 0 and
                        os.path.exists(os.path.join(tmp, "c-clean", "src", "index.js")), ""))

        results.append(_template_hook_check(tmp, bad_dir, clean_dir))
        results.append(_pre_commit_check(tmp))
    except Exception as e:  # report, don't crash
        results.append(("selftest ran", False, repr(e)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    out.write(color("repo-guard %s selftest (Python %s, %s)\n" % (__version__, sys.version.split()[0],
                                                                  sys.platform), "1", out))
    for name, ok, why in results:
        mark = color("PASS", "32", out) if ok else color("FAIL", "1;31", out)
        out.write("  %s  %s%s\n" % (mark, name, "  (%s)" % why if not ok and why else ""))
    ok = all(r[1] for r in results)
    out.write(color("  all checks passed\n" if ok else "  selftest FAILED\n", "32" if ok else "1;31", out))
    return 0 if ok else 1


def _template_hook_check(tmp, bad_dir, clean_dir):
    """A plain `git clone` with repo-guard's template hook quarantines an infected repo."""
    from .hooks import QUARANTINE_FILE, render_hook, self_command
    tpl = os.path.join(tmp, "template", "hooks")
    os.makedirs(tpl)
    hook = os.path.join(tpl, "post-checkout")
    with open(hook, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_hook("post-checkout", self_command()))
    os.chmod(hook, 0o755)
    env = git_env({"REPO_GUARD_ALLOW_FILE": os.path.join(tmp, "no-allowlist")})
    for name, src in (("q-bad", bad_dir), ("q-clean", clean_dir)):
        subprocess.run(["git", "-c", "core.hooksPath=.git/hooks", *IDENT[:-2], "clone", "-q",
                        "--template=" + os.path.join(tmp, "template"), src, os.path.join(tmp, name)],
                       capture_output=True, env=env)
    bad_left = sorted(os.listdir(os.path.join(tmp, "q-bad")))
    clean_ok = os.path.exists(os.path.join(tmp, "q-clean", "src", "index.js"))
    ok = bad_left == [".git", QUARANTINE_FILE] and clean_ok
    return ("git clone with the template hook quarantines infected repos", ok,
            "left %s, clean checked out: %s" % (bad_left, clean_ok))


def _pre_commit_check(tmp):
    from .hooks import pre_commit
    repo = os.path.join(tmp, "pc")
    files = {p: v for p, v in bad_files().items() if p == "eslint.config.js"}
    make_repo(repo, files, commit=False)
    cwd = os.getcwd()
    try:
        os.chdir(repo)
        with contextlib.redirect_stderr(io.StringIO()):
            code = pre_commit()
    finally:
        os.chdir(cwd)
    git_run(repo, "reset", "-q")
    return ("pre-commit blocks an infected file", code == 1, "exit %s" % code)

