"""`repo-guard setup`: git template hooks, so every clone made by any app that runs the
`git` program is scanned on its first checkout and quarantined if infected. Also the
hook entry points (post-checkout, post-merge, pre-commit)."""

import json
import os
import re
import shutil
import subprocess
import sys

from . import allow
from .findings import INFO, fails
from .gitutil import IS_WINDOWS, git, git_env, toplevel
from .progress import spinning
from .report import Result, print_text
from .scanner import NULL_SHA, scan_blobs, scan_refs, scan_worktree

HOOK_NAMES = ("post-checkout", "post-merge", "pre-commit")
MARKER = "# repo-guard hook"
QUARANTINE_FILE = "REPO-GUARD-QUARANTINE.txt"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
MAX_DIFF_BLOBS = 5000

HOOK_TEMPLATE = """#!/bin/sh
{marker} (installed by `repo-guard setup`; remove with `repo-guard setup --uninstall`)
status=0
if [ -z "${{REPO_GUARD_OFF:-}}" ] && [ -e {cmd0} ]; then
  {command} hook {name} "$@" || status=$?
fi
if [ "$status" = 0 ] && [ -x "$0.chained" ]; then
  exec "$0.chained" "$@"
fi
exit $status
"""


def _sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _posix(p):
    return p.replace("\\", "/") if IS_WINDOWS else p


def self_command():
    """The command that runs this repo-guard, as an argv list. Hooks run inside untrusted
    repos, so Python is always started in isolated mode (-I): the repo's files can never
    shadow repo-guard's modules."""
    argv0 = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if argv0.endswith(".pyz") and os.path.isfile(argv0):
        return [sys.executable, "-I", argv0]
    base = os.path.basename(argv0).lower()
    if os.path.isfile(argv0) and base.startswith("repo-guard") and not base.endswith(".py"):
        return [argv0]  # console script from pip, pipx or Homebrew
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    boot = ("import sys; sys.path.insert(0, %r); from repo_guard.cli import main; sys.exit(main())"
            % pkg_parent)
    return [sys.executable, "-I", "-c", boot]


def render_hook(name, cmd=None):
    cmd = cmd or self_command()
    command = " ".join(_sh_quote(_posix(c)) for c in cmd)
    return HOOK_TEMPLATE.format(marker=MARKER, cmd0=_sh_quote(_posix(cmd[0])), command=command, name=name)


_OWN = None


def is_own_hook(path):
    """True for a hook file written by `repo-guard setup` (any install location)."""
    global _OWN
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError):
        return False
    if MARKER not in text:
        return False
    name = os.path.basename(path)
    if name not in HOOK_NAMES:
        return False
    if _OWN is None:
        _OWN = {}
    if name not in _OWN:
        sample = render_hook(name, ["@@CMD@@"])
        rx = re.escape(sample).replace(re.escape("'@@CMD@@'"), r"[^\n]+")
        _OWN[name] = re.compile(rx + r"\Z")
    return bool(_OWN[name].match(text))


def is_template_hook(path):
    """True if the hook is byte-identical to the same hook in the user's git template
    (repo-guard's, or the one init.templateDir points at): the user installed it."""
    name = os.path.basename(path)
    dirs = [template_dir()]
    cur = _global_get("init.templateDir")
    if cur:
        dirs.append(os.path.expanduser(cur))
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    for d in dirs:
        try:
            with open(os.path.join(d, "hooks", name), "rb") as fh:
                if fh.read() == data:
                    return True
        except OSError:
            continue
    return False


# --- setup ------------------------------------------------------------------------

def template_dir():
    return os.path.join(allow.config_dir(), "git-template")


def state_file():
    return os.path.join(allow.config_dir(), "setup.json")


def _global_get(key):
    r = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, env=git_env())
    return r.stdout.decode().strip() if r.returncode == 0 else None


def _global_set(key, value):
    args = ["git", "config", "--global"] + (["--unset", key] if value is None else [key, value])
    subprocess.run(args, capture_output=True, env=git_env())


def _default_templates():
    r = subprocess.run(["git", "--exec-path"], capture_output=True)
    exec_path = r.stdout.decode().strip()
    cands = []
    if exec_path:
        prefix = os.path.dirname(os.path.dirname(exec_path))  # <prefix>/libexec/git-core
        cands.append(os.path.join(prefix, "share", "git-core", "templates"))
        cands.append(os.path.join(os.path.dirname(prefix), "share", "git-core", "templates"))
    cands += ["/usr/share/git-core/templates", "/usr/local/share/git-core/templates",
              "/opt/homebrew/share/git-core/templates"]
    for c in cands:
        if os.path.isdir(c):
            return c
    return None


def setup(pre_commit=True, out=None):
    out = out or sys.stdout
    tdir = template_dir()
    state = _load_state()
    current = _global_get("init.templateDir")
    cur_abs = os.path.abspath(os.path.expanduser(current)) if current else None
    if cur_abs and os.path.normcase(cur_abs) == os.path.normcase(os.path.abspath(tdir)):
        previous = state.get("previous_template_dir")  # re-running setup: keep what we saved
    else:
        previous = current
    source = os.path.expanduser(previous) if previous else _default_templates()

    staging = tdir + ".new"
    shutil.rmtree(staging, ignore_errors=True)
    if source and os.path.isdir(source):
        shutil.copytree(source, staging, symlinks=True)
    os.makedirs(os.path.join(staging, "hooks"), exist_ok=True)
    cmd = self_command()
    names = HOOK_NAMES if pre_commit else ("post-checkout", "post-merge")
    for name in names:
        hook = os.path.join(staging, "hooks", name)
        if os.path.isfile(hook) and not is_own_hook(hook):
            os.replace(hook, hook + ".chained")  # keep the user's own template hook; ours runs it
        with open(hook, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_hook(name, cmd))
        os.chmod(hook, 0o755)
    shutil.rmtree(tdir, ignore_errors=True)
    os.replace(staging, tdir)
    _global_set("init.templateDir", tdir)
    _save_state({"previous_template_dir": previous, "command": cmd, "pre_commit": bool(pre_commit)})

    out.write("repo-guard: git template hooks installed in %s\n" % tdir)
    out.write("  init.templateDir now points there%s.\n" % (" (your previous template %s was merged in)"
                                                         % previous if previous else ""))
    out.write("  Every new clone is scanned on checkout and quarantined if infected%s.\n"
              % ("; commits are checked by a pre-commit hook" if pre_commit else ""))
    hp = _global_get("core.hooksPath")
    if hp:
        out.write("  WARNING: your global core.hooksPath (%s) makes git ignore template hooks. Unset it or add\n"
                  "  repo-guard's hooks there, or the clone check will not run.\n" % hp)
    out.write("  Repos cloned before now are not covered: run `repo-guard scan-all DIR` for those.\n")
    return 0


def uninstall(out=None):
    out = out or sys.stdout
    state = _load_state()
    current = _global_get("init.templateDir")
    tdir = template_dir()
    if current and os.path.normcase(os.path.abspath(os.path.expanduser(current))) == \
            os.path.normcase(os.path.abspath(tdir)):
        _global_set("init.templateDir", state.get("previous_template_dir"))
    shutil.rmtree(tdir, ignore_errors=True)
    try:
        os.remove(state_file())
    except OSError:
        pass
    out.write("repo-guard: template hooks removed; init.templateDir restored. Repos cloned meanwhile keep a\n"
              "  hook that does nothing once repo-guard is gone.\n")
    return 0


def _load_state():
    try:
        with open(state_file(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    os.makedirs(os.path.dirname(state_file()), exist_ok=True)
    with open(state_file(), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def status(out=None):
    out = out or sys.stdout
    tdir = template_dir()
    current = _global_get("init.templateDir")
    ok = bool(current) and os.path.normcase(os.path.abspath(os.path.expanduser(current))) == \
        os.path.normcase(os.path.abspath(tdir)) and os.path.isfile(os.path.join(tdir, "hooks", "post-checkout"))
    out.write("repo-guard setup: %s\n" % ("active (%s)" % tdir if ok else "not active (run: repo-guard setup)"))
    return 0 if ok else 1


# --- hook entry points ----------------------------------------------------------------

def _diff_blobs(repo, old, new):
    r = git(repo, "diff-tree", "-r", "-z", "--no-renames", "--diff-filter=ACMRT", old, new, check=False)
    return _parse_raw_diff(r.stdout)


def _parse_raw_diff(raw):
    blobs = {}
    parts = raw.split(b"\x00")
    i = 0
    while i < len(parts) - 1:
        meta = parts[i].decode("utf-8", "replace")
        if not meta.startswith(":"):
            i += 1
            continue
        fields = meta[1:].split()
        path = parts[i + 1].decode("utf-8", "replace")
        if len(fields) >= 4 and fields[1] != "160000" and fields[3] != NULL_SHA:
            blobs.setdefault(fields[3], {}).setdefault(path, [])
        i += 2
    return blobs


def _filtered(findings, repo):
    kept, allowed = allow.apply(findings, repo)
    return kept, allowed


def hook_post_checkout(args, fail_on="medium"):
    repo = toplevel(".") or os.getcwd()
    old, new = (args + ["", ""])[:2]
    initial = old == NULL_SHA
    if not initial:
        if old and new and old != new:
            return _warn_on_diff(repo, old, new, "checkout")
        return 0
    with spinning("repo-guard: scanning the new clone"):
        findings, nrefs = scan_refs(repo)
        findings += scan_worktree(repo)
    kept, allowed = _filtered(findings, repo)
    result = Result(repo, kept, nrefs, allowed, "%d branches/tags, first checkout" % nrefs)
    if not fails(kept, fail_on):
        sys.stderr.write("repo-guard: %s scanned (%d branches/tags): no malware indicators found\n"
                         % (repo, nrefs))
        return 0
    quarantine(repo, result)
    return 1


def quarantine(repo, result):
    """Delete the files the first checkout just wrote, so nothing in them can run."""
    files = git(repo, "ls-files", "-z", check=False).stdout.split(b"\x00")
    removed = 0
    for f in files:
        if not f:
            continue
        full = os.path.join(repo, *f.decode("utf-8", "replace").split("/"))
        try:
            if os.path.islink(full) or os.path.isfile(full):
                os.remove(full)
                removed += 1
        except OSError:
            pass
    for dirpath, dirnames, _ in os.walk(repo, topdown=False):
        rel = os.path.relpath(dirpath, repo).split(os.sep)
        if dirpath == repo or rel[0] == ".git":
            continue
        try:
            os.rmdir(dirpath)
        except OSError:
            pass
    import io
    buf = io.StringIO()
    print_text(result, stream=buf)
    note = ("repo-guard QUARANTINED this clone: it found malware indicators, so it removed the %d files the\n"
            "checkout had written. Only git's data (.git) is left; nothing from the repo can run.\n\n%s\n"
            "Review the findings (e.g. `repo-guard scan --refs-only .`). If you are sure the repo is safe,\n"
            "restore the files with:  git reset --hard\n" % (removed, buf.getvalue()))
    with open(os.path.join(repo, QUARANTINE_FILE), "w", encoding="utf-8") as fh:
        fh.write(note)
    sys.stderr.write(note)


def _warn_on_diff(repo, old, new, what):
    blobs = _diff_blobs(repo, old, new)
    if not blobs:
        return 0
    if len(blobs) > MAX_DIFF_BLOBS:  # huge branch switch: don't stall git; suggest a full scan
        sys.stderr.write("repo-guard: %d files changed; run `repo-guard scan` to check them\n" % len(blobs))
        return 0
    with spinning("repo-guard: scanning files changed by this " + what):
        findings, _ = _filtered(scan_blobs(repo, blobs), repo)
    findings = [f for f in findings if f.sev != INFO]
    if findings:
        print_text(Result(repo, findings, note="files changed by this " + what), stream=sys.stderr)
        sys.stderr.write("repo-guard: do not run, build or open this repo in an editor until you have reviewed "
                         "these files.\n")
    return 0  # the files are already there; post hooks can't undo, so warn only


def hook_post_merge(args):
    repo = toplevel(".") or os.getcwd()
    r = git(repo, "rev-parse", "-q", "--verify", "ORIG_HEAD", check=False)
    if r.returncode != 0:
        return 0
    return _warn_on_diff(repo, r.stdout.decode().strip(), "HEAD", "pull/merge")


def staged_blobs(repo, only=None):
    env = {}
    idx = os.environ.get("GIT_INDEX_FILE")
    if idx:
        env["GIT_INDEX_FILE"] = os.path.abspath(idx)
    head = "HEAD" if git(repo, "rev-parse", "-q", "--verify", "HEAD", check=False, env=env).returncode == 0 \
        else EMPTY_TREE
    r = git(repo, "diff-index", "--cached", "-z", "--no-renames", "--diff-filter=ACMRT", head, env=env)
    blobs = _parse_raw_diff(r.stdout)
    if only:
        wanted = {p.replace(os.sep, "/") for p in only}
        blobs = {s: {p: w for p, w in ps.items() if p in wanted} for s, ps in blobs.items()}
        blobs = {s: ps for s, ps in blobs.items() if ps}
    return blobs


def pre_commit(paths=(), fail_on="medium", fmt="text"):
    repo = toplevel(".")
    if not repo:
        sys.stderr.write("repo-guard: not inside a git repository\n")
        return 2
    rel = [os.path.relpath(os.path.abspath(p), repo).replace(os.sep, "/") for p in paths]
    with spinning("repo-guard: scanning staged changes"):
        findings = scan_blobs(repo, staged_blobs(repo, rel))
    kept, allowed = _filtered(findings, repo)
    result = Result(repo, kept, allowed=allowed, note="staged changes")
    if fmt != "text":
        from .report import emit
        emit([result], fmt)
        return 1 if fails(kept, fail_on) else 0
    if fails(kept, fail_on):
        print_text(result, stream=sys.stderr)
        sys.stderr.write("repo-guard: commit blocked. Remove the flagged code, or allowlist a false positive in %s.\n"
                         % allow.allow_path())
        return 1
    return 0
