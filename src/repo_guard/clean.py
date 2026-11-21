"""`repo-guard clean`: propose a fix for an infected working tree, show it as a diff,
and apply it only after confirmation. Never touches history, other branches or remotes."""

import difflib
import os
import re
import sys

from .findings import HIGH, INFO
from .gitutil import git, is_git_repo
from .rules import CODE_LIKE, WORM_FILENAMES, scan_content
from .scanner import scan_worktree

PAYLOAD_TAIL = re.compile(rb"[ \t]{150,}(\S[^\r\n]*)")
# Split so this file never matches the worm indicators it removes.
WORM_IGNORE = tuple("temp_%s_push.bat" % k for k in ("auto", "interactive")) + ("branch_" + "structure.json",)
TASK_AUTORUN = re.compile(rb'("runOn"\s*:\s*)"folderOpen"')


class Plan:
    def __init__(self, root):
        self.root = root
        self.changes = {}   # path -> new bytes
        self.deletes = []   # paths
        self.manual = []    # (path, reason)

    def empty(self):
        return not self.changes and not self.deletes


def _read(root, rel):
    try:
        with open(os.path.join(root, *rel.split("/")), "rb") as fh:
            return fh.read()
    except OSError:
        return None


def strip_hidden(data):
    """Cut code hidden after a long whitespace run; drop lines that held only the payload."""
    out = []
    for line in data.splitlines(True):
        m = PAYLOAD_TAIL.search(line)
        if m and CODE_LIKE.search(m.group(1)):
            body = line[:m.start()]
            ending = line[len(line.rstrip(b"\r\n")):]
            if not body.strip():
                continue
            line = body + ending
        out.append(line)
    return b"".join(out)


def _referenced_files(root):
    """Files that package.json scripts or VS Code tasks run with `node X`."""
    refs = {}
    for rel in ("package.json", ".vscode/tasks.json"):
        data = _read(root, rel)
        if data:
            for m in re.finditer(rb"\bnode\s+(?:\./)?((?:[\w.-]+/)*[\w.-]+)", data):
                refs.setdefault(m.group(1).decode(), rel)
    return refs


def plan_clean(root):
    plan = Plan(root)
    findings = [f for f in scan_worktree(root) if f.sev != INFO]
    by_path = {}
    for f in findings:
        by_path.setdefault(f.path, []).append(f)
    refs = _referenced_files(root)

    droppers = set()
    for path, fs in by_path.items():
        rules = {f.rule for f in fs}
        name = path.rsplit("/", 1)[-1]
        high = any(f.sev == HIGH for f in fs)
        if name in WORM_FILENAMES or ("fake-asset" in rules and high) or \
                (high and path in refs and not path.endswith(".json")):
            droppers.add(path)
    plan.deletes = sorted(droppers)

    for path, fs in by_path.items():
        if path in droppers or path.startswith(".git/"):
            continue
        rules = {f.rule for f in fs}
        data = _read(root, path)
        if data is None:
            continue
        new = data
        if "hidden-code" in rules:
            new = strip_hidden(new)
        if path.endswith(".vscode/tasks.json") and "auto-run-task" in rules:
            if any(d.encode() in data for d in droppers):
                plan.deletes.append(path)
                continue
            new = TASK_AUTORUN.sub(rb'\1"default"', new)
        if path.rsplit("/", 1)[-1] == "package.json":
            new = _strip_script_calls(new, droppers)
        if path.rsplit("/", 1)[-1] == ".gitignore" and "worm-gitignore" in rules:
            new = fix_gitignore(root, path, new)
        if new != data:
            plan.changes[path] = new
        left = {f.rule for f in scan_content(path, new)} & {f.rule for f in fs}
        for r in sorted(left - {"install-script"}):
            plan.manual.append((path, r))
    # package.json may not be flagged itself but still call a dropper
    if "package.json" not in plan.changes and droppers:
        data = _read(root, "package.json")
        if data:
            new = _strip_script_calls(data, droppers)
            if new != data:
                plan.changes["package.json"] = new
    plan.deletes = sorted(set(plan.deletes))
    return plan


def _strip_script_calls(data, droppers):
    for d in droppers:
        p = re.escape(d.encode())
        call = rb"node\s+(?:\./)?" + p + rb"(?![\w./-])"
        data = re.sub(call + rb"\s*(?:&&|;)\s*", b"", data)
        data = re.sub(rb"\s*(?:&&|;)\s*" + call, b"", data)
    return data


def fix_gitignore(root, path, data):
    lines = data.decode("utf-8", "replace").splitlines(True)
    worm_present = any(ln.strip() in WORM_IGNORE for ln in lines)
    keep = [ln for ln in lines if ln.strip() not in WORM_IGNORE and not (worm_present and ln.strip() == "config.bat")]
    restored = removed_by_worm(root, path)
    have = {ln.strip() for ln in keep}
    add = [ln for ln in restored if ln not in have]
    if add:
        if keep and not keep[-1].endswith("\n"):
            keep[-1] += "\n"
        keep += [ln + "\n" for ln in add]
    return "".join(keep).encode()


def removed_by_worm(root, path):
    """Lines the infecting commit deleted from .gitignore, found from git history."""
    if not is_git_repo(root):
        return []
    log = git(root, "log", "--format=%H", "-n", "200", "--", path, check=False).stdout.decode().split()
    for sha in log:  # newest first; find the commit that introduced the worm lines
        cur = git(root, "show", "%s:%s" % (sha, path), check=False)
        par = git(root, "show", "%s^:%s" % (sha, path), check=False)
        if cur.returncode != 0:
            continue
        cur_lines = cur.stdout.decode("utf-8", "replace").splitlines()
        par_lines = par.stdout.decode("utf-8", "replace").splitlines() if par.returncode == 0 else []
        if any(ln.strip() in WORM_IGNORE for ln in cur_lines) and \
                not any(ln.strip() in WORM_IGNORE for ln in par_lines):
            now = {ln.strip() for ln in cur_lines}
            return [ln.strip() for ln in par_lines if ln.strip() and ln.strip() not in now]
    return []


def show(plan, out):
    for path in plan.deletes:
        out.write("delete  %s\n" % path)
    for path, new in sorted(plan.changes.items()):
        out.write("modify  %s\n" % path)
    for path, new in sorted(plan.changes.items()):
        old = _old_text(plan, path)
        diff = difflib.unified_diff(old.splitlines(True), new.decode("utf-8", "replace").splitlines(True),
                                    "a/" + path, "b/" + path, n=1)
        for line in diff:
            if len(line) > 200:
                line = line[:120] + " ...[%d more chars]\n" % (len(line) - 120)
            out.write(line if line.endswith("\n") else line + "\n")
    for path, rule in plan.manual:
        out.write("review  %s  (%s: needs a manual fix)\n" % (path, rule))


def _old_text(plan, path):
    data = _read(plan.root, path) or b""
    return data.decode("utf-8", "replace")


def apply_plan(root, plan):
    for path in plan.deletes:
        try:
            os.remove(os.path.join(root, *path.split("/")))
        except OSError:
            pass
    for path, new in plan.changes.items():
        with open(os.path.join(root, *path.split("/")), "wb") as fh:
            fh.write(new)


def clean(root, yes=False, out=None, inp=None):
    out = out or sys.stdout
    from .progress import spinning
    root = os.path.abspath(root)
    with spinning("repo-guard: working out the fix"):
        plan = plan_clean(root)
    if plan.empty():
        out.write("repo-guard clean: nothing to fix automatically in %s\n" % root)
        for path, rule in plan.manual:
            out.write("review  %s  (%s: needs a manual fix)\n" % (path, rule))
        return 1 if plan.manual else 0
    out.write("repo-guard clean: proposed changes for %s\n\n" % root)
    show(plan, out)
    if not yes:
        inp = inp or sys.stdin
        if not (hasattr(inp, "isatty") and inp.isatty()) and inp is sys.stdin:
            out.write("\nNothing changed (no terminal to confirm). Re-run with --yes to apply.\n")
            return 1
        out.write("\nApply these changes? [y/N] ")
        out.flush()
        answer = inp.readline().strip().lower()
        if answer not in ("y", "yes"):
            out.write("Nothing changed.\n")
            return 1
    apply_plan(root, plan)
    with spinning("repo-guard: rescanning"):
        remaining = [f for f in scan_worktree(root) if f.sev != INFO]
    out.write("\nApplied. %s\n" % ("The working tree now scans clean." if not remaining else
                                   "%d finding(s) remain; review them by hand." % len(remaining)))
    out.write("Next: review `git diff`, commit, and run `repo-guard scan --refs-only .`: other branches and tags\n"
              "may still carry the payload. Rotate any tokens this machine had.\n")
    return 0 if not remaining else 1
