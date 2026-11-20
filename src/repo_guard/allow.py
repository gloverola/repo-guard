"""User-level allowlist. Only ~/.config/repo-guard/allow is read: a repo can never
allowlist itself, because an attacker who controls the repo would do exactly that.

Format, one entry per line (# starts a comment):

    RULE  PATH_GLOB  [REPO_GLOB]

RULE is a rule id or *. PATH_GLOB matches the file path inside the repo. REPO_GLOB
(optional) matches the repo's absolute path, `owner/name` for `check`, and may start with ~.
Example:  install-script  package.json  ~/Dev/my-app
"""

import fnmatch
import os

from .gitutil import IS_WINDOWS


def config_dir():
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "repo-guard")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "repo-guard")


def allow_path():
    return os.environ.get("REPO_GUARD_ALLOW_FILE") or os.path.join(config_dir(), "allow")


def load(path=None):
    path = path or allow_path()
    entries = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return entries
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        repo = os.path.expanduser(parts[2]) if len(parts) > 2 else None
        entries.append((parts[0], parts[1], repo))
    return entries


def _norm(p):
    return p.replace("\\", "/").rstrip("/")


def apply(findings, target, entries=None):
    """Return (kept, number_allowed)."""
    entries = load() if entries is None else entries
    if not entries:
        return findings, 0
    target = _norm(target or "")
    kept, allowed = [], 0
    for f in findings:
        hit = False
        for rule, pglob, rglob in entries:
            if rule not in ("*", f.rule):
                continue
            if not fnmatch.fnmatchcase(f.path, pglob):
                continue
            if rglob and not fnmatch.fnmatchcase(target, _norm(rglob)):
                continue
            hit = True
            break
        if hit:
            allowed += 1
        else:
            kept.append(f)
    return kept, allowed
