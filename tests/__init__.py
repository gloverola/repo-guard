"""Test setup: import the package from src/, and isolate git and repo-guard from the
user's own configuration so tests never read or change it."""

import atexit
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

_HOME = tempfile.mkdtemp(prefix="repo-guard-tests-")
atexit.register(shutil.rmtree, _HOME, True)
_GLOBAL = os.path.join(_HOME, "gitconfig")
open(_GLOBAL, "w").close()
os.environ.update({
    "GIT_CONFIG_GLOBAL": _GLOBAL,
    "GIT_CONFIG_NOSYSTEM": "1",
    "XDG_CONFIG_HOME": os.path.join(_HOME, "config"),
    "APPDATA": os.path.join(_HOME, "appdata"),
    "REPO_GUARD_ALLOW_FILE": os.path.join(_HOME, "allow"),
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
})
for _k in ("GITHUB_TOKEN", "GH_TOKEN", "REPO_GUARD_OFF"):
    os.environ.pop(_k, None)
