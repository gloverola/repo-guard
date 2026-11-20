import contextlib
import io
import os
import shutil
import tempfile
import unittest

from repo_guard.fixtures import git_run, make_repo  # noqa: F401  (re-exported for tests)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rg-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


@contextlib.contextmanager
def chdir(path):
    old = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


def rules_of(findings, serious=False):
    return {f.rule for f in findings if not serious or f.sev != "INFO"}
