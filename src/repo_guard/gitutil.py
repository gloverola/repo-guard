"""Running git safely: no repo hook, fsmonitor, or ext:: transport can ever run."""

import os
import subprocess
import tempfile

IS_WINDOWS = os.name == "nt"


def _no_hooks_dir():
    if not IS_WINDOWS:
        return "/dev/null"
    d = os.path.join(tempfile.gettempdir(), "repo-guard-no-hooks")
    os.makedirs(d, exist_ok=True)
    return d


GIT_SAFE = [
    "-c", "core.hooksPath=" + _no_hooks_dir(), "-c", "core.fsmonitor=false",
    "-c", "protocol.file.allow=user", "-c", "protocol.ext.allow=never",
    "-c", "core.pager=cat",
]


def git_env(extra=None):
    env = dict(os.environ)
    for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"):
        env.pop(k, None)  # hooks run with these set; they would point git at the wrong repo
    env.update(extra or {})
    return env


def git(repo, *args, check=True, input=None, env=None):
    return subprocess.run(["git", *GIT_SAFE, "-C", repo, *args], capture_output=True, check=check,
                          input=input, env=git_env(env))


def is_git_repo(path):
    return git(path, "rev-parse", "--git-dir", check=False).returncode == 0


def git_dir(repo):
    gd = git(repo, "rev-parse", "--git-common-dir").stdout.decode().strip()
    return gd if os.path.isabs(gd) else os.path.join(repo, gd)


def toplevel(path):
    r = git(path, "rev-parse", "--show-toplevel", check=False)
    return r.stdout.decode().strip() if r.returncode == 0 else None


class BlobReader:
    """Reads blobs through one `git cat-file --batch` process.

    Requests go one at a time: writing every id up front deadlocks once both pipes fill.
    """

    def __init__(self, repo):
        self.proc = subprocess.Popen(["git", *GIT_SAFE, "-C", repo, "cat-file", "--batch"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=git_env())

    def read(self, sha):
        self.proc.stdin.write((sha + "\n").encode())
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().split()
        if len(header) < 3:
            return None
        data = self.proc.stdout.read(int(header[2]))
        self.proc.stdout.read(1)
        return data

    def close(self):
        try:
            self.proc.stdin.close()
        finally:
            self.proc.wait()
            self.proc.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def blob_sizes(repo, shas):
    """sha -> size, or None if the object is missing (partial clone). Never fetches."""
    if not shas:
        return {}
    r = subprocess.run(["git", *GIT_SAFE, "-C", repo, "cat-file", "--batch-check"],
                       input=("\n".join(shas) + "\n").encode(), capture_output=True,
                       env=git_env({"GIT_NO_LAZY_FETCH": "1"}))
    out = {}
    for line in r.stdout.decode().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].isdigit():
            out[parts[0]] = int(parts[2])
        elif len(parts) == 2 and parts[1] == "missing":
            out[parts[0]] = None
    return out
