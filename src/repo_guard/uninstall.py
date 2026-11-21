"""`repo-guard uninstall`: remove repo-guard from this machine.

Turns off the git template hooks (restoring any previous init.templateDir), removes the
shell wrapper blocks the install scripts added, deletes repo-guard's config folder, and
finally removes the program itself, however it was installed (pipx, Homebrew, pip, or
install.sh / install.ps1).
"""

import os
import shutil
import subprocess
import sys
import zipfile

from . import allow, hooks
from .gitutil import IS_WINDOWS

BEGIN, END = "# >>> repo-guard >>>", "# <<< repo-guard <<<"
DIST = "git-repo-guard"


def rc_files(home):
    files = [os.path.join(home, ".zshrc"), os.path.join(home, ".bashrc")]
    if IS_WINDOWS:
        docs = os.path.join(home, "Documents")
        files += [os.path.join(docs, "WindowsPowerShell", "profile.ps1"),
                  os.path.join(docs, "PowerShell", "profile.ps1")]
    return [f for f in files if _has_block(f)]


def _has_block(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return any(line.rstrip("\r\n") == BEGIN for line in fh)
    except OSError:
        return False


def remove_block(path):
    """Delete the marked block in place, keeping the file's other lines, owner and mode."""
    with open(path, "rb") as fh:
        lines = fh.read().splitlines(True)
    out, skip = [], False
    for line in lines:
        bare = line.decode("utf-8", "replace").rstrip("\r\n")
        if bare == BEGIN:
            skip = True
            continue
        if bare == END:
            skip = False
            continue
        if not skip:
            out.append(line)
    with open(path, "r+b") as fh:
        fh.write(b"".join(out))
        fh.truncate()


def install_method(argv0=None, prefix=None):
    """Return (kind, detail): pipx, brew, zipapp, pip or source."""
    argv0 = os.path.realpath(argv0 or (sys.argv[0] if sys.argv else ""))
    prefix = os.path.realpath(prefix or sys.prefix).replace("\\", "/")
    if os.path.isfile(argv0) and zipfile.is_zipfile(argv0):
        return "zipapp", argv0
    if "/pipx/venvs/" in prefix + "/":
        return "pipx", prefix
    if "/Cellar/repo-guard/" in prefix + "/" or "/Cellar/repo-guard/" in argv0.replace("\\", "/"):
        return "brew", prefix
    pkg = os.path.dirname(os.path.abspath(__file__)).replace("\\", "/")
    if "/site-packages/" in pkg or "/dist-packages/" in pkg:
        return "pip", sys.executable
    return "source", pkg


def removal_command(kind, detail):
    if kind == "pipx":
        return ["pipx", "uninstall", DIST]
    if kind == "brew":
        return ["brew", "uninstall", "repo-guard"]
    if kind == "pip":
        return [detail, "-m", "pip", "uninstall", "-y", DIST]
    return None


def plan(home=None, keep_allowlist=False):
    home = home or os.path.expanduser("~")
    kind, detail = install_method()
    items = []
    if hooks._load_state() or os.path.isdir(hooks.template_dir()):
        items.append("turn off the git template hooks and restore init.templateDir")
    for f in rc_files(home):
        items.append("remove the repo-guard block from " + f)
    cfg = allow.config_dir()
    if os.path.isdir(cfg):
        items.append("delete %s%s" % (cfg, " (keeping your allowlist)" if keep_allowlist else ""))
    cmd = removal_command(kind, detail)
    if kind == "zipapp":
        items.append("delete " + detail + (" (and its folder)" if IS_WINDOWS else ""))
    elif cmd:
        items.append("run: " + " ".join(cmd))
    else:
        items.append("nothing to remove for the program itself (running from a source checkout)")
    return items, kind, detail


def uninstall(yes=False, keep_allowlist=False, home=None, out=None, inp=None, run=subprocess.run):
    out = out or sys.stdout
    home = home or os.path.expanduser("~")
    items, kind, detail = plan(home, keep_allowlist)
    out.write("repo-guard uninstall will:\n")
    for it in items:
        out.write("  - %s\n" % it)
    out.write("Repos cloned while it was installed keep a small hook that does nothing once repo-guard is gone.\n")
    if not yes:
        inp = inp or sys.stdin
        if inp is sys.stdin and not (hasattr(inp, "isatty") and inp.isatty()):
            out.write("Nothing changed (no terminal to confirm). Re-run with --yes.\n")
            return 1
        out.write("Continue? [y/N] ")
        out.flush()
        if inp.readline().strip().lower() not in ("y", "yes"):
            out.write("Nothing changed.\n")
            return 1

    hooks.uninstall(out=_Null())
    for f in rc_files(home):
        remove_block(f)
    cfg = allow.config_dir()
    if os.path.isdir(cfg):
        if keep_allowlist:
            for name in os.listdir(cfg):
                if name != "allow":
                    p = os.path.join(cfg, name)
                    shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
        else:
            shutil.rmtree(cfg, ignore_errors=True)

    status = 0
    cmd = removal_command(kind, detail)
    if kind == "zipapp":
        if IS_WINDOWS:
            out.write("Finish by running install.ps1 -Uninstall (Windows can't delete a running program).\n")
        else:
            os.remove(detail)
    elif cmd:
        if IS_WINDOWS:  # the running program's files are locked on Windows
            out.write("Finish with:  %s\n" % " ".join(cmd))
        else:
            try:
                status = run(cmd).returncode
            except OSError as e:
                out.write("Could not run %s (%s). Run it yourself to finish.\n" % (" ".join(cmd), e))
                status = 1
    out.write("repo-guard has been removed%s. Open a new terminal for the change to take effect.\n"
              % ("" if status == 0 else " except the program itself (see above)"))
    return 0 if status == 0 else 1


class _Null:
    def write(self, _):
        pass
