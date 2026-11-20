"""Build repo-guard as one self-contained file (a Python zipapp), standard library only.

    python3 -I scripts/build_pyz.py OUTPUT [INTERPRETER]

INTERPRETER becomes the shebang line, e.g. "/usr/bin/python3 -I". Used by install.sh,
install.ps1, the GitHub Action and the release workflow.
"""

import os
import stat
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "src", "repo_guard")
# zipapp's own generated __main__ drops main()'s return value; this one keeps the exit code.
MAIN = "import sys\nfrom repo_guard.cli import main\nsys.exit(main())\n"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    interpreter = sys.argv[2] if len(sys.argv) > 2 else None
    with open(out, "wb") as fh:
        if interpreter:
            fh.write(b"#!" + interpreter.encode() + b"\n")
        with zipfile.ZipFile(fh, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("__main__.py", MAIN)
            for name in sorted(os.listdir(PKG)):
                if name.endswith(".py"):
                    z.write(os.path.join(PKG, name), "repo_guard/" + name)
    if interpreter:
        os.chmod(out, os.stat(out).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


if __name__ == "__main__":
    main()
