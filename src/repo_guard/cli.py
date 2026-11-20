"""Command line interface."""

import argparse
import os
import subprocess
import sys

from . import __version__, allow
from .findings import fails

if sys.version_info < (3, 8):
    sys.exit("repo-guard needs Python 3.8 or newer")

DESCRIPTION = """Scan git repositories for hidden malware before anything in them can run.

commands:
  scan [PATH]          scan a repo: working files, every branch and tag, git config and hooks
  scan-all [ROOT]      scan every repo under ROOT (default: current directory)
  clone URL [DIR]      clone without checkout, scan every branch and tag, then check out if clean
  check URL            scan a GitHub repo before cloning (downloads its archive; no git)
  setup                scan every future clone from any app (git template hooks)
  pre-commit [FILES]   block commits that add infected files
  clean [PATH]         propose a fix for an infected working tree; applies only after you confirm
  rules                list detection rules
  mcp                  run the MCP server (stdio) for AI agents
  selftest             check that detection and blocking work on this machine

exit codes: 0 clean, 1 findings at or above --fail-on, 2 error.
docs: https://github.com/gloverola/repo-guard"""

LEVELS = ("high", "medium", "info", "never")


def _output_opts(p, deps=True):
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE")
    p.add_argument("--fail-on", choices=LEVELS, default="medium",
                   help="lowest severity that makes the exit code 1 (default: medium)")
    if deps:
        p.add_argument("--deps", action="store_true",
                       help="also check lockfiles against OSV malware advisories (uses the network)")


def build_parser():
    ap = argparse.ArgumentParser(prog="repo-guard", description=DESCRIPTION,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-V", "--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")

    p = sub.add_parser("scan", help="scan a repository")
    p.add_argument("path", nargs="?", default=".")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--worktree-only", action="store_true", help="only the files on disk")
    g.add_argument("--refs-only", action="store_true", help="only branches and tags (git objects)")
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing when clean")
    p.add_argument("--no-history", action="store_true", help="skip the rewritten-commit check")
    _output_opts(p)

    p = sub.add_parser("scan-all", help="scan every repository under a folder")
    p.add_argument("root", nargs="?", default=".")
    p.add_argument("-q", "--quiet", action="store_true", help="only print repos with findings")
    _output_opts(p)

    sub.add_parser("clone", help="hardened clone (accepts git clone options)", add_help=False)

    p = sub.add_parser("check", help="scan a GitHub repository before cloning")
    p.add_argument("url")
    p.add_argument("--ref", action="append", help="branch, tag or commit (repeatable)")
    p.add_argument("--all-branches", action="store_true", help="scan every branch (up to 30)")
    _output_opts(p)

    p = sub.add_parser("setup", help="install git template hooks for every future clone")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("--status", action="store_true")
    p.add_argument("--no-pre-commit", action="store_true", help="don't add the pre-commit hook")

    p = sub.add_parser("pre-commit", help="scan staged changes; exit 1 if infected")
    p.add_argument("files", nargs="*")
    p.add_argument("--fail-on", choices=LEVELS, default="medium")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")

    p = sub.add_parser("hook", help=argparse.SUPPRESS)
    p.add_argument("name")
    p.add_argument("args", nargs="*")

    p = sub.add_parser("clean", help="propose and apply a fix for an infected working tree")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--yes", action="store_true", help="apply without asking")

    p = sub.add_parser("rules", help="list detection rules")
    p.add_argument("--format", choices=("text", "json"), default="text")

    sub.add_parser("mcp", help="run the MCP server on stdio")
    sub.add_parser("selftest", help="check that detection works on this machine")
    sub.add_parser("allowlist", help="show where the allowlist lives and what it contains")
    return ap


def _finish(results, args):
    from .report import emit
    emit(results, args.format, quiet=getattr(args, "quiet", False), output=args.output)
    return 1 if any(fails(r.findings, args.fail_on) for r in results) else 0


def cmd_scan(args):
    from .report import Result
    from .scanner import scan_repo
    if not os.path.isdir(args.path):
        return die("not a directory: %s" % args.path)
    mode = "worktree" if args.worktree_only else "refs" if args.refs_only else "both"
    findings, nrefs = scan_repo(args.path, mode, history=not args.no_history)
    if args.deps:
        from .deps import check_files, collect_worktree
        findings += check_files(collect_worktree(args.path))
    target = os.path.abspath(args.path)
    kept, allowed = allow.apply(findings, target)
    note = "%d branches/tags + working files" % nrefs if nrefs and mode == "both" else \
        "%d branches/tags" % nrefs if nrefs else ""
    return _finish([Result(target, kept, nrefs, allowed, note)], args)


def cmd_scan_all(args):
    from .report import Result, color
    from .rules import SKIP_DIRS
    from .scanner import scan_repo
    root = os.path.abspath(os.path.expanduser(args.root))
    results, errors = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if ".git" in os.listdir(dirpath):
            dirnames[:] = []
            try:
                findings, nrefs = scan_repo(dirpath)
                if args.deps:
                    from .deps import check_files, collect_worktree
                    findings += check_files(collect_worktree(dirpath))
            except Exception as e:  # one broken repo must not end the sweep
                sys.stderr.write(color("repo-guard: %s\n  ERROR  scan failed: %r\n" % (dirpath, e), "1;31",
                                       sys.stderr))
                errors += 1
                continue
            kept, allowed = allow.apply(findings, dirpath)
            results.append(Result(dirpath, kept, nrefs, allowed))
    if args.format == "text" and not args.output:
        args.quiet = True  # list only infected repos, then a summary
    status = _finish(results, args)
    if args.format == "text" and not args.output:
        bad = sum(1 for r in results if fails(r.findings, args.fail_on))
        msg = "%d repos scanned under %s: %s" % (len(results), root, "%d with findings" % bad if bad else "all clean")
        sys.stdout.write(color("repo-guard: " + msg + "\n", "1;31" if bad else "32"))
    return 2 if errors and not status else status


def cmd_check(args):
    from .remote import CheckError, check
    from .report import Result
    try:
        findings, scanned, label = check(args.url, refs=args.ref, all_branches=args.all_branches,
                                         want_deps=args.deps)
    except CheckError as e:
        return die(str(e))
    kept, allowed = allow.apply(findings, label)
    return _finish([Result("github.com/" + label, kept, scanned, allowed,
                           "%d ref(s) from archives, nothing cloned" % scanned)], args)


def cmd_setup(args):
    from . import hooks
    if args.status:
        return hooks.status()
    if args.uninstall:
        return hooks.uninstall()
    return hooks.setup(pre_commit=not args.no_pre_commit)


def cmd_hook(args):
    from . import hooks
    if args.name == "post-checkout":
        return hooks.hook_post_checkout(args.args)
    if args.name == "post-merge":
        return hooks.hook_post_merge(args.args)
    if args.name == "pre-commit":
        return hooks.pre_commit()
    return 0


def cmd_rules(args):
    import json
    from .rules import RULES
    if args.format == "json":
        print(json.dumps([{"id": k, "severity": v[0], "description": v[1]} for k, v in RULES.items()], indent=2))
    else:
        for k, (sev, desc) in RULES.items():
            print("%-22s %-6s %s" % (k, sev, desc))
    return 0


def cmd_allowlist(_args):
    path = allow.allow_path()
    print("allowlist: %s%s" % (path, "" if os.path.exists(path) else " (not created yet)"))
    for rule, pglob, rglob in allow.load(path):
        print("  %s  %s%s" % (rule, pglob, "  " + rglob if rglob else ""))
    print("format: RULE PATH_GLOB [REPO_GLOB]   (repos can never allowlist themselves)")
    return 0


def enable_windows_ansi():
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def die(msg):
    sys.stderr.write("repo-guard: %s\n" % msg)
    return 2


def run(argv):
    if argv and argv[0] == "clone":  # git clone options pass straight through
        from .clone import clone
        if len(argv) > 1 and argv[1] in ("-h", "--help"):
            print("usage: repo-guard clone URL [DIR] [git clone options] [--force] [--fail-on LEVEL]")
            return 0
        return clone(argv[1:])
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    if args.cmd == "mcp":
        from .mcp import serve
        return serve()
    if args.cmd == "selftest":
        from .selftest import run as selftest
        return selftest()
    if args.cmd == "pre-commit":
        from .hooks import pre_commit
        return pre_commit(args.files, args.fail_on, args.format)
    if args.cmd == "clean":
        from .clean import clean
        if not os.path.isdir(args.path):
            return die("not a directory: %s" % args.path)
        return clean(args.path, yes=args.yes)
    handler = {"scan": cmd_scan, "scan-all": cmd_scan_all, "check": cmd_check, "setup": cmd_setup,
               "hook": cmd_hook, "rules": cmd_rules, "allowlist": cmd_allowlist}[args.cmd]
    return handler(args)


def main(argv=None):
    enable_windows_ansi()
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except KeyboardInterrupt:
        return 130
    except (subprocess.CalledProcessError, OSError) as e:
        return die(str(e))


if __name__ == "__main__":
    sys.exit(main())
