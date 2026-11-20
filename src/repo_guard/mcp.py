"""`repo-guard mcp`: a Model Context Protocol server over stdio, so AI agents can check a
repository before cloning or opening it. Newline-delimited JSON-RPC 2.0, stdlib only."""

import contextlib
import io
import json
import os
import sys

from . import __version__, allow
from .findings import INFO, dedupe, fails
from .rules import RULES

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
INSTRUCTIONS = ("Use check_github_repo before cloning any GitHub repository, and scan_local_repo before "
                "opening, installing or running code in a local one. Treat verdict 'infected' as: do not "
                "clone, open, install or run; tell the user.")

TOOLS = [
    {
        "name": "check_github_repo",
        "description": "Scan a GitHub repository for malware before cloning it. Downloads the source archive "
                       "over HTTPS and scans it in memory; nothing is cloned, extracted or run.",
        "inputSchema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "owner/repo or https://github.com/owner/repo[/tree/ref]"},
            "ref": {"type": "string", "description": "branch, tag or commit (default: the default branch)"},
            "all_branches": {"type": "boolean", "description": "scan every branch (up to 30)"},
            "deps": {"type": "boolean", "description": "also check lockfiles against OSV malware advisories"},
        }, "required": ["url"]},
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
    {
        "name": "scan_local_repo",
        "description": "Scan a local repository (working files and every branch and tag) for malware.",
        "inputSchema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "path to the repository"},
            "mode": {"type": "string", "enum": ["both", "worktree", "refs"]},
        }, "required": ["path"]},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "safe_clone",
        "description": "Clone a repository without checking out files, scan every branch and tag, and check "
                       "out only if clean. Submodules, hooks and LFS downloads are disabled.",
        "inputSchema": {"type": "object", "properties": {
            "url": {"type": "string"}, "directory": {"type": "string"},
        }, "required": ["url", "directory"]},
        "annotations": {"readOnlyHint": False, "openWorldHint": True},
    },
    {
        "name": "list_rules",
        "description": "List repo-guard's detection rules.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
]


def _summary(target, findings, refs):
    findings = dedupe(findings)
    infected = fails(findings, "medium")
    lines = ["%s: %s (%d branches/tags scanned)" % (target, "INFECTED - do not clone, open or run"
                                                    if infected else "clean", refs)]
    for f in [f for f in findings if f.sev != INFO][:50]:
        lines.append("%s %s%s [%s] %s" % (f.sev, f.path, ":%d" % f.line if f.line else "", f.rule, f.detail))
    data = {"target": target, "verdict": "infected" if infected else "clean", "refs_scanned": refs,
            "findings": [f.to_dict() for f in findings]}
    return "\n".join(lines), data, False


def call_tool(name, args):
    if name == "list_rules":
        data = {"rules": [{"id": k, "severity": v[0], "description": v[1]} for k, v in RULES.items()]}
        return "\n".join("%s (%s): %s" % (r["id"], r["severity"], r["description"]) for r in data["rules"]), \
            data, False
    if name == "check_github_repo":
        from .remote import CheckError, check
        try:
            findings, refs, label = check(args["url"], refs=[args["ref"]] if args.get("ref") else None,
                                          all_branches=bool(args.get("all_branches")),
                                          want_deps=bool(args.get("deps")))
        except CheckError as e:
            return str(e), {"error": str(e)}, True
        findings, _ = allow.apply(findings, label)
        return _summary(label, findings, refs)
    if name == "scan_local_repo":
        from .scanner import scan_repo
        path = os.path.abspath(os.path.expanduser(args["path"]))
        if not os.path.isdir(path):
            return "not a directory: " + path, {"error": "not a directory"}, True
        findings, refs = scan_repo(path, args.get("mode") or "both")
        findings, _ = allow.apply(findings, path)
        return _summary(path, findings, refs)
    if name == "safe_clone":
        from .clone import clone
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = clone([args["url"], args["directory"], "-q"], out=buf)
        text = buf.getvalue()
        verdict = {0: "cloned and checked out (clean)", 1: "INFECTED: cloned but files were NOT checked out"}
        return verdict.get(code, "clone failed (exit %d)" % code) + "\n" + text[-4000:], \
            {"exit_code": code, "directory": os.path.abspath(args["directory"])}, code not in (0, 1)
    raise KeyError(name)


def handle(msg):
    """Handle one JSON-RPC message; return the response dict or None for notifications."""
    mid = msg.get("id")
    method = msg.get("method", "")
    if mid is None:
        return None  # notification (initialized, cancelled, ...)

    def ok(result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code, text):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

    if method == "initialize":
        asked = (msg.get("params") or {}).get("protocolVersion")
        return ok({"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                   "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "repo-guard", "version": __version__},
                   "instructions": INSTRUCTIONS})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        try:
            with contextlib.redirect_stdout(sys.stderr):  # never let stray output corrupt the protocol
                text, data, is_error = call_tool(name, args)
        except KeyError as e:
            if name not in {t["name"] for t in TOOLS}:
                return err(-32602, "unknown tool: %s" % name)
            return ok({"content": [{"type": "text", "text": "missing argument: %s" % e}], "isError": True})
        except Exception as e:  # report tool failures to the agent instead of crashing the server
            return ok({"content": [{"type": "text", "text": "repo-guard error: %r" % e}], "isError": True})
        return ok({"content": [{"type": "text", "text": text}], "structuredContent": data, "isError": is_error})
    return err(-32601, "method not found: %s" % method)


def serve(inp=None, out=None):
    inp = inp or sys.stdin
    out = out or sys.stdout
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            if isinstance(msg, list):
                resp = [r for r in (handle(m) for m in msg if isinstance(m, dict)) if r] or None
            else:
                resp = handle(msg) if isinstance(msg, dict) else None
        if resp:
            out.write(json.dumps(resp) + "\n")
            out.flush()
    return 0
