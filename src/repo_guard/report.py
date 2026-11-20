"""Output: coloured text, JSON and SARIF 2.1.0."""

import json
import sys

from . import __version__
from .findings import HIGH, INFO, MEDIUM, SEV_ORDER, dedupe
from .rules import RULES

HOMEPAGE = "https://github.com/gloverola/repo-guard"
RULES_DOC = HOMEPAGE + "/blob/main/docs/rules.md#"
SEV_COLOR = {HIGH: "1;31", MEDIUM: "33", INFO: "36"}


def color(s, code, stream=None):
    stream = stream or sys.stdout
    return "\033[%sm%s\033[0m" % (code, s) if hasattr(stream, "isatty") and stream.isatty() else s


class Result:
    """Findings for one scanned target."""

    def __init__(self, target, findings, refs=0, allowed=0, note=""):
        self.target, self.findings, self.refs, self.allowed, self.note = \
            target, dedupe(findings), refs, allowed, note

    def counts(self):
        return {s.lower(): sum(1 for f in self.findings if f.sev == s) for s in (HIGH, MEDIUM, INFO)}

    def to_dict(self):
        d = {"target": self.target, "refs_scanned": self.refs, "summary": self.counts(),
             "findings": [f.to_dict() for f in self.findings]}
        if self.allowed:
            d["allowed"] = self.allowed
        return d


def print_text(result, quiet=False, show_info=True, stream=None):
    out = stream or sys.stdout
    bad = [f for f in result.findings if f.sev != INFO]
    if quiet and not bad:
        return

    def w(s=""):
        out.write(s + "\n")

    title = result.target + ("  (%s)" % result.note if result.note else "")
    w(color("repo-guard: " + title, "1", out))
    if not bad:
        w(color("  OK  no malware indicators found", "32", out))
    for f in result.findings:
        if f.sev == INFO and not show_info:
            continue
        loc = f.path + (":%d" % f.line if f.line else "")
        w("  %s %s  [%s]" % (color(f.sev.ljust(6), SEV_COLOR[f.sev], out), loc, f.rule))
        w("         " + f.detail)
        if f.where:
            shown = ", ".join(f.where[:4]) + (" (+%d more)" % (len(f.where) - 4) if len(f.where) > 4 else "")
            w("         on: " + shown)
    if result.allowed:
        w("  (%d finding(s) hidden by your allowlist)" % result.allowed)
    if bad:
        highs = sum(1 for f in bad if f.sev == HIGH)
        w(color("  !! %d high, %d medium. Do not open, install or run this repo until you have "
                "reviewed these files." % (highs, len(bad) - highs), "1;31", out))


def to_json(results):
    return json.dumps({"tool": "repo-guard", "version": __version__,
                       "results": [r.to_dict() for r in results]}, indent=2)


SARIF_LEVEL = {HIGH: "error", MEDIUM: "warning", INFO: "note"}


def to_sarif(results):
    used = sorted({f.rule for r in results for f in r.findings})
    rules = []
    index = {}
    for rid in used:
        sev, desc = RULES.get(rid, (MEDIUM, rid))
        index[rid] = len(rules)
        rules.append({
            "id": rid, "name": rid,
            "shortDescription": {"text": desc},
            "helpUri": RULES_DOC + rid,
            "defaultConfiguration": {"level": SARIF_LEVEL[sev]},
            "properties": {"tags": ["security", "malware"],
                           "security-severity": {HIGH: "9.0", MEDIUM: "6.0", INFO: "2.0"}[sev]},
        })
    res = []
    for r in results:
        for f in r.findings:
            path = f.path if not f.path.startswith("(") else ".git"
            loc = {"physicalLocation": {"artifactLocation": {"uri": path}}}
            if f.line:
                loc["physicalLocation"]["region"] = {"startLine": f.line}
            item = {
                "ruleId": f.rule, "ruleIndex": index[f.rule], "level": SARIF_LEVEL[f.sev],
                "message": {"text": f.detail + (" (on: %s)" % ", ".join(f.where[:10]) if f.where else "")},
                "locations": [loc],
                "partialFingerprints": {"repoGuard/v1": "%s:%s:%s" % (f.rule, f.path, f.detail[:80])},
            }
            if f.where:
                item["properties"] = {"refs": list(f.where)}
            res.append(item)
    res.sort(key=lambda x: SEV_ORDER[{"error": HIGH, "warning": MEDIUM, "note": INFO}[x["level"]]])
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "repo-guard", "version": __version__, "semanticVersion": __version__,
                                "informationUri": HOMEPAGE, "rules": rules}},
            "results": res,
        }],
    }
    return json.dumps(doc, indent=2)


def emit(results, fmt="text", quiet=False, output=None):
    if fmt == "text" and not output:
        for r in results:
            print_text(r, quiet=quiet)
        return
    if fmt == "json":
        text = to_json(results)
    elif fmt == "sarif":
        text = to_sarif(results)
    else:
        import io
        buf = io.StringIO()
        for r in results:
            print_text(r, quiet=quiet, stream=buf)
        text = buf.getvalue()
    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        sys.stdout.write(text + "\n")
