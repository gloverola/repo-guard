"""Finding type, severities and small text helpers shared by every module."""

import re

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
SEV_ORDER = {HIGH: 0, MEDIUM: 1, INFO: 2}
FAIL_LEVELS = {"high": 0, "medium": 1, "info": 2, "never": -1}


class Finding:
    __slots__ = ("sev", "rule", "path", "line", "detail", "where")

    def __init__(self, sev, rule, path, detail, line=None):
        self.sev, self.rule, self.path, self.detail, self.line = sev, rule, path, detail, line
        self.where = []  # branches/tags the file was found on (git object scans)

    def key(self):
        return (self.sev, self.rule, self.path, self.line, self.detail)

    def to_dict(self):
        d = {"severity": self.sev, "rule": self.rule, "path": self.path, "message": self.detail}
        if self.line:
            d["line"] = self.line
        if self.where:
            d["refs"] = list(self.where)
        return d

    def __repr__(self):
        return "Finding(%s %s %s:%s %s)" % (self.sev, self.rule, self.path, self.line, self.detail)


def dedupe(findings):
    seen = {}
    for f in findings:
        k = f.key()
        if k in seen:
            for w in f.where:
                if w not in seen[k].where:
                    seen[k].where.append(w)
        else:
            seen[k] = f
    return sorted(seen.values(), key=lambda f: (SEV_ORDER[f.sev], f.path, f.line or 0, f.rule))


def fails(findings, fail_on="medium"):
    """True if any finding is at or above the --fail-on level."""
    limit = FAIL_LEVELS[fail_on]
    return any(SEV_ORDER[f.sev] <= limit for f in findings)


def excerpt(raw, n=90):
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    s = re.sub(r"[ \t]{20,}", " <whitespace> ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return (s[:n] + "...") if len(s) > n else s


def line_of(data, idx):
    return data.count(b"\n", 0, idx) + 1


def is_textish(data):
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13) or b >= 128)
    return printable / len(sample) > 0.9
