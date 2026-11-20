"""Opt-in (--deps) malicious-dependency check: lockfile versions are looked up in OSV,
and only malware advisories (ids starting with MAL-) are reported. Uses the network."""

import json
import os
import re
import urllib.request

from .findings import HIGH, INFO, Finding
from .rules import SKIP_DIRS

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
LOCKFILES = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm",
             "yarn.lock": "npm", "poetry.lock": "PyPI", "uv.lock": "PyPI", "Pipfile.lock": "PyPI"}
REQ_FILE = re.compile(r"^requirements[\w.-]*\.(?:txt|in)$")
USER_AGENT = "repo-guard (+https://github.com/gloverola/repo-guard)"


def is_lockfile(name):
    return name in LOCKFILES or bool(REQ_FILE.match(name))


def parse(name, data):
    """Return a set of (ecosystem, package, version)."""
    text = data.decode("utf-8", "replace")
    out = set()
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            doc = json.loads(text)
        except ValueError:
            return out
        for key, meta in (doc.get("packages") or {}).items():
            if key and isinstance(meta, dict) and meta.get("version") and not meta.get("link"):
                out.add(("npm", key.rsplit("node_modules/", 1)[-1], meta["version"]))

        def walk(deps):
            for pkg, meta in (deps or {}).items():
                if isinstance(meta, dict):
                    if meta.get("version"):
                        out.add(("npm", pkg, meta["version"]))
                    walk(meta.get("dependencies"))
        walk(doc.get("dependencies"))
    elif name == "pnpm-lock.yaml":
        for m in re.finditer(r"(?m)^  ['\"]?/?((?:@[^/@\s'\"]+/)?[^/@\s'\"(]+)[@/](\d[\w.+-]*)", text):
            out.add(("npm", m.group(1), m.group(2)))
    elif name == "yarn.lock":
        pkg = None
        for line in text.splitlines():
            if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
                spec = line.rstrip(":").split(",")[0].strip().strip('"')
                at = spec.find("@", 1)
                pkg = spec[:at] if at > 0 else None
            else:
                m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
                if m and pkg:
                    out.add(("npm", pkg, m.group(1)))
                    pkg = None
    elif name in ("poetry.lock", "uv.lock"):
        for m in re.finditer(r'(?m)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
            out.add(("PyPI", m.group(1), m.group(2)))
    elif name == "Pipfile.lock":
        try:
            doc = json.loads(text)
        except ValueError:
            return out
        for section in ("default", "develop"):
            for pkg, meta in (doc.get(section) or {}).items():
                v = str((meta or {}).get("version", ""))
                if v.startswith("=="):
                    out.add(("PyPI", pkg, v[2:]))
    elif REQ_FILE.match(name):
        for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?\s*==\s*([\w.+!\-]+)", text):
            out.add(("PyPI", m.group(1), m.group(2)))
    return out


def _post_json(url, payload, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
        return json.loads(resp.read().decode())


def query_osv(packages):
    """packages: list of (eco, name, version) -> {index: [MAL ids]}"""
    hits = {}
    for start in range(0, len(packages), 1000):
        chunk = packages[start:start + 1000]
        payload = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
        doc = _post_json(OSV_BATCH, payload)
        for i, res in enumerate(doc.get("results", [])):
            ids = [v.get("id", "") for v in (res or {}).get("vulns", []) or []]
            mal = [x for x in ids if x.startswith("MAL-")]
            if mal:
                hits[start + i] = mal
    return hits


def check_files(files):
    """files: {path: bytes} of lockfiles. Returns findings."""
    entries = []  # (path, eco, name, version)
    for path, data in files.items():
        for eco, name, ver in sorted(parse(path.rsplit("/", 1)[-1], data)):
            entries.append((path, eco, name, ver))
    if not entries:
        return []
    uniq = sorted({(e, n, v) for _, e, n, v in entries})
    try:
        hits = query_osv(uniq)
    except (OSError, ValueError) as e:
        return [Finding(INFO, "scan-error", "(deps)", "could not reach OSV: %s" % str(e)[:100])]
    bad = {uniq[i]: ids for i, ids in hits.items()}
    out = []
    for path, eco, name, ver in entries:
        ids = bad.get((eco, name, ver))
        if ids:
            out.append(Finding(HIGH, "malicious-dependency", path,
                               "pins %s@%s, which OSV lists as malware (%s)" % (name, ver, ", ".join(ids[:3]))))
    out.append(Finding(INFO, "malicious-dependency", "(deps)",
                       "checked %d locked packages against OSV malware advisories" % len(uniq)))
    return out


def collect_worktree(root):
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if is_lockfile(fn):
                full = os.path.join(dirpath, fn)
                try:
                    with open(full, "rb") as fh:
                        files[os.path.relpath(full, root).replace(os.sep, "/")] = fh.read()
                except OSError:
                    pass
    return files
