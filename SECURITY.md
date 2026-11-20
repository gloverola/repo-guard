# Security policy

## Reporting a vulnerability

Please report vulnerabilities in repo-guard privately through GitHub's
[private vulnerability reporting](https://github.com/gloverola/repo-guard/security/advisories/new).
Don't open a public issue. You should get a reply within a few days.

In scope: anything that makes repo-guard run code from a scanned repository, lets a repository
hide a payload from a scan or allowlist itself, makes an infected clone pass as clean, or
compromises how repo-guard is built and released.

**Detection gaps** (a malware technique repo-guard misses) are welcome as normal issues or pull
requests, with a harmless sample. Never attach live malware: describe it, or build the sample
from split strings like `src/repo_guard/fixtures.py` does.

## How repo-guard protects itself

- **No dependencies.** Python standard library only, so there is nothing to hijack.
- **Never runs scanned code.** Files are read as bytes, archives are never extracted, and every
  git command runs with hooks, fsmonitor and the `ext::` transport disabled. Hooks start Python
  in isolated mode (`-I`), so a repository's files can't shadow repo-guard's modules.
- **User-level allowlist only.** Repositories can't allowlist themselves.
- **Network is opt-in:** only `check` (GitHub archive download) and `--deps` (api.osv.dev).
- **Releases come only from CI**, from signed tags, published to PyPI with trusted publishing
  (no API tokens) and with build provenance attestations. Verify with
  `gh attestation verify <file> --repo gloverola/repo-guard`.
- The repository's own CI scans it with repo-guard, and its tests assert it never flags itself.

## Supported versions

Only the latest release gets fixes.
