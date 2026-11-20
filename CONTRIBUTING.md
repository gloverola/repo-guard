# Contributing

Thanks for helping. Issues and pull requests are welcome, especially new detection rules for
techniques seen in the wild.

## Ground rules

- **Standard library only**, Python 3.8+. No runtime dependencies, ever.
- **Never execute anything from a scanned repository.** Read bytes; run git only through
  `gitutil.git()` (which disables hooks and fsmonitor).
- **No live malware in the repo.** Fixtures in `src/repo_guard/fixtures.py` are harmless and
  built from split strings at runtime, so the repository never matches its own rules.
- **Patterns must not match their own source text.** Write `Ld14V[B]` rather than the literal.
  `python3 -m unittest` includes a test that scans this repository and fails on any finding.
- Network access only in opt-in features (`check`, `--deps`), and tests must mock it.
- Keep output short; every finding names its rule.

## Development

```bash
python3 -m unittest                      # all tests (no network, no changes to your git config)
PYTHONPATH=src python3 -m repo_guard selftest
PYTHONPATH=src python3 -m repo_guard scan .
```

## Adding a rule

1. Add the id, default severity and one-line description to `RULES` in `src/repo_guard/rules.py`,
   and the check to `scan_content` (or a helper it calls).
2. Add a harmless fixture that triggers it to `bad_files()` in `fixtures.py`. If ordinary projects
   have something similar, add that to `clean_files()` too: it must stay quiet.
3. Document it in `docs/rules.md` (a `### rule-id` section; a test checks this).
4. Run `repo-guard scan-all` over a folder of real projects and look at every new finding before
   opening the PR: false positives cost users trust.

## Releasing (maintainers)

1. Update `__version__` in `src/repo_guard/__init__.py` and add the section to `CHANGELOG.md`.
2. Commit, then push a signed tag: `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
3. The `release` workflow tests, builds, attests, publishes to PyPI and creates the GitHub release.
4. Update `url` and `sha256` in the Homebrew tap's `Formula/repo-guard.rb`
   (template: `packaging/homebrew/repo-guard.rb`).
