# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the project uses [semantic versioning](https://semver.org/).

## [1.0.0] - 2026-11-20

First public release, published on PyPI as `git-repo-guard` (the command is `repo-guard`).

### Added
- Python package with the `repo-guard` command (standard library only), installable with pipx,
  pip or Homebrew; `install.sh` / `install.ps1` build a single-file zipapp.
- `repo-guard setup`: git template hooks scan every new clone from any app on first checkout and
  quarantine infected ones; merges with an existing `init.templateDir`; post-merge warnings and a
  pre-commit hook.
- `repo-guard check <github-url>`: scan a GitHub repository from its archive before cloning.
- `repo-guard pre-commit` and `.pre-commit-hooks.yaml`.
- `repo-guard clean`: proposes a fix, shows the diff, applies only after confirmation.
- `repo-guard mcp`: MCP server for AI agents.
- GitHub Action with SARIF upload; `--format json|sarif`, `--output`, `--fail-on`.
- User-level allowlist (`~/.config/repo-guard/allow`); repositories can never allowlist themselves.
- `--deps`: lockfiles checked against OSV malware advisories (`MAL-*`).
- Rules: dev containers, JetBrains startup tasks, AI-agent configs, editor settings, encoded blobs,
  invisible Unicode, secret theft, download-and-execute, reverse shells, committed executables,
  PolinRider and blockchain-loader signatures, committed secrets and `.env` files, risky
  Dockerfiles, rewritten commits, force-pushes. See `docs/rules.md`.
- Hardened clone: submodules, LFS smudge, hooks and fsmonitor disabled.
- CI on macOS, Linux and Windows with Python 3.8 to 3.13; releases with trusted publishing and
  build provenance attestations.

## [0.2.0] - 2026-11-20

Internal single-file version: `scan`, `scan-all`, `clone`, `selftest`, shell hooks.
