# repo-guard

[![CI](https://github.com/gloverola/repo-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gloverola/repo-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/git-repo-guard)](https://pypi.org/project/git-repo-guard/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**repo-guard scans every git clone for hidden malware before any of its code can run.** It blocks or quarantines infected clones, scans the repos already on your machine, and helps you clean up.

It was built during a 2026 outbreak of npm/config-file worms ("Contagious Interview", PolinRider): code hidden behind hundreds of spaces in `eslint.config.js`, `vite.config.mjs` or `postcss.config.mjs`, VS Code tasks that run when you open the folder, JavaScript disguised as font files, droppers wired into `npm run dev`. Opening the folder or running `dev`/`build`/`lint` infected the machine, stole its tokens, and force-pushed the payload into every repo the victim could reach, often on branches nobody had checked out.

What makes it different:

- **Automatic, from any app.** `repo-guard setup` installs git template hooks, so clones made by VS Code, GitHub Desktop, JetBrains, `gh` or a terminal are all scanned on their first checkout and quarantined if infected.
- **Every branch and tag, before checkout.** `repo-guard clone` reads git's object store without writing a single file, so payloads hiding on side branches and old tags are caught too.
- **Helps you clean up.** `repo-guard clean` proposes the fix (strip payloads, delete droppers, restore the `.gitignore` lines the worm removed), shows the diff, and applies it only when you say yes.
- **Standard library only.** Python 3.8+ and git; no dependencies to hijack. Never runs code from the repos it scans. Uses the network only when you ask (`check`, `--deps`).

## Install

You need **git** and **Python 3.8+**.

```bash
pipx install git-repo-guard      # or: pip install --user git-repo-guard (the command is `repo-guard`)
brew install gloverola/tap/repo-guard
```

Then turn on automatic protection and check it works:

```bash
repo-guard setup                 # scan every future clone, from any app
repo-guard selftest              # every line must say PASS
```

**From source** (also adds a `git clone`/`git pull` wrapper to your shell):

```bash
git clone https://github.com/gloverola/repo-guard.git && cd repo-guard
./install.sh                     # macOS / Linux
powershell -ExecutionPolicy Bypass -File .\install.ps1    # Windows (PowerShell and Git Bash)
```

Release files carry [build provenance attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations); verify a download with `gh attestation verify <file> --repo gloverola/repo-guard`.

## Protection points

| When | How | What happens if infected |
|---|---|---|
| Any clone, any app | `repo-guard setup` (git template hooks) | The checked-out files are deleted right away (quarantine); only `.git` and `REPO-GUARD-QUARANTINE.txt` remain. Nothing can run. |
| Clone from a terminal | `repo-guard clone URL [DIR]` (or `git clone` with the shell wrapper) | Files are never checked out. Submodules, LFS downloads, hooks and fsmonitor are disabled. |
| Before cloning | `repo-guard check owner/repo` | Downloads the GitHub source archive and scans it in memory. No git, nothing extracted. |
| Pull / merge | post-merge hook, or the shell wrapper | Warns about infected files the pull brought in. |
| Commit | pre-commit hook (`setup`), or [pre-commit](https://pre-commit.com) | Refuses to commit infected files. |
| CI | [GitHub Action](#github-action) | Fails the job; SARIF in code scanning; daily all-branch scan. |
| AI agents | [MCP server](#mcp-server) | Agents check a repo before cloning or opening it. |

`setup` keeps your existing `init.templateDir` (its files are copied in, and its hooks still run after repo-guard's). `repo-guard setup --uninstall` restores it. Template hooks only reach repos cloned or initialised after setup: scan older ones with `scan-all`. Skip the check once with `REPO_GUARD_OFF=1`.

To review a quarantined clone: `repo-guard scan --refs-only DIR`. If you are sure it is safe, `git -C DIR reset --hard` restores the files.

## Everyday use

```bash
repo-guard scan .                    # working files + every branch and tag + git config/hooks
repo-guard scan-all ~/code           # every repo under a folder; lists only infected ones
repo-guard check owner/repo --all-branches
repo-guard scan . --deps             # also check lockfiles against OSV malware advisories
repo-guard clean .                   # propose a fix, show the diff, apply after you confirm
repo-guard rules                     # list detection rules
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `medium`), `2` error.
Output: `--format text|json|sarif`, `--output FILE`.

## What it detects

Hidden code after long whitespace, auto-run editor tasks (VS Code, Zed, JetBrains), editor settings that enable them, dev container commands, AI-agent configs (Claude Code hooks, `.mcp.json`, Cursor), fonts and images that are really JavaScript or executables, worm markers and file names, the PolinRider and blockchain-loader signatures, obfuscated and encoded payloads, decode-and-eval, download-and-execute, reverse shells, credential and wallet theft, invisible Unicode, committed executables, secrets and `.env` files, risky install scripts and workflows, rewritten commits and force-pushes, and (with `--deps`) packages with OSV malware advisories.

Full list with severities: [docs/rules.md](docs/rules.md).

## Allowlist

False positives go in **your** allowlist, `~/.config/repo-guard/allow` (`%APPDATA%\repo-guard\allow` on Windows). repo-guard never reads an allowlist from inside a repository: an attacker controlling the repo would simply allowlist their payload.

```text
# RULE        PATH_GLOB      [REPO_GLOB]
install-script  package.json   ~/code/my-app
committed-binary  vendor/*.dll
```

`repo-guard allowlist` shows the file in use.

## GitHub Action

```yaml
# .github/workflows/repo-guard.yml
on:
  push:
  pull_request:
  schedule: [{ cron: "17 5 * * *" }]   # daily scan of every branch and tag
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: ${{ github.event_name == 'schedule' && '0' || '1' }}
          persist-credentials: false
      - uses: gloverola/repo-guard@v1
        with:
          scope: ${{ github.event_name == 'schedule' && 'all-refs' || 'both' }}
          sarif-category: repo-guard-${{ github.event_name }}
```

Inputs: `path`, `scope` (`worktree`, `all-refs`, `both`), `fail-on`, `deps`, `sarif` (upload to code scanning, default `true`), `sarif-category`. The scheduled run catches payloads force-pushed onto branches between pushes. Pin the action to a commit SHA in production.

## MCP server

`repo-guard mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio with four tools: `check_github_repo`, `scan_local_repo`, `safe_clone` and `list_rules`. For Claude Code:

```bash
claude mcp add repo-guard -- repo-guard mcp
```

Other clients: command `repo-guard`, args `["mcp"]`.

## If it finds something

1. **Stop.** Don't open the folder in an editor, and don't run `npm install`, `dev`, `build`, `lint` or tests in it.
2. Assume the machine that pushed the payload is compromised: rotate GitHub, npm, cloud and SSH credentials from a clean device.
3. Run `repo-guard clean` for the working tree, then `repo-guard scan --refs-only .`: other branches and tags may still carry the payload. Coordinate with your team before pushing, or the next force-push will undo the cleanup.

Also set `"task.allowAutomaticTasks": "off"` and keep Workspace Trust on in VS Code-based editors; in Zed keep `"session": { "trust_all_worktrees": false }`.

## Limits

- It recognizes **known** techniques. A clean result is a strong signal, not a guarantee.
- It skips `node_modules`, build output and files over 5 MB, and does not fetch submodules.
- Template hooks run after git has written the files (then delete them); `repo-guard clone` is stricter because nothing is written until the scan passes.
- A global `core.hooksPath` disables template hooks; `setup` warns about it.

## More

[docs/rules.md](docs/rules.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md) · MIT licensed
