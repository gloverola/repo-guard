# repo-guard

[![CI](https://github.com/gloverola/repo-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gloverola/repo-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/git-repo-guard)](https://pypi.org/project/git-repo-guard/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**repo-guard scans every git clone for hidden malware before any of its code can run.** It blocks or quarantines infected clones, scans the repos already on your machine, and helps you clean up.

```bash
pipx install git-repo-guard && repo-guard setup
```

## The problem

In 2026, npm and config-file worms ("Contagious Interview", PolinRider) spread through developers' git repositories:

- Code hidden after hundreds of spaces in `eslint.config.js`, `vite.config.mjs` or `postcss.config.mjs`, so it sits off-screen in editors and diffs.
- VS Code tasks that run as soon as you **open the folder**.
- JavaScript disguised as font files, launched by `node init &&` inserted into `npm run dev`.
- Existing commits rewritten and force-pushed, often to branches and tags nobody checks out.

Opening the project or running `dev`, `build` or `lint` was enough. The worm stole the machine's tokens and pushed itself into every repo the developer could reach.

Most tools look at a repo after it is on your disk, and only at the branch you have checked out. By then the payload is one click away from running.

## The solution

repo-guard checks code **before** it can run, everywhere it can arrive:

- **Every clone, from any app.** `repo-guard setup` adds git template hooks, so clones made by VS Code, GitHub Desktop, JetBrains, `gh` or a terminal are scanned on their first checkout. Infected clones are quarantined: the files are removed before anything can open them.
- **Every branch and tag, before checkout.** `repo-guard clone` reads git's object store without writing a single file, so payloads hidden on side branches and old tags are caught too.
- **Before you clone.** `repo-guard check owner/repo` scans a GitHub repo's archive in memory: no git, nothing written.
- **On pull and commit.** Hooks warn about infected files a pull brings in, and refuse commits that add them.
- **Cleanup.** `repo-guard clean` proposes the fix, shows the diff and applies it only when you say yes.
- **CI and AI agents.** A GitHub Action with code-scanning (SARIF) results, and an MCP server so agents check repos before cloning them.
- **Nothing to trust but itself.** Python standard library only (no dependencies), never runs code from a scanned repo, uses the network only when you ask, and releases are built and signed in CI.

See [what it detects](#what-it-detects) for the full list of techniques.

## Install

You need **git** and **Python 3.8+**. The package is called `git-repo-guard`; the command is `repo-guard`.

```bash
pipx install git-repo-guard              # recommended
brew install gloverola/tap/repo-guard    # Homebrew
pip install --user git-repo-guard        # plain pip
```

Homebrew can sit silently for a few minutes while it updates itself; `HOMEBREW_NO_AUTO_UPDATE=1 brew install gloverola/tap/repo-guard` skips that.

From source, which also adds a `git clone` / `git pull` wrapper to your shell:

```bash
git clone https://github.com/gloverola/repo-guard.git && cd repo-guard
./install.sh                                              # macOS / Linux
powershell -ExecutionPolicy Bypass -File .\install.ps1    # Windows (PowerShell and Git Bash)
```

Release files carry [build provenance attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations): `gh attestation verify <file> --repo gloverola/repo-guard`.

## Setup

```bash
repo-guard setup              # protect every future clone, from any app
repo-guard selftest           # every line must say PASS
repo-guard scan-all ~/code    # check the repos you already have
```

`setup` keeps your existing `init.templateDir` (its files are copied in, and its hooks still run after repo-guard's). Template hooks only reach repos cloned or created after setup, which is why `scan-all` is the third step. `repo-guard setup --status` shows whether protection is on.

Upgrade with `pipx upgrade git-repo-guard` (or `brew upgrade repo-guard`), and remove everything with `repo-guard uninstall`.

## Commands

| Command | What it does |
|---|---|
| `repo-guard scan [PATH]` | Scan a repo: working files, every branch and tag, local git config and hooks, rewritten commits. |
| `repo-guard scan-all [ROOT]` | Scan every repo under a folder (default: current folder); lists only the infected ones. |
| `repo-guard clone URL [DIR]` | Hardened clone: no checkout until every branch and tag scans clean. Accepts `git clone` options. |
| `repo-guard check URL` | Scan a GitHub repo before cloning (`owner/repo` or a github.com URL). |
| `repo-guard setup` | Install the git template hooks: clone quarantine, pull warnings, pre-commit check. |
| `repo-guard pre-commit [FILES]` | Scan staged changes; exit 1 if infected. Used by the hook and by [pre-commit](https://pre-commit.com). |
| `repo-guard clean [PATH]` | Propose a fix for an infected working tree, show the diff, apply after you confirm. |
| `repo-guard rules` | List every detection rule and its severity. |
| `repo-guard allowlist` | Show your allowlist file and its entries. |
| `repo-guard mcp` | Run the MCP server on stdio for AI agents. |
| `repo-guard selftest` | Check that detection and blocking work on this machine. |
| `repo-guard uninstall` | Remove repo-guard: hooks, shell wrapper, config and the program itself. |
| `repo-guard --version` / `--help` | Version, or help (also `repo-guard COMMAND --help`). |

**Options**

| Option | Commands | Meaning |
|---|---|---|
| `--format text\|json\|sarif` | scan, scan-all, check, pre-commit | Output format. |
| `--output FILE`, `-o` | scan, scan-all, check | Write the report to a file. |
| `--fail-on high\|medium\|info\|never` | scan, scan-all, check, clone, pre-commit | Lowest severity that makes the exit code 1 (default `medium`). |
| `--deps` | scan, scan-all, check | Also check lockfiles against OSV malware advisories (uses the network). |
| `--worktree-only` / `--refs-only` | scan | Only the files on disk / only branches and tags. |
| `--no-history` | scan | Skip the rewritten-commit check. |
| `-q`, `--quiet` | scan, scan-all | Print nothing for clean repos. |
| `--ref REF`, `--all-branches` | check | Scan a branch, tag or commit (repeatable), or every branch (up to 30). |
| `--force` | clone | Check out even if something was found. |
| `--status`, `--uninstall`, `--no-pre-commit` | setup | Show status, remove the hooks, or skip the pre-commit hook. |
| `--yes` | clean, uninstall | Don't ask for confirmation. |
| `--keep-allowlist` | uninstall | Keep `~/.config/repo-guard/allow`. |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` error.

**Environment variables:** `REPO_GUARD_OFF=1` skips the hooks for one command (for example `REPO_GUARD_OFF=1 git clone …`, only for repos you trust). `REPO_GUARD_NO_PROGRESS=1` hides the progress line. `GITHUB_TOKEN` is used by `check` for private repos and higher rate limits.

### How each protection point responds

| When | How | If infected |
|---|---|---|
| Any clone, any app | `setup` (git template hooks) | Checked-out files are deleted at once; only `.git` and `REPO-GUARD-QUARANTINE.txt` remain. |
| Clone from a terminal | `repo-guard clone` (or `git clone` with the shell wrapper) | Files are never checked out; submodules, LFS downloads, hooks and fsmonitor are disabled. |
| Before cloning | `repo-guard check` | Reports findings; nothing is downloaded with git. |
| Pull / merge | post-merge hook or shell wrapper | Warns about the infected files the pull brought in. |
| Commit | pre-commit hook | Refuses the commit. |
| CI | [GitHub Action](#github-action) | Fails the job; findings appear in code scanning. |
| AI agents | [MCP server](#mcp-server) | The agent gets an "infected" verdict and the findings. |

To review a quarantined clone, run `repo-guard scan --refs-only DIR`. If you're sure it's safe, `git -C DIR reset --hard` restores the files.

## What it detects

Hidden code after long whitespace, auto-run editor tasks (VS Code, Zed, JetBrains), editor settings that enable them, dev container commands, AI-agent configs (Claude Code hooks, `.mcp.json`, Cursor), fonts and images that are really JavaScript or executables, worm markers and file names, the PolinRider and blockchain-loader signatures, obfuscated and encoded payloads, decode-and-eval, download-and-execute, reverse shells, credential and wallet theft, invisible Unicode, committed executables, secrets and `.env` files, risky install scripts and workflows, rewritten commits and force-pushes, and (with `--deps`) packages with OSV malware advisories.

Every rule, with its severity: [docs/rules.md](docs/rules.md).

## Allowlist

False positives go in **your** allowlist, `~/.config/repo-guard/allow` (`%APPDATA%\repo-guard\allow` on Windows). repo-guard never reads an allowlist from inside a repository, because an attacker controlling the repo would simply allowlist their payload.

```text
# RULE            PATH_GLOB      [REPO_GLOB]
install-script    package.json   ~/code/my-app
committed-binary  vendor/*.dll
```

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
      - uses: gloverola/repo-guard@v1.1.0
        with:
          scope: ${{ github.event_name == 'schedule' && 'all-refs' || 'both' }}
          sarif-category: repo-guard-${{ github.event_name }}
```

Inputs: `path`, `scope` (`worktree`, `all-refs`, `both`), `fail-on`, `deps`, `sarif` (upload to code scanning, default `true`), `sarif-category`. The scheduled run catches payloads force-pushed onto branches between pushes. For production, pin the action to a commit SHA.

## MCP server

`repo-guard mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio with four tools: `check_github_repo`, `scan_local_repo`, `safe_clone` and `list_rules`. For Claude Code:

```bash
claude mcp add repo-guard -- repo-guard mcp
```

Other clients: command `repo-guard`, args `["mcp"]`.

## If it finds something

1. **Stop.** Don't open the folder in an editor, and don't run `npm install`, `dev`, `build`, `lint` or tests in it.
2. Assume the machine that pushed the payload is compromised: rotate GitHub, npm, cloud and SSH credentials from a clean device.
3. Run `repo-guard clean` on the working tree, then `repo-guard scan --refs-only .`, because other branches and tags may still carry the payload. Coordinate with your team before pushing, or the next force-push will undo the cleanup.

Also set `"task.allowAutomaticTasks": "off"` and keep Workspace Trust on in VS Code-based editors. In Zed, keep `"session": { "trust_all_worktrees": false }`.

## Limits

- It recognizes **known** techniques. A clean result is a strong signal, not a guarantee.
- It skips `node_modules`, build output and files over 5 MB, and does not fetch submodules.
- Template hooks run after git has written the files (and then delete them). `repo-guard clone` is stricter, because nothing is written until the scan passes.
- A global `core.hooksPath` disables template hooks; `setup` warns about it.

## Uninstall

```bash
repo-guard uninstall
```

It lists what it will do and asks first. It turns off the git hooks (restoring your previous `init.templateDir`), removes the shell wrapper, deletes `~/.config/repo-guard` (add `--keep-allowlist` to keep your allowlist), and removes the program however you installed it (pipx, Homebrew, pip or the install scripts). Repos cloned in the meantime keep a small hook that does nothing once repo-guard is gone.

## More

[docs/rules.md](docs/rules.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md) · MIT licensed
