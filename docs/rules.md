# Detection rules

Every finding names its rule. Severities: **HIGH** (malware indicator), **MEDIUM** (needs review; fails the scan by default), **INFO** (awareness only). Change the threshold with `--fail-on`, and silence a known false positive in your [allowlist](../README.md#allowlist). `repo-guard rules` prints this list.

Documentation files (`.md`, `.mdx`, `.txt`, `.rst`, `.adoc`) are never matched against indicators, because they may quote them; only `hidden-unicode` applies to them.

| Rule | Default | What it means |
|---|---|---|
| [`known-indicator`](#known-indicator) | HIGH | Known worm or malware indicator (C2 address, payload marker, key) |
| [`worm-file`](#worm-file) | HIGH | File name or workflow marker used by npm worms |
| [`hidden-code`](#hidden-code) | HIGH | Code hidden after a long run of whitespace |
| [`auto-run-task`](#auto-run-task) | HIGH | Editor task that runs automatically when the folder is opened |
| [`fake-asset`](#fake-asset) | HIGH | Font, image or archive that is really text or JavaScript |
| [`mislabeled-image`](#mislabeled-image) | INFO | Image file that is really an SVG/XML image |
| [`obfuscated-require`](#obfuscated-require) | HIGH | require() of a module name hidden with \u escapes |
| [`obfuscated-code`](#obfuscated-code) | MEDIUM | Obfuscator output (many _0x identifiers) |
| [`decode-and-run`](#decode-and-run) | MEDIUM | eval / new Function on decoded data |
| [`config-network`](#config-network) | HIGH | Build/lint config file contacts a raw IP address |
| [`worm-gitignore`](#worm-gitignore) | HIGH | .gitignore hides worm auto-push files |
| [`risky-script`](#risky-script) | HIGH | package.json script downloads, pipes to a shell or runs inline code |
| [`install-script`](#install-script) | INFO | package.json script that runs on install |
| [`runs-odd-file`](#runs-odd-file) | MEDIUM | Script runs `node <file>` without a .js extension or from an asset path |
| [`workflow-secrets`](#workflow-secrets) | HIGH | GitHub workflow dumps all secrets |
| [`workflow-pipe-shell`](#workflow-pipe-shell) | MEDIUM | GitHub workflow pipes a download into a shell |
| [`risky-git-hook`](#risky-git-hook) | MEDIUM | Committed git hook (husky) downloads or decodes something |
| [`devcontainer-command`](#devcontainer-command) | MEDIUM | Dev container runs commands (initializeCommand runs on the host) |
| [`jetbrains-autorun`](#jetbrains-autorun) | HIGH | JetBrains project runs a configuration on open, or a risky run configuration |
| [`ai-agent-config`](#ai-agent-config) | MEDIUM | AI agent config runs commands or redirects the agent (Claude, MCP, Cursor) |
| [`editor-settings`](#editor-settings) | HIGH | Editor workspace settings turn on automatic tasks or disable trust |
| [`encoded-blob`](#encoded-blob) | MEDIUM | Long encoded blob in source code |
| [`hidden-unicode`](#hidden-unicode) | HIGH | Invisible Unicode (tag or bidi characters) that can hide code or instructions |
| [`secret-theft`](#secret-theft) | MEDIUM | Code reads SSH keys, cloud credentials, Keychain, browser profiles or wallets |
| [`download-exec`](#download-exec) | HIGH | Code downloads something and executes it |
| [`reverse-shell`](#reverse-shell) | HIGH | Reverse shell |
| [`committed-binary`](#committed-binary) | MEDIUM | Committed executable (Mach-O, ELF or PE) |
| [`blockchain-loader`](#blockchain-loader) | HIGH | Blockchain remote-code loader |
| [`committed-secret`](#committed-secret) | MEDIUM | Committed credential (value never printed) |
| [`committed-env`](#committed-env) | MEDIUM | Committed .env file |
| [`risky-dockerfile`](#risky-dockerfile) | INFO | Dockerfile downloads and runs code or contacts a raw IP |
| [`rewritten-commit`](#rewritten-commit) | INFO | Commit rewritten after it was authored (committer date differs) |
| [`force-push`](#force-push) | INFO | Remote branch was force-pushed (reflog forced-update) |
| [`malicious-dependency`](#malicious-dependency) | HIGH | Lockfile pins a package with an OSV malware advisory (MAL-*) |
| [`local-git-hook`](#local-git-hook) | MEDIUM | Active git hook in .git/hooks |
| [`local-git-config`](#local-git-config) | MEDIUM | Local git config that can run commands or redirect pushes |
| [`submodules`](#submodules) | INFO | Repository has submodules that were not scanned |
| [`scan-error`](#scan-error) | MEDIUM | Part of the repository could not be scanned |
| [`not-fetched`](#not-fetched) | INFO | Partial clone: some files were not downloaded and not scanned |

### known-indicator

Exact strings from known worm payloads: C2 addresses, loader keys, payload markers such as the `global.i` assignment, and the PolinRider signature. Treat the repo as infected.

### worm-file

File names the npm worms drop (`setup_bun.js`, `bun_environment.js`, `branch_structure.json`) and Shai-Hulud workflow markers.

### hidden-code

Code after 150+ spaces or tabs on one line, so it sits off-screen in editors and diffs. This is how the 2025-26 config-file worm hides its payload in `eslint`/`vite`/`postcss`/`tailwind`/`next` configs. `repo-guard clean` strips it.

### auto-run-task

`.vscode/tasks.json` with `runOn: folderOpen`, or a Zed task hooked to worktree creation: opening the folder runs it. `clean` switches it off, or deletes the file when it only runs a dropper.

### fake-asset

A `.woff2`, `.ttf`, `.png`, `.ico`, ... that is really text (usually JavaScript). Droppers hide here and get run with `node public/fonts/x.woff2`.

### mislabeled-image

An image extension holding an SVG/XML image. Usually harmless.

### obfuscated-require

`require()` with a `\u`-escaped module name, a trick to hide `child_process` or `http`.

### obfuscated-code

Many `_0x1234`-style identifiers (javascript-obfuscator output). HIGH in config files and extension-less files, MEDIUM elsewhere. Minified files and build output are skipped.

### decode-and-run

`eval` or `new Function` on `atob`/base64/`fromCharCode`/`Buffer.from` output.

### config-network

A build or lint config file that contains a raw-IP URL.

### worm-gitignore

`.gitignore` entries the worm adds to hide its auto-push scripts. `clean` removes them and restores the lines the worm deleted (found in git history).

### risky-script

A `package.json` script that downloads (`curl`, `wget`, `Invoke-WebRequest`), pipes to a shell, decodes base64 or contacts a raw IP. HIGH for install-time scripts (`preinstall`, `postinstall`, `prepare`, ...), which also may not run inline code (`node -e`).

### install-script

A script that runs on `npm install`. Information only.

### runs-odd-file

`node init`, `node .vscode/ini`, `node public/x.woff2`: a script running a file without a `.js` extension (MEDIUM) or from an asset path (HIGH). The worm prefixes `dev`/`build`/`lint` with `node init &&`. `clean` removes the call.

### workflow-secrets

A GitHub workflow that serialises every secret (`toJSON(secrets)`), the exfiltration step of Shai-Hulud style worms.

### workflow-pipe-shell

A workflow step that pipes a download into a shell.

### risky-git-hook

A committed husky hook that downloads or runs inline code.

### devcontainer-command

Dev container lifecycle commands. `initializeCommand` runs on your machine, not in the container. INFO for plain commands, MEDIUM/HIGH (host) when they download or run inline code.

### jetbrains-autorun

JetBrains startup tasks run a configuration when the project opens (HIGH); shell run configurations that download or run inline code (MEDIUM).

### ai-agent-config

Repo-level AI agent settings: Claude Code `hooks` (run commands automatically), `env` overrides such as `ANTHROPIC_BASE_URL` (redirects the agent's traffic), `enableAllProjectMcpServers`, and MCP servers in `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` that run shell one-liners or asset files. Plain MCP servers are INFO.

### editor-settings

`.vscode/settings.json` or `.code-workspace` that turns on automatic tasks, turns off Workspace Trust, auto-approves agent tools (HIGH), or points an executable setting at a file in the repo (MEDIUM).

### encoded-blob

A base64 run of 1500+ characters or 300+ `\x` escapes in source code (data URIs and lockfile hashes are ignored). HIGH when the file also evaluates code or is a config file.

### hidden-unicode

Unicode tag characters (invisible text that AI agents still read) anywhere, and bidi control characters (Trojan Source) in code and agent instruction files such as `CLAUDE.md`, `AGENTS.md`, `.cursorrules`. Flag emoji are allowed.

### secret-theft

Code that reads SSH keys, cloud credentials, the macOS Keychain, browser profiles or crypto wallets. HIGH when it reads two kinds and talks to the network; MEDIUM for wallets/browser data or two kinds; INFO for one.

### download-exec

Downloading code and executing it: `eval(await fetch(...))`, `exec(requests.get(...).text)`, `curl ... | node`, PowerShell `iex (... DownloadString ...)`. Piping into `node script.js` or `node -e` (data, not code) is not flagged.

### reverse-shell

Classic reverse shells: `/dev/tcp/HOST/PORT`, `nc -e /bin/sh`, `mkfifo` + `nc`, Python `dup2` + `pty.spawn`, PowerShell `TCPClient` + `iex`, Node `net.Socket` piped into a shell.

### committed-binary

A committed ELF, Mach-O or Windows PE executable. HIGH when its name pretends to be something else (an executable called `logo.png`, also flagged in working files); MEDIUM for executables and libraries; INFO for `.node` addons.

### blockchain-loader

The loader that fetches its next stage from a blockchain transaction (the `BLOCK_MULTIPLE` + `NONCE_FANOUT` signature, or RPC calls like `eth_getTransactionByHash` together with `eval`).

### committed-secret

AWS, GitHub, Slack, Stripe, npm, OpenAI and Anthropic keys and private keys, in committed files only. The value is never printed. Test and fixture paths and `EXAMPLE` values are skipped; Google API keys are INFO because browser keys are public by design.

### committed-env

A committed `.env`, `.env.local`, `.env.production`, ... (`.env.example`, `.sample`, `.template` are fine).

### risky-dockerfile

A Dockerfile that contacts a raw IP (HIGH) or pipes a download into a shell (INFO).

### rewritten-commit

Commits whose committer date or timezone differs from the author date: the worm rewrites existing commits and force-pushes them. MEDIUM when the rewritten commit changed a file that has findings; otherwise a single INFO count (rebases and amends are normal causes). Commits made by github.com are ignored.

### force-push

`forced-update` entries in your fetch reflog. MEDIUM for `main`/`master`/`develop`/`trunk`, INFO for other branches.

### malicious-dependency

With `--deps`: a lockfile (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt`) pins a version that OSV lists as malware (`MAL-*`). Ordinary CVEs are out of scope. Uses the network (api.osv.dev).

### local-git-hook

An active hook in `.git/hooks` that you (or malware on your machine) installed. repo-guard's own hooks and hooks identical to your git template are not reported.

### local-git-config

Local git config that can run commands or redirect pushes: `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.editor`, `diff.external`, aliases, credential helpers, `url.*.insteadOf`, custom filter/diff/merge drivers.

### submodules

`repo-guard clone` never clones submodules; this lists them so you can scan and clone each one.

### scan-error

Something could not be scanned (an unreadable branch, a failed download). Never treated as clean.

### not-fetched

A partial clone: some files were never downloaded, so they were not scanned (repo-guard never triggers lazy fetches).
