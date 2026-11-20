"""Content rules: everything repo-guard can tell from one file's path and bytes.

Patterns are written so their own source text never matches them (for example
`Ld14V[B]`), so repo-guard can scan itself without flagging its own rules.
"""

import json
import os
import re

from .findings import HIGH, INFO, MEDIUM, Finding, excerpt, is_textish, line_of

MAX_BLOB = 5 * 1024 * 1024
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".turbo",
    ".cache", "coverage", ".venv", "venv", "__pycache__", ".expo", "Pods",
    ".gradle", ".build", "DerivedData", ".output", ".svelte-kit", ".parcel-cache", ".vercel",
}
DOC_EXT = (".md", ".mdx", ".txt", ".rst", ".adoc")
JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
CODE_EXT = JS_EXT + (".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".rb",
                     ".php", ".pl", ".lua", ".vbs", "")

# Rule catalogue: id -> (default severity, one-line description). Used by SARIF and docs.
RULES = {
    "known-indicator": (HIGH, "Known worm or malware indicator (C2 address, payload marker, key)"),
    "worm-file": (HIGH, "File name or workflow marker used by npm worms"),
    "hidden-code": (HIGH, "Code hidden after a long run of whitespace"),
    "auto-run-task": (HIGH, "Editor task that runs automatically when the folder is opened"),
    "fake-asset": (HIGH, "Font, image or archive that is really text or JavaScript"),
    "mislabeled-image": (INFO, "Image file that is really an SVG/XML image"),
    "obfuscated-require": (HIGH, "require() of a module name hidden with \\u escapes"),
    "obfuscated-code": (MEDIUM, "Obfuscator output (many _0x identifiers)"),
    "decode-and-run": (MEDIUM, "eval / new Function on decoded data"),
    "config-network": (HIGH, "Build/lint config file contacts a raw IP address"),
    "worm-gitignore": (HIGH, ".gitignore hides worm auto-push files"),
    "risky-script": (HIGH, "package.json script downloads, pipes to a shell or runs inline code"),
    "install-script": (INFO, "package.json script that runs on install"),
    "runs-odd-file": (MEDIUM, "Script runs `node <file>` without a .js extension or from an asset path"),
    "workflow-secrets": (HIGH, "GitHub workflow dumps all secrets"),
    "workflow-pipe-shell": (MEDIUM, "GitHub workflow pipes a download into a shell"),
    "risky-git-hook": (MEDIUM, "Committed git hook (husky) downloads or decodes something"),
    "devcontainer-command": (MEDIUM, "Dev container runs commands (initializeCommand runs on the host)"),
    "jetbrains-autorun": (HIGH, "JetBrains project runs a configuration on open, or a risky run configuration"),
    "ai-agent-config": (MEDIUM, "AI agent config runs commands or redirects the agent (Claude, MCP, Cursor)"),
    "editor-settings": (HIGH, "Editor workspace settings turn on automatic tasks or disable trust"),
    "encoded-blob": (MEDIUM, "Long encoded blob in source code"),
    "hidden-unicode": (HIGH, "Invisible Unicode (tag or bidi characters) that can hide code or instructions"),
    "secret-theft": (MEDIUM, "Code reads SSH keys, cloud credentials, Keychain, browser profiles or wallets"),
    "download-exec": (HIGH, "Code downloads something and executes it"),
    "reverse-shell": (HIGH, "Reverse shell"),
    "committed-binary": (MEDIUM, "Committed executable (Mach-O, ELF or PE)"),
    "blockchain-loader": (HIGH, "Blockchain remote-code loader"),
    "committed-secret": (MEDIUM, "Committed credential (value never printed)"),
    "committed-env": (MEDIUM, "Committed .env file"),
    "risky-dockerfile": (INFO, "Dockerfile downloads and runs code or contacts a raw IP"),
    "rewritten-commit": (INFO, "Commit rewritten after it was authored (committer date differs)"),
    "force-push": (INFO, "Remote branch was force-pushed (reflog forced-update)"),
    "malicious-dependency": (HIGH, "Lockfile pins a package with an OSV malware advisory (MAL-*)"),
    "local-git-hook": (MEDIUM, "Active git hook in .git/hooks"),
    "local-git-config": (MEDIUM, "Local git config that can run commands or redirect pushes"),
    "submodules": (INFO, "Repository has submodules that were not scanned"),
    "scan-error": (MEDIUM, "Part of the repository could not be scanned"),
    "not-fetched": (INFO, "Partial clone: some files were not downloaded and not scanned"),
}

# --- indicators -------------------------------------------------------------------

IOC_PATTERNS = [
    (re.compile(rb"95\.135\.181\.84|194\.11\.226\.162"), "known malware C2 address"),
    (re.compile(rb"q4FZkxX\{!h,Sr3=@"), "known loader decryption key"),
    (re.compile(rb"\.npm-ws(?:-runner\.js|\.json|\.pid)"), "known npm-hijack loader file"),
    (re.compile(rb"Ld14V[B]"), "known payload folder name"),
    (re.compile(rb"global\.i\s*=\s*[\"']A\d+"), "worm payload marker (global.i=\"A..\")"),
    (re.compile(rb"global\._t_s\b"), "worm payload marker (global _t_s)"),
    (re.compile(rb"global\[\s*[\"']!\s*[\"']\s*\]\s*=\s*[\"']\d+"), "worm payload marker (global['!']=)"),
    (re.compile(rb"Z2xvYmFsW[y]ch"), "base64 of a worm payload marker (global['!'])"),
    (re.compile(rb"rmcej%ot[b]%"), "PolinRider payload signature"),
    (re.compile(rb"temp_(?:auto|interactive)_push\.bat"), "worm auto-push artifact"),
]
WORM_FILENAMES = {"setup_bun.js", "bun_environment.js", "branch_structure.json"}
WORM_GITIGNORE = re.compile(rb"temp_(?:auto|interactive)_push\.bat|branch_structure\.json")

HIDDEN_CODE = re.compile(rb"[ \t]{150,}(\S.{0,200})")
CODE_LIKE = re.compile(rb"[;(){}=]|\b(?:require|function|eval|global|import|var|const|let)\b")
JS_LIKE = re.compile(rb"\b(?:require|function|eval|global|module|exports|process|const|let|var)\b|=>")
UNICODE_REQUIRE = re.compile(rb"require\(\s*[\"'](?:\\u00[0-9a-fA-F]{2}){3,}")
OBFUSCATED = re.compile(rb"_0x[0-9a-f]{4,6}")
DECODE_EXEC = re.compile(
    rb"(?<![\w$.])(?:eval|new\s+Function)\s*\([^)]{0,80}(?:atob|base64|fromCharCode|Buffer\.from)")
RAW_IP_URL = re.compile(rb"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")
EVAL_ANY = re.compile(rb"(?<![\w$.])(?:eval|exec|new\s+Function|Function)\s*\(")

CONFIG_FILE = re.compile(
    r"(?:^|/)(?:(?:eslint|vite|vitest|next|nuxt|postcss|tailwind|babel|webpack|rollup|"
    r"jest|prettier|tsup|astro|svelte|metro|app)\.config\.[cm]?[jt]s|\.eslintrc\.[cm]?js|"
    r"init|index\.cjs)$")

MAGIC = {
    ".woff2": [b"wOF2"], ".woff": [b"wOFF"],
    ".ttf": [b"\x00\x01\x00\x00", b"true", b"typ1"], ".otf": [b"OTTO", b"\x00\x01\x00\x00"],
    ".eot": None, ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF8"], ".ico": [b"\x00\x00\x01\x00", b"\x00\x00\x02\x00", b"\x89PNG"],
    ".webp": [b"RIFF"], ".mp4": None, ".pdf": [b"%PDF"], ".zip": [b"PK"],
}

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepack", "postpack")
NET_CMD = re.compile(
    r"curl\s|wget\s|\|\s*(?:ba|z)?sh\b|powershell|iwr\s|Invoke-WebRequest|base64\s+-d|--decode|"
    r"https?://\d{1,3}(?:\.\d{1,3}){3}")
INLINE_CMD = re.compile(r"node\s+-e\b|bash\s+-c|sh\s+-c|python3?\s+-c")
RUNS_ODD_FILE = re.compile(r"\bnode\s+(?:\./)?((?:[\w.-]+/)*[\w.-]+)")
BUILD_OUTPUT = ("dist/", "build/", "out/", "lib/", ".output/")

# --- new rule data ------------------------------------------------------------------

# Unicode tag characters (U+E0000-E007F) and bidi overrides, as UTF-8 bytes.
TAG_CHARS = re.compile(rb"\xf3\xa0[\x80\x81][\x80-\xbf]")
BIDI_CHARS = re.compile(rb"\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]")
AGENT_DOCS = re.compile(
    r"(?:^|/)(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|"
    r"copilot-instructions\.md|\.cursor/rules/[^/]+|\.github/instructions/[^/]+)$", re.I)

BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{1500,}={0,2}")
HEX_ESCAPES = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){300,}")

SECRET_THEFT = [
    ("ssh keys", re.compile(rb"\.ssh[/\\]+(?:id_(?:rsa|ed25519|ecdsa|dsa)|known_hosts|config)\b|~/\.ssh\b")),
    ("cloud credentials", re.compile(
        rb"\.aws[/\\]+credentials|\.config[/\\]+gcloud|\.azure[/\\]+|\.kube[/\\]+config|"
        rb"\.docker[/\\]+config\.json|\.npmr[c]\b|\.git-credential[s]")),
    ("macOS Keychain", re.compile(rb"login\.keychain|find-(?:generic|internet)-password|dump-keychai[n]")),
    ("browser profiles", re.compile(
        rb"[/\\\"']Login Data\b|Cookies\.binarycookies|(?:Google[/\\]+Chrome|BraveSoftware|"
        rb"Microsoft[/\\]+Edge)[/\\]+(?:User Data|Default)|Firefox[/\\]+Profiles|key4\.db|logins\.json")),
    ("crypto wallets", re.compile(
        rb"nkbihfbeogaeaoehlefnkodbefgpgkn[n]|bfnaelmomeimhlpmgjnjophhpkkoljp[a]|"
        rb"ejbalbakoplchlghecdalmeeeajnimh[m]|\bExodus[/\\]+exodus\.wallet|\.electrum[/\\]+wallets|"
        rb"solana[/\\]+id\.json|Ethereum[/\\]+keystore|wallet\.da[t]\b")),
]
NETWORKY = re.compile(rb"https?://|\bfetch\(|axios|request\(|urlopen|requests\.(?:get|post)|socket|"
                      rb"https?\.(?:get|request)\(|FormData|upload")

DOWNLOAD_EXEC = [
    re.compile(rb"(?<![\w$.])(?:eval|exec|new\s+Function)\s*\([^;\n]{0,200}?"
               rb"(?:urlopen\(|requests\.get\(|fetch\(|axios\.get\(|https?\.get\(|\.text\(\)|response\.data|res\.data)"),
    # `curl ... | node` runs the download; `| node script.js` or `| node -e "..."` only reads it as data.
    re.compile(rb"(?m)(?:curl|wget)[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:node|python3?|perl|ruby)(?:\s+-)?[ \t]*"
               rb"(?=$|[;&|)])"),
    re.compile(rb"\b(?:iex|Invoke-Expression)\b[^\n]{0,120}(?:Download[S]tring|Invoke-WebReques[t]|iw[r]\b)", re.I),
    re.compile(rb"(?:Download[S]tring|Invoke-WebReques[t]|iw[r]\b)[^\n]{0,120}\|\s*(?:iex|Invoke-Expression)\b", re.I),
]
PIPE_SHELL = re.compile(rb"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")

REVERSE_SHELL = [
    re.compile(rb"/dev/tc[p]/[\w.\-]+/\d+"),
    re.compile(rb"\bn(?:c|cat)\b[^\n]{0,60}\s-[ec]\s+/bin/(?:ba)?sh"),
    re.compile(rb"mkfifo[^\n]{0,80}\bn(?:c|cat)\b"),
    re.compile(rb"os\.dup2\([^)]*fileno\(\)[^)]*\)[\s\S]{0,200}(?:pty\.spawn|subprocess\.call)\(\s*\[?[\"']/bin/(?:ba)?sh"),
    re.compile(rb"Net\.Sockets\.TCPClient[\s\S]{0,300}GetStream[\s\S]{0,300}(?:iex|Invoke-Expression)", re.I),
    re.compile(rb"child_process[\s\S]{0,300}net\.Socket[\s\S]{0,300}\.pipe\("),
]

EXEC_MAGIC = [
    (b"\x7fELF", "ELF"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"), (b"\xfe\xed\xfa\xce", "Mach-O"), (b"\xca\xfe\xba\xbe", "Mach-O universal"),
]
EXEC_EXT = ("", ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".node", ".out", ".com", ".sys", ".elf")

BLOCKCHAIN = [re.compile(rb"BLOCK_MULTIPL[E]"), re.compile(rb"NONCE_FANOU[T]")]
CHAIN_RPC = re.compile(rb"eth_getTransactionByHash|api\.trongrid\.io|fullnode\.mainnet\.aptoslabs|"
                       rb"bsc-dataseed|getTransactionsByAddress")

SECRET_PATTERNS = [
    (re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36}\b"), "GitHub token"),
    (re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}"), "GitHub fine-grained token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
     "private key"),
    (re.compile(rb"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(rb"\b[rs]k_live_[A-Za-z0-9]{20,}"), "Stripe live key"),
    (re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key (often a public browser key; check its restrictions)"),
    (re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b"), "npm token"),
    (re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "OpenAI API key"),
    (re.compile(rb"\bsk-proj-[A-Za-z0-9_\-]{40,}"), "OpenAI API key"),
]
TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|testdata|__mocks__)/|\.(?:test|spec)\.")
ENV_FILE = re.compile(r"^\.env(?:\.[\w.-]+)?$")
ENV_OK_SUFFIX = ("example", "sample", "template", "dist", "defaults", "schema", "tpl", "default")

DEVCONTAINER = re.compile(r"(?:^|/)(?:\.devcontainer/(?:[^/]+/)?devcontainer\.json|\.devcontainer\.json)$")
DEVCONTAINER_KEYS = ("initializeCommand", "onCreateCommand", "updateContentCommand",
                     "postCreateCommand", "postStartCommand", "postAttachCommand")
MCP_CONFIG = re.compile(r"(?:^|/)(?:\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|"
                        r"\.windsurf/mcp\.json|\.gemini/settings\.json|\.roo/mcp\.json)$")
CLAUDE_SETTINGS = re.compile(r"(?:^|/)\.claude/settings(?:\.local)?\.json$")


# --- helpers --------------------------------------------------------------------------

def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas (VS Code style JSON)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_jsonc(data):
    try:
        return json.loads(strip_jsonc(data.decode("utf-8", "replace")))
    except ValueError:
        return None


def strings_in(value):
    """Every string inside a JSON value, flattened."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings_in(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings_in(v)


def risky_command(text):
    return bool(NET_CMD.search(text) or INLINE_CMD.search(text))


def _in_skip(path):
    return any(part in SKIP_DIRS for part in path.split("/")[:-1])


# --- the scanner ----------------------------------------------------------------------

def scan_content(path, data, committed=False):
    """Return findings for one file. `committed` is True for files read from git objects
    or an archive (rules about committing secrets and .env files only apply there)."""
    out = []
    name = path.rsplit("/", 1)[-1]
    lower = path.lower()
    ext = os.path.splitext(lower)[1]
    in_skip = _in_skip(path)

    if name in WORM_FILENAMES:
        out.append(Finding(HIGH, "worm-file", path, "file name used by npm worms (%s)" % name))

    if committed and ENV_FILE.match(name) and not lower.rstrip("/").endswith(ENV_OK_SUFFIX):
        out.append(Finding(MEDIUM, "committed-env", path, "a .env file is committed (secrets belong outside git)"))

    if ext in MAGIC and data:
        magics = MAGIC[ext]
        ok = magics is None or any(data.startswith(m) for m in magics)
        if not ok and _ascii_text(data):
            head = data[:4096].lstrip()
            if re.match(rb"(?:<\?xml|<svg|<!--)", head, re.I) and not re.search(rb"<script", data, re.I):
                out.append(Finding(INFO, "mislabeled-image", path, "%s file is really an SVG/XML image" % ext))
            else:
                looks_js = bool(JS_LIKE.search(head))
                out.append(Finding(HIGH if looks_js else MEDIUM, "fake-asset", path,
                                   "%s file is actually text%s" % (ext, " containing JavaScript" if looks_js else "")))
        elif not ok:
            out.extend(_check_binary(path, data, ext))  # executable disguised as an asset
        return out

    if not is_textish(data):
        if committed:
            out.extend(_check_binary(path, data, ext))
        return out

    is_doc = ext in DOC_EXT
    if not is_doc:
        out.extend(_indicators(path, name, data))
        for m in HIDDEN_CODE.finditer(data):
            tail = m.group(1)
            if CODE_LIKE.search(tail):
                out.append(Finding(HIGH, "hidden-code", path,
                                   "code hidden after a long run of whitespace: " + excerpt(tail, 70),
                                   line_of(data, m.start())))
                break

    out.extend(_hidden_unicode(path, data, ext))

    if lower.endswith(".vscode/tasks.json") and b"folderOpen" in data:
        out.append(Finding(HIGH, "auto-run-task", path,
                           "VS Code task runs automatically when the folder is opened (runOn: folderOpen)"))
    if lower.endswith(".zed/tasks.json") and b"create_worktree" in data:
        sev = HIGH if risky_command(data.decode("utf-8", "replace")) else MEDIUM
        out.append(Finding(sev, "auto-run-task", path, "Zed task runs automatically on worktree creation"))
    if lower.endswith(".vscode/settings.json") or lower.endswith(".code-workspace"):
        out.extend(_editor_settings(path, data))
    if DEVCONTAINER.search(path):
        out.extend(_devcontainer(path, data))
    if "/.idea/" in "/" + lower or lower.startswith(".run/") or "/.run/" in lower:
        out.extend(_jetbrains(path, data))
    if MCP_CONFIG.search(path) or CLAUDE_SETTINGS.search(path):
        out.extend(_agent_config(path, data))

    m = UNICODE_REQUIRE.search(data)
    if m:
        out.append(Finding(HIGH, "obfuscated-require", path,
                           "require() of a module name hidden with \\u escapes", line_of(data, m.start())))

    is_min = ".min." in lower or in_skip
    if not is_min and ext in JS_EXT + ("",):
        n = len(OBFUSCATED.findall(data))
        if n >= 20:
            sev = HIGH if CONFIG_FILE.search(path) or ext == "" else MEDIUM
            out.append(Finding(sev, "obfuscated-code", path, "obfuscator output (%d _0x identifiers)" % n))
        m = DECODE_EXEC.search(data)
        if m:
            out.append(Finding(MEDIUM, "decode-and-run", path,
                               "eval/new Function on decoded data: " + excerpt(m.group(0), 60),
                               line_of(data, m.start())))
        if CONFIG_FILE.search(path):
            m = RAW_IP_URL.search(data)
            if m:
                out.append(Finding(HIGH, "config-network", path,
                                   "config file contacts a raw IP address: " + excerpt(m.group(0)),
                                   line_of(data, m.start())))
    if not is_min and ext in CODE_EXT:
        out.extend(_encoded_blob(path, data))
    if not is_doc:
        out.extend(_behaviour(path, data, ext, in_skip))

    if name == ".gitignore" and WORM_GITIGNORE.search(data):
        out.append(Finding(HIGH, "worm-gitignore", path, ".gitignore hides worm auto-push files"))

    if name == "package.json" and not in_skip:
        out.extend(check_package_json(path, data))

    if lower.startswith(".github/workflows/") or "/.github/workflows/" in lower:
        if re.search(rb"toJSON\(\s*secrets\s*\)", data):
            out.append(Finding(HIGH, "workflow-secrets", path, "workflow dumps all secrets (toJSON(secrets))"))
        if PIPE_SHELL.search(data):
            out.append(Finding(MEDIUM, "workflow-pipe-shell", path, "workflow pipes a download into a shell"))
        if re.search(rb"shai-?hulud", data, re.I):
            out.append(Finding(HIGH, "worm-file", path, "Shai-Hulud workflow marker"))

    if name == "Dockerfile" or name.startswith("Dockerfile.") or lower.endswith(".dockerfile"):
        out.extend(_dockerfile(path, data))

    hook_text = data.decode("utf-8", "replace")
    if ("/.husky/" in "/" + lower and "/_/" not in lower) and risky_command(hook_text):
        out.append(Finding(MEDIUM, "risky-git-hook", path, "husky hook downloads or decodes something"))

    if committed and not is_doc and not in_skip and not TEST_PATH.search(lower):
        out.extend(_secrets(path, data))
    return out


def _ascii_text(data):
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / max(1, len(sample)) > 0.9


def _indicators(path, name, data):
    out = []
    for rx, why in IOC_PATTERNS:
        if name == ".gitignore" and why == "worm auto-push artifact":
            continue  # reported by the worm-gitignore rule
        m = rx.search(data)
        if m:
            out.append(Finding(HIGH, "known-indicator", path, why, line_of(data, m.start())))
    if all(rx.search(data) for rx in BLOCKCHAIN):
        out.append(Finding(HIGH, "blockchain-loader", path,
                           "blockchain remote-code loader signature (block multiple + nonce fanout)"))
    else:
        m = CHAIN_RPC.search(data)
        if m and EVAL_ANY.search(data) and os.path.splitext(path.lower())[1] in JS_EXT + ("",):
            out.append(Finding(HIGH, "blockchain-loader", path,
                               "reads code from a blockchain transaction and evaluates it", line_of(data, m.start())))
    return out


def _hidden_unicode(path, data, ext):
    out = []
    m = next((m for m in TAG_CHARS.finditer(data)
              if not _flag_emoji(data, m.start())), None)
    if m:
        out.append(Finding(HIGH, "hidden-unicode", path,
                           "invisible Unicode tag characters (can hide instructions from reviewers)",
                           line_of(data, m.start())))
    m = BIDI_CHARS.search(data)
    if m and (ext in CODE_EXT and ext != "" or AGENT_DOCS.search(path)):
        out.append(Finding(MEDIUM, "hidden-unicode", path,
                           "bidirectional control characters (code may not read as it runs)",
                           line_of(data, m.start())))
    return out


def _flag_emoji(data, i):
    """Subdivision flag emoji (England, Scotland, Wales) legitimately use tag characters."""
    j = i
    while j >= 4 and TAG_CHARS.match(data, j - 4):
        j -= 4
    return data[max(0, j - 4):j] == b"\xf0\x9f\x8f\xb4"


def _check_binary(path, data, ext):
    for magic, kind in EXEC_MAGIC:
        if data.startswith(magic):
            break
    else:
        kind = None
        if data.startswith(b"MZ") and len(data) > 0x40:
            off = int.from_bytes(data[0x3c:0x40], "little")
            if 0 < off < len(data) - 4 and data[off:off + 4] == b"PE\x00\x00":
                kind = "Windows PE"
    if not kind:
        return []
    if kind == "Mach-O universal" and ext == ".class":
        return []  # Java class files share the magic number
    if ext in EXEC_EXT:
        sev = INFO if ext == ".node" else MEDIUM
        return [Finding(sev, "committed-binary", path, "committed %s executable" % kind)]
    return [Finding(HIGH, "committed-binary", path,
                    "%s executable disguised as a %s file" % (kind, ext or "plain"))]


def _encoded_blob(path, data):
    for rx, what in ((BASE64_RUN, "base64"), (HEX_ESCAPES, "\\x-escaped")):
        for m in rx.finditer(data):
            before = data[max(0, m.start() - 12):m.start()]
            if b"base64," in before or b"sha512-" in before:
                continue  # data: URIs and integrity hashes
            blob = m.group(0)
            if rx is BASE64_RUN and not (re.search(rb"[a-z]", blob) and re.search(rb"[A-Z]", blob)
                                         and re.search(rb"\d", blob)):
                continue
            sev = HIGH if EVAL_ANY.search(data) or CONFIG_FILE.search(path) else MEDIUM
            return [Finding(sev, "encoded-blob", path, "%d-character %s blob in source code" % (len(blob), what),
                            line_of(data, m.start()))]
    return []


def _behaviour(path, data, ext, in_skip):
    out = []
    for rx in REVERSE_SHELL:
        m = rx.search(data)
        if m:
            out.append(Finding(HIGH, "reverse-shell", path, "reverse shell: " + excerpt(m.group(0), 60),
                               line_of(data, m.start())))
            break
    if ext in CODE_EXT or ext in (".json", ".yml", ".yaml", ".toml"):
        for rx in DOWNLOAD_EXEC:
            m = rx.search(data)
            if m:
                out.append(Finding(HIGH, "download-exec", path,
                                   "downloads code and runs it: " + excerpt(m.group(0), 60),
                                   line_of(data, m.start())))
                break
    if ext in CODE_EXT and not in_skip:
        hits = [(what, rx.search(data)) for what, rx in SECRET_THEFT]
        hits = [(what, m) for what, m in hits if m]
        if hits:
            kinds = [w for w, _ in hits]
            if len(hits) >= 2 and NETWORKY.search(data):
                sev = HIGH
            elif any(k in ("browser profiles", "crypto wallets") for k in kinds) or len(hits) >= 2:
                sev = MEDIUM
            else:
                sev = INFO
            out.append(Finding(sev, "secret-theft", path, "reads " + ", ".join(kinds),
                               line_of(data, hits[0][1].start())))
    return out


def _secrets(path, data):
    out, seen = [], set()
    for rx, what in SECRET_PATTERNS:
        for m in rx.finditer(data):
            val = m.group(0)
            if b"EXAMPLE" in val.upper() or re.search(rb"(.)\1{9,}", val) or what in seen:
                continue
            seen.add(what)
            out.append(Finding(INFO if what.startswith("Google") else MEDIUM, "committed-secret", path, "looks like a committed %s" % what,
                               line_of(data, m.start())))
            break
    return out


def _dockerfile(path, data):
    out = []
    m = RAW_IP_URL.search(data)
    if m:
        out.append(Finding(HIGH, "risky-dockerfile", path, "Dockerfile contacts a raw IP address: "
                           + excerpt(m.group(0)), line_of(data, m.start())))
    m = PIPE_SHELL.search(data)
    if m:
        out.append(Finding(INFO, "risky-dockerfile", path, "Dockerfile pipes a download into a shell",
                           line_of(data, m.start())))
    return out


def _editor_settings(path, data):
    out = []
    cfg = load_jsonc(data)
    if isinstance(cfg, dict) and isinstance(cfg.get("settings"), dict):
        cfg = cfg["settings"]  # .code-workspace
    if not isinstance(cfg, dict):
        return out
    if str(cfg.get("task.allowAutomaticTasks", "")).lower() == "on":
        out.append(Finding(HIGH, "editor-settings", path, "turns on automatic tasks (task.allowAutomaticTasks: on)"))
    if cfg.get("security.workspace.trust.enabled") is False:
        out.append(Finding(HIGH, "editor-settings", path, "turns off Workspace Trust"))
    for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
        if cfg.get(key) is True:
            out.append(Finding(HIGH, "editor-settings", path, "lets the AI agent run tools without asking (%s)" % key))
    for key, val in cfg.items():
        if isinstance(val, str) and re.search(r"(?:[Pp]ath|[Ee]xecutable|interpreterPath)$", key) and \
                re.match(r"(?:\./|\$\{workspaceFolder\})", val) and not re.search(r"venv|node_modules", val):
            out.append(Finding(MEDIUM, "editor-settings", path,
                               "%s points at a file inside the repo (%s)" % (key, excerpt(val, 50))))
    return out


def _devcontainer(path, data):
    out = []
    cfg = load_jsonc(data)
    if not isinstance(cfg, dict):
        return out
    for key in DEVCONTAINER_KEYS:
        if key not in cfg:
            continue
        cmd = " ".join(strings_in(cfg[key]))
        host = key == "initializeCommand"
        if risky_command(cmd) or RAW_IP_URL.search(cmd.encode()):
            sev = HIGH if host else MEDIUM
        else:
            sev = INFO
        where = "on your machine (host)" if host else "in the container"
        out.append(Finding(sev, "devcontainer-command", path, "%s runs %s: %s" % (key, where, excerpt(cmd, 70))))
    return out


def _jetbrains(path, data):
    out = []
    if re.search(rb"ProjectStartupConfigurations|ProjectStartupTaskManager|<startupTasks?\b", data):
        out.append(Finding(HIGH, "jetbrains-autorun", path, "JetBrains startup task runs a configuration when the "
                           "project opens"))
    if path.lower().endswith(".xml") and re.search(rb"ShConfigurationType|ShellScript|SCRIPT_TEXT", data):
        text = data.decode("utf-8", "replace")
        if risky_command(text):
            out.append(Finding(MEDIUM, "jetbrains-autorun", path, "run configuration downloads or runs inline code"))
    return out


def _agent_config(path, data):
    out = []
    cfg = load_jsonc(data)
    if not isinstance(cfg, dict):
        return out
    if CLAUDE_SETTINGS.search(path):
        hooks = cfg.get("hooks")
        if hooks:
            cmds = [s for s in strings_in(hooks) if s and not re.fullmatch(r"\w+|[\w|*]+", s)]
            risky = any(risky_command(c) or RAW_IP_URL.search(c.encode()) for c in cmds)
            out.append(Finding(HIGH if risky else MEDIUM, "ai-agent-config", path,
                               "Claude Code hooks run commands automatically: " + excerpt(" ; ".join(cmds), 70)))
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        for k in env:
            if k.upper().endswith("_BASE_URL") or k.upper() in ("HTTPS_PROXY", "HTTP_PROXY", "NODE_OPTIONS"):
                out.append(Finding(HIGH, "ai-agent-config", path, "sets %s for the agent (can redirect or "
                                   "inject into its traffic)" % k))
        for k in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport"):
            if cfg.get(k):
                out.append(Finding(MEDIUM, "ai-agent-config", path, "%s runs a command: %s" % (k, excerpt(str(cfg[k]), 60))))
        if cfg.get("enableAllProjectMcpServers") is True:
            out.append(Finding(MEDIUM, "ai-agent-config", path, "auto-approves every MCP server in the repo"))
    servers = cfg.get("mcpServers") or cfg.get("servers") or {}
    if isinstance(servers, dict):
        for sname, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            cmd = " ".join([str(spec.get("command", ""))] + [str(a) for a in spec.get("args", []) or []])
            url = str(spec.get("url", ""))
            if risky_command(cmd) or RAW_IP_URL.search((cmd + " " + url).encode()):
                out.append(Finding(HIGH, "ai-agent-config", path,
                                   "MCP server %r runs: %s" % (sname, excerpt(cmd + " " + url, 60))))
            elif re.search(r"(?:^|\s)(?:\./|\.\.?/)?[\w./-]+\.(?:woff2?|ttf|png|jpg|ico|svg|txt|dat)\b", cmd):
                out.append(Finding(HIGH, "ai-agent-config", path,
                                   "MCP server %r runs an asset file: %s" % (sname, excerpt(cmd, 60))))
            elif cmd.strip():
                out.append(Finding(INFO, "ai-agent-config", path,
                                   "MCP server %r runs: %s" % (sname, excerpt(cmd, 60))))
    return out


def check_package_json(path, data):
    out = []
    try:
        pkg = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return out
    scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
    if not isinstance(scripts, dict):
        return out
    for key, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue
        lifecycle = key in LIFECYCLE
        if NET_CMD.search(cmd) or (lifecycle and INLINE_CMD.search(cmd)):
            sev = HIGH if lifecycle else MEDIUM
            out.append(Finding(sev, "risky-script", path, 'script "%s" runs: %s' % (key, excerpt(cmd, 80))))
        elif lifecycle:
            out.append(Finding(INFO, "install-script", path, '"%s" runs on install: %s' % (key, excerpt(cmd, 80))))
        for m in RUNS_ODD_FILE.finditer(cmd):
            target = m.group(1)
            if target.startswith("-") or target.startswith(BUILD_OUTPUT):
                continue  # node flags (--import, --test) and compiled output (dist/main)
            base = target.rsplit("/", 1)[-1]
            asset = base.lower().endswith(tuple(MAGIC)) or target.startswith("public/")
            if "." not in base or asset:
                sev = HIGH if asset else MEDIUM
                out.append(Finding(sev, "runs-odd-file", path,
                                   'script "%s" runs "node %s" (no .js extension or an asset path): '
                                   "check that file before running" % (key, target)))
    return out
