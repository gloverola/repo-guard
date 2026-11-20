#!/bin/sh
# repo-guard installer for macOS and Linux.
#
#   ./install.sh              install (or update) repo-guard and the git hooks
#   ./install.sh --no-hook    install the command only
#   ./install.sh --uninstall  remove the command and the hooks
#
# Installs one file, ~/.local/bin/repo-guard (override with REPO_GUARD_BIN), runs
# `repo-guard setup` (git template hooks: every new clone from any app is scanned),
# and adds a marked `git clone`/`git pull` wrapper to ~/.zshrc and/or ~/.bashrc.
# Re-running it is safe. Prefer pipx or Homebrew? See README.md.

set -eu

ACTION=install
HOOK=1
for arg in "$@"; do
  case "$arg" in
    --uninstall) ACTION=uninstall ;;
    --no-hook) HOOK=0 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option $arg" >&2; exit 2 ;;
  esac
done

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR=${REPO_GUARD_BIN:-$HOME/.local/bin}
TARGET=$BIN_DIR/repo-guard
BEGIN='# >>> repo-guard >>>'
END='# <<< repo-guard <<<'

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# Shell startup files to manage: the ones that exist, plus the one for $SHELL.
rc_files() {
  for f in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
  case "${SHELL:-}" in
    */zsh) [ -f "$HOME/.zshrc" ] || printf '%s\n' "$HOME/.zshrc" ;;
    */bash) [ -f "$HOME/.bashrc" ] || printf '%s\n' "$HOME/.bashrc" ;;
  esac
}

remove_block() {
  [ -f "$1" ] || return 0
  grep -qF "$BEGIN" "$1" || return 0
  tmp=$(mktemp)
  awk -v b="$BEGIN" -v e="$END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' "$1" > "$tmp"
  cat "$tmp" > "$1"   # keep the file's owner and permissions
  rm -f "$tmp"
}

if [ "$ACTION" = uninstall ]; then
  [ -x "$TARGET" ] && "$TARGET" setup --uninstall || true
  rm -f "$TARGET"
  for rc in $(rc_files); do remove_block "$rc"; done
  say "repo-guard removed. Open a new terminal for the change to take effect."
  exit 0
fi

command -v git >/dev/null 2>&1 || fail "git is not installed."
[ -f "$SRC_DIR/src/repo_guard/cli.py" ] || fail "run this from the repo-guard folder (src/repo_guard not found)."

# Find Python 3.8+. On macOS, /usr/bin/python3 is a stub until the Command Line Tools exist.
PY=
for cand in python3 python; do
  p=$(command -v "$cand" 2>/dev/null) || continue
  if [ "$p" = /usr/bin/python3 ] && [ "$(uname)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then
    continue
  fi
  if "$p" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
    PY=$p   # the stable command path, so a Python upgrade doesn't break the shebang
    break
  fi
done
if [ -z "$PY" ]; then
  if [ "$(uname)" = Darwin ]; then
    fail "Python 3.8+ not found. Run 'xcode-select --install', then run this installer again."
  fi
  fail "Python 3.8+ not found. Install python3 with your package manager, then run this installer again."
fi

mkdir -p "$BIN_DIR"
tmp="$TARGET.tmp.$$"
"$PY" -I "$SRC_DIR/scripts/build_pyz.py" "$tmp" "$PY -I" || fail "could not build repo-guard."
chmod 755 "$tmp"
mv -f "$tmp" "$TARGET"   # replaces an older copy or symlink
say "Installed $TARGET (Python: $PY)"

if [ "$HOOK" = 1 ]; then
  for rc in $(rc_files); do
    remove_block "$rc"
    if grep -q 'repo-guard clone' "$rc" 2>/dev/null; then
      say "Note: $rc already has an older, unmarked repo-guard hook. Delete it so only one runs."
    fi
    cat >> "$rc" <<EOF
$BEGIN
# Scans repos for hidden malware: \`git clone\` checks files out only if every
# branch is clean, and \`git pull\` rescans. Bypass once: REPO_GUARD_OFF=1 git clone ...
case ":\$PATH:" in *":$BIN_DIR:"*) ;; *) export PATH="$BIN_DIR:\$PATH" ;; esac
function git {
  if [ -z "\${REPO_GUARD_OFF:-}" ] && [ "\${1:-}" = clone ]; then
    shift
    repo-guard clone "\$@"
  elif [ -z "\${REPO_GUARD_OFF:-}" ] && [ "\${1:-}" = pull ]; then
    command git "\$@" || return \$?
    repo-guard scan --worktree-only --quiet "\$(command git rev-parse --show-toplevel)"
  else
    command git "\$@"
  fi
}
$END
EOF
    say "Added the git hook to $rc"
  done
  "$TARGET" setup || fail "repo-guard setup failed."
fi

say ""
"$TARGET" selftest || fail "selftest failed. Please report the output above: https://github.com/gloverola/repo-guard/issues"
say ""
say "Done. Open a new terminal (or run: exec \$SHELL), then try: repo-guard --help"
