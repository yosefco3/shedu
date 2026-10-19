#!/usr/bin/env bash
# install_hooks.sh — install the pre-push secret scan (scripts/secret_scan.sh) as
# .git/hooks/pre-push in this repository and in private/ (its own repository).
# Hooks are not versioned, so run this once per clone:  scripts/install_hooks.sh
# The private hook reaches the scanner by relative path (../scripts/secret_scan.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

install_hook() { # <repo dir> <scanner path relative to that repo's root>
  local repo=$1 rel=$2 hooks hook
  hooks=$(git -C "$repo" rev-parse --git-path hooks)
  case "$hooks" in /*) ;; *) hooks="$repo/$hooks";; esac
  hook="$hooks/pre-push"
  if [ -e "$hook" ] && ! grep -q 'secret_scan.sh' "$hook"; then
    echo "✖ $hook exists and is not ours; move it away and run again" >&2
    return 1
  fi
  mkdir -p "$hooks"
  cat >"$hook" <<EOF
#!/bin/sh
# pre-push: secret scan. Written by scripts/install_hooks.sh (shedu); re-run it to update.
scan="\$(git rev-parse --show-toplevel)/$rel"
if [ ! -x "\$scan" ]; then
  echo "pre-push: secret scanner not found at \$scan; run scripts/install_hooks.sh in the shedu repo" >&2
  exit 1
fi
exec "\$scan" "\$@"
EOF
  chmod +x "$hook"
  if p=$(git -C "$repo" config --get core.hooksPath); then
    echo "! $repo has core.hooksPath=$p, so git will ignore $hook" >&2
  fi
  echo "✔ $hook -> $rel"
}

chmod +x scripts/secret_scan.sh
install_hook . scripts/secret_scan.sh
if [ -d private ] && git -C private rev-parse --git-dir >/dev/null 2>&1; then
  install_hook private ../scripts/secret_scan.sh
else
  echo "- private/ is not a git repository here, skipped"
fi
