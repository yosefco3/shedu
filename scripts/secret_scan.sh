#!/usr/bin/env bash
# secret_scan.sh — refuse to push commits that contain secrets.
#
# Installed as .git/hooks/pre-push by scripts/install_hooks.sh (in this repo and in
# private/). Standard tools only: git, grep, awk, sed. If gitleaks is installed it runs
# as an extra check; it is never required.
#
# Modes
#   as a pre-push hook   reads "<local-ref> <local-sha> <remote-ref> <remote-sha>" lines
#                        from stdin (what git gives pre-push). Scans every line ADDED by
#                        any commit between the remote sha and the local sha, so a secret
#                        that was committed and then removed is still caught. When the
#                        remote sha is unknown (new branch, new tag, or a sha we do not
#                        have) it falls back to scanning the whole tree at the local sha.
#   --range OLD NEW      same scan for the commits OLD..NEW (manual use)
#   --tree [REF]         scan every tracked file in the tree at REF (default HEAD)
#
# What is reported (pattern name → what it matches)
#   telegram-bot-token   6-12 digits, a colon, then exactly 35 token characters
#   anthropic-api-key    sk-ant- followed by 20+ key characters
#   openai-style-key     sk- (or sk-proj-) followed by 32+ letters/digits
#   aws-access-key-id    AKIA/ASIA/ABIA/ACCA followed by 16 upper-case letters/digits
#   private-key          a "-----BEGIN ... PRIVATE KEY-----" header
#   config-file          ANY non-blank, non-comment line in a file named guard.conf, .env
#                        or .env.<something> (.env.example/.sample/.template/.dist excepted)
#
# Opt-outs
#   per line   put the marker  secret-scan: allow  anywhere on the line (in a comment:
#              "# secret-scan: allow" or "// secret-scan: allow"). Use it only for values
#              that are not real.
#   fixtures   a line in a test fixture — any file under a testdata/ directory, or a
#              *_test.go / *_test.sh file — is skipped when the SAME line also contains one
#              of the words fake, dummy, example, placeholder, sample or redacted (case
#              does not matter). That is how you mark an obviously fake value; any other
#              match in a fixture is still reported. The config-file rule never applies
#              to fixtures (a guard.conf under testdata/ is, by definition, fake).
#   gitleaks   SECRET_SCAN_NO_GITLEAKS=1 skips the gitleaks pass. gitleaks has its own
#              inline marker, "gitleaks:allow".
#
# Output: one line per finding with file, line, pattern name and a REDACTED form (first
# four characters, never the value). Exit 1 if anything was found, 0 otherwise.
set -euo pipefail

ZERO=0000000000000000000000000000000000000000
ALLOW_MARKER='secret-scan: allow'
FAKE_WORDS='fake|dummy|example|placeholder|sample|redacted'

# name|POSIX-ERE (checked in this order; a line is reported once, for the first match)
PATTERNS=(
  'telegram-bot-token|[0-9]{6,12}:[A-Za-z0-9_-]{35}'
  'anthropic-api-key|sk-ant-[A-Za-z0-9_-]{20,}'
  'openai-style-key|sk-(proj-)?[A-Za-z0-9]{32,}'
  'aws-access-key-id|(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}'
  'private-key|-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
)
COMBINED=""
for entry in "${PATTERNS[@]}"; do
  COMBINED="${COMBINED:+$COMBINED|}(${entry#*|})"
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/secret-scan.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
RECORDS="$TMP/records"   # commit \t path \t lineno \t kind \t content
: >"$RECORDS"
COMMITS_SCANNED=0
TREES_SCANNED=0

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  exit 2
}

# tag_records: stdin = "commit \t path \t lineno \t content"; adds the kind column.
#   kind = fix (test fixture) | cfg (guard.conf / .env family) | src (anything else)
tag_records() {
  awk -F'\t' -v OFS='\t' '
    {
      commit=$1; path=$2; ln=$3
      content=substr($0, length(commit)+length(path)+length(ln)+4)
      kind="src"
      if (path ~ /(^|\/)(guard\.conf|\.env|\.env\.[^\/]*)$/ && path !~ /\.env\.(example|sample|template|dist)$/) kind="cfg"
      if (path ~ /(^|\/)testdata\// || path ~ /_test\.(go|sh)$/) kind="fix"
      print commit, path, ln, kind, content
    }' >>"$RECORDS"
}

# collect_range OLD NEW: every line added by any commit in OLD..NEW
collect_range() {
  local old=$1 new=$2
  COMMITS_SCANNED=$((COMMITS_SCANNED + $(git rev-list --count "$old..$new" </dev/null)))
  git log -p --unified=0 --no-color --no-renames --no-ext-diff --no-textconv \
      --diff-filter=ACMR --format='commit %H' "$old..$new" </dev/null \
  | awk -v OFS='\t' '
      /^commit [0-9a-f]+$/ && length($0)==47 { commit=substr($0,8); path=""; inhdr=0; next }
      /^diff --git /  { inhdr=1; path=""; next }
      inhdr && /^\+\+\+ / {
        p=substr($0,5)
        if (p=="/dev/null") path=""; else if (substr(p,1,2)=="b/") path=substr(p,3); else path=p
        next
      }
      /^@@ / { inhdr=0; s=$0; sub(/^@@ -[0-9]+(,[0-9]+)? \+/, "", s); sub(/[ ,].*$/, "", s); ln=s+0; next }
      inhdr || path=="" { next }
      /^\+/  { print commit, path, ln, substr($0,2); ln++; next }
      /^ /   { ln++; next }
    ' \
  | tag_records
}

# collect_tree REF: candidate lines in every tracked text file of the tree at REF
collect_tree() {
  local ref=$1 sha path
  sha=$(git rev-parse --verify "$ref^{commit}")
  TREES_SCANNED=$((TREES_SCANNED + 1))
  # lines matching any pattern (git grep -z prints "sha:path NUL lineno NUL content")
  { git grep -nzIE -e "$COMBINED" "$sha" -- </dev/null || true; } \
  | tr '\0' '\t' \
  | awk -F'\t' -v OFS='\t' '{ p=$1; sub(/^[^:]*:/, "", p); print substr($1,1,40), p, $2, substr($0, length($1)+length($2)+3) }' \
  | tag_records
  # config files: every line (the cfg rule), content read straight from the tree
  { git ls-tree -r --name-only "$sha" </dev/null \
    | grep -E '(^|/)(guard\.conf|\.env|\.env\.[^/]*)$' || true; } \
  | while IFS= read -r path; do
      git show "$sha:$path" </dev/null | awk -v OFS='\t' -v c="$sha" -v p="$path" '{ print c, p, NR, $0 }'
    done | tag_records
}

# hook_mode: stdin lines from git pre-push
hook_mode() {
  local lref lsha rref rsha line lines=()
  mapfile -t lines                                         # read all of stdin first
  for line in "${lines[@]+"${lines[@]}"}"; do
    read -r lref lsha rref rsha <<<"$line" || true
    [ -n "${lsha:-}" ] || continue
    [ "$lsha" = "$ZERO" ] && continue                      # deleting a remote ref
    if [ "${rsha:-$ZERO}" != "$ZERO" ] && git cat-file -e "$rsha^{commit}" 2>/dev/null; then
      collect_range "$rsha" "$lsha"
    else
      echo "secret-scan: remote ref unknown for $lref, scanning the whole tree" >&2
      collect_tree "$lsha"
    fi
  done
}

redact() { # the matched value -> first 4 chars + stars + length
  local v=$1
  printf '%s**** (%d chars)' "${v:0:4}" "${#v}"
}

FOUND=0
report() { # commit path lineno name redacted
  if [ "$FOUND" -eq 0 ]; then
    echo "secret-scan: BLOCKED, possible secret(s) in what is about to be pushed:" >&2
  fi
  FOUND=$((FOUND + 1))
  printf '  %s:%s  %s  %s  [%s]\n' "$2" "$3" "$4" "$5" "${1:0:7}" >&2
}

classify() {
  local commit path lineno kind content entry name re m key
  # pre-filter: cfg lines are always candidates, others only if some pattern matches
  { grep -E -e "$COMBINED" "$RECORDS" || true; awk -F'\t' '$4=="cfg"' "$RECORDS"; } | sort -u \
  | while IFS=$'\t' read -r commit path lineno kind content; do
      case "$content" in *"$ALLOW_MARKER"*) continue;; esac
      if [ "$kind" = fix ] && printf '%s\n' "$content" | grep -qiE -e "$FAKE_WORDS"; then continue; fi
      for entry in "${PATTERNS[@]}"; do
        name=${entry%%|*}; re=${entry#*|}
        m=$(printf '%s\n' "$content" | grep -oE -e "$re" | head -n1 || true)
        if [ -n "$m" ]; then
          report "$commit" "$path" "$lineno" "$name" "$(redact "$m")"
          continue 2
        fi
      done
      if [ "$kind" = cfg ]; then
        key=$(printf '%s' "$content" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?//; s/[[:space:]]*=.*$//')
        case "$key" in ''|'#'*) continue;; esac
        case "$content" in *=*) key="$key=****";; *) key="(whole line hidden)";; esac
        report "$commit" "$path" "$lineno" "config-file" "$key"
      fi
    done
}

run_gitleaks() { # [range-opts]
  [ "${SECRET_SCAN_NO_GITLEAKS:-0}" = 1 ] && return 0
  command -v gitleaks >/dev/null 2>&1 || return 0
  local rc=0
  if [ $# -gt 0 ]; then
    if gitleaks git --help >/dev/null 2>&1; then
      gitleaks git --redact --no-banner --exit-code 1 --log-opts="$1" . >&2 || rc=$?
    else
      gitleaks detect --redact --no-banner --exit-code 1 --source . --log-opts="$1" >&2 || rc=$?
    fi
  else
    if gitleaks dir --help >/dev/null 2>&1; then
      gitleaks dir --redact --no-banner --exit-code 1 . >&2 || rc=$?
    else
      gitleaks detect --redact --no-banner --exit-code 1 --no-git --source . >&2 || rc=$?
    fi
  fi
  case $rc in
    0) ;;
    1) echo "secret-scan: BLOCKED by gitleaks (see its report above)" >&2; return 1;;
    *) echo "secret-scan: warning: gitleaks exited with $rc, continuing without it" >&2;;
  esac
  return 0
}

main() {
  git rev-parse --git-dir >/dev/null 2>&1 || { echo "secret-scan: not inside a git repository" >&2; exit 2; }
  local gitleaks_args=()
  case "${1:-}" in
    -h|--help) usage;;
    --range)
      [ $# -eq 3 ] || usage
      collect_range "$2" "$3"; gitleaks_args=("$2..$3");;
    --tree)
      [ $# -le 2 ] || usage
      collect_tree "${2:-HEAD}";;
    -*) usage;;
    *)  # no flags, or the "<remote name> <remote url>" git passes to a pre-push hook
      if [ -t 0 ]; then
        if git rev-parse --verify -q '@{upstream}' >/dev/null; then
          echo "secret-scan: scanning @{upstream}..HEAD (use --tree or --range for something else)" >&2
          collect_range '@{upstream}' HEAD; gitleaks_args=('@{upstream}..HEAD')
        else
          echo "secret-scan: no upstream, scanning the whole tree at HEAD" >&2
          collect_tree HEAD
        fi
      else
        hook_mode
      fi;;
  esac

  # classify runs in a subshell (pipeline), so count findings from its output instead
  local out
  out=$(classify 2>&1 >/dev/null) || true
  if [ -n "$out" ]; then
    printf '%s\n' "$out" >&2
    cat >&2 <<EOF

  Nothing above shows the value itself (first 4 characters only).
  If a line is a real secret: remove it, rotate the secret, and rewrite the history
  before pushing. If it is a fake value: append "# secret-scan: allow" to that line
  (or use a fake/dummy/example word on a line in a testdata/ fixture).
  Details: scripts/secret_scan.sh --help
EOF
    exit 1
  fi
  run_gitleaks "${gitleaks_args[@]+"${gitleaks_args[@]}"}" || exit 1
  if [ "$COMMITS_SCANNED" -gt 0 ] || [ "$TREES_SCANNED" -gt 0 ]; then
    echo "secret-scan: ok ($COMMITS_SCANNED commit(s), $TREES_SCANNED whole tree(s) scanned)" >&2
  fi
  exit 0
}

main "$@"
