#!/usr/bin/env bash
# secret_scan_test.sh — end-to-end test of scripts/secret_scan.sh and
# scripts/install_hooks.sh in throwaway git repositories (no root, no network).
#   run:  scripts/secret_scan_test.sh        expected last line: "... 0 failed"
# Token-shaped values are built at run time, so this file never contains one itself.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/secret-scan-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
export SECRET_SCAN_NO_GITLEAKS=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

TG_TOKEN="123456789:AAFAKE$(printf 'x%.0s' {1..29})"      # 35 chars after the colon
TG_SECRET_PART=${TG_TOKEN#*:}
ANTHROPIC_KEY="sk-ant-api03-$(printf 'y%.0s' {1..40})"
OPENAI_KEY="sk-$(printf 'Z%.0s' {1..48})"
AWS_KEY="AKIA$(printf 'Q%.0s' {1..16})"
PEM_HEADER=$(printf -- '-----BEGIN RSA %s KEY-----' PRIVATE)

pass=0; fail=0; OUT=""
ok()  { echo "ok   - $1"; pass=$((pass + 1)); }
bad() { echo "FAIL - $1"; fail=$((fail + 1)); printf '%s\n' "$OUT" | sed 's/^/       | /'; }
# check <description> <expected exit code> <command...>   (output lands in $OUT)
check() {
  local desc=$1 want=$2 rc=0; shift 2
  OUT=$("$@" 2>&1) || rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$desc"; else bad "$desc (exit $rc, wanted $want)"; fi
}
has()    { case "$OUT" in *"$1"*) ok "output mentions: $1";; *) bad "output lacks: $1";; esac; }
hasnot() { case "$OUT" in *"$1"*) bad "output LEAKS: $1";; *) ok "output hides the value";; esac; }

# ---- layout: repo (public) with private/ inside, each with its own bare remote ----
REPO=$TMP/repo
git init -q -b main "$REPO"
git init -q -b master "$REPO/private"
git init -q --bare "$TMP/remote.git"
git init -q --bare "$TMP/private-remote.git"
g() { git -C "$REPO" "$@"; }
p() { git -C "$REPO/private" "$@"; }
in_repo() { (cd "$REPO" && "$@"); }
g remote add origin "$TMP/remote.git"
p remote add origin "$TMP/private-remote.git"
mkdir -p "$REPO/scripts"
cp "$HERE/secret_scan.sh" "$HERE/install_hooks.sh" "$REPO/scripts/"
echo "private/" >"$REPO/.gitignore"
g add -A && g commit -qm "init"
echo "# internal notes" >"$REPO/private/README.md"
p add -A && p commit -qm "init"

echo "# install_hooks.sh"
check "installs both hooks" 0 "$REPO/scripts/install_hooks.sh"
[ -x "$REPO/.git/hooks/pre-push" ] && ok "public hook is executable" || bad "public hook missing"
[ -x "$REPO/private/.git/hooks/pre-push" ] && ok "private hook is executable" || bad "private hook missing"
grep -q '/\.\./scripts/secret_scan.sh' "$REPO/private/.git/hooks/pre-push" \
  && ok "private hook uses the relative path ../scripts/secret_scan.sh" || bad "private hook path"

echo "# first push: remote ref unknown -> whole tree"
check "first push passes (the scanner's own source does not trip it)" 0 g push -q origin main
has "scanning the whole tree"
check "first push of private/ passes through the relative-path hook" 0 p push -q origin master

echo "# planted Telegram token"
printf 'bot token: %s\n' "$TG_TOKEN" >"$REPO/notes.md"
g add notes.md && g commit -qm "notes"
check "push --dry-run is blocked" 1 g push --dry-run origin main
has "BLOCKED"
has "notes.md:1  telegram-bot-token  1234**** (45 chars)"
hasnot "$TG_SECRET_PART"
check "--range reports the same" 1 in_repo scripts/secret_scan.sh --range origin/main main
check "--tree reports the same" 1 in_repo scripts/secret_scan.sh --tree
check "push to a NEW remote branch falls back to the whole tree, still blocked" 1 \
  g push --dry-run origin main:refs/heads/feature
has "scanning the whole tree"

echo "# allow marker"
printf 'bot token: %s  # secret-scan: allow\n' "$TG_TOKEN" >"$REPO/notes.md"
g commit -q --amend -am "notes (allowed)"
check "push --dry-run passes with the marker" 0 g push --dry-run origin main
has "secret-scan: ok (1 commit(s)"
check "--tree passes with the marker" 0 in_repo scripts/secret_scan.sh --tree
g push -q origin main 2>/dev/null

echo "# secret added then removed in the same push (still in history)"
printf 'leak %s\n' "$TG_TOKEN" >"$REPO/leak.txt"
g add leak.txt && g commit -qm "leak"
g rm -q leak.txt && g commit -qm "remove leak"
check "push --dry-run is blocked although the final tree is clean" 1 g push --dry-run origin main
has "leak.txt:1  telegram-bot-token"
g reset -q --hard origin/main

echo "# every pattern is named"
{ echo "a=$ANTHROPIC_KEY"; echo "o=$OPENAI_KEY"; echo "w=$AWS_KEY"; echo "$PEM_HEADER"; } >"$REPO/keys.txt"
g add keys.txt && g commit -qm "keys"
check "push --dry-run is blocked" 1 g push --dry-run origin main
has "keys.txt:1  anthropic-api-key  sk-a****"
has "keys.txt:2  openai-style-key  sk-Z****"
has "keys.txt:3  aws-access-key-id  AKIA****"
has "keys.txt:4  private-key  ----****"
hasnot "${ANTHROPIC_KEY#sk-ant-api03-}"
g reset -q --hard origin/main

echo "# minisign keys (secret parts built at run time)"
MS_HEAD="untrusted comment: minisign"
MS_ENC_BODY="RWRTY0Iy$(printf 'Q%.0s' {1..200})"      # encrypted key: 8 + 200 base64 characters
MS_PLAIN_BODY="RWQAAEIy$(printf 'Q%.0s' {1..100})"    # unencrypted key (minisign -G -W): 8 + 100
MS_PUB_KEY="RWTvgwLfc3RDnS1jVBV3b3vEPLs1HzysJTfbFsfUqEmGxk7T8KOjJ1uv"
MS_SIG="RURETUJBuxFYGWoGqmRxqDjJaxW4/7mYjjkl4cWVLhab1+JiO4wqh+am3Pi3gnLrf0otf2kFx02VrbJuSqf9h1rmPlsJcRacdQw="
mkdir -p "$REPO/keys"
printf '%s encrypted secret key\n%s\n' "$MS_HEAD" "$MS_ENC_BODY" >"$REPO/keys/minisign.key"
g add -A && g commit -qm "encrypted minisign key"
check "an encrypted minisign secret key is blocked" 1 g push --dry-run origin main
has "keys/minisign.key:1  minisign-secret-key  untr****"
has "keys/minisign.key:2  minisign-secret-key  RWRT****"
g reset -q --hard origin/main
mkdir -p "$REPO/keys"
printf '%s\n' "$MS_PLAIN_BODY" >"$REPO/keys/plain.key"
g add -A && g commit -qm "unencrypted minisign key"
check "an unencrypted minisign secret key body is blocked" 1 g push --dry-run origin main
has "keys/plain.key:1  minisign-secret-key  RWQA****"
g reset -q --hard origin/main
mkdir -p "$REPO/keys"
printf 'untrusted comment: minisign public key 9D437473DF0283EF\n%s\n%s\n' "$MS_PUB_KEY" "$MS_SIG" >"$REPO/keys/release.minisig"
g add -A && g commit -qm "minisign public key and signature"
check "a minisign public key, its comment and a signature pass" 0 g push --dry-run origin main
has "secret-scan: ok (1 commit(s)"
g reset -q --hard origin/main

echo "# fixtures under testdata/"
mkdir -p "$REPO/internal/x/testdata"
printf '%s fake key for tests\n' "$PEM_HEADER" >"$REPO/internal/x/testdata/key.pem"
printf 'TELEGRAM_TOKEN="123456:ABC-DEF"\n' >"$REPO/internal/x/testdata/guard.conf"
g add -A && g commit -qm "fixtures"
check "a fixture line that says fake, and a testdata guard.conf, pass" 0 g push --dry-run origin main
g push -q origin main 2>/dev/null
printf 'aws_access_key_id = %s\n' "$AWS_KEY" >"$REPO/internal/x/testdata/creds.txt"
g add -A && g commit -qm "fixture without a fake word"
check "a fixture line without a fake word is still blocked" 1 g push --dry-run origin main
has "testdata/creds.txt:1  aws-access-key-id"
g reset -q --hard origin/main

echo "# config files: guard.conf and .env"
printf 'API_KEY=put-yours-here\n' >"$REPO/.env.example"
g add -A && g commit -qm "env example"
check ".env.example passes" 0 g push --dry-run origin main
mkdir -p "$REPO/docs"
printf '# written by install.sh\n\nTELEGRAM_TOKEN="short-value"\nLANG=en\n' >"$REPO/docs/guard.conf"
printf 'DB_PASSWORD=hunter2\n' >"$REPO/.env"
g add -A && g commit -qm "config"
check "guard.conf and .env are blocked line by line" 1 g push --dry-run origin main
has "docs/guard.conf:3  config-file  TELEGRAM_TOKEN=****"
has "docs/guard.conf:4  config-file  LANG=****"
has ".env:1  config-file  DB_PASSWORD=****"
hasnot "short-value"
hasnot "hunter2"
g reset -q --hard origin/main

echo "# private repo through the relative-path hook"
printf 'key: %s\n' "$ANTHROPIC_KEY" >"$REPO/private/HANDOFF.md"
p add -A && p commit -qm "handoff"
check "push --dry-run of private/ is blocked" 1 p push --dry-run origin master
has "HANDOFF.md:1  anthropic-api-key  sk-a****"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
