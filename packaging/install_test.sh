#!/usr/bin/env bash
# Tests for install.sh's release download and signature checks, without root and without
# the network: the functions are sourced (SHEDU_INSTALL_LIB=1) and "GitHub" is a file://
# tree built from internal/update/testdata/release (signed by a test key, comment
# "shedu v0.3.1 SHA256SUMS"). Cases that need minisign are skipped when it is missing;
# CI installs it.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
FIX=internal/update/testdata/release
TESTKEY=$(sed -n 2p "$FIX/test.pub")
PASS=0; FAIL=0; SKIP=0
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# release TAG SIG: a release folder for TAG with the fixture binary, SHA256SUMS and the
# named signature file (or none when SIG is "-").
release() {
  local d="$TMP/${ROOT:-gh}/download/$1"; mkdir -p "$d"
  cp "$FIX/shedu_linux_amd64" "$FIX/shedu_linux_arm64" "$FIX/SHA256SUMS" "$d/"
  [ "$2" = - ] || cp "$FIX/$2" "$d/SHA256SUMS.minisig"
}
release v0.3.0 -
release v0.3.1 SHA256SUMS.minisig
release v0.3.2 SHA256SUMS.minisig          # v0.3.1's signature passed off as v0.3.2
release v0.4.0 -                           # signed era, signature stripped
release v0.3.1-rc1 SHA256SUMS.rc1.minisig
release v0.3.1-rc2 -                       # rc of the first signed release, unsigned
release v0.0.1 -                           # a fake "old" release
release v0.3.0-rc9 -
ROOT=suffix release v0.3.1 SHA256SUMS.suffix.minisig
release v0.5.0 SHA256SUMS.otherkey.minisig
# a second "GitHub" whose v0.3.1 binary was changed after signing
ROOT=tampered release v0.3.1 SHA256SUMS.minisig && echo x >>"$TMP/tampered/download/v0.3.1/shedu_linux_amd64"

# run_install TAG [MINISIGN_BIN]: install TAG into a temp BIN; prints output, returns status.
run_install() {
  local bin="$TMP/bin-$RANDOM"
  SHEDU_INSTALL_LIB=1 bash -c '
    set -euo pipefail
    a=("$@"); set --   # install.sh parses "$@" as its own options
    source packaging/install.sh
    RELEASES="file://${a[0]}" MINISIGN_PUBKEY="${a[1]}" VERSION="${a[2]}" BIN="${a[3]}" MINISIGN_BIN="${a[4]}"
    install_binary && test -x "$BIN" && echo INSTALLED
  ' _ "$TMP/${ROOT:-gh}" "$TESTKEY" "$1" "$bin" "${2:-minisign}" 2>&1
}

check() { # name expected-substring tag [minisign-bin]
  local name=$1 want=$2 out
  if [ "${4:-minisign}" = minisign ] && ! command -v minisign >/dev/null; then
    SKIP=$((SKIP+1)); echo "skip  $name (minisign not installed)"; return
  fi
  out=$(run_install "$3" "${4:-minisign}")
  if [[ $out == *"$want"* ]]; then PASS=$((PASS+1)); echo "ok    $name"
  else FAIL=$((FAIL+1)); echo "FAIL  $name: want '$want', got:"; echo "$out" | sed 's/^/        /'; fi
}

check "signed release installs"                    "Release signature verified"   v0.3.1
check "  ...and is installed"                      INSTALLED                      v0.3.1
check "v0.3.0 predates signing: sha256 + warning"  "predates signed releases"     v0.3.0
check "  ...and is installed"                      INSTALLED                      v0.3.0
check "missing signature from v0.3.1 on: refused"  "has no signature"             v0.4.0
check "signed rc installs"                         INSTALLED                      v0.3.1-rc1
check "unsigned rc of the first signed release"    "has no signature"             v0.3.1-rc2
check "fake old release v0.0.1: refused"           "is not a shedu release"       v0.0.1
check "fake old release v0.3.0-rc9: refused"       "is not a shedu release"       v0.3.0-rc9
check "  ...even without minisign"                 "is not a shedu release"       v0.0.1 /nonexistent/minisign
check "leading zeros: refused"                     "not a release tag"            v0.3.08 /nonexistent/minisign
ROOT=suffix check "comment with extra text"        "is not for v0.3.1"            v0.3.1
check "signature by another key: refused"          "signature check failed"       v0.5.0
check "old signature under a new tag: refused"     "is not for v0.3.2"            v0.3.2
ROOT=tampered check "tampered binary: refused"     "checksum mismatch"            v0.3.1
check "no minisign: sha256 + warning"              "minisign is not installed"    v0.4.0 /nonexistent/minisign
check "  ...and is installed"                      INSTALLED                      v0.4.0 /nonexistent/minisign
check "bad tag: refused"                           "not a release tag"            "v0.3.1;rm"  /nonexistent/minisign
check "unknown tag: refused"                       "download failed"              v9.9.9 /nonexistent/minisign

# version_at_least, the floor's comparison
cmp_case() { # A B want(0|1)
  local got; SHEDU_INSTALL_LIB=1 bash -c 'a=("$@"); set --; source packaging/install.sh; version_at_least "${a[0]}" "${a[1]}"' _ "$1" "$2"; got=$?
  if [ "$got" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL  version_at_least $1 $2 = $got, want $3"; fi
}
cmp_case v0.3.1 v0.3.1 0; cmp_case v0.3.0 v0.3.1 1; cmp_case v0.3.1-rc1 v0.3.1 0; cmp_case v0.10.0 v0.3.1 0
cmp_case v1.0.0 v0.3.1 0; cmp_case v0.2.9 v0.3.1 1; cmp_case v0.3.2 v0.3.1 0; cmp_case v0.4.0 v0.3.10 0
cmp_case v0.3.0-rc1 v0.3.1 1; cmp_case v0.3.10 v0.3.9 0; cmp_case v0.3.9 v0.3.10 1

# --no-auto-update sets AUTO_UPDATE=no; without it the default is yes
auto_case() { # want(yes|no) [install.sh args]
  local want=$1 got; shift
  got=$(SHEDU_INSTALL_LIB=1 bash -c 'source packaging/install.sh "$@"; echo "$AUTO_UPDATE"' _ "$@")
  if [ "$got" = "$want" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL  AUTO_UPDATE with [$*] = '$got', want '$want'"; fi
}
auto_case no --no-auto-update; auto_case yes

# knows_auto_update: only binaries from v0.3.1 on (or dev builds) get the AUTO_UPDATE key,
# because older ones refuse a config key they don't know.
knows_case() { # version-printed want(0|1)
  local bin="$TMP/fakebin-$RANDOM" got
  printf '#!/bin/sh\necho %s\n' "$1" >"$bin"; chmod +x "$bin"
  SHEDU_INSTALL_LIB=1 bash -c 'a=("$@"); set --; source packaging/install.sh; BIN=${a[0]}; knows_auto_update' _ "$bin"; got=$?
  if [ "$got" = "$2" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL  knows_auto_update for $1 = $got, want $2"; fi
}
knows_case v0.3.0 1; knows_case v0.3.0-5-gabc1234 1; knows_case v0.3.1 0; knows_case v0.3.1-rc1 0; knows_case v1.0.0 0; knows_case dev 0

# auto_update_note on an existing config: --no-auto-update is applied, else a one-time notice.
note_case() { # name binary-version flag existing-conf-line want-in-conf want-in-output
  local bin="$TMP/fakebin-$RANDOM" conf="$TMP/conf-$RANDOM" out
  printf '#!/bin/sh\necho %s\n' "$2" >"$bin"; chmod +x "$bin"
  printf 'LANG=he\n%s\n' "$4" >"$conf"
  out=$(SHEDU_INSTALL_LIB=1 bash -c 'a=("$@"); set --; source packaging/install.sh; BIN=${a[0]} CONF=${a[1]} AUTO_UPDATE=${a[2]}; auto_update_note' _ "$bin" "$conf" "$3" 2>&1)
  if grep -qxF -- "$5" "$conf" && [[ $out == *"$6"* ]]; then PASS=$((PASS+1)); echo "ok    $1"
  else FAIL=$((FAIL+1)); echo "FAIL  $1: conf:"; sed 's/^/        /' "$conf"; echo "      output: $out"; fi
}
note_case "existing conf, --no-auto-update: replaced"  v0.3.1 no  "AUTO_UPDATE=yes" "AUTO_UPDATE=no" "Auto-update is off"
note_case "existing conf, --no-auto-update: appended"  v0.3.1 no  "DAILY_REPORT_AT=08:00" "AUTO_UPDATE=no" "Auto-update is off"
note_case "existing conf, upgrade: notice once"        v0.3.1 yes "DAILY_REPORT_AT=08:00" "DAILY_REPORT_AT=08:00" "updates itself at night"
note_case "existing conf, key set: no notice"          v0.3.1 yes "AUTO_UPDATE=yes" "AUTO_UPDATE=yes" ""
note_case "old binary: key never written"              v0.3.0 no  "DAILY_REPORT_AT=08:00" "DAILY_REPORT_AT=08:00" "has no auto-update"

echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
