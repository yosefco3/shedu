#!/usr/bin/env bash
# Shedu installer — one command, zero configuration.
#   curl -fsSL https://raw.githubusercontent.com/yosefco3/shedu/main/packaging/install.sh | sudo bash
# Options (all optional):
#   --cloud TOKEN      connect to the Shedu cloud with a one-time token from the dashboard;
#                      alerts then come from the cloud, so Telegram is not asked for
#   --url URL          cloud API URL for --cloud (default https://api.getshedu.com)
#   --token TOKEN      Telegram bot token (else asked, unless --cloud)
#   --chat-id ID       Telegram chat id (else asked / auto-detected)
#   --lang he|en       language of the Telegram messages (default he); terminal output is always English
#   --binary PATH      install this binary instead of downloading a release (dev)
#   --version TAG      install this release (vX.Y.Z or vX.Y.Z-rcN) instead of the latest
#   --upgrade          replace the binary and restart, keep config
#   --no-auto-update   do not install new signed releases automatically at night (AUTO_UPDATE=no)
#   --yes              never ask; skip Telegram if not given
#   --help             show this help
set -euo pipefail

usage() {
  cat <<'USAGE'
Shedu installer: one command, zero configuration.

  curl -fsSL https://raw.githubusercontent.com/yosefco3/shedu/main/packaging/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/yosefco3/shedu/main/packaging/install.sh | sudo bash -s -- --cloud <token>

Options (all optional):
  --cloud TOKEN    connect this server to Shedu Cloud with a one-time token from the
                   dashboard (Add a server). Alerts then come from the cloud, so Telegram
                   is not asked for. Without --cloud nothing is ever sent to the cloud.
  --url URL        cloud API URL for --cloud (default https://api.getshedu.com)
  --token TOKEN    Telegram bot token for direct alerts (else asked, unless --cloud)
  --chat-id ID     Telegram chat id (else detected from your first message to the bot)
  --lang he|en     language of the alerts (default he); terminal output is always English
  --binary PATH    install this binary instead of downloading a release (development)
  --version TAG    install this release (vX.Y.Z, or a pre-release such as vX.Y.Z-rc1)
                   instead of the latest one
  --upgrade        replace the binary and restart the service; keeps the configuration
  --no-auto-update do not install new signed releases automatically at night (AUTO_UPDATE=no)
  --yes            never ask; skip Telegram if no token is given
  --help           show this help

Release downloads are checked against SHA256SUMS (not with --binary). Releases from
v0.3.1 on are signed: when minisign is installed, SHA256SUMS must carry a valid signature
by the release key that names the release being installed, or nothing is installed. Without
minisign the script warns and checks SHA256SUMS only (apt install minisign, or dnf install
minisign). Older releases (v0.3.0) were never signed and are checked with SHA256SUMS only.
USAGE
}

REPO="yosefco3/shedu"
BIN=/usr/local/bin/shedu
CONF_DIR=/etc/shedu
CONF=$CONF_DIR/guard.conf
STATE_DIR=/var/lib/shedu
UNIT=/etc/systemd/system/shedu.service

# Release signing key (minisign public key, key id 9D437473DF0283EF). Keep it identical to
# README.md, SECURITY.md, internal/update (ReleasePublicKey) and https://api.getshedu.com/keys;
# a test checks that. Edit only this one assignment.
MINISIGN_PUBKEY="RWTvgwLfc3RDnS1jVBV3b3vEPLs1HzysJTfbFsfUqEmGxk7T8KOjJ1uv"

# The first signed release. From this version on (pre-releases of it included) the signature
# is required whenever minisign is installed, so it cannot be stripped from a release. The
# only older release, v0.3.0, predates signing and is checked with SHA256SUMS alone; any other
# tag below SIGNED_SINCE is refused (it can only be a fake release).
SIGNED_SINCE=v0.3.1
UNSIGNED_RELEASES="v0.3.0"

RELEASES="https://github.com/$REPO/releases"
MINISIGN_BIN=minisign   # tests point this elsewhere

TOKEN=""; CHAT_ID=""; LANG_OPT="he"; BINARY=""; VERSION=""; UPGRADE=0; YES=0; CLOUD_TOKEN=""; CLOUD_URL=""; AUTO_UPDATE=yes
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2;;
    --cloud) CLOUD_TOKEN="$2"; shift 2;;
    --url) CLOUD_URL="$2"; shift 2;;
    --chat-id) CHAT_ID="$2"; shift 2;;
    --lang) LANG_OPT="$2"; shift 2;;
    --binary) BINARY="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --upgrade) UPGRADE=1; shift;;
    --no-auto-update) AUTO_UPDATE=no; shift;;
    --yes) YES=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

# Terminal output is always English (terminals render Hebrew badly);
# $LANG_OPT only selects the language of the Telegram messages.
say() { echo "$2"; }
die() { echo "✖ $*" >&2; exit 1; }

# --- binary ---------------------------------------------------------------
install_binary() {
  if [ -n "$BINARY" ]; then
    install -m 0755 "$BINARY" "$BIN"
    return
  fi
  local arch tag
  case "$(uname -m)" in
    x86_64) arch=amd64;;
    aarch64|arm64) arch=arm64;;
    *) die "unsupported architecture: $(uname -m)";;
  esac
  tag=${VERSION:-$(latest_tag)}
  valid_tag "$tag" || die "not a release tag: '$tag' (expected vX.Y.Z or vX.Y.Z-rcN)"
  # Every file comes from the same tag, so a release published mid-download can't mix in.
  local base="$RELEASES/download/$tag"
  local tmp; tmp=$(mktemp -d)
  say "⬇ מוריד את Shedu $tag ($arch)..." "⬇ Downloading Shedu $tag ($arch)..."
  curl -fsSL "$base/shedu_linux_$arch" -o "$tmp/shedu" || die "download failed: $base/shedu_linux_$arch"
  curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
  verify_signature "$tmp" "$base" "$tag"
  (cd "$tmp" && mv shedu "shedu_linux_$arch" && sha256sum -c --ignore-missing SHA256SUMS >/dev/null) \
    || die "checksum mismatch — download aborted"
  install -m 0755 "$tmp/shedu_linux_$arch" "$BIN"
  rm -rf "$tmp"
}

# latest_tag: the tag GitHub's "latest release" points to (never a pre-release).
latest_tag() {
  local url
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$RELEASES/latest") \
    || die "could not find the latest release on GitHub"
  echo "${url##*/}"
}

# No leading zeros (bash would read 08 as bad octal), at most 4 digits per number.
valid_tag() { [[ $1 =~ ^v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(-rc[1-9][0-9]*)?$ ]]; }

# version_at_least A B: is A's vX.Y.Z core >= B's? A pre-release counts as its release,
# so v0.3.1-rc1 is "at least v0.3.1" and must be signed too.
version_at_least() {
  local a=${1#v} b=${2#v} a1 a2 a3 b1 b2 b3
  a=${a%%-*}; b=${b%%-*}
  IFS=. read -r a1 a2 a3 <<<"$a"
  IFS=. read -r b1 b2 b3 <<<"$b"
  (( 10#$a1 != 10#$b1 )) && { (( 10#$a1 > 10#$b1 )); return; }
  (( 10#$a2 != 10#$b2 )) && { (( 10#$a2 > 10#$b2 )); return; }
  (( 10#$a3 >= 10#$b3 ))
}

# verify_signature DIR BASE_URL TAG: for a release from $SIGNED_SINCE on, with minisign
# installed, SHA256SUMS must carry a valid signature by the release key whose signed
# comment names TAG ("shedu TAG SHA256SUMS"); a missing one is an error too. Without
# minisign, or for an older release, the SHA256SUMS check is the only check, and the
# script says so.
verify_signature() {
  local dir=$1 base=$2 tag=$3 out
  case "$MINISIGN_PUBKEY" in RW*) ;; *) return 0;; esac   # a fork without a key
  if ! version_at_least "$tag" "$SIGNED_SINCE"; then
    case " $UNSIGNED_RELEASES " in
      *" $tag "*) ;;
      *) die "$tag is not a shedu release (signed releases start at $SIGNED_SINCE) — download aborted";;
    esac
    say "⚠ $tag קודמת להפצות החתומות (מ-$SIGNED_SINCE): נבדקת מול SHA256SUMS בלבד." \
        "⚠ $tag predates signed releases (from $SIGNED_SINCE on): checking SHA256SUMS only."
    return 0
  fi
  if ! command -v "$MINISIGN_BIN" >/dev/null 2>&1; then
    say "⚠ minisign לא מותקן: ההורדה נבדקת מול SHA256SUMS בלבד, בלי בדיקת חתימה (apt install minisign)." \
        "⚠ minisign is not installed: checking SHA256SUMS only, not the release signature (apt install minisign)."
    return 0
  fi
  curl -fsSL "$base/SHA256SUMS.minisig" -o "$dir/SHA256SUMS.minisig" \
    || die "release $tag has no signature (SHA256SUMS.minisig) — download aborted"
  out=$("$MINISIGN_BIN" -V -P "$MINISIGN_PUBKEY" -m "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" 2>&1) \
    || die "signature check failed — download aborted"
  grep -qxF "Trusted comment: shedu $tag SHA256SUMS" <<<"$out" \
    || die "the signature is not for $tag — download aborted"
  say "✔ חתימת ההפצה אומתה (minisign)." "✔ Release signature verified (minisign)."
}

# knows_auto_update: does the installed binary understand AUTO_UPDATE (v0.3.1 and later, or
# a development build)? Older ones refuse a guard.conf with a key they don't know.
knows_auto_update() {
  local v
  v=$("$BIN" version 2>/dev/null) || return 1
  [[ $v =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || return 0   # "dev": built from current source
  version_at_least "$v" v0.3.1
}

# set_auto_update CONF VALUE: write AUTO_UPDATE=VALUE into an existing config.
set_auto_update() {
  if grep -q '^AUTO_UPDATE=' "$1"; then
    sed -i "s/^AUTO_UPDATE=.*/AUTO_UPDATE=$2/" "$1"
  else
    printf '%s\n' "# Nightly self-update to new signed releases (yes/no). Off: AUTO_UPDATE=no" "AUTO_UPDATE=$2" >>"$1"
  fi
}

# auto_update_note: for an existing config after installing a binary, apply --no-auto-update or
# say once that nightly updates are now on (they default to on from v0.3.1).
auto_update_note() {
  [ -f "$CONF" ] || return 0
  if ! knows_auto_update; then
    [ "$AUTO_UPDATE" = no ] && say "ℹ לגרסה הזו אין עדכון אוטומטי, אין מה לכבות." "ℹ This version has no auto-update; nothing to turn off."
    return 0
  fi
  if [ "$AUTO_UPDATE" = no ]; then
    set_auto_update "$CONF" no
    say "✔ עדכון אוטומטי כבוי (AUTO_UPDATE=no ב-$CONF)." "✔ Auto-update is off (AUTO_UPDATE=no in $CONF)."
  elif ! grep -q '^AUTO_UPDATE=' "$CONF"; then
    say "ℹ מעכשיו Shedu מתעדכן לבד בלילה, רק לגרסאות חתומות. לכיבוי: AUTO_UPDATE=no ב-$CONF" \
        "ℹ Shedu now updates itself at night, to signed releases only. To turn it off: AUTO_UPDATE=no in $CONF"
  fi
}

# Sourced by packaging/install_test.sh with SHEDU_INSTALL_LIB=1: functions only.
[ "${SHEDU_INSTALL_LIB:-}" = 1 ] && return 0

[ "$(id -u)" -eq 0 ] || die "$(say 'יש להריץ עם sudo' 'please run with sudo')"

HAS_SYSTEMD=1
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || HAS_SYSTEMD=0
if [ -f /etc/debian_version ]; then :; else
  say "⚠ זו לא מערכת Debian/Ubuntu. Shedu ירוץ, אבל בדיקת העדכונים תדולג." \
      "⚠ Not a Debian/Ubuntu system. Shedu will run, but the updates check is skipped."
fi

# --- unit (also rewritten on --upgrade, so hardening changes reach old installs) ---
write_unit() {
  cat > "$UNIT" <<'UNIT'
[Unit]
Description=Shedu — plain-language security watch for this server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/shedu run
Restart=always
RestartSec=5
ProtectSystem=strict
ReadWritePaths=/var/lib/shedu
ProtectHome=read-only
# PrivateTmp stays off: the scans must see the real /tmp, where droppers land.
NoNewPrivileges=true
MemoryMax=64M
Nice=10

[Install]
WantedBy=multi-user.target
UNIT
}

if [ "$UPGRADE" -eq 1 ]; then
  OLD=$("$BIN" version 2>/dev/null || echo none)
  install_binary
  NEW=$("$BIN" version)
  auto_update_note
  if [ "$HAS_SYSTEMD" -eq 1 ] && [ -f "$UNIT" ]; then
    write_unit
    systemctl daemon-reload
    systemctl restart shedu 2>/dev/null || true
  fi
  echo "✔ shedu $OLD → $NEW"
  exit 0
fi

install_binary
mkdir -p "$CONF_DIR" "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# --- telegram -------------------------------------------------------------
if [ ! -f "$CONF" ]; then
  if [ -z "$TOKEN" ] && [ -z "$CLOUD_TOKEN" ] && [ "$YES" -eq 0 ] && [ -t 0 ]; then
    say "" ""
    say "Shedu שולח התראות לטלגרם. כדי לחבר אותו:" "Shedu sends alerts to Telegram. To connect it:"
    say "  1. פתח בטלגרם את @BotFather, שלח /newbot ועקוב אחרי ההוראות." "  1. Open @BotFather in Telegram, send /newbot and follow the steps."
    say "  2. העתק את ה-token שהוא נותן (נראה כמו 123456:ABC-DEF...)." "  2. Copy the token it gives you (looks like 123456:ABC-DEF...)."
    say "  3. שלח הודעה כלשהי לבוט החדש שלך, כדי שהוא יכיר אותך." "  3. Send any message to your new bot so it knows who you are."
    say "" ""
    read -r -p "Paste the token (or Enter to skip): " TOKEN </dev/tty || TOKEN=""
  fi
  if [ -n "$TOKEN" ] && [ -z "$CHAT_ID" ]; then
    # auto-detect the chat id from the message the user just sent
    CHAT_ID=$(curl -fsSL "https://api.telegram.org/bot$TOKEN/getUpdates" 2>/dev/null \
      | grep -o '"chat":{"id":-\?[0-9]*' | head -1 | grep -o -- '-\?[0-9]*$' || true)
    if [ -z "$CHAT_ID" ] && [ "$YES" -eq 0 ] && [ -t 0 ]; then
      say "לא מצאתי הודעה לבוט. שלח לו הודעה עכשיו ולחץ Enter, או הדבק chat id ידנית." \
          "No message to the bot found. Send it one now and press Enter, or paste a chat id."
      read -r -p "chat id: " CHAT_ID </dev/tty || CHAT_ID=""
      [ -z "$CHAT_ID" ] && CHAT_ID=$(curl -fsSL "https://api.telegram.org/bot$TOKEN/getUpdates" 2>/dev/null \
        | grep -o '"chat":{"id":-\?[0-9]*' | head -1 | grep -o -- '-\?[0-9]*$' || true)
    fi
  fi
  {
    echo "# Shedu configuration — generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by install.sh"
    echo "LANG=$LANG_OPT"
    echo "DAILY_REPORT_AT=08:00"
    echo "BRUTE_FORCE_THRESHOLD=5"
    if knows_auto_update; then
      echo "# Nightly self-update to new signed releases (yes/no). Off: AUTO_UPDATE=no"
      echo "AUTO_UPDATE=$AUTO_UPDATE"
    fi
    cat <<'TUNING'

# How noisy Shedu is: low | normal | high. Everything below follows this dial.
# SENSITIVITY=normal
#
# Expert overrides (uncomment to pin one value; it always beats the dial).
# Defaults shown are for normal (low / high in brackets).
# MINER_CPU_PERCENT=80      # sustained CPU % before a process looks like a miner (90 / 70)
# OUTBOUND_NEW_DAYS=30      # a destination unseen this many days counts as new (90 / 7)
# MASSFILE_COUNT=200        # files changed ... (500 / 50)
# MASSFILE_WINDOW=60s       # ... within this window
# OUTBOUND_ALERTS=beacon    # off | beacon | all (high: all)
# SECRET_AUDIT=off          # on = live secret-read alerts, needs auditd
# CLAMAV_AT=03:00           # nightly ClamAV scan if installed; empty disables
# AUTO_UPDATE_AT=03:30      # when to check for an update (HH:MM local; default: a fixed minute 03:00-05:00 per server)
TUNING
    [ -n "$TOKEN" ] && echo "TELEGRAM_TOKEN=\"$TOKEN\""
    [ -n "$CHAT_ID" ] && echo "TELEGRAM_CHAT_ID=\"$CHAT_ID\""
  } > "$CONF"
  chmod 0600 "$CONF"
  if [ -n "$TOKEN" ] && [ -n "$CHAT_ID" ]; then
    curl -fsS -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
      -d chat_id="$CHAT_ID" -d text="✔ Shedu: $(hostname)" >/dev/null \
      && say "✔ הודעת בדיקה נשלחה לטלגרם." "✔ Test message sent to Telegram." \
      || say "⚠ שליחת הבדיקה לטלגרם נכשלה. בדוק את ה-token ואת ה-chat id ב-$CONF" "⚠ Telegram test failed. Check the token and chat id in $CONF"
  elif [ -z "$CLOUD_TOKEN" ]; then
    say "ℹ טלגרם לא הוגדר. אפשר להוסיף TELEGRAM_TOKEN ו-TELEGRAM_CHAT_ID ל-$CONF בכל רגע." \
        "ℹ Telegram not configured. Add TELEGRAM_TOKEN and TELEGRAM_CHAT_ID to $CONF any time."
  fi
else
  auto_update_note   # re-install over an existing config
fi

# --- cloud (before the service starts, so its first run already reports) ----
if [ -n "$CLOUD_TOKEN" ]; then
  ENROLL_ARGS=(enroll "$CLOUD_TOKEN" --config "$CONF")
  [ -n "$CLOUD_URL" ] && ENROLL_ARGS+=(--url "$CLOUD_URL")
  "$BIN" "${ENROLL_ARGS[@]}" \
    || die "could not connect to the Shedu cloud (token expired or already used? create a new one in the dashboard). Nothing was started; run this command again with a new token."
fi

# --- service --------------------------------------------------------------
if [ "$HAS_SYSTEMD" -eq 1 ]; then
  write_unit
  systemctl daemon-reload
  systemctl enable --now shedu >/dev/null
  # a reinstall onto a running service: pick up the new CLOUD_KEY
  [ -n "$CLOUD_TOKEN" ] && systemctl restart shedu
else
  say "⚠ אין systemd: השירות לא הותקן. הרץ ידנית: sudo shedu run" "⚠ No systemd: service not installed. Run manually: sudo shedu run"
fi

# --- first report ---------------------------------------------------------
echo
"$BIN" check --config "$CONF" || true
echo
say "✔ Shedu הותקן. דוח יומי בשעה 08:00. בכל רגע: sudo shedu check" \
    "✔ Shedu installed. Daily report at 08:00. Any time: sudo shedu check"
