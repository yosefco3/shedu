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
#   --upgrade          replace the binary and restart, keep config
#   --yes              never ask; skip Telegram if not given
set -euo pipefail

REPO="yosefco3/shedu"
BIN=/usr/local/bin/shedu
CONF_DIR=/etc/shedu
CONF=$CONF_DIR/guard.conf
STATE_DIR=/var/lib/shedu
UNIT=/etc/systemd/system/shedu.service

TOKEN=""; CHAT_ID=""; LANG_OPT="he"; BINARY=""; UPGRADE=0; YES=0; CLOUD_TOKEN=""; CLOUD_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2;;
    --cloud) CLOUD_TOKEN="$2"; shift 2;;
    --url) CLOUD_URL="$2"; shift 2;;
    --chat-id) CHAT_ID="$2"; shift 2;;
    --lang) LANG_OPT="$2"; shift 2;;
    --binary) BINARY="$2"; shift 2;;
    --upgrade) UPGRADE=1; shift;;
    --yes) YES=1; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

# Terminal output is always English (terminals render Hebrew badly);
# $LANG_OPT only selects the language of the Telegram messages.
say() { echo "$2"; }
die() { echo "✖ $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "$(say 'יש להריץ עם sudo' 'please run with sudo')"

HAS_SYSTEMD=1
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || HAS_SYSTEMD=0
if [ -f /etc/debian_version ]; then :; else
  say "⚠ זו לא מערכת Debian/Ubuntu. Shedu ירוץ, אבל בדיקת העדכונים תדולג." \
      "⚠ Not a Debian/Ubuntu system. Shedu will run, but the updates check is skipped."
fi

# --- binary ---------------------------------------------------------------
install_binary() {
  if [ -n "$BINARY" ]; then
    install -m 0755 "$BINARY" "$BIN"
    return
  fi
  local arch
  case "$(uname -m)" in
    x86_64) arch=amd64;;
    aarch64|arm64) arch=arm64;;
    *) die "unsupported architecture: $(uname -m)";;
  esac
  local base="https://github.com/$REPO/releases/latest/download"
  local tmp; tmp=$(mktemp -d)
  say "⬇ מוריד את Shedu ($arch)..." "⬇ Downloading Shedu ($arch)..."
  curl -fsSL "$base/shedu_linux_$arch" -o "$tmp/shedu"
  curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
  (cd "$tmp" && mv shedu "shedu_linux_$arch" && sha256sum -c --ignore-missing SHA256SUMS >/dev/null) \
    || die "checksum mismatch — download aborted"
  install -m 0755 "$tmp/shedu_linux_$arch" "$BIN"
  rm -rf "$tmp"
}

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
