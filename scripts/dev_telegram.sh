#!/usr/bin/env bash
# Local (no sudo) Telegram setup for development: asks for the bot token without
# echoing it, finds your chat id from the message you sent the bot, writes
# ./guard.conf (0600, git-ignored) and sends a first real report.
set -euo pipefail
cd "$(dirname "$0")/.."
read -r -s -p "Telegram bot token (hidden): " TOKEN; echo
[ -n "$TOKEN" ] || { echo "no token given"; exit 1; }
CHAT_ID=$(curl -fsSL "https://api.telegram.org/bot$TOKEN/getUpdates" \
  | grep -o '"chat":{"id":-\?[0-9]*' | head -1 | grep -o -- '-\?[0-9]*$' || true)
if [ -z "$CHAT_ID" ]; then
  echo "No message found. Open the bot in Telegram, send it any message, then run this again."
  exit 1
fi
umask 077
cat > guard.conf <<CONF
# local dev config — not committed
LANG=he
DAILY_REPORT_AT=08:00
BRUTE_FORCE_THRESHOLD=5
TELEGRAM_TOKEN="$TOKEN"
TELEGRAM_CHAT_ID="$CHAT_ID"
CONF
echo "✔ guard.conf written (chat id $CHAT_ID)"
make build >/dev/null
./bin/shedu check --config ./guard.conf
