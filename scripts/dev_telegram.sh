#!/usr/bin/env bash
# Local (no sudo) Telegram setup for development: asks for the bot token without
# echoing it, finds your chat id from the message you sent the bot, writes
# ./guard.conf (0600, git-ignored) and sends a first real report.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Paste ONLY the bot token from BotFather (it looks like 123456789:AAH...)."
echo "Nothing will appear on screen while you paste. Then press Enter."
read -r -s -p "token: " TOKEN; echo
TOKEN=$(printf '%s' "$TOKEN" | tr -d '[:space:]')
[ -n "$TOKEN" ] || { echo "✖ nothing was entered"; exit 1; }
if ! printf '%s' "$TOKEN" | grep -Eq '^[0-9]{6,}:[A-Za-z0-9_-]{30,}$'; then
  echo "✖ That does not look like a bot token (expected digits, a colon, then ~35 letters). Try again."
  exit 1
fi
# first: is the token valid at all?
ME=$(curl -sS "https://api.telegram.org/bot$TOKEN/getMe" || true)
case "$ME" in
  *'"ok":true'*) BOT=$(echo "$ME" | grep -o '"username":"[^"]*' | cut -d'"' -f4); NAME=$(echo "$ME" | grep -o '"first_name":"[^"]*' | cut -d'"' -f4); echo "✔ token ok, bot: @$BOT (display name: $NAME)";;
  *401*|*Unauthorized*) echo "✖ Telegram says the token is wrong (Unauthorized). Copy it again from @BotFather — it looks like 123456789:AAH...". ; exit 1;;
  *) echo "✖ could not reach api.telegram.org: ${ME:-no response}"; exit 1;;
esac
UPDATES=$(curl -sS "https://api.telegram.org/bot$TOKEN/getUpdates" || true)
case "$UPDATES" in
  *409*|*webhook*) echo "✖ this bot has a webhook set, so getUpdates is blocked. Remove it: curl -s https://api.telegram.org/bot<TOKEN>/deleteWebhook"; exit 1;;
esac
CHAT_ID=$(echo "$UPDATES" | grep -o '"chat":{"id":-\?[0-9]*' | head -1 | grep -o -- '-\?[0-9]*$' || true)
if [ -z "$CHAT_ID" ]; then
  echo "✖ The bot @$BOT has not received any message yet."
  echo "  Open https://t.me/$BOT in Telegram, press Start (or send 'hi'), then run this again."
  echo "  Raw reply from Telegram (safe to share, contains no token):"
  echo "  ${UPDATES:0:400}"
  WH=$(curl -sS "https://api.telegram.org/bot$TOKEN/getWebhookInfo" || true)
  echo "  Webhook info: ${WH:0:200}"
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
