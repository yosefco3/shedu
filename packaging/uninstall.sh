#!/usr/bin/env bash
# Remove Shedu. Asks before deleting config and state.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "please run with sudo" >&2; exit 1; }
systemctl disable --now shedu 2>/dev/null || true
rm -f /etc/systemd/system/shedu.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/shedu
echo "✔ service and binary removed"
if [ -t 0 ]; then
  read -r -p "Also delete /etc/shedu (config) and /var/lib/shedu (state)? [y/N] " ans
  if [ "${ans,,}" = "y" ]; then rm -rf /etc/shedu /var/lib/shedu; echo "✔ config and state removed"; fi
else
  echo "ℹ config and state kept in /etc/shedu and /var/lib/shedu"
fi
