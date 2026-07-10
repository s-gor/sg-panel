#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${1:-}" == "--yes" ]] || {
  echo "Usage: sudo bash uninstall-node-agent.sh --yes" >&2
  exit 2
}
[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo "Run with sudo" >&2
  exit 1
}

GREEN=$'\033[0;32m'
RESET=$'\033[0m'

systemctl disable --now sg-node-agent.service >/dev/null 2>&1 || true
systemctl disable --now sg-node-worker.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sg-node-agent.service
rm -f /etc/systemd/system/sg-node-worker.service
rm -f /usr/local/libexec/sg-node-worker.py
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed sg-node-agent.service sg-node-worker.service >/dev/null 2>&1 || true
rm -rf /opt/sg-node /etc/sg-node /var/lib/sg-node/jobs

printf '%s[OK]%s SG-Node Agent и Worker удалены.\n' "$GREEN" "$RESET"
# Xray, Nginx and VPN configuration were not changed.
echo "Xray, Nginx, VPN-конфигурация и резервные копии ноды не изменены."
