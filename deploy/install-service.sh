#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/etc/xpanel-mvp/web.env"
SERVICE_FILE="/etc/systemd/system/xpanel-web.service"
PROJECT_DIR="/opt/xpanel-mvp"

[[ $EUID -eq 0 ]] || { echo "Ошибка: запустите от root" >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Ошибка: не найден $ENV_FILE" >&2; exit 1; }

get_env(){
  local key="$1" default="$2" value
  value="$(grep -E "^${key}=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
  printf '%s' "${value:-$default}"
}

BIND_ADDRESS="$(get_env XPANEL_BIND_ADDRESS 0.0.0.0)"
PORT="$(get_env XPANEL_PORT 8080)"
if [[ "$BIND_ADDRESS" == *:* && "$BIND_ADDRESS" != \[*\] ]]; then
  LISTEN_ADDRESS="[$BIND_ADDRESS]:$PORT"
else
  LISTEN_ADDRESS="$BIND_ADDRESS:$PORT"
fi

if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "Ошибка: XPANEL_PORT должен быть от 1 до 65535" >&2
  exit 1
fi

cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=SG-Panel web interface
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$PROJECT_DIR/.venv/bin/waitress-serve --listen=$LISTEN_ADDRESS xpanel.web:app
Restart=on-failure
RestartSec=3
User=root
Group=root
UMask=0077
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$PROJECT_DIR/data $PROJECT_DIR/backups /etc/xpanel-mvp /usr/local/etc/xray

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable xpanel-web >/dev/null
