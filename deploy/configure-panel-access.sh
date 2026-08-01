#!/usr/bin/env bash
set -Eeuo pipefail

MODE=""
HOST=""
PUBLIC_PORT="61443"
ACME_ROOT="/var/www/letsencrypt"
STATE_FILE="/etc/xpanel-mvp/panel-access.env"
INSTALL_MARKER="/etc/xpanel-mvp/install-complete.env"

log(){ printf '[SG-Panel Access] %s\n' "$*"; }
fail(){ printf '[SG-Panel Access] ERROR: %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'USAGE'
Использование:
  configure-panel-access.sh --mode http  --host 192.168.1.200 --port 61443
  configure-panel-access.sh --mode https --host panel.example.com --port 61443
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PUBLIC_PORT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "неизвестный параметр: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
[[ "$MODE" == "http" || "$MODE" == "https" ]] || { usage; exit 1; }
[[ -n "$HOST" ]] || fail "укажите IP, имя сервера или домен"
[[ "$PUBLIC_PORT" =~ ^[0-9]+$ ]] && (( PUBLIC_PORT >= 1024 && PUBLIC_PORT <= 65535 )) || fail "порт должен быть от 1024 до 65535"

if [[ "$MODE" == "http" ]]; then
  exec bash /opt/xpanel-mvp/deploy/configure-http.sh --host "$HOST" --port "$PUBLIC_PORT"
fi

[[ "$HOST" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || fail "для HTTPS укажите корректное доменное имя"
for command in nginx certbot openssl getent curl; do
  command -v "$command" >/dev/null 2>&1 || fail "не найден $command"
done

detect_public_ipv4(){
  local token="" value=""
  token="$(curl -fsS --connect-timeout 1 --max-time 2 -X PUT \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
    http://169.254.169.254/latest/api/token 2>/dev/null || true)"
  if [[ -n "$token" ]]; then
    value="$(curl -fsS --connect-timeout 1 --max-time 2 \
      -H "X-aws-ec2-metadata-token: $token" \
      http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"
  fi
  if [[ ! "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    value="$(curl -4fsS --max-time 15 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  printf '%s' "$value"
}

PUBLIC_IP="$(detect_public_ipv4)"
[[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "не удалось определить публичный IPv4"
RESOLVED="$(getent ahostsv4 "$HOST" | awk '{print $1}' | sort -u || true)"
if ! grep -Fxq "$PUBLIC_IP" <<<"$RESOLVED"; then
  printf 'Домен: %s\nПубличный IP: %s\nDNS возвращает:\n%s\n' "$HOST" "$PUBLIC_IP" "${RESOLVED:-ничего}" >&2
  fail "A-запись домена ещё не указывает на этот сервер"
fi

log "Подготавливаю безопасное переключение на HTTPS"
BACKUP_DIR="$(mktemp -d /root/sg-panel-https.XXXXXX)"
COMMITTED=0
backup_path(){
  local source="$1" name="$2"
  if [[ -e "$source" || -L "$source" ]]; then
    cp -a "$source" "$BACKUP_DIR/$name"
  fi
  return 0
}
restore_path(){
  local backup="$1" target="$2"
  if [[ -e "$backup" || -L "$backup" ]]; then
    mkdir -p "$(dirname "$target")"
    cp -a "$backup" "$target"
  fi
  return 0
}
backup_path /etc/nginx/sites-available/sg-panel nginx-conf
backup_path /etc/nginx/sites-enabled/sg-panel nginx-link
backup_path /etc/nginx/sites-available/sg-panel-acme acme-conf
backup_path /etc/nginx/sites-enabled/sg-panel-acme acme-link
backup_path /etc/xpanel-mvp/web.env web.env
backup_path "$STATE_FILE" panel-access.env
backup_path "$INSTALL_MARKER" install-complete.env
backup_path /etc/nginx/sites-available/sg-panel-xray-transport xray-transport-conf
backup_path /etc/nginx/sites-enabled/sg-panel-xray-transport xray-transport-link
backup_path /etc/nginx/modules-enabled/90-sg-panel-reality-edge.conf reality-stream-conf
backup_path /etc/nginx/sites-available/sg-panel-reality-placeholder reality-web-conf
backup_path /etc/nginx/sites-enabled/sg-panel-reality-placeholder reality-web-link
backup_path /etc/xpanel-mvp/reality-edge.env reality-edge.env
backup_path /usr/local/etc/xray/config.json xray-config.json
if [[ -f /opt/xpanel-mvp/data/panel.db ]]; then
  cp -a /opt/xpanel-mvp/data/panel.db "$BACKUP_DIR/panel.db"
fi

rollback(){
  local rc=$?
  if [[ $COMMITTED -eq 0 ]]; then
    log "HTTPS не настроен, восстанавливаю предыдущий доступ"
    rm -f /etc/nginx/sites-available/sg-panel /etc/nginx/sites-enabled/sg-panel \
      /etc/nginx/sites-available/sg-panel-acme /etc/nginx/sites-enabled/sg-panel-acme \
      /etc/nginx/sites-available/sg-panel-xray-transport /etc/nginx/sites-enabled/sg-panel-xray-transport \
      /etc/nginx/modules-enabled/90-sg-panel-reality-edge.conf \
      /etc/nginx/sites-available/sg-panel-reality-placeholder \
      /etc/nginx/sites-enabled/sg-panel-reality-placeholder
    restore_path "$BACKUP_DIR/nginx-conf" /etc/nginx/sites-available/sg-panel
    restore_path "$BACKUP_DIR/nginx-link" /etc/nginx/sites-enabled/sg-panel
    restore_path "$BACKUP_DIR/acme-conf" /etc/nginx/sites-available/sg-panel-acme
    restore_path "$BACKUP_DIR/acme-link" /etc/nginx/sites-enabled/sg-panel-acme
    restore_path "$BACKUP_DIR/web.env" /etc/xpanel-mvp/web.env
    rm -f "$STATE_FILE" "$INSTALL_MARKER"
    restore_path "$BACKUP_DIR/panel-access.env" "$STATE_FILE"
    restore_path "$BACKUP_DIR/install-complete.env" "$INSTALL_MARKER"
    rm -f /etc/xpanel-mvp/reality-edge.env /usr/local/etc/xray/config.json
    restore_path "$BACKUP_DIR/reality-edge.env" /etc/xpanel-mvp/reality-edge.env
    restore_path "$BACKUP_DIR/xray-config.json" /usr/local/etc/xray/config.json
    restore_path "$BACKUP_DIR/xray-transport-conf" /etc/nginx/sites-available/sg-panel-xray-transport
    restore_path "$BACKUP_DIR/xray-transport-link" /etc/nginx/sites-enabled/sg-panel-xray-transport
    restore_path "$BACKUP_DIR/reality-stream-conf" /etc/nginx/modules-enabled/90-sg-panel-reality-edge.conf
    restore_path "$BACKUP_DIR/reality-web-conf" /etc/nginx/sites-available/sg-panel-reality-placeholder
    restore_path "$BACKUP_DIR/reality-web-link" /etc/nginx/sites-enabled/sg-panel-reality-placeholder
    restore_path "$BACKUP_DIR/panel.db" /opt/xpanel-mvp/data/panel.db
    systemctl restart xray >/dev/null 2>&1 || true
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    systemctl restart xpanel-web >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap rollback ERR INT TERM

log "Готовлю HTTP-01 на TCP 80"
mkdir -p "$ACME_ROOT/.well-known/acme-challenge" /etc/nginx/sites-available /etc/nginx/sites-enabled

# configure-http.sh keeps the HTTP placeholder and panel proxy in one site.
# Its :80 block can compete with the temporary ACME site for the same domain.
# The old symlink was backed up above and rollback restores it on failure.
log "Временно отключаю прежний HTTP-сайт панели на TCP 80"
rm -f /etc/nginx/sites-enabled/sg-panel /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/sg-panel-acme <<EOF_ACME
server {
    listen 80;
    listen [::]:80;
    server_name $HOST;

    location ^~ /.well-known/acme-challenge/ {
        root $ACME_ROOT;
        default_type text/plain;
    }

    location / {
        return 404;
    }
}
EOF_ACME
ln -sfn /etc/nginx/sites-available/sg-panel-acme /etc/nginx/sites-enabled/sg-panel-acme
nginx -t
systemctl enable --now nginx
systemctl reload nginx

log "Проверяю локальный HTTP-01 Nginx/webroot"
PROBE_NAME="sg-panel-local-$(openssl rand -hex 8)"
PROBE_TOKEN="sg-panel-http01-ready-$PROBE_NAME"
PROBE_FILE="$ACME_ROOT/.well-known/acme-challenge/$PROBE_NAME"
printf '%s\n' "$PROBE_TOKEN" > "$PROBE_FILE"
PROBE_RESULT="$(curl --noproxy '*' -fsS --max-time 5 \
  --resolve "$HOST:80:127.0.0.1" \
  "http://$HOST/.well-known/acme-challenge/$PROBE_NAME" 2>/dev/null || true)"
rm -f "$PROBE_FILE"
if [[ "$PROBE_RESULT" != "$PROBE_TOKEN" ]]; then
  printf '[SG-Panel Access] ERROR: локальная проверка HTTP-01 через Nginx/webroot не пройдена\n' >&2
  false
fi
log "Локальный HTTP-01 готов; внешнюю доступность TCP 80 проверит Let's Encrypt"

CERT_DIR="/etc/letsencrypt/live/$HOST"
CERT_FILE="$CERT_DIR/fullchain.pem"
KEY_FILE="$CERT_DIR/privkey.pem"
if [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] && openssl x509 -checkend 604800 -noout -in "$CERT_FILE" >/dev/null 2>&1; then
  log "Использую существующий сертификат"
else
  log "Получаю сертификат Let's Encrypt для $HOST"
  if ! certbot certonly \
    --webroot -w "$ACME_ROOT" \
    --domain "$HOST" \
    --register-unsafely-without-email \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring; then
    printf '[SG-Panel Access] ERROR: Let\047s Encrypt не смог подтвердить домен. Проверьте внешний TCP 80; HTTPS не включён, предыдущий доступ будет восстановлен.\n' >&2
    false
  fi
fi

log "Переключаю панель на HTTPS"
rm -f /etc/nginx/sites-enabled/sg-panel-acme
bash /opt/xpanel-mvp/deploy/configure-https.sh \
  --domain "$HOST" \
  --cert "$CERT_FILE" \
  --key "$KEY_FILE" \
  --port "$PUBLIC_PORT" \
  --mode full

cd /opt/xpanel-mvp
.venv/bin/python - "$HOST" "$PUBLIC_PORT" <<'PY'
import sys
from xpanel.db import connect, init_db
host, port = sys.argv[1:]
init_db()
with connect() as con:
    con.execute(
        "UPDATE subscription_settings SET base_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
        (f"https://{host}:{port}",),
    )
PY

mkdir -p /etc/xpanel-mvp
cat > "$STATE_FILE" <<EOF_STATE
PANEL_ACCESS_MODE=https
PANEL_PUBLIC_HOST=$HOST
PANEL_PUBLIC_PORT=$PUBLIC_PORT
PANEL_DOMAIN=$HOST
UPDATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_STATE
chmod 600 "$STATE_FILE"
cat > "$INSTALL_MARKER" <<EOF_MARKER
INSTALL_COMPLETE=1
VERSION=$(/opt/xpanel-mvp/.venv/bin/python -m xpanel --version | awk '{print $2}')
PANEL_ACCESS_MODE=https
PANEL_PUBLIC_HOST=$HOST
PANEL_PUBLIC_PORT=$PUBLIC_PORT
PANEL_DOMAIN=$HOST
COMPLETED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_MARKER
chmod 600 "$INSTALL_MARKER"

COMMITTED=1
trap - ERR INT TERM
rm -rf "$BACKUP_DIR"
log "HTTPS настроен: https://$HOST:$PUBLIC_PORT"
log "При переключении с HTTP войдите в панель заново по новому адресу"
