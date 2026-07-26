#!/usr/bin/env bash
set -Eeuo pipefail

HOST=""
PUBLIC_PORT="61443"
ENV_FILE="/etc/xpanel-mvp/web.env"
NGINX_CONF="/etc/nginx/sites-available/sg-panel"
NGINX_LINK="/etc/nginx/sites-enabled/sg-panel"
STATE_FILE="/etc/xpanel-mvp/panel-access.env"
INSTALL_MARKER="/etc/xpanel-mvp/install-complete.env"
PLACEHOLDER_SOURCE="/opt/xpanel-mvp/assets/placeholders/sg-dark/index.html"
PLACEHOLDER_ROOT="/var/www/sg-panel-placeholder"
BACKUP_DIR=""
COMMITTED=0

log(){ printf '[SG-Panel HTTP] %s\n' "$*"; }
fail(){ printf '[SG-Panel HTTP] ERROR: %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'USAGE'
Использование:
  configure-http.sh --host 192.168.1.200 --port 61443

Настраивает публичный HTTP-доступ через Nginx на выбранном порту.
Backend SG-Panel остаётся на 127.0.0.1:8080.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PUBLIC_PORT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "неизвестный параметр: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
[[ -n "$HOST" ]] || { usage; exit 1; }
[[ "$HOST" =~ ^[A-Za-z0-9._:-]+$ ]] || fail "IP или имя сервера содержит недопустимые символы"
[[ "$PUBLIC_PORT" =~ ^[0-9]+$ ]] && (( PUBLIC_PORT >= 1024 && PUBLIC_PORT <= 65535 )) || fail "порт должен быть от 1024 до 65535"
case "$PUBLIC_PORT" in
  22|80|443|8080|8443) fail "порт $PUBLIC_PORT зарезервирован для другого назначения" ;;
esac
command -v nginx >/dev/null 2>&1 || fail "nginx не установлен"
[[ -f "$ENV_FILE" ]] || fail "не найден $ENV_FILE"

if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)$PUBLIC_PORT$"; then
  nginx -T 2>/dev/null | grep -Eq "listen[[:space:]]+${PUBLIC_PORT}([[:space:]]|;)" || \
    fail "порт $PUBLIC_PORT уже занят другим процессом"
fi

log "Подготавливаю безопасное переключение на HTTP"
BACKUP_DIR="$(mktemp -d /root/sg-panel-http.XXXXXX)"
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
backup_path "$NGINX_CONF" nginx-conf
backup_path "$NGINX_LINK" nginx-link
backup_path "$ENV_FILE" web.env
backup_path "$STATE_FILE" panel-access.env
backup_path "$INSTALL_MARKER" install-complete.env
if [[ -f /opt/xpanel-mvp/data/panel.db ]]; then
  cp -a /opt/xpanel-mvp/data/panel.db "$BACKUP_DIR/panel.db"
fi

rollback(){
  local rc=$?
  if [[ $COMMITTED -eq 0 ]]; then
    log "Операция не завершена, восстанавливаю предыдущий доступ"
    rm -f "$NGINX_CONF" "$NGINX_LINK"
    restore_path "$BACKUP_DIR/nginx-conf" "$NGINX_CONF"
    restore_path "$BACKUP_DIR/nginx-link" "$NGINX_LINK"
    restore_path "$BACKUP_DIR/web.env" "$ENV_FILE"
    rm -f "$STATE_FILE" "$INSTALL_MARKER"
    restore_path "$BACKUP_DIR/panel-access.env" "$STATE_FILE"
    restore_path "$BACKUP_DIR/install-complete.env" "$INSTALL_MARKER"
    restore_path "$BACKUP_DIR/panel.db" /opt/xpanel-mvp/data/panel.db
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    systemctl restart xpanel-web >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap rollback ERR INT TERM

reserve_port(){
  python3 - "$PUBLIC_PORT" <<'PY'
from pathlib import Path
import subprocess
import sys
port = int(sys.argv[1])
try:
    current = subprocess.check_output(
        ["sysctl", "-n", "net.ipv4.ip_local_reserved_ports"],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    current = ""
parts = [item.strip() for item in current.split(",") if item.strip()]
covered = False
for item in parts:
    try:
        if "-" in item:
            lo, hi = map(int, item.split("-", 1))
            covered = lo <= port <= hi
        else:
            covered = int(item) == port
    except ValueError:
        pass
    if covered:
        break
if not covered:
    parts.append(str(port))
Path("/etc/sysctl.d/99-sg-panel-port.conf").write_text(
    "net.ipv4.ip_local_reserved_ports=" + ",".join(parts) + "\n",
    encoding="utf-8",
)
PY
  sysctl --system >/dev/null
}

reserve_port
BACKEND_PORT="$(grep -E '^XPANEL_PORT=' "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
BACKEND_PORT="${BACKEND_PORT:-8080}"

log "Настраиваю Nginx: заглушка :80 и панель :$PUBLIC_PORT -> 127.0.0.1:$BACKEND_PORT"
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled "$PLACEHOLDER_ROOT"
[[ -f "$PLACEHOLDER_SOURCE" ]] || fail "не найден шаблон страницы-заглушки: $PLACEHOLDER_SOURCE"
install -m 0644 "$PLACEHOLDER_SOURCE" "$PLACEHOLDER_ROOT/index.default.html"
if [[ ! -f "$PLACEHOLDER_ROOT/index.html" ]]; then
  install -m 0644 "$PLACEHOLDER_SOURCE" "$PLACEHOLDER_ROOT/index.html"
fi
cat > "$NGINX_CONF" <<EOF_NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $HOST;

    location = / {
        root $PLACEHOLDER_ROOT;
        try_files /index.html =404;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;
    }

    location = /index.html {
        root $PLACEHOLDER_ROOT;
        try_files /index.html =404;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;
    }

    location / {
        return 404;
    }
}

server {
    listen $PUBLIC_PORT;
    listen [::]:$PUBLIC_PORT;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${BACKEND_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto http;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
EOF_NGINX

rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/sg-panel-acme
ln -sfn "$NGINX_CONF" "$NGINX_LINK"
nginx -t
systemctl enable --now nginx
systemctl reload nginx

python3 - "$ENV_FILE" "$BACKEND_PORT" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
backend_port = sys.argv[2]
values = {
    "XPANEL_BIND_ADDRESS": "127.0.0.1",
    "XPANEL_PORT": backend_port,
    "XPANEL_TRUST_PROXY_HEADERS": "1",
    "XPANEL_SECURE_COOKIES": "0",
}
lines = path.read_text(encoding="utf-8").splitlines()
out = []
pending = dict(values)
for line in lines:
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in pending:
        out.append(f"{key}={pending.pop(key)}")
    else:
        out.append(line)
out.extend(f"{key}={value}" for key, value in pending.items())
path.write_text("\n".join(out) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

cd /opt/xpanel-mvp
.venv/bin/python - "$HOST" "$PUBLIC_PORT" <<'PY'
import sys
from xpanel.db import connect, init_db
host, port = sys.argv[1:]
init_db()
with connect() as con:
    con.execute(
        "UPDATE security_settings SET trust_proxy_headers=1, updated_at=CURRENT_TIMESTAMP WHERE id=1"
    )
    con.execute(
        "UPDATE subscription_settings SET base_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
        (f"http://{host}:{port}",),
    )
PY

mkdir -p /etc/xpanel-mvp
cat > "$STATE_FILE" <<EOF_STATE
PANEL_ACCESS_MODE=http
PANEL_PUBLIC_HOST=$HOST
PANEL_PUBLIC_PORT=$PUBLIC_PORT
PANEL_DOMAIN=
UPDATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_STATE
chmod 600 "$STATE_FILE"

cat > "$INSTALL_MARKER" <<EOF_MARKER
INSTALL_COMPLETE=1
VERSION=$(/opt/xpanel-mvp/.venv/bin/python -m xpanel --version | awk '{print $2}')
PANEL_ACCESS_MODE=http
PANEL_PUBLIC_HOST=$HOST
PANEL_PUBLIC_PORT=$PUBLIC_PORT
PANEL_DOMAIN=
COMPLETED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_MARKER
chmod 600 "$INSTALL_MARKER"

bash /opt/xpanel-mvp/deploy/install-service.sh
systemctl restart xpanel-web

log "Проверяю backend"
for _ in {1..30}; do
  curl -fsS --max-time 3 "http://127.0.0.1:$BACKEND_PORT/login" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS --max-time 5 -H "Host: $HOST" "http://127.0.0.1:$PUBLIC_PORT/login" >/dev/null
PLACEHOLDER_CHECK="$BACKUP_DIR/placeholder-check.html"
if curl -fsS --max-time 5 -H "Host: $HOST" \
  --output "$PLACEHOLDER_CHECK" \
  "http://127.0.0.1/" && \
  grep -Fq "SG Digital Systems" "$PLACEHOLDER_CHECK"; then
  log "Локальная HTTP-заглушка доступна"
else
  log "Предупреждение: порт 80 обслуживается другим Nginx-блоком; установка панели продолжена"
fi

COMMITTED=1
trap - ERR INT TERM
rm -rf "$BACKUP_DIR"
log "HTTP настроен: http://$HOST:$PUBLIC_PORT"
log "Страница-заглушка: http://$HOST"
log "Backend: 127.0.0.1:$BACKEND_PORT"
