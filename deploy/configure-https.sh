#!/usr/bin/env bash
set -Eeuo pipefail

DOMAIN=""
CERT=""
KEY=""
HTTPS_PORT="61443"
MODE="full"
ENV_FILE="/etc/xpanel-mvp/web.env"
NGINX_CONF="/etc/nginx/sites-available/sg-panel"
ACME_ROOT="/var/www/letsencrypt"

usage(){
  cat <<'USAGE'
Использование:
  configure-https.sh --domain panel.example.com \
    --cert /etc/letsencrypt/live/panel.example.com/fullchain.pem \
    --key /etc/letsencrypt/live/panel.example.com/privkey.pem \
    [--port 61443] [--mode full|subscriptions-only]

Порт 443 остаётся у Xray Reality. Для панели по умолчанию используется
private/dynamic порт 61443. Скрипт резервирует выбранный порт в Linux,
переводит backend на 127.0.0.1 и настраивает Nginx.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --cert) CERT="${2:-}"; shift 2 ;;
    --key) KEY="${2:-}"; shift 2 ;;
    --port) HTTPS_PORT="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ошибка: запустите от root" >&2; exit 1; }
[[ -n "$DOMAIN" && -n "$CERT" && -n "$KEY" ]] || { usage; exit 1; }
[[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || {
  echo "Некорректное доменное имя: $DOMAIN" >&2; exit 1;
}
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && (( HTTPS_PORT >= 1024 && HTTPS_PORT <= 65535 )) || {
  echo "Некорректный порт: используйте 1024-65535" >&2; exit 1;
}
[[ "$MODE" == "full" || "$MODE" == "subscriptions-only" ]] || {
  echo "Mode: full или subscriptions-only" >&2; exit 1;
}
[[ -f "$CERT" ]] || { echo "Не найден сертификат: $CERT" >&2; exit 1; }
[[ -f "$KEY" ]] || { echo "Не найден ключ: $KEY" >&2; exit 1; }
command -v nginx >/dev/null || { echo "Сначала установите nginx" >&2; exit 1; }

case "$HTTPS_PORT" in
  22|80|443|8080) echo "Порт $HTTPS_PORT зарезервирован для другого назначения" >&2; exit 1 ;;
esac

# Не считаем текущий nginx конфликтом при повторном запуске.
if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)$HTTPS_PORT$"; then
  if ! nginx -T 2>/dev/null | grep -Eq "listen[[:space:]]+${HTTPS_PORT}([[:space:]]|;)"; then
    echo "Порт $HTTPS_PORT уже занят другим процессом" >&2
    exit 1
  fi
fi

reserve_port(){
  python3 - "$HTTPS_PORT" <<'PY'
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
parts = [x.strip() for x in current.split(",") if x.strip()]
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
value = ",".join(parts)
path = Path("/etc/sysctl.d/99-sg-panel-port.conf")
path.write_text(f"net.ipv4.ip_local_reserved_ports={value}\n", encoding="utf-8")
print(value)
PY
  sysctl --system >/dev/null
}

reserve_port

BACKEND_PORT="$(grep -E '^XPANEL_PORT=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
BACKEND_PORT="${BACKEND_PORT:-8080}"

mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled "$ACME_ROOT/.well-known/acme-challenge"

if [[ "$MODE" == "full" ]]; then
  LOCATION_BLOCK=$(cat <<EOF_LOCATION
    location / {
        proxy_pass http://127.0.0.1:${BACKEND_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
EOF_LOCATION
)
else
  LOCATION_BLOCK=$(cat <<EOF_LOCATION
    location ^~ /sub/ {
        proxy_pass http://127.0.0.1:${BACKEND_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }

    location / {
        return 404;
    }
EOF_LOCATION
)
fi

cat > "$NGINX_CONF" <<EOF_NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location ^~ /.well-known/acme-challenge/ {
        root $ACME_ROOT;
        default_type text/plain;
    }

    location / {
        return 301 https://\$host:$HTTPS_PORT\$request_uri;
    }
}

server {
    listen $HTTPS_PORT ssl;
    listen [::]:$HTTPS_PORT ssl;
    server_name $DOMAIN;

    ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SERGPANEL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;

$LOCATION_BLOCK
}
EOF_NGINX

rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-enabled/sg-panel-acme
ln -sfn "$NGINX_CONF" /etc/nginx/sites-enabled/sg-panel
nginx -t
systemctl enable --now nginx
systemctl reload nginx

python3 - "$ENV_FILE" "$MODE" "$BACKEND_PORT" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); mode=sys.argv[2]; backend_port=sys.argv[3]
values={
    'XPANEL_BIND_ADDRESS':'127.0.0.1',
    'XPANEL_PORT':backend_port,
    'XPANEL_TRUST_PROXY_HEADERS':'1',
    'XPANEL_SECURE_COOKIES':'1' if mode == 'full' else '0',
}
lines=path.read_text(encoding='utf-8').splitlines() if path.exists() else []
out=[]; pending=dict(values)
for line in lines:
    key=line.split('=',1)[0] if '=' in line else ''
    if key in pending:
        out.append(f'{key}={pending.pop(key)}')
    else:
        out.append(line)
out += [f'{k}={v}' for k,v in pending.items()]
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text('\n'.join(out)+'\n', encoding='utf-8')
path.chmod(0o600)
PY

cd /opt/xpanel-mvp
.venv/bin/python - <<'PYSEC'
from xpanel.db import connect, init_db
init_db()
with connect() as con:
    con.execute("UPDATE security_settings SET trust_proxy_headers = 1, updated_at = CURRENT_TIMESTAMP WHERE id = 1")
PYSEC

/opt/xpanel-mvp/deploy/install-service.sh
systemctl restart xpanel-web

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-sg-panel-nginx.sh <<'EOF_HOOK'
#!/usr/bin/env bash
systemctl reload nginx
EOF_HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/reload-sg-panel-nginx.sh

echo "HTTPS настроен: https://$DOMAIN:$HTTPS_PORT"
echo "Backend: 127.0.0.1:$BACKEND_PORT"
echo "Режим: $MODE"
echo "Порт $HTTPS_PORT зарезервирован в net.ipv4.ip_local_reserved_ports"
