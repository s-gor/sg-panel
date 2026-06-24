#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.9.3"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_VERSION="v26.3.27"
DEFAULT_HTTPS_PORT="61443"
DEFAULT_BACKEND_PORT="8080"
DEFAULT_REALITY_DEST="www.microsoft.com:443"
DEFAULT_REALITY_SNI="www.microsoft.com"
DEFAULT_USER="Sergey"
ACME_ROOT="/var/www/letsencrypt"

log(){ printf '[SG-Panel EC2] %s\n' "$*"; }
fail(){ printf '[SG-Panel EC2] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
[[ -f "$SOURCE_DIR/xpanel/__init__.py" ]] || fail "не найден каталог проекта"
grep -q "__version__ = \"$EXPECTED_VERSION\"" "$SOURCE_DIR/xpanel/__init__.py" || fail "исходники не версии $EXPECTED_VERSION"

prompt_value(){
  local var_name="$1" prompt="$2" default="${3:-}" secret="${4:-0}" value=""
  value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    if [[ "$secret" == "1" ]]; then
      read -r -s -p "$prompt" value; echo
    elif [[ -n "$default" ]]; then
      read -r -p "$prompt [$default]: " value
      value="${value:-$default}"
    else
      read -r -p "$prompt: " value
    fi
  fi
  printf -v "$var_name" '%s' "$value"
}

prompt_value XRAY_ADDRESS "Домен подключения Xray в Dynu"
prompt_value PANEL_DOMAIN "Домен HTTPS-панели" "$XRAY_ADDRESS"
prompt_value LETSENCRYPT_EMAIL "Email для Let's Encrypt"
prompt_value PANEL_HTTPS_PORT "Внешний HTTPS-порт панели" "$DEFAULT_HTTPS_PORT"
prompt_value FIRST_USER "Имя первого пользователя" "$DEFAULT_USER"
prompt_value REALITY_DEST "Reality target" "$DEFAULT_REALITY_DEST"
prompt_value REALITY_SNI "Reality SNI" "$DEFAULT_REALITY_SNI"

if [[ -z "${XPANEL_ADMIN_PASSWORD:-}" ]]; then
  prompt_value XPANEL_ADMIN_PASSWORD "Пароль администратора панели: " "" 1
  prompt_value XPANEL_ADMIN_PASSWORD_2 "Повторите пароль: " "" 1
  [[ "$XPANEL_ADMIN_PASSWORD" == "$XPANEL_ADMIN_PASSWORD_2" ]] || fail "пароли не совпадают"
fi

[[ ${#XPANEL_ADMIN_PASSWORD} -ge 8 ]] || fail "пароль должен содержать не менее 8 символов"
[[ "$XRAY_ADDRESS" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || fail "некорректный домен Xray"
[[ "$PANEL_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || fail "некорректный домен панели"
[[ "$LETSENCRYPT_EMAIL" == *@*.* ]] || fail "некорректный email"
[[ "$PANEL_HTTPS_PORT" =~ ^[0-9]+$ ]] && (( PANEL_HTTPS_PORT >= 49152 && PANEL_HTTPS_PORT <= 65535 )) || fail "для EC2 выберите private/dynamic порт 49152-65535"
[[ -n "$FIRST_USER" ]] || fail "имя пользователя не может быть пустым"
[[ "$REALITY_DEST" == *:* ]] || fail "Reality target должен иметь вид host:port"

for reserved in 22 80 443 "$DEFAULT_BACKEND_PORT"; do
  [[ "$PANEL_HTTPS_PORT" != "$reserved" ]] || fail "порт $PANEL_HTTPS_PORT нельзя использовать для панели"
done

log "Устанавливаю системные пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  curl ca-certificates unzip rsync \
  python3 python3-venv python3-pip \
  sqlite3 jq iproute2 dnsutils \
  nginx certbot

if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)$PANEL_HTTPS_PORT$"; then
  fail "порт $PANEL_HTTPS_PORT уже занят"
fi

PUBLIC_IP="$(curl -4fsS --max-time 15 https://checkip.amazonaws.com | tr -d '[:space:]')" || fail "не удалось определить публичный IPv4"
[[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "получен некорректный публичный IP: $PUBLIC_IP"

check_dns(){
  local domain="$1" resolved
  resolved="$(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u || true)"
  grep -Fxq "$PUBLIC_IP" <<<"$resolved" || {
    echo "Домен: $domain" >&2
    echo "Публичный IP EC2: $PUBLIC_IP" >&2
    echo "Сейчас DNS возвращает:" >&2
    printf '%s\n' "${resolved:-ничего}" >&2
    fail "создайте/обновите A-запись в Dynu и повторите установку после обновления DNS"
  }
}

log "Проверяю Dynu DNS"
check_dns "$XRAY_ADDRESS"
check_dns "$PANEL_DOMAIN"

CURRENT_XRAY_VERSION=""
if [[ -x /usr/local/bin/xray ]]; then
  CURRENT_XRAY_VERSION="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"
fi
if [[ "$CURRENT_XRAY_VERSION" != "$XRAY_VERSION" ]]; then
  log "Устанавливаю Xray $XRAY_VERSION"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "$XRAY_VERSION"
else
  log "Xray уже установлен: $CURRENT_XRAY_VERSION"
fi
systemctl enable xray >/dev/null

log "Устанавливаю SG-Panel с backend только на localhost"
export XPANEL_BIND_ADDRESS="127.0.0.1"
export XPANEL_PORT="$DEFAULT_BACKEND_PORT"
export XPANEL_SECURE_COOKIES="0"
export XPANEL_TRUST_PROXY_HEADERS="0"
export XPANEL_ADMIN_PASSWORD
bash "$SOURCE_DIR/install-or-upgrade.sh"
unset XPANEL_ADMIN_PASSWORD

cd /opt/xpanel-mvp

SERVER_COUNT="$(sqlite3 data/panel.db 'SELECT COUNT(*) FROM server_settings;' 2>/dev/null || echo 0)"
if [[ "$SERVER_COUNT" == "0" ]]; then
  log "Создаю Reality-ключи и серверные настройки"
  TMP_ENV="$(mktemp /root/sg-panel-reality.XXXXXX)"
  chmod 600 "$TMP_ENV"
  .venv/bin/python -m xpanel gen-keys --save "$TMP_ENV" >/dev/null
  # shellcheck disable=SC1090
  set -a; . "$TMP_ENV"; set +a
  .venv/bin/python -m xpanel set-server \
    --address "$XRAY_ADDRESS" \
    --listen 0.0.0.0 \
    --port 443 \
    --dest "$REALITY_DEST" \
    --server-name "$REALITY_SNI" \
    --private-key "$PRIVATE_KEY" \
    --public-key "$PUBLIC_KEY" \
    --short-id "$SHORT_ID" \
    --fingerprint chrome
  rm -f "$TMP_ENV"
  unset PRIVATE_KEY PUBLIC_KEY SHORT_ID
else
  log "Существующие Reality-настройки сохранены"
fi

USER_COUNT="$(sqlite3 data/panel.db 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo 0)"
if [[ "$USER_COUNT" == "0" ]]; then
  log "Создаю первого пользователя: $FIRST_USER"
  .venv/bin/python -m xpanel add-user "$FIRST_USER"
else
  log "Существующие пользователи сохранены"
fi

log "Проверяю и применяю Xray config.json"
.venv/bin/python -m xpanel apply

log "Готовлю Nginx на порту 80 для ACME HTTP-01"
mkdir -p "$ACME_ROOT/.well-known/acme-challenge" /etc/nginx/sites-available /etc/nginx/sites-enabled
cat > /etc/nginx/sites-available/sg-panel-acme <<EOF_ACME
server {
    listen 80;
    listen [::]:80;
    server_name $PANEL_DOMAIN;

    location ^~ /.well-known/acme-challenge/ {
        root $ACME_ROOT;
        default_type text/plain;
    }

    location / {
        return 404;
    }
}
EOF_ACME
rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/sg-panel-acme /etc/nginx/sites-enabled/sg-panel-acme
nginx -t
systemctl enable --now nginx
systemctl reload nginx

log "Получаю сертификат Let's Encrypt"
certbot certonly \
  --webroot -w "$ACME_ROOT" \
  --domain "$PANEL_DOMAIN" \
  --email "$LETSENCRYPT_EMAIL" \
  --agree-tos --non-interactive --keep-until-expiring

log "Настраиваю HTTPS панели на порту $PANEL_HTTPS_PORT"
rm -f /etc/nginx/sites-enabled/sg-panel-acme
/opt/xpanel-mvp/deploy/configure-https.sh \
  --domain "$PANEL_DOMAIN" \
  --cert "/etc/letsencrypt/live/$PANEL_DOMAIN/fullchain.pem" \
  --key "/etc/letsencrypt/live/$PANEL_DOMAIN/privkey.pem" \
  --port "$PANEL_HTTPS_PORT" \
  --mode full

python3 - /opt/xpanel-mvp/data/panel.db "$PANEL_DOMAIN" "$PANEL_HTTPS_PORT" <<'PY'
import sqlite3, sys
path, domain, port = sys.argv[1:]
url = f"https://{domain}:{port}"
with sqlite3.connect(path) as con:
    con.execute(
        "UPDATE subscription_settings SET base_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        (url,),
    )
PY

log "Финальная проверка"
cd /opt/xpanel-mvp
CLI_VERSION="$(.venv/bin/python -m xpanel --version | awk '{print $2}')"
[[ "$CLI_VERSION" == "$EXPECTED_VERSION" ]] || fail "неожиданная версия CLI: $CLI_VERSION"
systemctl is-active --quiet xpanel-web || fail "xpanel-web не active"
systemctl is-active --quiet xray || fail "xray не active"
systemctl is-active --quiet nginx || fail "nginx не active"
curl -kfsS "https://127.0.0.1:$PANEL_HTTPS_PORT/login" -H "Host: $PANEL_DOMAIN" | grep -q "v$EXPECTED_VERSION" || fail "HTTPS GUI не прошёл проверку"

LINK="$(.venv/bin/python -m xpanel show-link "$FIRST_USER" 2>/dev/null || true)"
SSH_IP="${SSH_CONNECTION%% *}"

cat <<EOF_RESULT

============================================================
SG-Panel $EXPECTED_VERSION установлен на EC2
============================================================
Панель:       https://$PANEL_DOMAIN:$PANEL_HTTPS_PORT
Xray:         $XRAY_ADDRESS:443
Backend GUI:  127.0.0.1:$DEFAULT_BACKEND_PORT
Публичный IP: $PUBLIC_IP

Откройте в AWS Security Group:
  TCP 22      только с вашего IP${SSH_IP:+ ($SSH_IP/32)}
  TCP 80      0.0.0.0/0 — Let's Encrypt HTTP-01 и renewal
  TCP 443     0.0.0.0/0 — Xray Reality
  TCP $PANEL_HTTPS_PORT только с вашего IP${SSH_IP:+ ($SSH_IP/32)}

НЕ открывайте TCP $DEFAULT_BACKEND_PORT в Security Group.

VLESS-ссылка первого пользователя:
$LINK
============================================================
EOF_RESULT
