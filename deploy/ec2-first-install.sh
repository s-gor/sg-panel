#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.10.0-rc9"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_VERSION="v26.3.27"
DEFAULT_HTTPS_PORT="61443"
DEFAULT_BACKEND_PORT="8080"
DEFAULT_REALITY_DEST="www.bing.com:443"
DEFAULT_REALITY_SNI="www.bing.com"
DEFAULT_USER="sg-admin"
ACME_ROOT="/var/www/letsencrypt"
TARGET="/opt/xpanel-mvp"
SERVICE="xpanel-web"
INSTALL_STATE_DIR="/etc/xpanel-mvp"
INSTALL_MARKER="$INSTALL_STATE_DIR/install-complete.env"
RECONFIGURE=0
PARTIAL_INSTALL=0

log(){ printf '[SG-Panel EC2] %s\n' "$*"; }
fail(){ printf '[SG-Panel EC2] ERROR: %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'USAGE'
Использование:
  ec2-first-install.sh [--reconfigure]

Без параметров:
  - завершённая установка обновляется без изменения настроек;
  - незавершённая установка автоматически возвращается к мастеру.

--reconfigure
  Повторно запустить мастер для изменения домена, HTTPS-порта,
  Reality target и Reality SNI. Существующие пароль, ключи и пользователи сохраняются.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reconfigure) RECONFIGURE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "неизвестный параметр: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
cd /
[[ -f "$SOURCE_DIR/xpanel/__init__.py" ]] || fail "не найден каталог проекта"
grep -q "__version__ = \"$EXPECTED_VERSION\"" "$SOURCE_DIR/xpanel/__init__.py" || fail "исходники не версии $EXPECTED_VERSION"

core_panel_files_exist(){
  [[ -d "$TARGET/xpanel" ]] &&
  [[ -x "$TARGET/.venv/bin/python" ]] &&
  [[ -f /etc/xpanel-mvp/web.env ]] &&
  [[ -f /etc/systemd/system/xpanel-web.service ]]
}

configured_https_is_usable(){
  local conf="/etc/nginx/sites-available/sg-panel" cert key
  [[ -s "$conf" ]] || return 1
  cert="$(awk '$1 == "ssl_certificate" {gsub(/;/, "", $2); print $2; exit}' "$conf" 2>/dev/null || true)"
  key="$(awk '$1 == "ssl_certificate_key" {gsub(/;/, "", $2); print $2; exit}' "$conf" 2>/dev/null || true)"
  [[ -n "$cert" && -n "$key" && -s "$cert" && -s "$key" ]] || return 1
  openssl x509 -checkend 60 -noout -in "$cert" >/dev/null 2>&1
}

existing_install_is_complete(){
  core_panel_files_exist &&
  [[ -s /usr/local/etc/xray/config.json ]] &&
  configured_https_is_usable
}

partial_install_artifacts_exist(){
  [[ -e "$TARGET" || -e /etc/xpanel-mvp/web.env ||
     -e /etc/systemd/system/xpanel-web.service ||
     -e /usr/local/etc/xray/config.json ||
     -e /etc/nginx/sites-available/sg-panel-acme ||
     -e /etc/nginx/sites-available/sg-panel ]]
}

write_install_marker(){
  local domain="$1" port="$2"
  mkdir -p "$INSTALL_STATE_DIR"
  cat > "$INSTALL_MARKER" <<EOF_MARKER
INSTALL_COMPLETE=1
VERSION=$EXPECTED_VERSION
PANEL_DOMAIN=$domain
PANEL_HTTPS_PORT=$port
COMPLETED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_MARKER
  chmod 600 "$INSTALL_MARKER"
}

if existing_install_is_complete && [[ $RECONFIGURE -eq 0 ]]; then
  CURRENT_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version 2>/dev/null | awk '{print $2}' || true)"
  CURRENT_VERSION="${CURRENT_VERSION:-неизвестна}"
  log "Обнаружена завершённая SG-Panel $CURRENT_VERSION"
  log "Перехожу в режим обновления без изменения домена, сертификата, пароля и настроек Xray"
  bash "$SOURCE_DIR/install-or-upgrade.sh"
  NEW_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version | awk '{print $2}')"
  [[ "$NEW_VERSION" == "$EXPECTED_VERSION" ]] || fail "после обновления установлена версия $NEW_VERSION"
  systemctl is-active --quiet "$SERVICE" || fail "служба $SERVICE не active после обновления"
  if [[ ! -f "$INSTALL_MARKER" ]]; then
    LEGACY_DOMAIN="$(awk '$1 == "server_name" {gsub(/;/, "", $2); if ($2 != "_") {print $2; exit}}' /etc/nginx/sites-available/sg-panel 2>/dev/null || true)"
    LEGACY_PORT="$(awk '$1 == "listen" && $2 ~ /^[0-9]+$/ {print $2; exit}' /etc/nginx/sites-available/sg-panel 2>/dev/null || true)"
    [[ -n "$LEGACY_DOMAIN" && -n "$LEGACY_PORT" ]] && write_install_marker "$LEGACY_DOMAIN" "$LEGACY_PORT"
  fi
  log "Обновление завершено: SG-Panel $NEW_VERSION"
  exit 0
fi

if partial_install_artifacts_exist; then
  PARTIAL_INSTALL=1
  if [[ $RECONFIGURE -eq 1 ]]; then
    log "Запущено изменение существующей установки"
  else
    log "Обнаружена незавершённая установка"
    log "Повторно запускаю мастер. Домен и параметры подключения можно ввести заново"
  fi
  rm -f "$INSTALL_MARKER"
elif [[ $RECONFIGURE -eq 1 ]]; then
  log "Завершённая установка не найдена; запускаю обычный мастер"
fi

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

DB_PATH="$TARGET/data/panel.db"
existing_db_value(){
  local sql="$1"
  [[ -f "$DB_PATH" ]] && command -v sqlite3 >/dev/null 2>&1 || return 0
  sqlite3 -noheader "$DB_PATH" "$sql" 2>/dev/null | head -n 1 || true
}

CURRENT_XRAY_ADDRESS="$(existing_db_value 'SELECT address FROM server_settings WHERE id = 1;')"
CURRENT_REALITY_DEST="$(existing_db_value 'SELECT dest FROM server_settings WHERE id = 1;')"
CURRENT_REALITY_SNI="$(existing_db_value 'SELECT server_name FROM server_settings WHERE id = 1;')"
CURRENT_FIRST_USER="$(existing_db_value 'SELECT name FROM users ORDER BY id LIMIT 1;')"
CURRENT_BASE_URL="$(existing_db_value 'SELECT base_url FROM subscription_settings WHERE id = 1;')"
CURRENT_PANEL_DOMAIN=""
CURRENT_PANEL_PORT=""

if [[ -f "$INSTALL_MARKER" ]]; then
  CURRENT_PANEL_DOMAIN="$(grep -E '^PANEL_DOMAIN=' "$INSTALL_MARKER" | tail -1 | cut -d= -f2- || true)"
  CURRENT_PANEL_PORT="$(grep -E '^PANEL_HTTPS_PORT=' "$INSTALL_MARKER" | tail -1 | cut -d= -f2- || true)"
fi

if [[ -z "$CURRENT_PANEL_DOMAIN" ]]; then
  for conf in /etc/nginx/sites-available/sg-panel /etc/nginx/sites-available/sg-panel-acme; do
    [[ -f "$conf" ]] || continue
    CURRENT_PANEL_DOMAIN="$(awk '$1 == "server_name" {gsub(/;/, "", $2); if ($2 != "_") {print $2; exit}}' "$conf" 2>/dev/null || true)"
    [[ -n "$CURRENT_PANEL_DOMAIN" ]] && break
  done
fi

if [[ "$CURRENT_BASE_URL" =~ ^https://([^/:]+):([0-9]+) ]]; then
  [[ -n "$CURRENT_PANEL_DOMAIN" ]] || CURRENT_PANEL_DOMAIN="${BASH_REMATCH[1]}"
  [[ -n "$CURRENT_PANEL_PORT" ]] || CURRENT_PANEL_PORT="${BASH_REMATCH[2]}"
fi

XRAY_ADDRESS_DEFAULT="${CURRENT_XRAY_ADDRESS:-}"
PANEL_DOMAIN_DEFAULT="${CURRENT_PANEL_DOMAIN:-${CURRENT_XRAY_ADDRESS:-}}"
PANEL_HTTPS_PORT_DEFAULT="${CURRENT_PANEL_PORT:-$DEFAULT_HTTPS_PORT}"
FIRST_USER_DEFAULT="${CURRENT_FIRST_USER:-$DEFAULT_USER}"
REALITY_DEST_DEFAULT="${CURRENT_REALITY_DEST:-$DEFAULT_REALITY_DEST}"
REALITY_SNI_DEFAULT="${CURRENT_REALITY_SNI:-$DEFAULT_REALITY_SNI}"

printf '%s\n' \
  "Для вопросов со значением в квадратных скобках уже задан рекомендуемый вариант." \
  "Чтобы принять значение по умолчанию, просто нажмите Enter." \
  ""

printf '%s\n' \
  "Введите доменное имя Xray-сервера." \
  "A-запись домена должна указывать на публичный IPv4 этого EC2." \
  "Пример: vpn.example.dynu.net"
prompt_value XRAY_ADDRESS "Домен Xray-сервера" "$XRAY_ADDRESS_DEFAULT"

printf '%s\n' \
  "Введите доменное имя HTTPS-панели." \
  "Можно использовать тот же домен, поскольку Xray и панель работают на разных портах."
PANEL_PROMPT_DEFAULT="${PANEL_DOMAIN_DEFAULT:-$XRAY_ADDRESS}"
if [[ $PARTIAL_INSTALL -eq 1 || $RECONFIGURE -eq 1 ]]; then
  if [[ -z "$CURRENT_PANEL_DOMAIN" || "$CURRENT_PANEL_DOMAIN" == "$CURRENT_XRAY_ADDRESS" ]]; then
    PANEL_PROMPT_DEFAULT="$XRAY_ADDRESS"
  fi
fi
prompt_value PANEL_DOMAIN "Домен HTTPS-панели" "$PANEL_PROMPT_DEFAULT"
prompt_value PANEL_HTTPS_PORT "Внешний HTTPS-порт панели" "$PANEL_HTTPS_PORT_DEFAULT"
prompt_value FIRST_USER "Имя первого пользователя" "$FIRST_USER_DEFAULT"
prompt_value REALITY_DEST "Reality target" "$REALITY_DEST_DEFAULT"
prompt_value REALITY_SNI "Reality SNI" "$REALITY_SNI_DEFAULT"

if [[ -f /etc/xpanel-mvp/web.env ]]; then
  log "Существующий пароль администратора будет сохранён"
elif [[ -z "${XPANEL_ADMIN_PASSWORD:-}" ]]; then
  while true; do
    prompt_value XPANEL_ADMIN_PASSWORD "Пароль администратора панели (не менее 8 символов): " "" 1
    prompt_value XPANEL_ADMIN_PASSWORD_2 "Повторите пароль: " "" 1

    if (( ${#XPANEL_ADMIN_PASSWORD} < 8 )); then
      echo "Ошибка: пароль должен содержать не менее 8 символов." >&2
    elif [[ "$XPANEL_ADMIN_PASSWORD" != "$XPANEL_ADMIN_PASSWORD_2" ]]; then
      echo "Ошибка: пароли не совпадают. Повторите ввод." >&2
    else
      break
    fi

    unset XPANEL_ADMIN_PASSWORD XPANEL_ADMIN_PASSWORD_2
  done
else
  [[ ${#XPANEL_ADMIN_PASSWORD} -ge 8 ]] || fail "пароль должен содержать не менее 8 символов"
fi
[[ "$XRAY_ADDRESS" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || fail "некорректный домен Xray"
[[ "$PANEL_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || fail "некорректный домен панели"
[[ "$PANEL_HTTPS_PORT" =~ ^[0-9]+$ ]] && (( PANEL_HTTPS_PORT >= 49152 && PANEL_HTTPS_PORT <= 65535 )) || fail "для EC2 выберите private/dynamic порт 49152-65535"
[[ -n "$FIRST_USER" ]] || fail "имя пользователя не может быть пустым"
[[ "$REALITY_DEST" == *:* ]] || fail "Reality target должен иметь вид host:port"

for reserved in 22 80 443 "$DEFAULT_BACKEND_PORT"; do
  [[ "$PANEL_HTTPS_PORT" != "$reserved" ]] || fail "порт $PANEL_HTTPS_PORT нельзя использовать для панели"
done

ensure_swap(){
  local mem_kib
  mem_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
  if (( mem_kib < 1572864 )) && ! swapon --show=NAME --noheadings | grep -qx '/swapfile'; then
    log "Мало оперативной памяти: подготавливаю swap 2 ГиБ"
    if [[ ! -f /swapfile ]]; then
      fallocate -l 2G /swapfile
    fi
    chmod 600 /swapfile
    if ! blkid /swapfile 2>/dev/null | grep -q 'TYPE="swap"'; then
      mkswap /swapfile >/dev/null
    fi
    swapon /swapfile
    grep -q '^/swapfile[[:space:]]' /etc/fstab || \
      echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
}

ensure_swap

log "Устанавливаю системные пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  curl ca-certificates unzip rsync zstd \
  python3 python3-venv python3-pip \
  sqlite3 jq iproute2 dnsutils \
  nginx certbot openssl

port_is_used_by_current_nginx(){
  command -v nginx >/dev/null 2>&1 || return 1
  nginx -T 2>/dev/null | grep -Eq "listen[[:space:]]+${PANEL_HTTPS_PORT}([[:space:]]|;)"
}

if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)$PANEL_HTTPS_PORT$"; then
  port_is_used_by_current_nginx || fail "порт $PANEL_HTTPS_PORT уже занят другим процессом"
  log "Порт $PANEL_HTTPS_PORT уже используется текущей конфигурацией Nginx и будет перенастроен"
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
if [[ -n "${XPANEL_ADMIN_PASSWORD:-}" ]]; then
  export XPANEL_ADMIN_PASSWORD
fi
bash "$SOURCE_DIR/install-or-upgrade.sh"
unset XPANEL_ADMIN_PASSWORD XPANEL_ADMIN_PASSWORD_2 2>/dev/null || true

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
elif [[ $PARTIAL_INSTALL -eq 1 || $RECONFIGURE -eq 1 ]]; then
  log "Обновляю домен и Reality-параметры существующего Xray-сервера"
  python3 - data/panel.db "$XRAY_ADDRESS" "$REALITY_DEST" "$REALITY_SNI" <<'PY_UPDATE_SERVER'
import sqlite3
import sys

path, address, dest, server_name = sys.argv[1:]
with sqlite3.connect(path) as con:
    con.execute(
        """
        UPDATE server_settings
           SET address = ?, dest = ?, server_name = ?
         WHERE id = 1
        """,
        (address, dest, server_name),
    )
PY_UPDATE_SERVER
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
rm -f   /etc/nginx/sites-enabled/default   /etc/nginx/sites-enabled/sg-panel   /etc/nginx/sites-enabled/sg-panel-acme
ln -sfn /etc/nginx/sites-available/sg-panel-acme /etc/nginx/sites-enabled/sg-panel-acme
nginx -t
systemctl enable --now nginx
systemctl reload nginx

CERT_DIR="/etc/letsencrypt/live/$PANEL_DOMAIN"
CERT_FILE="$CERT_DIR/fullchain.pem"
KEY_FILE="$CERT_DIR/privkey.pem"

certificate_is_usable(){
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] || return 1
  openssl x509 -checkend 604800 -noout -in "$CERT_FILE" >/dev/null 2>&1
}

print_certbot_error(){
  local output="$1" retry_line=""

  printf '%s\n' "$output" >&2
  echo >&2

  if grep -Eqi 'too many certificates|rate limit|rateLimited' <<<"$output"; then
    retry_line="$(grep -Eio 'retry after[^[:cntrl:]]*' <<<"$output" | head -n 1 || true)"
    echo "ПРИЧИНА: Let's Encrypt временно запретил выпуск нового сертификата из-за лимита." >&2
    [[ -z "$retry_line" ]] || echo "Срок следующей попытки: $retry_line" >&2
    echo "Удаление старого сертификата не снимает этот лимит." >&2
    echo "Повторите установку после указанного срока." >&2
  elif grep -Eqi 'timeout during connect|connection refused|likely firewall problem' <<<"$output"; then
    echo "ПРИЧИНА: сервер Let's Encrypt не смог подключиться к TCP-порту 80." >&2
    echo "Проверьте правило HTTP 80/tcp = 0.0.0.0/0 в AWS Security Group." >&2
    echo "Также проверьте, что домен указывает на публичный IPv4 этого EC2." >&2
  elif grep -Eqi 'unauthorized|invalid response|challenge failed|failed to authenticate' <<<"$output"; then
    echo "ПРИЧИНА: Let's Encrypt не подтвердил управление доменом." >&2
    echo "Проверьте A-запись DNS, порт 80 и доступность /.well-known/acme-challenge/." >&2
  elif grep -Eqi 'dns problem|nxdomain|no valid ip addresses found' <<<"$output"; then
    echo "ПРИЧИНА: доменное имя не разрешается в публичный IPv4." >&2
    echo "Создайте или исправьте A-запись и дождитесь обновления DNS." >&2
  else
    echo "ПРИЧИНА: Certbot не смог получить сертификат Let's Encrypt." >&2
    echo "Полный ответ Certbot показан выше." >&2
  fi
}

if certificate_is_usable; then
  CERT_EXPIRES="$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2-)"
  log "Использую существующий сертификат Let's Encrypt"
  log "Сертификат действует до: $CERT_EXPIRES"
else
  log "Получаю сертификат Let's Encrypt для $PANEL_DOMAIN"

  if ! CERTBOT_OUTPUT="$(certbot certonly \
      --webroot -w "$ACME_ROOT" \
      --domain "$PANEL_DOMAIN" \
      --register-unsafely-without-email \
      --agree-tos \
      --non-interactive \
      --keep-until-expiring 2>&1)"; then
    print_certbot_error "$CERTBOT_OUTPUT"
    fail "установка остановлена: сертификат Let's Encrypt не получен"
  fi

  printf '%s\n' "$CERTBOT_OUTPUT"
fi

log "Настраиваю HTTPS панели на порту $PANEL_HTTPS_PORT"
rm -f /etc/nginx/sites-enabled/sg-panel-acme
bash /opt/xpanel-mvp/deploy/configure-https.sh \
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

wait_for_gui(){
  local attempt body
  log "Ожидаю готовность HTTPS GUI"
  for ((attempt=1; attempt<=30; attempt++)); do
    if body="$(curl -kfsS --max-time 5 \
      --resolve "$PANEL_DOMAIN:$PANEL_HTTPS_PORT:127.0.0.1" \
      "https://$PANEL_DOMAIN:$PANEL_HTTPS_PORT/login" 2>/dev/null)" && \
      grep -q "v$EXPECTED_VERSION" <<<"$body"; then
      return 0
    fi
    sleep 1
  done

  systemctl --no-pager --full status xpanel-web >&2 || true
  journalctl -u xpanel-web -n 50 --no-pager >&2 || true
  tail -n 50 /var/log/nginx/error.log >&2 2>/dev/null || true
  return 1
}

wait_for_gui || fail "HTTPS GUI не прошёл проверку за 30 секунд"
write_install_marker "$PANEL_DOMAIN" "$PANEL_HTTPS_PORT"

LINK="$(.venv/bin/python -m xpanel show-link "$FIRST_USER" 2>/dev/null || true)"
LINK_FILE="/root/sg-panel-first-user.txt"
if [[ -n "$LINK" ]]; then
  printf '%s\n' "$LINK" > "$LINK_FILE"
  chmod 600 "$LINK_FILE"
fi

SSH_IP="${SSH_CONNECTION:-}"
SSH_IP="${SSH_IP%% *}"
SSH_SOURCE="${SSH_IP:+$SSH_IP/32}"
SSH_SOURCE="${SSH_SOURCE:-ваш публичный IP/32}"

cat <<EOF_RESULT

============================================================
 SG-Panel $EXPECTED_VERSION — установка завершена успешно
============================================================

ПАНЕЛЬ УПРАВЛЕНИЯ
  Адрес:           https://$PANEL_DOMAIN:$PANEL_HTTPS_PORT
  Вход:            пароль администратора, заданный при установке

XRAY REALITY
  Сервер:          $XRAY_ADDRESS:443
  Пользователь:    $FIRST_USER
  VLESS-ссылка:    $LINK_FILE
  Показать ссылку: cat $LINK_FILE

ПРОВЕРКИ
  SG-Panel:        active — 127.0.0.1:$DEFAULT_BACKEND_PORT
  Nginx:           active — HTTPS :$PANEL_HTTPS_PORT
  Xray:            active — Reality :443
  HTTPS GUI:       OK
  Публичный IPv4:  $PUBLIC_IP

AWS SECURITY GROUP
  22/tcp           $SSH_SOURCE
  80/tcp           0.0.0.0/0       Let's Encrypt
  443/tcp          0.0.0.0/0       Xray Reality
  $PANEL_HTTPS_PORT/tcp       $SSH_SOURCE
  $DEFAULT_BACKEND_PORT/tcp         НЕ ОТКРЫВАТЬ

DNS
  $PANEL_DOMAIN -> $PUBLIC_IP

Откройте панель в браузере и войдите с заданным паролем.
============================================================
EOF_RESULT
