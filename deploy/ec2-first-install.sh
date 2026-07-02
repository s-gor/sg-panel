#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.10.0-rc30"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_VERSION="v26.5.9"
DEFAULT_PANEL_PORT="61443"
DEFAULT_BACKEND_PORT="8080"
DEFAULT_REALITY_DEST="www.bing.com:443"
DEFAULT_REALITY_SNI="www.bing.com"
DEFAULT_USER="sg-admin"
TARGET="/opt/xpanel-mvp"
SERVICE="xpanel-web"
INSTALL_STATE_DIR="/etc/xpanel-mvp"
INSTALL_MARKER="$INSTALL_STATE_DIR/install-complete.env"
PANEL_STATE_FILE="$INSTALL_STATE_DIR/panel-access.env"
RECONFIGURE=0
PARTIAL_INSTALL=0
PRESERVE_PANEL_ACCESS=0

log(){ printf '[SG-Panel Install] %s\n' "$*"; }
fail(){ printf '[SG-Panel Install] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  COLOR_GREEN=$'\033[1;32m'
  COLOR_RED=$'\033[1;31m'
  COLOR_DIM=$'\033[2m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_GREEN=""; COLOR_RED=""; COLOR_DIM=""; COLOR_RESET=""
fi

run_stage(){
  local label="$1"; shift
  local output rc pid frame_index=0 started elapsed
  local frames='|/-\\'
  output="$(mktemp /tmp/sg-panel-stage.XXXXXX)"
  started=$SECONDS

  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    "$@" >"$output" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
      elapsed=$((SECONDS - started))
      printf '\r[SG-Panel] [%s%s%s] %s (%s сек)' \
        "$COLOR_GREEN" "${frames:frame_index%4:1}" "$COLOR_RESET" "$label" "$elapsed"
      frame_index=$((frame_index + 1))
      sleep 0.25
    done
    if wait "$pid"; then
      rc=0
      elapsed=$((SECONDS - started))
      printf '\r[SG-Panel] [%sOK%s] %s (%s сек)\033[K\n' \
        "$COLOR_GREEN" "$COLOR_RESET" "$label" "$elapsed"
    else
      rc=$?
      elapsed=$((SECONDS - started))
      printf '\r[SG-Panel] [%sОШИБКА%s] %s (%s сек)\033[K\n' \
        "$COLOR_RED" "$COLOR_RESET" "$label" "$elapsed" >&2
      cat "$output" >&2
      rm -f "$output"
      return "$rc"
    fi
  else
    printf '[SG-Panel] %s\n' "$label"
    if "$@" >"$output" 2>&1; then rc=0; else rc=$?; fi
    elapsed=$((SECONDS - started))
    if [[ $rc -eq 0 ]]; then
      printf '[SG-Panel] [OK] %s (%s сек)\n' "$label" "$elapsed"
    else
      printf '[SG-Panel] [ОШИБКА] %s (%s сек)\n' "$label" "$elapsed" >&2
      cat "$output" >&2
      rm -f "$output"
      return "$rc"
    fi
  fi
  rm -f "$output"
}

ensure_xray_version(){
  local current="" backup_dir="" installed="" config="/usr/local/etc/xray/config.json"
  if [[ -x /usr/local/bin/xray ]]; then
    current="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"
  fi
  if [[ "$current" == "$XRAY_VERSION" ]]; then
    systemctl enable xray >/dev/null 2>&1 || true
    return 0
  fi

  backup_dir="/root/sg-panel-backups/xray-core/$(date -u +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  if [[ -x /usr/local/bin/xray ]]; then
    cp -a /usr/local/bin/xray "$backup_dir/xray"
    printf '%s
' "$current" > "$backup_dir/version.txt"
  fi
  [[ -f "$config" ]] && cp -a "$config" "$backup_dir/config.json"

  rollback_xray(){
    if [[ -x "$backup_dir/xray" ]]; then
      install -m 0755 "$backup_dir/xray" /usr/local/bin/xray
      systemctl daemon-reload || true
      [[ -f "$config" ]] && systemctl restart xray || true
    fi
  }

  if ! bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "$XRAY_VERSION"; then
    rollback_xray
    return 1
  fi
  installed="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"
  if [[ "$installed" != "$XRAY_VERSION" ]]; then
    echo "ожидался Xray $XRAY_VERSION, установлен $installed" >&2
    rollback_xray
    return 1
  fi
  if [[ -s "$config" ]] && ! /usr/local/bin/xray run -test -config "$config"; then
    echo "текущий config.json не прошёл проверку Xray $XRAY_VERSION" >&2
    rollback_xray
    return 1
  fi
  systemctl enable xray >/dev/null 2>&1 || true
  if [[ -s "$config" ]]; then
    systemctl restart xray
    sleep 1
    systemctl is-active --quiet xray || {
      echo "Xray $XRAY_VERSION не запустился с текущей конфигурацией" >&2
      rollback_xray
      return 1
    }
  fi
}

usage(){
  cat <<'USAGE'
Использование:
  ec2-first-install.sh [--reconfigure]

Без параметров:
  - новая установка запускается по HTTP без домена и сертификата;
  - завершённая установка обновляется с сохранением текущего HTTP/HTTPS-доступа;
  - незавершённая установка возвращается к мастеру.

--reconfigure
  Повторно запросить адрес Xray, Reality target и Reality SNI.
  Режим доступа к панели, домен и публичный порт меняются позже в
  «Безопасность → Доступ к панели».
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

configured_panel_access_exists(){
  [[ -s /etc/nginx/sites-available/sg-panel ]] &&
  [[ -e /etc/nginx/sites-enabled/sg-panel ]]
}

existing_install_is_complete(){
  core_panel_files_exist &&
  [[ -s /usr/local/etc/xray/config.json ]] &&
  configured_panel_access_exists
}

partial_install_artifacts_exist(){
  [[ -e "$TARGET" || -e /etc/xpanel-mvp/web.env ||
     -e /etc/systemd/system/xpanel-web.service ||
     -e /usr/local/etc/xray/config.json ||
     -e /etc/nginx/sites-available/sg-panel ]]
}

read_state_value(){
  local key="$1" file
  for file in "$PANEL_STATE_FILE" "$INSTALL_MARKER"; do
    [[ -f "$file" ]] || continue
    grep -E "^${key}=" "$file" | tail -1 | cut -d= -f2- && return 0
  done
  return 0
}

detect_panel_access(){
  PANEL_MODE="$(read_state_value PANEL_ACCESS_MODE)"
  PANEL_HOST="$(read_state_value PANEL_PUBLIC_HOST)"
  PANEL_PUBLIC_PORT="$(read_state_value PANEL_PUBLIC_PORT)"
  PANEL_DOMAIN="$(read_state_value PANEL_DOMAIN)"

  if [[ -f /etc/nginx/sites-available/sg-panel ]]; then
    local nginx_mode="" nginx_port="" nginx_host=""
    nginx_port="$(awk '$1 == "listen" {line=$0; gsub(/;/, "", $2); if (line ~ /[[:space:]]ssl([[:space:];]|$)/ && $2 ~ /^[0-9]+$/) {print $2; exit}}' /etc/nginx/sites-available/sg-panel 2>/dev/null || true)"
    if [[ -n "$nginx_port" ]]; then
      nginx_mode="https"
    else
      nginx_port="$(awk '$1 == "listen" {gsub(/;/, "", $2); if ($2 ~ /^[0-9]+$/ && $2 != 80) {print $2; exit}}' /etc/nginx/sites-available/sg-panel 2>/dev/null || true)"
      [[ -n "$nginx_port" ]] && nginx_mode="http"
    fi
    nginx_host="$(awk '$1 == "server_name" {gsub(/;/, "", $2); if ($2 != "_") {print $2; exit}}' /etc/nginx/sites-available/sg-panel 2>/dev/null || true)"
    if [[ -n "$nginx_mode" ]]; then
      PANEL_MODE="$nginx_mode"
      PANEL_PUBLIC_PORT="${nginx_port:-$PANEL_PUBLIC_PORT}"
      [[ -n "$nginx_host" ]] && PANEL_HOST="$nginx_host"
    fi
  fi
  PANEL_HOST="${PANEL_HOST:-${PANEL_DOMAIN:-}}"
  PANEL_PUBLIC_PORT="${PANEL_PUBLIC_PORT:-$DEFAULT_PANEL_PORT}"
  PANEL_MODE="${PANEL_MODE:-http}"
}

write_install_marker(){
  local mode="$1" host="$2" port="$3"
  mkdir -p "$INSTALL_STATE_DIR"
  cat > "$INSTALL_MARKER" <<EOF_MARKER
INSTALL_COMPLETE=1
VERSION=$EXPECTED_VERSION
PANEL_ACCESS_MODE=$mode
PANEL_PUBLIC_HOST=$host
PANEL_PUBLIC_PORT=$port
PANEL_DOMAIN=$([[ "$mode" == "https" ]] && printf '%s' "$host" || true)
COMPLETED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_MARKER
  chmod 600 "$INSTALL_MARKER"
}

if existing_install_is_complete && [[ $RECONFIGURE -eq 0 ]]; then
  CURRENT_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version 2>/dev/null | awk '{print $2}' || true)"
  CURRENT_VERSION="${CURRENT_VERSION:-неизвестна}"
  log "Обнаружена завершённая SG-Panel $CURRENT_VERSION"
  run_stage "Обновление Xray до $XRAY_VERSION с автоматическим откатом" ensure_xray_version
  run_stage "Обновление приложения с сохранением текущего доступа" bash "$SOURCE_DIR/install-or-upgrade.sh"
  NEW_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version | awk '{print $2}')"
  [[ "$NEW_VERSION" == "$EXPECTED_VERSION" ]] || fail "после обновления установлена версия $NEW_VERSION"
  systemctl is-active --quiet "$SERVICE" || fail "служба $SERVICE не active после обновления"
  detect_panel_access
  PANEL_HOST="${PANEL_HOST:-localhost}"
  if [[ "$PANEL_MODE" == "https" ]]; then
    PANEL_URL="https://$PANEL_HOST:$PANEL_PUBLIC_PORT"
  else
    PANEL_URL="http://$PANEL_HOST:$PANEL_PUBLIC_PORT"
  fi
  write_install_marker "$PANEL_MODE" "$PANEL_HOST" "$PANEL_PUBLIC_PORT"
  cat <<EOF_UPDATE

============================================================
 SG-Panel $NEW_VERSION — обновление завершено
============================================================

[OK] Приложение обновлено
[OK] Текущий режим ${PANEL_MODE^^} сохранён
[OK] Пользователи, SQLite и Xray-конфигурация сохранены

Панель:
  $PANEL_URL

Резервная копия создана установщиком в /root/sg-panel-backups/
============================================================
EOF_UPDATE
  exit 0
fi

if existing_install_is_complete && [[ $RECONFIGURE -eq 1 ]]; then
  PRESERVE_PANEL_ACCESS=1
  log "Запущено изменение параметров Xray. Текущий доступ к панели будет сохранён"
elif partial_install_artifacts_exist; then
  PARTIAL_INSTALL=1
  log "Обнаружена незавершённая установка"
  log "Повторно запускаю мастер. Домен и HTTPS для начальной установки не требуются"
  rm -f "$INSTALL_MARKER"
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

detect_ec2_public_ipv4(){
  python3 - <<'PY_EC2_IP' 2>/dev/null || true
import ipaddress
import urllib.request

try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token_request = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    with opener.open(token_request, timeout=1.2) as response:
        token = response.read().decode("ascii").strip()
    ip_request = urllib.request.Request(
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        headers={"X-aws-ec2-metadata-token": token},
    )
    with opener.open(ip_request, timeout=1.2) as response:
        value = response.read().decode("ascii").strip()
    ip = ipaddress.ip_address(value)
    if ip.version == 4 and ip.is_global:
        print(value)
except Exception:
    pass
PY_EC2_IP
}

detect_default_address(){
  local value=""
  value="$(detect_ec2_public_ipv4)"
  if [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    printf '%s' "$value"
    return 0
  fi
  value="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
  if [[ ! "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    value="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s' "$value"
}

CURRENT_XRAY_ADDRESS="$(existing_db_value 'SELECT address FROM server_settings WHERE id = 1;')"
CURRENT_REALITY_DEST="$(existing_db_value 'SELECT dest FROM server_settings WHERE id = 1;')"
CURRENT_REALITY_SNI="$(existing_db_value 'SELECT server_name FROM server_settings WHERE id = 1;')"
CURRENT_FIRST_USER="$(existing_db_value 'SELECT name FROM users ORDER BY id LIMIT 1;')"
AUTO_ADDRESS="$(detect_default_address)"
XRAY_ADDRESS_DEFAULT="${CURRENT_XRAY_ADDRESS:-$AUTO_ADDRESS}"
FIRST_USER_DEFAULT="${CURRENT_FIRST_USER:-$DEFAULT_USER}"
REALITY_DEST_DEFAULT="${CURRENT_REALITY_DEST:-$DEFAULT_REALITY_DEST}"
REALITY_SNI_DEFAULT="${CURRENT_REALITY_SNI:-$DEFAULT_REALITY_SNI}"

printf '%s\n' \
  "Начальная установка работает по HTTP и не требует домена или сертификата." \
  "HTTPS можно включить позже в разделе «Безопасность → Доступ к панели»." \
  "Чтобы принять значение в квадратных скобках, нажмите Enter." \
  ""

prompt_value XRAY_ADDRESS "Адрес Xray для клиентов (публичный IP или домен)" "$XRAY_ADDRESS_DEFAULT"
if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]]; then
  prompt_value PANEL_PUBLIC_PORT "Публичный HTTP-порт панели" "$DEFAULT_PANEL_PORT"
fi
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
fi

[[ -n "$XRAY_ADDRESS" && "$XRAY_ADDRESS" =~ ^[A-Za-z0-9._:-]+$ ]] || fail "некорректный IP или домен Xray"
[[ -n "$FIRST_USER" ]] || fail "имя пользователя не может быть пустым"
[[ "$REALITY_DEST" == *:* ]] || fail "Reality target должен иметь вид host:port"
if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]]; then
  [[ "$PANEL_PUBLIC_PORT" =~ ^[0-9]+$ ]] && (( PANEL_PUBLIC_PORT >= 49152 && PANEL_PUBLIC_PORT <= 65535 )) || fail "выберите порт панели 49152-65535"
  for reserved in 22 80 443 "$DEFAULT_BACKEND_PORT" 8443; do
    [[ "$PANEL_PUBLIC_PORT" != "$reserved" ]] || fail "порт $PANEL_PUBLIC_PORT нельзя использовать для панели"
  done
fi

ensure_swap(){
  local mem_kib
  mem_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
  if (( mem_kib < 1572864 )) && ! swapon --show=NAME --noheadings | grep -qx '/swapfile'; then
    [[ -f /swapfile ]] || fallocate -l 2G /swapfile
    chmod 600 /swapfile
    blkid /swapfile 2>/dev/null | grep -q 'TYPE="swap"' || mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile[[:space:]]' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
}

install_system_packages(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    curl ca-certificates unzip rsync zstd \
    python3 python3-venv python3-pip \
    sqlite3 jq iproute2 dnsutils \
    nginx certbot openssl
}

install_xray_stage(){
  ensure_xray_version
}

install_panel_stage(){
  export XPANEL_BIND_ADDRESS="127.0.0.1"
  export XPANEL_PORT="$DEFAULT_BACKEND_PORT"
  export XPANEL_SECURE_COOKIES="0"
  export XPANEL_TRUST_PROXY_HEADERS="1"
  if [[ -n "${XPANEL_ADMIN_PASSWORD:-}" ]]; then
    export XPANEL_ADMIN_PASSWORD
  fi
  bash "$SOURCE_DIR/install-or-upgrade.sh"
}

configure_panel_data_stage(){
  cd "$TARGET"
  local server_count user_count tmp_env
  server_count="$(sqlite3 data/panel.db 'SELECT COUNT(*) FROM server_settings;' 2>/dev/null || echo 0)"
  if [[ "$server_count" == "0" ]]; then
    tmp_env="$(mktemp /root/sg-panel-reality.XXXXXX)"
    chmod 600 "$tmp_env"
    .venv/bin/python -m xpanel gen-keys --save "$tmp_env" >/dev/null
    set -a; . "$tmp_env"; set +a
    .venv/bin/python -m xpanel set-server \
      --address "$XRAY_ADDRESS" \
      --listen 0.0.0.0 \
      --port 443 \
      --dest "$REALITY_DEST" \
      --server-name "$REALITY_SNI" \
      --private-key "$PRIVATE_KEY" \
      --public-key "$PUBLIC_KEY" \
      --short-id "$SHORT_ID" \
      --fingerprint chrome >/dev/null
    rm -f "$tmp_env"
    unset PRIVATE_KEY PUBLIC_KEY SHORT_ID
  elif [[ $PARTIAL_INSTALL -eq 1 || $RECONFIGURE -eq 1 ]]; then
    python3 - data/panel.db "$XRAY_ADDRESS" "$REALITY_DEST" "$REALITY_SNI" <<'PY_UPDATE_SERVER'
import sqlite3
import sys
path, address, dest, server_name = sys.argv[1:]
with sqlite3.connect(path) as con:
    con.execute(
        "UPDATE server_settings SET address=?, dest=?, server_name=? WHERE id=1",
        (address, dest, server_name),
    )
PY_UPDATE_SERVER
  fi

  user_count="$(sqlite3 data/panel.db 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo 0)"
  if [[ "$user_count" == "0" ]]; then
    .venv/bin/python -m xpanel add-user "$FIRST_USER" >/dev/null
  fi
}

apply_xray_stage(){
  cd "$TARGET"
  .venv/bin/python -m xpanel apply >/dev/null
}

configure_panel_access_stage(){
  if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]]; then
    bash "$TARGET/deploy/configure-http.sh" --host "$XRAY_ADDRESS" --port "$PANEL_PUBLIC_PORT"
  else
    log "Сохраняю существующий HTTP/HTTPS-доступ к панели"
  fi
}

validate_installation_stage(){
  cd "$TARGET"
  local cli_version xray_version mode host port url
  cli_version="$(.venv/bin/python -m xpanel --version | awk '{print $2}')"
  [[ "$cli_version" == "$EXPECTED_VERSION" ]] || fail "неожиданная версия CLI: $cli_version"
  xray_version="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"
  [[ "$xray_version" == "$XRAY_VERSION" ]] || fail "неожиданная версия Xray: $xray_version"
  systemctl is-active --quiet xpanel-web || fail "xpanel-web не active"
  systemctl is-active --quiet xray || fail "xray не active"
  systemctl is-active --quiet nginx || fail "nginx не active"
  systemctl is-active --quiet xpanel-traffic.timer || fail "xpanel-traffic.timer не active"
  .venv/bin/python -m xpanel collect-traffic --online --strict

  detect_panel_access
  mode="$PANEL_MODE"
  host="${PANEL_HOST:-$XRAY_ADDRESS}"
  port="$PANEL_PUBLIC_PORT"
  if [[ "$mode" == "https" ]]; then
    url="https://$host:$port"
    curl -kfsS --max-time 5 --resolve "$host:$port:127.0.0.1" "$url/login" >/dev/null
  else
    curl -fsS --max-time 5 -H "Host: $host" "http://127.0.0.1:$port/login" >/dev/null
  fi
  write_install_marker "$mode" "$host" "$port"
}

run_stage "Этап 1/7 · Подготовка системы" ensure_swap
run_stage "Этап 2/7 · Установка системных пакетов" install_system_packages

if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]] && ss -lntH | awk '{print $4}' | grep -Eq "(^|:)$PANEL_PUBLIC_PORT$"; then
  nginx -T 2>/dev/null | grep -Eq "listen[[:space:]]+${PANEL_PUBLIC_PORT}([[:space:]]|;)" || fail "порт $PANEL_PUBLIC_PORT уже занят другим процессом"
fi

run_stage "Этап 3/7 · Установка Xray $XRAY_VERSION" install_xray_stage
run_stage "Этап 4/7 · Установка SG-Panel" install_panel_stage
unset XPANEL_ADMIN_PASSWORD XPANEL_ADMIN_PASSWORD_2 2>/dev/null || true
run_stage "Этап 5/7 · Настройка Reality и пользователей" configure_panel_data_stage
apply_and_publish_stage(){ apply_xray_stage; configure_panel_access_stage; }
run_stage "Этап 6/7 · Применение Xray и публикация панели" apply_and_publish_stage
run_stage "Этап 7/7 · Финальная проверка" validate_installation_stage

cd "$TARGET"
CLI_VERSION="$(.venv/bin/python -m xpanel --version | awk '{print $2}')"
detect_panel_access
PANEL_HOST="${PANEL_HOST:-$XRAY_ADDRESS}"
if [[ "$PANEL_MODE" == "https" ]]; then
  PANEL_URL="https://$PANEL_HOST:$PANEL_PUBLIC_PORT"
else
  PANEL_URL="http://$PANEL_HOST:$PANEL_PUBLIC_PORT"
fi
write_install_marker "$PANEL_MODE" "$PANEL_HOST" "$PANEL_PUBLIC_PORT"

LINK="$(.venv/bin/python -m xpanel show-link "$FIRST_USER" 2>/dev/null || true)"
LINK_FILE="/root/sg-panel-first-user.txt"
if [[ -n "$LINK" ]]; then
  printf '%s\n' "$LINK" > "$LINK_FILE"
  chmod 600 "$LINK_FILE"
fi

SSH_IP="${SSH_CONNECTION:-}"
SSH_IP="${SSH_IP%% *}"
SSH_SOURCE="${SSH_IP:+$SSH_IP/32}"
SSH_SOURCE="${SSH_SOURCE:-ваш IP или локальная сеть}"
if [[ "$PANEL_MODE" == "https" ]]; then
  PANEL_HTTPS_STATUS="включён"
else
  PANEL_HTTPS_STATUS="можно включить позже в «Безопасность → Доступ к панели»"
fi

cat <<EOF_RESULT

============================================================
 SG-Panel $EXPECTED_VERSION — установка завершена успешно
============================================================

ПАНЕЛЬ УПРАВЛЕНИЯ
  Адрес:           $PANEL_URL
  Режим:           ${PANEL_MODE^^}
  Backend:         127.0.0.1:$DEFAULT_BACKEND_PORT
  HTTPS:           $PANEL_HTTPS_STATUS

XRAY REALITY
  Сервер:          $XRAY_ADDRESS:443
  Пользователь:    $FIRST_USER
  VLESS-ссылка:    $LINK_FILE
  Показать ссылку: cat $LINK_FILE

ПРОВЕРКИ
  SG-Panel:        active
  Nginx:           active — :$PANEL_PUBLIC_PORT
  Xray:            active — $XRAY_VERSION — Reality :443

FIREWALL / SECURITY GROUP
  22/tcp           $SSH_SOURCE
  443/tcp          клиенты Xray
  $PANEL_PUBLIC_PORT/tcp       только ваш IP или локальная сеть
  $DEFAULT_BACKEND_PORT/tcp         НЕ ОТКРЫВАТЬ
  80/tcp           нужен только при последующем включении Let's Encrypt

Откройте панель и войдите с заданным паролем.
============================================================
EOF_RESULT
