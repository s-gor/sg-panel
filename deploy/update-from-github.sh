#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${XPANEL_PROJECT_DIR:-/opt/xpanel-mvp}"
ENV_FILE="${XPANEL_ENV_FILE:-/etc/xpanel-mvp/web.env}"
STATE_DIR="${XPANEL_UPDATE_STATE_DIR:-/var/lib/sg-panel-update}"
STATUS_FILE="${XPANEL_UPDATE_STATUS:-$STATE_DIR/status.json}"
LOG_FILE="${XPANEL_UPDATE_LOG:-$STATE_DIR/update.log}"
VERSION="${XPANEL_UPDATE_VERSION:-}"
REF="${XPANEL_UPDATE_REF:-}"
LOCAL_SOURCE_DIR="${XPANEL_UPDATE_SOURCE_DIR:-}"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/sg-panel-backups/${STAMP}-update-rollback"
TMP="$(mktemp -d)"
LOCK_FILE="/run/lock/sg-panel-update.lock"
ROLLBACK_NEEDED=0
PANEL_WAS_ACTIVE=0
XRAY_WAS_ACTIVE=0
NGINX_WAS_ACTIVE=0
MAINTENANCE_TIMER_WAS_ACTIVE=0
TRAFFIC_TIMER_WAS_ACTIVE=0
TARGET_URL=""
SOURCE_DIR=""

MANAGED_PATHS=(
  /usr/local/etc/xray/config.json
  /usr/local/etc/xray/sg-panel-tls
  /etc/nginx/sites-available/sg-panel
  /etc/nginx/sites-enabled/sg-panel
  /etc/nginx/sites-available/sg-panel-acme
  /etc/nginx/sites-enabled/sg-panel-acme
  /etc/nginx/sites-available/sg-panel-xray-transport
  /etc/nginx/sites-enabled/sg-panel-xray-transport
  /etc/nginx/modules-enabled/90-sg-panel-reality-edge.conf
  /etc/nginx/sites-available/sg-panel-reality-placeholder
  /etc/nginx/sites-enabled/sg-panel-reality-placeholder
  /var/www/sg-panel-placeholder
  /etc/letsencrypt/renewal-hooks/deploy/sync-sg-panel-hysteria-tls.sh
  /usr/local/sbin/sg-panel-fix-xray-cert-access
  /etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access
)
SYSTEMD_UNITS=(
  xpanel-web.service
  xpanel-maintenance.service
  xpanel-maintenance.timer
  xpanel-traffic.service
  xpanel-traffic.timer
  xray.service
)

mkdir -p "$STATE_DIR" "$(dirname "$STATUS_FILE")" "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"
chmod 0600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log(){ printf '[SG-Panel Update] %s\n' "$*"; }
fail(){ printf '[SG-Panel Update] ERROR: %s\n' "$*" >&2; return 1; }

status(){
  local state="$1" message="${2:-}" restored="${3:-0}"
  python3 - "$STATUS_FILE" "$LOG_FILE" "$state" "$VERSION" "$REF" "$message" "$TARGET_URL" "$restored" <<'PY'
import json, os, sys, tempfile
from datetime import datetime, timezone
status_path, log_path, state, version, ref, message, target_url, restored = sys.argv[1:]
os.makedirs(os.path.dirname(status_path), exist_ok=True)
try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as stream:
        log = stream.read()[-64000:]
except OSError:
    log = ""
payload = {
    "state": state,
    "version": version,
    "ref": ref,
    "message": message,
    "updatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "log": log,
}
if target_url:
    payload["targetUrl"] = target_url
if restored == "1":
    payload["restored"] = True
raw = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
fd, temporary = tempfile.mkstemp(prefix=".status-", dir=os.path.dirname(status_path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(raw)
    os.chmod(temporary, 0o600)
    os.replace(temporary, status_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

phase(){
  log "$1"
  status "$2" "$1"
}

safe_copy_path(){
  local path="$1" name
  name="$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a "$path" "$BACKUP_DIR/managed/$name"
    : > "$BACKUP_DIR/managed/$name.exists"
  fi
}

restore_path(){
  local path="$1" name
  name="$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
  rm -rf "$path"
  if [[ -f "$BACKUP_DIR/managed/$name.exists" ]]; then
    mkdir -p "$(dirname "$path")"
    cp -a "$BACKUP_DIR/managed/$name" "$path"
  fi
}

service_active(){ systemctl is-active --quiet "$1" 2>/dev/null; }

get_public_url(){
  python3 - "$PROJECT_DIR" <<'PY'
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
state = Path('/etc/xpanel-mvp/panel-access.env')
values = {}
if state.exists():
    for line in state.read_text(encoding='utf-8', errors='replace').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
mode = values.get('PANEL_ACCESS_MODE', 'http').lower()
host = values.get('PANEL_PUBLIC_HOST') or values.get('PANEL_DOMAIN') or ''
port = values.get('PANEL_PUBLIC_PORT', '61443')
nginx = Path('/etc/nginx/sites-available/sg-panel')
if nginx.exists():
    text = nginx.read_text(encoding='utf-8', errors='replace')
    ssl = re.search(r'(?m)^\s*listen\s+(?:\[::\]:)?(\d+)\s+ssl', text)
    plain = re.search(r'(?m)^\s*listen\s+(?:\[::\]:)?(\d+)\s*;', text)
    server_name = re.search(r'(?m)^\s*server_name\s+([^;\s]+)', text)
    if ssl:
        mode, port = 'https', ssl.group(1)
    elif plain and plain.group(1) != '80':
        mode, port = 'http', plain.group(1)
    if server_name and server_name.group(1) != '_':
        host = server_name.group(1)
if not host:
    host = 'SERVER_IP'
default = '443' if mode == 'https' else '80'
suffix = '' if port == default else ':' + port
print(f'{mode}://{host}{suffix}/updates?updated=1')
PY
}

get_health_url(){
  local bind port host
  bind="$(grep -E '^XPANEL_BIND_ADDRESS=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  port="$(grep -E '^XPANEL_PORT=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  bind="${bind:-127.0.0.1}"
  port="${port:-8080}"
  case "$bind" in
    0.0.0.0|127.0.0.1) host="127.0.0.1" ;;
    ::|::0|::1) host="[::1]" ;;
    *) host="$bind" ;;
  esac
  printf 'http://%s:%s/health' "$host" "$port"
}

wait_for_health(){
  local url="$1" attempt
  for attempt in {1..30}; do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

backup_database(){
  local source="$PROJECT_DIR/data/panel.db" target="$BACKUP_DIR/data/panel.db"
  [[ -f "$source" ]] || return 0
  SOURCE_DB="$source" TARGET_DB="$target" python3 - <<'PY'
import os, sqlite3
source = sqlite3.connect(os.environ['SOURCE_DB'])
target = sqlite3.connect(os.environ['TARGET_DB'])
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY
}

backup_certificates(){
  [[ -x "$PROJECT_DIR/.venv/bin/python" && -f "$PROJECT_DIR/data/panel.db" ]] || return 0
  mkdir -p "$BACKUP_DIR/certificates"
  "$PROJECT_DIR/.venv/bin/python" - "$PROJECT_DIR/data/panel.db" "$BACKUP_DIR/certificates" <<'PY'
import json, shutil, sqlite3, sys
from pathlib import Path
source_db = Path(sys.argv[1])
target = Path(sys.argv[2])
con = sqlite3.connect(source_db)
try:
    row = con.execute('SELECT tls_cert_path, tls_key_path FROM server_settings WHERE id=1').fetchone()
finally:
    con.close()
manifest = {}
if row:
    for label, raw in zip(('certificate', 'private_key'), row):
        path = Path(str(raw or ''))
        if path.is_file():
            destination = target / (label + path.suffix)
            shutil.copy2(path.resolve(), destination)
            manifest[label] = {'source': str(path), 'backup': destination.name}
(target / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
PY
}

rollback(){
  local rc=$? rollback_ok=1 health_url=""
  trap - ERR INT TERM
  set +e
  if (( ROLLBACK_NEEDED )); then
    status rollback "Ошибка обновления. Восстанавливается предыдущая рабочая версия" 1
    log "Ошибка обновления; начинаю автоматический откат"
    systemctl stop xpanel-web.service 2>/dev/null || true

    if [[ -d "$BACKUP_DIR/project" ]]; then
      rsync -a --delete \
        --exclude='.venv/' --exclude='data/' --exclude='backups/' \
        "$BACKUP_DIR/project/" "$PROJECT_DIR/" || rollback_ok=0
    else
      rollback_ok=0
    fi
    if [[ -d "$BACKUP_DIR/data" ]]; then
      mkdir -p "$PROJECT_DIR/data" || rollback_ok=0
      rsync -a --delete "$BACKUP_DIR/data/" "$PROJECT_DIR/data/" || rollback_ok=0
    else
      rollback_ok=0
    fi
    if [[ -d "$BACKUP_DIR/etc-xpanel-mvp" ]]; then
      rm -rf /etc/xpanel-mvp
      cp -a "$BACKUP_DIR/etc-xpanel-mvp" /etc/xpanel-mvp || rollback_ok=0
    else
      rollback_ok=0
    fi

    for path in "${MANAGED_PATHS[@]}"; do
      restore_path "$path" || rollback_ok=0
    done
    for unit in "${SYSTEMD_UNITS[@]}"; do
      restore_path "/etc/systemd/system/$unit" || rollback_ok=0
    done

    cd "$PROJECT_DIR" 2>/dev/null || rollback_ok=0
    if [[ -x .venv/bin/pip && -f requirements.txt ]]; then
      .venv/bin/pip install --no-cache-dir -q -r requirements.txt || rollback_ok=0
    else
      rollback_ok=0
    fi
    systemctl daemon-reload || rollback_ok=0

    if (( XRAY_WAS_ACTIVE )); then
      if [[ -x .venv/bin/python ]]; then
        XRAY_BIN="$(.venv/bin/python - <<'PY' 2>/dev/null
from xpanel.service import get_server
print(get_server()['xray_bin'])
PY
)"
        XRAY_CONFIG="$(.venv/bin/python - <<'PY' 2>/dev/null
from xpanel.service import get_server
print(get_server()['config_path'])
PY
)"
        [[ -n "$XRAY_BIN" && -n "$XRAY_CONFIG" ]] || rollback_ok=0
        "$XRAY_BIN" run -test -config "$XRAY_CONFIG" >/dev/null 2>&1 || rollback_ok=0
      else
        rollback_ok=0
      fi
      systemctl restart xray.service || rollback_ok=0
      systemctl is-active --quiet xray.service || rollback_ok=0
    else
      systemctl stop xray.service 2>/dev/null || true
    fi

    if (( NGINX_WAS_ACTIVE )); then
      nginx -t >/dev/null 2>&1 || rollback_ok=0
      systemctl restart nginx.service || rollback_ok=0
      systemctl is-active --quiet nginx.service || rollback_ok=0
    else
      systemctl stop nginx.service 2>/dev/null || true
    fi

    if (( MAINTENANCE_TIMER_WAS_ACTIVE )); then
      systemctl enable --now xpanel-maintenance.timer >/dev/null 2>&1 || rollback_ok=0
    else
      systemctl disable --now xpanel-maintenance.timer >/dev/null 2>&1 || true
    fi
    if (( TRAFFIC_TIMER_WAS_ACTIVE )); then
      systemctl enable --now xpanel-traffic.timer >/dev/null 2>&1 || rollback_ok=0
    else
      systemctl disable --now xpanel-traffic.timer >/dev/null 2>&1 || true
    fi

    if (( PANEL_WAS_ACTIVE )); then
      systemctl restart xpanel-web.service || rollback_ok=0
      systemctl is-active --quiet xpanel-web.service || rollback_ok=0
      health_url="$(get_health_url)"
      wait_for_health "$health_url" || rollback_ok=0
    else
      systemctl stop xpanel-web.service 2>/dev/null || true
    fi

    if (( rollback_ok )); then
      status rolled_back "Предыдущая рабочая версия восстановлена автоматически" 1
      log "Предыдущая рабочая версия восстановлена и проверена"
    else
      status error "Автоматический откат выполнен не полностью. Требуется проверка через SSH" 1
      log "ОШИБКА: не все проверки после отката прошли. Используйте страховочную копию вручную"
    fi
    log "Страховочная копия: $BACKUP_DIR"
  else
    status error "Обновление остановлено до изменения рабочей установки" 0
    log "Рабочая установка не изменялась"
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap rollback ERR INT TERM

exec 9>"$LOCK_FILE"
flock -n 9 || fail "другое обновление уже выполняется"

[[ $EUID -eq 0 ]] || fail "запустите обновление от root"
[[ -x "$PROJECT_DIR/.venv/bin/python" ]] || fail "текущая установка SG-Panel не найдена"
[[ -f "$ENV_FILE" ]] || fail "не найден $ENV_FILE"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)[0-9]+)?$ ]] || fail "некорректная версия: $VERSION"
[[ "$REF" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ && "$REF" != *..* ]] || fail "некорректная ссылка на версию"
for command in rsync python3 flock systemctl curl; do command -v "$command" >/dev/null 2>&1 || fail "не найдена команда $command"; done

TARGET_URL="$(get_public_url)"
service_active xpanel-web.service && PANEL_WAS_ACTIVE=1 || true
service_active xray.service && XRAY_WAS_ACTIVE=1 || true
service_active nginx.service && NGINX_WAS_ACTIVE=1 || true
service_active xpanel-maintenance.timer && MAINTENANCE_TIMER_WAS_ACTIVE=1 || true
service_active xpanel-traffic.timer && TRAFFIC_TIMER_WAS_ACTIVE=1 || true

phase "Загрузка исходного кода $VERSION" downloading
if [[ -n "$LOCAL_SOURCE_DIR" ]]; then
  SOURCE_DIR="$(cd "$LOCAL_SOURCE_DIR" && pwd)"
  log "Используется локальный кандидат: $SOURCE_DIR"
else
  for command in tar; do command -v "$command" >/dev/null 2>&1 || fail "не найдена команда $command"; done
  URL="https://github.com/s-gor/sg-panel/archive/refs/tags/${REF}.tar.gz"
  curl -fsSL --retry 3 --retry-all-errors --connect-timeout 15 --max-time 180 "$URL" -o "$TMP/source.tar.gz"
  tar -xzf "$TMP/source.tar.gz" -C "$TMP"
  SOURCE_DIR="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
fi
[[ -n "$SOURCE_DIR" && -f "$SOURCE_DIR/xpanel/__init__.py" ]] || fail "архив исходного кода неполный"
[[ -f "$SOURCE_DIR/deploy/update-from-github.sh" && -f "$SOURCE_DIR/install-or-upgrade.sh" ]] || fail "в архиве нет updater или установщика"

phase "Проверка кандидата перед изменением сервера" verifying
SOURCE_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/v\1/p' "$SOURCE_DIR/xpanel/__init__.py" | head -n 1)"
[[ "$SOURCE_VERSION" == "$VERSION" ]] || fail "версия исходников $SOURCE_VERSION не совпадает с $VERSION"
find "$SOURCE_DIR" -type f -name '*.sh' -print0 | while IFS= read -r -d '' script; do bash -n "$script"; done
"$PROJECT_DIR/.venv/bin/python" -m compileall -q "$SOURCE_DIR/xpanel"
PYTHONPATH="$SOURCE_DIR" "$PROJECT_DIR/.venv/bin/python" - "$SOURCE_DIR/xpanel/templates" <<'PY'
import sys
from jinja2 import Environment, FileSystemLoader
root = sys.argv[1]
env = Environment(loader=FileSystemLoader(root))
for name in env.list_templates():
    env.get_template(name)
print(f'Jinja templates: {len(env.list_templates())}')
PY

phase "Создание полной страховочной копии" backing_up
mkdir -p "$BACKUP_DIR/project" "$BACKUP_DIR/data" "$BACKUP_DIR/managed"
rsync -a \
  --exclude='.venv/' --exclude='data/' --exclude='backups/' \
  --exclude='__pycache__/' --exclude='*.pyc' \
  "$PROJECT_DIR/" "$BACKUP_DIR/project/"
if [[ -d "$PROJECT_DIR/data" ]]; then rsync -a "$PROJECT_DIR/data/" "$BACKUP_DIR/data/"; fi
backup_database
if [[ -d /etc/xpanel-mvp ]]; then cp -a /etc/xpanel-mvp "$BACKUP_DIR/etc-xpanel-mvp"; fi
for path in "${MANAGED_PATHS[@]}"; do
  safe_copy_path "$path"
done
for unit in "${SYSTEMD_UNITS[@]}"; do
  safe_copy_path "/etc/systemd/system/$unit"
done
backup_certificates
cd "$PROJECT_DIR"
.venv/bin/python -m xpanel backup
ROLLBACK_NEEDED=1

phase "Установка файлов новой версии" installing
systemctl stop xpanel-web.service
rsync -a --delete \
  --exclude='.git/' --exclude='.venv/' --exclude='data/' --exclude='backups/' \
  --exclude='__pycache__/' --exclude='*.pyc' \
  "$SOURCE_DIR/" "$PROJECT_DIR/"
find "$PROJECT_DIR" -type f -name '*.sh' -exec chmod 0755 {} +
cd "$PROJECT_DIR"
.venv/bin/pip install --no-cache-dir -q -r requirements.txt
.venv/bin/python -m xpanel init-db

phase "Проверка Xray и служб" validating
if ! SERVER_COUNT="$(.venv/bin/python - <<'PY'
from xpanel.db import connect
with connect() as con:
    print(con.execute('SELECT COUNT(*) FROM server_settings').fetchone()[0])
PY
)"; then
  fail "не удалось открыть SQLite после обновления"
fi
bash deploy/install-xray-cert-access.sh
if [[ "$SERVER_COUNT" != "0" ]]; then
  .venv/bin/python -m xpanel apply
fi
bash deploy/install-service.sh
bash deploy/install-maintenance.sh
if (( MAINTENANCE_TIMER_WAS_ACTIVE )); then
  systemctl enable --now xpanel-maintenance.timer >/dev/null
else
  systemctl disable --now xpanel-maintenance.timer >/dev/null 2>&1 || true
fi
if (( TRAFFIC_TIMER_WAS_ACTIVE )); then
  systemctl enable --now xpanel-traffic.timer >/dev/null
else
  systemctl disable --now xpanel-traffic.timer >/dev/null 2>&1 || true
fi
if [[ ! -x /usr/local/bin/wgcf-cli ]]; then
  if ! bash deploy/install-wgcf-cli.sh; then
    log "Предупреждение: wgcf-cli не установлен; существующая конфигурация WARP сохранена"
  fi
else
  log "Существующий wgcf-cli сохранён без переустановки"
fi
if ! bash deploy/repair-panel-access.sh; then
  log "Предупреждение: публичный адрес не изменён, автоматическая сверка не выполнена"
fi
systemctl daemon-reload
systemctl restart xpanel-web.service
HEALTH_URL="$(get_health_url)"
wait_for_health "$HEALTH_URL" || fail "локальная health-проверка SG-Panel не пройдена"
systemctl is-active --quiet xpanel-web.service
if (( TRAFFIC_TIMER_WAS_ACTIVE )); then systemctl is-active --quiet xpanel-traffic.timer; fi
if (( MAINTENANCE_TIMER_WAS_ACTIVE )); then systemctl is-active --quiet xpanel-maintenance.timer; fi
if [[ "$SERVER_COUNT" != "0" ]]; then
  XRAY_BIN="$(.venv/bin/python - <<'PY'
from xpanel.service import get_server
print(get_server()['xray_bin'])
PY
)"
  XRAY_CONFIG="$(.venv/bin/python - <<'PY'
from xpanel.service import get_server
print(get_server()['config_path'])
PY
)"
  log "Проверка: xray run -test"
  "$XRAY_BIN" run -test -config "$XRAY_CONFIG"
  systemctl is-active --quiet xray.service
fi
if (( NGINX_WAS_ACTIVE )); then
  nginx -t
  systemctl restart nginx.service
  systemctl is-active --quiet nginx.service
fi
INSTALLED_VERSION="v$(.venv/bin/python -c 'import xpanel; print(xpanel.__version__)')"
[[ "$INSTALLED_VERSION" == "$VERSION" ]] || fail "после установки обнаружена версия $INSTALLED_VERSION"

ROLLBACK_NEEDED=0
trap - ERR INT TERM
log "Готово: $INSTALLED_VERSION"
log "Страховочная копия для ручного восстановления: $BACKUP_DIR"
log "SQLite, Xray, WARP, DNS, Traffic Rules, Outbounds, Nginx и доступ к панели сохранены"
status success "Обновление завершено. Конфигурация и доступ к панели сохранены"
rm -rf "$TMP"
