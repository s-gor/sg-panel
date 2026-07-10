#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.10.0-rc70"
EXPECTED_UI_REVISION="sg070"
TARGET="/opt/xpanel-mvp"
SERVICE="xpanel-web"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="/root/sg-panel-backups/$STAMP"
LOG_FILE="${SG_PANEL_UPGRADE_LOG:-/var/log/sg-panel-upgrade-$STAMP.log}"
ROLLBACK_NEEDED=0
ROLLBACK_RUNNING=0
OLD_EXISTS=0
OLD_XRAY_CONFIG_EXISTS=0
SERVER_COUNT=0
CURRENT_STEP="Подготовка"
SPINNER_PID=""
STEP_STARTED=0
WGCF_WARNING=0
ACCESS_WARNING=0

COLOR_GREEN=$'\033[1;32m'
COLOR_RED=$'\033[1;31m'
COLOR_YELLOW=$'\033[1;33m'
COLOR_RESET=$'\033[0m'

log(){ printf '[SG-Panel] %s\n' "$*" >>"$LOG_FILE"; }

spinner_loop(){
  local label="$1" started="$2"
  local frames='|/-\'
  local frame_index=0 elapsed
  while :; do
    elapsed=$(( $(date +%s) - started ))
    printf '\r\033[K[SG-Panel] [%s%s%s] %s (%s сек)' \
      "$COLOR_GREEN" "${frames:frame_index%4:1}" "$COLOR_RESET" "$label" "$elapsed"
    frame_index=$((frame_index + 1))
    sleep 0.25
  done
}

stop_spinner(){
  if [[ -n "${SPINNER_PID:-}" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
  fi
  SPINNER_PID=""
}

step_begin(){
  CURRENT_STEP="$1"
  STEP_STARTED="$(date +%s)"
  printf '\n[SG-Panel] %s\n' "$CURRENT_STEP" >>"$LOG_FILE"
  if [[ -t 1 ]]; then
    spinner_loop "$CURRENT_STEP" "$STEP_STARTED" &
    SPINNER_PID=$!
  else
    printf '[SG-Panel] %s\n' "$CURRENT_STEP"
  fi
}

step_ok(){
  local elapsed=$(( $(date +%s) - STEP_STARTED ))
  stop_spinner
  if [[ -t 1 ]]; then
    printf '\r\033[K[SG-Panel] [%sOK%s] %s (%s сек)\n' \
      "$COLOR_GREEN" "$COLOR_RESET" "$CURRENT_STEP" "$elapsed"
  else
    printf '[SG-Panel] [OK] %s (%s сек)\n' "$CURRENT_STEP" "$elapsed"
  fi
  printf '[SG-Panel] [OK] %s (%s сек)\n' "$CURRENT_STEP" "$elapsed" >>"$LOG_FILE"
}

run_stage(){
  local label="$1"
  shift
  step_begin "$label"
  "$@" >>"$LOG_FILE" 2>&1
  step_ok
}

show_failure(){
  local rc="$1"
  stop_spinner
  printf '\r\033[K[SG-Panel] [%sОШИБКА%s] %s\n' "$COLOR_RED" "$COLOR_RESET" "$CURRENT_STEP" >&2
  if [[ -s "$LOG_FILE" ]]; then
    printf '\nПоследние полезные строки журнала:\n' >&2
    tail -n 35 "$LOG_FILE" >&2 || true
  fi
  printf '\nПолный журнал: %s\n' "$LOG_FILE" >&2
  return "$rc"
}

rollback(){
  local rc=$?
  if [[ $ROLLBACK_RUNNING -eq 1 ]]; then
    exit "$rc"
  fi
  ROLLBACK_RUNNING=1
  stop_spinner

  if [[ $ROLLBACK_NEEDED -eq 1 ]]; then
    log "Ошибка на этапе: $CURRENT_STEP. Выполняется rollback"
    CURRENT_STEP="Rollback · восстановление предыдущего рабочего состояния"
    STEP_STARTED="$(date +%s)"
    if [[ -t 1 ]]; then
      spinner_loop "$CURRENT_STEP" "$STEP_STARTED" &
      SPINNER_PID=$!
    else
      printf '[SG-Panel] %s\n' "$CURRENT_STEP" >&2
    fi

    systemctl stop "$SERVICE" >>"$LOG_FILE" 2>&1 || true
    rm -rf "$TARGET" >>"$LOG_FILE" 2>&1 || true
    if [[ $OLD_EXISTS -eq 1 && -d "$BACKUP_ROOT/xpanel-mvp" ]]; then
      cp -a "$BACKUP_ROOT/xpanel-mvp" "$TARGET" >>"$LOG_FILE" 2>&1 || true
    fi
    if [[ -f "$BACKUP_ROOT/web.env" ]]; then mkdir -p /etc/xpanel-mvp; cp -a "$BACKUP_ROOT/web.env" /etc/xpanel-mvp/web.env; fi
    if [[ -f "$BACKUP_ROOT/panel-access.env" ]]; then mkdir -p /etc/xpanel-mvp; cp -a "$BACKUP_ROOT/panel-access.env" /etc/xpanel-mvp/panel-access.env; fi
    if [[ -f "$BACKUP_ROOT/install-complete.env" ]]; then mkdir -p /etc/xpanel-mvp; cp -a "$BACKUP_ROOT/install-complete.env" /etc/xpanel-mvp/install-complete.env; fi
    if [[ -f "$BACKUP_ROOT/xpanel-web.service" ]]; then cp -a "$BACKUP_ROOT/xpanel-web.service" /etc/systemd/system/xpanel-web.service; fi
    if [[ -d "$BACKUP_ROOT/warp" ]]; then
      rm -rf /etc/xpanel-mvp/warp
      mkdir -p /etc/xpanel-mvp
      cp -a "$BACKUP_ROOT/warp" /etc/xpanel-mvp/warp
    fi
    if [[ -f "$BACKUP_ROOT/xray-config.json" ]]; then
      mkdir -p /usr/local/etc/xray
      cp -a "$BACKUP_ROOT/xray-config.json" /usr/local/etc/xray/config.json
    elif [[ $OLD_XRAY_CONFIG_EXISTS -eq 0 ]]; then
      rm -f /usr/local/etc/xray/config.json
    fi
    systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
    systemctl restart xray >>"$LOG_FILE" 2>&1 || true
    systemctl restart "$SERVICE" >>"$LOG_FILE" 2>&1 || true

    local rollback_elapsed=$(( $(date +%s) - STEP_STARTED ))
    stop_spinner
    if [[ $OLD_EXISTS -eq 1 && -d "$TARGET" ]]; then
      printf '\r\033[K[SG-Panel] [%sOK%s] %s (%s сек)\n' \
        "$COLOR_GREEN" "$COLOR_RESET" "$CURRENT_STEP" "$rollback_elapsed" >&2
      log "Rollback завершён успешно за ${rollback_elapsed} сек"
    else
      printf '\r\033[K[SG-Panel] [%sОШИБКА%s] Rollback не нашёл предыдущую установку\n' \
        "$COLOR_RED" "$COLOR_RESET" >&2
    fi
  fi

  show_failure "$rc" || true
  exit "$rc"
}
trap rollback ERR INT TERM

preflight(){
  cd /
  [[ $EUID -eq 0 ]] || { echo "запустите скрипт от root" >&2; return 1; }
  [[ -f "$SOURCE_DIR/xpanel/__init__.py" ]] || { echo "запускайте скрипт из распакованного каталога SG-Panel" >&2; return 1; }
  grep -q "__version__ = \"$EXPECTED_VERSION\"" "$SOURCE_DIR/xpanel/__init__.py" || { echo "исходники не версии $EXPECTED_VERSION" >&2; return 1; }
  grep -q "SG-Panel RC70 — Latte light theme preview" "$SOURCE_DIR/xpanel/static/app.css" || { echo "в исходниках отсутствует светлая тема SG-Panel RC70" >&2; return 1; }
  grep -q "SG-Panel RC70 — Cluster completion and node-detail overflow hotfix" "$SOURCE_DIR/xpanel/static/app.css" || { echo "в исходниках отсутствует Cluster hotfix SG-Panel RC70" >&2; return 1; }
  grep -q "$EXPECTED_UI_REVISION" "$SOURCE_DIR/xpanel/templates/base.html" || { echo "в шаблоне отсутствует ревизия CSS SG-Panel RC70" >&2; return 1; }
  for command in rsync python3 curl; do
    command -v "$command" >/dev/null || { echo "не найден $command" >&2; return 1; }
  done

  # При прямой первой установке пароль принимается до начала любых изменений.
  if [[ ! -f /etc/xpanel-mvp/web.env && -z "${XPANEL_ADMIN_PASSWORD:-}" ]]; then
    local password confirm
    read -r -s -p "Пароль администратора панели (не менее 8 символов): " password
    printf '\n'
    read -r -s -p "Повторите пароль: " confirm
    printf '\n'
    [[ ${#password} -ge 8 ]] || { echo "пароль должен содержать не менее 8 символов" >&2; return 1; }
    [[ "$password" == "$confirm" ]] || { echo "пароли не совпадают" >&2; return 1; }
    export XPANEL_ADMIN_PASSWORD="$password"
  fi
}

backup_stage(){
  mkdir -p "$BACKUP_ROOT"
  if [[ -d "$TARGET" ]]; then
    OLD_EXISTS=1
    cp -a "$TARGET" "$BACKUP_ROOT/xpanel-mvp"
  fi
  if [[ -f /etc/xpanel-mvp/web.env ]]; then
    cp -a /etc/xpanel-mvp/web.env "$BACKUP_ROOT/web.env"
  fi
  if [[ -f /etc/xpanel-mvp/panel-access.env ]]; then
    cp -a /etc/xpanel-mvp/panel-access.env "$BACKUP_ROOT/panel-access.env"
  fi
  if [[ -f /etc/xpanel-mvp/install-complete.env ]]; then
    cp -a /etc/xpanel-mvp/install-complete.env "$BACKUP_ROOT/install-complete.env"
  fi
  if [[ -f /etc/systemd/system/xpanel-web.service ]]; then
    cp -a /etc/systemd/system/xpanel-web.service "$BACKUP_ROOT/xpanel-web.service"
  fi
  if [[ -f /usr/local/etc/xray/config.json ]]; then
    OLD_XRAY_CONFIG_EXISTS=1
    cp -a /usr/local/etc/xray/config.json "$BACKUP_ROOT/xray-config.json"
  fi
  if [[ -d /etc/xpanel-mvp/warp ]]; then
    cp -a /etc/xpanel-mvp/warp "$BACKUP_ROOT/warp"
  fi
  return 0
}

copy_stage(){
  ROLLBACK_NEEDED=1
  systemctl stop "$SERVICE" 2>/dev/null || true
  mkdir -p "$TARGET"
  rsync -a --delete \
    --exclude='.git/' --exclude='.venv/' --exclude='data/' --exclude='backups/' \
    --exclude='__pycache__/' --exclude='*.pyc' \
    "$SOURCE_DIR/" "$TARGET/"
  mkdir -p "$TARGET/data" "$TARGET/backups"
  if [[ -f "$BACKUP_ROOT/xpanel-mvp/data/panel.db" ]]; then
    cp -a "$BACKUP_ROOT/xpanel-mvp/data/panel.db" "$TARGET/data/panel.db"
  fi
}

python_stage(){
  cd "$TARGET"
  if ! bash deploy/install-wgcf-cli.sh; then
    WGCF_WARNING=1
    log "WARNING: wgcf-cli was not installed; SG-Panel works, but WARP creation is unavailable until the helper is installed"
  fi
  [[ -x .venv/bin/python ]] || python3 -m venv .venv
  .venv/bin/pip install --no-cache-dir -q --upgrade pip
  .venv/bin/pip install --no-cache-dir -q -r requirements.txt
  .venv/bin/python -m xpanel init-db
  SERVER_COUNT="$(.venv/bin/python - <<'PY_SERVER_COUNT'
from xpanel.db import connect
with connect() as con:
    print(con.execute("SELECT COUNT(*) FROM server_settings").fetchone()[0])
PY_SERVER_COUNT
)"
}

xray_stage(){
  cd "$TARGET"
  if [[ "$SERVER_COUNT" != "0" ]]; then
    log "Включаю Stats API и безопасно применяю конфигурацию Xray"
    .venv/bin/python -m xpanel apply
  fi
}

web_stage(){
  cd "$TARGET"
  if [[ ! -f /etc/xpanel-mvp/web.env ]]; then
    bash deploy/install-gui.sh
  else
    python3 - /etc/xpanel-mvp/web.env <<'PY_WEB_ENV'
from pathlib import Path
import os
import sys
path=Path(sys.argv[1])
defaults={
    'XPANEL_BIND_ADDRESS':os.environ.get('XPANEL_BIND_ADDRESS','0.0.0.0'),
    'XPANEL_PORT':os.environ.get('XPANEL_PORT','8080'),
    'XPANEL_SECURE_COOKIES':os.environ.get('XPANEL_SECURE_COOKIES','0'),
    'XPANEL_TRUST_PROXY_HEADERS':os.environ.get('XPANEL_TRUST_PROXY_HEADERS','0'),
}
lines=path.read_text(encoding='utf-8').splitlines()
keys={line.split('=',1)[0] for line in lines if '=' in line}
for key,value in defaults.items():
    if key not in keys: lines.append(f'{key}={value}')
path.write_text('\n'.join(lines)+'\n', encoding='utf-8')
path.chmod(0o600)
PY_WEB_ENV
    bash deploy/install-service.sh
    bash deploy/install-maintenance.sh
    systemctl restart "$SERVICE"
  fi
}

validate_stage(){
  cd "$TARGET"
  if [[ "$SERVER_COUNT" != "0" ]]; then
    .venv/bin/python -m xpanel collect-traffic --online --strict
  fi
  sleep 3

  local cli_version bind port health_host http_body css_body
  cli_version="$(.venv/bin/python -m xpanel --version | awk '{print $2}')"
  [[ "$cli_version" == "$EXPECTED_VERSION" ]] || { echo "CLI сообщает версию $cli_version"; return 1; }
  systemctl is-active --quiet "$SERVICE" || { echo "служба $SERVICE не active"; return 1; }
  systemctl is-active --quiet xpanel-traffic.timer || { echo "служба xpanel-traffic.timer не active"; return 1; }

  if ! bash deploy/repair-panel-access.sh; then
    ACCESS_WARNING=1
    log "WARNING: автоматическое исправление публичного адреса не выполнено; текущий доступ оставлен без изменений"
  fi

  bind="$(grep -E '^XPANEL_BIND_ADDRESS=' /etc/xpanel-mvp/web.env | tail -1 | cut -d= -f2- || true)"
  port="$(grep -E '^XPANEL_PORT=' /etc/xpanel-mvp/web.env | tail -1 | cut -d= -f2- || true)"
  bind="${bind:-0.0.0.0}"
  port="${port:-8080}"
  case "$bind" in
    0.0.0.0|127.0.0.1) health_host="127.0.0.1" ;;
    ::|::0|::1) health_host="[::1]" ;;
    *) health_host="$bind" ;;
  esac
  http_body="$(curl -fsS "http://$health_host:$port/login")"
  grep -q "v$EXPECTED_VERSION" <<<"$http_body" || { echo "GUI не отдаёт версию $EXPECTED_VERSION"; return 1; }
  grep -q "$EXPECTED_UI_REVISION" <<<"$http_body" || { echo "GUI не подключает CSS SG-Panel RC70"; return 1; }
  css_body="$(curl -fsS "http://$health_host:$port/static/app.css?v=$EXPECTED_VERSION-$EXPECTED_UI_REVISION")"
  grep -q "SG-Panel RC70 — Latte light theme preview" <<<"$css_body" || { echo "веб-служба не отдаёт светлую тему SG-Panel RC70"; return 1; }
  grep -q "SG-Panel RC70 — Cluster completion and node-detail overflow hotfix" <<<"$css_body" || { echo "веб-служба не отдаёт Cluster hotfix SG-Panel RC70"; return 1; }
}

main(){
  install -d -m 0755 "$(dirname "$LOG_FILE")"
  : >"$LOG_FILE"
  chmod 0600 "$LOG_FILE"

  step_begin "Запуск обновления SG-Panel RC70"
  preflight >>"$LOG_FILE" 2>&1
  step_ok
  printf '[SG-Panel] Все параметры приняты. Дальнейшее обновление не потребует ввода.\n'
  run_stage "Создание резервной копии" backup_stage
  run_stage "Копирование SG-Panel $EXPECTED_VERSION" copy_stage
  run_stage "Подготовка Python, базы данных и компонентов" python_stage
  run_stage "Проверка и применение конфигурации Xray" xray_stage
  run_stage "Установка и запуск веб-служб SG-Panel" web_stage
  run_stage "Финальная проверка служб и интерфейса" validate_stage

  ROLLBACK_NEEDED=0
  trap - ERR INT TERM
  stop_spinner

  printf '\n[SG-Panel] [%sГОТОВО%s] SG-Panel %s, UI %s установлена и проверена.\n' \
    "$COLOR_GREEN" "$COLOR_RESET" "$EXPECTED_VERSION" "$EXPECTED_UI_REVISION"
  printf '[SG-Panel] Резервная копия: %s\n' "$BACKUP_ROOT"
  printf '[SG-Panel] Журнал: %s\n' "$LOG_FILE"
  if [[ $WGCF_WARNING -eq 1 ]]; then
    printf '[SG-Panel] [%sПРЕДУПРЕЖДЕНИЕ%s] WARP-helper не обновлён; основная панель работает.\n' "$COLOR_YELLOW" "$COLOR_RESET"
  fi
  if [[ $ACCESS_WARNING -eq 1 ]]; then
    printf '[SG-Panel] [%sПРЕДУПРЕЖДЕНИЕ%s] Публичный адрес оставлен без автоматического исправления.\n' "$COLOR_YELLOW" "$COLOR_RESET"
  fi
}

main "$@"
