#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.10.0-rc70"
EXPECTED_BUILD="FIX40"
EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_VERSION_FILE="$SOURCE_DIR/deploy/xray-version.env"
[[ -r "$XRAY_VERSION_FILE" ]] || { echo "не найден единый файл версии Xray: $XRAY_VERSION_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$XRAY_VERSION_FILE"
[[ "${XRAY_VERSION:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "некорректная версия Xray в $XRAY_VERSION_FILE" >&2; exit 1; }
DEFAULT_PANEL_PORT="61443"
DEFAULT_BACKEND_PORT="8080"
DEFAULT_REALITY_DEST="www.bing.com:443"
DEFAULT_REALITY_SNI="www.bing.com"
DEFAULT_USER="sg-admin"
DEFAULT_INSTANCE_NAME="SG-Panel"
TARGET="/opt/xpanel-mvp"
SERVICE="xpanel-web"
INSTALL_STATE_DIR="/etc/xpanel-mvp"
INSTALL_MARKER="$INSTALL_STATE_DIR/install-complete.env"
PANEL_STATE_FILE="$INSTALL_STATE_DIR/panel-access.env"
RECONFIGURE=0
PARTIAL_INSTALL=0
PRESERVE_PANEL_ACCESS=0

LOG_FILE="${SG_PANEL_INSTALL_LOG:-/var/log/sg-panel-install-$(date -u +%Y%m%d-%H%M%S).log}"
STEP_LABEL=""
STEP_STARTED=0
STEP_ACTIVE=0
STEP_SPINNER_PID=""

if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  COLOR_GREEN=$'\033[1;32m'
  COLOR_RED=$'\033[1;31m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_GREEN=""; COLOR_RED=""; COLOR_RESET=""
fi

log(){
  if [[ -e "$LOG_FILE" ]]; then
    printf '[SG-Panel] %s\n' "$*" >>"$LOG_FILE"
  fi
}

print_service_summary(){
  printf '\n[SG-Panel] SG-Panel: %sactive%s\n' "$COLOR_GREEN" "$COLOR_RESET"
  printf '[SG-Panel] Nginx:    %sactive%s\n' "$COLOR_GREEN" "$COLOR_RESET"
  printf '[SG-Panel] Xray:     %sactive%s\n' "$COLOR_GREEN" "$COLOR_RESET"
}

stage(){
  printf '\n[SG-Panel] Этап %s/%s: %s\n' "$1" "$2" "$3"
  printf '[SG-Panel] Этап %s/%s: %s\n' "$1" "$2" "$3" >>"$LOG_FILE"
}

stop_spinner(){
  if [[ -n "$STEP_SPINNER_PID" ]]; then
    kill "$STEP_SPINNER_PID" 2>/dev/null || true
    wait "$STEP_SPINNER_PID" 2>/dev/null || true
    STEP_SPINNER_PID=""
  fi
}

spinner_loop(){
  local label="$1" started="$2" frame_index=0 elapsed
  local frames='|/-\'
  while true; do
    elapsed=$((SECONDS - started))
    printf '\r[SG-Panel] [%s%s%s] %s (%s сек)' \
      "$COLOR_GREEN" "${frames:frame_index%4:1}" "$COLOR_RESET" "$label" "$elapsed"
    frame_index=$((frame_index + 1))
    sleep 0.25
  done
}

step_begin(){
  stop_spinner
  STEP_LABEL="$1"
  STEP_STARTED=$SECONDS
  STEP_ACTIVE=1
  printf '\n[SG-Panel] %s\n' "$STEP_LABEL" >>"$LOG_FILE"
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    spinner_loop "$STEP_LABEL" "$STEP_STARTED" &
    STEP_SPINNER_PID=$!
  else
    printf '[SG-Panel] [..] %s...\n' "$STEP_LABEL"
  fi
}

step_ok(){
  local elapsed=$((SECONDS - STEP_STARTED))
  stop_spinner
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    printf '\r[SG-Panel] [%sOK%s] %s (%s сек)\033[K\n' \
      "$COLOR_GREEN" "$COLOR_RESET" "$STEP_LABEL" "$elapsed"
  else
    printf '[SG-Panel] [OK] %s (%s сек)\n' "$STEP_LABEL" "$elapsed"
  fi
  printf '[SG-Panel] [OK] %s (%s сек)\n' "$STEP_LABEL" "$elapsed" >>"$LOG_FILE"
  STEP_ACTIVE=0
}

fail(){
  local message="$*" elapsed=0
  if (( STEP_ACTIVE == 1 )); then
    elapsed=$((SECONDS - STEP_STARTED))
    stop_spinner
    if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
      printf '\r[SG-Panel] [%sОШИБКА%s] %s (%s сек)\033[K\n' \
        "$COLOR_RED" "$COLOR_RESET" "$STEP_LABEL" "$elapsed" >&2
    else
      printf '[SG-Panel] [ОШИБКА] %s (%s сек)\n' "$STEP_LABEL" "$elapsed" >&2
    fi
    STEP_ACTIVE=0
  fi
  printf '[SG-Panel] [ERROR] %s\n' "$message" >&2
  if [[ -s "$LOG_FILE" ]]; then
    printf '\nПоследние строки журнала %s:\n' "$LOG_FILE" >&2
    tail -n 50 "$LOG_FILE" >&2 || true
  fi
  exit 1
}

cleanup_spinner(){ stop_spinner; }
trap cleanup_spinner EXIT

run_logged(){
  local label="$1"; shift
  printf '[SG-Panel] %s\n' "$label" >>"$LOG_FILE"
  "$@" >>"$LOG_FILE" 2>&1
}

run_stage(){
  local label="$1" rc; shift
  step_begin "$label"
  set +e
  ( set -Eeuo pipefail; "$@" ) >>"$LOG_FILE" 2>&1
  rc=$?
  set -e
  if (( rc != 0 )); then
    fail "$label завершился с кодом $rc"
  fi
  step_ok
}

wait_notice(){
  local message="$*"
  printf '[SG-Panel] %s\n' "$message" >>"$LOG_FILE"
  if [[ -w /dev/tty ]]; then
    printf '\r[SG-Panel] %s\033[K\n' "$message" >/dev/tty 2>/dev/null || true
  fi
}

package_manager_busy_details(){
  local locks=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local lock pids pid command_line output found=0

  if command -v fuser >/dev/null 2>&1; then
    for lock in "${locks[@]}"; do
      pids="$(fuser "$lock" 2>/dev/null || true)"
      [[ -n "$pids" ]] || continue
      found=1
      for pid in $pids; do
        command_line="$(ps -p "$pid" -o args= 2>/dev/null || true)"
        printf '%s: PID %s%s\n' \
          "$lock" "$pid" "${command_line:+ · $command_line}"
      done
    done
    (( found == 1 )) && return 0
  fi

  output="$({
    pgrep -a -x apt 2>/dev/null || true
    pgrep -a -x apt-get 2>/dev/null || true
    pgrep -a -x dpkg 2>/dev/null || true
    pgrep -a -f '(^|[[:space:]/])[u]nattended-upgrade([[:space:]]|$)' 2>/dev/null || true
  } | awk 'NF && !seen[$0]++')"
  [[ -n "$output" ]] || return 1
  printf '%s\n' "$output"
}

package_manager_busy(){
  package_manager_busy_details >/dev/null 2>&1
}

wait_for_apt(){
  local waited=0 timeout=300 detail=""
  while package_manager_busy; do
    if (( waited % 15 == 0 )); then
      detail="$(package_manager_busy_details 2>/dev/null | tr '\n' ';' | sed 's/;*$//' || true)"
      [[ -n "$detail" ]] || detail="активна блокировка APT/DPKG"
      wait_notice "APT/DPKG занят: $detail · ожидание ${waited}/${timeout} сек."
    fi
    if (( waited >= timeout )); then
      detail="$(package_manager_busy_details 2>/dev/null | tr '\n' ';' | sed 's/;*$//' || true)"
      wait_notice "APT/DPKG не освободил блокировку за ${timeout} секунд: ${detail:-владелец не определён}."
      fail "apt/dpkg не освободил блокировку за ${timeout} секунд"
    fi
    sleep 5
    waited=$((waited + 5))
  done
  if (( waited > 0 )); then
    wait_notice "APT/DPKG блокировка снята; установка продолжается."
  fi
}

wait_for_service_active(){
  local unit="$1" label="${2:-$1}" attempts="${3:-20}" delay="${4:-3}"
  local attempt state=""
  for ((attempt=1; attempt<=attempts; attempt++)); do
    state="$(systemctl is-active "$unit" 2>/dev/null || true)"
    if [[ "$state" == "active" ]]; then
      return 0
    fi
    sleep "$delay"
  done
  echo "$label не находится в active после $((attempts * delay)) секунд" >&2
  systemctl --no-pager --full status "$unit" >&2 2>/dev/null || true
  journalctl -u "$unit" -n 60 --no-pager >&2 2>/dev/null || true
  return 1
}

migrate_reality_edge_web_port(){
  local state="/etc/xpanel-mvp/reality-edge.env"
  [[ -f "$state" ]] || return 0
  if grep -qx 'WEB_PORT=9443' "$state"; then
    sed -i 's/^WEB_PORT=9443$/WEB_PORT=10443/' "$state"
    printf '[SG-Panel] REALITY fallback: внутренний WEB_PORT перенесён 9443 -> 10443\n' >>"$LOG_FILE"
  fi
}

ensure_xray_version(){
  local current="" backup_dir="" installed="" config="/usr/local/etc/xray/config.json"
  local xray_install_script="" xray_install_url=""
  local -a curl_args=(
    --retry 5
    --retry-all-errors
    --retry-delay 3
    --connect-timeout 15
    --max-time 180
  )
  if [[ -x /usr/local/bin/xray ]]; then
    current="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"
  fi
  if [[ "$current" == "$XRAY_VERSION" ]]; then
    systemctl enable xray >/dev/null 2>&1 || true
    return 0
  fi
  if [[ -n "$current" ]] && [[ "$(printf '%s\n%s\n' "$current" "$XRAY_VERSION" | sort -V | tail -n 1)" == "$current" ]]; then
    if [[ -s "$config" ]] && ! /usr/local/bin/xray run -test -config "$config"; then
      echo "текущий config.json не прошёл проверку установленным Xray $current" >&2
      return 1
    fi
    systemctl enable xray >/dev/null 2>&1 || true
    if [[ -s "$config" ]]; then
      systemctl restart xray
      wait_for_service_active xray "установленный Xray $current" || {
        echo "установленный Xray $current не запустился с текущей конфигурацией" >&2
        return 1
      }
    fi
    log "Сохраняю установленный Xray $current: он новее рекомендуемой версии $XRAY_VERSION"
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

  xray_install_script="$(mktemp /tmp/sg-panel-xray-install.XXXXXX.sh)"
  for xray_install_url in \
    "https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh" \
    "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
  do
    rm -f "$xray_install_script"
    if curl -fL "${curl_args[@]}" "$xray_install_url" -o "$xray_install_script"; then
      break
    fi
  done

  if [[ ! -s "$xray_install_script" ]]; then
    echo "не удалось скачать официальный установщик Xray после повторных попыток" >&2
    rm -f "$xray_install_script"
    rollback_xray
    return 1
  fi
  if ! bash -n "$xray_install_script"; then
    echo "скачанный официальный установщик Xray повреждён" >&2
    rm -f "$xray_install_script"
    rollback_xray
    return 1
  fi
  if ! bash "$xray_install_script" install --version "$XRAY_VERSION"; then
    rm -f "$xray_install_script"
    rollback_xray
    return 1
  fi
  rm -f "$xray_install_script"

  if [[ ! -x /usr/local/bin/xray ]]; then
    echo "официальный установщик завершился без /usr/local/bin/xray" >&2
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

  # На совершенно новой Ubuntu официальный Xray-install создаёт временный
  # config.json со значением {}. Такой placeholder синтаксически корректен,
  # но Xray может завершиться сразу, потому что рабочих inbound/outbound ещё нет.
  # Настоящий конфиг SG-Panel создаётся на этапе 8/9; там же служба обязана
  # запуститься и затем строго проверяется на этапе 9/9.
  local bootstrap_placeholder=0
  if [[ ! -d "$TARGET" && -s "$config" ]]; then
    if python3 - "$config" <<'PY_XRAY_PLACEHOLDER'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        value = json.load(handle)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if value == {} else 1)
PY_XRAY_PLACEHOLDER
    then
      bootstrap_placeholder=1
    fi
  fi

  if [[ -s "$config" && "$bootstrap_placeholder" -eq 0 ]]; then
    systemctl restart xray
    wait_for_service_active xray "Xray $XRAY_VERSION" || {
      echo "Xray $XRAY_VERSION не запустился с текущей конфигурацией" >&2
      rollback_xray
      return 1
    }
  else
    systemctl stop xray >/dev/null 2>&1 || true
    log "Xray $XRAY_VERSION установлен; запуск отложен до создания рабочего конфига SG-Panel"
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
grep -Fq "__version__ = \"$EXPECTED_VERSION\"" "$SOURCE_DIR/xpanel/__init__.py" || fail "исходники не версии ядра $EXPECTED_VERSION"
grep -Fq "__build__ = \"$EXPECTED_BUILD\"" "$SOURCE_DIR/xpanel/__init__.py" || fail "исходники не сборки $EXPECTED_BUILD"
grep -Fq "__release_label__ = \"$EXPECTED_RELEASE_LABEL\"" "$SOURCE_DIR/xpanel/__init__.py" || fail "исходники не релиза $EXPECTED_RELEASE_LABEL"
[[ -f "$SOURCE_DIR/xpanel/static/fix40-cascade-steps-ui20.css" ]] || fail "в исходниках отсутствует Cascade Steps UI20"
[[ -f "$SOURCE_DIR/xpanel/static/fix40-cluster-restore-ui21.css" ]] || fail "в исходниках отсутствует Cluster Restore UI21"
grep -Fq "Restore the compact Cluster and SG-Node card" "$SOURCE_DIR/xpanel/static/fix40-cluster-restore-ui21.css" || fail "CSS Cluster Restore UI21 повреждён"
grep -Fq 'fix40-cluster-restore-ui21.css' "$SOURCE_DIR/xpanel/templates/base.html" || fail "Cluster Restore UI21 не подключён"
[[ -f "$SOURCE_DIR/xpanel/static/fix40-node-detail-polish-ui22.css" ]] || fail "в исходниках отсутствует Node Detail Polish UI22"
grep -Fq 'remove the inherited gray slabs' "$SOURCE_DIR/xpanel/static/fix40-node-detail-polish-ui22.css" || fail "CSS Node Detail Polish UI22 повреждён"
grep -Fq 'fix40-node-detail-polish-ui22.css' "$SOURCE_DIR/xpanel/templates/base.html" || fail "Node Detail Polish UI22 не подключён"
grep -Fq 'HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)' "$SOURCE_DIR/xpanel/service.py" || fail "в исходниках отсутствует контракт Salamander UI23"
grep -Fq 'def _apply_hysteria_salamander_to_inbound' "$SOURCE_DIR/xpanel/service.py" || fail "в исходниках отсутствует безопасное слияние FinalMask UI23"
grep -Fq 'obfs_mode TEXT NOT NULL DEFAULT' "$SOURCE_DIR/xpanel/db.py" || fail "в исходниках отсутствует миграция Salamander UI23"
grep -Fq 'data-hysteria-salamander-card' "$SOURCE_DIR/xpanel/templates/settings.html" || fail "в интерфейсе отсутствует Salamander UI23"
grep -Fq 'build_hysteria2_uri' "$SOURCE_DIR/xpanel/service.py" || fail "в исходниках отсутствует единый URI builder Salamander UI23"
grep -Fq 'compact-node-row' "$SOURCE_DIR/xpanel/templates/nodes.html" || fail "компактный список Cluster не найден"
grep -Fq 'node-restore-status' "$SOURCE_DIR/xpanel/templates/node_detail.html" || fail "компактная карточка SG-Node не найдена"
! grep -Fq 'class="node-simple-nav"' "$SOURCE_DIR/xpanel/templates/node_detail.html" || fail "в карточке SG-Node осталась дублирующая навигация"
grep -Fq 'WORKER_VERSION = "0.7.0"' "$SOURCE_DIR/node_agent/sg_node_worker.py" || fail "в исходниках отсутствует Worker UI19"
grep -Fq 'def upsert_cascade_access' "$SOURCE_DIR/node_agent/sg_node_worker.py" || fail "в Worker отсутствует безопасная операция Cascade"
! grep -Fq '<select' "$SOURCE_DIR/xpanel/templates/cascade.html" || fail "в Cascade остался системный select"
install -d -m 0755 "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 0600 "$LOG_FILE"

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

step_begin "Запуск мастера SG-Panel RC70"

if existing_install_is_complete && [[ $RECONFIGURE -eq 0 ]]; then
  CURRENT_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version 2>/dev/null | awk '{print $2}' || true)"
  CURRENT_VERSION="${CURRENT_VERSION:-неизвестна}"
  log "Обнаружена завершённая SG-Panel $CURRENT_VERSION"
  log "Журнал: $LOG_FILE"

  update_panel_stage(){ SG_PANEL_SUPPRESS_SUCCESS_SUMMARY=1 bash "$SOURCE_DIR/install-or-upgrade.sh"; }
  validate_updated_panel_stage(){
    NEW_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version | awk '{print $2}')"
    [[ "$NEW_VERSION" == "$EXPECTED_VERSION" ]] || return 1
    wait_for_service_active "$SERVICE" "SG-Panel"
    wait_for_service_active xray "Xray"
    wait_for_service_active nginx "Nginx"
  }

  step_ok
  printf '[SG-Panel] Обнаружена SG-Panel %s. Запускаю безопасное обновление.\n' "$CURRENT_VERSION"
  printf '[SG-Panel] Технический журнал: %s\n\n' "$LOG_FILE"
  run_stage "Этап 1/4 · Проверка установленного Xray" ensure_xray_version
  run_stage "Этап 2/4 · Подготовка совместимости и миграций" migrate_reality_edge_web_port
  run_stage "Этап 3/4 · Обновление SG-Panel с резервной копией" update_panel_stage
  run_stage "Этап 4/4 · Финальная проверка служб и версии" validate_updated_panel_stage
  NEW_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version | awk '{print $2}')"
  detect_panel_access
  PANEL_HOST="${PANEL_HOST:-localhost}"
  if [[ "$PANEL_MODE" == "https" ]]; then
    PANEL_URL="https://$PANEL_HOST:$PANEL_PUBLIC_PORT"
  else
    PANEL_URL="http://$PANEL_HOST:$PANEL_PUBLIC_PORT"
  fi
  write_install_marker "$PANEL_MODE" "$PANEL_HOST" "$PANEL_PUBLIC_PORT"
  print_service_summary
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
CURRENT_INSTANCE_NAME="$(existing_db_value 'SELECT instance_name FROM server_settings WHERE id = 1;')"
CURRENT_FIRST_USER="$(existing_db_value 'SELECT name FROM users ORDER BY id LIMIT 1;')"
AUTO_ADDRESS="$(detect_default_address)"
step_ok
XRAY_ADDRESS_DEFAULT="${CURRENT_XRAY_ADDRESS:-$AUTO_ADDRESS}"
INSTANCE_NAME_DEFAULT="${CURRENT_INSTANCE_NAME:-$DEFAULT_INSTANCE_NAME}"
FIRST_USER_DEFAULT="${CURRENT_FIRST_USER:-$DEFAULT_USER}"
REALITY_DEST_DEFAULT="${CURRENT_REALITY_DEST:-$DEFAULT_REALITY_DEST}"
REALITY_SNI_DEFAULT="${CURRENT_REALITY_SNI:-$DEFAULT_REALITY_SNI}"

if [[ "${SG_PANEL_INPUTS_PRECOLLECTED:-0}" == "1" ]]; then
  printf '[SG-Panel] Параметры заранее приняты единым мастером. Дополнительных вопросов не будет.\n\n'
else
  printf '%s\n' \
    "Сначала задайте пароль администратора. Затем установщик соберёт остальные параметры" \
    "и выполнит все действия автоматически без дополнительных вопросов." \
    "Начальная установка работает по HTTP; HTTPS можно включить позже в панели." \
    "Чтобы принять значение в квадратных скобках, нажмите Enter." \
    ""
fi

# На новой установке пароль — самый первый вопрос мастера.
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

if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]]; then
  prompt_value PANEL_PUBLIC_PORT "Публичный HTTP-порт панели" "$DEFAULT_PANEL_PORT"
fi
prompt_value XRAY_ADDRESS "Адрес Xray для клиентов (публичный IP или домен)" "$XRAY_ADDRESS_DEFAULT"
prompt_value INSTANCE_NAME "Имя этого сервера в панели" "$INSTANCE_NAME_DEFAULT"
prompt_value FIRST_USER "Имя первого пользователя" "$FIRST_USER_DEFAULT"
prompt_value REALITY_DEST "Reality target" "$REALITY_DEST_DEFAULT"
prompt_value REALITY_SNI "Reality SNI" "$REALITY_SNI_DEFAULT"

log "Все параметры приняты. Дальнейшая установка не потребует ввода"
log "Журнал: $LOG_FILE"
printf '[SG-Panel] Все параметры приняты. Дальнейшая установка не потребует ввода.\n'
printf '[SG-Panel] Технический журнал: %s\n\n' "$LOG_FILE"

[[ -n "$XRAY_ADDRESS" && "$XRAY_ADDRESS" =~ ^[A-Za-z0-9._:-]+$ ]] || fail "некорректный IP или домен Xray"
[[ -n "$INSTANCE_NAME" ]] || fail "имя сервера не может быть пустым"
[[ ${#INSTANCE_NAME} -le 64 ]] || fail "имя сервера не должно быть длиннее 64 символов"
[[ -n "$FIRST_USER" ]] || fail "имя пользователя не может быть пустым"
[[ "$REALITY_DEST" == *:* ]] || fail "Reality target должен иметь вид host:port"
if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]]; then
  [[ "$PANEL_PUBLIC_PORT" =~ ^[0-9]+$ ]] && (( PANEL_PUBLIC_PORT >= 49152 && PANEL_PUBLIC_PORT <= 65535 )) || fail "выберите порт панели 49152-65535"
  for reserved in 22 80 443 "$DEFAULT_BACKEND_PORT" 8443; do
    [[ "$PANEL_PUBLIC_PORT" != "$reserved" ]] || fail "порт $PANEL_PUBLIC_PORT нельзя использовать для панели"
  done
fi

check_memory_and_disk(){
  local mem_kib root_free_kib root_free_mib
  mem_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
  root_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
  root_free_mib=$(( root_free_kib / 1024 ))

  # Не блокируем установку искусственным фиксированным порогом: реальную
  # пригодность диска подтверждают apt/dpkg и запись каждого компонента.
  log "Свободное место корневого раздела перед установкой: ${root_free_mib} MiB."

  if (( mem_kib < 1572864 )); then
    log "Оперативной памяти меньше 1.5 GiB. Swap автоматически не создаётся; существующий swap сохраняется без изменений."
  fi

  if [[ -f /swapfile ]]; then
    log "Обнаружен существующий /swapfile. Установщик не изменяет и не удаляет его."
  fi
}

install_system_packages(){
  if [[ "${SG_PANEL_SYSTEM_READY:-0}" == "1" ]]; then
    local required
    for required in curl unzip rsync python3 sqlite3 jq nginx certbot openssl setfacl; do
      command -v "$required" >/dev/null 2>&1 || {
        echo "после системного этапа не найден обязательный компонент: $required" >&2
        return 1
      }
    done
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  wait_for_apt
  dpkg --configure -a
  apt-get -o DPkg::Lock::Timeout=30 -o Dpkg::Use-Pty=0 update -qq
  apt-get -o DPkg::Lock::Timeout=30 -o Dpkg::Use-Pty=0 install -y \
    curl ca-certificates unzip rsync zstd psmisc \
    python3 python3-venv python3-pip \
    sqlite3 jq iproute2 dnsutils \
    nginx libnginx-mod-stream certbot openssl acl
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
  SG_PANEL_SUPPRESS_SUCCESS_SUMMARY=1 bash "$SOURCE_DIR/install-or-upgrade.sh"
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
      --fingerprint firefox \
      --flow xtls-rprx-vision >/dev/null
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

  python3 - data/panel.db "$INSTANCE_NAME" <<'PY_INSTANCE_NAME'
import sqlite3
import sys
path, instance_name = sys.argv[1:]
with sqlite3.connect(path) as con:
    columns = {row[1] for row in con.execute("PRAGMA table_info(server_settings)")}
    if "instance_name" in columns:
        con.execute("UPDATE server_settings SET instance_name=? WHERE id=1", (instance_name.strip(),))
PY_INSTANCE_NAME

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
  local cli_version xray_version mode host port url login_body
  cli_version="$(.venv/bin/python -m xpanel --version | awk '{print $2}')"
  [[ "$cli_version" == "$EXPECTED_VERSION" ]] || fail "неожиданная версия CLI: $cli_version"
  xray_version="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"
  [[ "$xray_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "не удалось определить версию Xray: $xray_version"
  [[ "$(printf '%s\n%s\n' "$xray_version" "$XRAY_VERSION" | sort -V | tail -n 1)" == "$xray_version" ]] || fail "версия Xray $xray_version старее рекомендуемой $XRAY_VERSION"
  wait_for_service_active xpanel-web "xpanel-web" || fail "xpanel-web не active"
  wait_for_service_active xray "xray" || fail "xray не active"
  wait_for_service_active nginx "nginx" || fail "nginx не active"
  wait_for_service_active xpanel-traffic.timer "xpanel-traffic.timer" || fail "xpanel-traffic.timer не active"
  .venv/bin/python -m xpanel collect-traffic --online --strict

  detect_panel_access
  mode="$PANEL_MODE"
  host="${PANEL_HOST:-$XRAY_ADDRESS}"
  port="$PANEL_PUBLIC_PORT"
  if [[ "$mode" == "https" ]]; then
    url="https://$host:$port"
    login_body="$(curl -kfsS --max-time 5 --resolve "$host:$port:127.0.0.1" "$url/login")"
  else
    login_body="$(curl -fsS --max-time 5 -H "Host: $host" "http://127.0.0.1:$port/login")"
  fi
  grep -Fq "$EXPECTED_BUILD" <<<"$login_body" || fail "GUI не отдаёт маркер сборки $EXPECTED_BUILD"
  local clients_css
  if [[ "$mode" == "https" ]]; then
    clients_css="$(curl -kfsS --max-time 5 --resolve "$host:$port:127.0.0.1" \
      "$url/static/fix40-clients-layout-hotfix3.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-clients-layout-hotfix3")"
  else
    clients_css="$(curl -fsS --max-time 5 -H "Host: $host" \
      "http://127.0.0.1:$port/static/fix40-clients-layout-hotfix3.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-clients-layout-hotfix3")"
  fi
  grep -Fq "Clients Layout Hotfix 3" <<<"$clients_css" || fail "GUI не отдаёт Clients Layout Hotfix 3"
  local global_css
  if [[ "$mode" == "https" ]]; then
    global_css="$(curl -kfsS --max-time 5 --resolve "$host:$port:127.0.0.1" \
      "$url/static/fix40-light-buttons-theme-icon-hotfix9.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-interface-cleanup-hotfix5")"
  else
    global_css="$(curl -fsS --max-time 5 -H "Host: $host" \
      "http://127.0.0.1:$port/static/fix40-light-buttons-theme-icon-hotfix9.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-interface-cleanup-hotfix5")"
  fi
  grep -Fq "Interface Cleanup Hotfix 5" <<<"$global_css" || fail "GUI не отдаёт Interface Cleanup Hotfix 5"
  if [[ "$mode" == "https" ]]; then
    global_css="$(curl -kfsS --max-time 5 --resolve "$host:$port:127.0.0.1" \
      "$url/static/fix40-light-buttons-theme-icon-hotfix9.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-ui-compact-hotfix6")"
  else
    global_css="$(curl -fsS --max-time 5 -H "Host: $host" \
      "http://127.0.0.1:$port/static/fix40-light-buttons-theme-icon-hotfix9.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-ui-compact-hotfix6")"
  fi
  grep -Fq "UI Compact Hotfix 6" <<<"$global_css" || fail "GUI не отдаёт UI Compact Hotfix 6"
  local tabs_css
  tabs_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-light-buttons-theme-icon-hotfix9.css")"
  grep -Fq "Global Tabs and Dark Buttons Hotfix 7" <<<"$tabs_css" || fail "GUI не отдаёт Global Tabs and Dark Buttons Hotfix 7"
  local ui8_css
  ui8_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-light-buttons-theme-icon-hotfix9.css")"
  grep -Fq "Interface Verification Hotfix 8" <<<"$ui8_css" || fail "GUI не отдаёт Interface Verification Hotfix 8"
  local ui9_css
  ui9_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-light-buttons-theme-icon-hotfix9.css")"
  grep -Fq "Light Button Gradient and Theme Icon Hotfix 9" <<<"$ui9_css" || fail "GUI не отдаёт Light Button Gradient and Theme Icon Hotfix 9"
  write_install_marker "$mode" "$host" "$port"
}

check_panel_port_stage(){
  if [[ $PRESERVE_PANEL_ACCESS -eq 0 ]] \
    && ss -lntH | awk '{print $4}' | grep -Eq "(^|:)$PANEL_PUBLIC_PORT$"; then
    nginx -T 2>/dev/null \
      | grep -Eq "listen[[:space:]]+${PANEL_PUBLIC_PORT}([[:space:]]|;)" \
      || return 1
  fi
}

apply_and_publish_stage(){ apply_xray_stage; configure_panel_access_stage; }

run_stage "Этап 1/9 · Проверка памяти и свободного места" check_memory_and_disk
run_stage "Этап 2/9 · Обновление системы и установка пакетов" install_system_packages
run_stage "Этап 3/9 · Проверка публичного порта панели" check_panel_port_stage
run_stage "Этап 4/9 · Установка или проверка Xray" install_xray_stage
run_stage "Этап 5/9 · Установка SG-Panel" install_panel_stage
unset XPANEL_ADMIN_PASSWORD XPANEL_ADMIN_PASSWORD_2 2>/dev/null || true
run_stage "Этап 6/9 · Настройка сервера и первого пользователя" configure_panel_data_stage
run_stage "Этап 7/9 · Подготовка REALITY fallback" migrate_reality_edge_web_port
run_stage "Этап 8/9 · Применение Xray и публикация панели" apply_and_publish_stage
run_stage "Этап 9/9 · Проверка служб, конфигурации и адреса панели" validate_installation_stage

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
ACTIVE_XRAY_VERSION="v$(/usr/local/bin/xray version | awk 'NR==1 {print $2}' | sed 's/^v//')"

print_service_summary
