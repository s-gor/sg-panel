#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.10.0-rc70"
EXPECTED_BUILD="FIX40"
EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"
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
OLD_XRAY_SECRET_EXISTS=0
SERVER_COUNT=0
CURRENT_STEP="Подготовка"
SPINNER_PID=""
STEP_STARTED=0
WGCF_WARNING=0
ACCESS_WARNING=0
OLD_NODE_AGENT_EXISTS=0
OLD_NODE_WORKER_EXISTS=0

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
    if [[ -f "$BACKUP_ROOT/xray-secrets.env" ]]; then
      mkdir -p /etc/xpanel-mvp
      cp -a "$BACKUP_ROOT/xray-secrets.env" /etc/xpanel-mvp/xray-secrets.env
      chmod 0600 /etc/xpanel-mvp/xray-secrets.env
    elif [[ $OLD_XRAY_SECRET_EXISTS -eq 0 ]]; then
      rm -f /etc/xpanel-mvp/xray-secrets.env
    fi
    if [[ -f "$BACKUP_ROOT/sg-node-agent.py" ]]; then
      install -D -o root -g root -m 0755 "$BACKUP_ROOT/sg-node-agent.py" /opt/sg-node/sg_node_agent.py
    elif [[ $OLD_NODE_AGENT_EXISTS -eq 0 ]]; then
      rm -f /opt/sg-node/sg_node_agent.py
    fi
    if [[ -f "$BACKUP_ROOT/sg-node-worker.py" ]]; then
      install -D -o root -g root -m 0755 "$BACKUP_ROOT/sg-node-worker.py" /usr/local/libexec/sg-node-worker.py
    elif [[ $OLD_NODE_WORKER_EXISTS -eq 0 ]]; then
      rm -f /usr/local/libexec/sg-node-worker.py
    fi
    systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
    systemctl restart xray >>"$LOG_FILE" 2>&1 || true
    if [[ -f /etc/systemd/system/sg-node-worker.service ]]; then
      systemctl restart sg-node-worker.service >>"$LOG_FILE" 2>&1 || true
    fi
    if [[ -f /etc/systemd/system/sg-node-agent.service ]]; then
      systemctl restart sg-node-agent.service >>"$LOG_FILE" 2>&1 || true
    fi
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


supported_ubuntu_version(){
  local version="${1:-}"
  [[ "$version" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  command -v dpkg >/dev/null 2>&1 || return 1
  dpkg --compare-versions "$version" ge "22.04"
}

check_supported_platform(){
  [[ -r /etc/os-release ]] || { echo "не удалось определить операционную систему" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || {
    echo "поддерживается Ubuntu 22.04 и новее; обнаружена ${PRETTY_NAME:-unknown}" >&2
    return 1
  }
  supported_ubuntu_version "${VERSION_ID:-}" || {
    echo "нужна Ubuntu 22.04 или новее; обнаружена ${VERSION_ID:-unknown}" >&2
    return 1
  }
  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) echo "поддерживаются архитектуры amd64 и arm64; обнаружена $(uname -m)" >&2; return 1 ;;
  esac
}

preflight(){
  cd /
  [[ $EUID -eq 0 ]] || { echo "запустите скрипт от root" >&2; return 1; }
  check_supported_platform
  [[ -f "$SOURCE_DIR/xpanel/__init__.py" ]] || { echo "запускайте скрипт из распакованного каталога SG-Panel" >&2; return 1; }
  grep -Fq "__version__ = \"$EXPECTED_VERSION\"" "$SOURCE_DIR/xpanel/__init__.py" || { echo "исходники не версии ядра $EXPECTED_VERSION" >&2; return 1; }
  grep -Fq "__build__ = \"$EXPECTED_BUILD\"" "$SOURCE_DIR/xpanel/__init__.py" || { echo "исходники не сборки $EXPECTED_BUILD" >&2; return 1; }
  grep -Fq "__release_label__ = \"$EXPECTED_RELEASE_LABEL\"" "$SOURCE_DIR/xpanel/__init__.py" || { echo "исходники не релиза $EXPECTED_RELEASE_LABEL" >&2; return 1; }
  grep -q "SG-Panel RC70 — Latte light theme preview" "$SOURCE_DIR/xpanel/static/app.css" || { echo "в исходниках отсутствует светлая тема SG-Panel RC70" >&2; return 1; }
  grep -q "SG-Panel RC70 — Cluster completion and node-detail overflow hotfix" "$SOURCE_DIR/xpanel/static/app.css" || { echo "в исходниках отсутствует Cluster hotfix SG-Panel RC70" >&2; return 1; }
  grep -q "try_files /index.html =404" "$SOURCE_DIR/deploy/configure-http.sh" || { echo "в исходниках отсутствует безопасный 404 fallback" >&2; return 1; }
  [[ -x "$SOURCE_DIR/deploy/migrate-placeholder-404.sh" ]] || { echo "в исходниках отсутствует миграция 404 fallback" >&2; return 1; }
  grep -q "$EXPECTED_UI_REVISION" "$SOURCE_DIR/xpanel/templates/base.html" || { echo "в шаблоне отсутствует ревизия CSS SG-Panel RC70" >&2; return 1; }
  [[ -f "$SOURCE_DIR/xpanel/static/fix40-cascade-steps-ui20.css" ]] || { echo "в исходниках отсутствует Cascade Steps UI20" >&2; return 1; }
  grep -Fq "guided three-step Cascade" "$SOURCE_DIR/xpanel/static/fix40-cascade-steps-ui20.css" || { echo "CSS Cascade Steps UI20 повреждён" >&2; return 1; }
  [[ -f "$SOURCE_DIR/xpanel/static/fix40-cluster-restore-ui21.css" ]] || { echo "в исходниках отсутствует Cluster Restore UI21" >&2; return 1; }
  grep -Fq "Restore the compact Cluster and SG-Node card" "$SOURCE_DIR/xpanel/static/fix40-cluster-restore-ui21.css" || { echo "CSS Cluster Restore UI21 повреждён" >&2; return 1; }
  grep -Fq 'fix40-cluster-restore-ui21.css' "$SOURCE_DIR/xpanel/templates/base.html" || { echo "Cluster Restore UI21 не подключён в base.html" >&2; return 1; }
  [[ -f "$SOURCE_DIR/xpanel/static/fix40-node-detail-polish-ui22.css" ]] || { echo "в исходниках отсутствует Node Detail Polish UI22" >&2; return 1; }
  grep -Fq 'remove the inherited gray slabs' "$SOURCE_DIR/xpanel/static/fix40-node-detail-polish-ui22.css" || { echo "CSS Node Detail Polish UI22 повреждён" >&2; return 1; }
  grep -Fq 'fix40-node-detail-polish-ui22.css' "$SOURCE_DIR/xpanel/templates/base.html" || { echo "Node Detail Polish UI22 не подключён в base.html" >&2; return 1; }
  grep -Fq 'HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)' "$SOURCE_DIR/xpanel/service.py" || { echo "в исходниках отсутствует контракт Salamander UI23" >&2; return 1; }
  grep -Fq 'def _apply_hysteria_salamander_to_inbound' "$SOURCE_DIR/xpanel/service.py" || { echo "в исходниках отсутствует безопасное слияние FinalMask UI23" >&2; return 1; }
  grep -Fq 'obfs_mode TEXT NOT NULL DEFAULT' "$SOURCE_DIR/xpanel/db.py" || { echo "в исходниках отсутствует миграция Salamander UI23" >&2; return 1; }
  grep -Fq 'data-hysteria-salamander-card' "$SOURCE_DIR/xpanel/templates/settings.html" || { echo "в интерфейсе отсутствует Salamander UI23" >&2; return 1; }
  grep -Fq 'build_hysteria2_uri' "$SOURCE_DIR/xpanel/service.py" || { echo "в исходниках отсутствует единый URI builder Salamander UI23" >&2; return 1; }
  grep -Fq 'compact-node-row' "$SOURCE_DIR/xpanel/templates/nodes.html" || { echo "компактный список Cluster не найден" >&2; return 1; }
  grep -Fq 'node-restore-status' "$SOURCE_DIR/xpanel/templates/node_detail.html" || { echo "компактная карточка SG-Node не найдена" >&2; return 1; }
  ! grep -Fq 'class="node-simple-nav"' "$SOURCE_DIR/xpanel/templates/node_detail.html" || { echo "в карточке SG-Node осталась дублирующая навигация" >&2; return 1; }
  grep -Fq 'WORKER_VERSION = "0.7.0"' "$SOURCE_DIR/node_agent/sg_node_worker.py" || { echo "в исходниках отсутствует Worker UI19" >&2; return 1; }
  grep -Fq 'def upsert_cascade_access' "$SOURCE_DIR/node_agent/sg_node_worker.py" || { echo "в Worker отсутствует безопасная операция Cascade" >&2; return 1; }
  grep -Fq 'def finalize_cascade_cluster_job' "$SOURCE_DIR/xpanel/service.py" || { echo "в Controller отсутствует финализация Cascade" >&2; return 1; }
  ! grep -Fq '<select' "$SOURCE_DIR/xpanel/templates/cascade.html" || { echo "в Cascade остался системный select" >&2; return 1; }
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

prune_upgrade_backups(){
  local keep="${SG_PANEL_UPGRADE_BACKUP_RETENTION:-10}"
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=10
  (( keep >= 2 )) || keep=2
  local root="/root/sg-panel-backups"
  [[ -d "$root" ]] || return 0
  mapfile -t candidates < <(find "$root" -mindepth 1 -maxdepth 1 -type d     -regextype posix-extended -regex '.*/[0-9]{8}-[0-9]{6}(-update-rollback)?'     -printf '%T@ %p
' | sort -nr | awk '{print $2}')
  local index
  for ((index=keep; index<${#candidates[@]}; index++)); do
    [[ "${candidates[$index]}" == "$BACKUP_ROOT" ]] && continue
    rm -rf -- "${candidates[$index]}"
  done
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
  if [[ -f /etc/xpanel-mvp/xray-secrets.env ]]; then
    OLD_XRAY_SECRET_EXISTS=1
    cp -a /etc/xpanel-mvp/xray-secrets.env "$BACKUP_ROOT/xray-secrets.env"
    chmod 0600 "$BACKUP_ROOT/xray-secrets.env"
  fi
  if [[ -d /etc/xpanel-mvp/warp ]]; then
    cp -a /etc/xpanel-mvp/warp "$BACKUP_ROOT/warp"
  fi
  if [[ -f /opt/sg-node/sg_node_agent.py ]]; then
    OLD_NODE_AGENT_EXISTS=1
    cp -a /opt/sg-node/sg_node_agent.py "$BACKUP_ROOT/sg-node-agent.py"
  fi
  if [[ -f /usr/local/libexec/sg-node-worker.py ]]; then
    OLD_NODE_WORKER_EXISTS=1
    cp -a /usr/local/libexec/sg-node-worker.py "$BACKUP_ROOT/sg-node-worker.py"
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


node_runtime_stage(){
  # A full SG-Panel may also be enrolled as SG-Node. Updating the same UI19
  # package on that server must refresh Agent/Worker automatically, without
  # touching Nginx, Xray configuration, clients or the enrollment token.
  if [[ -f /etc/sg-node/agent.json || -f /etc/systemd/system/sg-node-worker.service || -f /usr/local/libexec/sg-node-worker.py ]]; then
    install -D -o root -g root -m 0755 "$TARGET/node_agent/sg_node_agent.py" /opt/sg-node/sg_node_agent.py
    install -D -o root -g root -m 0755 "$TARGET/node_agent/sg_node_worker.py" /usr/local/libexec/sg-node-worker.py
    systemctl daemon-reload
    if [[ -f /etc/systemd/system/sg-node-worker.service ]]; then
      systemctl enable --now sg-node-worker.service
      systemctl restart sg-node-worker.service
      systemctl is-active --quiet sg-node-worker.service
    fi
    if [[ -f /etc/systemd/system/sg-node-agent.service ]]; then
      systemctl enable --now sg-node-agent.service
      systemctl restart sg-node-agent.service
      systemctl is-active --quiet sg-node-agent.service
    fi
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
    local required current newest
    # shellcheck disable=SC1091
    source deploy/xray-version.env
    required="${XRAY_VERSION:-v26.6.27}"
    current="v$(/usr/local/bin/xray version 2>/dev/null | awk 'NR==1 {print $2}' | sed 's/^v//')"
    [[ "$current" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo "не удалось определить установленную версию Xray" >&2
      return 1
    }
    newest="$(printf '%s\n%s\n' "$current" "$required" | sort -V | tail -n 1)"
    if [[ "$newest" == "$required" && "$current" != "$required" ]]; then
      log "Xray $current старее обязательной версии $required; выполняется проверенное обновление"
      XPANEL_XRAY_UPDATE_VERSION="$required" \
      XPANEL_XRAY_UPDATE_CHANNEL=stable \
      bash deploy/update-xray.sh
    fi
    log "Создаю или проверяю ML-KEM-768 и безопасно применяю Always-On конфигурацию Xray"
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
  grep -Fq "$EXPECTED_BUILD" <<<"$http_body" || { echo "GUI не отдаёт маркер сборки $EXPECTED_BUILD"; return 1; }
  grep -Fq "$EXPECTED_UI_REVISION" <<<"$http_body" || { echo "GUI не подключает базовую CSS-ревизию $EXPECTED_UI_REVISION"; return 1; }
  css_body="$(curl -fsS "http://$health_host:$port/static/fix40-ui-repair.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-installer-hotfix1")"
  grep -Fq "SG-Panel Preview 9 FIX40" <<<"$css_body" || { echo "веб-служба не отдаёт UI-исправления FIX40"; return 1; }
  css_body="$(curl -fsS "http://$health_host:$port/static/fix40-clients-layout-hotfix3.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-clients-layout-hotfix3")"
  grep -Fq "Clients Layout Hotfix 3" <<<"$css_body" || { echo "веб-служба не отдаёт Clients Layout Hotfix 3"; return 1; }
  css_body="$(curl -fsS "http://$health_host:$port/static/fix40-interface-cleanup-hotfix5.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-interface-cleanup-hotfix5")"
  grep -Fq "Interface Cleanup Hotfix 5" <<<"$css_body" || { echo "веб-служба не отдаёт Interface Cleanup Hotfix 5"; return 1; }
  css_body="$(curl -fsS "http://$health_host:$port/static/fix40-ui-compact-hotfix6.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-ui-compact-hotfix6")"
  grep -Fq "UI Compact Hotfix 6" <<<"$css_body" || { echo "веб-служба не отдаёт UI Compact Hotfix 6"; return 1; }
  local tabs_css
  tabs_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-global-tabs-dark-buttons-hotfix7.css")"
  grep -Fq "Global Tabs and Dark Buttons Hotfix 7" <<<"$tabs_css" || { echo "веб-служба не отдаёт Global Tabs and Dark Buttons Hotfix 7"; return 1; }
  local ui8_css
  ui8_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-interface-verification-hotfix8.css")"
  grep -Fq "Interface Verification Hotfix 8" <<<"$ui8_css" || { echo "веб-служба не отдаёт Interface Verification Hotfix 8"; return 1; }
  local ui9_css
  ui9_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-light-buttons-theme-icon-hotfix9.css")"
  grep -Fq "Light Button Gradient and Theme Icon Hotfix 9" <<<"$ui9_css" || { echo "веб-служба не отдаёт Light Button Gradient and Theme Icon Hotfix 9"; return 1; }
  local ui18_css
  ui18_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-node-simple-hotfix18.css")"
  grep -Fq "Node card and safe card geometry" <<<"$ui18_css" || { echo "веб-служба не отдаёт Node Simple Hotfix 18"; return 1; }
  local ui19_css
  ui19_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-cascade-steps-ui20.css")"
  grep -Fq "guided three-step Cascade" <<<"$ui19_css" || { echo "веб-служба не отдаёт Cascade Steps UI20"; return 1; }
  local ui21_css
  ui21_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-cluster-restore-ui21.css")"
  grep -Fq "Restore the compact Cluster and SG-Node card" <<<"$ui21_css" || { echo "веб-служба не отдаёт Cluster Restore UI21"; return 1; }
  local ui22_css
  ui22_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-node-detail-polish-ui22.css")"
  grep -Fq "remove the inherited gray slabs" <<<"$ui22_css" || { echo "веб-служба не отдаёт Node Detail Polish UI22"; return 1; }
  grep -Fq 'HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)' "$TARGET/xpanel/service.py" || { echo "установленный код не содержит Salamander UI23"; return 1; }
  grep -Fq 'obfs_mode TEXT NOT NULL DEFAULT' "$TARGET/xpanel/db.py" || { echo "установленный код не содержит миграцию Salamander UI23"; return 1; }
  grep -Fq 'data-hysteria-salamander-card' "$TARGET/xpanel/templates/settings.html" || { echo "установленный GUI не содержит Salamander UI23"; return 1; }
  if [[ -f /usr/local/libexec/sg-node-worker.py ]]; then
    grep -Fq 'WORKER_VERSION = "0.7.0"' /usr/local/libexec/sg-node-worker.py || { echo "SG-Node Worker не обновлён до UI19"; return 1; }
  fi
  if [[ -f /etc/systemd/system/sg-node-worker.service ]]; then
    systemctl is-active --quiet sg-node-worker.service || { echo "sg-node-worker.service не active"; return 1; }
  fi
  if [[ -f /etc/systemd/system/sg-node-agent.service ]]; then
    systemctl is-active --quiet sg-node-agent.service || { echo "sg-node-agent.service не active"; return 1; }
  fi
}

main(){
  install -d -m 0755 "$(dirname "$LOG_FILE")"
  : >"$LOG_FILE"
  chmod 0600 "$LOG_FILE"

  step_begin "Запуск обновления SG-Panel $EXPECTED_RELEASE_LABEL"
  preflight >>"$LOG_FILE" 2>&1
  step_ok
  printf '[SG-Panel] Все параметры приняты. Дальнейшее обновление не потребует ввода.\n'
  run_stage "Создание резервной копии" backup_stage
  run_stage "Копирование SG-Panel $EXPECTED_RELEASE_LABEL" copy_stage
  run_stage "Синхронизация SG-Node Runtime, если этот сервер подключён как нода" node_runtime_stage
  run_stage "Подготовка Python, базы данных и компонентов" python_stage
  run_stage "Проверка и применение конфигурации Xray" xray_stage
  run_stage "Установка и запуск веб-служб SG-Panel" web_stage
  run_stage "Исправление публичной заглушки: неизвестные пути → 404" bash "$TARGET/deploy/migrate-placeholder-404.sh"
  run_stage "Финальная проверка служб и интерфейса" validate_stage
  run_stage "Ограничение истории полных резервных копий" prune_upgrade_backups

  ROLLBACK_NEEDED=0
  trap - ERR INT TERM
  stop_spinner

  printf '\n[SG-Panel] [%sГОТОВО%s] SG-Panel %s (%s; core %s) установлена и проверена.\n' \
    "$COLOR_GREEN" "$COLOR_RESET" "$EXPECTED_RELEASE_LABEL" "$EXPECTED_BUILD" "$EXPECTED_VERSION"
  printf '[SG-Panel] Резервная копия: %s\n' "$BACKUP_ROOT"
  printf '[SG-Panel] Журнал: %s\n' "$LOG_FILE"
  if [[ $WGCF_WARNING -eq 1 ]]; then
    log "WARP-helper не обновлён; необязательный компонент оставлен без изменений."
  fi
  if [[ $ACCESS_WARNING -eq 1 ]]; then
    printf '[SG-Panel] [%sПРЕДУПРЕЖДЕНИЕ%s] Публичный адрес оставлен без автоматического исправления.\n' "$COLOR_YELLOW" "$COLOR_RESET"
  fi
}

main "$@"
