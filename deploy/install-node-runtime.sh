#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_VERSION="1.0"
XRAY_VERSION="v26.5.9"
LOG_FILE="/var/log/sg-node-runtime-install.log"
STATE_FILE="/etc/sg-node/runtime.env"
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
RESET=$'\033[0m'
CURRENT_PID=""

cleanup() {
  if [[ -n "${CURRENT_PID:-}" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
    kill "$CURRENT_PID" 2>/dev/null || true
    wait "$CURRENT_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

fail() {
  local message="$1"
  printf "\r\033[K${RED}[ОШИБКА]${RESET} %s\n" "$message" >&2
  printf "%sПоследние строки журнала:%s\n" "$YELLOW" "$RESET" >&2
  tail -n 35 "$LOG_FILE" 2>/dev/null >&2 || true
  printf "\nПолный журнал: %s\n" "$LOG_FILE" >&2
  exit 1
}

spinner_loop() {
  local pid="$1" label="$2" started="$3"
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 elapsed
  while kill -0 "$pid" 2>/dev/null; do
    elapsed=$(( $(date +%s) - started ))
    printf "\r\033[K${GREEN}%s${RESET} %s  %02d:%02d" \
      "${frames:i++%${#frames}:1}" "$label" "$((elapsed/60))" "$((elapsed%60))"
    sleep 0.12
  done
}

run_step() {
  local label="$1"; shift
  local started rc=0 elapsed
  started="$(date +%s)"
  printf '\n[SG-Node runtime] %s\n' "$label" >>"$LOG_FILE"
  "$@" >>"$LOG_FILE" 2>&1 &
  CURRENT_PID=$!
  spinner_loop "$CURRENT_PID" "$label" "$started"
  wait "$CURRENT_PID" || rc=$?
  CURRENT_PID=""
  elapsed=$(( $(date +%s) - started ))
  ((rc == 0)) || fail "$label завершился с кодом $rc"
  printf "\r\033[K${GREEN}[OK]${RESET} %s  %02d:%02d\n" "$label" "$((elapsed/60))" "$((elapsed%60))"
}

if [[ "${1:-}" == "--version" ]]; then
  printf '%s\n' "$SCRIPT_VERSION"
  exit 0
fi
[[ $# -eq 0 ]] || fail "Неизвестный параметр: $1"
[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Запустите через sudo"

: >"$LOG_FILE"
chmod 0600 "$LOG_FILE"
printf '\nУстановка SG-Node Runtime\n'
printf 'Версия скрипта: %s\n' "$SCRIPT_VERSION"
printf 'Xray: %s\n' "$XRAY_VERSION"
printf 'Журнал: %s\n\n' "$LOG_FILE"

check_node_registration() {
  [[ -f /etc/os-release ]] || { echo "не найден /etc/os-release" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || { echo "поддерживается Ubuntu" >&2; return 1; }
  [[ -f /etc/sg-node/agent.json ]] || { echo "сначала подключите ноду к Cluster Controller" >&2; return 1; }
  python3 - <<'PY'
import json
from pathlib import Path
path = Path('/etc/sg-node/agent.json')
data = json.loads(path.read_text(encoding='utf-8'))
if not data.get('panel_url') or not data.get('agent_token'):
    raise SystemExit('регистрация SG-Node не завершена')
if not str(data['panel_url']).startswith(('http://', 'https://')):
    raise SystemExit('некорректный panel_url в agent.json')
PY
  systemctl is-active --quiet sg-node-agent.service || {
    echo "sg-node-agent.service не active" >&2
    return 1
  }
  systemctl is-active --quiet sg-node-worker.service || {
    echo "sg-node-worker.service не active" >&2
    return 1
  }
}


update_agent_and_worker() (
  local agent_tmp worker_tmp panel_url
  trap 'rm -f "${agent_tmp:-}" "${worker_tmp:-}"' EXIT
  panel_url="$(python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path('/etc/sg-node/agent.json').read_text(encoding='utf-8'))
print(str(data['panel_url']).rstrip('/'))
PY
)"
  [[ "$panel_url" =~ ^https?:// ]] || { echo "некорректный panel_url в agent.json" >&2; return 1; }
  agent_tmp="$(mktemp /tmp/sg-node-agent.XXXXXX.py)"
  worker_tmp="$(mktemp /tmp/sg-node-worker.XXXXXX.py)"
  curl -fsSL --retry 5 --retry-delay 2 "$panel_url/node/agent.py" -o "$agent_tmp"
  curl -fsSL --retry 5 --retry-delay 2 "$panel_url/node/worker.py" -o "$worker_tmp"
  python3 -m py_compile "$agent_tmp" "$worker_tmp"
  install -o root -g sg-node -m 0750 "$agent_tmp" /opt/sg-node/sg_node_agent.py
  install -o root -g root -m 0755 "$worker_tmp" /usr/local/libexec/sg-node-worker.py
  systemctl restart sg-node-worker.service
  systemctl restart sg-node-agent.service
  systemctl is-active --quiet sg-node-worker.service
  systemctl is-active --quiet sg-node-agent.service
)

wait_for_apt() {
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock /var/lib/apt/lists/lock)
  local lock busy
  for _ in $(seq 1 120); do
    busy=0
    for lock in "${locks[@]}"; do
      if fuser "$lock" >/dev/null 2>&1; then busy=1; break; fi
    done
    ((busy == 0)) && return 0
    sleep 2
  done
  echo "apt/dpkg lock did not become free" >&2
  return 1
}

install_requirements() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get update -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0
  apt-get install -y --no-install-recommends \
    -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0 \
    curl ca-certificates unzip jq python3 psmisc
}

xray_current_version() {
  if [[ -x /usr/local/bin/xray ]]; then
    /usr/local/bin/xray version 2>/dev/null | awk 'NR == 1 {print "v" $2}' | sed 's/^vv/v/'
  fi
}

install_xray_runtime() {
  local current installer rc installed
  current="$(xray_current_version || true)"
  if [[ -n "$current" && -f /etc/systemd/system/xray.service ]]; then
    printf 'Сохраняется установленный Xray %s\n' "$current"
  else
    installer="$(mktemp /tmp/xray-install.XXXXXX.sh)"
    curl -fsSL --retry 5 --retry-delay 2 \
      https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh \
      -o "$installer"
    bash -n "$installer"

    # Официальный установщик может вернуть ненулевой код, если новая служба
    # ещё не имеет рабочей конфигурации. Для runtime это ожидаемо: ниже мы
    # отдельно проверяем бинарный файл и systemd unit.
    set +e
    bash "$installer" install --version "$XRAY_VERSION"
    rc=$?
    set -e
    rm -f "$installer"

    if ((rc != 0)); then
      printf 'Установщик вернул код %d; выполняется проверка фактически установленных файлов.\n' "$rc"
    fi
  fi

  [[ -x /usr/local/bin/xray ]] || { echo "Xray binary не установлен" >&2; return 1; }
  [[ -f /etc/systemd/system/xray.service ]] || { echo "xray.service не установлен" >&2; return 1; }
  installed="$(xray_current_version || true)"
  [[ -n "$installed" ]] || { echo "не удалось определить версию Xray" >&2; return 1; }

  install -d -o root -g root -m 0755 /usr/local/etc/xray
  install -d -o root -g root -m 0755 /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log
  chmod 0644 /var/log/xray/access.log /var/log/xray/error.log

  python3 - <<'PY'
import json
from pathlib import Path
path = Path('/usr/local/etc/xray/config.json')
if not path.exists():
    raise SystemExit(0)
try:
    data = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(0)
known_placeholder = {
    'log': {'loglevel': 'warning'},
    'inbounds': [],
    'outbounds': [
        {'tag': 'direct', 'protocol': 'freedom'},
        {'tag': 'blocked', 'protocol': 'blackhole'},
    ],
}
if data == {} or data == known_placeholder:
    path.unlink()
PY

  systemctl daemon-reload

  if [[ -s /usr/local/etc/xray/config.json ]]; then
    /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
    systemctl enable xray.service >/dev/null
    systemctl restart xray.service
    systemctl is-active --quiet xray.service
  else
    systemctl disable --now xray.service >/dev/null 2>&1 || true
    systemctl reset-failed xray.service >/dev/null 2>&1 || true
  fi
}

write_runtime_state() {
  local xray_version service_state prepared_at config_status
  xray_version="$(xray_current_version)"
  service_state="$(systemctl is-active xray.service 2>/dev/null || true)"
  service_state="${service_state:-inactive}"
  prepared_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ -s /usr/local/etc/xray/config.json ]]; then
    config_status="configured"
  else
    config_status="waiting_config"
  fi
  install -d -o sg-node -g sg-node -m 0750 /etc/sg-node
  cat >"$STATE_FILE" <<STATE
SG_NODE_RUNTIME_VERSION=$SCRIPT_VERSION
STATUS=ready_for_profile
PREPARED_AT=$prepared_at
XRAY_VERSION=$xray_version
XRAY_CONFIG_STATUS=$config_status
XRAY_SERVICE=$service_state
NGINX_STATUS=not_required_for_reality
STATE
  chown sg-node:sg-node "$STATE_FILE"
  chmod 0640 "$STATE_FILE"
}

refresh_agent() {
  systemctl restart sg-node-worker.service
  systemctl restart sg-node-agent.service
  systemctl is-active --quiet sg-node-worker.service
  systemctl is-active --quiet sg-node-agent.service
}

run_step "Проверка регистрации SG-Node" check_node_registration
run_step "Обновление SG-Node Agent и Worker" update_agent_and_worker
run_step "Ожидание освобождения apt/dpkg" wait_for_apt
run_step "Проверка системных компонентов" install_requirements
run_step "Установка Xray Runtime" install_xray_runtime
run_step "Сохранение состояния Runtime" write_runtime_state
run_step "Обновление сведений на Cluster Controller" refresh_agent

printf '\n%sSG-Node Runtime готов.%s\n' "$GREEN" "$RESET"
printf 'Xray: %s\n' "$(xray_current_version)"
if [[ -s /usr/local/etc/xray/config.json ]]; then
  printf 'Служба Xray: active\n'
  printf 'Конфигурация: сохранена существующая рабочая конфигурация\n'
else
  printf 'Служба Xray: inactive — ожидает первую конфигурацию от Cluster Controller\n'
  printf 'Конфигурация: waiting_config\n'
fi
printf 'Nginx: не устанавливался — для VLESS REALITY не требуется\n'
printf 'Журнал: %s\n' "$LOG_FILE"
