#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_VERSION="1.1"
PANEL_URL=""
ENROLLMENT_TOKEN=""
LOG_FILE="/var/log/sg-node-connect.log"
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
  tail -n 40 "$LOG_FILE" 2>/dev/null >&2 || true
  printf "\nПоследние сообщения Agent:%s\n" "$RESET" >&2
  journalctl -u sg-node-agent.service -n 25 --no-pager 2>/dev/null >&2 || true
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
  printf '\n[SG-Node connect] %s\n' "$label" >>"$LOG_FILE"
  "$@" >>"$LOG_FILE" 2>&1 &
  CURRENT_PID=$!
  spinner_loop "$CURRENT_PID" "$label" "$started"
  wait "$CURRENT_PID" || rc=$?
  CURRENT_PID=""
  elapsed=$(( $(date +%s) - started ))
  ((rc == 0)) || fail "$label завершился с кодом $rc"
  printf "\r\033[K${GREEN}[OK]${RESET} %s  %02d:%02d\n" "$label" "$((elapsed/60))" "$((elapsed%60))"
}

while (($#)); do
  case "$1" in
    --panel) PANEL_URL="${2:-}"; shift 2 ;;
    --token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --version) printf '%s\n' "$SCRIPT_VERSION"; exit 0 ;;
    # Backward compatibility: the new connection always replaces stale registration.
    --replace-registration) shift ;;
    *) fail "Неизвестный параметр: $1" ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Запустите через sudo"
[[ "$PANEL_URL" =~ ^https?:// ]] || fail "Передайте --panel с адресом Cluster Controller"
[[ -n "$ENROLLMENT_TOKEN" ]] || fail "Передайте одноразовый --token из Cluster Controller"
PANEL_URL="${PANEL_URL%/}"

: >"$LOG_FILE"
chmod 0600 "$LOG_FILE"
printf '\nПодключение SG-Node к Cluster Controller\n'
printf 'Версия скрипта: %s\n' "$SCRIPT_VERSION"
printf 'Cluster Controller: %s\n' "$PANEL_URL"
printf 'Журнал: %s\n\n' "$LOG_FILE"

check_full_install() {
  [[ -f /etc/sg-node/install.env ]] || {
    echo "SG-Node ещё не подготовлена. Сначала выполните полную установку SG-Node." >&2
    return 1
  }
  grep -Eq '^STATUS=(ready_to_connect|connected)$' /etc/sg-node/install.env || {
    echo "установка SG-Node не завершена: /etc/sg-node/install.env" >&2
    return 1
  }
  [[ -x /usr/local/bin/xray ]] || { echo "Xray Runtime не установлен" >&2; return 1; }
  [[ -x /usr/sbin/nginx ]] || { echo "Nginx не установлен" >&2; return 1; }
  [[ -f /etc/systemd/system/sg-node-agent.service ]] || { echo "sg-node-agent.service не установлен" >&2; return 1; }
  [[ -f /etc/systemd/system/sg-node-worker.service ]] || { echo "sg-node-worker.service не установлен" >&2; return 1; }
}

check_controller() {
  curl -fsSI --max-time 15 "$PANEL_URL/" >/dev/null
  curl -fsSL --max-time 15 "$PANEL_URL/node/agent.py" -o /dev/null
  curl -fsSL --max-time 15 "$PANEL_URL/node/worker.py" -o /dev/null
}

refresh_components() {
  local agent_tmp worker_tmp
  agent_tmp="$(mktemp /tmp/sg-node-agent.XXXXXX.py)"
  worker_tmp="$(mktemp /tmp/sg-node-worker.XXXXXX.py)"
  trap 'rm -f "${agent_tmp:-}" "${worker_tmp:-}"' RETURN
  curl -fsSL --retry 5 --retry-delay 2 "$PANEL_URL/node/agent.py" -o "$agent_tmp"
  curl -fsSL --retry 5 --retry-delay 2 "$PANEL_URL/node/worker.py" -o "$worker_tmp"
  python3 -m py_compile "$agent_tmp" "$worker_tmp"
  install -o root -g sg-node -m 0750 "$agent_tmp" /opt/sg-node/sg_node_agent.py
  install -o root -g root -m 0755 "$worker_tmp" /usr/local/libexec/sg-node-worker.py
}

replace_registration() {
  systemctl stop sg-node-agent.service >/dev/null 2>&1 || true
  if [[ -f /etc/sg-node/agent.json ]]; then
    cp -a /etc/sg-node/agent.json "/etc/sg-node/agent.json.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  python3 - "$PANEL_URL" "$ENROLLMENT_TOKEN" <<'PY'
import json, os, sys
from pathlib import Path
path = Path('/etc/sg-node/agent.json')
data = {
    'panel_url': sys.argv[1].rstrip('/'),
    'enrollment_token': sys.argv[2],
}
tmp = path.with_suffix('.tmp')
tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')
os.chmod(tmp, 0o600)
tmp.replace(path)
PY
  chown sg-node:sg-node /etc/sg-node/agent.json
  chmod 0600 /etc/sg-node/agent.json
}

start_services() {
  systemctl daemon-reload
  systemctl enable --now sg-node-worker.service
  systemctl restart sg-node-worker.service
  systemctl enable --now sg-node-agent.service
  systemctl restart sg-node-agent.service
  systemctl is-active --quiet sg-node-worker.service
  systemctl is-active --quiet sg-node-agent.service
}

wait_for_registration() {
  for _ in $(seq 1 60); do
    if python3 - <<'PY'
import json
from pathlib import Path
try:
    data = json.loads(Path('/etc/sg-node/agent.json').read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if data.get('agent_token') and not data.get('enrollment_token') else 1)
PY
    then
      return 0
    fi
    if ! systemctl is-active --quiet sg-node-agent.service; then
      journalctl -u sg-node-agent.service -n 40 --no-pager
      return 1
    fi
    sleep 1
  done
  echo "Controller не завершил регистрацию за 60 секунд" >&2
  return 1
}

verify_real_heartbeat() {
  python3 - "$PANEL_URL" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

panel = sys.argv[1].rstrip('/')
config = json.loads(Path('/etc/sg-node/agent.json').read_text(encoding='utf-8'))
token = str(config.get('agent_token') or '')
if not token:
    raise SystemExit('постоянный токен агента не получен')
spec = importlib.util.spec_from_file_location('sg_node_agent_verify', '/opt/sg-node/sg_node_agent.py')
if spec is None or spec.loader is None:
    raise SystemExit('не удалось загрузить SG-Node Agent')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = module.request_json(
    panel + '/api/node/v1/heartbeat',
    module.collect_metadata(),
    token=token,
    timeout=20,
)
if result.get('ok') is not True:
    raise SystemExit('Cluster Controller не подтвердил heartbeat')
print('heartbeat accepted: node_id=' + str(result.get('node_id') or config.get('node_id') or 'unknown'))
PY
}

save_connected_state() {
  python3 - "$PANEL_URL" <<'PY'
from pathlib import Path
import sys
path = Path('/etc/sg-node/install.env')
lines = []
seen = set()
updates = {
    'STATUS': 'connected',
    'PANEL_URL': sys.argv[1].rstrip('/'),
    'CLUSTER_CONTROLLER_CONFIGURED': '1',
}
for raw in path.read_text(encoding='utf-8').splitlines():
    if '=' not in raw:
        lines.append(raw)
        continue
    key = raw.split('=', 1)[0]
    if key in updates:
        lines.append(f'{key}={updates[key]}')
        seen.add(key)
    else:
        lines.append(raw)
for key, value in updates.items():
    if key not in seen:
        lines.append(f'{key}={value}')
path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
PY
  chown sg-node:sg-node /etc/sg-node/install.env
  chmod 0640 /etc/sg-node/install.env
}

run_step "Проверка полной установки SG-Node" check_full_install
run_step "Проверка Cluster Controller" check_controller
run_step "Обновление Agent и Worker" refresh_components
run_step "Замена прежней регистрации" replace_registration
run_step "Запуск Agent и Worker" start_services
run_step "Получение нового Agent token" wait_for_registration
run_step "Подтверждение реального heartbeat" verify_real_heartbeat
run_step "Сохранение состояния подключения" save_connected_state

printf '\n%sSG-Node подключена к Cluster Controller.%s\n' "$GREEN" "$RESET"
printf 'Agent: active\n'
printf 'Worker: active\n'
printf 'Heartbeat: подтверждён Controller\n'
printf 'Xray и Nginx: установлены и готовы к созданию серверного профиля\n'
printf 'Журнал: %s\n' "$LOG_FILE"
