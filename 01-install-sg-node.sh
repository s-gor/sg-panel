#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_VERSION="1.0"
XRAY_VERSION="v26.5.9"
PANEL_URL=""
LOG_FILE="/var/log/sg-node-full-install.log"
STATE_FILE="/etc/sg-node/install.env"
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
RESET=$'\033[0m'
CURRENT_PID=""
EXISTING_CONNECTED=0
XRAY_WAS_ACTIVE=0
NGINX_WAS_ACTIVE=0

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
  printf '\n[SG-Node full install] %s\n' "$label" >>"$LOG_FILE"
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
    --version) printf '%s\n' "$SCRIPT_VERSION"; exit 0 ;;
    *) fail "Неизвестный параметр: $1" ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Запустите через sudo"
[[ "$PANEL_URL" =~ ^https?:// ]] || fail "Передайте --panel с адресом Cluster Controller"
PANEL_URL="${PANEL_URL%/}"
if systemctl is-active --quiet xray.service 2>/dev/null; then XRAY_WAS_ACTIVE=1; fi
if systemctl is-active --quiet nginx.service 2>/dev/null; then NGINX_WAS_ACTIVE=1; fi
if [[ -f /etc/sg-node/agent.json ]] && python3 - <<'PY_CONNECTED'
import json
from pathlib import Path
try:
    data = json.loads(Path('/etc/sg-node/agent.json').read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if data.get('agent_token') else 1)
PY_CONNECTED
then
  EXISTING_CONNECTED=1
fi

: >"$LOG_FILE"
chmod 0600 "$LOG_FILE"
printf '\nПолная установка SG-Node\n'
printf 'Версия скрипта: %s\n' "$SCRIPT_VERSION"
printf 'Cluster Controller: %s\n' "$PANEL_URL"
printf 'Журнал: %s\n\n' "$LOG_FILE"

check_platform() {
  [[ -f /etc/os-release ]] || { echo "не найден /etc/os-release" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || { echo "поддерживается только Ubuntu" >&2; return 1; }
  case "${VERSION_ID:-}" in
    24.04|24.10|25.04|25.10|26.04) ;;
    *) echo "рекомендуется Ubuntu 24.04 LTS; обнаружена ${VERSION_ID:-unknown}" >&2 ;;
  esac
  [[ "$(uname -m)" =~ ^(x86_64|aarch64)$ ]] || { echo "поддерживается amd64/arm64" >&2; return 1; }
  local free_kb
  free_kb="$(df -Pk / | awk 'NR==2 {print $4}')"
  [[ "${free_kb:-0}" -ge 2097152 ]] || { echo "нужно не менее 2 GiB свободного места" >&2; return 1; }
  if [[ -e /opt/sg-panel || -e /etc/systemd/system/sg-panel.service ]]; then
    echo "на этой машине обнаружена SG-Panel; Controller и SG-Node должны быть раздельными" >&2
    return 1
  fi
}

wait_cloud_init() {
  if command -v cloud-init >/dev/null 2>&1; then
    timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
  fi
}

check_network() {
  getent ahosts raw.githubusercontent.com >/dev/null
  curl -fsSI --max-time 15 "$PANEL_URL/" >/dev/null
}

wait_for_apt() {
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock /var/lib/apt/lists/lock)
  local lock busy
  for _ in $(seq 1 180); do
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

repair_packages() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  dpkg --configure -a
  apt-get -f install -y -o Dpkg::Use-Pty=0
}

update_packages() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get update -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0
  apt-get upgrade -y -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get install -y --no-install-recommends \
    -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0 \
    ca-certificates curl unzip rsync zstd psmisc jq \
    python3 python3-venv python3-pip sqlite3 \
    iproute2 dnsutils openssl procps util-linux \
    nginx certbot python3-certbot-nginx
}

prepare_account_and_dirs() {
  if ! id sg-node >/dev/null 2>&1; then
    useradd --system --home /nonexistent --shell /usr/sbin/nologin sg-node
  fi
  install -d -o root -g sg-node -m 0750 /opt/sg-node
  install -d -o sg-node -g sg-node -m 0750 /etc/sg-node
  install -d -o sg-node -g sg-node -m 0750 /var/lib/sg-node/jobs
  install -d -o root -g root -m 0700 /var/lib/sg-node/backups
  install -d -o root -g root -m 0755 /usr/local/libexec
  install -d -o root -g root -m 0755 /usr/local/etc/xray
  install -d -o root -g root -m 0755 /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log
  chmod 0644 /var/log/xray/access.log /var/log/xray/error.log
}

download_node_components() {
  local agent_tmp worker_tmp connect_tmp
  agent_tmp="$(mktemp /tmp/sg-node-agent.XXXXXX.py)"
  worker_tmp="$(mktemp /tmp/sg-node-worker.XXXXXX.py)"
  connect_tmp="$(mktemp /tmp/sg-node-connect.XXXXXX.sh)"
  trap 'rm -f "${agent_tmp:-}" "${worker_tmp:-}" "${connect_tmp:-}"' RETURN
  curl -fsSL --retry 5 --retry-delay 2 "$PANEL_URL/node/agent.py" -o "$agent_tmp"
  curl -fsSL --retry 5 --retry-delay 2 "$PANEL_URL/node/worker.py" -o "$worker_tmp"
  curl -fsSL --retry 5 --retry-delay 2 "$PANEL_URL/node/connect.sh" -o "$connect_tmp"
  python3 -m py_compile "$agent_tmp" "$worker_tmp"
  bash -n "$connect_tmp"
  install -o root -g sg-node -m 0750 "$agent_tmp" /opt/sg-node/sg_node_agent.py
  install -o root -g root -m 0755 "$worker_tmp" /usr/local/libexec/sg-node-worker.py
  install -o root -g root -m 0755 "$connect_tmp" /usr/local/sbin/sg-node-connect
}

xray_current_version() {
  if [[ -x /usr/local/bin/xray ]]; then
    /usr/local/bin/xray version 2>/dev/null | awk 'NR == 1 {print "v" $2}' | sed 's/^vv/v/'
  fi
}

install_xray() {
  local installer rc installed
  if [[ -x /usr/local/bin/xray && -f /etc/systemd/system/xray.service ]]; then
    printf 'Сохраняется установленный Xray %s\n' "$(xray_current_version || true)"
  else
    installer="$(mktemp /tmp/xray-install.XXXXXX.sh)"
    curl -fsSL --retry 5 --retry-delay 2 \
      https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh \
      -o "$installer"
    bash -n "$installer"
    set +e
    bash "$installer" install --version "$XRAY_VERSION"
    rc=$?
    set -e
    rm -f "$installer"
    if ((rc != 0)); then
      printf 'Официальный установщик вернул код %d; проверяются установленные файлы.\n' "$rc"
    fi
  fi
  [[ -x /usr/local/bin/xray ]] || { echo "Xray binary не установлен" >&2; return 1; }
  [[ -f /etc/systemd/system/xray.service ]] || { echo "xray.service не установлен" >&2; return 1; }
  installed="$(xray_current_version || true)"
  [[ -n "$installed" ]] || { echo "не удалось определить версию Xray" >&2; return 1; }

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
known = {
    'log': {'loglevel': 'warning'},
    'inbounds': [],
    'outbounds': [
        {'tag': 'direct', 'protocol': 'freedom'},
        {'tag': 'blocked', 'protocol': 'blackhole'},
    ],
}
if data == {} or data == known:
    path.unlink()
PY
  if [[ $EXISTING_CONNECTED -eq 1 && -s /usr/local/etc/xray/config.json ]]; then
    /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
    systemctl enable xray.service >/dev/null
    systemctl restart xray.service
    systemctl is-active --quiet xray.service
  else
    systemctl disable --now xray.service >/dev/null 2>&1 || true
    systemctl reset-failed xray.service >/dev/null 2>&1 || true
  fi
}

prepare_nginx() {
  if [[ $EXISTING_CONNECTED -eq 0 ]]; then
    rm -f /etc/nginx/sites-enabled/default
  fi
  nginx -t
  if [[ $EXISTING_CONNECTED -eq 1 && $NGINX_WAS_ACTIVE -eq 1 ]]; then
    systemctl enable nginx.service >/dev/null
    systemctl restart nginx.service
    systemctl is-active --quiet nginx.service
  else
    systemctl disable --now nginx.service >/dev/null 2>&1 || true
    systemctl reset-failed nginx.service >/dev/null 2>&1 || true
  fi
}

write_services() {
  cat >/etc/systemd/system/sg-node-worker.service <<'UNIT'
[Unit]
Description=SG-Node Privileged Worker
After=network.target

[Service]
Type=simple
User=root
Group=root
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /usr/local/libexec/sg-node-worker.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT

  cat >/etc/systemd/system/sg-node-agent.service <<'UNIT'
[Unit]
Description=SG-Node Agent
After=network-online.target sg-node-worker.service
Wants=network-online.target
Requires=sg-node-worker.service

[Service]
Type=simple
User=sg-node
Group=sg-node
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/sg-node/sg_node_agent.py
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/etc/sg-node /var/lib/sg-node/jobs
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  if [[ $EXISTING_CONNECTED -eq 1 ]]; then
    systemctl enable --now sg-node-worker.service
    systemctl restart sg-node-worker.service
    systemctl enable --now sg-node-agent.service
    systemctl restart sg-node-agent.service
  else
    systemctl disable --now sg-node-agent.service >/dev/null 2>&1 || true
    systemctl disable --now sg-node-worker.service >/dev/null 2>&1 || true
  fi
}

write_state() {
  local prepared_at xray_version nginx_version
  prepared_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  xray_version="$(xray_current_version)"
  nginx_version="$(nginx -v 2>&1 | sed 's#nginx version: ##')"
  local node_status controller_configured
  if [[ $EXISTING_CONNECTED -eq 1 ]]; then
    node_status="connected"
    controller_configured="1"
  else
    node_status="ready_to_connect"
    controller_configured="0"
  fi
  cat >"$STATE_FILE" <<STATE
SG_NODE_INSTALL_VERSION=$SCRIPT_VERSION
STATUS=$node_status
PREPARED_AT=$prepared_at
PANEL_URL=$PANEL_URL
XRAY_VERSION=$xray_version
XRAY_SERVICE=$(systemctl is-active xray.service 2>/dev/null || true)
NGINX_VERSION=$nginx_version
NGINX_SERVICE=$(systemctl is-active nginx.service 2>/dev/null || true)
HYSTERIA2_RUNTIME=xray
CERTBOT=installed
CLUSTER_CONTROLLER_CONFIGURED=$controller_configured
STATE
  chown sg-node:sg-node "$STATE_FILE"
  chmod 0640 "$STATE_FILE"
}

final_check() {
  [[ -x /usr/local/bin/xray ]]
  [[ -x /usr/sbin/nginx ]]
  [[ -x /usr/bin/certbot ]]
  [[ -f /opt/sg-node/sg_node_agent.py ]]
  [[ -f /usr/local/libexec/sg-node-worker.py ]]
  [[ -x /usr/local/sbin/sg-node-connect ]]
  [[ -f /etc/systemd/system/sg-node-agent.service ]]
  [[ -f /etc/systemd/system/sg-node-worker.service ]]
  [[ -f "$STATE_FILE" ]]
  if [[ $EXISTING_CONNECTED -eq 1 ]]; then
    systemctl is-active --quiet sg-node-agent.service
    systemctl is-active --quiet sg-node-worker.service
  else
    [[ "$(systemctl is-active xray.service 2>/dev/null || true)" != "active" ]]
    [[ "$(systemctl is-active nginx.service 2>/dev/null || true)" != "active" ]]
  fi
}

run_step "Проверка Ubuntu, архитектуры и свободного места" check_platform
run_step "Ожидание завершения первоначальной настройки" wait_cloud_init
run_step "Проверка Cluster Controller и интернета" check_network
run_step "Ожидание освобождения apt/dpkg" wait_for_apt
run_step "Проверка состояния apt и dpkg" repair_packages
run_step "Обновление системы" update_packages
run_step "Установка системных компонентов" install_packages
run_step "Подготовка защищённых каталогов" prepare_account_and_dirs
run_step "Установка SG-Node Agent и Worker" download_node_components
run_step "Установка Xray Runtime" install_xray
run_step "Подготовка Nginx и Certbot" prepare_nginx
run_step "Создание системных служб" write_services
run_step "Сохранение состояния SG-Node" write_state
run_step "Финальная проверка готовности" final_check

printf '\n%sSG-Node полностью установлена.%s\n' "$GREEN" "$RESET"
if [[ $EXISTING_CONNECTED -eq 1 ]]; then
  printf 'Agent и Worker: обновлены, подключение сохранено\n'
else
  printf 'Agent и Worker: установлены, ожидают подключения\n'
fi
printf 'Xray: %s, служба ожидает профиль\n' "$(xray_current_version)"
printf 'Nginx и Certbot: установлены, Nginx ожидает профиль\n'
printf 'Hysteria 2: поддержка входит в Xray Runtime\n'
printf 'Firewall: не изменялся\n'
printf 'Следующий шаг: в Cluster Controller добавьте ноду и скопируйте команду подключения.\n'
printf 'Журнал: %s\n' "$LOG_FILE"
