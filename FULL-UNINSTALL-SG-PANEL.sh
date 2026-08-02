#!/usr/bin/env bash
set -Eeuo pipefail

ASSUME_YES=0
TOTAL_STAGES=8
PORTS_FILE="/tmp/sg-panel-reset-ports.$$"
STAGE_LOG=""

usage() {
  cat <<'USAGE'
SG-Panel Full Reset — полная очистка выделенного тестового EC2.

Использование:
  sudo bash /opt/xpanel-mvp/FULL-UNINSTALL-SG-PANEL.sh --yes

Будут удалены:
  - SG-Panel / старые каталоги Controller;
  - SG-Node Agent, Worker, runtime и их состояние;
  - Xray, конфигурация, GeoFiles и журналы;
  - Nginx, Certbot и все сертификаты Let's Encrypt;
  - резервные копии SG-Panel, WARP/wgcf и временные файлы;
  - swap /swapfile, если он существует;
  - резервирование публичного порта панели.

Не изменяются:
  - SSH и пользовательские файлы /home;
  - сетевая конфигурация Ubuntu;
  - EC2 Security Group, Elastic IP, IAM и другие настройки AWS.

ВНИМАНИЕ: скрипт предназначен только для отдельного тестового сервера,
где Nginx и сертификаты не используются другими проектами.
Параметр --yes обязателен.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      ASSUME_YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Неизвестный параметр: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo "Ошибка: запустите через sudo." >&2
  exit 1
}

[[ $ASSUME_YES -eq 1 ]] || {
  echo "Отказ: для полной очистки требуется параметр --yes." >&2
  echo "Команда: sudo bash /opt/xpanel-mvp/FULL-UNINSTALL-SG-PANEL.sh --yes" >&2
  exit 2
}

cd /
umask 077

cleanup() {
  rm -f "$PORTS_FILE"
  [[ -z "${STAGE_LOG:-}" ]] || rm -f "$STAGE_LOG"
}
trap cleanup EXIT

if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  COLOR_GREEN=$'\033[1;32m'
  COLOR_RED=$'\033[1;31m'
  COLOR_YELLOW=$'\033[1;33m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_GREEN=""
  COLOR_RED=""
  COLOR_YELLOW=""
  COLOR_RESET=""
fi

run_stage() {
  local label="$1"
  shift
  local pid rc frame=0 started elapsed
  local frames='|/-\\'
  STAGE_LOG="$(mktemp /tmp/sg-panel-full-reset.XXXXXX)"
  started=$SECONDS

  "$@" >"$STAGE_LOG" 2>&1 &
  pid=$!

  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    while kill -0 "$pid" 2>/dev/null; do
      elapsed=$((SECONDS - started))
      printf '\r[SG-Panel Reset] [%s%s%s] %s (%s сек)' \
        "$COLOR_GREEN" "${frames:frame%4:1}" "$COLOR_RESET" "$label" "$elapsed"
      frame=$((frame + 1))
      sleep 0.25
    done
  else
    printf '[SG-Panel Reset] %s\n' "$label"
  fi

  if wait "$pid"; then
    rc=0
  else
    rc=$?
  fi
  elapsed=$((SECONDS - started))

  if [[ $rc -eq 0 ]]; then
    if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
      printf '\r[SG-Panel Reset] [%sOK%s] %s (%s сек)\033[K\n' \
        "$COLOR_GREEN" "$COLOR_RESET" "$label" "$elapsed"
    else
      printf '[SG-Panel Reset] [OK] %s (%s сек)\n' "$label" "$elapsed"
    fi
  else
    if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
      printf '\r[SG-Panel Reset] [%sОШИБКА%s] %s (%s сек)\033[K\n' \
        "$COLOR_RED" "$COLOR_RESET" "$label" "$elapsed" >&2
    else
      printf '[SG-Panel Reset] [ОШИБКА] %s (%s сек)\n' "$label" "$elapsed" >&2
    fi
    cat "$STAGE_LOG" >&2
    return "$rc"
  fi

  rm -f "$STAGE_LOG"
  STAGE_LOG=""
}

collect_panel_ports() {
  local file value
  : >"$PORTS_FILE"
  printf '%s\n' 61443 >>"$PORTS_FILE"

  for file in \
    /etc/xpanel-mvp/panel-access.env \
    /etc/xpanel-mvp/install-complete.env; do
    [[ -f "$file" ]] || continue
    while IFS='=' read -r key value; do
      case "$key" in
        PANEL_PUBLIC_PORT)
          [[ "$value" =~ ^[0-9]+$ ]] && printf '%s\n' "$value" >>"$PORTS_FILE"
          ;;
      esac
    done <"$file"
  done

  for file in \
    /etc/nginx/sites-available/sg-panel \
    /etc/nginx/sites-available/sg-panel-acme; do
    [[ -f "$file" ]] || continue
    awk '
      $1 == "listen" {
        value=$2
        gsub(/\[::\]:/, "", value)
        gsub(/[^0-9].*$/, "", value)
        if (value ~ /^[0-9]+$/ && value >= 1024) print value
      }
    ' "$file" >>"$PORTS_FILE" || true
  done

  sort -nu "$PORTS_FILE" -o "$PORTS_FILE"
}

stop_services() {
  local unit
  local units=(
    xpanel-web.service
    xpanel-maintenance.timer
    xpanel-maintenance.service
    xpanel-traffic.timer
    xpanel-traffic.service
    sg-panel.service
    xpanel.service
    sg-node-agent.service
    sg-node-worker.service
    sg-panel-update.service
    sg-panel-xray-update.service
    xray.service
    xray@.service
    cascade.service
    hysteria_studio.service
    nginx.service
    certbot.timer
  )

  for unit in "${units[@]}"; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl stop "$unit" >/dev/null 2>&1 || true
  done

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl stop "$unit" >/dev/null 2>&1 || true
  done < <(
    systemctl list-units --all --plain --no-legend \
      'sg-panel-*' 'sg-node-*' 'xpanel-*' 'xray@*.service' 2>/dev/null \
      | awk '{print $1}' | sort -u
  )
}

remove_reserved_ports_and_swap() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$PORTS_FILE" <<'PY'
from pathlib import Path
import subprocess
import sys

ports_path = Path(sys.argv[1])
remove = {
    int(line.strip())
    for line in ports_path.read_text(encoding="utf-8").splitlines()
    if line.strip().isdigit()
}
try:
    current = subprocess.check_output(
        ["sysctl", "-n", "net.ipv4.ip_local_reserved_ports"],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    current = ""

result: list[str] = []
for raw in (item.strip() for item in current.split(",")):
    if not raw:
        continue
    try:
        if "-" not in raw:
            value = int(raw)
            if value not in remove:
                result.append(str(value))
            continue
        lo, hi = (int(part) for part in raw.split("-", 1))
    except ValueError:
        result.append(raw)
        continue

    points = sorted(port for port in remove if lo <= port <= hi)
    start = lo
    for port in points:
        if start <= port - 1:
            result.append(str(start) if start == port - 1 else f"{start}-{port - 1}")
        start = port + 1
    if start <= hi:
        result.append(str(start) if start == hi else f"{start}-{hi}")

value = ",".join(result)
subprocess.run(
    ["sysctl", "-w", f"net.ipv4.ip_local_reserved_ports={value}"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=False,
)
PY
  fi

  rm -f /etc/sysctl.d/99-sg-panel-port.conf

  if swapon --show=NAME --noheadings 2>/dev/null | grep -Fxq '/swapfile'; then
    swapoff /swapfile || true
  fi
  if [[ -f /etc/fstab ]]; then
    sed -i '\|^/swapfile[[:space:]]|d' /etc/fstab
  fi
  rm -f /swapfile
}

remove_panel_node_and_xray() {
  rm -rf \
    /opt/xpanel-mvp \
    /opt/sg-panel \
    /opt/sg-node \
    /etc/xpanel-mvp \
    /etc/sg-panel \
    /etc/sg-node \
    /var/lib/sg-panel-update \
    /var/lib/sg-panel \
    /var/lib/sg-node \
    /root/sg-panel-backups \
    /root/sg-panel-first-user.txt \
    /usr/local/etc/xray \
    /etc/xray \
    /usr/local/share/xray \
    /usr/share/xray \
    /var/lib/xray \
    /var/log/xray \
    /opt/geofiles

  rm -f \
    /usr/local/bin/sg-panel \
    /usr/local/bin/xray \
    /usr/local/bin/wgcf-cli \
    /usr/local/sbin/sg-node-connect \
    /usr/local/libexec/sg-node-worker.py

  rm -rf \
    /etc/systemd/system/xray.service.d \
    /etc/systemd/system/xray@.service.d

  rm -f \
    /etc/systemd/system/xpanel-web.service \
    /etc/systemd/system/xpanel-maintenance.service \
    /etc/systemd/system/xpanel-maintenance.timer \
    /etc/systemd/system/xpanel-traffic.service \
    /etc/systemd/system/xpanel-traffic.timer \
    /etc/systemd/system/sg-panel.service \
    /etc/systemd/system/xpanel.service \
    /etc/systemd/system/sg-node-agent.service \
    /etc/systemd/system/sg-node-worker.service \
    /etc/systemd/system/xray.service \
    /etc/systemd/system/xray@.service \
    /etc/systemd/system/cascade.service \
    /etc/systemd/system/hysteria_studio.service

  if id sg-node >/dev/null 2>&1; then
    userdel sg-node >/dev/null 2>&1 || true
  fi
  if getent group sg-node >/dev/null 2>&1; then
    groupdel sg-node >/dev/null 2>&1 || true
  fi
}

wait_for_package_manager() {
  local attempt=0
  while true; do
    if command -v fuser >/dev/null 2>&1; then
      if ! fuser \
        /var/lib/dpkg/lock-frontend \
        /var/lib/dpkg/lock \
        /var/cache/apt/archives/lock \
        /var/lib/apt/lists/lock >/dev/null 2>&1; then
        return 0
      fi
    elif ! pgrep -x apt >/dev/null 2>&1 \
      && ! pgrep -x apt-get >/dev/null 2>&1 \
      && ! pgrep -x dpkg >/dev/null 2>&1 \
      && ! pgrep -f unattended-upgrade >/dev/null 2>&1; then
      return 0
    fi

    attempt=$((attempt + 1))
    if ((attempt >= 120)); then
      echo "apt/dpkg занят более 10 минут." >&2
      return 1
    fi
    sleep 5
  done
}

purge_nginx_and_certbot_packages() {
  local package
  local packages=()

  if command -v snap >/dev/null 2>&1 && snap list certbot >/dev/null 2>&1; then
    snap remove certbot >/dev/null 2>&1 || true
  fi

  for package in \
    nginx nginx-common nginx-core nginx-full nginx-light \
    libnginx-mod-stream \
    certbot python3-certbot python3-certbot-nginx python3-acme; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
      packages+=("$package")
    fi
  done

  if ((${#packages[@]} > 0)); then
    wait_for_package_manager
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt-get purge -y -o Dpkg::Use-Pty=0 "${packages[@]}"
    apt-get clean
  fi
}

remove_web_certificates_and_logs() {
  rm -rf \
    /etc/nginx \
    /var/cache/nginx \
    /var/lib/nginx \
    /var/log/nginx \
    /var/www/sg-panel-placeholder \
    /var/www/letsencrypt \
    /etc/letsencrypt \
    /var/lib/letsencrypt \
    /var/log/letsencrypt

  rm -f \
    /var/log/sg-node-connect.log \
    /var/log/sg-node-full-install.log \
    /var/log/sg-node-runtime-install.log

  find /var/log -maxdepth 1 -type f -name 'sg-panel-install-*' -delete 2>/dev/null || true
}

remove_temporary_data() {
  local path
  shopt -s nullglob
  for path in \
    /tmp/sg-panel-* \
    /tmp/xpanel-* \
    /tmp/sg-node-* \
    /tmp/xray-install.* \
    /tmp/install-sg-panel.sh \
    /tmp/uninstall-sg-panel.sh; do
    [[ "$path" == "$PORTS_FILE" || "$path" == "$STAGE_LOG" ]] && continue
    rm -rf -- "$path"
  done
  shopt -u nullglob

  rm -f /run/lock/sg-panel-update.lock
  systemctl daemon-reload
  systemctl reset-failed >/dev/null 2>&1 || true
}

verify_removal() {
  local path package unit current
  local leftovers=()
  local paths=(
    /opt/xpanel-mvp
    /opt/sg-panel
    /opt/sg-node
    /etc/xpanel-mvp
    /etc/sg-panel
    /etc/sg-node
    /var/lib/sg-panel-update
    /var/lib/sg-panel
    /var/lib/sg-node
    /root/sg-panel-backups
    /root/sg-panel-first-user.txt
    /usr/local/bin/sg-panel
    /usr/local/bin/xray
    /usr/local/bin/wgcf-cli
    /usr/local/sbin/sg-node-connect
    /usr/local/etc/xray
    /etc/xray
    /etc/nginx
    /etc/letsencrypt
    /swapfile
    /etc/sysctl.d/99-sg-panel-port.conf
  )

  for path in "${paths[@]}"; do
    [[ ! -e "$path" ]] || leftovers+=("$path")
  done

  for unit in \
    xpanel-web.service \
    xpanel-maintenance.timer \
    xpanel-traffic.timer \
    sg-node-agent.service \
    sg-node-worker.service \
    xray.service; do
    if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "^$unit"; then
      leftovers+=("unit:$unit")
    fi
  done

  for package in \
    nginx nginx-common nginx-core nginx-full nginx-light \
    libnginx-mod-stream certbot python3-certbot python3-certbot-nginx python3-acme; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
      leftovers+=("package:$package")
    fi
  done

  if id sg-node >/dev/null 2>&1; then
    leftovers+=("user:sg-node")
  fi

  if [[ -f /etc/fstab ]] && grep -Eq '^/swapfile[[:space:]]' /etc/fstab; then
    leftovers+=("/etc/fstab:/swapfile")
  fi

  current="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
  while IFS= read -r port; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    if python3 - "$current" "$port" <<'PY'
import sys
value = sys.argv[1]
port = int(sys.argv[2])
for item in value.split(','):
    item = item.strip()
    if not item:
        continue
    try:
        if '-' in item:
            lo, hi = (int(x) for x in item.split('-', 1))
            if lo <= port <= hi:
                raise SystemExit(0)
        elif int(item) == port:
            raise SystemExit(0)
    except ValueError:
        pass
raise SystemExit(1)
PY
    then
      leftovers+=("reserved-port:$port")
    fi
  done <"$PORTS_FILE"

  if ((${#leftovers[@]} > 0)); then
    echo "Остались компоненты SG-Panel:" >&2
    printf '  - %s\n' "${leftovers[@]}" >&2
    return 1
  fi
}

printf '\n%sSG-Panel Full Reset — тестовый EC2%s\n' "$COLOR_YELLOW" "$COLOR_RESET"
printf 'Сервер будет очищен от SG-Panel, SG-Node, Xray, Nginx, Certbot и их данных.\n'
printf 'SSH, /home и настройки AWS сохраняются.\n\n'

run_stage "Этап 1/$TOTAL_STAGES · Определение портов панели" collect_panel_ports
run_stage "Этап 2/$TOTAL_STAGES · Остановка служб" stop_services
run_stage "Этап 3/$TOTAL_STAGES · Сброс порта и swap" remove_reserved_ports_and_swap
run_stage "Этап 4/$TOTAL_STAGES · Удаление SG-Panel, SG-Node и Xray" remove_panel_node_and_xray
run_stage "Этап 5/$TOTAL_STAGES · Удаление пакетов Nginx и Certbot" purge_nginx_and_certbot_packages
run_stage "Этап 6/$TOTAL_STAGES · Удаление конфигураций и журналов" remove_web_certificates_and_logs
run_stage "Этап 7/$TOTAL_STAGES · Очистка временных данных" remove_temporary_data
run_stage "Этап 8/$TOTAL_STAGES · Финальная проверка" verify_removal

cat <<DONE

============================================================
${COLOR_GREEN}Полная очистка SG-Panel завершена успешно.${COLOR_RESET}

Удалены:
  SG-Panel, SG-Node, Xray, Nginx, Certbot, сертификаты,
  GeoFiles, WARP, резервные копии, swap и временные данные.

Сохранены:
  SSH, сеть Ubuntu, /home и настройки AWS/EC2.

Теперь на этом же EC2 можно снова запускать чистый установщик.
Перезагрузка не обязательна, но рекомендуется перед контрольной установкой:
  sudo reboot
============================================================
DONE
