#!/usr/bin/env bash
set -Eeuo pipefail

ASSUME_YES=0
TOTAL_STAGES=7

usage() {
  cat <<'USAGE'
Использование:
  sudo bash deploy/full-uninstall.sh --yes

Полностью удаляет компоненты SG-Panel с выделенного тестового сервера:
  - SG-Panel, базу, службы, резервные копии и временные данные;
  - Xray, его конфигурацию и журналы;
  - Nginx, Certbot и все сертификаты Let's Encrypt;
  - страницу-заглушку и конфигурацию fallback;
  - wgcf-cli, данные WARP и swap, созданный установщиком;
  - резервирование порта панели.

SSH, системная сеть и правила Security Group / облачного firewall не меняются.
Скрипт предназначен только для отдельного тестового сервера без других сайтов.
Параметр --yes обязателен. Дополнительного текстового подтверждения нет.
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

[[ $EUID -eq 0 ]] || {
  echo "Ошибка: запустите скрипт через sudo." >&2
  exit 1
}

[[ $ASSUME_YES -eq 1 ]] || {
  echo "Отказ: для полной очистки требуется параметр --yes." >&2
  echo "Команда: sudo bash deploy/full-uninstall.sh --yes" >&2
  exit 2
}

cd /

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
  local output rc pid frame_index=0 started elapsed
  local frames='|/-\\'
  output="$(mktemp /tmp/sg-panel-uninstall-stage.XXXXXX)"
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
    if "$@" >"$output" 2>&1; then
      rc=0
    else
      rc=$?
    fi
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

stop_services() {
  local unit
  for unit in \
    xpanel-maintenance.timer \
    xpanel-maintenance.service \
    xpanel-traffic.timer \
    xpanel-traffic.service \
    xpanel-web.service \
    xray.service \
    'xray@.service' \
    nginx.service \
    certbot.timer; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl stop "$unit" >/dev/null 2>&1 || true
  done

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    systemctl stop "$unit" >/dev/null 2>&1 || true
  done < <(systemctl list-units --all --plain --no-legend 'sg-panel-*' 2>/dev/null | awk '{print $1}')
}

remove_panel_and_xray() {
  rm -rf \
    /opt/xpanel-mvp \
    /etc/xpanel-mvp \
    /root/sg-panel-backups \
    /root/sg-panel-first-user.txt \
    /etc/systemd/system/xpanel-web.service \
    /etc/systemd/system/xpanel-maintenance.service \
    /etc/systemd/system/xpanel-maintenance.timer \
    /etc/systemd/system/xpanel-traffic.service \
    /etc/systemd/system/xpanel-traffic.timer \
    /etc/systemd/system/xray.service \
    /etc/systemd/system/xray@.service \
    /etc/systemd/system/xray.service.d \
    /usr/local/bin/xray \
    /usr/local/bin/wgcf-cli \
    /usr/local/share/xray \
    /usr/local/etc/xray \
    /var/log/xray
}

remove_web_and_certificates() {
  if command -v snap >/dev/null 2>&1 && snap list certbot >/dev/null 2>&1; then
    snap remove certbot >/dev/null 2>&1 || true
  fi

  rm -rf \
    /etc/nginx \
    /var/log/nginx \
    /var/cache/nginx \
    /var/lib/nginx \
    /var/www/letsencrypt \
    /var/www/sg-panel-placeholder \
    /etc/letsencrypt \
    /var/lib/letsencrypt \
    /var/log/letsencrypt
}

wait_for_package_manager() {
  local attempts=0
  while true; do
    if command -v fuser >/dev/null 2>&1; then
      if ! fuser \
        /var/lib/dpkg/lock-frontend \
        /var/lib/dpkg/lock \
        /var/cache/apt/archives/lock >/dev/null 2>&1; then
        return 0
      fi
    elif ! pgrep -x apt >/dev/null 2>&1 && \
         ! pgrep -x apt-get >/dev/null 2>&1 && \
         ! pgrep -x dpkg >/dev/null 2>&1 && \
         ! pgrep -f unattended-upgrade >/dev/null 2>&1; then
      return 0
    fi

    attempts=$((attempts + 1))
    if (( attempts >= 120 )); then
      echo "Менеджер пакетов Ubuntu занят более 10 минут." >&2
      echo "Дождитесь завершения обновления и повторите полный uninstall." >&2
      return 1
    fi
    sleep 5
  done
}

purge_packages() {
  local package
  local packages=()

  for package in \
    nginx nginx-common nginx-core nginx-full nginx-light libnginx-mod-stream \
    certbot python3-certbot python3-certbot-nginx python3-acme; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
      packages+=("$package")
    fi
  done

  if (( ${#packages[@]} > 0 )); then
    wait_for_package_manager
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y "${packages[@]}"
    apt-get autoremove -y --purge
    apt-get clean
  fi
}

remove_swap_and_port_reservation() {
  if swapon --show=NAME --noheadings 2>/dev/null | grep -qx '/swapfile'; then
    swapoff /swapfile
  fi
  if [[ -f /etc/fstab ]]; then
    sed -i '\|^/swapfile[[:space:]]|d' /etc/fstab
  fi
  rm -f /swapfile /etc/sysctl.d/99-sg-panel-port.conf
  sysctl --system >/dev/null 2>&1 || true
}

remove_temporary_data() {
  rm -rf \
    /tmp/sg-panel-install.* \
    /tmp/sg-panel-src \
    /tmp/sg-panel-main.zip \
    /tmp/install-sg-panel.sh \
    /tmp/uninstall-sg-panel.sh \
    /tmp/sg-panel-uninstall.sh \
    /tmp/sg-panel-stage.* \
    /tmp/sg-panel-wgcf.* \
    /tmp/sg-panel-validate-* \
    /tmp/sg-panel-candidate-* \
    /tmp/sg-panel-verify-*

  systemctl daemon-reload
  systemctl reset-failed >/dev/null 2>&1 || true
}

verify_removal() {
  local path package
  local leftovers=()

  for path in \
    /opt/xpanel-mvp \
    /etc/xpanel-mvp \
    /root/sg-panel-backups \
    /root/sg-panel-first-user.txt \
    /usr/local/bin/xray \
    /usr/local/bin/wgcf-cli \
    /usr/local/etc/xray \
    /etc/nginx \
    /etc/letsencrypt \
    /var/www/sg-panel-placeholder \
    /swapfile \
    /etc/sysctl.d/99-sg-panel-port.conf; do
    [[ ! -e "$path" ]] || leftovers+=("$path")
  done

  for package in nginx nginx-common nginx-core nginx-full nginx-light libnginx-mod-stream certbot; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
      leftovers+=("package:$package")
    fi
  done

  if [[ -f /etc/fstab ]] && grep -Eq '^/swapfile[[:space:]]' /etc/fstab; then
    leftovers+=("/etc/fstab:/swapfile")
  fi

  if (( ${#leftovers[@]} > 0 )); then
    echo "Остались компоненты:" >&2
    printf '  %s\n' "${leftovers[@]}" >&2
    return 1
  fi
}

printf '\n%sSG-Panel: полный uninstall тестового сервера%s\n' "$COLOR_YELLOW" "$COLOR_RESET"
printf 'Будут удалены SG-Panel, Xray, Nginx, Certbot, сертификаты, WARP, swap и резервные копии.\n'
printf 'SSH, сеть Ubuntu и Security Group не изменяются.\n\n'

run_stage "Этап 1/$TOTAL_STAGES · Остановка служб" stop_services
run_stage "Этап 2/$TOTAL_STAGES · Удаление SG-Panel, Xray и WARP" remove_panel_and_xray
run_stage "Этап 3/$TOTAL_STAGES · Удаление системных пакетов веб-сервера" purge_packages
run_stage "Этап 4/$TOTAL_STAGES · Удаление Nginx и сертификатов" remove_web_and_certificates
run_stage "Этап 5/$TOTAL_STAGES · Удаление swap и резервирования порта" remove_swap_and_port_reservation
run_stage "Этап 6/$TOTAL_STAGES · Очистка временных данных" remove_temporary_data
run_stage "Этап 7/$TOTAL_STAGES · Финальная проверка" verify_removal

cat <<DONE

============================================================
${COLOR_GREEN}Полный uninstall SG-Panel завершён успешно.${COLOR_RESET}

Удалены:
  SG-Panel, Xray, WARP, Nginx, Certbot, сертификаты Let's Encrypt,
  fallback/заглушка, резервные копии, swap и временные данные.

Сохранены:
  SSH, сеть Ubuntu, пользовательские файлы в /home и Security Group EC2.
============================================================
DONE
