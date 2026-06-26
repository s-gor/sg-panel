#!/usr/bin/env bash
set -Eeuo pipefail

ASSUME_YES=0
EXPLICIT_CONFIRM=0

usage() {
  cat <<'USAGE'
Использование:
  purge-test-server.sh --destroy-test-server [--yes]

ОПАСНО: этот скрипт предназначен только для одноразового тестового сервера.
Он удаляет SG-Panel, Xray, Nginx, Certbot, все сертификаты Let's Encrypt,
ACME-каталоги, страницу-заглушку, /swapfile, резервные копии и временные файлы.

Не запускайте его на сервере с другими сайтами, сертификатами или сервисами Nginx.
SSH, системная сеть и правила облачного firewall не изменяются.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --destroy-test-server)
      EXPLICIT_CONFIRM=1
      shift
      ;;
    --yes)
      ASSUME_YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Неизвестный параметр: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ошибка: запустите скрипт от root" >&2; exit 1; }
cd /
[[ $EXPLICIT_CONFIRM -eq 1 ]] || {
  echo "Отказ: требуется явный параметр --destroy-test-server" >&2
  usage >&2
  exit 2
}

if [[ $ASSUME_YES -ne 1 ]]; then
  cat <<'WARNING'
ПОЛНАЯ ОЧИСТКА ОДНОРАЗОВОГО ТЕСТОВОГО СЕРВЕРА.

Будут безвозвратно удалены:
  - SG-Panel и все её данные;
  - Xray и его конфигурация;
  - Nginx и все его конфигурации;
  - Certbot и все сертификаты Let's Encrypt;
  - /etc/letsencrypt, /var/lib/letsencrypt и /var/log/letsencrypt;
  - /var/www/letsencrypt и страница-заглушка;
  - /swapfile и его запись в /etc/fstab;
  - резервные копии /root/sg-panel-backups;
  - временные файлы SG-Panel.

SSH, системная сеть и правила облачного firewall не изменяются.
WARNING
  read -r -p "Type DELETE ALL to continue: " answer
  [[ "$answer" == "DELETE ALL" ]] || { echo "Отменено."; exit 0; }
fi

log() {
  printf '[SG-Panel purge] %s\n' "$*"
}

log "Останавливаю службы"
systemctl disable --now xpanel-maintenance.timer 2>/dev/null || true
systemctl stop xpanel-maintenance.service 2>/dev/null || true
systemctl disable --now xpanel-web.service 2>/dev/null || true
systemctl disable --now xray.service 2>/dev/null || true
systemctl disable --now 'xray@.service' 2>/dev/null || true
systemctl disable --now nginx.service 2>/dev/null || true
systemctl disable --now certbot.timer 2>/dev/null || true

log "Удаляю SG-Panel и Xray"
rm -rf \
  /opt/xpanel-mvp \
  /etc/xpanel-mvp \
  /root/sg-panel-backups \
  /root/sg-panel-first-user.txt \
  /etc/systemd/system/xpanel-web.service \
  /etc/systemd/system/xpanel-maintenance.service \
  /etc/systemd/system/xpanel-maintenance.timer \
  /etc/systemd/system/xray.service \
  /etc/systemd/system/xray@.service \
  /etc/systemd/system/xray.service.d \
  /usr/local/bin/xray \
  /usr/local/share/xray \
  /usr/local/etc/xray \
  /var/log/xray

log "Удаляю Nginx, Certbot и все данные Let's Encrypt"
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

packages=()
for package in \
  nginx nginx-common nginx-core nginx-full nginx-light \
  certbot python3-certbot python3-certbot-nginx python3-acme; do
  if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
    packages+=("$package")
  fi
done

wait_for_package_manager(){
  local attempts=0
  while true; do
    if command -v fuser >/dev/null 2>&1; then
      if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock           /var/cache/apt/archives/lock >/dev/null 2>&1; then
        return 0
      fi
    elif ! pgrep -x apt >/dev/null 2>&1 &&          ! pgrep -x apt-get >/dev/null 2>&1 &&          ! pgrep -x dpkg >/dev/null 2>&1 &&          ! pgrep -f unattended-upgrade >/dev/null 2>&1; then
      return 0
    fi

    attempts=$((attempts + 1))
    if (( attempts >= 120 )); then
      echo "Ошибка: менеджер пакетов занят более 10 минут." >&2
      echo "Дождитесь завершения обновления Ubuntu и повторите запуск." >&2
      exit 1
    fi
    if (( attempts == 1 || attempts % 6 == 0 )); then
      log "Ожидаю освобождения менеджера пакетов Ubuntu"
    fi
    sleep 5
  done
}

if (( ${#packages[@]} > 0 )); then
  wait_for_package_manager
  export DEBIAN_FRONTEND=noninteractive
  apt-get purge -y "${packages[@]}"
  apt-get autoremove -y --purge
  apt-get clean
fi

log "Удаляю swap, созданный установщиком"
if swapon --show=NAME --noheadings 2>/dev/null | grep -qx '/swapfile'; then
  swapoff /swapfile
fi
sed -i '\|^/swapfile[[:space:]]|d' /etc/fstab
rm -f /swapfile

log "Удаляю резервирование порта и временные файлы"
rm -f /etc/sysctl.d/99-sg-panel-port.conf
rm -rf \
  /tmp/sg-panel-install.* \
  /tmp/sg-panel-src \
  /tmp/sg-panel-main.zip \
  /tmp/install-sg-panel.sh \
  /tmp/uninstall-sg-panel.sh \
  /tmp/sg-panel-uninstall.sh
sysctl --system >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

cat <<'DONE'

Полная очистка тестового сервера завершена.

Удалены SG-Panel, Xray, Nginx, Certbot, сертификаты Let's Encrypt,
ACME-каталоги, swap, резервные копии и временные файлы.
SSH, системная сеть и правила облачного firewall сохранены.
DONE
