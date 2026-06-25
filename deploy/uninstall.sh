#!/usr/bin/env bash
set -Eeuo pipefail

ASSUME_YES=0
PURGE_ALL=0
REMOVE_XRAY=1
REMOVE_BACKUPS=1

usage() {
  cat <<'USAGE'
Использование:
  uninstall.sh [--yes] [--keep-xray] [--keep-backups]
  uninstall.sh --purge-all [--yes]

Обычный режим удаляет SG-Panel и Xray, но сохраняет Nginx, Certbot,
сертификаты Let's Encrypt, системные пакеты и swap.

--purge-all выполняет полную очистку тестового EC2:
  SG-Panel, Xray, Nginx, Certbot, сертификаты Let's Encrypt,
  ACME-каталог, swap, резервирование порта и временные файлы.
SSH, системная сеть и AWS Security Group не изменяются.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) ASSUME_YES=1; shift ;;
    --purge-all) PURGE_ALL=1; shift ;;
    --keep-xray) REMOVE_XRAY=0; shift ;;
    --keep-backups) REMOVE_BACKUPS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ошибка: запустите от root" >&2; exit 1; }

if [[ $PURGE_ALL -eq 1 ]]; then
  REMOVE_XRAY=1
  REMOVE_BACKUPS=1
fi

if [[ $ASSUME_YES -ne 1 ]]; then
  if [[ $PURGE_ALL -eq 1 ]]; then
    cat <<'WARNING'
ПОЛНАЯ ОЧИСТКА ТЕСТОВОГО EC2.

Будут удалены:
  SG-Panel и её база данных
  Xray и его конфигурация
  Nginx и Certbot
  все сертификаты Let's Encrypt на этом EC2
  /var/www/letsencrypt
  /swapfile и его запись в /etc/fstab
  резервирование порта SG-Panel
  резервные и временные файлы SG-Panel

SSH, системная сеть и AWS Security Group не изменяются.
WARNING
    read -r -p "Введите УДАЛИТЬ ВСЁ для продолжения: " answer
    [[ "$answer" == "УДАЛИТЬ ВСЁ" ]] || { echo "Отменено."; exit 0; }
  else
    cat <<'WARNING'
Будут удалены SG-Panel, её службы, конфигурация Nginx,
созданная панелью, и Xray.

Nginx, Certbot, сертификаты Let's Encrypt, пакеты и swap сохранятся.
WARNING
    read -r -p "Введите УДАЛИТЬ для продолжения: " answer
    [[ "$answer" == "УДАЛИТЬ" ]] || { echo "Отменено."; exit 0; }
  fi
fi

log() {
  printf '[SG-Panel uninstall] %s\n' "$*"
}

log "Останавливаю службы SG-Panel"
systemctl disable --now xpanel-maintenance.timer 2>/dev/null || true
systemctl stop xpanel-maintenance.service 2>/dev/null || true
systemctl disable --now xpanel-web.service 2>/dev/null || true

rm -f \
  /etc/systemd/system/xpanel-web.service \
  /etc/systemd/system/xpanel-maintenance.service \
  /etc/systemd/system/xpanel-maintenance.timer

if [[ $REMOVE_XRAY -eq 1 ]]; then
  log "Удаляю Xray"
  systemctl disable --now xray.service 2>/dev/null || true
  systemctl disable --now 'xray@.service' 2>/dev/null || true
  rm -rf \
    /etc/systemd/system/xray.service \
    /etc/systemd/system/xray@.service \
    /etc/systemd/system/xray.service.d \
    /usr/local/bin/xray \
    /usr/local/share/xray \
    /usr/local/etc/xray \
    /var/log/xray
fi

log "Удаляю файлы SG-Panel"
rm -rf /opt/xpanel-mvp /etc/xpanel-mvp
[[ $REMOVE_BACKUPS -eq 1 ]] && rm -rf /root/sg-panel-backups
rm -rf \
  /tmp/sg-panel-install.* \
  /tmp/sg-panel-src \
  /tmp/sg-panel-main.zip \
  /tmp/install-sg-panel.sh \
  /tmp/sg-panel-uninstall.sh

log "Удаляю конфигурацию Nginx, созданную SG-Panel"
rm -f \
  /etc/nginx/sites-enabled/sg-panel \
  /etc/nginx/sites-enabled/sg-panel-acme \
  /etc/nginx/sites-available/sg-panel \
  /etc/nginx/sites-available/sg-panel-acme \
  /etc/letsencrypt/renewal-hooks/deploy/reload-sg-panel-nginx.sh

log "Удаляю резервирование порта SG-Panel"
rm -f /etc/sysctl.d/99-sg-panel-port.conf
sysctl --system >/dev/null 2>&1 || true

if [[ $PURGE_ALL -eq 1 ]]; then
  log "Удаляю Nginx, Certbot и Let's Encrypt"
  systemctl disable --now nginx.service 2>/dev/null || true
  systemctl disable --now certbot.timer 2>/dev/null || true

  rm -rf \
    /etc/nginx \
    /var/log/nginx \
    /var/cache/nginx \
    /var/lib/nginx \
    /var/www/letsencrypt \
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

  if (( ${#packages[@]} > 0 )); then
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
fi

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

if [[ $PURGE_ALL -eq 1 ]]; then
  echo
  cat <<'DONE'
Полная очистка SG-Panel завершена.

Удалены SG-Panel, Xray, Nginx, Certbot, сертификаты Let's Encrypt,
ACME-каталог, swap, резервирование порта и временные файлы.

SSH, системная сеть и AWS Security Group сохранены.
Этот EC2 готов к повторной установке с самого начала.
DONE
else
  if command -v nginx >/dev/null 2>&1; then
    nginx -t
    systemctl reload nginx 2>/dev/null || true
  fi

  echo
  cat <<'DONE'
SG-Panel удалена.

Сохранены Nginx, Certbot, сертификаты Let's Encrypt,
установленные системные пакеты и /swapfile.
DONE
fi
