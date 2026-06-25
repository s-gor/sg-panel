#!/usr/bin/env bash
set -Eeuo pipefail

ASSUME_YES=0
REMOVE_XRAY=1
REMOVE_BACKUPS=1

usage() {
  cat <<'USAGE'
Использование:
  uninstall.sh [--yes] [--keep-xray] [--keep-backups]

Удаляет SG-Panel и созданную ею конфигурацию с сервера.
Сертификаты Let's Encrypt, Nginx, Certbot, системные пакеты и swap сохраняются.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) ASSUME_YES=1; shift ;;
    --keep-xray) REMOVE_XRAY=0; shift ;;
    --keep-backups) REMOVE_BACKUPS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ошибка: запустите от root" >&2; exit 1; }

if [[ $ASSUME_YES -ne 1 ]]; then
  cat <<'WARNING'
Будут удалены:
  /opt/xpanel-mvp
  /etc/xpanel-mvp
  службы xpanel-web и xpanel-maintenance
  конфигурация Nginx, созданная SG-Panel
  конфигурация Xray, установленная SG-Panel

Сертификаты Let's Encrypt, Nginx, Certbot, пакеты и /swapfile останутся.
WARNING
  read -r -p "Введите УДАЛИТЬ для продолжения: " answer
  [[ "$answer" == "УДАЛИТЬ" ]] || { echo "Отменено."; exit 0; }
fi

echo "[SG-Panel uninstall] Останавливаю службы"
systemctl disable --now xpanel-maintenance.timer 2>/dev/null || true
systemctl stop xpanel-maintenance.service 2>/dev/null || true
systemctl disable --now xpanel-web.service 2>/dev/null || true

rm -f \
  /etc/systemd/system/xpanel-web.service \
  /etc/systemd/system/xpanel-maintenance.service \
  /etc/systemd/system/xpanel-maintenance.timer

if [[ $REMOVE_XRAY -eq 1 ]]; then
  systemctl disable --now xray.service 2>/dev/null || true
  rm -rf \
    /etc/systemd/system/xray.service \
    /etc/systemd/system/xray@.service \
    /etc/systemd/system/xray.service.d \
    /usr/local/bin/xray \
    /usr/local/share/xray \
    /usr/local/etc/xray \
    /var/log/xray
fi

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

echo "[SG-Panel uninstall] Удаляю файлы панели"
rm -rf /opt/xpanel-mvp /etc/xpanel-mvp
[[ $REMOVE_BACKUPS -eq 1 ]] && rm -rf /root/sg-panel-backups
rm -rf /tmp/sg-panel-install.* /tmp/sg-panel-src /tmp/sg-panel-main.zip

echo "[SG-Panel uninstall] Удаляю конфигурацию Nginx"
rm -f \
  /etc/nginx/sites-enabled/sg-panel \
  /etc/nginx/sites-enabled/sg-panel-acme \
  /etc/nginx/sites-available/sg-panel \
  /etc/nginx/sites-available/sg-panel-acme \
  /etc/letsencrypt/renewal-hooks/deploy/reload-sg-panel-nginx.sh

if command -v nginx >/dev/null 2>&1; then
  nginx -t
  systemctl reload nginx 2>/dev/null || true
fi

rm -f /etc/sysctl.d/99-sg-panel-port.conf

echo
cat <<'DONE'
SG-Panel удалена.
Сохранены:
  сертификаты Let's Encrypt
  Nginx и Certbot
  установленные системные пакеты
  /swapfile

Сервер готов к чистой повторной установке SG-Panel.
DONE
