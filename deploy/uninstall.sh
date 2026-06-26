#!/usr/bin/env bash
set -Eeuo pipefail

ASSUME_YES=0
REMOVE_XRAY=0
REMOVE_BACKUPS=0

usage() {
  cat <<'USAGE'
Использование:
  uninstall.sh [--yes] [--remove-xray] [--remove-backups]

Без дополнительных параметров скрипт удаляет только SG-Panel:
  - приложение и виртуальное окружение;
  - службы SG-Panel;
  - конфигурацию Nginx, созданную SG-Panel;
  - страницу-заглушку и резервирование порта панели.

По умолчанию сохраняются:
  - Xray, его служба и текущий config.json;
  - резервные копии /root/sg-panel-backups;
  - Nginx, Certbot и сертификаты Let's Encrypt;
  - системные пакеты и /swapfile.

Дополнительные параметры:
  --remove-xray       также удалить Xray и его конфигурацию
  --remove-backups    также удалить резервные копии SG-Panel
  --yes               не запрашивать подтверждение
  -h, --help          показать эту справку

Полная очистка одноразового тестового сервера вынесена в отдельный скрипт:
  deploy/purge-test-server.sh
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      ASSUME_YES=1
      shift
      ;;
    --remove-xray)
      REMOVE_XRAY=1
      shift
      ;;
    --remove-backups)
      REMOVE_BACKUPS=1
      shift
      ;;
    --keep-xray|--keep-backups)
      printf '[SG-Panel uninstall] Параметр %s больше не требуется: сохранение включено по умолчанию.\n' "$1" >&2
      shift
      ;;
    --purge-all)
      cat >&2 <<'ERROR'
Параметр --purge-all удалён из uninstall.sh из соображений безопасности.
Для полной очистки одноразового тестового сервера используйте отдельный скрипт:
  deploy/purge-test-server.sh
ERROR
      exit 2
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

log() {
  printf '[SG-Panel uninstall] %s\n' "$*"
}

make_final_backup() {
  [[ $REMOVE_BACKUPS -eq 0 ]] || return 0

  local stamp backup_dir copied=0
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_dir="/root/sg-panel-backups/uninstall-$stamp"

  if [[ -f /opt/xpanel-mvp/data/panel.db || \
        -f /usr/local/etc/xray/config.json || \
        -f /etc/xpanel-mvp/web.env || \
        -f /root/sg-panel-first-user.txt ]]; then
    install -d -m 700 "$backup_dir"

    if [[ -f /opt/xpanel-mvp/data/panel.db ]]; then
      cp -a /opt/xpanel-mvp/data/panel.db "$backup_dir/panel.db"
      copied=1
    fi
    if [[ -f /usr/local/etc/xray/config.json ]]; then
      cp -a /usr/local/etc/xray/config.json "$backup_dir/xray-config.json"
      copied=1
    fi
    if [[ -f /etc/xpanel-mvp/web.env ]]; then
      cp -a /etc/xpanel-mvp/web.env "$backup_dir/web.env"
      copied=1
    fi
    if [[ -f /root/sg-panel-first-user.txt ]]; then
      cp -a /root/sg-panel-first-user.txt "$backup_dir/first-user.txt"
      copied=1
    fi

    if [[ $copied -eq 1 ]]; then
      chmod 600 "$backup_dir"/* 2>/dev/null || true
      cat > "$backup_dir/README.txt" <<TXT
Финальная резервная копия создана перед удалением SG-Panel.
Дата UTC: $stamp

Файлы могут содержать UUID, парольные хеши, токены и приватный Reality-ключ.
Храните каталог с правами root и не публикуйте его.
TXT
      chmod 600 "$backup_dir/README.txt"
      log "Финальная резервная копия: $backup_dir"
    else
      rmdir "$backup_dir" 2>/dev/null || true
    fi
  fi
}

print_plan() {
  cat <<'PLAN'
Будут удалены:
  - SG-Panel, её база из рабочего каталога и виртуальное окружение;
  - службы xpanel-web и xpanel-maintenance;
  - конфигурация Nginx и страница-заглушка SG-Panel;
  - резервирование внешнего порта панели.
PLAN

  if [[ $REMOVE_XRAY -eq 1 ]]; then
    cat <<'PLAN'
  - Xray, его systemd-служба, бинарный файл, конфигурация и журналы.
PLAN
  else
    cat <<'PLAN'

Будут сохранены:
  - Xray, его systemd-служба и текущая конфигурация.
PLAN
  fi

  if [[ $REMOVE_BACKUPS -eq 1 ]]; then
    cat <<'PLAN'
  - все резервные копии /root/sg-panel-backups.
PLAN
  else
    cat <<'PLAN'
  - резервные копии /root/sg-panel-backups;
  - перед удалением будет создана финальная копия текущей базы и config.json.
PLAN
  fi

  cat <<'PLAN'
  - Nginx, Certbot, сертификаты Let's Encrypt, системные пакеты и /swapfile.
PLAN
}

if [[ $ASSUME_YES -ne 1 ]]; then
  print_plan
  echo
  read -r -p "Введите УДАЛИТЬ ПАНЕЛЬ для продолжения: " answer
  [[ "$answer" == "УДАЛИТЬ ПАНЕЛЬ" ]] || { echo "Отменено."; exit 0; }
fi

make_final_backup

log "Останавливаю службы SG-Panel"
systemctl disable --now xpanel-maintenance.timer 2>/dev/null || true
systemctl stop xpanel-maintenance.service 2>/dev/null || true
systemctl disable --now xpanel-web.service 2>/dev/null || true

rm -f \
  /etc/systemd/system/xpanel-web.service \
  /etc/systemd/system/xpanel-maintenance.service \
  /etc/systemd/system/xpanel-maintenance.timer

if [[ $REMOVE_XRAY -eq 1 ]]; then
  log "Удаляю Xray по явному параметру --remove-xray"
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
  rm -f /root/sg-panel-first-user.txt
fi

log "Удаляю файлы SG-Panel"
rm -rf /opt/xpanel-mvp /etc/xpanel-mvp

if [[ $REMOVE_BACKUPS -eq 1 ]]; then
  log "Удаляю резервные копии по явному параметру --remove-backups"
  rm -rf /root/sg-panel-backups
fi

rm -rf \
  /tmp/sg-panel-install.* \
  /tmp/sg-panel-src \
  /tmp/sg-panel-main.zip \
  /tmp/install-sg-panel.sh \
  /tmp/uninstall-sg-panel.sh \
  /tmp/sg-panel-uninstall.sh

log "Удаляю только конфигурацию Nginx, созданную SG-Panel"
rm -f \
  /etc/nginx/sites-enabled/sg-panel \
  /etc/nginx/sites-enabled/sg-panel-acme \
  /etc/nginx/sites-available/sg-panel \
  /etc/nginx/sites-available/sg-panel-acme \
  /etc/letsencrypt/renewal-hooks/deploy/reload-sg-panel-nginx.sh
rm -rf /var/www/sg-panel-placeholder

log "Удаляю резервирование порта SG-Panel"
rm -f /etc/sysctl.d/99-sg-panel-port.conf
sysctl --system >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

if command -v nginx >/dev/null 2>&1; then
  if nginx -t; then
    systemctl reload nginx 2>/dev/null || true
  else
    log "Внимание: nginx -t завершился ошибкой; Nginx не перезагружен"
  fi
fi

echo
cat <<DONE
SG-Panel удалена.

Сохранены:
  Nginx, Certbot, сертификаты Let's Encrypt, системные пакеты и /swapfile.
DONE

if [[ $REMOVE_XRAY -eq 0 ]]; then
  echo "  Xray, его служба и текущая конфигурация."
else
  echo "  Xray удалён по параметру --remove-xray."
fi

if [[ $REMOVE_BACKUPS -eq 0 ]]; then
  echo "  Резервные копии в /root/sg-panel-backups."
else
  echo "  Резервные копии удалены по параметру --remove-backups."
fi
