#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_VERSION="0.10.0-rc7"
TARGET="/opt/xpanel-mvp"
SERVICE="xpanel-web"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd /
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="/root/sg-panel-backups/$STAMP"
ROLLBACK_NEEDED=0
OLD_EXISTS=0

log(){ printf '[SG-Panel] %s\n' "$*"; }
fail(){ printf '[SG-Panel] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
[[ -f "$SOURCE_DIR/xpanel/__init__.py" ]] || fail "запускайте скрипт из распакованного каталога xpanel-mvp"
grep -q "__version__ = \"$EXPECTED_VERSION\"" "$SOURCE_DIR/xpanel/__init__.py" || fail "исходники не версии $EXPECTED_VERSION"
for command in rsync python3 curl; do command -v "$command" >/dev/null || fail "не найден $command"; done

mkdir -p "$BACKUP_ROOT"
if [[ -d "$TARGET" ]]; then
  OLD_EXISTS=1
  log "Создаю резервную копию текущей установки"
  cp -a "$TARGET" "$BACKUP_ROOT/xpanel-mvp"
fi
[[ -f /etc/xpanel-mvp/web.env ]] && cp -a /etc/xpanel-mvp/web.env "$BACKUP_ROOT/web.env"
[[ -f /etc/systemd/system/xpanel-web.service ]] && cp -a /etc/systemd/system/xpanel-web.service "$BACKUP_ROOT/xpanel-web.service"
[[ -f /usr/local/etc/xray/config.json ]] && cp -a /usr/local/etc/xray/config.json "$BACKUP_ROOT/xray-config.json"
[[ -d /etc/xpanel-mvp/warp ]] && cp -a /etc/xpanel-mvp/warp "$BACKUP_ROOT/warp"

rollback(){
  local rc=$?
  if [[ $ROLLBACK_NEEDED -eq 1 ]]; then
    log "Обновление не завершено, выполняю rollback"
    systemctl stop "$SERVICE" 2>/dev/null || true
    rm -rf "$TARGET"
    if [[ $OLD_EXISTS -eq 1 && -d "$BACKUP_ROOT/xpanel-mvp" ]]; then cp -a "$BACKUP_ROOT/xpanel-mvp" "$TARGET"; fi
    if [[ -f "$BACKUP_ROOT/web.env" ]]; then mkdir -p /etc/xpanel-mvp; cp -a "$BACKUP_ROOT/web.env" /etc/xpanel-mvp/web.env; fi
    if [[ -f "$BACKUP_ROOT/xpanel-web.service" ]]; then cp -a "$BACKUP_ROOT/xpanel-web.service" /etc/systemd/system/xpanel-web.service; fi
    if [[ -d "$BACKUP_ROOT/warp" ]]; then
      rm -rf /etc/xpanel-mvp/warp
      mkdir -p /etc/xpanel-mvp
      cp -a "$BACKUP_ROOT/warp" /etc/xpanel-mvp/warp
    fi
    systemctl daemon-reload || true
    systemctl restart "$SERVICE" 2>/dev/null || true
  fi
  exit "$rc"
}
trap rollback ERR INT TERM

ROLLBACK_NEEDED=1
systemctl stop "$SERVICE" 2>/dev/null || true
mkdir -p "$TARGET"

log "Копирую версию $EXPECTED_VERSION"
rsync -a --delete \
  --exclude='.git/' --exclude='.venv/' --exclude='data/' --exclude='backups/' \
  --exclude='__pycache__/' --exclude='*.pyc' \
  "$SOURCE_DIR/" "$TARGET/"
mkdir -p "$TARGET/data" "$TARGET/backups"
if [[ -f "$BACKUP_ROOT/xpanel-mvp/data/panel.db" ]]; then cp -a "$BACKUP_ROOT/xpanel-mvp/data/panel.db" "$TARGET/data/panel.db"; fi

cd "$TARGET"
if ! bash deploy/install-wgcf-cli.sh; then
  log "WARNING: wgcf-cli was not installed; SG-Panel works, but WARP creation is unavailable until the helper is installed"
fi
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/pip install --no-cache-dir -q --upgrade pip
.venv/bin/pip install --no-cache-dir -q -r requirements.txt
.venv/bin/python -m xpanel init-db

if [[ ! -f /etc/xpanel-mvp/web.env ]]; then
  log "Первая установка GUI: потребуется пароль администратора"
  bash deploy/install-gui.sh
else
  python3 - /etc/xpanel-mvp/web.env <<'PY'
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
PY
  bash deploy/install-service.sh
  bash deploy/install-maintenance.sh
  systemctl restart "$SERVICE"
fi
sleep 3

CLI_VERSION="$(cd "$TARGET" && .venv/bin/python -m xpanel --version | awk '{print $2}')"
[[ "$CLI_VERSION" == "$EXPECTED_VERSION" ]] || fail "CLI сообщает версию $CLI_VERSION"
systemctl is-active --quiet "$SERVICE" || fail "служба $SERVICE не active"

BIND="$(grep -E '^XPANEL_BIND_ADDRESS=' /etc/xpanel-mvp/web.env | tail -1 | cut -d= -f2- || true)"
PORT="$(grep -E '^XPANEL_PORT=' /etc/xpanel-mvp/web.env | tail -1 | cut -d= -f2- || true)"
BIND="${BIND:-0.0.0.0}"; PORT="${PORT:-8080}"
case "$BIND" in
  0.0.0.0|127.0.0.1) HEALTH_HOST="127.0.0.1" ;;
  ::|::0|::1) HEALTH_HOST="[::1]" ;;
  *) HEALTH_HOST="$BIND" ;;
esac
HTTP_BODY="$(curl -fsS "http://$HEALTH_HOST:$PORT/login")"
grep -q "v$EXPECTED_VERSION" <<<"$HTTP_BODY" || fail "GUI не отдаёт версию $EXPECTED_VERSION"

ROLLBACK_NEEDED=0
trap - ERR INT TERM
log "Готово: CLI $CLI_VERSION, GUI v$EXPECTED_VERSION, $SERVICE active"
log "Резервная копия: $BACKUP_ROOT"
