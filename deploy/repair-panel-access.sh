#!/usr/bin/env bash
set -Eeuo pipefail

NGINX_CONF="/etc/nginx/sites-available/sg-panel"
STATE_FILE="/etc/xpanel-mvp/panel-access.env"
INSTALL_MARKER="/etc/xpanel-mvp/install-complete.env"
PROJECT_DIR="/opt/xpanel-mvp"

log(){ printf '[SG-Panel Access Repair] %s\n' "$*"; }
fail(){ printf '[SG-Panel Access Repair] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "запустите от root"
[[ -f "$NGINX_CONF" ]] || { log "конфигурация Nginx отсутствует, исправление не требуется"; exit 0; }

BACKUP="$(mktemp /root/sg-panel-nginx.XXXXXX)"
cp -a "$NGINX_CONF" "$BACKUP"
COMMITTED=0
rollback(){
  local rc=$?
  if [[ $COMMITTED -eq 0 ]]; then
    cp -a "$BACKUP" "$NGINX_CONF"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  fi
  rm -f "$BACKUP"
  exit "$rc"
}
trap rollback ERR INT TERM

META_OUTPUT="$(python3 - "$NGINX_CONF" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
match = re.search(
    r"(?m)^(?P<line>\s*listen\s+(?:\[::\]:)?(?P<port>\d+)\s+ssl(?:\s+[^;]*)?;)\s*$",
    text,
)
if not match:
    print("http")
    print("")
    print("")
    print("0")
    raise SystemExit(0)

hosts = re.findall(r"(?m)^\s*server_name\s+([^;\s]+)\s*;", text)
host = next((item for item in hosts if item != "_"), "")
if not re.fullmatch(r"([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", host):
    raise SystemExit("HTTPS listener found but canonical domain is missing")

port = match.group("port")
canonical = f"    error_page 497 =308 https://{host}:{port}$request_uri;"
clean = re.sub(r"(?m)^\s*error_page\s+497\b[^\n]*\n?", "", text)
match = re.search(
    r"(?m)^\s*listen\s+(?:\[::\]:)?" + re.escape(port) + r"\s+ssl(?:\s+[^;]*)?;\s*$",
    clean,
)
if not match:
    raise SystemExit("cannot locate HTTPS listener")
new_text = clean[:match.end()] + "\n" + canonical + clean[match.end():]
changed = int(new_text != text)
if changed:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(new_text, encoding="utf-8")
    temporary.chmod(path.stat().st_mode)
    temporary.replace(path)

print("https")
print(host)
print(port)
print(changed)
PY
)"
mapfile -t META <<<"$META_OUTPUT"

MODE="${META[0]:-}"
HOST="${META[1]:-}"
PORT="${META[2]:-}"
CHANGED="${META[3]:-0}"

if [[ "$MODE" != "https" ]]; then
  log "активен HTTP, HTTPS-исправление не требуется"
  COMMITTED=1
  trap - ERR INT TERM
  rm -f "$BACKUP"
  exit 0
fi

nginx -t
if [[ "$CHANGED" == "1" ]]; then
  systemctl reload nginx
  log "добавлено перенаправление старого HTTP-адреса на https://$HOST:$PORT"
else
  log "перенаправление Nginx уже настроено"
fi

mkdir -p /etc/xpanel-mvp
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="unknown"
if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
  VERSION="$($PROJECT_DIR/.venv/bin/python -m xpanel --version 2>/dev/null | awk '{print $2}' || true)"
  VERSION="${VERSION:-unknown}"
fi
cat > "$STATE_FILE" <<EOF_STATE
PANEL_ACCESS_MODE=https
PANEL_PUBLIC_HOST=$HOST
PANEL_PUBLIC_PORT=$PORT
PANEL_DOMAIN=$HOST
UPDATED_AT=$NOW
EOF_STATE
chmod 600 "$STATE_FILE"
cat > "$INSTALL_MARKER" <<EOF_MARKER
INSTALL_COMPLETE=1
VERSION=$VERSION
PANEL_ACCESS_MODE=https
PANEL_PUBLIC_HOST=$HOST
PANEL_PUBLIC_PORT=$PORT
PANEL_DOMAIN=$HOST
COMPLETED_AT=$NOW
EOF_MARKER
chmod 600 "$INSTALL_MARKER"

if [[ -x "$PROJECT_DIR/.venv/bin/python" && -f "$PROJECT_DIR/data/panel.db" ]]; then
  cd "$PROJECT_DIR"
  .venv/bin/python - "$HOST" "$PORT" <<'PYDB'
import sys
from xpanel.db import connect, init_db
host, port = sys.argv[1:]
init_db()
with connect() as con:
    con.execute(
        "UPDATE subscription_settings SET base_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
        (f"https://{host}:{port}",),
    )
PYDB
fi

COMMITTED=1
trap - ERR INT TERM
rm -f "$BACKUP"
log "канонический адрес подтверждён: https://$HOST:$PORT"
