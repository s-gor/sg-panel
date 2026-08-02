#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${XPANEL_PROJECT_DIR:-/opt/xpanel-mvp}"
RUNTIME_HELPER="/usr/local/sbin/sg-panel-fix-xray-cert-access"
RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access"

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo "Ошибка: настройку доступа к сертификатам запустите от root." >&2
  exit 1
}
command -v setfacl >/dev/null 2>&1 || {
  echo "Ошибка: setfacl не найден. Пакет acl должен устанавливаться до HTTPS-перехода." >&2
  exit 1
}

install -d -m 0755 "$(dirname "$RUNTIME_HELPER")"
cat >"$RUNTIME_HELPER" <<'EOF_HELPER'
#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${XPANEL_PROJECT_DIR:-/opt/xpanel-mvp}"
declare -a CERT_PATHS=("$@")

command -v setfacl >/dev/null 2>&1 || {
  echo "setfacl не найден" >&2
  exit 1
}

xray_user() {
  local value="" attempt
  for ((attempt=1; attempt<=10; attempt++)); do
    value="$(systemctl show -p User --value xray.service 2>/dev/null || true)"
    [[ -n "$value" ]] && break
    sleep 1
  done
  if [[ -z "$value" && -f /etc/systemd/system/xray.service ]]; then
    value="$(sed -n 's/^User=//p' /etc/systemd/system/xray.service | tail -1)"
  fi
  printf '%s' "${value:-root}"
}

collect_config_paths() {
  local config="/usr/local/etc/xray/config.json"
  [[ -f "$config" ]] || return 0
  python3 - "$config" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(0)

wanted = {"certificateFile", "keyFile"}

def walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in wanted and isinstance(item, str) and item:
                print(item)
            walk(item)
    elif isinstance(value, list):
        for item in value:
            walk(item)

walk(payload)
PY
}

collect_database_paths() {
  local database="$PROJECT_DIR/data/panel.db"
  [[ -f "$database" ]] || return 0
  python3 - "$database" <<'PY'
import sqlite3
import sys

con = None
try:
    con = sqlite3.connect(sys.argv[1])
    row = con.execute(
        "SELECT tls_cert_path, tls_key_path FROM server_settings WHERE id=1"
    ).fetchone()
except sqlite3.Error:
    row = None
finally:
    if con is not None:
        con.close()

if row:
    for value in row:
        if value:
            print(str(value))
PY
}

collect_edge_paths() {
  local state="/etc/xpanel-mvp/reality-edge.env"
  [[ -f "$state" ]] || return 0
  sed -n -e 's/^CERT=//p' -e 's/^KEY=//p' "$state"
}

if ((${#CERT_PATHS[@]} == 0)); then
  while IFS= read -r path; do
    [[ -n "$path" ]] && CERT_PATHS+=("$path")
  done < <(
    {
      collect_config_paths
      collect_database_paths
      collect_edge_paths
    } | awk 'NF && !seen[$0]++'
  )
fi

SERVICE_USER="$(xray_user)"
[[ "$SERVICE_USER" == "root" ]] && exit 0
id "$SERVICE_USER" >/dev/null 2>&1 || {
  echo "Пользователь службы Xray не найден: $SERVICE_USER" >&2
  exit 1
}

grant_directory_chain() {
  local current="$1"
  while [[ -n "$current" && "$current" != "/" ]]; do
    if [[ -d "$current" ]]; then
      setfacl -m "u:${SERVICE_USER}:--x" "$current"
    fi
    current="$(dirname "$current")"
  done
}

grant_file() {
  local requested="$1" resolved=""
  [[ "$requested" == /* ]] || {
    echo "Путь сертификата должен быть абсолютным: $requested" >&2
    return 1
  }
  [[ -e "$requested" || -L "$requested" ]] || return 0

  grant_directory_chain "$(dirname "$requested")"
  resolved="$(readlink -f "$requested" 2>/dev/null || true)"
  [[ -n "$resolved" && -f "$resolved" ]] || {
    echo "Не удалось разрешить путь сертификата: $requested" >&2
    return 1
  }
  grant_directory_chain "$(dirname "$resolved")"
  setfacl -m "u:${SERVICE_USER}:r--" "$resolved"
}

declare -A SEEN=()
for path in "${CERT_PATHS[@]}"; do
  [[ -n "$path" ]] || continue
  [[ -z "${SEEN[$path]:-}" ]] || continue
  SEEN["$path"]=1
  grant_file "$path"
done
EOF_HELPER
chmod 0755 "$RUNTIME_HELPER"

install -d -m 0755 "$(dirname "$RENEWAL_HOOK")"
cat >"$RENEWAL_HOOK" <<'EOF_HOOK'
#!/bin/sh
set -eu
/usr/local/sbin/sg-panel-fix-xray-cert-access
systemctl restart xray.service
attempt=0
while [ "$attempt" -lt 20 ]; do
  state="$(systemctl is-active xray.service 2>/dev/null || true)"
  [ "$state" = "active" ] && exit 0
  attempt=$((attempt + 1))
  sleep 3
done
systemctl --no-pager --full status xray.service >&2 2>/dev/null || true
exit 1
EOF_HOOK
chmod 0755 "$RENEWAL_HOOK"

"$RUNTIME_HELPER" "$@"
