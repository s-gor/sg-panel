#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${XPANEL_PROJECT_DIR:-/opt/xpanel-mvp}"
RUNTIME_HELPER="/usr/local/sbin/sg-panel-fix-xray-cert-access"
RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access"

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo "Ошибка: настройку доступа к сертификатам запустите от root." >&2
  exit 1
}

if ! command -v setfacl >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends acl
fi

install -d -m 0755 "$(dirname "$RUNTIME_HELPER")"
cat >"$RUNTIME_HELPER" <<'EOF_HELPER'
#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${XPANEL_PROJECT_DIR:-/opt/xpanel-mvp}"
XRAY_USER="$(systemctl show xray.service --property=User --value 2>/dev/null || true)"
XRAY_USER="${XRAY_USER:-nobody}"

[[ "$XRAY_USER" == "root" ]] && exit 0
id "$XRAY_USER" >/dev/null 2>&1 || {
  echo "Не найден системный пользователь Xray: $XRAY_USER" >&2
  exit 1
}

declare -a CERT_PATHS=("$@")

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
from pathlib import Path

path = Path(sys.argv[1])
con = None
row = None
try:
    con = sqlite3.connect(path)
    row = con.execute(
        "SELECT tls_cert_path, tls_key_path FROM server_settings WHERE id=1"
    ).fetchone()
except sqlite3.Error:
    pass
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

grant_directory_chain() {
  local current="$1"
  declare -a chain=()
  while [[ "$current" != "/" && -n "$current" ]]; do
    chain+=("$current")
    current="$(dirname "$current")"
  done
  local index
  for ((index=${#chain[@]}-1; index>=0; index--)); do
    [[ -d "${chain[index]}" ]] || continue
    setfacl -m "u:${XRAY_USER}:--x" "${chain[index]}"
  done
}

grant_file() {
  local requested="$1"
  local resolved=""
  [[ -e "$requested" || -L "$requested" ]] || return 0
  grant_directory_chain "$(dirname "$requested")"
  resolved="$(readlink -f "$requested" 2>/dev/null || true)"
  if [[ -n "$resolved" && -f "$resolved" ]]; then
    grant_directory_chain "$(dirname "$resolved")"
    setfacl -m "u:${XRAY_USER}:r--" "$resolved"
  elif [[ -f "$requested" ]]; then
    setfacl -m "u:${XRAY_USER}:r--" "$requested"
  fi
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
if systemctl is-active --quiet xray.service; then
  systemctl restart xray.service
fi
EOF_HOOK
chmod 0755 "$RENEWAL_HOOK"

"$RUNTIME_HELPER" "$@"
