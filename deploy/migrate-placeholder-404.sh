#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "[SG-Panel 404] ERROR: запустите от root" >&2; exit 1; }
command -v nginx >/dev/null 2>&1 || { echo "[SG-Panel 404] Nginx не установлен, миграция не требуется"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "[SG-Panel 404] ERROR: Python 3 не найден" >&2; exit 1; }

STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/sg-panel-backups/${STAMP}-placeholder-404"
mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

CONFIGS=(
  /etc/nginx/sites-available/sg-panel
  /etc/nginx/sites-available/sg-panel-reality-placeholder
)

backup_file(){
  local path="$1" key
  [[ -e "$path" || -L "$path" ]] || return 0
  key="$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
  cp -a "$path" "$BACKUP_DIR/$key"
  : > "$BACKUP_DIR/$key.exists"
}

restore_all(){
  local path key
  for path in "${CONFIGS[@]}"; do
    key="$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
    if [[ -f "$BACKUP_DIR/$key.exists" ]]; then
      cp -a "$BACKUP_DIR/$key" "$path"
    fi
  done
}

for file in "${CONFIGS[@]}"; do
  backup_file "$file"
done

COMMITTED=0
rollback(){
  local rc=$?
  if [[ $COMMITTED -eq 0 ]]; then
    restore_all
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap rollback ERR INT TERM

PATCH_RESULT="$(python3 - "${CONFIGS[@]}" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

HEADERS = '''        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;'''

REPLACEMENT = f'''    location = / {{
        root /var/www/sg-panel-placeholder;
        try_files /index.html =404;
{HEADERS}
    }}

    location = /index.html {{
        root /var/www/sg-panel-placeholder;
        try_files /index.html =404;
{HEADERS}
    }}

    location / {{
        return 404;
    }}'''

OLD_BLOCK = re.compile(
    r'(?ms)^    location / \{\n'
    r'(?P<body>(?:(?!^    \}).)*?)'
    r'^    \}'
)

changed: list[str] = []
already_safe: list[str] = []
ignored: list[str] = []

for raw_path in sys.argv[1:]:
    path = Path(raw_path)
    if not path.exists():
        ignored.append(str(path))
        continue

    text = path.read_text(encoding='utf-8', errors='strict')
    change_state = [False]

    def replace(match: re.Match[str]) -> str:
        body = match.group('body')
        if '/var/www/sg-panel-placeholder' not in body:
            return match.group(0)
        if 'try_files' not in body or '/index.html' not in body:
            return match.group(0)
        change_state[0] = True
        return REPLACEMENT

    updated = OLD_BLOCK.sub(replace, text)
    if '/var/www/sg-panel-placeholder' in updated:
        safe_unknown = re.search(
            r'(?ms)^    location / \{(?:(?!^    \}).)*?return 404;(?:(?!^    \}).)*?^    \}',
            updated,
        )
        safe = (
            'location = / {' in updated
            and 'location = /index.html {' in updated
            and updated.count('try_files /index.html =404;') >= 2
            and safe_unknown is not None
        )
        if not safe:
            raise SystemExit(f'не удалось безопасно исправить fallback-блок: {path}')
        if change_state[0]:
            path.write_text(updated, encoding='utf-8')
            changed.append(str(path))
        else:
            already_safe.append(str(path))
    else:
        ignored.append(str(path))

print(f"changed={len(changed)}")
print(f"safe={len(already_safe)}")
for item in changed:
    print(f"patched:{item}")
for item in already_safe:
    print(f"already:{item}")
PY
)"

nginx -t
if grep -q '^changed=[1-9]' <<<"$PATCH_RESULT"; then
  systemctl reload nginx
fi

COMMITTED=1
trap - ERR INT TERM
printf '%s\n' "$PATCH_RESULT"
printf '[SG-Panel 404] Неизвестные пути публичной заглушки возвращают 404. Резервная копия: %s\n' "$BACKUP_DIR"
