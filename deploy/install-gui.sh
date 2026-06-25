#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="/opt/xpanel-mvp"
ENV_DIR="/etc/xpanel-mvp"
ENV_FILE="$ENV_DIR/web.env"

[[ $EUID -eq 0 ]] || { echo "Ошибка: запустите скрипт от root" >&2; exit 1; }
[[ -f "$PROJECT_DIR/requirements.txt" ]] || { echo "Ошибка: проект не найден в $PROJECT_DIR" >&2; exit 1; }

BIND_ADDRESS="${XPANEL_BIND_ADDRESS:-0.0.0.0}"
INTERNAL_PORT="${XPANEL_PORT:-8080}"
SECURE_COOKIES="${XPANEL_SECURE_COOKIES:-0}"
TRUST_PROXY_HEADERS="${XPANEL_TRUST_PROXY_HEADERS:-0}"

[[ "$INTERNAL_PORT" =~ ^[0-9]+$ ]] && (( INTERNAL_PORT >= 1 && INTERNAL_PORT <= 65535 )) || {
  echo "Ошибка: XPANEL_PORT должен быть от 1 до 65535" >&2
  exit 1
}
[[ "$SECURE_COOKIES" == "0" || "$SECURE_COOKIES" == "1" ]] || {
  echo "Ошибка: XPANEL_SECURE_COOKIES должен быть 0 или 1" >&2
  exit 1
}
[[ "$TRUST_PROXY_HEADERS" == "0" || "$TRUST_PROXY_HEADERS" == "1" ]] || {
  echo "Ошибка: XPANEL_TRUST_PROXY_HEADERS должен быть 0 или 1" >&2
  exit 1
}

if [[ -z "${XPANEL_ADMIN_PASSWORD:-}" ]]; then
  read -r -s -p "Пароль администратора GUI: " XPANEL_ADMIN_PASSWORD; echo
  read -r -s -p "Повторите пароль: " XPANEL_ADMIN_PASSWORD_2; echo
  [[ "$XPANEL_ADMIN_PASSWORD" == "$XPANEL_ADMIN_PASSWORD_2" ]] || { echo "Ошибка: пароли не совпадают" >&2; exit 1; }
fi
[[ ${#XPANEL_ADMIN_PASSWORD} -ge 8 ]] || { echo "Ошибка: пароль должен содержать не менее 8 символов" >&2; exit 1; }

cd "$PROJECT_DIR"
python3 -m venv .venv
.venv/bin/pip install --no-cache-dir -q --upgrade pip
.venv/bin/pip install --no-cache-dir -q -r requirements.txt

mkdir -p "$ENV_DIR"
SECRET_KEY="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
PASSWORD_HASH="$(XPANEL_PASSWORD="$XPANEL_ADMIN_PASSWORD" .venv/bin/python - <<'PY'
import os
from werkzeug.security import generate_password_hash
print(generate_password_hash(os.environ['XPANEL_PASSWORD']))
PY
)"

cat > "$ENV_FILE" <<EOF_ENV
XPANEL_SECRET_KEY=$SECRET_KEY
XPANEL_PASSWORD_HASH=$PASSWORD_HASH
XPANEL_BIND_ADDRESS=$BIND_ADDRESS
XPANEL_PORT=$INTERNAL_PORT
XPANEL_SECURE_COOKIES=$SECURE_COOKIES
XPANEL_TRUST_PROXY_HEADERS=$TRUST_PROXY_HEADERS
EOF_ENV
chmod 600 "$ENV_FILE"

bash "$PROJECT_DIR/deploy/install-service.sh"
bash "$PROJECT_DIR/deploy/install-maintenance.sh"
systemctl restart xpanel-web
systemctl --no-pager --full status xpanel-web

echo
echo "GUI запущен: $BIND_ADDRESS:$INTERNAL_PORT"
if [[ "$BIND_ADDRESS" == "0.0.0.0" || "$BIND_ADDRESS" == "::" ]]; then
  echo "Не публикуйте этот порт в интернет без HTTPS и ограничения доступа."
fi
