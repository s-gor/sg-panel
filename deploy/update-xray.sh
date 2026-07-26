#!/usr/bin/env bash
set -Eeuo pipefail

STATE_DIR="${XPANEL_UPDATE_STATE_DIR:-/var/lib/sg-panel-update}"
STATUS_FILE="${XPANEL_XRAY_UPDATE_STATUS:-$STATE_DIR/xray-status.json}"
LOG_FILE="${XPANEL_XRAY_UPDATE_LOG:-$STATE_DIR/xray-update.log}"
TARGET_VERSION="${XPANEL_XRAY_UPDATE_VERSION:-}"
CHANNEL="${XPANEL_XRAY_UPDATE_CHANNEL:-stable}"
XRAY_BIN="${XPANEL_XRAY_BIN:-/usr/local/bin/xray}"
CONFIG="${XPANEL_XRAY_CONFIG:-/usr/local/etc/xray/config.json}"
XRAY_SERVICE="${XPANEL_XRAY_SERVICE:-xray}"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/sg-panel-backups/${STAMP}-xray-update-rollback"
TMP_DIR="$(mktemp -d)"
LOCK_FILE="/run/lock/sg-panel-update.lock"
ROLLBACK_NEEDED=0
CURRENT_VERSION=""
ASSET=""
DOWNLOAD_URL=""
BACKUP_BIN=""
OLD_CAPABILITIES=""

mkdir -p "$STATE_DIR" "$(dirname "$STATUS_FILE")" "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"
chmod 0600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log(){ printf '[Xray Update] %s\n' "$*"; }
fail(){ printf '[Xray Update] ERROR: %s\n' "$*" >&2; return 1; }

status(){
  local state="$1" message="${2:-}" restored="${3:-0}"
  python3 - "$STATUS_FILE" "$LOG_FILE" "$state" "$TARGET_VERSION" "$CHANNEL" "$message" "$CURRENT_VERSION" "$BACKUP_DIR" "$restored" <<'PY'
import json, os, sys, tempfile
from datetime import datetime, timezone
(
    status_path, log_path, state, version, channel, message,
    previous_version, backup_dir, restored,
) = sys.argv[1:]
os.makedirs(os.path.dirname(status_path), exist_ok=True)
try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as stream:
        log = stream.read()[-64000:]
except OSError:
    log = ""
payload = {
    "state": state,
    "version": version,
    "channel": channel,
    "message": message,
    "previousVersion": previous_version,
    "updatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "log": log,
}
if backup_dir:
    payload["backupDir"] = backup_dir
if restored == "1":
    payload["restored"] = True
raw = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
fd, temporary = tempfile.mkstemp(prefix=".xray-status-", dir=os.path.dirname(status_path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(raw)
    os.chmod(temporary, 0o600)
    os.replace(temporary, status_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

phase(){
  log "$1"
  status "$2" "$1"
}

xray_version(){
  "$1" version | awk 'NR == 1 && $1 == "Xray" {print "v" $2; exit}'
}

wait_for_service(){
  local attempt
  for attempt in {1..20}; do
    if systemctl is-active --quiet "$XRAY_SERVICE"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

check_listeners(){
  local protocol port label attempt found
  while IFS=$'\t' read -r protocol port label; do
    [[ -n "$protocol" && -n "$port" ]] || continue
    found=0
    for attempt in {1..10}; do
      if [[ "$protocol" == "udp" ]]; then
        if ss -H -lun "sport = :$port" 2>/dev/null | grep -q .; then
          found=1
          break
        fi
      else
        if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
          found=1
          break
        fi
      fi
      sleep 1
    done
    (( found == 1 )) || fail "$label не слушает ${protocol^^}/$port после обновления"
    log "$label: ${protocol^^}/$port слушается"
  done < "$TMP_DIR/expected-listeners.tsv"
}

rollback(){
  local rc=$? rollback_ok=1 restored_version=""
  trap - ERR INT TERM
  set +e
  if (( ROLLBACK_NEEDED )); then
    status rollback "Ошибка обновления Xray. Возвращается предыдущий бинарник" 1
    log "Начинаю автоматический откат"
    systemctl stop "$XRAY_SERVICE" >/dev/null 2>&1 || true
    if [[ -f "$BACKUP_BIN" ]]; then
      cp -a "$BACKUP_BIN" "${XRAY_BIN}.restore" || rollback_ok=0
      if [[ -n "$OLD_CAPABILITIES" ]] && command -v setcap >/dev/null 2>&1; then
        setcap "$OLD_CAPABILITIES" "${XRAY_BIN}.restore" || rollback_ok=0
      fi
      mv -f "${XRAY_BIN}.restore" "$XRAY_BIN" || rollback_ok=0
    else
      rollback_ok=0
    fi
    "$XRAY_BIN" run -test -config "$CONFIG" >/dev/null 2>&1 || rollback_ok=0
    systemctl restart "$XRAY_SERVICE" >/dev/null 2>&1 || rollback_ok=0
    wait_for_service || rollback_ok=0
    restored_version="$(xray_version "$XRAY_BIN" 2>/dev/null || true)"
    [[ "$restored_version" == "$CURRENT_VERSION" ]] || rollback_ok=0
    if (( rollback_ok )); then
      log "Предыдущий Xray $CURRENT_VERSION восстановлен и запущен"
      status rolled_back "Обновление не выполнено. Xray $CURRENT_VERSION восстановлен автоматически" 1
    else
      log "Автоматический откат выполнен не полностью"
      status error "Критическая ошибка: автоматический откат Xray выполнен не полностью" 1
    fi
  else
    status error "Обновление Xray остановлено до изменения рабочего бинарника"
  fi
  rm -rf "$TMP_DIR"
  exit "$rc"
}
trap rollback ERR INT TERM

[[ $EUID -eq 0 ]] || fail "запустите updater от root"
[[ "$TARGET_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "некорректная целевая версия: $TARGET_VERSION"
[[ "$CHANNEL" == "stable" || "$CHANNEL" == "prerelease" ]] || fail "некорректный канал: $CHANNEL"
[[ "$XRAY_SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || fail "некорректное имя службы Xray"
[[ -x "$XRAY_BIN" ]] || fail "не найден исполняемый Xray: $XRAY_BIN"
[[ -f "$CONFIG" ]] || fail "не найден config.json: $CONFIG"
command -v curl >/dev/null || fail "не найдена команда curl"
command -v unzip >/dev/null || fail "не найдена команда unzip"
command -v sha256sum >/dev/null || fail "не найдена команда sha256sum"
command -v ss >/dev/null || fail "не найдена команда ss"

mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || fail "другая операция обновления уже выполняется"

case "$(uname -m)" in
  x86_64|amd64) ASSET="Xray-linux-64.zip" ;;
  aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
  *) fail "архитектура $(uname -m) пока не поддерживается" ;;
esac

CURRENT_VERSION="$(xray_version "$XRAY_BIN")"
[[ "$CURRENT_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "не удалось определить установленную версию Xray"
[[ "$CURRENT_VERSION" != "$TARGET_VERSION" ]] || fail "Xray $TARGET_VERSION уже установлен"
python3 - "$CURRENT_VERSION" "$TARGET_VERSION" <<'PYVERSION'
import re
import sys

def version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", value.strip())
    if not match:
        raise SystemExit(2)
    return tuple(int(item) for item in match.groups())

current = version(sys.argv[1])
target = version(sys.argv[2])
minimum = (26, 6, 27)
if target < minimum:
    print("Целевая версия ниже обязательного минимума v26.6.27", file=sys.stderr)
    raise SystemExit(3)
if target < current:
    print("Понижение версии Xray запрещено", file=sys.stderr)
    raise SystemExit(4)
PYVERSION

DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${TARGET_VERSION}/${ASSET}"

phase "Подготовка обновления Xray $CURRENT_VERSION → $TARGET_VERSION" starting
if [[ "$CHANNEL" == "prerelease" ]]; then
  log "Выбран канал: предварительная версия"
else
  log "Выбран канал: стабильная версия"
fi
log "Конфигурация и база SG-Panel изменяться не будут"

python3 - "$CONFIG" "$TMP_DIR/expected-listeners.tsv" <<'PY'
import json, sys
source, target = sys.argv[1:]
with open(source, "r", encoding="utf-8") as stream:
    config = json.load(stream)
def expand_ports(value):
    if isinstance(value, int):
        return [value] if 1 <= value <= 65535 else []
    if not isinstance(value, str):
        return []
    result = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            if not (left.strip().isdigit() and right.strip().isdigit()):
                continue
            start, end = int(left), int(right)
            if 1 <= start <= end <= 65535:
                result.extend(range(start, end + 1))
        elif part.isdigit() and 1 <= int(part) <= 65535:
            result.append(int(part))
    return sorted(set(result))

rows = []
for index, inbound in enumerate(config.get("inbounds", []), 1):
    if not isinstance(inbound, dict):
        continue
    ports = expand_ports(inbound.get("port"))
    if not ports:
        continue
    protocol = str(inbound.get("protocol") or "").lower()
    stream_settings = inbound.get("streamSettings")
    stream_network = (
        str(stream_settings.get("network") or "").lower()
        if isinstance(stream_settings, dict)
        else ""
    )
    network = (
        "udp"
        if protocol in {"hysteria", "hysteria2", "dokodemo-door-udp"}
        or stream_network in {"hysteria", "hysteria2"}
        else "tcp"
    )
    tag = str(inbound.get("tag") or f"Inbound {index}").replace("\t", " ").replace("\n", " ")
    for port in ports:
        rows.append((network, port, tag))
with open(target, "w", encoding="utf-8") as stream:
    for network, port, tag in rows:
        stream.write(f"{network}\t{port}\t{tag}\n")
PY

phase "Скачивание официального архива XTLS/Xray-core" downloading
curl -fL --retry 4 --retry-delay 3 --connect-timeout 15 \
  -H 'Cache-Control: no-cache' -o "$TMP_DIR/$ASSET" "$DOWNLOAD_URL"
curl -fL --retry 4 --retry-delay 3 --connect-timeout 15 \
  -H 'Cache-Control: no-cache' -o "$TMP_DIR/$ASSET.dgst" "$DOWNLOAD_URL.dgst"

phase "Проверка SHA-256 и версии бинарника" verifying
EXPECTED_SHA256="$(awk -F '= ' '/256=/ {print $2; exit}' "$TMP_DIR/$ASSET.dgst" | tr -d '\r')"
ACTUAL_SHA256="$(sha256sum "$TMP_DIR/$ASSET" | awk '{print $1}')"
[[ "$EXPECTED_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || fail "официальный .dgst не содержит корректный SHA-256"
[[ "${EXPECTED_SHA256,,}" == "${ACTUAL_SHA256,,}" ]] || fail "SHA-256 архива не совпадает"
log "SHA-256 подтверждён: ${ACTUAL_SHA256,,}"
unzip -q "$TMP_DIR/$ASSET" -d "$TMP_DIR/package"
[[ -f "$TMP_DIR/package/xray" ]] || fail "в архиве отсутствует бинарник xray"
chmod 0755 "$TMP_DIR/package/xray"
NEW_VERSION="$(xray_version "$TMP_DIR/package/xray")"
[[ "$NEW_VERSION" == "$TARGET_VERSION" ]] || fail "архив содержит Xray $NEW_VERSION вместо $TARGET_VERSION"
"$TMP_DIR/package/xray" run -test -config "$CONFIG"
log "Текущий config.json совместим с Xray $TARGET_VERSION"

phase "Создание страховочной копии Xray $CURRENT_VERSION" backing_up
mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"
BACKUP_BIN="$BACKUP_DIR/xray"
cp -a "$XRAY_BIN" "$BACKUP_BIN"
cp -a "$CONFIG" "$BACKUP_DIR/config.json"
if command -v getcap >/dev/null 2>&1; then
  OLD_CAPABILITIES="$(getcap "$XRAY_BIN" 2>/dev/null | sed -E "s#^${XRAY_BIN//\//\\/}[[:space:]]*##" || true)"
fi
printf '%s\n' "$CURRENT_VERSION" > "$BACKUP_DIR/version.txt"
log "Страховочная копия: $BACKUP_DIR"

phase "Установка Xray $TARGET_VERSION" installing
ROLLBACK_NEEDED=1
install -o root -g root -m 0755 "$TMP_DIR/package/xray" "${XRAY_BIN}.new"
if [[ -n "$OLD_CAPABILITIES" ]] && command -v setcap >/dev/null 2>&1; then
  setcap "$OLD_CAPABILITIES" "${XRAY_BIN}.new"
fi
mv -f "${XRAY_BIN}.new" "$XRAY_BIN"
systemctl restart "$XRAY_SERVICE"

phase "Проверка службы, конфигурации и активных Inbound" validating
wait_for_service || fail "служба $XRAY_SERVICE не перешла в active"
INSTALLED_VERSION="$(xray_version "$XRAY_BIN")"
[[ "$INSTALLED_VERSION" == "$TARGET_VERSION" ]] || fail "после установки обнаружен Xray $INSTALLED_VERSION"
"$XRAY_BIN" run -test -config "$CONFIG"
check_listeners

ROLLBACK_NEEDED=0
status success "Xray успешно обновлён с $CURRENT_VERSION до $TARGET_VERSION"
log "Xray успешно обновлён: $CURRENT_VERSION → $TARGET_VERSION"
log "Рабочая конфигурация не изменялась"
log "Страховочная копия сохранена: $BACKUP_DIR"
rm -rf "$TMP_DIR"
trap - ERR INT TERM
exit 0
