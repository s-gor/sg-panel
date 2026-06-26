#!/usr/bin/env bash
set -Eeuo pipefail

OWNER="${OWNER:-s-gor}"
REPO="${REPO:-sg-panel}"
BRANCH="${BRANCH:-main}"

cd /

ARCHIVE="${REPO}-${BRANCH}.zip"
ARCHIVE_URL="https://github.com/${OWNER}/${REPO}/archive/refs/heads/${BRANCH}.zip"
WORK="$(mktemp -d /tmp/sg-panel-install.XXXXXX)"

cleanup() {
    rm -rf "$WORK"
}

trap cleanup EXIT

log() {
    printf '[SG-Panel bootstrap] %s\n' "$*"
}

fail() {
    printf '[SG-Panel bootstrap] ERROR: %s\n' "$*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
command -v curl >/dev/null 2>&1 || fail "не установлен curl"
command -v unzip >/dev/null 2>&1 || fail "не установлен unzip"

log "Скачиваю ${OWNER}/${REPO}, ветка ${BRANCH}"
curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 \
    -o "$WORK/$ARCHIVE" "$ARCHIVE_URL"

mkdir -p "$WORK/extracted"
log "Распаковываю архив репозитория"
unzip -q "$WORK/$ARCHIVE" -d "$WORK/extracted"

INSTALLER="$(
    find "$WORK/extracted" \
        -maxdepth 5 \
        -type f \
        -path '*/deploy/ec2-first-install.sh' \
        -print \
        -quit
)"

[[ -n "$INSTALLER" && -f "$INSTALLER" ]] || \
    fail "в архиве репозитория не найден deploy/ec2-first-install.sh"

SOURCE="$(dirname "$(dirname "$INSTALLER")")"
[[ -f "$SOURCE/install-or-upgrade.sh" ]] || \
    fail "не удалось определить каталог проекта SG-Panel"

# GitHub source archives do not preserve executable bits reliably.
find "$SOURCE" -type f -name '*.sh' -exec chmod 755 {} +

log "Каталог проекта: $SOURCE"
log "Запускаю установку или обновление SG-Panel"
cd "$SOURCE"
bash "$INSTALLER"
