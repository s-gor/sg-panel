#!/usr/bin/env bash
set -Eeuo pipefail

OWNER="${OWNER:-s-gor}"
REPO="${REPO:-sg-panel}"
VERSION="${VERSION:-v0.9.3}"

ASSET="SG-Panel-${VERSION}.zip"
CHECKSUM="SHA256SUMS.txt"

BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}"
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

command -v curl >/dev/null 2>&1 ||
    fail "не найден curl"

command -v unzip >/dev/null 2>&1 ||
    fail "не найден unzip"

command -v sha256sum >/dev/null 2>&1 ||
    fail "не найден sha256sum"

log "Скачиваю ${ASSET}"

curl \
    -fL \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout 15 \
    -o "$WORK/$ASSET" \
    "$BASE_URL/$ASSET"

log "Скачиваю контрольную сумму"

curl \
    -fL \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout 15 \
    -o "$WORK/$CHECKSUM" \
    "$BASE_URL/$CHECKSUM"

cd "$WORK"

log "Проверяю SHA-256"

sha256sum -c "$CHECKSUM" ||
    fail "контрольная сумма архива не совпадает"

mkdir -p "$WORK/extracted"

log "Распаковываю релиз"

unzip -q "$ASSET" -d "$WORK/extracted"

INSTALLER="$(
    find "$WORK/extracted" \
        -maxdepth 5 \
        -type f \
        -path '*/deploy/ec2-first-install.sh' \
        -print \
        -quit
)"

[[ -n "$INSTALLER" && -f "$INSTALLER" ]] ||
    fail "в архиве не найден deploy/ec2-first-install.sh"

SOURCE="$(dirname "$(dirname "$INSTALLER")")"

[[ -f "$SOURCE/install-or-upgrade.sh" ]] ||
    fail "не удалось определить корневой каталог SG-Panel"

log "Найден каталог релиза: $SOURCE"
log "Запускаю мастер установки ${VERSION}"

cd "$SOURCE"

exec bash "$INSTALLER"