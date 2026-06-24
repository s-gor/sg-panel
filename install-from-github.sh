#!/usr/bin/env bash
set -Eeuo pipefail

OWNER="${OWNER:-s-gor}"
REPO="${REPO:-sg-panel}"
VERSION="${VERSION:-v0.9.3}"
ASSET="SG-Panel-${VERSION}.zip"
CHECKSUM="${ASSET}.sha256"
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}"
WORK="$(mktemp -d /tmp/sg-panel-install.XXXXXX)"

cleanup(){ rm -rf "$WORK"; }
trap cleanup EXIT

log(){ printf '[SG-Panel bootstrap] %s\n' "$*"; }
fail(){ printf '[SG-Panel bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "запустите скрипт от root"
command -v curl >/dev/null || fail "не найден curl"
command -v unzip >/dev/null || fail "не найден unzip"
command -v sha256sum >/dev/null || fail "не найден sha256sum"

log "Скачиваю ${ASSET}"
curl -fL --retry 3 --connect-timeout 15 \
  -o "$WORK/$ASSET" "$BASE_URL/$ASSET"

log "Скачиваю контрольную сумму"
curl -fL --retry 3 --connect-timeout 15 \
  -o "$WORK/$CHECKSUM" "$BASE_URL/$CHECKSUM"

cd "$WORK"
sha256sum -c "$CHECKSUM"

unzip -q "$ASSET" -d extracted
SOURCE="$(find extracted -maxdepth 4 -type f -path '*/deploy/ec2-first-install.sh' -printf '%h/..\n' | head -1)"
[[ -n "$SOURCE" && -x "$SOURCE/deploy/ec2-first-install.sh" ]] || \
  fail "в архиве не найден deploy/ec2-first-install.sh"

log "Запускаю мастер установки ${VERSION}"
cd "$SOURCE"
exec ./deploy/ec2-first-install.sh
