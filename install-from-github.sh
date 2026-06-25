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

[[ $EUID -eq 0 ]] || fail "Run this script as root"

command -v curl >/dev/null 2>&1 ||
    fail "curl is not installed"

command -v unzip >/dev/null 2>&1 ||
    fail "unzip is not installed"

command -v sha256sum >/dev/null 2>&1 ||
    fail "sha256sum is not installed"

log "Downloading ${ASSET}"

curl \
    -fL \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout 15 \
    -o "$WORK/$ASSET" \
    "$BASE_URL/$ASSET"

log "Downloading checksum file"

curl \
    -fL \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout 15 \
    -o "$WORK/$CHECKSUM" \
    "$BASE_URL/$CHECKSUM"

cd "$WORK"

log "Verifying SHA-256"

sha256sum -c "$CHECKSUM" ||
    fail "SHA-256 verification failed"

mkdir -p "$WORK/extracted"

log "Extracting release archive"

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
    fail "deploy/ec2-first-install.sh was not found in the archive"

SOURCE="$(dirname "$(dirname "$INSTALLER")")"

[[ -f "$SOURCE/install-or-upgrade.sh" ]] ||
    fail "Unable to determine the SG-Panel release directory"

log "Release directory: $SOURCE"
log "Starting SG-Panel ${VERSION} installation wizard"

cd "$SOURCE"

bash "$INSTALLER"