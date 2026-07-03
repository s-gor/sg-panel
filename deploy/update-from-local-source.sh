#!/usr/bin/env bash
set -Eeuo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/v\1/p' "$SOURCE_DIR/xpanel/__init__.py" | head -n 1)"
[[ -n "$VERSION" ]] || { echo "Cannot determine candidate version" >&2; exit 1; }
exec env \
  XPANEL_UPDATE_VERSION="$VERSION" \
  XPANEL_UPDATE_REF="local-${VERSION}" \
  XPANEL_UPDATE_SOURCE_DIR="$SOURCE_DIR" \
  bash "$SOURCE_DIR/deploy/update-from-github.sh"
