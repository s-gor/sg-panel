#!/usr/bin/env bash
set -Eeuo pipefail

OWNER="${OWNER:-s-gor}"
REPO="${REPO:-sg-panel}"
BRANCH="${BRANCH:-main}"
RAW_INSTALLER_URL="${SG_PANEL_INSTALLER_URL:-https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/install.sh}"
LOG_FILE="${SG_PANEL_BOOTSTRAP_LOG:-/var/log/sg-panel-bootstrap-$(date -u +%Y%m%d-%H%M%S).log}"
TMP_INSTALLER="$(mktemp /tmp/sg-panel-install.XXXXXX.sh)"
SPINNER_PID=""

if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  GREEN=$'\033[1;32m'
  RED=$'\033[1;31m'
  RESET=$'\033[0m'
else
  GREEN=""
  RED=""
  RESET=""
fi

cleanup(){
  if [[ -n "$SPINNER_PID" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
  fi
  rm -f "$TMP_INSTALLER"
}
trap cleanup EXIT

spinner_loop(){
  local label="$1" started="$2" i=0 elapsed
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  while :; do
    elapsed=$(( $(date +%s) - started ))
    printf '\r\033[K[SG-Panel] [%s%s%s] %s (%s сек)' \
      "$GREEN" "${frames:i%10:1}" "$RESET" "$label" "$elapsed"
    i=$((i + 1))
    sleep 0.25
  done
}

run_step(){
  local label="$1" rc started
  shift
  started="$(date +%s)"
  printf '[SG-Panel] %s\n' "$label" >>"$LOG_FILE"
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    spinner_loop "$label" "$started" &
    SPINNER_PID=$!
  else
    printf '[SG-Panel] %s\n' "$label"
  fi

  set +e
  "$@" >>"$LOG_FILE" 2>&1
  rc=$?
  set -e

  if [[ -n "$SPINNER_PID" ]]; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
  fi

  if (( rc != 0 )); then
    printf '\r\033[K[SG-Panel] [%sОШИБКА%s] %s\n' "$RED" "$RESET" "$label" >&2
    tail -n 40 "$LOG_FILE" >&2 || true
    printf 'Полный журнал: %s\n' "$LOG_FILE" >&2
    exit "$rc"
  fi

  printf '\r\033[K[SG-Panel] [%sOK%s] %s (%s сек)\n' \
    "$GREEN" "$RESET" "$label" "$(( $(date +%s) - started ))"
}

ensure_downloader(){
  if command -v curl >/dev/null 2>&1; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
  apt-get -o Dpkg::Use-Pty=0 update -qq
  apt-get -o Dpkg::Use-Pty=0 install -y -qq curl ca-certificates
}

download_installer(){
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 \
    -o "$TMP_INSTALLER" "$RAW_INSTALLER_URL"
  bash -n "$TMP_INSTALLER"
  chmod 0700 "$TMP_INSTALLER"
}

main(){
  [[ $EUID -eq 0 ]] || { echo 'Запустите через sudo bash.' >&2; exit 1; }
  install -d -m 0755 "$(dirname "$LOG_FILE")"
  : >"$LOG_FILE"
  chmod 0600 "$LOG_FILE"

  run_step 'Bootstrap 1/2 · Подготовка загрузчика' ensure_downloader
  run_step 'Bootstrap 2/2 · Загрузка мастера SG-Panel' download_installer

  printf '[SG-Panel] Мастер загружен. Все вопросы будут заданы до начала установки.\n\n'
  bash "$TMP_INSTALLER" "$@"
}

main "$@"
