#!/usr/bin/env bash
set -Eeuo pipefail

# SG-Panel unified installer for Ubuntu 22.04 and newer.
# Any official Ubuntu release is accepted; the installer is not tied to a
# particular release channel.
# The same file is intended for both:
#   a downloaded GitHub bootstrap;
#   a local test with the exact source ZIP supplied through --source-zip.

OWNER="${OWNER:-s-gor}"
REPO="${REPO:-sg-panel}"
BRANCH="${BRANCH:-main}"
DEFAULT_PANEL_PORT="61443"
DEFAULT_FIRST_USER="sg-admin"
DEFAULT_INSTANCE_NAME="SG-Panel"
DEFAULT_REALITY_DEST="www.bing.com:443"
DEFAULT_REALITY_SNI="www.bing.com"
EXPECTED_VERSION="0.10.0-rc70"
EXPECTED_BUILD="FIX40"
EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"
LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"
ARCHIVE_URL="${SG_PANEL_ARCHIVE_URL:-https://github.com/${OWNER}/${REPO}/archive/refs/heads/${BRANCH}.zip}"
LOG_FILE="${SG_PANEL_INSTALLER_LOG:-/var/log/sg-panel-installer-$(date -u +%Y%m%d-%H%M%S).log}"
CORE_LOG="${SG_PANEL_CORE_LOG:-/var/log/sg-panel-core-install-$(date -u +%Y%m%d-%H%M%S).log}"
WORK_DIR=""
STEP_LABEL=""
STEP_STARTED=0
STEP_ACTIVE=0
STEP_SPINNER_PID=""
STARTUP_SPINNER_PID=""
STARTUP_STARTED=0
PREDETECTED_PUBLIC_IPV4=""
SOURCE_ZIP_ARG=""

if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
  C_GREEN=$'\033[1;32m'
  C_RED=$'\033[1;31m'
  C_RESET=$'\033[0m'
else
  C_GREEN=""
  C_RED=""
  C_RESET=""
fi

startup_spinner_loop(){
  local label="$1" started="$2" frame_index=0 elapsed
  local frames='|/-\'
  while true; do
    elapsed=$((SECONDS - started))
    printf '\r[SG-Panel] [%s%s%s] %s (%s сек)' \
      "$C_GREEN" "${frames:frame_index%4:1}" "$C_RESET" "$label" "$elapsed"
    frame_index=$((frame_index + 1))
    sleep 0.25
  done
}

startup_begin(){
  local label="$1"
  STARTUP_STARTED=$SECONDS
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    startup_spinner_loop "$label" "$STARTUP_STARTED" &
    STARTUP_SPINNER_PID=$!
  else
    printf '[SG-Panel] [..] %s...\n' "$label"
  fi
}

startup_stop(){
  if [[ -n "$STARTUP_SPINNER_PID" ]]; then
    kill "$STARTUP_SPINNER_PID" 2>/dev/null || true
    wait "$STARTUP_SPINNER_PID" 2>/dev/null || true
    STARTUP_SPINNER_PID=""
  fi
}

startup_ok(){
  local label="$1" elapsed=$((SECONDS - STARTUP_STARTED))
  startup_stop
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    printf '\r[SG-Panel] [%sOK%s] %s (%s сек)\033[K\n' \
      "$C_GREEN" "$C_RESET" "$label" "$elapsed"
  else
    printf '[SG-Panel] [OK] %s (%s сек)\n' "$label" "$elapsed"
  fi
}

startup_error(){
  local message="$1"
  startup_stop
  printf '\r[SG-Panel] [%sОШИБКА%s] Запуск мастера\033[K\n' \
    "$C_RED" "$C_RESET" >&2
  printf '[SG-Panel] [ERROR] %s\n' "$message" >&2
  exit 1
}

supported_ubuntu_version(){
  local version="${1:-}"
  [[ "$version" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  command -v dpkg >/dev/null 2>&1 || return 1
  dpkg --compare-versions "$version" ge "22.04"
}

check_supported_platform(){
  [[ -r /etc/os-release ]] || startup_error "Не удалось определить операционную систему."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || \
    startup_error "Поддерживается Ubuntu 22.04 и новее. Обнаружена: ${PRETTY_NAME:-unknown}."
  supported_ubuntu_version "${VERSION_ID:-}" || \
    startup_error "Нужна Ubuntu 22.04 или новее. Обнаружена версия: ${VERSION_ID:-unknown}."
  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) startup_error "Поддерживаются архитектуры amd64 и arm64. Обнаружена: $(uname -m)." ;;
  esac
}

usage(){
  cat <<'USAGE'
Использование:
  sudo bash install.sh --source-zip ./SG-PANEL-FIX40-FULL-UI23-SOURCE.zip
  sudo bash install.sh

Для установки точной версии передайте архив FIX40 UI23 через --source-zip.
Сначала мастер с зелёной вертушкой подготавливает Ubuntu и устанавливает все системные компоненты.
После этого один раз запрашиваются параметры панели, затем установка продолжается без дополнительного ввода.
Весь технический вывод apt, dpkg, curl, Python, Xray, Nginx и systemd идёт только в журналы.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-zip)
      [[ $# -ge 2 ]] || { echo "Не указан путь после --source-zip" >&2; exit 2; }
      SOURCE_ZIP_ARG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Неизвестный параметр: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

stop_spinner(){
  if [[ -n "$STEP_SPINNER_PID" ]]; then
    kill "$STEP_SPINNER_PID" 2>/dev/null || true
    wait "$STEP_SPINNER_PID" 2>/dev/null || true
    STEP_SPINNER_PID=""
  fi
}

spinner_loop(){
  local label="$1" started="$2" frame_index=0 elapsed
  local frames='|/-\'
  while true; do
    elapsed=$((SECONDS - started))
    printf '\r[SG-Panel] [%s%s%s] %s (%s сек)' \
      "$C_GREEN" "${frames:frame_index%4:1}" "$C_RESET" "$label" "$elapsed"
    frame_index=$((frame_index + 1))
    sleep 0.25
  done
}

stage(){
  printf '\n[SG-Panel] Этап %s/%s: %s\n' "$1" "$2" "$3"
  [[ -e "$LOG_FILE" ]] && printf '[SG-Panel] Этап %s/%s: %s\n' "$1" "$2" "$3" >>"$LOG_FILE"
}

step_begin(){
  stop_spinner
  STEP_LABEL="$1"
  STEP_STARTED=$SECONDS
  STEP_ACTIVE=1
  printf '\n[SG-Panel] %s\n' "$STEP_LABEL" >>"$LOG_FILE"
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    spinner_loop "$STEP_LABEL" "$STEP_STARTED" &
    STEP_SPINNER_PID=$!
  else
    printf '[SG-Panel] [..] %s...\n' "$STEP_LABEL"
  fi
}

step_ok(){
  local elapsed=$((SECONDS - STEP_STARTED))
  stop_spinner
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    printf '\r[SG-Panel] [%sOK%s] %s (%s сек)\033[K\n' \
      "$C_GREEN" "$C_RESET" "$STEP_LABEL" "$elapsed"
  else
    printf '[SG-Panel] [OK] %s (%s сек)\n' "$STEP_LABEL" "$elapsed"
  fi
  printf '[SG-Panel] [OK] %s (%s сек)\n' "$STEP_LABEL" "$elapsed" >>"$LOG_FILE"
  STEP_ACTIVE=0
}

fail(){
  local message="$*" elapsed=0
  if (( STEP_ACTIVE == 1 )); then
    elapsed=$((SECONDS - STEP_STARTED))
    stop_spinner
    if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
      printf '\r[SG-Panel] [%sОШИБКА%s] %s (%s сек)\033[K\n' \
        "$C_RED" "$C_RESET" "$STEP_LABEL" "$elapsed" >&2
    else
      printf '[SG-Panel] [ОШИБКА] %s (%s сек)\n' "$STEP_LABEL" "$elapsed" >&2
    fi
    STEP_ACTIVE=0
  fi
  printf '[SG-Panel] [ERROR] %s\n' "$message" >&2
  if [[ -s "$CORE_LOG" ]]; then
    printf '\nПоследние строки внутренней установки:\n' >&2
    tail -n 80 "$CORE_LOG" >&2 || true
  elif [[ -s "$LOG_FILE" ]]; then
    printf '\nПоследние полезные строки журнала мастера:\n' >&2
    tail -n 80 "$LOG_FILE" >&2 || true
  fi
  printf '\nПолный журнал: %s\n' "$LOG_FILE" >&2
  printf 'Журнал внутренней установки: %s\n' "$CORE_LOG" >&2
  exit 1
}

cleanup(){
  startup_stop
  stop_spinner
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

run_step(){
  local label="$1" rc
  shift
  step_begin "$label"
  set +e
  ( set -Eeuo pipefail; "$@" ) >>"$LOG_FILE" 2>&1
  rc=$?
  set -e
  (( rc == 0 )) || fail "$label завершился с кодом $rc"
  step_ok
}

wait_for_apt(){
  local waited=0 timeout=900
  local locks=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  if command -v fuser >/dev/null 2>&1; then
    while fuser "${locks[@]}" >/dev/null 2>&1; do
      (( waited < timeout )) || return 1
      sleep 5
      waited=$((waited + 5))
    done
  fi
}

prompt_secret(){
  local prompt="$1" __name="$2" value=""
  IFS= read -r -s -p "$prompt" value </dev/tty
  printf '\n' >/dev/tty
  printf -v "$__name" '%s' "$value"
}

prompt_default(){
  local prompt="$1" default="$2" __name="$3" value=""
  IFS= read -r -p "$prompt [$default]: " value </dev/tty
  value="${value:-$default}"
  printf -v "$__name" '%s' "$value"
}

prompt_required(){
  local prompt="$1" __name="$2" value=""
  IFS= read -r -p "$prompt: " value </dev/tty
  printf -v "$__name" '%s' "$value"
}

is_ipv4(){
  local value="$1" a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
  done
}

is_public_ipv4(){
  local value="$1" a b c d
  is_ipv4 "$value" || return 1
  IFS=. read -r a b c d <<<"$value"
  (( 10#$a != 0 )) || return 1
  (( 10#$a != 10 )) || return 1
  (( 10#$a != 127 )) || return 1
  ! (( 10#$a == 169 && 10#$b == 254 )) || return 1
  ! (( 10#$a == 172 && 10#$b >= 16 && 10#$b <= 31 )) || return 1
  ! (( 10#$a == 192 && 10#$b == 168 )) || return 1
  (( 10#$a < 224 )) || return 1
}

is_hostname(){
  local value="$1"
  (( ${#value} >= 1 && ${#value} <= 253 )) || return 1
  [[ "$value" != *[[:space:]]* ]] || return 1
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
  [[ "$value" != *..* && "$value" != .* && "$value" != *. ]] || return 1
}

is_valid_public_host(){
  local value="$1"
  if [[ "$value" =~ ^[0-9.]+$ ]]; then
    is_public_ipv4 "$value"
  else
    is_hostname "$value"
  fi
}

extract_public_ipv4_from_cloud_init_file(){
  local file="$1" value=""
  [[ -r "$file" ]] || return 1
  value="$(sed -nE 's/.*"public_ipv4"[[:space:]]*:[[:space:]]*"([0-9.]+)".*/\1/p' "$file" | head -n 1)"
  is_public_ipv4 "$value" || return 1
  printf '%s' "$value"
}

detect_public_ipv4(){
  local value="" token="" file="" python_bin=""

  if command -v cloud-init >/dev/null 2>&1; then
    for query_path in ds.meta_data.public_ipv4 ds.meta_data.public-ipv4; do
      value="$(cloud-init query "$query_path" 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
      if is_public_ipv4 "$value"; then
        printf '%s' "$value"
        return 0
      fi
    done
  fi

  for file in /run/cloud-init/instance-data-sensitive.json /run/cloud-init/instance-data.json; do
    if value="$(extract_public_ipv4_from_cloud_init_file "$file" 2>/dev/null)"; then
      printf '%s' "$value"
      return 0
    fi
  done

  if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    python_bin="python"
  fi

  if [[ -n "$python_bin" ]]; then
    value="$($python_bin - <<'PY_PUBLIC_IP' 2>/dev/null || true
import ipaddress
import urllib.request


def valid(value: str) -> str:
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ""
    return value if ip.version == 4 and ip.is_global else ""

# AWS IMDSv2 first. It works before curl and other packages are installed.
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token_request = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    with opener.open(token_request, timeout=2.0) as response:
        token = response.read().decode("ascii", "ignore").strip()
    ip_request = urllib.request.Request(
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        headers={"X-aws-ec2-metadata-token": token},
    )
    with opener.open(ip_request, timeout=2.0) as response:
        value = valid(response.read().decode("ascii", "ignore"))
    if value:
        print(value)
        raise SystemExit(0)
except Exception:
    pass

# Fallback for EC2 installations where instance metadata access is disabled.
for url in ("https://checkip.amazonaws.com", "https://api.ipify.org"):
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "SG-Panel-Installer/1"})
        with urllib.request.urlopen(request, timeout=3.0) as response:
            value = valid(response.read().decode("ascii", "ignore"))
        if value:
            print(value)
            raise SystemExit(0)
    except Exception:
        pass
PY_PUBLIC_IP
)"
    value="${value//$'\r'/}"
    value="${value//$'\n'/}"
    if is_public_ipv4 "$value"; then
      printf '%s' "$value"
      return 0
    fi
  fi

  if command -v curl >/dev/null 2>&1; then
    token="$(curl -fsS --noproxy '*' --connect-timeout 2 --max-time 3 -X PUT \
      -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
      http://169.254.169.254/latest/api/token 2>/dev/null || true)"
    if [[ -n "$token" ]]; then
      value="$(curl -fsS --noproxy '*' --connect-timeout 2 --max-time 3 \
        -H "X-aws-ec2-metadata-token: $token" \
        http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"
      value="${value//$'\r'/}"
      value="${value//$'\n'/}"
      if is_public_ipv4 "$value"; then
        printf '%s' "$value"
        return 0
      fi
    fi
  fi

  return 1
}

collect_inputs(){
  local password2=""
  printf '%s\n' \
    "SG-Panel — параметры новой установки" \
    "Ubuntu и необходимые системные компоненты уже подготовлены." \
    "Начальная установка работает по HTTP: домен и TLS-сертификат не требуются." \
    "Сейчас один раз задаются параметры панели; затем установка продолжится без дополнительного ввода." \
    "Чтобы принять значение в квадратных скобках, нажмите Enter." \
    ""

  while true; do
    prompt_secret "Пароль администратора панели (не менее 8 символов): " ADMIN_PASSWORD
    prompt_secret "Повторите пароль: " password2
    if (( ${#ADMIN_PASSWORD} < 8 )); then
      printf 'Ошибка: пароль должен содержать не менее 8 символов.\n' >&2
    elif [[ "$ADMIN_PASSWORD" != "$password2" ]]; then
      printf 'Ошибка: пароли не совпадают. Повторите ввод.\n' >&2
    else
      break
    fi
  done

  while true; do
    prompt_default "Публичный HTTP-порт панели" "$DEFAULT_PANEL_PORT" PANEL_PUBLIC_PORT
    if [[ "$PANEL_PUBLIC_PORT" =~ ^[0-9]+$ ]] \
      && (( PANEL_PUBLIC_PORT >= 49152 && PANEL_PUBLIC_PORT <= 65535 )); then
      case "$PANEL_PUBLIC_PORT" in
        8080|8443) printf 'Ошибка: порт %s зарезервирован.\n' "$PANEL_PUBLIC_PORT" >&2 ;;
        *) break ;;
      esac
    else
      printf 'Ошибка: выберите порт от 49152 до 65535.\n' >&2
    fi
  done

  local detected_public_ipv4="${PREDETECTED_PUBLIC_IPV4:-}"
  if [[ -n "$detected_public_ipv4" ]]; then
    printf '[SG-Panel] Публичный IPv4 EC2 определён автоматически: %s\n' "$detected_public_ipv4"
    while true; do
      prompt_default "Адрес панели и Xray (можно указать домен)" "$detected_public_ipv4" XRAY_ADDRESS
      is_valid_public_host "$XRAY_ADDRESS" && break
      printf 'Ошибка: введите корректный публичный IPv4 или домен.\n' >&2
    done
  else
    printf '[SG-Panel] Автоматически определить публичный IPv4 не удалось.\n' >&2
    while true; do
      prompt_required "Адрес панели и Xray (публичный IPv4 или домен)" XRAY_ADDRESS
      is_valid_public_host "$XRAY_ADDRESS" && break
      printf 'Ошибка: введите корректный публичный IPv4 или домен.\n' >&2
    done
  fi

  prompt_default "Имя этого сервера в панели" "$DEFAULT_INSTANCE_NAME" INSTANCE_NAME
  prompt_default "Имя первого пользователя" "$DEFAULT_FIRST_USER" FIRST_USER

  while true; do
    prompt_default "Reality target" "$DEFAULT_REALITY_DEST" REALITY_DEST
    [[ "$REALITY_DEST" == *:* ]] && break
    printf 'Ошибка: Reality target должен иметь вид host:port.\n' >&2
  done

  while true; do
    prompt_default "Reality SNI" "$DEFAULT_REALITY_SNI" REALITY_SNI
    [[ -n "$REALITY_SNI" && "$REALITY_SNI" != *[[:space:]]* ]] && break
    printf 'Ошибка: Reality SNI не должен быть пустым или содержать пробелы.\n' >&2
  done

  unset password2

  printf '\n[SG-Panel] Все параметры приняты. Установка продолжается без дополнительного ввода.\n'
  printf '[SG-Panel] Панель будет доступна по адресу: http://%s:%s\n' \
    "$XRAY_ADDRESS" "$PANEL_PUBLIC_PORT"
}

prepare_system(){
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
  if command -v cloud-init >/dev/null 2>&1; then
    timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
  fi
  wait_for_apt
}

apt_update_indexes(){
  wait_for_apt
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
  dpkg --configure -a
  apt-get -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0 update -qq
}

apt_install_dependencies(){
  wait_for_apt
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
  apt-get -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0 install -y -qq \
    curl ca-certificates unzip rsync zstd psmisc \
    python3 python3-venv python3-pip \
    sqlite3 jq iproute2 dnsutils \
    nginx libnginx-mod-stream certbot openssl
}

detect_public_address_stage(){
  local detected=""
  detected="$(detect_public_ipv4 2>/dev/null || true)"
  if is_public_ipv4 "$detected"; then
    printf '%s\n' "$detected" >"$WORK_DIR/public-ipv4"
    printf '[SG-Panel] Публичный IPv4 определён: %s\n' "$detected" >>"$LOG_FILE"
  else
    : >"$WORK_DIR/public-ipv4"
    printf '[SG-Panel] Публичный IPv4 автоматически не определён; мастер запросит его вручную.\n' >>"$LOG_FILE"
  fi
}

find_local_archive(){
  local candidate="" script_dir="" cwd=""
  cwd="$(pwd)"
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"

  if [[ -n "$SOURCE_ZIP_ARG" ]]; then
    [[ -f "$SOURCE_ZIP_ARG" ]] || return 1
    printf '%s' "$SOURCE_ZIP_ARG"
    return 0
  fi
  if [[ -n "${SG_PANEL_SOURCE_ZIP:-}" ]]; then
    [[ -f "$SG_PANEL_SOURCE_ZIP" ]] || return 1
    printf '%s' "$SG_PANEL_SOURCE_ZIP"
    return 0
  fi

  for candidate in \
    "$cwd/$LOCAL_ARCHIVE_NAME" \
    "$script_dir/$LOCAL_ARCHIVE_NAME"; do
    if [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

prepare_source(){
  local archive="$WORK_DIR/source.zip" local_archive=""
  mkdir -p "$WORK_DIR/extracted"

  if local_archive="$(find_local_archive)"; then
    printf '[SG-Panel] Используется локальный архив: %s\n' "$local_archive" >>"$LOG_FILE"
    cp -f "$local_archive" "$archive"
  else
    printf '[SG-Panel] Локальный архив не найден. Загрузка: %s\n' "$ARCHIVE_URL" >>"$LOG_FILE"
    curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 \
      -o "$archive" "$ARCHIVE_URL"
  fi

  unzip -tq "$archive"
  unzip -q "$archive" -d "$WORK_DIR/extracted"

  local source_root=""
  source_root="$(find "$WORK_DIR/extracted" -maxdepth 5 -type f \
    -path '*/deploy/ec2-first-install.sh' -printf '%h\n' | sed 's#/deploy$##' | head -n 1)"
  [[ -n "$source_root" && -f "$source_root/xpanel/__init__.py" ]]
  grep -Fq "__version__ = \"$EXPECTED_VERSION\"" "$source_root/xpanel/__init__.py"
  grep -Fq "__build__ = \"$EXPECTED_BUILD\"" "$source_root/xpanel/__init__.py"
  grep -Fq "__release_label__ = \"$EXPECTED_RELEASE_LABEL\"" "$source_root/xpanel/__init__.py"
  [[ -f "$source_root/xpanel/static/fix40-node-simple-hotfix18.css" ]]
  [[ -f "$source_root/xpanel/static/fix40-cascade-steps-ui20.css" ]]
  [[ -f "$source_root/xpanel/static/fix40-cluster-restore-ui21.css" ]]
  [[ -f "$source_root/xpanel/static/fix40-node-detail-polish-ui22.css" ]]
  grep -Fq 'WORKER_VERSION = "0.7.0"' "$source_root/node_agent/sg_node_worker.py"
  grep -Fq 'def upsert_cascade_access' "$source_root/node_agent/sg_node_worker.py"
  grep -Fq 'def finalize_cascade_cluster_job' "$source_root/xpanel/service.py"
  grep -Fq 'fix40-cascade-steps-ui20.css' "$source_root/xpanel/templates/base.html"
  grep -Fq 'fix40-cluster-restore-ui21.css' "$source_root/xpanel/templates/base.html"
  grep -Fq 'fix40-node-detail-polish-ui22.css' "$source_root/xpanel/templates/base.html"
  grep -Fq 'HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)' "$source_root/xpanel/service.py"
  grep -Fq 'def _apply_hysteria_salamander_to_inbound' "$source_root/xpanel/service.py"
  grep -Fq 'obfs_mode TEXT NOT NULL DEFAULT' "$source_root/xpanel/db.py"
  grep -Fq 'data-hysteria-salamander-card' "$source_root/xpanel/templates/settings.html"
  grep -Fq 'build_hysteria2_uri' "$source_root/xpanel/service.py"
  grep -Fq 'compact-node-row' "$source_root/xpanel/templates/nodes.html"
  grep -Fq 'node-restore-status' "$source_root/xpanel/templates/node_detail.html"
  ! grep -Fq 'class="node-simple-nav"' "$source_root/xpanel/templates/node_detail.html"
  ! grep -Fq '<select' "$source_root/xpanel/templates/cascade.html"
  find "$source_root" -type f -name '*.sh' -exec chmod 0755 {} +
  printf '%s\n' "$source_root" >"$WORK_DIR/source-root"
}

install_panel(){
  local source_root=""
  [[ -s "$WORK_DIR/source-root" ]] || {
    echo "не сохранён путь к распакованным исходникам" >&2
    return 1
  }
  source_root="$(cat "$WORK_DIR/source-root")"
  [[ -n "$source_root" && -x "$source_root/deploy/ec2-first-install.sh" ]] || {
    echo "не найден внутренний установщик: $source_root/deploy/ec2-first-install.sh" >&2
    return 1
  }
  env \
    XPANEL_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    PANEL_PUBLIC_PORT="$PANEL_PUBLIC_PORT" \
    XRAY_ADDRESS="$XRAY_ADDRESS" \
    INSTANCE_NAME="$INSTANCE_NAME" \
    FIRST_USER="$FIRST_USER" \
    REALITY_DEST="$REALITY_DEST" \
    REALITY_SNI="$REALITY_SNI" \
    SG_PANEL_INPUTS_PRECOLLECTED=1 \
    SG_PANEL_SYSTEM_READY=1 \
    SG_PANEL_INSTALL_LOG="$CORE_LOG" \
    bash "$source_root/deploy/ec2-first-install.sh"
}

validate_result(){
  local marker="/etc/xpanel-mvp/install-complete.env" mode host port
  [[ -s "$marker" ]]
  systemctl is-active --quiet xpanel-web
  systemctl is-active --quiet nginx
  systemctl is-active --quiet xray

  mode="$(grep -E '^PANEL_ACCESS_MODE=' "$marker" | tail -1 | cut -d= -f2-)"
  host="$(grep -E '^PANEL_PUBLIC_HOST=' "$marker" | tail -1 | cut -d= -f2-)"
  port="$(grep -E '^PANEL_PUBLIC_PORT=' "$marker" | tail -1 | cut -d= -f2-)"
  [[ -n "$mode" && -n "$host" && "$port" =~ ^[0-9]+$ ]]

  local login_body=""
  if [[ "$mode" == "https" ]]; then
    login_body="$(curl -kfsS --max-time 10 --resolve "$host:$port:127.0.0.1" \
      "https://$host:$port/login")"
  else
    login_body="$(curl -fsS --max-time 10 -H "Host: $host" \
      "http://127.0.0.1:$port/login")"
  fi
  grep -Fq "$EXPECTED_BUILD" <<<"$login_body" || {
    echo "GUI не отдаёт маркер сборки $EXPECTED_BUILD" >&2
    return 1
  }
  local clients_css
  if [[ "$mode" == "https" ]]; then
    clients_css="$(curl -kfsS --max-time 10 --resolve "$host:$port:127.0.0.1" \
      "https://$host:$port/static/fix40-clients-layout-hotfix3.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-clients-layout-hotfix3")"
  else
    clients_css="$(curl -fsS --max-time 10 -H "Host: $host" \
      "http://127.0.0.1:$port/static/fix40-clients-layout-hotfix3.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-clients-layout-hotfix3")"
  fi
  grep -Fq "Clients Layout Hotfix 3" <<<"$clients_css" || {
    echo "GUI не отдаёт Clients Layout Hotfix 3" >&2
    return 1
  }
  local global_css
  if [[ "$mode" == "https" ]]; then
    global_css="$(curl -kfsS --max-time 10 --resolve "$host:$port:127.0.0.1" \
      "https://$host:$port/static/fix40-interface-cleanup-hotfix5.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-interface-cleanup-hotfix5")"
  else
    global_css="$(curl -fsS --max-time 10 -H "Host: $host" \
      "http://127.0.0.1:$port/static/fix40-interface-cleanup-hotfix5.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-interface-cleanup-hotfix5")"
  fi
  grep -Fq "Interface Cleanup Hotfix 5" <<<"$global_css" || {
    echo "GUI не отдаёт Interface Cleanup Hotfix 5" >&2
    return 1
  }
  if [[ "$mode" == "https" ]]; then
    global_css="$(curl -kfsS --max-time 10 --resolve "$host:$port:127.0.0.1" \
      "https://$host:$port/static/fix40-ui-compact-hotfix6.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-ui-compact-hotfix6")"
  else
    global_css="$(curl -fsS --max-time 10 -H "Host: $host" \
      "http://127.0.0.1:$port/static/fix40-ui-compact-hotfix6.css?v=$EXPECTED_VERSION-$EXPECTED_BUILD-ui-compact-hotfix6")"
  fi
  grep -Fq "UI Compact Hotfix 6" <<<"$global_css" || {
    echo "GUI не отдаёт UI Compact Hotfix 6" >&2
    return 1
  }
  local tabs_css
  tabs_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-global-tabs-dark-buttons-hotfix7.css")"
  grep -Fq "Global Tabs and Dark Buttons Hotfix 7" <<<"$tabs_css" || {
    echo "GUI не отдаёт Global Tabs and Dark Buttons Hotfix 7" >&2
    return 1
  }
  local ui8_css
  ui8_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-interface-verification-hotfix8.css")"
  grep -Fq "Interface Verification Hotfix 8" <<<"$ui8_css" || {
    echo "GUI не отдаёт Interface Verification Hotfix 8" >&2
    return 1
  }
  local ui9_css
  ui9_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-light-buttons-theme-icon-hotfix9.css")"
  grep -Fq "Light Button Gradient and Theme Icon Hotfix 9" <<<"$ui9_css" || {
    echo "GUI не отдаёт Light Button Gradient and Theme Icon Hotfix 9" >&2
    return 1
  }
  local ui18_css
  ui18_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-node-simple-hotfix18.css")"
  grep -Fq "Node card and safe card geometry" <<<"$ui18_css" || {
    echo "GUI не отдаёт Node Simple Hotfix 18" >&2
    return 1
  }
  local ui19_css
  ui19_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-cascade-steps-ui20.css")"
  grep -Fq "guided three-step Cascade" <<<"$ui19_css" || {
    echo "GUI не отдаёт Cascade Steps UI20" >&2
    return 1
  }
  local ui21_css
  ui21_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-cluster-restore-ui21.css")"
  grep -Fq "Restore the compact Cluster and SG-Node card" <<<"$ui21_css" || {
    echo "GUI не отдаёт Cluster Restore UI21" >&2
    return 1
  }
  local ui22_css
  ui22_css="$(curl -fsS --max-time 10 "http://127.0.0.1:8080/static/fix40-node-detail-polish-ui22.css")"
  grep -Fq "remove the inherited gray slabs" <<<"$ui22_css" || {
    echo "GUI не отдаёт Node Detail Polish UI22" >&2
    return 1
  }
  grep -Fq 'HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)' "$TARGET/xpanel/service.py" || {
    echo "установленный код не содержит Salamander UI23" >&2
    return 1
  }
  grep -Fq 'data-hysteria-salamander-card' "$TARGET/xpanel/templates/settings.html" || {
    echo "установленный GUI не содержит Salamander UI23" >&2
    return 1
  }
}

show_result(){
  printf '\n[SG-Panel] SG-Panel: %sactive%s\n' "$C_GREEN" "$C_RESET"
  printf '[SG-Panel] Nginx:    %sactive%s\n' "$C_GREEN" "$C_RESET"
  printf '[SG-Panel] Xray:     %sactive%s\n' "$C_GREEN" "$C_RESET"
}

main(){
  startup_begin "Запуск мастера полной установки SG-Panel"
  [[ $EUID -eq 0 ]] || startup_error "Запустите установщик через sudo bash."
  if [[ -e /opt/xpanel-mvp || -e /etc/xpanel-mvp || -e /var/lib/xpanel-mvp || -e /var/log/xpanel-mvp ]]; then
    startup_error "Этот файл предназначен только для новой EC2. Обнаружены следы установленной SG-Panel; ничего не удалено."
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -Eq '^(xpanel-web|xray|nginx)\.service$'; then
    startup_error "Этот файл предназначен только для новой EC2. Обнаружены уже установленные службы SG-Panel/Xray/Nginx; ничего не удалено."
  fi
  check_supported_platform
  [[ -r /dev/tty && -w /dev/tty ]] || \
    startup_error "Нужен интерактивный терминал для первоначальных вопросов."

  if [[ -n "$SOURCE_ZIP_ARG" && ! -f "$SOURCE_ZIP_ARG" ]]; then
    startup_error "Не найден архив SG-Panel FIX40: $SOURCE_ZIP_ARG"
  fi

  install -d -m 0755 "$(dirname "$LOG_FILE")"
  : >"$LOG_FILE"
  chmod 0600 "$LOG_FILE"
  : >"$CORE_LOG"
  chmod 0600 "$CORE_LOG"
  WORK_DIR="$(mktemp -d /tmp/sg-panel-install.XXXXXX)"
  startup_ok "Мастер полной установки SG-Panel запущен"

  # Надёжный bootstrap выполняется до вопросов. Пользователь с первой секунды
  # видит зелёную вертушку, а весь apt/dpkg-вывод остаётся в журнале.
  run_step "Этап 1/7 · Подготовка чистой Ubuntu" prepare_system
  run_step "Этап 2/7 · Обновление индексов APT" apt_update_indexes
  run_step "Этап 3/7 · Установка системных компонентов" apt_install_dependencies
  run_step "Этап 4/7 · Определение публичного адреса" detect_public_address_stage

  PREDETECTED_PUBLIC_IPV4="$(cat "$WORK_DIR/public-ipv4" 2>/dev/null || true)"
  collect_inputs

  run_step "Этап 5/7 · Проверка и распаковка SG-Panel FIX40" prepare_source
  run_step "Этап 6/7 · Установка SG-Panel, Xray и Nginx" install_panel
  unset ADMIN_PASSWORD
  run_step "Этап 7/7 · Финальная проверка панели и служб" validate_result
  show_result
}

main "$@"
