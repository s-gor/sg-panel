from __future__ import annotations

# SG ALL VLESS TRANSPORTS ENCRYPTION + VISION V1

import base64
import errno
import fcntl
import io
import ipaddress
import hashlib
import json
import os
import platform
import pwd
import grp
import re
import secrets
import shutil
import socket
import time
import sqlite3
import subprocess
import tempfile
import uuid as uuidlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

from .db import PROJECT_ROOT, connect, db_path, init_db, use_db_path
from .security import get_security_settings, security_overview


from .xray_encryption import client_value_ready, server_value_ready
from .xray_encryption_runtime import (
    DEFAULT_SECRET_PATH as XRAY_ENCRYPTION_SECRET_PATH,
    MINIMUM_XRAY_LABEL,
    XrayEncryptionRuntimeError,
    ensure_pair as ensure_xray_encryption_pair,
    read_pair as read_xray_encryption_pair,
    require_supported_xray,
)
class XPanelError(RuntimeError):
    pass


VLESSENC_SERVER_PROFILES = {
    "xhttp_reality",
    "xhttp_tls",
    "grpc_tls",
    "xhttp_hysteria_tls",
    "russia_kit",
}
VISION_INBOUND_PROFILES = {"raw_reality", *VLESSENC_SERVER_PROFILES}
VLESSENC_CLIENT_MODE_DEFAULT = "stream-one"
VLESSENC_TLS_CLIENT_MODE_DEFAULT = "auto"
VLESSENC_SERVER_MODE_DEFAULT = "auto"
ALLOWED_PROTOCOLS = {"http", "tls", "quic", "bittorrent"}
ALLOWED_NETWORKS = {"", "tcp", "udp", "tcp,udp"}
ALLOWED_RULE_TARGETS = {"outbound", "balancer"}
ALLOWED_DOMAIN_STRATEGIES = {"AsIs", "IPIfNonMatch", "IPOnDemand"}
ALLOWED_DNS_QUERY_STRATEGIES = {"UseIP", "UseIPv4", "UseIPv6", "UseSystem"}
ALLOWED_DNS_SERVER_QUERY_STRATEGIES = {"", *ALLOWED_DNS_QUERY_STRATEGIES}
ALLOWED_LOGLEVELS = {"debug", "info", "warning", "error", "none"}
ALLOWED_FLOWS = {"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}
ALLOWED_OUTBOUND_NETWORKS = {"raw", "xhttp"}
ALLOWED_OUTBOUND_SECURITY = {"reality", "tls"}
ALLOWED_XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
ALLOWED_XMUX_MODES = {"auto", "reduced", "expert"}
# Community-requested conservative XMUX policy. It intentionally uses
# maxConnections and never maxConcurrency because Xray treats them as
# mutually exclusive controls. Values remain hidden from ordinary UI.
XMUX_REDUCED_PRESET: dict[str, object] = {
    "maxConnections": "2-6",
    "cMaxReuseTimes": "300-600",
    "hMaxRequestTimes": "1000-2000",
    "hMaxReusableSecs": "1200-2400",
}
RUSSIA_KIT_PROFILE = "russia_kit"
RUSSIA_KIT_XHTTP_REALITY_PATH = "/sg-rf-reality"
RUSSIA_KIT_XHTTP_TLS_PATH = "/sg-rf-xhttp"
RUSSIA_KIT_WS_PATH = "/sg-rf-ws"
RUSSIA_KIT_XHTTP_REALITY_PORT = 8444
RUSSIA_KIT_XHTTP_TLS_PORT = 8443
RUSSIA_KIT_WS_PORT = 8446
ALLOWED_INBOUND_PROFILES = {"raw_reality", "xhttp_tls", "xhttp_reality", "grpc_tls", "hysteria2_tls", "xhttp_hysteria_tls", RUSSIA_KIT_PROFILE}
ALLOWED_HYSTERIA_PRESETS = {"auto", "mobile", "speed", "limited", "custom"}
ALLOWED_HYSTERIA_CONGESTION = {"reno", "bbr", "brutal", "force-brutal"}
ALLOWED_HYSTERIA_BBR_PROFILES = {"conservative", "standard", "aggressive"}
HYSTERIA_OBFS_MODES = {"none", "salamander"}
HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)
HYSTERIA_SALAMANDER_MIN_LABEL = "v26.3.27"


def generate_hysteria_obfs_password() -> str:
    """Generate the shared per-inbound Salamander secret.

    Twenty-four random bytes encoded as unpadded Base64URL produce a compact
    32-character value without coupling the obfuscation secret to a client
    UUID or Hysteria authentication token.
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("=")


def _version_tuple(value: object) -> tuple[int, int, int]:
    numbers = [int(item) for item in re.findall(r"\d+", str(value or ""))[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _installed_xray_version(xray_bin: str) -> tuple[int, int, int]:
    binary = str(xray_bin or "").strip()
    if not binary:
        raise XPanelError("не указан путь к Xray")
    if not Path(binary).is_file() and shutil.which(binary) is None:
        raise XPanelError(f"Xray не найден: {binary}")
    result = _run([binary, "version"], timeout=15)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "xray version завершился с ошибкой").strip()
        raise XPanelError(detail)
    version = _version_tuple(result.stdout + "\n" + result.stderr)
    if version == (0, 0, 0):
        raise XPanelError("не удалось определить версию Xray")
    return version


def hysteria_salamander_support_status(xray_bin: str | None = None) -> dict[str, object]:
    binary = str(xray_bin or get_server()["xray_bin"])
    try:
        version = _installed_xray_version(binary)
        supported = version >= HYSTERIA_SALAMANDER_MIN_VERSION
        message = (
            "Hysteria2 Salamander FinalMask поддерживается"
            if supported
            else "Установленная версия Xray не поддерживает Hysteria2 Salamander FinalMask"
        )
    except (XPanelError, OSError) as exc:
        version = (0, 0, 0)
        supported = False
        message = str(exc)
    return {
        "supported": supported,
        "version": f"v{version[0]}.{version[1]}.{version[2]}" if version != (0, 0, 0) else "",
        "minimum": HYSTERIA_SALAMANDER_MIN_LABEL,
        "message": message,
    }


def _require_hysteria_salamander_support(xray_bin: str | None = None) -> tuple[int, int, int]:
    binary = str(xray_bin or get_server()["xray_bin"])
    version = _installed_xray_version(binary)
    if version < HYSTERIA_SALAMANDER_MIN_VERSION:
        shown = f"v{version[0]}.{version[1]}.{version[2]}"
        raise XPanelError(
            "Установленная версия Xray " + shown
            + " не поддерживает Hysteria2 Salamander FinalMask. "
            + "Сначала обновите Xray минимум до " + HYSTERIA_SALAMANDER_MIN_LABEL + "."
        )
    return version


def redact_hysteria_obfs_secrets(value: object, *, extra: list[str] | None = None) -> str:
    """Remove stored or request-local Salamander passwords from user-visible diagnostics."""
    text = str(value or "")
    secrets_to_hide: list[str] = []
    try:
        secrets_to_hide.extend(
            str(row["obfs_password"])
            for row in list_hysteria_inbounds()
            if row["obfs_password"] is not None and len(str(row["obfs_password"])) >= 6
        )
    except (sqlite3.Error, OSError, KeyError, TypeError):
        pass
    secrets_to_hide.extend(str(item) for item in (extra or []) if len(str(item)) >= 6)
    for secret in sorted(set(secrets_to_hide), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def _normalise_hysteria_obfs(mode: object, password: object) -> tuple[str, str | None]:
    clean_mode = str(mode or "none").strip().lower()
    if clean_mode not in HYSTERIA_OBFS_MODES:
        raise ValueError("Hysteria 2: неподдерживаемый режим обфускации")
    if clean_mode == "none":
        return "none", None
    value = "" if password is None else str(password)
    if not value or not value.strip():
        raise ValueError("Hysteria 2: для Salamander укажите пароль")
    if any(char in value for char in "\r\n\x00"):
        raise ValueError("Hysteria 2: пароль Salamander содержит недопустимые символы")
    if len(value.encode("utf-8")) > 512:
        raise ValueError("Hysteria 2: пароль Salamander слишком длинный")
    return "salamander", value


def _format_uri_host(host: str) -> str:
    value = str(host or "").strip()
    candidate = value.strip("[]")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return value
    return f"[{candidate}]" if parsed.version == 6 else candidate


def build_hysteria2_uri(
    *, auth: str, host: str, port: str | int, sni: str, profile_name: str,
    obfs_mode: str = "none", obfs_password: str | None = None,
) -> str:
    mode, password = _normalise_hysteria_obfs(obfs_mode, obfs_password)
    query: dict[str, str] = {"sni": str(sni or ""), "alpn": "h3", "insecure": "0"}
    if mode == "salamander":
        query["obfs"] = "salamander"
        query["obfs-password"] = str(password)
    return (
        f"hysteria2://{quote(str(auth), safe='')}@{_format_uri_host(host)}:{port}/?"
        f"{urlencode(query, quote_via=quote)}#{quote(str(profile_name), safe='')}"
    )
FINGERPRINT_ALIASES = {"brave": "chrome", "opera": "chrome", "vivaldi": "chrome"}
STANDARD_FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized", "unsafe", *FINGERPRINT_ALIASES.keys(),
}
TLS_INBOUND_PROFILES = {"xhttp_tls", "grpc_tls", "xhttp_hysteria_tls"}
HYSTERIA_ACTIVE_PROFILES = {"hysteria2_tls", "xhttp_hysteria_tls", RUSSIA_KIT_PROFILE}
XHTTP_ACTIVE_PROFILES = {"xhttp_tls", "xhttp_hysteria_tls", RUSSIA_KIT_PROFILE}
DIRECT_TLS_INBOUND_PROFILES = HYSTERIA_ACTIVE_PROFILES
CERTIFICATE_INBOUND_PROFILES = TLS_INBOUND_PROFILES | DIRECT_TLS_INBOUND_PROFILES
REALITY_INBOUND_PROFILES = {"raw_reality", "xhttp_reality", RUSSIA_KIT_PROFILE}
SUPPORTED_VLESS_OUTBOUND_COMBINATIONS = {
    ("raw", "reality"),
    ("xhttp", "tls"),
    ("xhttp", "reality"),
}
OUTBOUND_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
RESERVED_OUTBOUND_TAGS = {"direct", "blocked", "api", "warp"}
DEFAULT_BACKUP_DIR = PROJECT_ROOT / "backups"
WARP_TAG = "warp"
WARP_IPV4_ENDPOINT = "162.159.192.1:2408"
WARP_RULE_NAME = "Cloudflare WARP"
WARP_IP_RULE_NAME = "Cloudflare WARP — IP"
WARP_DIR = Path(os.environ.get("XPANEL_WARP_DIR", "/etc/xpanel-mvp/warp"))
HYSTERIA_TLS_DIR = Path(os.environ.get("XPANEL_HYSTERIA_TLS_DIR", "/usr/local/etc/xray/sg-panel-tls"))
HYSTERIA_MAX_INBOUNDS = 3
HYSTERIA_INBOUND_TAGS = {
    1: "vless-reality-in",
    2: "hysteria2-secondary-in",
    3: "hysteria2-tertiary-in",
}
XHTTP_MAX_INBOUNDS = 3
XHTTP_INBOUND_TAGS = {
    1: "vless-reality-in",
    2: "xhttp-secondary-in",
    3: "xhttp-tertiary-in",
}
REALITY_MAX_INBOUNDS = 3
REALITY_INBOUND_TAGS = {
    1: "vless-reality-in",
    2: "reality-secondary-in",
    3: "reality-tertiary-in",
}
HYSTERIA_COMBINED_PRIMARY_TAG = "hysteria2-primary-in"
REALITY_EDGE_STATE = Path(os.environ.get("XPANEL_REALITY_EDGE_STATE", "/etc/xpanel-mvp/reality-edge.env"))
REALITY_EDGE_XRAY_PORT = 8444
REALITY_EDGE_WEB_PORT = 10443
REALITY_EDGE_LEGACY_WEB_PORT = 9443

GEOFILES_BUNDLED_DIR = PROJECT_ROOT / "assets" / "geofiles"
GEOFILES_MINIMUM_SIZE = 4 * 1024
GEOFILES_BUNDLED_SHA256 = {
    "geoip.dat": "c0f37cacaca04fcf273d6fc740e236748b2a7a082056b162bf7ce95db8af6efa",
    "geosite.dat": "8bc708286ac3160003d9eba7290841f931e3ef41a05d92555a07b513a7a08163",
}
_GEOFILE_CATEGORY_CACHE: dict[tuple[str, int, int], tuple[str, ...]] = {}
GEOFILES_SOURCES: dict[str, dict[str, object]] = {
    "sgclient": {
        "label": "Комплект SG Client",
        "description": "Проверенная связанная пара geoip.dat и geosite.dat из SG Client 086.",
        "geoip_url": "",
        "geosite_url": "",
        "selectable": True,
    },
    "loyalsoldier": {
        "label": "Loyalsoldier",
        "description": "Расширенный популярный комплект v2ray-rules-dat.",
        "geoip_url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        "geosite_url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
        "selectable": True,
    },
    "runetfreedom": {
        "label": "RunetFreedom",
        "description": "Специализированные российские категории и списки блокировок.",
        "geoip_url": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
        "geosite_url": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
        "selectable": True,
    },
    "roscomvpn": {
        "label": "RoscomVPN",
        "description": "Связанный комплект с category-ru/category-ads и direct/private/whitelist.",
        "geoip_url": "https://github.com/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat",
        "geosite_url": "https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat",
        "selectable": True,
    },
    "custom": {
        "label": "Пользовательские URL",
        "description": "Отдельные HTTPS URL для связанной пары geoip.dat и geosite.dat.",
        "geoip_url": "",
        "geosite_url": "",
        "selectable": True,
    },
    "local": {
        "label": "Локальные файлы",
        "description": "Связанная пара файлов, уже находящихся на сервере.",
        "geoip_url": "",
        "geosite_url": "",
        "selectable": True,
    },
    # Legacy label for installations whose currently active files predate the
    # bundled SG Client source. It is intentionally not offered for selection.
    "xray": {
        "label": "Исходный комплект установленного Xray",
        "description": "Резервная копия GeoFiles, которые были установлены вместе с Xray.",
        "geoip_url": "",
        "geosite_url": "",
        "selectable": False,
    },
}
GEOFILES_STATE_DIR = Path(os.environ.get("XPANEL_GEOFILES_STATE_DIR", "/var/lib/sg-panel/geofiles"))
GEOFILES_OPERATION_LOCK = GEOFILES_STATE_DIR / ".operation.lock"


@contextmanager
def _geofiles_operation_lock(action: str):
    """Serialize Controller GeoFiles check/apply operations across web workers."""
    GEOFILES_STATE_DIR.mkdir(parents=True, exist_ok=True)
    stream = GEOFILES_OPERATION_LOCK.open("a+")
    try:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise XPanelError(
                f"GeoFiles: уже выполняется другая операция; дождитесь её завершения и повторите {action}"
            ) from exc
        stream.seek(0)
        stream.truncate()
        stream.write(
            json.dumps(
                {
                    "action": str(action),
                    "pid": os.getpid(),
                    "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                },
                ensure_ascii=False,
            )
        )
        stream.flush()
        yield
    finally:
        try:
            stream.seek(0)
            stream.truncate()
            stream.flush()
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()
PANEL_BACKUP_RETENTION = max(1, int(os.environ.get("XPANEL_BACKUP_RETENTION", "10") or 10))
GEOFILES_SET_RETENTION = max(2, int(os.environ.get("XPANEL_GEOFILES_SET_RETENTION", "5") or 5))
GEOFILES_BACKUP_RETENTION = max(2, int(os.environ.get("XPANEL_GEOFILES_BACKUP_RETENTION", "5") or 5))
GEOFILES_STAGING_MAX_AGE_HOURS = max(1, int(os.environ.get("XPANEL_GEOFILES_STAGING_MAX_AGE_HOURS", "24") or 24))
COUNTRY_GEOIP_PATH = PROJECT_ROOT / "assets" / "geoip" / "sg-country-geoip.dat"
ROSCOMVPN_DIRECT_GEOSITE = (
    "private", "whitelist", "category-ru", "apple", "microsoft", "steam",
    "epicgames", "riot", "escapefromtarkov", "faceit", "pinterest",
)
ROSCOMVPN_DIRECT_GEOIP = ("private", "whitelist", "direct")
ROSCOMVPN_BLOCK_GEOSITE = ("category-ads", "win-spy", "torrent")
ROSCOMVPN_DIRECT_RULE = "RoscomVPN · Direct"
ROSCOMVPN_BLOCK_RULE = "RoscomVPN · Block"

WARP_RUSSIA_TLDS = "geosite:tld-ru"
WARP_RUSSIA_DOMAINS = "geosite:category-ru"
WARP_RUSSIA_IPS = "geoip:ru"

WARP_DEFAULT_DOMAINS = """domain:google.com
domain:googleapis.com
domain:gstatic.com
domain:spotify.com
domain:scdn.co
domain:reddit.com
domain:redd.it
domain:instagram.com
domain:facebook.com
domain:fbcdn.net
domain:openai.com
domain:chatgpt.com
domain:oaistatic.com
domain:oaiusercontent.com"""


CASCADE_SERVICE_COMMENT = "SG-Panel managed Cascade service access"


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("для этой операции нужны права root")


def _run(
    args: list[str], *, timeout: int = 15, cwd: str | Path | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args, text=True, capture_output=True, timeout=timeout,
            cwd=str(cwd) if cwd is not None else None,
        )
    except subprocess.TimeoutExpired as exc:
        raise XPanelError(f"команда превысила тайм-аут {timeout} с: {' '.join(args)}") from exc


def get_server() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
    if row is None:
        raise XPanelError("настройки сервера ещё не заданы; выполните set-server")
    return row


def _normalise_instance_name(value: str) -> str:
    name = re.sub(r"\s+", " ", str(value or "").strip())
    if not name:
        raise ValueError("укажите имя сервера")
    if len(name) > 64:
        raise ValueError("имя сервера не должно быть длиннее 64 символов")
    if any(ord(char) < 32 for char in name):
        raise ValueError("имя сервера содержит недопустимые символы")
    return name


def get_instance_name() -> str:
    server = get_server()
    value = str(server["instance_name"] or "").strip()
    return value or "SG-Panel"


def get_instance_address() -> str:
    server = get_server()
    return str(server["address"] or "").strip()


def get_instance_identity() -> str:
    name = get_instance_name()
    address = get_instance_address()
    if not address or address.casefold() in name.casefold():
        return name
    return f"{name} · {address}"


def update_instance_name(value: str) -> str:
    name = _normalise_instance_name(value)
    with connect() as con:
        con.execute("UPDATE server_settings SET instance_name = ? WHERE id = 1", (name,))
        settings = con.execute("SELECT service_user_id FROM cascade_settings WHERE id = 1").fetchone()
        service_user_id = int(settings["service_user_id"] or 0) if settings else 0
        if service_user_id:
            user = con.execute("SELECT id FROM users WHERE id = ?", (service_user_id,)).fetchone()
            desired = f"Cascade · {name}"[:80]
            if user is not None:
                collision = con.execute(
                    "SELECT 1 FROM users WHERE name = ? COLLATE NOCASE AND id != ?",
                    (desired, service_user_id),
                ).fetchone()
                if collision is None:
                    con.execute(
                        "UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (desired, service_user_id),
                    )
    return name


def list_hysteria_inbounds() -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM hysteria_inbounds ORDER BY id"
        ).fetchall()


def list_xhttp_inbounds() -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM xhttp_inbounds ORDER BY id"
        ).fetchall()


def list_reality_inbounds() -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM reality_inbounds ORDER BY id"
        ).fetchall()


def _normalise_reality_instances(
    values: list[dict[str, object]] | None,
    *,
    primary_listen: str,
    primary_port: int,
    primary_short_id: str,
) -> list[dict[str, object]]:
    current = {int(row["id"]): dict(row) for row in list_reality_inbounds()}
    provided: dict[int, dict[str, object]] = {}
    for raw in values or []:
        try:
            instance_id = int(raw.get("id", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("REALITY: некорректный номер Inbound") from exc
        if instance_id not in REALITY_INBOUND_TAGS:
            raise ValueError("REALITY: разрешены только Inbound #1, #2 и #3")
        if instance_id in provided:
            raise ValueError(f"REALITY #{instance_id}: настройки переданы дважды")
        provided[instance_id] = raw

    def as_bool(value: object) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    result: list[dict[str, object]] = []
    names: dict[str, int] = {}
    ports: dict[int, int] = {}
    short_ids: dict[str, int] = {}
    for instance_id in range(1, REALITY_MAX_INBOUNDS + 1):
        base = current.get(instance_id, {})
        item = provided.get(instance_id, {})
        name = str(item.get("name", base.get("name", f"REALITY #{instance_id}"))).strip()
        if not name or len(name) > 80:
            raise ValueError(f"REALITY #{instance_id}: имя должно содержать от 1 до 80 символов")
        name_key = name.casefold()
        if name_key in names:
            raise ValueError(f"REALITY #{instance_id}: название уже используется Inbound #{names[name_key]}")
        names[name_key] = instance_id
        enabled = True if instance_id == 1 else as_bool(item.get("enabled", base.get("enabled", False)))
        listen = str(primary_listen if instance_id == 1 else item.get("listen", base.get("listen", "0.0.0.0"))).strip()
        default_port = 8443 if instance_id == 2 else 9443
        try:
            port = int(primary_port if instance_id == 1 else item.get("port", base.get("port", default_port)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"REALITY #{instance_id}: TCP-порт должен быть числом") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"REALITY #{instance_id}: TCP-порт должен быть от 1 до 65535")
        try:
            parsed_listen = ipaddress.ip_address(listen)
        except ValueError as exc:
            raise ValueError(f"REALITY #{instance_id}: listen должен быть IP-адресом") from exc
        if enabled and instance_id > 1 and parsed_listen.is_loopback:
            raise ValueError(f"REALITY #{instance_id}: публичный TCP-listener не может быть loopback")
        short_id = str(primary_short_id if instance_id == 1 else item.get("short_id", base.get("short_id", ""))).strip().lower()
        if not short_id:
            short_id = secrets.token_hex(8)
        if not re.fullmatch(r"[0-9a-f]{2,32}", short_id) or len(short_id) % 2:
            raise ValueError(f"REALITY #{instance_id}: Short ID должен быть HEX-строкой чётной длины от 2 до 32 символов")
        if enabled:
            if port in ports:
                raise ValueError(f"Конфликт REALITY: TCP-порт {port} уже используется Inbound #{ports[port]}")
            ports[port] = instance_id
            if short_id in short_ids:
                raise ValueError(f"Конфликт REALITY: Short ID уже используется Inbound #{short_ids[short_id]}")
            short_ids[short_id] = instance_id
        result.append({
            "id": instance_id,
            "name": name,
            "tag": REALITY_INBOUND_TAGS[instance_id],
            "enabled": enabled,
            "listen": listen,
            "port": port,
            "short_id": short_id,
        })
    return result


def update_reality_inbounds(
    values: list[dict[str, object]] | None,
    *,
    primary_listen: str,
    primary_port: int,
    primary_short_id: str,
) -> list[sqlite3.Row]:
    cleaned = _normalise_reality_instances(
        values,
        primary_listen=primary_listen,
        primary_port=primary_port,
        primary_short_id=primary_short_id,
    )
    with connect() as con:
        for item in cleaned:
            con.execute(
                """
                INSERT INTO reality_inbounds (id, name, tag, enabled, listen, port, short_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, tag=excluded.tag, enabled=excluded.enabled,
                    listen=excluded.listen, port=excluded.port, short_id=excluded.short_id,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    int(item["id"]), str(item["name"]), str(item["tag"]),
                    int(bool(item["enabled"])), str(item["listen"]), int(item["port"]),
                    str(item["short_id"]),
                ),
            )
    return list_reality_inbounds()


def _normalise_xhttp_instances(
    values: list[dict[str, object]] | None,
    *,
    primary_listen: str,
    primary_port: int,
    primary_path: str,
) -> list[dict[str, object]]:
    current = {int(row["id"]): dict(row) for row in list_xhttp_inbounds()}
    provided: dict[int, dict[str, object]] = {}
    for raw in values or []:
        try:
            instance_id = int(raw.get("id", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("XHTTP: некорректный номер Inbound") from exc
        if instance_id not in XHTTP_INBOUND_TAGS:
            raise ValueError("XHTTP: разрешены только Inbound #1, #2 и #3")
        if instance_id in provided:
            raise ValueError(f"XHTTP #{instance_id}: настройки переданы дважды")
        provided[instance_id] = raw

    def as_bool(value: object) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    result: list[dict[str, object]] = []
    names: dict[str, int] = {}
    paths: dict[str, int] = {}
    endpoints: dict[tuple[str, int], int] = {}
    for instance_id in range(1, XHTTP_MAX_INBOUNDS + 1):
        base = current.get(instance_id, {})
        item = provided.get(instance_id, {})
        name = str(item.get("name", base.get("name", f"XHTTP #{instance_id}"))).strip()
        if not name or len(name) > 80:
            raise ValueError(f"XHTTP #{instance_id}: имя должно содержать от 1 до 80 символов")
        name_key = name.casefold()
        if name_key in names:
            raise ValueError(
                f"XHTTP #{instance_id}: название уже используется Inbound #{names[name_key]}"
            )
        names[name_key] = instance_id
        enabled = True if instance_id == 1 else as_bool(
            item.get("enabled", base.get("enabled", False))
        )
        listen = str(
            primary_listen if instance_id == 1 else item.get("listen", base.get("listen", "127.0.0.1"))
        ).strip()
        default_port = 8444 if instance_id == 2 else 8445
        try:
            port = int(
                primary_port if instance_id == 1 else item.get("port", base.get("port", default_port))
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"XHTTP #{instance_id}: локальный TCP-порт должен быть числом") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"XHTTP #{instance_id}: локальный TCP-порт должен быть от 1 до 65535")
        path = str(
            primary_path if instance_id == 1 else item.get("path", base.get("path", f"/sg-xhttp-{instance_id}"))
        ).strip()
        _validate_xhttp_path(path)
        try:
            parsed_listen = ipaddress.ip_address(listen)
        except ValueError as exc:
            raise ValueError(f"XHTTP #{instance_id}: listen должен быть IP-адресом") from exc
        if enabled and not parsed_listen.is_loopback:
            raise ValueError(
                f"XHTTP #{instance_id}: локальный Xray должен слушать только loopback-адрес"
            )
        canonical_path = path.rstrip("/") or "/"
        if canonical_path in paths:
            raise ValueError(
                f"Конфликт XHTTP: Path {path} уже используется Inbound #{paths[canonical_path]}"
            )
        paths[canonical_path] = instance_id
        endpoint = (listen, port)
        if endpoint in endpoints:
            raise ValueError(
                f"Конфликт XHTTP: {listen}:{port} уже используется Inbound #{endpoints[endpoint]}"
            )
        endpoints[endpoint] = instance_id
        result.append({
            "id": instance_id,
            "name": name,
            "tag": XHTTP_INBOUND_TAGS[instance_id],
            "enabled": enabled,
            "listen": listen,
            "port": port,
            "path": path,
        })
    return result


def update_xhttp_inbounds(
    values: list[dict[str, object]] | None,
    *,
    primary_listen: str,
    primary_port: int,
    primary_path: str,
) -> list[sqlite3.Row]:
    cleaned = _normalise_xhttp_instances(
        values,
        primary_listen=primary_listen,
        primary_port=primary_port,
        primary_path=primary_path,
    )
    with connect() as con:
        for item in cleaned:
            con.execute(
                """
                INSERT INTO xhttp_inbounds (id, name, tag, enabled, listen, port, path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, tag=excluded.tag, enabled=excluded.enabled,
                    listen=excluded.listen, port=excluded.port, path=excluded.path,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    int(item["id"]), str(item["name"]), str(item["tag"]),
                    int(bool(item["enabled"])), str(item["listen"]), int(item["port"]),
                    str(item["path"]),
                ),
            )
    return list_xhttp_inbounds()


def _normalise_hysteria_instances(
    values: list[dict[str, object]] | None,
    *,
    primary_listen: str,
    primary_port: int,
    hop_ports: str = "",
) -> list[dict[str, object]]:
    current = {int(row["id"]): dict(row) for row in list_hysteria_inbounds()}
    provided: dict[int, dict[str, object]] = {}
    for raw in values or []:
        try:
            instance_id = int(raw.get("id", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Hysteria 2: некорректный номер Inbound") from exc
        if instance_id not in HYSTERIA_INBOUND_TAGS:
            raise ValueError("Hysteria 2: разрешены только Inbound #1, #2 и #3")
        if instance_id in provided:
            raise ValueError(f"Hysteria 2 #{instance_id}: настройки переданы дважды")
        provided[instance_id] = raw

    def as_bool(value: object) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    result: list[dict[str, object]] = []
    names: dict[str, int] = {}
    for instance_id in range(1, HYSTERIA_MAX_INBOUNDS + 1):
        base = current.get(instance_id, {})
        item = provided.get(instance_id, {})
        name = str(
            item.get("name", base.get("name", f"Hysteria 2 #{instance_id}"))
        ).strip()
        if not name or len(name) > 80:
            raise ValueError(
                f"Hysteria 2 #{instance_id}: имя должно содержать от 1 до 80 символов"
            )
        name_key = name.casefold()
        if name_key in names:
            raise ValueError(
                f"Hysteria 2 #{instance_id}: название уже используется Inbound #{names[name_key]}"
            )
        names[name_key] = instance_id
        tag = HYSTERIA_INBOUND_TAGS[instance_id]
        enabled = True if instance_id == 1 else as_bool(
            item.get("enabled", base.get("enabled", False))
        )
        listen = str(
            primary_listen
            if instance_id == 1
            else item.get("listen", base.get("listen", "0.0.0.0"))
        ).strip()
        default_port = 8443 if instance_id == 2 else 9443
        try:
            port = int(
                primary_port
                if instance_id == 1
                else item.get("port", base.get("port", default_port))
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Hysteria 2 #{instance_id}: UDP-порт должен быть числом"
            ) from exc
        if not 1 <= port <= 65535:
            raise ValueError(
                f"Hysteria 2 #{instance_id}: UDP-порт должен быть от 1 до 65535"
            )
        try:
            parsed_listen = ipaddress.ip_address(listen)
        except ValueError as exc:
            raise ValueError(
                f"Hysteria 2 #{instance_id}: listen должен быть IP-адресом"
            ) from exc
        if enabled and parsed_listen.is_loopback:
            raise ValueError(
                f"Hysteria 2 #{instance_id}: публичный UDP-listener не может быть loopback"
            )
        obfs_mode, obfs_password = _normalise_hysteria_obfs(
            item.get("obfs_mode", base.get("obfs_mode", "none")),
            item.get("obfs_password", base.get("obfs_password")),
        )
        result.append(
            {
                "id": instance_id,
                "name": name,
                "tag": tag,
                "enabled": enabled,
                "listen": listen,
                "port": port,
                "obfs_mode": obfs_mode,
                "obfs_password": obfs_password,
                "obfs_updated_by": str(
                    item.get("obfs_updated_by", base.get("obfs_updated_by", "")) or ""
                )[:80],
            }
        )

    enabled_items = [item for item in result if item["enabled"]]
    ports: dict[int, str] = {}
    for item in enabled_items:
        port = int(item["port"])
        if port in ports:
            raise ValueError(
                f"Конфликт Hysteria 2: UDP-порт {port} уже используется "
                f"экземпляром «{ports[port]}»"
            )
        ports[port] = str(item["name"])
    if len(enabled_items) > 1 and str(hop_ports or "").strip():
        raise ValueError(
            "На первом этапе port hopping можно использовать только с одним Hysteria 2 Inbound. "
            "Отключите дополнительные Inbound или очистите диапазон UDP hopping."
        )
    return result


def update_hysteria_inbounds(
    values: list[dict[str, object]] | None,
    *,
    primary_listen: str,
    primary_port: int,
    hop_ports: str = "",
) -> list[sqlite3.Row]:
    cleaned = _normalise_hysteria_instances(
        values, primary_listen=primary_listen, primary_port=primary_port, hop_ports=hop_ports
    )
    if any(str(item["obfs_mode"]) == "salamander" for item in cleaned):
        _require_hysteria_salamander_support()
    with connect() as con:
        for item in cleaned:
            con.execute(
                """
                INSERT INTO hysteria_inbounds (
                    id, name, tag, enabled, listen, port,
                    obfs_mode, obfs_password, obfs_updated_at, obfs_updated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, tag=excluded.tag, enabled=excluded.enabled,
                    listen=excluded.listen, port=excluded.port,
                    obfs_mode=excluded.obfs_mode,
                    obfs_password=excluded.obfs_password,
                    obfs_updated_at=CASE
                        WHEN hysteria_inbounds.obfs_mode IS NOT excluded.obfs_mode
                          OR COALESCE(hysteria_inbounds.obfs_password,'') IS NOT COALESCE(excluded.obfs_password,'')
                        THEN CURRENT_TIMESTAMP ELSE hysteria_inbounds.obfs_updated_at END,
                    obfs_updated_by=CASE
                        WHEN hysteria_inbounds.obfs_mode IS NOT excluded.obfs_mode
                          OR COALESCE(hysteria_inbounds.obfs_password,'') IS NOT COALESCE(excluded.obfs_password,'')
                        THEN excluded.obfs_updated_by ELSE hysteria_inbounds.obfs_updated_by END,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    int(item["id"]), str(item["name"]), str(item["tag"]),
                    int(bool(item["enabled"])), str(item["listen"]), int(item["port"]),
                    str(item["obfs_mode"]), item["obfs_password"],
                    str(item.get("obfs_updated_by") or "")[:80],
                ),
            )
    return list_hysteria_inbounds()


def update_hysteria_obfuscation(
    inbound_id: int, *, mode: str, password: str | None, actor: str = "admin"
) -> sqlite3.Row:
    """Persist one inbound's obfuscation desired state.

    This function only mutates the active database context.  The web layer
    runs it first against a candidate SQLite copy and only commits the live
    change after a successful full ``xray run -test``.
    """
    inbound_id = int(inbound_id)
    if inbound_id not in HYSTERIA_INBOUND_TAGS:
        raise ValueError("Hysteria 2: Inbound не найден")
    clean_mode, clean_password = _normalise_hysteria_obfs(mode, password)
    if clean_mode == "salamander":
        _require_hysteria_salamander_support()
    with connect() as con:
        current = con.execute(
            "SELECT * FROM hysteria_inbounds WHERE id=?", (inbound_id,)
        ).fetchone()
        if current is None:
            raise ValueError("Hysteria 2: Inbound не найден")
        changed = (
            str(current["obfs_mode"] or "none") != clean_mode
            or str(current["obfs_password"] or "") != str(clean_password or "")
        )
        con.execute(
            """
            UPDATE hysteria_inbounds
            SET obfs_mode=?, obfs_password=?,
                obfs_updated_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE obfs_updated_at END,
                obfs_updated_by=CASE WHEN ? THEN ? ELSE obfs_updated_by END,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (
                clean_mode, clean_password, int(changed), int(changed),
                str(actor or "admin")[:80], inbound_id,
            ),
        )
        row = con.execute(
            "SELECT * FROM hysteria_inbounds WHERE id=?", (inbound_id,)
        ).fetchone()
    if row is None:
        raise XPanelError("Hysteria 2: состояние Inbound не сохранено")
    return row


def _ensure_legacy_hysteria_user_auths() -> dict[int, dict[int, str]]:
    init_db()
    with connect() as con:
        inbounds = con.execute("SELECT id FROM hysteria_inbounds ORDER BY id").fetchall()
        users = con.execute("SELECT id, uuid FROM users ORDER BY id").fetchall()
        for inbound in inbounds:
            inbound_id = int(inbound["id"])
            for user in users:
                user_id = int(user["id"])
                if inbound_id == 1:
                    auth = str(user["uuid"])
                    con.execute(
                        """
                        INSERT INTO hysteria_user_auth (inbound_id, user_id, auth)
                        VALUES (?, ?, ?)
                        ON CONFLICT(inbound_id, user_id) DO UPDATE SET
                            auth=excluded.auth, updated_at=CURRENT_TIMESTAMP
                        """,
                        (inbound_id, user_id, auth),
                    )
                    continue
                exists = con.execute(
                    "SELECT auth FROM hysteria_user_auth WHERE inbound_id=? AND user_id=?",
                    (inbound_id, user_id),
                ).fetchone()
                if exists is not None:
                    continue
                while True:
                    auth = secrets.token_urlsafe(24)
                    try:
                        con.execute(
                            "INSERT INTO hysteria_user_auth (inbound_id, user_id, auth) VALUES (?, ?, ?)",
                            (inbound_id, user_id, auth),
                        )
                        break
                    except sqlite3.IntegrityError:
                        continue
        rows = con.execute(
            "SELECT inbound_id, user_id, auth FROM hysteria_user_auth"
        ).fetchall()
    result: dict[int, dict[int, str]] = {}
    for row in rows:
        result.setdefault(int(row["inbound_id"]), {})[int(row["user_id"])] = str(row["auth"])
    return result


def find_user(identifier: str | int) -> sqlite3.Row:
    init_db()
    with connect() as con:
        if isinstance(identifier, int) or str(identifier).isdigit():
            row = con.execute("SELECT * FROM users WHERE id = ?", (int(identifier),)).fetchone()
        else:
            row = con.execute(
                "SELECT * FROM users WHERE name = ? COLLATE NOCASE", (str(identifier),)
            ).fetchone()
    if row is None:
        raise XPanelError(f"пользователь не найден: {identifier}")
    return row


def _normalise_expiry(value: str | None) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("срок действия должен быть датой и временем") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(second=0, microsecond=0).isoformat()


def user_is_expired(user: sqlite3.Row, now: datetime | None = None) -> bool:
    value = user["expiry_at"]
    if not value:
        return False
    try:
        expiry = datetime.fromisoformat(str(value))
    except ValueError:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return expiry <= current


def list_users() -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute("SELECT * FROM users ORDER BY id").fetchall()




def _expiry_is_past(value: object, now: datetime | None = None) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        expiry = datetime.fromisoformat(text)
    except ValueError:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry <= (now or datetime.now(timezone.utc))


def _device_hysteria_payload(value: object, device_uuid: str) -> dict[str, object]:
    try:
        payload = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    auths = payload.get("hysteria_auths")
    if not isinstance(auths, dict):
        auths = {}
    legacy = str(payload.get("hysteria_auth") or "").strip()
    if "1" not in auths:
        auths["1"] = legacy or device_uuid
    payload["hysteria_auths"] = auths
    payload.pop("hysteria_auth", None)
    return payload


def _ensure_device_credential(con: sqlite3.Connection, device: sqlite3.Row) -> sqlite3.Row:
    row = con.execute(
        "SELECT * FROM device_credentials WHERE device_id=? AND engine='xray'",
        (int(device["id"]),),
    ).fetchone()
    payload = _device_hysteria_payload(
        row["config_json"] if row is not None else "{}", str(device["uuid"])
    )
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if row is None:
        con.execute(
            """
            INSERT INTO device_credentials
                (device_id, engine, status, engine_object_id, config_json)
            VALUES (?, 'xray', 'applied', ?, ?)
            """,
            (int(device["id"]), str(device["uuid"]), encoded),
        )
    elif encoded != str(row["config_json"] or "") or str(row["engine_object_id"] or "") != str(device["uuid"]):
        con.execute(
            """
            UPDATE device_credentials
            SET engine_object_id=?, config_json=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (str(device["uuid"]), encoded, int(row["id"])),
        )
    return con.execute(
        "SELECT * FROM device_credentials WHERE device_id=? AND engine='xray'",
        (int(device["id"]),),
    ).fetchone()


def _ensure_primary_device_for_user(user_id: int) -> dict[str, object]:
    init_db()
    with connect() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (int(user_id),)).fetchone()
        if user is None:
            raise XPanelError(f"пользователь не найден: {user_id}")
        device = con.execute(
            "SELECT * FROM devices WHERE user_id=? AND is_primary=1 ORDER BY id LIMIT 1",
            (int(user_id),),
        ).fetchone()
        token = str(user["subscription_token"] or "") or secrets.token_urlsafe(32)
        if not user["subscription_token"]:
            con.execute("UPDATE users SET subscription_token=? WHERE id=?", (token, int(user_id)))
        if device is None:
            cursor = con.execute(
                """
                INSERT INTO devices (
                    user_id, name, uuid, enabled, comment, expiry_at, is_primary,
                    subscription_enabled, subscription_token,
                    subscription_access_count, subscription_last_access_at
                ) VALUES (?, 'Основной доступ', ?, ?, '', ?, 1, ?, ?, ?, ?)
                """,
                (
                    int(user_id), str(user["uuid"]), int(user["enabled"]), user["expiry_at"],
                    int(user["subscription_enabled"]), token,
                    int(user["subscription_access_count"] or 0),
                    user["subscription_last_access_at"],
                ),
            )
            device = con.execute("SELECT * FROM devices WHERE id=?", (int(cursor.lastrowid),)).fetchone()
        else:
            con.execute(
                """
                UPDATE devices
                SET uuid=?, enabled=?, expiry_at=?, subscription_enabled=?,
                    subscription_token=?, subscription_access_count=?,
                    subscription_last_access_at=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    str(user["uuid"]), int(user["enabled"]), user["expiry_at"],
                    int(user["subscription_enabled"]), token,
                    int(user["subscription_access_count"] or 0),
                    user["subscription_last_access_at"], int(device["id"]),
                ),
            )
            device = con.execute("SELECT * FROM devices WHERE id=?", (int(device["id"]),)).fetchone()
        _ensure_device_credential(con, device)
        return dict(device)


def list_user_devices(user_id: int, *, include_disabled: bool = True) -> list[dict[str, object]]:
    init_db()
    _ensure_primary_device_for_user(int(user_id))
    query = """
        SELECT d.*, u.name AS user_name, u.enabled AS user_enabled,
               u.expiry_at AS user_expiry_at
        FROM devices d JOIN users u ON u.id=d.user_id
        WHERE d.user_id=?
    """
    values: list[object] = [int(user_id)]
    if not include_disabled:
        query += " AND d.enabled=1 AND u.enabled=1"
    query += " ORDER BY d.is_primary DESC, d.id"
    with connect() as con:
        rows = con.execute(query, values).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            credential = _ensure_device_credential(con, row)
            item = dict(row)
            item["credential"] = dict(credential)
            item["effective_enabled"] = bool(row["enabled"] and row["user_enabled"])
            item["expired"] = _expiry_is_past(row["expiry_at"]) or _expiry_is_past(row["user_expiry_at"])
            item["display_name"] = (
                str(row["user_name"]) if bool(row["is_primary"])
                else f"{row['user_name']} · {row['name']}"
            )
            result.append(item)
        return result


def list_devices(*, include_disabled: bool = True) -> list[dict[str, object]]:
    init_db()
    with connect() as con:
        user_ids = [int(row["id"]) for row in con.execute("SELECT id FROM users ORDER BY id").fetchall()]
    result: list[dict[str, object]] = []
    for user_id in user_ids:
        result.extend(list_user_devices(user_id, include_disabled=include_disabled))
    return result


def find_device(user_id: int, device_id: int | None = None) -> dict[str, object]:
    devices = list_user_devices(int(user_id), include_disabled=True)
    if device_id is None:
        for item in devices:
            if bool(item["is_primary"]):
                return item
    else:
        for item in devices:
            if int(item["id"]) == int(device_id):
                return item
    raise XPanelError("доступ/устройство не найдено")


def add_device(
    user_id: int,
    *,
    name: str,
    comment: str = "",
    expiry_at: str | None = None,
    enabled: bool = True,
) -> dict[str, object]:
    find_user(int(user_id))
    device_name = str(name or "").strip()
    device_comment = str(comment or "").strip()
    if not device_name or len(device_name) > 80:
        raise ValueError("имя устройства должно содержать от 1 до 80 символов")
    if len(device_comment) > 500:
        raise ValueError("комментарий слишком длинный")
    expiry = _normalise_expiry(expiry_at)
    for _ in range(12):
        device_uuid = str(uuidlib.uuid4())
        token = secrets.token_urlsafe(32)
        try:
            with connect() as con:
                cursor = con.execute(
                    """
                    INSERT INTO devices (
                        user_id, name, uuid, enabled, comment, expiry_at,
                        is_primary, subscription_enabled, subscription_token
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?)
                    """,
                    (
                        int(user_id), device_name, device_uuid, 1 if enabled else 0,
                        device_comment, expiry, token,
                    ),
                )
                device_id = int(cursor.lastrowid)
                device = con.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
                _ensure_device_credential(con, device)
            _sync_local_device_deployment(device_id)
            return find_device(int(user_id), device_id)
        except sqlite3.IntegrityError:
            continue
    raise XPanelError("не удалось создать уникальные реквизиты устройства")


def update_device(
    user_id: int,
    device_id: int,
    *,
    name: str,
    comment: str = "",
    expiry_at: str | None = None,
) -> dict[str, object]:
    current = find_device(int(user_id), int(device_id))
    device_name = str(name or "").strip()
    device_comment = str(comment or "").strip()
    if not device_name or len(device_name) > 80:
        raise ValueError("имя устройства должно содержать от 1 до 80 символов")
    if bool(current["is_primary"]):
        device_name = "Основной доступ"
    expiry = _normalise_expiry(expiry_at)
    with connect() as con:
        con.execute(
            """
            UPDATE devices SET name=?, comment=?, expiry_at=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND user_id=?
            """,
            (device_name, device_comment, expiry, int(device_id), int(user_id)),
        )
    _sync_local_device_deployment(int(device_id))
    return find_device(int(user_id), int(device_id))


def set_device_enabled(user_id: int, device_id: int, enabled: bool) -> dict[str, object]:
    device = find_device(int(user_id), int(device_id))
    if bool(device["is_primary"]):
        # Primary mirrors the legacy client switch so old API and subscriptions
        # keep exactly the same meaning.
        set_user_enabled(int(user_id), bool(enabled))
        return find_device(int(user_id), int(device_id))
    with connect() as con:
        con.execute(
            "UPDATE devices SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
            (1 if enabled else 0, int(device_id), int(user_id)),
        )
        con.execute(
            """
            UPDATE node_deployments
            SET desired_state=?, subscription_enabled=?,
                state=CASE WHEN node_id IN (SELECT id FROM nodes WHERE is_local=0)
                                AND state='active' THEN 'error' ELSE state END,
                last_message=CASE WHEN node_id IN (SELECT id FROM nodes WHERE is_local=0)
                    THEN 'Состояние устройства изменено на Controller; требуется синхронизация Node'
                    ELSE last_message END,
                updated_at=CURRENT_TIMESTAMP
            WHERE device_id=? AND state!='removed'
            """,
            ("active" if enabled else "standby", 1 if enabled else 0, int(device_id)),
        )
    _sync_local_device_deployment(int(device_id))
    return find_device(int(user_id), int(device_id))


def regenerate_device_uuid(user_id: int, device_id: int) -> dict[str, object]:
    device = find_device(int(user_id), int(device_id))
    if bool(device["is_primary"]):
        regenerate_user_uuid(int(user_id))
        return find_device(int(user_id), int(device_id))
    new_uuid = str(uuidlib.uuid4())
    with connect() as con:
        con.execute(
            "UPDATE devices SET uuid=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
            (new_uuid, int(device_id), int(user_id)),
        )
        credential = con.execute(
            "SELECT * FROM device_credentials WHERE device_id=? AND engine='xray'",
            (int(device_id),),
        ).fetchone()
        payload = _device_hysteria_payload(
            credential["config_json"] if credential is not None else "{}", new_uuid
        )
        auths = payload.get("hysteria_auths") if isinstance(payload.get("hysteria_auths"), dict) else {}
        auths["1"] = new_uuid
        payload["hysteria_auths"] = auths
        con.execute(
            """
            UPDATE device_credentials SET engine_object_id=?, config_json=?, rotated_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP WHERE device_id=? AND engine='xray'
            """,
            (new_uuid, json.dumps(payload, ensure_ascii=False, sort_keys=True), int(device_id)),
        )
        con.execute(
            """
            UPDATE node_deployments SET state='error', subscription_enabled=0,
                last_message='Требуется повторное развёртывание после смены UUID устройства',
                updated_at=CURRENT_TIMESTAMP
            WHERE device_id=? AND node_id IN (SELECT id FROM nodes WHERE is_local=0)
              AND state!='removed'
            """,
            (int(device_id),),
        )
    _sync_local_device_deployment(int(device_id), uuid_changed=True)
    return find_device(int(user_id), int(device_id))


def delete_device(user_id: int, device_id: int) -> dict[str, object]:
    device = find_device(int(user_id), int(device_id))
    if bool(device["is_primary"]):
        raise XPanelError("Основной доступ нельзя удалить отдельно; удалите клиента или отключите доступ")
    with connect() as con:
        active_remote = con.execute(
            """
            SELECT COUNT(*) FROM node_deployments
            WHERE device_id=? AND node_id IN (SELECT id FROM nodes WHERE is_local=0)
              AND state NOT IN ('removed')
            """,
            (int(device_id),),
        ).fetchone()[0]
        if int(active_remote or 0) > 0:
            raise XPanelError("Сначала удалите устройство с SG-Node или выполните синхронизацию ноды")
        con.execute("DELETE FROM node_deployments WHERE device_id=?", (int(device_id),))
        con.execute("DELETE FROM devices WHERE id=? AND user_id=?", (int(device_id), int(user_id)))
    return device


def set_device_subscription_enabled(user_id: int, device_id: int, enabled: bool) -> dict[str, object]:
    device = find_device(int(user_id), int(device_id))
    if bool(device["is_primary"]):
        set_user_subscription_enabled(int(user_id), bool(enabled))
        return find_device(int(user_id), int(device_id))
    with connect() as con:
        con.execute(
            "UPDATE devices SET subscription_enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
            (1 if enabled else 0, int(device_id), int(user_id)),
        )
    return find_device(int(user_id), int(device_id))


def regenerate_device_subscription_token(user_id: int, device_id: int) -> dict[str, object]:
    device = find_device(int(user_id), int(device_id))
    if bool(device["is_primary"]):
        regenerate_subscription_token(int(user_id))
        return find_device(int(user_id), int(device_id))
    token = secrets.token_urlsafe(32)
    with connect() as con:
        con.execute(
            """
            UPDATE devices SET subscription_token=?, subscription_access_count=0,
                subscription_last_access_at=NULL, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND user_id=?
            """,
            (token, int(device_id), int(user_id)),
        )
    return find_device(int(user_id), int(device_id))


def _access_identity(user_id: int, device_id: int | None = None) -> dict[str, object]:
    device = find_device(int(user_id), device_id)
    return {
        "id": int(device["id"]),
        "user_id": int(user_id),
        "device_id": int(device["id"]),
        "name": str(device["display_name"]),
        "user_name": str(device["user_name"]),
        "device_name": str(device["name"]),
        "uuid": str(device["uuid"]),
        "enabled": int(bool(device["effective_enabled"])),
        "expiry_at": device["expiry_at"] or device["user_expiry_at"],
        "subscription_enabled": int(bool(device["subscription_enabled"])),
        "subscription_token": str(device["subscription_token"] or ""),
        "is_primary": int(bool(device["is_primary"])),
    }


def _active_access_identities() -> list[dict[str, object]]:
    return [
        _access_identity(int(item["user_id"]), int(item["id"]))
        for item in list_devices(include_disabled=False)
        if not bool(item["expired"])
    ]


def _ensure_device_hysteria_auths() -> dict[int, dict[int, str]]:
    init_db()
    with connect() as con:
        inbounds = con.execute("SELECT id FROM hysteria_inbounds ORDER BY id").fetchall()
        devices = con.execute("SELECT * FROM devices ORDER BY id").fetchall()
        result: dict[int, dict[int, str]] = {}
        for device in devices:
            credential = _ensure_device_credential(con, device)
            payload = _device_hysteria_payload(credential["config_json"], str(device["uuid"]))
            auths = payload["hysteria_auths"]
            changed = False
            for inbound in inbounds:
                inbound_id = int(inbound["id"])
                key = str(inbound_id)
                if not str(auths.get(key) or "").strip():
                    auths[key] = str(device["uuid"]) if inbound_id == 1 else secrets.token_urlsafe(24)
                    changed = True
                result.setdefault(inbound_id, {})[int(device["id"])] = str(auths[key])
            if changed:
                payload["hysteria_auths"] = auths
                con.execute(
                    "UPDATE device_credentials SET config_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (json.dumps(payload, ensure_ascii=False, sort_keys=True), int(credential["id"])),
                )
        return result

def users_json_document() -> str:
    """Return clients and all independent Access/device identities as editable JSON."""
    users: list[dict[str, object]] = []
    for row in list_users():
        devices = list_user_devices(int(row["id"]))
        users.append({
            "name": str(row["name"]),
            "uuid": str(row["uuid"]),
            "enabled": bool(row["enabled"]),
            "comment": str(row["comment"] or ""),
            "expiryAt": str(row["expiry_at"] or "") or None,
            "subscriptionEnabled": bool(row["subscription_enabled"]),
            "devices": [
                {
                    "name": str(device["name"]),
                    "uuid": str(device["uuid"]),
                    "enabled": bool(device["enabled"]),
                    "comment": str(device["comment"] or ""),
                    "expiryAt": str(device["expiry_at"] or "") or None,
                    "subscriptionEnabled": bool(device["subscription_enabled"]),
                    "primary": bool(device["is_primary"]),
                }
                for device in devices
            ],
        })
    document = {
        "_sgPanel": {
            "format": "users-devices-v2",
            "note": (
                "users описывает людей, devices — их независимые доступы. "
                "Основной доступ имеет тот же UUID, что и поле user.uuid. "
                "Токены подписок и Hysteria auth сохраняются для неизменённых UUID."
            ),
        },
        "users": users,
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"

def _json_bool(value: object, *, field: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} должен быть true или false")
    return value


def _parse_users_json_document(text: str) -> list[dict[str, object]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(document, dict):
        raise ValueError("Users JSON должен быть объектом")
    users = document.get("users")
    if not isinstance(users, list):
        raise ValueError("поле users должно быть массивом")
    if len(users) > 5000:
        raise ValueError("за одну операцию можно сохранить не более 5000 клиентов")

    parsed: list[dict[str, object]] = []
    names: set[str] = set()
    access_uuids: set[str] = set()
    allowed = {
        "name", "uuid", "enabled", "comment", "expiryAt",
        "subscriptionEnabled", "devices",
    }
    device_allowed = {
        "name", "uuid", "enabled", "comment", "expiryAt",
        "subscriptionEnabled", "primary",
    }
    for index, item in enumerate(users, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"users[{index}] должен быть объектом")
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise ValueError(f"users[{index}]: неизвестные поля: {', '.join(unknown)}")
        name = str(item.get("name", "")).strip()
        if not name or len(name) > 80:
            raise ValueError(f"users[{index}].name: требуется от 1 до 80 символов")
        name_key = name.casefold()
        if name_key in names:
            raise ValueError(f"повторяющееся имя клиента: {name}")
        names.add(name_key)
        user_uuid = str(item.get("uuid", "")).strip()
        try:
            uuidlib.UUID(user_uuid)
        except ValueError as exc:
            raise ValueError(f"users[{index}].uuid: некорректный UUID") from exc
        comment = str(item.get("comment", "")).strip()
        if len(comment) > 500:
            raise ValueError(f"users[{index}].comment: не более 500 символов")
        expiry_value = item.get("expiryAt")
        if expiry_value is not None and not isinstance(expiry_value, str):
            raise ValueError(f"users[{index}].expiryAt должен быть строкой или null")

        raw_devices = item.get("devices")
        if raw_devices is None:
            raw_devices = [{
                "name": "Основной доступ", "uuid": user_uuid,
                "enabled": bool(item.get("enabled", True)), "comment": "",
                "expiryAt": expiry_value, "subscriptionEnabled": bool(item.get("subscriptionEnabled", True)),
                "primary": True,
            }]
        if not isinstance(raw_devices, list) or not raw_devices:
            raise ValueError(f"users[{index}].devices должен быть непустым массивом")
        if len(raw_devices) > 100:
            raise ValueError(f"users[{index}]: не более 100 устройств")
        devices: list[dict[str, object]] = []
        device_names: set[str] = set()
        primary_count = 0
        for dindex, raw_device in enumerate(raw_devices, start=1):
            if not isinstance(raw_device, dict):
                raise ValueError(f"users[{index}].devices[{dindex}] должен быть объектом")
            unknown_device = sorted(set(raw_device) - device_allowed)
            if unknown_device:
                raise ValueError(
                    f"users[{index}].devices[{dindex}]: неизвестные поля: {', '.join(unknown_device)}"
                )
            primary = _json_bool(
                raw_device.get("primary"),
                field=f"users[{index}].devices[{dindex}].primary",
                default=False,
            )
            device_name = str(raw_device.get("name", "")).strip()
            if primary:
                primary_count += 1
                device_name = "Основной доступ"
            if not device_name or len(device_name) > 80:
                raise ValueError(f"users[{index}].devices[{dindex}].name: требуется от 1 до 80 символов")
            name_key_device = device_name.casefold()
            if name_key_device in device_names:
                raise ValueError(f"users[{index}]: повторяющееся имя устройства {device_name}")
            device_names.add(name_key_device)
            device_uuid = str(raw_device.get("uuid", "")).strip()
            try:
                uuidlib.UUID(device_uuid)
            except ValueError as exc:
                raise ValueError(f"users[{index}].devices[{dindex}].uuid: некорректный UUID") from exc
            if device_uuid in access_uuids:
                raise ValueError(f"повторяющийся UUID доступа: {device_uuid}")
            access_uuids.add(device_uuid)
            device_comment = str(raw_device.get("comment", "")).strip()
            if len(device_comment) > 500:
                raise ValueError(f"users[{index}].devices[{dindex}].comment: не более 500 символов")
            device_expiry = raw_device.get("expiryAt")
            if device_expiry is not None and not isinstance(device_expiry, str):
                raise ValueError(f"users[{index}].devices[{dindex}].expiryAt должен быть строкой или null")
            devices.append({
                "name": device_name,
                "uuid": device_uuid,
                "enabled": _json_bool(raw_device.get("enabled"), field=f"users[{index}].devices[{dindex}].enabled", default=True),
                "comment": device_comment,
                "expiry_at": _normalise_expiry(str(device_expiry or "")),
                "subscription_enabled": _json_bool(raw_device.get("subscriptionEnabled"), field=f"users[{index}].devices[{dindex}].subscriptionEnabled", default=True),
                "is_primary": primary,
            })
        if primary_count != 1:
            raise ValueError(f"users[{index}].devices: должен быть ровно один основной доступ")
        primary_device = next(device for device in devices if bool(device["is_primary"]))
        if str(primary_device["uuid"]) != user_uuid:
            raise ValueError(f"users[{index}]: UUID основного доступа должен совпадать с user.uuid")
        parsed.append({
            "name": name,
            "uuid": user_uuid,
            "enabled": _json_bool(item.get("enabled"), field=f"users[{index}].enabled", default=True),
            "comment": comment,
            "expiry_at": _normalise_expiry(str(expiry_value or "")),
            "subscription_enabled": _json_bool(item.get("subscriptionEnabled"), field=f"users[{index}].subscriptionEnabled", default=True),
            "devices": devices,
        })
    return parsed

def update_users_json_document(text: str) -> list[sqlite3.Row]:
    """Replace the central client catalogue while preserving stable device secrets."""
    parsed = _parse_users_json_document(text)
    with connect() as con:
        existing = con.execute("SELECT * FROM users ORDER BY id").fetchall()
        existing_devices = con.execute("SELECT * FROM devices ORDER BY id").fetchall()
        credentials = con.execute(
            "SELECT dc.*, d.uuid AS device_uuid FROM device_credentials dc "
            "JOIN devices d ON d.id=dc.device_id ORDER BY dc.id"
        ).fetchall()
        by_uuid = {str(row["uuid"]): row for row in existing}
        by_name = {str(row["name"]).casefold(): row for row in existing}
        device_by_uuid = {str(row["uuid"]): row for row in existing_devices}
        credentials_by_uuid: dict[str, list[sqlite3.Row]] = {}
        for credential in credentials:
            credentials_by_uuid.setdefault(str(credential["device_uuid"]), []).append(credential)
        used_ids: set[int] = set()
        used_device_ids: set[int] = set()
        prepared: list[tuple[dict[str, object], sqlite3.Row | None]] = []
        rename_map: dict[str, str] = {}

        for item in parsed:
            row = by_uuid.get(str(item["uuid"]))
            if row is None or int(row["id"]) in used_ids:
                row = by_name.get(str(item["name"]).casefold())
            if row is not None and int(row["id"]) in used_ids:
                row = None
            if row is not None:
                used_ids.add(int(row["id"]))
                if str(row["name"]) != str(item["name"]):
                    rename_map[str(row["name"])] = str(item["name"])
            prepared.append((item, row))

        deleted_names = {str(row["name"]) for row in existing if int(row["id"]) not in used_ids}
        traffic_totals = [tuple(row) for row in con.execute(
            "SELECT user_id, uplink_total, downlink_total, last_raw_uplink, "
            "last_raw_downlink, session_uplink, session_downlink, uplink_bps, "
            "downlink_bps, online_state, last_seen_at, last_collected_at, reset_at "
            "FROM user_traffic_totals"
        ).fetchall()]
        traffic_daily = [tuple(row) for row in con.execute(
            "SELECT user_id, day, uplink, downlink FROM user_traffic_daily"
        ).fetchall()]

        con.execute("DELETE FROM users")
        for item, row in prepared:
            user_token = str(row["subscription_token"] or "") if row is not None else ""
            user_token = user_token or secrets.token_urlsafe(32)
            if row is None:
                cursor = con.execute(
                    """
                    INSERT INTO users
                        (name, uuid, enabled, comment, expiry_at,
                         subscription_enabled, subscription_token)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["name"], item["uuid"], int(item["enabled"]),
                        item["comment"], item["expiry_at"],
                        int(item["subscription_enabled"]), user_token,
                    ),
                )
                user_id = int(cursor.lastrowid)
                user_access_count = 0
                user_last_access = None
            else:
                user_id = int(row["id"])
                user_access_count = int(row["subscription_access_count"] or 0)
                user_last_access = row["subscription_last_access_at"]
                con.execute(
                    """
                    INSERT INTO users
                        (id, name, uuid, enabled, comment, expiry_at, created_at,
                         updated_at, subscription_enabled, subscription_token,
                         subscription_access_count, subscription_last_access_at,
                         connection_order_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id, item["name"], item["uuid"], int(item["enabled"]),
                        item["comment"], item["expiry_at"], row["created_at"],
                        int(item["subscription_enabled"]), user_token,
                        user_access_count, user_last_access,
                        str(row["connection_order_mode"] or "auto"),
                    ),
                )

            for device in item["devices"]:
                previous = device_by_uuid.get(str(device["uuid"]))
                preserve_id = (
                    int(previous["id"])
                    if previous is not None and int(previous["id"]) not in used_device_ids
                    else None
                )
                if preserve_id is not None:
                    used_device_ids.add(preserve_id)
                primary = bool(device["is_primary"])
                token = user_token if primary else (
                    str(previous["subscription_token"] or "") if previous is not None else ""
                )
                token = token or secrets.token_urlsafe(32)
                access_count = user_access_count if primary else int(previous["subscription_access_count"] or 0) if previous is not None else 0
                last_access = user_last_access if primary else previous["subscription_last_access_at"] if previous is not None else None
                values = (
                    user_id, "Основной доступ" if primary else device["name"],
                    device["uuid"], int(device["enabled"]), device["comment"],
                    device["expiry_at"], 1 if primary else 0,
                    int(device["subscription_enabled"]), token,
                    access_count, last_access,
                )
                if preserve_id is None:
                    cursor = con.execute(
                        """
                        INSERT INTO devices
                            (user_id, name, uuid, enabled, comment, expiry_at, is_primary,
                             subscription_enabled, subscription_token,
                             subscription_access_count, subscription_last_access_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        values,
                    )
                    device_id = int(cursor.lastrowid)
                else:
                    created_at = previous["created_at"]
                    con.execute(
                        """
                        INSERT INTO devices
                            (id, user_id, name, uuid, enabled, comment, expiry_at, is_primary,
                             subscription_enabled, subscription_token,
                             subscription_access_count, subscription_last_access_at,
                             created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (preserve_id, *values, created_at),
                    )
                    device_id = preserve_id
                old_credentials = credentials_by_uuid.get(str(device["uuid"]), [])
                if old_credentials:
                    for credential in old_credentials:
                        con.execute(
                            """
                            INSERT INTO device_credentials
                                (device_id, engine, status, engine_object_id, config_json,
                                 rotated_at, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            """,
                            (
                                device_id, credential["engine"], credential["status"],
                                credential["engine_object_id"], credential["config_json"],
                                credential["rotated_at"], credential["created_at"],
                            ),
                        )
                else:
                    payload = _device_hysteria_payload("{}", str(device["uuid"]))
                    con.execute(
                        """
                        INSERT INTO device_credentials
                            (device_id, engine, status, engine_object_id, config_json)
                        VALUES (?, 'xray', 'applied', ?, ?)
                        """,
                        (device_id, str(device["uuid"]), json.dumps(payload, ensure_ascii=False, sort_keys=True)),
                    )

        current_ids = {int(row["id"]) for row in con.execute("SELECT id FROM users").fetchall()}
        for values in traffic_totals:
            if int(values[0]) in current_ids:
                con.execute(
                    """
                    INSERT OR REPLACE INTO user_traffic_totals (
                        user_id, uplink_total, downlink_total, last_raw_uplink,
                        last_raw_downlink, session_uplink, session_downlink,
                        uplink_bps, downlink_bps, online_state, last_seen_at,
                        last_collected_at, reset_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
        for values in traffic_daily:
            if int(values[0]) in current_ids:
                con.execute(
                    "INSERT OR REPLACE INTO user_traffic_daily (user_id, day, uplink, downlink) VALUES (?, ?, ?, ?)",
                    values,
                )

        if rename_map or deleted_names:
            rules = con.execute("SELECT id, enabled, users FROM routing_rules WHERE users != ''").fetchall()
            for rule in rules:
                original = split_values(rule["users"])
                changed: list[str] = []
                for value in original:
                    if value in deleted_names:
                        continue
                    replacement = rename_map.get(value, value)
                    if replacement not in changed:
                        changed.append(replacement)
                enabled = int(rule["enabled"])
                if original and not changed:
                    enabled = 0
                con.execute(
                    "UPDATE routing_rules SET users=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    ("\n".join(changed), enabled, int(rule["id"])),
                )

        # Restore remote deployment ownership after ON DELETE SET NULL fired.
        con.execute(
            """
            UPDATE node_deployments
            SET device_id=(SELECT d.id FROM devices d WHERE d.uuid=node_deployments.user_uuid LIMIT 1),
                device_uuid=user_uuid,
                device_name=COALESCE((SELECT d.name FROM devices d WHERE d.uuid=node_deployments.user_uuid LIMIT 1), device_name),
                user_id=(SELECT d.user_id FROM devices d WHERE d.uuid=node_deployments.user_uuid LIMIT 1),
                user_name=COALESCE((SELECT u.name FROM devices d JOIN users u ON u.id=d.user_id WHERE d.uuid=node_deployments.user_uuid LIMIT 1), user_name)
            WHERE user_uuid!=''
            """
        )
    for current in list_users():
        _sync_local_user_deployment(int(current["id"]))
    return list_users()

def _sync_local_device_deployment(device_id: int, *, uuid_changed: bool = False) -> None:
    """Mirror one Access/device on the local Controller deployment row."""
    with connect() as con:
        row = con.execute(
            """
            SELECT d.*, u.name AS user_name, u.enabled AS user_enabled
            FROM devices d JOIN users u ON u.id=d.user_id
            WHERE d.id=?
            """,
            (int(device_id),),
        ).fetchone()
        if row is None:
            return
        node = con.execute("SELECT id FROM nodes WHERE is_local=1 LIMIT 1").fetchone()
        server = con.execute(
            "SELECT inbound_profile, address, port FROM server_settings WHERE id=1"
        ).fetchone()
        if node is None:
            return
        node_id = int(node["id"])
        profile = str(server["inbound_profile"] or "raw_reality") if server else "raw_reality"
        address = str(server["address"] or "") if server else ""
        port = int(server["port"] or 443) if server else 443
        effective_enabled = bool(row["enabled"] and row["user_enabled"])
        con.execute(
            """
            UPDATE node_deployments
            SET user_name=?, device_name=?, device_uuid=?, updated_at=CURRENT_TIMESTAMP
            WHERE device_id=?
            """,
            (str(row["user_name"]), str(row["name"]), str(row["uuid"]), int(device_id)),
        )
        if uuid_changed:
            con.execute(
                """
                UPDATE node_deployments
                SET state='error', subscription_enabled=0,
                    last_message='Требуется повторное развёртывание после смены UUID устройства',
                    updated_at=CURRENT_TIMESTAMP
                WHERE device_id=? AND node_id!=? AND state!='removed'
                """,
                (int(device_id), node_id),
            )
        con.execute(
            """
            DELETE FROM node_deployments
            WHERE node_id=? AND device_id=? AND user_uuid!=?
            """,
            (node_id, int(device_id), str(row["uuid"])),
        )
        con.execute(
            """
            INSERT INTO node_deployments (
                node_id, user_id, device_id, user_uuid, device_uuid,
                user_name, device_name, profile, public_host, public_port,
                client_link, state, last_message, slot, priority,
                subscription_enabled, desired_state, last_verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 'active',
                      'Локальное развёртывание Controller', 'primary', 10, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(node_id, user_uuid) DO UPDATE SET
                user_id=excluded.user_id, device_id=excluded.device_id,
                device_uuid=excluded.device_uuid, user_name=excluded.user_name,
                device_name=excluded.device_name, profile=excluded.profile,
                public_host=excluded.public_host, public_port=excluded.public_port,
                state='active', desired_state=excluded.desired_state,
                subscription_enabled=excluded.subscription_enabled,
                last_message='Локальное развёртывание Controller',
                last_verified_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
            """,
            (
                node_id, int(row["user_id"]), int(device_id), str(row["uuid"]),
                str(row["uuid"]), str(row["user_name"]), str(row["name"]),
                profile, address, port, 1 if effective_enabled else 0,
                "active" if effective_enabled else "standby",
            ),
        )
        con.execute(
            """
            UPDATE node_deployments
            SET slot=CASE WHEN EXISTS (
                    SELECT 1 FROM node_deployments remote
                    JOIN nodes remote_node ON remote_node.id=remote.node_id
                    WHERE remote.device_id=? AND remote_node.is_local=0
                      AND remote.slot='primary' AND remote.state='active'
                      AND remote.desired_state='active'
                ) THEN 'backup' ELSE 'primary' END,
                priority=CASE WHEN EXISTS (
                    SELECT 1 FROM node_deployments remote
                    JOIN nodes remote_node ON remote_node.id=remote.node_id
                    WHERE remote.device_id=? AND remote_node.is_local=0
                      AND remote.slot='primary' AND remote.state='active'
                      AND remote.desired_state='active'
                ) THEN 20 ELSE 10 END,
                updated_at=CURRENT_TIMESTAMP
            WHERE node_id=? AND device_id=? AND user_uuid=?
            """,
            (int(device_id), int(device_id), node_id, int(device_id), str(row["uuid"])),
        )


def _sync_local_user_deployment(user_id: int, *, uuid_changed: bool = False) -> None:
    """Synchronise all devices of one central Client."""
    primary = _ensure_primary_device_for_user(int(user_id))
    with connect() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (int(user_id),)).fetchone()
        if user is None:
            return
        # The compatibility primary mirrors all legacy identity fields.
        con.execute(
            """
            UPDATE devices
            SET uuid=?, enabled=?, expiry_at=?, subscription_enabled=?,
                subscription_token=?, subscription_access_count=?,
                subscription_last_access_at=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (
                str(user["uuid"]), int(user["enabled"]), user["expiry_at"],
                int(user["subscription_enabled"]), str(user["subscription_token"] or ""),
                int(user["subscription_access_count"] or 0),
                user["subscription_last_access_at"], int(primary["id"]),
            ),
        )
        device_ids = [
            int(row["id"])
            for row in con.execute("SELECT id FROM devices WHERE user_id=? ORDER BY id", (int(user_id),)).fetchall()
        ]
        con.execute(
            "UPDATE node_deployments SET user_name=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?",
            (str(user["name"]), int(user_id)),
        )
    for device_id in device_ids:
        _sync_local_device_deployment(
            device_id,
            uuid_changed=uuid_changed and device_id == int(primary["id"]),
        )


def add_user(
    name: str,
    user_uuid: str | None = None,
    enabled: bool = True,
    comment: str = "",
    expiry_at: str | None = None,
) -> sqlite3.Row:
    name = name.strip()
    comment = comment.strip()
    if not name:
        raise ValueError("имя пользователя не может быть пустым")
    if len(name) > 80:
        raise ValueError("имя пользователя слишком длинное")
    if len(comment) > 500:
        raise ValueError("комментарий слишком длинный")
    value = (user_uuid or str(uuidlib.uuid4())).strip()
    try:
        uuidlib.UUID(value)
    except ValueError as exc:
        raise ValueError("некорректный UUID") from exc
    expiry = _normalise_expiry(expiry_at)
    try:
        with connect() as con:
            cur = con.execute(
                """
                INSERT INTO users (
                    name, uuid, enabled, comment, expiry_at, subscription_token
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    name, value, 1 if enabled else 0, comment, expiry,
                    secrets.token_urlsafe(32),
                ),
            )
            user_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("пользователь с таким именем или UUID уже существует") from exc
    _sync_local_user_deployment(user_id)
    return find_user(user_id)


def update_user(
    identifier: str | int,
    *,
    name: str,
    user_uuid: str,
    comment: str = "",
    expiry_at: str | None = None,
) -> sqlite3.Row:
    user = find_user(identifier)
    name = name.strip()
    comment = comment.strip()
    if not name or len(name) > 80:
        raise ValueError("имя пользователя должно содержать от 1 до 80 символов")
    if len(comment) > 500:
        raise ValueError("комментарий слишком длинный")
    try:
        uuidlib.UUID(user_uuid.strip())
    except ValueError as exc:
        raise ValueError("некорректный UUID") from exc
    expiry = _normalise_expiry(expiry_at)
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE users SET name = ?, uuid = ?, comment = ?, expiry_at = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (name, user_uuid.strip(), comment, expiry, user["id"]),
            )
            if name != user["name"]:
                rows = con.execute("SELECT id, users FROM routing_rules WHERE users != ''").fetchall()
                for row in rows:
                    values = split_values(row["users"])
                    changed = [name if value == user["name"] else value for value in values]
                    if changed != values:
                        con.execute(
                            "UPDATE routing_rules SET users = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                            ("\n".join(changed), row["id"]),
                        )
    except sqlite3.IntegrityError as exc:
        raise XPanelError("пользователь с таким именем или UUID уже существует") from exc
    _sync_local_user_deployment(int(user["id"]), uuid_changed=(str(user["uuid"]) != user_uuid.strip()))
    return find_user(user["id"])


def update_user_connection_order_mode(
    identifier: str | int, mode: object
) -> sqlite3.Row:
    """Select automatic or manual endpoint ordering for one client only."""
    user = find_user(identifier)
    value = str(mode or "auto").strip().lower()
    if value not in {"auto", "manual"}:
        raise ValueError("Выберите автоматический или ручной порядок подключений")
    with connect() as con:
        con.execute(
            """
            UPDATE users
            SET connection_order_mode=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (value, int(user["id"])),
        )
    return find_user(int(user["id"]))


def regenerate_user_uuid(
    identifier: str | int, new_uuid: str | None = None
) -> sqlite3.Row:
    user = find_user(identifier)
    value = str(new_uuid or uuidlib.uuid4()).strip()
    try:
        uuidlib.UUID(value)
    except ValueError as exc:
        raise ValueError("некорректный UUID") from exc
    with connect() as con:
        con.execute(
            "UPDATE users SET uuid = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (value, user["id"]),
        )
    _sync_local_user_deployment(int(user["id"]), uuid_changed=True)
    return find_user(user["id"])


def set_user_enabled(identifier: str | int, enabled: bool) -> sqlite3.Row:
    user = find_user(identifier)
    with connect() as con:
        con.execute(
            "UPDATE users SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if enabled else 0, user["id"]),
        )
        if enabled:
            # Re-enable the central client immediately on the local Controller,
            # but never claim that a remote raw credential was restored.  A
            # Node which was disabled is intentionally left in error/standby
            # until an explicit Agent redeployment confirms the new state.
            con.execute(
                """
                UPDATE node_deployments
                SET desired_state='active', updated_at=CURRENT_TIMESTAMP
                WHERE user_id=?
                  AND node_id IN (SELECT id FROM nodes WHERE is_local=1)
                  AND state!='removed'
                """,
                (int(user["id"]),),
            )
            con.execute(
                """
                UPDATE node_deployments
                SET desired_state='standby', subscription_enabled=0,
                    last_message=CASE
                        WHEN state='error' THEN
                            'Клиент снова включён на Controller; требуется повторное развёртывание на Node'
                        ELSE last_message END,
                    updated_at=CURRENT_TIMESTAMP
                WHERE user_id=?
                  AND node_id IN (SELECT id FROM nodes WHERE is_local=0)
                  AND state!='removed'
                """,
                (int(user["id"]),),
            )
        else:
            con.execute(
                """
                UPDATE node_deployments
                SET desired_state='standby',
                    state=CASE
                        WHEN node_id IN (SELECT id FROM nodes WHERE is_local=0)
                             AND state='active' THEN 'error'
                        ELSE state END,
                    subscription_enabled=CASE
                        WHEN node_id IN (SELECT id FROM nodes WHERE is_local=0) THEN 0
                        ELSE subscription_enabled END,
                    last_message=CASE
                        WHEN node_id IN (SELECT id FROM nodes WHERE is_local=0)
                        THEN 'Клиент отключён на Controller; удалённый raw-профиль требует синхронизации Node'
                        ELSE last_message END,
                    updated_at=CURRENT_TIMESTAMP
                WHERE user_id=? AND state!='removed'
                """,
                (int(user["id"]),),
            )
    _sync_local_user_deployment(int(user["id"]))
    return find_user(user["id"])


def delete_user(identifier: str | int) -> sqlite3.Row:
    user = find_user(identifier)
    with connect() as con:
        # Remove the local Controller mirror. Remote rows are retained as
        # deployment history (their user_id becomes NULL via the FK) after the
        # Agent has confirmed removal.
        con.execute(
            "DELETE FROM node_deployments WHERE user_id=? AND node_id IN (SELECT id FROM nodes WHERE is_local=1)",
            (user["id"],),
        )
        con.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    return user


def get_subscription_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute(
            "SELECT * FROM subscription_settings WHERE id = 1"
        ).fetchone()
    if row is None:
        raise XPanelError("настройки подписок не инициализированы")
    return row


def _normalise_subscription_base_url(value: str | None) -> str:
    value = (value or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("публичный URL должен начинаться с http:// или https://")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("публичный URL не должен содержать логин, query или fragment")
    return value


def update_subscription_settings(
    *, enabled: bool, base_url: str = "", profile_title: str = "SG-Panel"
) -> sqlite3.Row:
    init_db()
    base_url = _normalise_subscription_base_url(base_url)
    profile_title = profile_title.strip()
    if not profile_title or len(profile_title) > 80:
        raise ValueError("название профиля должно содержать от 1 до 80 символов")
    with connect() as con:
        con.execute(
            """
            UPDATE subscription_settings
            SET enabled = ?, base_url = ?, profile_title = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
            """,
            (1 if enabled else 0, base_url, profile_title),
        )
    return get_subscription_settings()


def find_subscription_access(token: str) -> tuple[sqlite3.Row, dict[str, object]]:
    init_db()
    value = str(token or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", value):
        raise XPanelError("подписка не найдена")
    with connect() as con:
        row = con.execute(
            """
            SELECT d.*, u.name AS user_name, u.enabled AS user_enabled,
                   u.expiry_at AS user_expiry_at
            FROM devices d JOIN users u ON u.id=d.user_id
            WHERE d.subscription_token=?
            LIMIT 1
            """,
            (value,),
        ).fetchone()
        if row is None:
            # Compatibility with a database that has not completed the device
            # migration yet. init_db normally makes this path unnecessary.
            user = con.execute(
                "SELECT * FROM users WHERE subscription_token=?", (value,)
            ).fetchone()
            if user is None:
                raise XPanelError("подписка не найдена")
            device_id = int(_ensure_primary_device_for_user(int(user["id"]))["id"])
            row = con.execute(
                """
                SELECT d.*, u.name AS user_name, u.enabled AS user_enabled,
                       u.expiry_at AS user_expiry_at
                FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?
                """,
                (device_id,),
            ).fetchone()
        user = con.execute("SELECT * FROM users WHERE id=?", (int(row["user_id"]),)).fetchone()
    item = dict(row)
    item["effective_enabled"] = bool(row["enabled"] and row["user_enabled"])
    item["expired"] = _expiry_is_past(row["expiry_at"]) or _expiry_is_past(row["user_expiry_at"])
    item["display_name"] = (
        str(row["user_name"]) if bool(row["is_primary"])
        else f"{row['user_name']} · {row['name']}"
    )
    return user, item


def find_subscription_user(token: str) -> sqlite3.Row:
    user, _device = find_subscription_access(token)
    return user


def set_user_subscription_enabled(
    identifier: str | int, enabled: bool
) -> sqlite3.Row:
    user = find_user(identifier)
    with connect() as con:
        con.execute(
            """
            UPDATE users SET subscription_enabled = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (1 if enabled else 0, user["id"]),
        )
    _sync_local_user_deployment(int(user["id"]))
    return find_user(user["id"])


def regenerate_subscription_token(identifier: str | int) -> sqlite3.Row:
    user = find_user(identifier)
    for _attempt in range(12):
        token = secrets.token_urlsafe(32)
        try:
            with connect() as con:
                con.execute(
                    """
                    UPDATE users
                    SET subscription_token = ?, subscription_access_count = 0,
                        subscription_last_access_at = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (token, user["id"]),
                )
            _sync_local_user_deployment(int(user["id"]))
            return find_user(user["id"])
        except sqlite3.IntegrityError:
            continue
    raise XPanelError("не удалось создать уникальный token подписки")


def record_subscription_access(
    identifier: str | int, *, device_id: int | None = None
) -> None:
    user = find_user(identifier)
    device = find_device(int(user["id"]), device_id)
    with connect() as con:
        con.execute(
            """
            UPDATE devices
            SET subscription_access_count=subscription_access_count+1,
                subscription_last_access_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (int(device["id"]),),
        )
        if bool(device["is_primary"]):
            con.execute(
                """
                UPDATE users
                SET subscription_access_count=subscription_access_count+1,
                    subscription_last_access_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (int(user["id"]),),
            )


def make_subscription_url(
    identifier: str | int, fallback_base_url: str = "", *, device_id: int | None = None
) -> str:
    user = find_user(identifier)
    device = find_device(int(user["id"]), device_id)
    settings = get_subscription_settings()
    base_url = str(settings["base_url"] or "").strip()
    if not base_url:
        base_url = _normalise_subscription_base_url(fallback_base_url)
    if not base_url:
        raise XPanelError("задайте публичный URL подписок или откройте страницу через GUI")
    return f"{base_url.rstrip('/')}/sub/{device['subscription_token']}"


def subscription_is_available(
    user: sqlite3.Row, device: dict[str, object] | None = None
) -> bool:
    settings = get_subscription_settings()
    if device is None:
        device = find_device(int(user["id"]), None)
    return bool(
        settings["enabled"]
        and user["enabled"]
        and device["enabled"]
        and device["subscription_enabled"]
        and not user_is_expired(user)
        and not _expiry_is_past(device.get("expiry_at"))
    )


def expire_users(*, apply: bool = False) -> list[sqlite3.Row]:
    expired = [row for row in list_users() if row["enabled"] and user_is_expired(row)]
    if not expired:
        return []
    with connect() as con:
        con.executemany(
            "UPDATE users SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [(row["id"],) for row in expired],
        )
    if apply:
        apply_config()
    return expired


def split_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in re.split(r"[\n,]+", value) if part.strip()]


def normalise_values(value: str | None) -> str:
    return "\n".join(split_values(value))


def validate_ports(value: str) -> str:
    compact = re.sub(r"\s+", "", value or "")
    if not compact:
        return ""
    for item in compact.split(","):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
        if not match:
            raise ValueError("порты: используйте 443 или диапазон 1000-2000 через запятую")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not (1 <= start <= end <= 65535):
            raise ValueError("порты должны находиться в диапазоне 1-65535")
    return compact


def validate_domains(value: str | None) -> str:
    result = split_values(value)
    allowed_prefixes = (
        "domain:", "full:", "keyword:", "regexp:", "geosite:",
        "!geosite:", "ext:",
    )
    for item in result:
        if any(ch.isspace() for ch in item):
            raise ValueError(f"доменное условие не должно содержать пробелы: {item}")
        if item.startswith(("geoip:", "!geoip:")):
            raise ValueError(
                f"условие {item} относится к GeoIP. Перенесите его в поле «IP / GeoIP / CIDR»"
            )
        if item.startswith(allowed_prefixes):
            continue
        if len(item) > 512:
            raise ValueError("доменное условие слишком длинное")
    return "\n".join(result)


def validate_ips(value: str | None) -> str:
    result = split_values(value)
    for item in result:
        if item.startswith(("geosite:", "!geosite:")):
            raise ValueError(
                f"условие {item} относится к Geosite. Перенесите его в поле «Домены / Geosite»"
            )
        if item.startswith(("geoip:", "!geoip:", "ext:")):
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"некорректный IP/CIDR: {item}") from exc
    return "\n".join(result)


def validate_protocols(value: str | None) -> str:
    protocols = [item.lower() for item in split_values(value)]
    unknown = sorted(set(protocols) - ALLOWED_PROTOCOLS)
    if unknown:
        raise ValueError("неподдерживаемые протоколы: " + ", ".join(unknown))
    return "\n".join(protocols)


def validate_rule_values(
    *,
    name: str,
    priority: int,
    outbound_tag: str,
    target_type: str = "outbound",
    domains: str = "",
    ips: str = "",
    ports: str = "",
    network: str = "",
    protocols: str = "",
    inbound_tags: str = "",
    users: str = "",
) -> dict[str, object]:
    name = name.strip()
    if not name:
        raise ValueError("название правила не может быть пустым")
    if len(name) > 100:
        raise ValueError("название правила слишком длинное")
    priority = int(priority)
    if not 1 <= priority <= 9999:
        raise ValueError("приоритет должен быть от 1 до 9999")
    target_type = (target_type or "outbound").strip().lower()
    if target_type not in ALLOWED_RULE_TARGETS:
        raise ValueError("цель правила должна быть outbound или balancer")
    if target_type == "outbound":
        enabled_tags = set(list_outbound_tags(enabled_only=True))
        if outbound_tag not in enabled_tags:
            raise ValueError("выбранный outbound не существует или отключён")
    else:
        if outbound_tag not in set(list_balancer_tags()):
            raise ValueError("выбранный balancer не существует")
    network = (network or "").strip().lower()
    if network not in ALLOWED_NETWORKS:
        raise ValueError("network должен быть tcp, udp, tcp,udp или пустым")
    cleaned = {
        "name": name,
        "priority": priority,
        "outbound_tag": outbound_tag,
        "target_type": target_type,
        "domains": validate_domains(domains),
        "ips": validate_ips(ips),
        "ports": validate_ports(ports),
        "network": network,
        "protocols": validate_protocols(protocols),
        "inbound_tags": normalise_values(inbound_tags),
        "users": normalise_values(users),
    }
    if not any(
        cleaned[key]
        for key in ("domains", "ips", "ports", "network", "protocols", "inbound_tags", "users")
    ):
        raise ValueError("задайте хотя бы одно условие правила")
    return cleaned



def get_dns_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        return con.execute("SELECT * FROM dns_settings WHERE id = 1").fetchone()


def update_dns_settings(
    *, enabled: bool, query_strategy: str, disable_cache: bool,
    disable_fallback: bool, disable_fallback_if_match: bool,
    enable_parallel_query: bool, use_system_hosts: bool,
) -> sqlite3.Row:
    if query_strategy not in ALLOWED_DNS_QUERY_STRATEGIES:
        raise ValueError("некорректная DNS queryStrategy")
    with connect() as con:
        con.execute(
            """
            UPDATE dns_settings SET
                enabled = ?, query_strategy = ?, disable_cache = ?,
                disable_fallback = ?, disable_fallback_if_match = ?,
                enable_parallel_query = ?, use_system_hosts = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
            """,
            (int(enabled), query_strategy, int(disable_cache), int(disable_fallback),
             int(disable_fallback_if_match), int(enable_parallel_query), int(use_system_hosts)),
        )
    return get_dns_settings()


def _validate_dns_address(address: str) -> str:
    value = (address or "").strip()
    if not value:
        raise ValueError("адрес DNS-сервера не может быть пустым")
    if value.lower() == "fakedns":
        raise ValueError("FakeDNS пока не поддерживается в SG-Panel")
    if value == "localhost":
        return value
    allowed_schemes = {"tcp", "tcp+local", "https", "https+local", "quic+local"}
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in allowed_schemes or not parsed.hostname:
            raise ValueError("неподдерживаемый формат DNS-сервера")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("некорректный порт DNS-сервера") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("порт DNS-сервера должен быть от 1 до 65535")
        if parsed.scheme.startswith("https") and not parsed.path:
            raise ValueError("для DoH укажите путь, например /dns-query")
        return value
    host = value
    port = None
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)\](?::(\d+))?", value)
        if not match:
            raise ValueError("некорректный IPv6 DNS-адрес")
        host, port_text = match.group(1), match.group(2)
        port = int(port_text) if port_text else None
    elif value.count(":") == 1:
        maybe_host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("обычный UDP DNS задаётся IP-адресом; для домена используйте DoH URL") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("порт DNS-сервера должен быть от 1 до 65535")
    return value


def validate_dns_server_values(
    *, name: str, address: str, priority: int = 100, domains: str = "",
    expected_ips: str = "", unexpected_ips: str = "", query_strategy: str = "",
    skip_fallback: bool = False, final_query: bool = False, timeout_ms: int = 4000,
) -> dict[str, object]:
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("название DNS-сервера не может быть пустым")
    if len(clean_name) > 100:
        raise ValueError("название DNS-сервера слишком длинное")
    priority = int(priority)
    if not 1 <= priority <= 9999:
        raise ValueError("приоритет DNS-сервера должен быть от 1 до 9999")
    query_strategy = (query_strategy or "").strip()
    if query_strategy not in ALLOWED_DNS_SERVER_QUERY_STRATEGIES:
        raise ValueError("некорректная queryStrategy DNS-сервера")
    timeout_ms = int(timeout_ms)
    if not 100 <= timeout_ms <= 60000:
        raise ValueError("DNS timeout должен быть от 100 до 60000 мс")
    return {
        "name": clean_name, "address": _validate_dns_address(address), "priority": priority,
        "domains": normalise_values(domains), "expected_ips": validate_ips(expected_ips),
        "unexpected_ips": validate_ips(unexpected_ips), "query_strategy": query_strategy,
        "skip_fallback": int(skip_fallback), "final_query": int(final_query),
        "timeout_ms": timeout_ms,
    }


def list_dns_servers(*, enabled_only: bool = False) -> list[sqlite3.Row]:
    init_db()
    query = "SELECT * FROM dns_servers" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY priority, id"
    with connect() as con:
        return con.execute(query).fetchall()


def find_dns_server(server_id: int) -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM dns_servers WHERE id = ?", (server_id,)).fetchone()
    if row is None:
        raise XPanelError(f"DNS-сервер не найден: {server_id}")
    return row


def add_dns_server(**values) -> sqlite3.Row:
    cleaned = validate_dns_server_values(**values)
    try:
        with connect() as con:
            cur = con.execute(
                """INSERT INTO dns_servers
                (name,address,priority,enabled,domains,expected_ips,unexpected_ips,query_strategy,skip_fallback,final_query,timeout_ms)
                VALUES (?,?,?,1,?,?,?,?,?,?,?)""",
                (cleaned["name"], cleaned["address"], cleaned["priority"], cleaned["domains"],
                 cleaned["expected_ips"], cleaned["unexpected_ips"], cleaned["query_strategy"],
                 cleaned["skip_fallback"], cleaned["final_query"], cleaned["timeout_ms"]),
            )
            server_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("DNS-сервер с таким названием уже существует") from exc
    return find_dns_server(server_id)


def update_dns_server(server_id: int, **values) -> sqlite3.Row:
    find_dns_server(server_id)
    cleaned = validate_dns_server_values(**values)
    try:
        with connect() as con:
            con.execute(
                """UPDATE dns_servers SET name=?,address=?,priority=?,domains=?,expected_ips=?,unexpected_ips=?,
                query_strategy=?,skip_fallback=?,final_query=?,timeout_ms=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (cleaned["name"], cleaned["address"], cleaned["priority"], cleaned["domains"],
                 cleaned["expected_ips"], cleaned["unexpected_ips"], cleaned["query_strategy"],
                 cleaned["skip_fallback"], cleaned["final_query"], cleaned["timeout_ms"], server_id),
            )
    except sqlite3.IntegrityError as exc:
        raise XPanelError("DNS-сервер с таким названием уже существует") from exc
    return find_dns_server(server_id)


def set_dns_server_enabled(server_id: int, enabled: bool) -> sqlite3.Row:
    find_dns_server(server_id)
    with connect() as con:
        con.execute("UPDATE dns_servers SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (int(enabled), server_id))
    return find_dns_server(server_id)


def delete_dns_server(server_id: int) -> sqlite3.Row:
    row = find_dns_server(server_id)
    with connect() as con:
        con.execute("DELETE FROM dns_servers WHERE id=?", (server_id,))
    return row


def list_dns_hosts(*, enabled_only: bool = False) -> list[sqlite3.Row]:
    init_db()
    query = "SELECT * FROM dns_hosts" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY domain COLLATE NOCASE"
    with connect() as con:
        return con.execute(query).fetchall()


def find_dns_host(host_id: int) -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM dns_hosts WHERE id=?", (host_id,)).fetchone()
    if row is None:
        raise XPanelError(f"DNS hosts-запись не найдена: {host_id}")
    return row


def _validate_dns_host(domain: str, addresses: str) -> tuple[str, str]:
    clean_domain = (domain or "").strip()
    if not clean_domain or any(ch.isspace() for ch in clean_domain):
        raise ValueError("укажите домен без пробелов")
    values = split_values(addresses)
    if not values:
        raise ValueError("укажите хотя бы один IP или домен назначения")
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if any(ch.isspace() for ch in value) or "." not in value:
                raise ValueError(f"некорректное значение hosts: {value}")
    return clean_domain, "\n".join(values)


def add_dns_host(*, domain: str, addresses: str) -> sqlite3.Row:
    clean_domain, clean_addresses = _validate_dns_host(domain, addresses)
    try:
        with connect() as con:
            cur = con.execute("INSERT INTO dns_hosts (domain,addresses,enabled) VALUES (?,?,1)", (clean_domain, clean_addresses))
            host_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("такая DNS hosts-запись уже существует") from exc
    return find_dns_host(host_id)


def update_dns_host(host_id: int, *, domain: str, addresses: str) -> sqlite3.Row:
    find_dns_host(host_id)
    clean_domain, clean_addresses = _validate_dns_host(domain, addresses)
    try:
        with connect() as con:
            con.execute("UPDATE dns_hosts SET domain=?,addresses=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (clean_domain, clean_addresses, host_id))
    except sqlite3.IntegrityError as exc:
        raise XPanelError("такая DNS hosts-запись уже существует") from exc
    return find_dns_host(host_id)


def set_dns_host_enabled(host_id: int, enabled: bool) -> sqlite3.Row:
    find_dns_host(host_id)
    with connect() as con:
        con.execute("UPDATE dns_hosts SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (int(enabled), host_id))
    return find_dns_host(host_id)


def delete_dns_host(host_id: int) -> sqlite3.Row:
    row = find_dns_host(host_id)
    with connect() as con:
        con.execute("DELETE FROM dns_hosts WHERE id=?", (host_id,))
    return row


def build_dns_server_json(row: sqlite3.Row) -> dict[str, object]:
    item = _json_object(row["config_json"] if "config_json" in row.keys() else "{}")
    item.pop("_sgPanel", None)
    item["address"] = row["address"]
    for key, column in (
        ("domains", "domains"),
        ("expectedIPs", "expected_ips"),
        ("unexpectedIPs", "unexpected_ips"),
    ):
        values = split_values(row[column])
        if values:
            item[key] = values
        else:
            item.pop(key, None)
    if row["query_strategy"]:
        item["queryStrategy"] = row["query_strategy"]
    else:
        item.pop("queryStrategy", None)
    if row["skip_fallback"]:
        item["skipFallback"] = True
    else:
        item.pop("skipFallback", None)
    if row["final_query"]:
        item["finalQuery"] = True
    else:
        item.pop("finalQuery", None)
    if int(row["timeout_ms"]) != 4000:
        item["timeoutMs"] = int(row["timeout_ms"])
    else:
        item.pop("timeoutMs", None)
    return item


def build_dns_json() -> dict[str, object] | None:
    settings = get_dns_settings()
    if not settings["enabled"]:
        return None
    servers = list_dns_servers(enabled_only=True)
    if not servers:
        raise XPanelError("DNS включён, но нет ни одного активного DNS-сервера")
    for row in servers:
        per_server = str(row["query_strategy"] or "")
        if settings["query_strategy"] == "UseIPv4" and per_server == "UseIPv6":
            raise XPanelError(f"DNS-сервер {row['name']}: UseIPv6 конфликтует с global UseIPv4")
        if settings["query_strategy"] == "UseIPv6" and per_server == "UseIPv4":
            raise XPanelError(f"DNS-сервер {row['name']}: UseIPv4 конфликтует с global UseIPv6")
    result = _json_object(settings["extra_json"] if "extra_json" in settings.keys() else "{}")
    result.pop("_sgPanel", None)
    result.update({
        "servers": [build_dns_server_json(row) for row in servers],
        "queryStrategy": settings["query_strategy"],
        "disableCache": bool(settings["disable_cache"]),
        "disableFallback": bool(settings["disable_fallback"]),
        "disableFallbackIfMatch": bool(settings["disable_fallback_if_match"]),
        "enableParallelQuery": bool(settings["enable_parallel_query"]),
        "useSystemHosts": bool(settings["use_system_hosts"]),
    })
    hosts: dict[str, object] = {}
    for row in list_dns_hosts(enabled_only=True):
        values = split_values(row["addresses"])
        hosts[str(row["domain"])] = values[0] if len(values) == 1 else values
    if hosts:
        result["hosts"] = hosts
    return result


def preview_dns_json() -> str:
    return json.dumps({"dns": build_dns_json()}, ensure_ascii=False, indent=2) + "\n"


def dns_json_document() -> str:
    settings = get_dns_settings()
    servers = list_dns_servers(enabled_only=True)
    dns = _json_object(settings["extra_json"] if "extra_json" in settings.keys() else "{}")
    dns.update({
        "_sgPanel": {
            "enabled": bool(settings["enabled"]),
            "note": "_sgPanel хранит состояние GUI и не передаётся Xray.",
        },
        "servers": [],
        "queryStrategy": settings["query_strategy"],
        "disableCache": bool(settings["disable_cache"]),
        "disableFallback": bool(settings["disable_fallback"]),
        "disableFallbackIfMatch": bool(settings["disable_fallback_if_match"]),
        "enableParallelQuery": bool(settings["enable_parallel_query"]),
        "useSystemHosts": bool(settings["use_system_hosts"]),
    })
    server_values: list[dict[str, object]] = []
    for row in servers:
        item = build_dns_server_json(row)
        item["_sgPanel"] = {
            "name": row["name"],
            "priority": int(row["priority"]),
        }
        server_values.append(item)
    dns["servers"] = server_values
    hosts: dict[str, object] = {}
    for row in list_dns_hosts(enabled_only=True):
        values = split_values(row["addresses"])
        hosts[str(row["domain"])] = values[0] if len(values) == 1 else values
    if hosts:
        dns["hosts"] = hosts
    return json.dumps(dns, ensure_ascii=False, indent=2) + "\n"


def update_dns_json_document(text: str) -> dict[str, object]:
    try:
        dns = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(dns, dict):
        raise ValueError("DNS должен быть JSON-объектом")
    meta = dns.get("_sgPanel")
    meta = meta if isinstance(meta, dict) else {}
    enabled = bool(meta.get("enabled", True))
    clean_dns = _strip_sgpanel_metadata(dns)
    if not isinstance(clean_dns, dict):
        raise ValueError("не удалось подготовить DNS JSON")
    servers = clean_dns.get("servers", [])
    if enabled or servers:
        parsed = _parse_full_dns({"dns": clean_dns})
        _replace_full_config_dns(parsed)
    if not enabled:
        current = get_dns_settings()
        update_dns_settings(
            enabled=False,
            query_strategy=str(clean_dns.get("queryStrategy", current["query_strategy"])),
            disable_cache=bool(clean_dns.get("disableCache", current["disable_cache"])),
            disable_fallback=bool(clean_dns.get("disableFallback", current["disable_fallback"])),
            disable_fallback_if_match=bool(
                clean_dns.get(
                    "disableFallbackIfMatch", current["disable_fallback_if_match"]
                )
            ),
            enable_parallel_query=bool(
                clean_dns.get("enableParallelQuery", current["enable_parallel_query"])
            ),
            use_system_hosts=bool(clean_dns.get("useSystemHosts", current["use_system_hosts"])),
        )
        extra = _copy_json_object(clean_dns)
        for key in (
            "servers", "hosts", "queryStrategy", "disableCache",
            "disableFallback", "disableFallbackIfMatch", "enableParallelQuery",
            "useSystemHosts",
        ):
            extra.pop(key, None)
        with connect() as con:
            con.execute(
                "UPDATE dns_settings SET extra_json = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = 1",
                (json.dumps(extra, ensure_ascii=False, separators=(",", ":")),),
            )
    return {
        "enabled": enabled,
        "servers": len(list_dns_servers(enabled_only=True)),
        "hosts": len(list_dns_hosts(enabled_only=True)),
    }


def test_dns_resolution(domain: str = "example.com") -> dict[str, object]:
    clean = (domain or "").strip()
    if not clean or any(ch.isspace() for ch in clean):
        raise ValueError("некорректный домен для проверки")
    started = time.perf_counter()
    try:
        values = sorted({item[4][0] for item in socket.getaddrinfo(clean, None)})
        return {"ok": True, "domain": clean, "addresses": values,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except OSError as exc:
        return {"ok": False, "domain": clean, "addresses": [], "detail": str(exc)}


def get_routing_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        return con.execute("SELECT * FROM routing_settings WHERE id = 1").fetchone()


def get_routing_extra() -> dict[str, object]:
    settings = get_routing_settings()
    extra = _json_object(settings["extra_json"])
    extra.pop("domainStrategy", None)
    extra.pop("rules", None)
    extra.pop("_sgPanel", None)
    return extra


def list_balancer_tags() -> list[str]:
    balancers = get_routing_extra().get("balancers", [])
    if not isinstance(balancers, list):
        return []
    result: list[str] = []
    for item in balancers:
        if isinstance(item, dict) and isinstance(item.get("tag"), str):
            tag = item["tag"].strip()
            if tag and tag not in result:
                result.append(tag)
    return result


def update_routing_settings(
    *,
    domain_strategy: str,
    sniffing_enabled: bool,
    sniffing_route_only: bool,
    sniff_http: bool,
    sniff_tls: bool,
    sniff_quic: bool,
    default_outbound_tag: str = "direct",
) -> sqlite3.Row:
    if domain_strategy not in ALLOWED_DOMAIN_STRATEGIES:
        raise ValueError("некорректная domainStrategy")
    if sniffing_enabled and not any((sniff_http, sniff_tls, sniff_quic)):
        raise ValueError("при включённом sniffing выберите хотя бы HTTP, TLS или QUIC")
    if default_outbound_tag == "blocked":
        raise ValueError("blocked нельзя назначить выходом по умолчанию")
    if default_outbound_tag not in set(list_outbound_tags(enabled_only=True)):
        raise ValueError("выход по умолчанию не существует или отключён")
    with connect() as con:
        con.execute(
            """
            UPDATE routing_settings SET
                domain_strategy = ?, default_outbound_tag = ?,
                sniffing_enabled = ?, sniffing_route_only = ?,
                sniff_http = ?, sniff_tls = ?, sniff_quic = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
            """,
            (
                domain_strategy,
                default_outbound_tag,
                int(sniffing_enabled),
                int(sniffing_route_only),
                int(sniff_http),
                int(sniff_tls),
                int(sniff_quic),
            ),
        )
        warp = con.execute(
            "SELECT enabled, outbound_json, route_mode FROM warp_settings WHERE id = 1"
        ).fetchone()
        if warp is not None and bool(warp["enabled"]) and bool(warp["outbound_json"]):
            if default_outbound_tag == WARP_TAG:
                con.execute(
                    "UPDATE warp_settings SET route_mode = 'all', "
                    "updated_at = CURRENT_TIMESTAMP WHERE id = 1"
                )
                con.execute(
                    "UPDATE routing_rules SET enabled = 0, updated_at = CURRENT_TIMESTAMP "
                    "WHERE name = ? AND outbound_tag = ?",
                    (WARP_RULE_NAME, WARP_TAG),
                )
            elif warp["route_mode"] == "all":
                con.execute(
                    "UPDATE warp_settings SET route_mode = 'off', "
                    "updated_at = CURRENT_TIMESTAMP WHERE id = 1"
                )
    return get_routing_settings()


def list_routing_rules() -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute("SELECT * FROM routing_rules ORDER BY priority, id").fetchall()


def find_routing_rule(rule_id: int) -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM routing_rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise XPanelError(f"правило не найдено: {rule_id}")
    return row


def _merge_rule_config(
    base: dict[str, object] | None, cleaned: dict[str, object]
) -> dict[str, object]:
    result = _copy_json_object(base)
    result.pop("_sgPanel", None)
    result["type"] = "field"
    result.pop("outboundTag", None)
    result.pop("balancerTag", None)
    target_key = "balancerTag" if cleaned["target_type"] == "balancer" else "outboundTag"
    result[target_key] = cleaned["outbound_tag"]
    mappings = (
        ("domain", "domains"),
        ("ip", "ips"),
        ("protocol", "protocols"),
        ("inboundTag", "inbound_tags"),
        ("user", "users"),
    )
    for json_key, db_key in mappings:
        values = split_values(str(cleaned[db_key] or ""))
        if values:
            result[json_key] = values
        else:
            result.pop(json_key, None)
    if cleaned["ports"]:
        result["port"] = cleaned["ports"]
    else:
        result.pop("port", None)
    if cleaned["network"]:
        result["network"] = cleaned["network"]
    else:
        result.pop("network", None)
    return result


def rule_json_document(row: sqlite3.Row | None = None) -> str:
    if row is None:
        document: dict[str, object] = {
            "_sgPanel": {"name": "Блокировка рекламы", "priority": 100, "enabled": True},
            "type": "field",
            "domain": ["geosite:category-ads-all"],
            "outboundTag": "blocked",
        }
    else:
        document = build_rule_json(row)
        document = {
            "_sgPanel": {
                "name": row["name"],
                "priority": row["priority"],
                "enabled": bool(row["enabled"]),
            },
            **document,
        }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def parse_rule_json_document(
    text: str,
    *,
    fallback_name: str = "JSON rule",
    fallback_priority: int = 100,
    validate_target: bool = True,
) -> tuple[dict[str, object], dict[str, object], bool]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ValueError("JSON правила должен быть объектом")
    document = _copy_json_object(document)
    meta = document.pop("_sgPanel", {})
    meta = meta if isinstance(meta, dict) else {}
    if document.get("type", "field") != "field":
        raise ValueError("поддерживаются только routing rules с type: field")
    has_outbound = isinstance(document.get("outboundTag"), str) and bool(document.get("outboundTag"))
    has_balancer = isinstance(document.get("balancerTag"), str) and bool(document.get("balancerTag"))
    if has_outbound == has_balancer:
        raise ValueError("укажите ровно одну цель: outboundTag или balancerTag")
    target_type = "balancer" if has_balancer else "outbound"
    target_tag = str(document.get("balancerTag" if has_balancer else "outboundTag", ""))

    def join_value(key: str) -> str:
        value = document.get(key, [])
        if isinstance(value, list):
            return "\n".join(str(item) for item in value)
        if value in (None, ""):
            return ""
        return str(value)

    values = {
        "name": str(meta.get("name") or fallback_name),
        "priority": int(meta.get("priority", fallback_priority)),
        "outbound_tag": target_tag,
        "target_type": target_type,
        "domains": join_value("domain"),
        "ips": join_value("ip"),
        "ports": str(document.get("port", "") or ""),
        "network": str(document.get("network", "") or ""),
        "protocols": join_value("protocol"),
        "inbound_tags": join_value("inboundTag"),
        "users": join_value("user"),
    }
    if validate_target:
        cleaned = validate_rule_values(**values)
    else:
        # Full routing import validates targets after all balancers are known.
        target_type_value = values.pop("target_type")
        if target_type_value not in ALLOWED_RULE_TARGETS:
            raise ValueError("некорректная цель правила")
        name = str(values["name"]).strip()
        if not name or len(name) > 100:
            raise ValueError("название правила должно содержать от 1 до 100 символов")
        priority = int(values["priority"])
        if not 1 <= priority <= 9999:
            raise ValueError("приоритет должен быть от 1 до 9999")
        network = str(values["network"]).strip().lower()
        if network not in ALLOWED_NETWORKS:
            raise ValueError("network должен быть tcp, udp, tcp,udp или пустым")
        cleaned = {
            "name": name,
            "priority": priority,
            "outbound_tag": target_tag,
            "target_type": target_type_value,
            "domains": validate_domains(str(values["domains"])),
            "ips": validate_ips(str(values["ips"])),
            "ports": validate_ports(str(values["ports"])),
            "network": network,
            "protocols": validate_protocols(str(values["protocols"])),
            "inbound_tags": normalise_values(str(values["inbound_tags"])),
            "users": normalise_values(str(values["users"])),
        }
        if not any(
            cleaned[key]
            for key in ("domains", "ips", "ports", "network", "protocols", "inbound_tags", "users")
        ):
            raise ValueError("задайте хотя бы одно условие правила")
    enabled = bool(meta.get("enabled", True))
    return cleaned, _merge_rule_config(document, cleaned), enabled


def _insert_routing_rule(
    cleaned: dict[str, object], *, enabled: bool, config: dict[str, object]
) -> sqlite3.Row:
    try:
        with connect() as con:
            cur = con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, target_type, domains, ips, ports,
                     network, protocols, inbound_tags, users, config_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned["name"], cleaned["priority"], int(enabled),
                    cleaned["outbound_tag"], cleaned["target_type"], cleaned["domains"],
                    cleaned["ips"], cleaned["ports"], cleaned["network"],
                    cleaned["protocols"], cleaned["inbound_tags"], cleaned["users"],
                    json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            rule_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("правило с таким названием уже существует") from exc
    return find_routing_rule(rule_id)


def add_routing_rule(**values) -> sqlite3.Row:
    values.setdefault("target_type", "outbound")
    cleaned = validate_rule_values(**values)
    return _insert_routing_rule(
        cleaned, enabled=bool(values.get("enabled", True)),
        config=_merge_rule_config({}, cleaned),
    )


def add_routing_rule_json(text: str) -> sqlite3.Row:
    cleaned, config, enabled = parse_rule_json_document(text)
    return _insert_routing_rule(cleaned, enabled=enabled, config=config)


def _update_routing_rule_record(
    rule_id: int,
    cleaned: dict[str, object],
    *,
    enabled: bool,
    config: dict[str, object],
) -> sqlite3.Row:
    find_routing_rule(rule_id)
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE routing_rules SET
                    name = ?, priority = ?, enabled = ?, outbound_tag = ?, target_type = ?,
                    domains = ?, ips = ?, ports = ?, network = ?, protocols = ?,
                    inbound_tags = ?, users = ?, config_json = ?,
                    managed_by = '', managed_role = '', updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    cleaned["name"], cleaned["priority"], int(enabled),
                    cleaned["outbound_tag"], cleaned["target_type"], cleaned["domains"],
                    cleaned["ips"], cleaned["ports"], cleaned["network"],
                    cleaned["protocols"], cleaned["inbound_tags"], cleaned["users"],
                    json.dumps(config, ensure_ascii=False, separators=(",", ":")), rule_id,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise XPanelError("правило с таким названием уже существует") from exc
    return find_routing_rule(rule_id)


def update_routing_rule(rule_id: int, **values) -> sqlite3.Row:
    current = find_routing_rule(rule_id)
    values.setdefault("target_type", "outbound")
    cleaned = validate_rule_values(**values)
    return _update_routing_rule_record(
        rule_id, cleaned, enabled=bool(current["enabled"]),
        config=_merge_rule_config(_json_object(current["config_json"]), cleaned),
    )


def update_routing_rule_json(rule_id: int, text: str) -> sqlite3.Row:
    current = find_routing_rule(rule_id)
    cleaned, config, enabled = parse_rule_json_document(
        text,
        fallback_name=str(current["name"]),
        fallback_priority=int(current["priority"]),
    )
    return _update_routing_rule_record(
        rule_id, cleaned, enabled=enabled, config=config
    )

def set_routing_rule_enabled(rule_id: int, enabled: bool) -> sqlite3.Row:
    rule = find_routing_rule(rule_id)
    if enabled:
        if rule["target_type"] == "balancer":
            if rule["outbound_tag"] not in set(list_balancer_tags()):
                raise XPanelError("нельзя включить правило: его balancer отсутствует")
        elif rule["outbound_tag"] not in set(list_outbound_tags(enabled_only=True)):
            raise XPanelError("нельзя включить правило: его outbound отсутствует или отключён")
    with connect() as con:
        con.execute(
            "UPDATE routing_rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (int(enabled), rule_id),
        )
    return find_routing_rule(rule_id)


def delete_routing_rule(rule_id: int) -> sqlite3.Row:
    rule = find_routing_rule(rule_id)
    with connect() as con:
        con.execute("DELETE FROM routing_rules WHERE id = ?", (rule_id,))
    return rule


def _system_outbounds() -> list[dict[str, object]]:
    return [
        {
            "id": None,
            "tag": "direct",
            "name": "Direct internet",
            "type": "freedom",
            "protocol": "freedom",
            "network": "",
            "security": "",
            "transport_label": "SYSTEM",
            "security_label": "",
            "enabled": 1,
            "system": True,
            "description": "Прямой выход в интернет.",
        },
        {
            "id": None,
            "tag": "blocked",
            "name": "Blocked",
            "type": "blackhole",
            "protocol": "blackhole",
            "network": "",
            "security": "",
            "transport_label": "SYSTEM",
            "security_label": "",
            "enabled": 1,
            "system": True,
            "description": "Отбрасывает трафик, совпавший с блокирующим правилом.",
        },
    ]


def list_custom_outbounds(*, enabled_only: bool = False) -> list[sqlite3.Row]:
    init_db()
    query = "SELECT * FROM outbounds"
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY id"
    with connect() as con:
        return con.execute(query).fetchall()



def get_warp_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM warp_settings WHERE id = 1").fetchone()
    if row is None:
        raise XPanelError("настройки WARP не созданы")
    return row


def _warp_binary() -> Path:
    return Path(os.environ.get("XPANEL_WGCF_CLI", "/usr/local/bin/wgcf-cli"))


def _normalise_warp_outbound(document: object) -> dict[str, object]:
    if not isinstance(document, dict):
        raise ValueError("WARP outbound должен быть JSON-объектом")
    result = json.loads(json.dumps(document))
    if str(result.get("protocol", "")).lower() != "wireguard":
        raise ValueError("WARP outbound должен использовать protocol: wireguard")
    settings = result.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("WARP outbound не содержит settings")
    if not str(settings.get("secretKey", "")).strip():
        raise ValueError("WARP outbound не содержит secretKey")
    address = settings.get("address")
    if not isinstance(address, list) or not any(str(item).strip() for item in address):
        raise ValueError("WARP outbound не содержит address")
    peers = settings.get("peers")
    if not isinstance(peers, list) or not peers or not isinstance(peers[0], dict):
        raise ValueError("WARP outbound не содержит peers")
    peer = peers[0]
    if not str(peer.get("publicKey", "")).strip() or not str(peer.get("endpoint", "")).strip():
        raise ValueError("WARP peer должен содержать publicKey и endpoint")
    # EC2 often has no IPv6 default route. The wgcf hostname resolves to both
    # address families, so Xray may select an unreachable IPv6 endpoint and hang.
    # Keep the verified Cloudflare WireGuard IPv4 endpoint for deterministic WARP.
    peer["endpoint"] = WARP_IPV4_ENDPOINT
    peer.setdefault("allowedIPs", ["0.0.0.0/0", "::/0"])
    settings.setdefault("mtu", 1280)
    settings["noKernelTun"] = True
    result["protocol"] = "wireguard"
    result["tag"] = WARP_TAG
    result["settings"] = settings
    return result


def build_warp_outbound() -> dict[str, object]:
    row = get_warp_settings()
    text = str(row["outbound_json"] or "").strip()
    if not text:
        raise XPanelError("WARP ещё не создан")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise XPanelError("сохранённый WARP outbound повреждён") from exc
    return _normalise_warp_outbound(document)


def get_warp_overview() -> dict[str, object]:
    row = get_warp_settings()
    configured = bool(str(row["outbound_json"] or "").strip())
    managed_rules = [
        dict(rule) for rule in (_find_warp_rule(WARP_RULE_NAME), _find_warp_rule(WARP_IP_RULE_NAME))
        if rule is not None and bool(rule["enabled"])
    ]
    return {
        **dict(row),
        "configured": configured,
        "enabled": bool(row["enabled"]) and configured,
        "helper_installed": _warp_binary().is_file(),
        "default_domains": WARP_DEFAULT_DOMAINS,
        "russia_tlds": WARP_RUSSIA_TLDS,
        "russia_domains": WARP_RUSSIA_DOMAINS,
        "russia_ips": WARP_RUSSIA_IPS,
        "managed_rules": managed_rules,
    }


def warp_json_document() -> str:
    row = get_warp_settings()
    text = str(row["outbound_json"] or "").strip()
    if not text:
        raise XPanelError("WARP ещё не создан")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise XPanelError("сохранённый WARP outbound повреждён") from exc
    if not isinstance(document, dict):
        raise XPanelError("сохранённый WARP outbound должен быть объектом")
    result = _copy_json_object(document)
    result["_sgPanel"] = {
        "enabled": bool(row["enabled"]),
        "routeMode": str(row["route_mode"]),
        "selectedDomains": split_values(row["selected_domains"]),
        "selectedIps": split_values(row["selected_ips"]),
        "note": "_sgPanel хранит состояние GUI и не передаётся Xray.",
    }
    return json.dumps(result, ensure_ascii=False, indent=2) + "\n"


def update_warp_json_document(text: str) -> dict[str, object]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(document, dict):
        raise ValueError("WARP outbound должен быть JSON-объектом")
    meta = document.get("_sgPanel")
    meta = meta if isinstance(meta, dict) else {}
    enabled = bool(meta.get("enabled", True))
    route_mode = str(meta.get("routeMode", "off"))
    selected = meta.get("selectedDomains", [])
    if isinstance(selected, list):
        selected_domains = "\n".join(str(item) for item in selected)
    else:
        selected_domains = str(selected or "")
    selected_ip_values = meta.get("selectedIps", [])
    if isinstance(selected_ip_values, list):
        selected_ips = "\n".join(str(item) for item in selected_ip_values)
    else:
        selected_ips = str(selected_ip_values or "")
    clean = _strip_sgpanel_metadata(document)
    outbound = _normalise_warp_outbound(clean)
    with connect() as con:
        con.execute(
            """
            UPDATE warp_settings SET enabled = ?, outbound_json = ?,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (
                int(enabled),
                json.dumps(outbound, ensure_ascii=False, separators=(",", ":")),
            ),
        )
    configure_warp_routing(route_mode if enabled else "off", selected_domains, selected_ips)
    return get_warp_overview()


def _clone_live_database(target: Path) -> None:
    """Copy the live SQLite database into *target* using SQLite backup."""
    init_db()
    source_path = db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source_path) as source, sqlite3.connect(target) as destination:
        source.backup(destination)


def _validate_database_candidate(mutator) -> dict[str, object]:
    """Apply *mutator* only to a cloned DB and run Xray's full config test."""
    with tempfile.TemporaryDirectory(prefix="sg-panel-candidate-") as temp_dir:
        candidate_path = Path(temp_dir) / "panel.db"
        _clone_live_database(candidate_path)
        with use_db_path(candidate_path):
            mutator()
            validation = validate_generated_config()
        if not validation["ok"]:
            detail = str(validation.get("detail") or "Xray отклонил конфигурацию")
            raise XPanelError("кандидат конфигурации не прошёл проверку Xray:\n" + detail)
        return validation


def _store_warp_candidate(outbound: dict[str, object], account_text: str) -> None:
    """Persist an already-normalised WARP candidate in the active DB context."""
    with connect() as con:
        con.execute(
            """
            UPDATE warp_settings SET
                enabled = 1, outbound_json = ?, account_json = ?,
                last_test_state = '', last_test_ip = '', last_test_at = NULL,
                created_at = COALESCE(created_at, CURRENT_TIMESTAMP),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
            """,
            (
                json.dumps(outbound, ensure_ascii=False, separators=(",", ":")),
                account_text,
            ),
        )


def _clear_warp_candidate() -> None:
    """Remove WARP state from the active DB context without touching files."""
    with connect() as con:
        con.execute(
            "UPDATE routing_settings SET default_outbound_tag = 'direct', "
            "updated_at = CURRENT_TIMESTAMP WHERE id = 1 AND default_outbound_tag = ?",
            (WARP_TAG,),
        )
        con.execute("DELETE FROM routing_rules WHERE outbound_tag = ?", (WARP_TAG,))
        con.execute(
            """
            UPDATE warp_settings SET enabled = 0, outbound_json = '', account_json = '',
                route_mode = 'off', selected_domains = '', selected_ips = '', last_test_state = '',
                last_test_ip = '', last_test_at = NULL, created_at = NULL,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """
        )


def create_warp(*, regenerate: bool = False) -> dict[str, object]:
    require_root()
    current = get_warp_settings()
    if str(current["outbound_json"] or "").strip() and not regenerate:
        raise XPanelError("WARP уже создан; используйте пересоздание")
    binary = _warp_binary()
    if not binary.is_file():
        raise FileNotFoundError(
            "не найден /usr/local/bin/wgcf-cli; повторно запустите установщик SG-Panel"
        )
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WARP_DIR, 0o700)
    workdir = Path(tempfile.mkdtemp(prefix="register-", dir=str(WARP_DIR)))
    try:
        registered = _run([str(binary), "register"], timeout=90, cwd=workdir)
        if registered.returncode != 0:
            raise XPanelError(
                (registered.stderr or registered.stdout).strip()
                or "wgcf-cli register завершился с ошибкой"
            )
        generated = _run([str(binary), "generate", "--xray"], timeout=60, cwd=workdir)
        if generated.returncode != 0:
            raise XPanelError(
                (generated.stderr or generated.stdout).strip()
                or "wgcf-cli generate --xray завершился с ошибкой"
            )
        account_path = workdir / "wgcf.json"
        outbound_path = workdir / "wgcf.xray.json"
        if not account_path.is_file() or not outbound_path.is_file():
            raise XPanelError("wgcf-cli не создал wgcf.json или wgcf.xray.json")
        account_text = account_path.read_text(encoding="utf-8")
        outbound = _normalise_warp_outbound(
            json.loads(outbound_path.read_text(encoding="utf-8"))
        )
        # Validate the exact generated credentials and outbound on a cloned DB first.
        # Nothing is written to the live DB or permanent account file before Xray accepts it.
        _validate_database_candidate(lambda: _store_warp_candidate(outbound, account_text))

        saved_account = WARP_DIR / "wgcf.json"
        saved_account.write_text(account_text, encoding="utf-8")
        os.chmod(saved_account, 0o600)
        _store_warp_candidate(outbound, account_text)
        return get_warp_overview()
    except json.JSONDecodeError as exc:
        raise XPanelError("wgcf-cli создал некорректный JSON") from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def set_warp_enabled(enabled: bool) -> dict[str, object]:
    row = get_warp_settings()
    if enabled and not str(row["outbound_json"] or "").strip():
        raise XPanelError("сначала создайте WARP")
    with connect() as con:
        con.execute(
            "UPDATE warp_settings SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            (int(enabled),),
        )
        if not enabled:
            con.execute(
                "UPDATE routing_settings SET default_outbound_tag = 'direct', "
                "updated_at = CURRENT_TIMESTAMP WHERE id = 1 AND default_outbound_tag = ?",
                (WARP_TAG,),
            )
            con.execute(
                "UPDATE routing_rules SET enabled = 0, updated_at = CURRENT_TIMESTAMP "
                "WHERE outbound_tag = ?",
                (WARP_TAG,),
            )
            con.execute(
                "UPDATE warp_settings SET route_mode = 'off', updated_at = CURRENT_TIMESTAMP "
                "WHERE id = 1"
            )
    return get_warp_overview()


def _find_warp_rule(name: str = WARP_RULE_NAME) -> sqlite3.Row | None:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM routing_rules WHERE name = ? COLLATE NOCASE",
            (name,),
        ).fetchone()


def configure_warp_routing(
    mode: str, selected_domains: str = "", selected_ips: str = ""
) -> dict[str, object]:
    mode = (mode or "off").strip().lower()
    if mode not in {"off", "selected", "all"}:
        raise ValueError("режим WARP должен быть off, selected или all")
    warp = get_warp_overview()
    if mode != "off" and not warp["enabled"]:
        raise XPanelError("включите WARP перед настройкой маршрута")
    domains = validate_domains(selected_domains)
    ips = validate_ips(selected_ips)
    if mode == "selected" and not domains and not ips:
        raise ValueError("укажите хотя бы одно условие: домен/Geosite или IP/GeoIP/CIDR")

    domain_rule = _find_warp_rule(WARP_RULE_NAME)
    ip_rule = _find_warp_rule(WARP_IP_RULE_NAME)

    def upsert_rule(
        con: sqlite3.Connection, *, existing: sqlite3.Row | None, name: str,
        priority: int, domains_value: str = "", ips_value: str = ""
    ) -> None:
        active = bool(domains_value or ips_value)
        if not active:
            if existing is not None:
                con.execute(
                    "UPDATE routing_rules SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (int(existing["id"]),),
                )
            return
        config: dict[str, object] = {
            "type": "field", "outboundTag": WARP_TAG, "network": "tcp,udp",
        }
        if domains_value:
            config["domain"] = split_values(domains_value)
        if ips_value:
            config["ip"] = split_values(ips_value)
        config_json = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
        if existing is None:
            con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, target_type, domains, ips, network,
                     config_json)
                VALUES (?, ?, 1, ?, 'outbound', ?, ?, 'tcp,udp', ?)
                """,
                (name, priority, WARP_TAG, domains_value, ips_value, config_json),
            )
            return
        con.execute(
            """
            UPDATE routing_rules SET name = ?, priority = ?, enabled = 1, outbound_tag = ?,
                target_type = 'outbound', domains = ?, ips = ?, ports = '',
                network = 'tcp,udp', protocols = '', inbound_tags = '', users = '',
                config_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                name, priority, WARP_TAG, domains_value, ips_value, config_json,
                int(existing["id"]),
            ),
        )

    with connect() as con:
        if mode == "all":
            con.execute(
                "UPDATE routing_settings SET default_outbound_tag = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                (WARP_TAG,),
            )
        else:
            con.execute(
                "UPDATE routing_settings SET default_outbound_tag = 'direct', "
                "updated_at = CURRENT_TIMESTAMP WHERE id = 1 AND default_outbound_tag = ?",
                (WARP_TAG,),
            )

        if mode == "selected":
            # Xray combines fields inside one rule with logical AND. Keep domain
            # and IP conditions in separate managed rules so either can match.
            upsert_rule(
                con, existing=domain_rule, name=WARP_RULE_NAME, priority=40,
                domains_value=domains,
            )
            upsert_rule(
                con, existing=ip_rule, name=WARP_IP_RULE_NAME, priority=41,
                ips_value=ips,
            )
        else:
            upsert_rule(con, existing=domain_rule, name=WARP_RULE_NAME, priority=40)
            upsert_rule(con, existing=ip_rule, name=WARP_IP_RULE_NAME, priority=41)

        con.execute(
            """
            UPDATE warp_settings SET route_mode = ?, selected_domains = ?, selected_ips = ?,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (mode, domains, ips),
        )
    return get_warp_overview()


def delete_warp() -> None:
    require_root()
    _validate_database_candidate(_clear_warp_candidate)
    _clear_warp_candidate()
    (WARP_DIR / "wgcf.json").unlink(missing_ok=True)


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_warp() -> dict[str, object]:
    require_root()
    warp = get_warp_overview()
    if not warp["enabled"]:
        raise XPanelError("WARP не включён")
    server = get_server()
    xray_bin = str(server["xray_bin"])
    if not Path(xray_bin).is_file():
        raise FileNotFoundError(f"не найден Xray: {xray_bin}")
    curl = shutil.which("curl")
    if curl is None:
        raise FileNotFoundError("не найден curl")
    port = _free_local_port()
    document = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "warp-test-in", "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": {"udp": True},
        }],
        "outbounds": [build_warp_outbound()],
        "routing": {"rules": [{
            "type": "field", "inboundTag": ["warp-test-in"], "outboundTag": WARP_TAG,
        }]},
    }
    fd, name = tempfile.mkstemp(prefix="sg-panel-warp-test-", suffix=".json")
    os.close(fd)
    path = Path(name)
    proc: subprocess.Popen[str] | None = None
    state = "error"
    ip = ""
    detail = ""
    try:
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.Popen(
            [xray_bin, "run", "-config", str(path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 8
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise XPanelError(stderr.strip() or "тестовый Xray завершился раньше времени")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    ready = True
                    break
            time.sleep(0.15)
        if not ready:
            raise XPanelError("тестовый SOCKS-порт WARP не открылся")
        result = _run(
            [curl, "--silent", "--show-error", "--max-time", "25",
             "--socks5-hostname", f"127.0.0.1:{port}",
             "https://www.cloudflare.com/cdn-cgi/trace"],
            timeout=30,
        )
        if result.returncode != 0:
            raise XPanelError((result.stderr or result.stdout).strip() or "проверка WARP не удалась")
        values = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        ip = values.get("ip", "")
        warp_state = values.get("warp", "off")
        if warp_state not in {"on", "plus"}:
            raise XPanelError(f"Cloudflare trace вернул warp={warp_state}")
        state = warp_state
        detail = f"WARP {warp_state}, IP {ip}" if ip else f"WARP {warp_state}"
        return {"ok": True, "state": state, "ip": ip, "detail": detail}
    except Exception as exc:
        detail = str(exc)
        raise
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        path.unlink(missing_ok=True)
        with connect() as con:
            con.execute(
                """
                UPDATE warp_settings SET last_test_state = ?, last_test_ip = ?,
                    last_test_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = 1
                """,
                (state if state != "error" else ("error: " + detail)[:250], ip),
            )


def _transport_label(network: str, mode: str = "") -> str:
    if network == "xhttp":
        return f"XHTTP / {(mode or 'auto').upper()}"
    return "RAW / TCP"


def _json_only_outbounds() -> list[dict[str, object]]:
    document = get_config_base_document()
    values = document.get("outbounds", [])
    if not isinstance(values, list):
        return []
    managed_tags = {"direct", "blocked"}
    if get_warp_overview()["configured"]:
        managed_tags.add(WARP_TAG)
    managed_tags.update(str(row["tag"]) for row in list_custom_outbounds(enabled_only=True))
    result: list[dict[str, object]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        tag = str(item.get("tag", "")).strip()
        if not tag or tag in managed_tags:
            continue
        protocol = str(item.get("protocol", "unknown"))
        stream = item.get("streamSettings")
        stream = stream if isinstance(stream, dict) else {}
        network = str(stream.get("network", ""))
        security = str(stream.get("security", ""))
        result.append(
            {
                "id": None,
                "tag": tag,
                "name": f"JSON · {tag}",
                "type": protocol,
                "protocol": protocol,
                "network": network,
                "security": security,
                "transport_label": network.upper() if network else "JSON",
                "security_label": security.upper(),
                "enabled": 1,
                "system": False,
                "json_only": True,
                "description": "Расширенный выход хранится в полном JSON конфигурации.",
            }
        )
    return result


def list_outbounds() -> list[dict[str, object]]:
    result = _system_outbounds()
    for row in list_custom_outbounds():
        item = dict(row)
        network = str(row["network"] or "raw")
        security = str(row["security"] or "reality")
        mode = str(row["xhttp_mode"] or "auto")
        transport_label = _transport_label(network, mode)
        security_label = security.upper()
        item.update(
            {
                "protocol": "vless",
                "system": False,
                "json_only": False,
                "transport_label": transport_label,
                "security_label": security_label,
                "combination_label": f"VLESS + {transport_label} + {security_label}",
                "description": (
                    f"VLESS {transport_label} + {security_label}: "
                    f"{row['address']}:{row['port']}"
                ),
            }
        )
        result.append(item)
    result.extend(_json_only_outbounds())
    return result


def list_outbound_tags(*, enabled_only: bool = False) -> list[str]:
    tags = ["direct", "blocked"]
    warp = get_warp_overview()
    if warp["configured"] and (warp["enabled"] or not enabled_only):
        tags.append(WARP_TAG)
    tags.extend(str(row["tag"]) for row in list_custom_outbounds(enabled_only=enabled_only))
    tags.extend(str(item["tag"]) for item in _json_only_outbounds())
    return list(dict.fromkeys(tags))



def routing_outbound_options(*, enabled_only: bool = True) -> list[dict[str, object]]:
    """Return only real server outbounds with user-facing type/state metadata.

    There is intentionally no generic or synthetic "VPN" target. A route can point
    only to Direct, Block, an active WARP instance, a configured Cascade outbound,
    an enabled custom VLESS outbound, or an outbound that exists in the live JSON.
    """
    enabled_tags = set(list_outbound_tags(enabled_only=True))
    cascade_ids: set[int] = set()
    with connect() as con:
        row = con.execute(
            "SELECT outbound_id FROM cascade_settings WHERE id=1"
        ).fetchone()
    if row is not None and row["outbound_id"] is not None:
        cascade_ids.add(int(row["outbound_id"]))

    options: list[dict[str, object]] = [
        {
            "tag": "direct",
            "label": "Direct",
            "kind": "direct",
            "type_label": "SYSTEM",
            "description": "Прямой выход этого сервера в интернет.",
            "enabled": True,
            "configured": True,
            "system": True,
            "default_eligible": True,
        },
        {
            "tag": "blocked",
            "label": "Block",
            "kind": "blocked",
            "type_label": "SYSTEM",
            "description": "Отбросить совпавший трафик.",
            "enabled": True,
            "configured": True,
            "system": True,
            "default_eligible": False,
        },
    ]

    warp = get_warp_overview()
    if warp["configured"] and (warp["enabled"] or not enabled_only):
        options.append(
            {
                "tag": WARP_TAG,
                "label": "WARP",
                "kind": "warp",
                "type_label": "WIREGUARD",
                "description": "Реальный Cloudflare WARP outbound Xray.",
                "enabled": bool(warp["enabled"]),
                "configured": True,
                "system": False,
                "default_eligible": bool(warp["enabled"]),
            }
        )

    for item in list_outbounds():
        tag = str(item.get("tag") or "")
        if tag in {"direct", "blocked"}:
            continue
        if enabled_only and tag not in enabled_tags:
            continue
        outbound_id = item.get("id")
        is_cascade = outbound_id is not None and int(outbound_id) in cascade_ids
        is_json = bool(item.get("json_only"))
        protocol = str(item.get("protocol") or item.get("type") or "OUTBOUND").upper()
        if is_cascade:
            label = f"Cascade · {item.get('name') or tag}"
            kind = "cascade"
            type_label = "CASCADE"
            description = "Реальный выход через настроенный Cascade-сервер."
        elif is_json:
            label = f"{protocol} · {tag}"
            kind = "custom"
            type_label = "JSON"
            description = str(item.get("description") or "Outbound из полного Xray JSON.")
        else:
            label = f"VLESS · {item.get('name') or tag}"
            kind = "custom"
            type_label = "VLESS"
            description = str(item.get("description") or "Пользовательский VLESS outbound.")
        options.append(
            {
                "tag": tag,
                "label": label,
                "kind": kind,
                "type_label": type_label,
                "description": description,
                "enabled": bool(item.get("enabled", True)),
                "configured": True,
                "system": False,
                "default_eligible": bool(item.get("enabled", True)),
            }
        )
    return options


def routing_outbound_map(*, enabled_only: bool = False) -> dict[str, dict[str, object]]:
    return {
        str(item["tag"]): item
        for item in routing_outbound_options(enabled_only=enabled_only)
    }


def routing_rules_overview() -> list[dict[str, object]]:
    available = routing_outbound_map(enabled_only=False)
    result: list[dict[str, object]] = []
    for row in list_routing_rules():
        item = dict(row)
        tag = str(row["outbound_tag"])
        if str(row["target_type"]) == "balancer":
            route = {
                "tag": tag,
                "label": f"Balancer · {tag}",
                "kind": "custom",
                "type_label": "BALANCER",
                "description": "Xray balancer.",
                "enabled": tag in set(list_balancer_tags()),
                "configured": tag in set(list_balancer_tags()),
                "system": False,
                "default_eligible": False,
            }
        else:
            route = available.get(tag)
            if route is None or not bool(route.get("enabled", False)):
                configured = route is not None and bool(route.get("configured", False))
                route = {
                    "tag": tag,
                    "label": f"Недоступен · {tag}",
                    "kind": "unavailable",
                    "type_label": "DISABLED" if configured else "MISSING",
                    "description": (
                        "Outbound настроен, но отключён."
                        if configured else "Outbound отсутствует на этом сервере."
                    ),
                    "enabled": False,
                    "configured": configured,
                    "system": False,
                    "default_eligible": False,
                }
        item["route"] = route
        result.append(item)
    return result


def find_outbound(outbound_id: int) -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM outbounds WHERE id = ?", (outbound_id,)).fetchone()
    if row is None:
        raise XPanelError(f"outbound не найден: {outbound_id}")
    return row


def _validate_outbound_tag(tag: str) -> str:
    tag = tag.strip()
    if not OUTBOUND_TAG_RE.fullmatch(tag):
        raise ValueError("tag: 1-64 символа, только латиница, цифры, точка, дефис и подчёркивание")
    if tag.lower() in RESERVED_OUTBOUND_TAGS:
        raise ValueError("этот tag зарезервирован системой")
    return tag


def normalise_fingerprint_profile(value: str | None) -> str:
    profile = (value or "firefox").strip()
    if not profile:
        return "firefox"
    lowered = profile.lower()
    if lowered in STANDARD_FINGERPRINTS:
        return lowered
    if len(profile) > 80 or not re.fullmatch(r"[A-Za-z0-9_.-]+", profile):
        raise ValueError("некорректное значение fingerprint")
    return profile


def fingerprint_for_xray(value: str | None) -> str:
    profile = normalise_fingerprint_profile(value)
    return FINGERPRINT_ALIASES.get(profile, profile)


def _normalise_alpn(value: str) -> str:
    tokens = [token for token in re.split(r"[,\s]+", value.strip()) if token]
    unique: list[str] = []
    for token in tokens:
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,32}", token):
            raise ValueError(f"некорректное значение ALPN: {token}")
        if token not in unique:
            unique.append(token)
    if len(unique) > 8:
        raise ValueError("можно указать не более восьми значений ALPN")
    return ",".join(unique)



def _first_link_query_value(query: dict[str, list[str]], *names: str) -> str:
    for name in names:
        values = query.get(name)
        if values:
            return str(values[0]).strip()
    return ""


def _suggest_outbound_tag(label: str, address: str) -> str:
    label = unquote(label or "").strip()
    tag_label = re.sub(r"/(?:Primary|Backup|Alt|#\d+)$", "", label, flags=re.IGNORECASE).strip()
    cascade_match = re.search(
        r"(?:^|[^a-z0-9])cascade(?:[^a-z0-9]+.*)?(?:-to-|\s+to\s+)([a-z0-9._-]+)$",
        tag_label.lower(),
    )
    if cascade_match:
        candidate = f"cascade-{cascade_match.group(1)}"
    else:
        source = tag_label or address or "vless-exit"
        candidate = re.sub(r"[^A-Za-z0-9._-]+", "-", source).strip("-._").lower()
    if not candidate:
        candidate = "vless-exit"
    if not candidate[0].isalnum():
        candidate = f"vless-{candidate}"
    candidate = candidate[:64].rstrip("-._") or "vless-exit"
    if candidate in RESERVED_OUTBOUND_TAGS:
        candidate = f"{candidate}-exit"
    return candidate


def parse_vless_share_link(link: str) -> dict[str, object]:
    """Parse a VLESS share link into values accepted by the outbound form.

    The link is only decoded and validated. It is not written to the database.
    """
    source = str(link or "").strip()
    if not source:
        raise ValueError("вставьте VLESS-ссылку")
    if len(source) > 16384:
        raise ValueError("VLESS-ссылка слишком длинная")

    parsed = urlparse(source)
    if parsed.scheme.lower() != "vless":
        raise ValueError("поддерживаются только ссылки, начинающиеся с vless://")
    user_uuid = unquote(parsed.username or "").strip()
    address = str(parsed.hostname or "").strip()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("в VLESS-ссылке указан некорректный порт") from exc
    if not user_uuid:
        raise ValueError("в VLESS-ссылке не найден UUID")
    if not address:
        raise ValueError("в VLESS-ссылке не найден адрес сервера")
    if port is None:
        raise ValueError("в VLESS-ссылке не найден порт сервера")

    try:
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=64)
    except ValueError as exc:
        raise ValueError("не удалось разобрать параметры VLESS-ссылки") from exc

    network_value = _first_link_query_value(query, "type", "network").lower() or "tcp"
    if network_value in {"tcp", "raw"}:
        network = "raw"
    elif network_value == "xhttp":
        network = "xhttp"
    else:
        raise ValueError(
            f"транспорт {network_value or 'не указан'} пока не поддерживается; "
            "нужен RAW/TCP или XHTTP"
        )

    security = _first_link_query_value(query, "security").lower() or "reality"
    if security not in ALLOWED_OUTBOUND_SECURITY:
        raise ValueError("в ссылке должна использоваться защита REALITY или TLS")

    label = unquote(parsed.fragment or "").strip()
    fingerprint = _first_link_query_value(query, "fp", "fingerprint") or "firefox"
    flow = _first_link_query_value(query, "flow")
    if network == "xhttp":
        flow = ""

    public_key = _first_link_query_value(query, "pbk", "publicKey", "public_key")
    short_id = _first_link_query_value(query, "sid", "shortId", "short_id")
    spider_x = _first_link_query_value(query, "spx", "spiderX")
    if security == "reality" and not spider_x:
        spider_x = "/"

    allow_insecure_value = _first_link_query_value(query, "allowInsecure", "insecure").lower()
    allow_insecure = allow_insecure_value in {"1", "true", "yes", "on"}
    alpn = _first_link_query_value(query, "alpn")

    suggested_name = label or f"VLESS через {address}"
    suggested_tag = _suggest_outbound_tag(label, address)
    values = validate_vless_outbound_values(
        tag=suggested_tag,
        name=suggested_name,
        address=address,
        port=int(port),
        user_uuid=user_uuid,
        flow=flow,
        network=network,
        security=security,
        server_name=_first_link_query_value(query, "sni", "serverName", "servername"),
        public_key=public_key,
        short_id=short_id,
        fingerprint=fingerprint,
        spider_x=spider_x,
        xhttp_host=_first_link_query_value(query, "host"),
        xhttp_path=_first_link_query_value(query, "path") or "/",
        xhttp_mode=_first_link_query_value(query, "mode") or "auto",
        allow_insecure=allow_insecure,
        alpn=alpn,
    )
    values["source_label"] = label
    values["transport_label"] = "RAW / TCP" if network == "raw" else "XHTTP"
    values["security_label"] = security.upper()
    values["vision"] = values["flow"] in {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}
    return values


def validate_vless_outbound_values(
    *,
    tag: str,
    name: str,
    address: str,
    port: int,
    user_uuid: str,
    flow: str = "xtls-rprx-vision",
    network: str = "raw",
    security: str = "reality",
    server_name: str,
    public_key: str = "",
    short_id: str = "",
    fingerprint: str = "firefox",
    spider_x: str = "",
    xhttp_host: str = "",
    xhttp_path: str = "/",
    xhttp_mode: str = "auto",
    allow_insecure: bool = False,
    alpn: str = "",
) -> dict[str, object]:
    tag = _validate_outbound_tag(tag)
    name = name.strip()
    address = address.strip()
    flow = flow.strip()
    network = network.strip().lower() or "raw"
    security = security.strip().lower() or "reality"
    server_name = server_name.strip()
    public_key = public_key.strip()
    short_id = short_id.strip().lower()
    fingerprint = normalise_fingerprint_profile(fingerprint)
    spider_x = spider_x.strip()
    xhttp_host = xhttp_host.strip()
    xhttp_path = xhttp_path.strip() or "/"
    xhttp_mode = xhttp_mode.strip().lower() or "auto"
    allow_insecure = bool(allow_insecure)
    alpn = _normalise_alpn(alpn)

    if not name:
        raise ValueError("название outbound не может быть пустым")
    if not address:
        raise ValueError("адрес удалённого Xray-сервера не может быть пустым")
    if not 1 <= int(port) <= 65535:
        raise ValueError("порт должен быть от 1 до 65535")
    try:
        uuidlib.UUID(user_uuid.strip())
    except ValueError as exc:
        raise ValueError("некорректный UUID удалённого сервера") from exc
    if flow not in ALLOWED_FLOWS:
        raise ValueError("неподдерживаемый flow")
    if network not in ALLOWED_OUTBOUND_NETWORKS:
        raise ValueError("поддерживаются только транспорты RAW/TCP и XHTTP")
    if security not in ALLOWED_OUTBOUND_SECURITY:
        raise ValueError("поддерживаются только REALITY и TLS")
    if (network, security) not in SUPPORTED_VLESS_OUTBOUND_COMBINATIONS:
        raise ValueError(
            "эта комбинация пока не поддерживается; используйте "
            "RAW/TCP + REALITY, XHTTP + TLS или XHTTP + REALITY"
        )
    if not server_name:
        raise ValueError("Server name / SNI не может быть пустым")

    if network == "xhttp":
        if flow:
            raise ValueError("для XHTTP поле Flow должно быть none")
        if xhttp_mode not in ALLOWED_XHTTP_MODES:
            raise ValueError("неподдерживаемый режим XHTTP")
        if not xhttp_path.startswith("/"):
            raise ValueError("XHTTP path должен начинаться с /")
        if any(char.isspace() for char in xhttp_path):
            raise ValueError("XHTTP path не должен содержать пробелы")
        if len(xhttp_path) > 512:
            raise ValueError("XHTTP path слишком длинный")
        if xhttp_host and ("/" in xhttp_host or any(char.isspace() for char in xhttp_host)):
            raise ValueError("XHTTP host должен быть доменным именем без схемы и пути")
    else:
        xhttp_host = ""
        xhttp_path = "/"
        xhttp_mode = "auto"

    if security == "reality":
        if not public_key:
            raise ValueError("Reality password/public key не может быть пустым")
        if short_id and (not re.fullmatch(r"[0-9a-f]{2,16}", short_id) or len(short_id) % 2):
            raise ValueError("shortId должен содержать чётное число hex-символов, максимум 16")
        allow_insecure = False
        alpn = ""
    else:
        public_key = ""
        short_id = ""
        spider_x = ""

    return {
        "tag": tag,
        "name": name,
        "address": address,
        "port": int(port),
        "uuid": user_uuid.strip(),
        "flow": flow,
        "network": network,
        "security": security,
        "server_name": server_name,
        "public_key": public_key,
        "short_id": short_id,
        "fingerprint": fingerprint,
        "spider_x": spider_x,
        "xhttp_host": xhttp_host,
        "xhttp_path": xhttp_path,
        "xhttp_mode": xhttp_mode,
        "allow_insecure": int(allow_insecure),
        "alpn": alpn,
    }


def _json_object(value: str | None) -> dict[str, object]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _copy_json_object(value: dict[str, object] | None) -> dict[str, object]:
    return json.loads(json.dumps(value or {}, ensure_ascii=False))


def _deep_merge_json(base: object, overlay: object) -> object:
    if isinstance(base, dict) and isinstance(overlay, dict):
        result = _copy_json_object(base)
        for key, value in overlay.items():
            result[key] = _deep_merge_json(result.get(key), value)
        return result
    return json.loads(json.dumps(overlay, ensure_ascii=False))


def _strip_sgpanel_metadata(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _strip_sgpanel_metadata(item)
            for key, item in value.items()
            if key != "_sgPanel"
        }
    if isinstance(value, list):
        result: list[object] = []
        for item in value:
            if isinstance(item, dict):
                meta = item.get("_sgPanel")
                if isinstance(meta, dict) and meta.get("enabled") is False:
                    continue
            result.append(_strip_sgpanel_metadata(item))
        return result
    return value


def get_config_base_document() -> dict[str, object]:
    init_db()
    with connect() as con:
        row = con.execute("SELECT document_json FROM config_settings WHERE id = 1").fetchone()
    if row is None or not row["document_json"]:
        return {}
    return _json_object(row["document_json"])


def _set_config_base_document(con: sqlite3.Connection, document: dict[str, object]) -> None:
    con.execute(
        """
        INSERT INTO config_settings (id, document_json, updated_at)
        VALUES (1, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            document_json = excluded.document_json,
            updated_at = CURRENT_TIMESTAMP
        """,
        (json.dumps(document, ensure_ascii=False, separators=(",", ":")),),
    )


def _merge_outbound_config(
    base: dict[str, object] | None, cleaned: dict[str, object]
) -> dict[str, object]:
    """Update fields managed by the form while preserving unknown Xray options."""
    result = _copy_json_object(base)
    result["tag"] = cleaned["tag"]
    result["protocol"] = "vless"

    settings = result.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    vnext = settings.get("vnext")
    if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
        server = dict(vnext[0])
        server["address"] = cleaned["address"]
        server["port"] = cleaned["port"]
        users = server.get("users")
        users = list(users) if isinstance(users, list) else []
        user = dict(users[0]) if users and isinstance(users[0], dict) else {}
        user["id"] = cleaned["uuid"]
        user["encryption"] = "none"
        user.setdefault("level", 0)
        if cleaned["flow"]:
            user["flow"] = cleaned["flow"]
        else:
            user.pop("flow", None)
        users = [user, *users[1:]]
        server["users"] = users
        settings["vnext"] = [server, *vnext[1:]]
        for key in ("address", "port", "id", "encryption", "level", "flow"):
            settings.pop(key, None)
    else:
        settings.update(
            {
                "address": cleaned["address"],
                "port": cleaned["port"],
                "id": cleaned["uuid"],
                "encryption": "none",
                "level": 0,
            }
        )
        if cleaned["flow"]:
            settings["flow"] = cleaned["flow"]
        else:
            settings.pop("flow", None)
    result["settings"] = settings

    stream = result.get("streamSettings")
    stream = stream if isinstance(stream, dict) else {}
    network = str(cleaned["network"])
    security = str(cleaned["security"])
    stream["network"] = network
    stream["security"] = security

    if network == "xhttp":
        xhttp = stream.get("xhttpSettings")
        xhttp = xhttp if isinstance(xhttp, dict) else {}
        xhttp["path"] = cleaned["xhttp_path"] or "/"
        mode = str(cleaned["xhttp_mode"] or "auto")
        if mode == "auto":
            xhttp.pop("mode", None)
        else:
            xhttp["mode"] = mode
        if cleaned["xhttp_host"]:
            xhttp["host"] = cleaned["xhttp_host"]
        else:
            xhttp.pop("host", None)
        stream["xhttpSettings"] = xhttp
    else:
        stream.pop("xhttpSettings", None)

    if security == "reality":
        reality = stream.get("realitySettings")
        reality = reality if isinstance(reality, dict) else {}
        reality.update(
            {
                "serverName": cleaned["server_name"],
                "fingerprint": fingerprint_for_xray(str(cleaned["fingerprint"])),
                "password": cleaned["public_key"],
                "shortId": cleaned["short_id"],
                "spiderX": cleaned["spider_x"],
            }
        )
        stream["realitySettings"] = reality
        stream.pop("tlsSettings", None)
    else:
        tls = stream.get("tlsSettings")
        tls = tls if isinstance(tls, dict) else {}
        tls.update(
            {
                "serverName": cleaned["server_name"],
                "fingerprint": fingerprint_for_xray(str(cleaned["fingerprint"])),
                "allowInsecure": bool(cleaned["allow_insecure"]),
            }
        )
        alpn = [item for item in str(cleaned["alpn"] or "").split(",") if item]
        if alpn:
            tls["alpn"] = alpn
        else:
            tls.pop("alpn", None)
        stream["tlsSettings"] = tls
        stream.pop("realitySettings", None)
    result["streamSettings"] = stream
    return result


def outbound_json_document(row: sqlite3.Row | None = None) -> str:
    if row is None:
        document: dict[str, object] = {
            "_sgPanel": {"name": "Европейский сервер", "enabled": True},
            "tag": "eu-exit",
            "protocol": "vless",
            "settings": {
                "address": "eu.example.com",
                "port": 443,
                "id": "00000000-0000-4000-8000-000000000000",
                "encryption": "none",
                "level": 0,
                "flow": "xtls-rprx-vision",
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.bing.com",
                    "fingerprint": "firefox",
                    "password": "PUBLIC_KEY",
                    "shortId": "0123456789abcdef",
                    "spiderX": "",
                },
            },
        }
    else:
        document = build_outbound_json(row)
        document = {
            "_sgPanel": {"name": row["name"], "enabled": bool(row["enabled"])},
            **document,
        }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def parse_outbound_json_document(
    text: str, *, fallback_name: str = ""
) -> tuple[dict[str, object], dict[str, object], bool]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ValueError("JSON выхода должен быть объектом")
    document = _copy_json_object(document)
    meta = document.pop("_sgPanel", {})
    meta = meta if isinstance(meta, dict) else {}
    if str(document.get("protocol", "")).lower() != "vless":
        raise ValueError("пока JSON-редактор поддерживает только protocol: vless")
    tag = str(document.get("tag", ""))
    settings = document.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("settings должен быть JSON-объектом")

    source = settings
    user = settings
    vnext = settings.get("vnext")
    if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
        source = vnext[0]
        users = source.get("users")
        if not isinstance(users, list) or not users or not isinstance(users[0], dict):
            raise ValueError("settings.vnext[0].users[0] не найден")
        user = users[0]

    stream = document.get("streamSettings")
    if not isinstance(stream, dict):
        raise ValueError("streamSettings должен быть JSON-объектом")
    network = str(stream.get("network", "raw")).lower()
    if network == "tcp":
        network = "raw"
    security = str(stream.get("security", "reality")).lower()
    xhttp = stream.get("xhttpSettings")
    xhttp = xhttp if isinstance(xhttp, dict) else {}
    reality = stream.get("realitySettings")
    reality = reality if isinstance(reality, dict) else {}
    tls = stream.get("tlsSettings")
    tls = tls if isinstance(tls, dict) else {}
    security_settings = reality if security == "reality" else tls
    alpn_value = tls.get("alpn", [])
    if isinstance(alpn_value, list):
        alpn = ",".join(str(item) for item in alpn_value)
    else:
        alpn = str(alpn_value or "")

    cleaned = validate_vless_outbound_values(
        tag=tag,
        name=str(meta.get("name") or fallback_name or tag),
        address=str(source.get("address", "")),
        port=int(source.get("port", 0) or 0),
        user_uuid=str(user.get("id", "")),
        flow=str(user.get("flow", settings.get("flow", "")) or ""),
        network=network,
        security=security,
        server_name=str(security_settings.get("serverName", "")),
        public_key=str(
            reality.get("password", reality.get("publicKey", reality.get("public_key", "")))
        ),
        short_id=str(reality.get("shortId", "")),
        fingerprint=str(security_settings.get("fingerprint", "firefox")),
        spider_x=str(reality.get("spiderX", "")),
        xhttp_host=str(xhttp.get("host", "")),
        xhttp_path=str(xhttp.get("path", "/")),
        xhttp_mode=str(xhttp.get("mode", "auto")),
        allow_insecure=bool(tls.get("allowInsecure", False)),
        alpn=alpn,
    )
    enabled = bool(meta.get("enabled", True))
    normalised = _merge_outbound_config(document, cleaned)
    return cleaned, normalised, enabled


def _insert_vless_outbound(
    cleaned: dict[str, object], *, enabled: bool, config: dict[str, object]
) -> sqlite3.Row:
    try:
        with connect() as con:
            cur = con.execute(
                """
                INSERT INTO outbounds (
                    tag, name, type, enabled, address, port, uuid, flow,
                    network, security, server_name, public_key, short_id,
                    fingerprint, spider_x, xhttp_host, xhttp_path, xhttp_mode,
                    allow_insecure, alpn, config_json
                ) VALUES (?, ?, 'vless_reality', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned["tag"], cleaned["name"], int(enabled), cleaned["address"],
                    cleaned["port"], cleaned["uuid"], cleaned["flow"],
                    cleaned["network"], cleaned["security"], cleaned["server_name"],
                    cleaned["public_key"], cleaned["short_id"], cleaned["fingerprint"],
                    cleaned["spider_x"], cleaned["xhttp_host"], cleaned["xhttp_path"],
                    cleaned["xhttp_mode"], cleaned["allow_insecure"], cleaned["alpn"],
                    json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            outbound_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("outbound с таким tag уже существует") from exc
    return find_outbound(outbound_id)


def add_vless_outbound(**values) -> sqlite3.Row:
    cleaned = validate_vless_outbound_values(**values)
    return _insert_vless_outbound(
        cleaned, enabled=True, config=_merge_outbound_config({}, cleaned)
    )


def add_vless_outbound_json(text: str) -> sqlite3.Row:
    cleaned, config, enabled = parse_outbound_json_document(text)
    return _insert_vless_outbound(cleaned, enabled=enabled, config=config)


def _update_vless_outbound_record(
    outbound_id: int,
    cleaned: dict[str, object],
    *,
    enabled: bool,
    config: dict[str, object],
) -> sqlite3.Row:
    current = find_outbound(outbound_id)
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE outbounds SET
                    tag = ?, name = ?, enabled = ?, address = ?, port = ?, uuid = ?, flow = ?,
                    network = ?, security = ?, server_name = ?, public_key = ?,
                    short_id = ?, fingerprint = ?, spider_x = ?, xhttp_host = ?,
                    xhttp_path = ?, xhttp_mode = ?, allow_insecure = ?, alpn = ?,
                    config_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    cleaned["tag"], cleaned["name"], int(enabled), cleaned["address"],
                    cleaned["port"], cleaned["uuid"], cleaned["flow"], cleaned["network"],
                    cleaned["security"], cleaned["server_name"], cleaned["public_key"],
                    cleaned["short_id"], cleaned["fingerprint"], cleaned["spider_x"],
                    cleaned["xhttp_host"], cleaned["xhttp_path"], cleaned["xhttp_mode"],
                    cleaned["allow_insecure"], cleaned["alpn"],
                    json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                    outbound_id,
                ),
            )
            if cleaned["tag"] != current["tag"]:
                con.execute(
                    "UPDATE routing_rules SET outbound_tag = ?, updated_at = CURRENT_TIMESTAMP WHERE target_type = 'outbound' AND outbound_tag = ?",
                    (cleaned["tag"], current["tag"]),
                )
                con.execute(
                    "UPDATE routing_settings SET default_outbound_tag = ?, updated_at = CURRENT_TIMESTAMP WHERE default_outbound_tag = ?",
                    (cleaned["tag"], current["tag"]),
                )
    except sqlite3.IntegrityError as exc:
        raise XPanelError("outbound с таким tag уже существует") from exc
    return find_outbound(outbound_id)


def update_vless_outbound(outbound_id: int, **values) -> sqlite3.Row:
    current = find_outbound(outbound_id)
    cleaned = validate_vless_outbound_values(**values)
    base = _json_object(current["config_json"])
    return _update_vless_outbound_record(
        outbound_id,
        cleaned,
        enabled=bool(current["enabled"]),
        config=_merge_outbound_config(base, cleaned),
    )


def update_vless_outbound_json(outbound_id: int, text: str) -> sqlite3.Row:
    current = find_outbound(outbound_id)
    cleaned, config, enabled = parse_outbound_json_document(
        text, fallback_name=str(current["name"])
    )
    return _update_vless_outbound_record(
        outbound_id, cleaned, enabled=enabled, config=config
    )

def set_outbound_enabled(outbound_id: int, enabled: bool) -> sqlite3.Row:
    outbound = find_outbound(outbound_id)
    if not enabled:
        settings = get_routing_settings()
        if settings["default_outbound_tag"] == outbound["tag"]:
            raise XPanelError("сначала выберите другой outbound по умолчанию")
        with connect() as con:
            used = con.execute(
                "SELECT COUNT(*) FROM routing_rules WHERE enabled = 1 AND target_type = 'outbound' AND outbound_tag = ?",
                (outbound["tag"],),
            ).fetchone()[0]
        if used:
            raise XPanelError("outbound используется активными routing rules")
    with connect() as con:
        con.execute(
            "UPDATE outbounds SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (int(enabled), outbound_id),
        )
    return find_outbound(outbound_id)


def delete_outbound(outbound_id: int) -> sqlite3.Row:
    outbound = find_outbound(outbound_id)
    settings = get_routing_settings()
    if settings["default_outbound_tag"] == outbound["tag"]:
        raise XPanelError("нельзя удалить outbound по умолчанию")
    with connect() as con:
        used = con.execute(
            "SELECT COUNT(*) FROM routing_rules WHERE target_type = 'outbound' AND outbound_tag = ?",
            (outbound["tag"],),
        ).fetchone()[0]
        if used:
            raise XPanelError("сначала измените или удалите routing rules, использующие этот outbound")
        con.execute("DELETE FROM outbounds WHERE id = ?", (outbound_id,))
    return outbound


def test_outbound_tcp(outbound_id: int, *, timeout: float = 4.0) -> dict[str, object]:
    outbound = find_outbound(outbound_id)
    started = time.monotonic()
    try:
        with socket.create_connection((outbound["address"], outbound["port"]), timeout=timeout):
            latency_ms = round((time.monotonic() - started) * 1000, 1)
            return {"ok": True, "latency_ms": latency_ms, "detail": "TCP port reachable"}
    except OSError as exc:
        return {"ok": False, "latency_ms": None, "detail": str(exc)}


def build_outbound_json(row: sqlite3.Row) -> dict[str, object]:
    cleaned: dict[str, object] = {
        "tag": row["tag"],
        "name": row["name"],
        "address": row["address"],
        "port": row["port"],
        "uuid": row["uuid"],
        "flow": row["flow"],
        "network": row["network"] or "raw",
        "security": row["security"] or "reality",
        "server_name": row["server_name"],
        "public_key": row["public_key"],
        "short_id": row["short_id"],
        "fingerprint": row["fingerprint"],
        "spider_x": row["spider_x"],
        "xhttp_host": row["xhttp_host"],
        "xhttp_path": row["xhttp_path"] or "/",
        "xhttp_mode": row["xhttp_mode"] or "auto",
        "allow_insecure": int(row["allow_insecure"]),
        "alpn": row["alpn"],
    }
    return _merge_outbound_config(_json_object(row["config_json"]), cleaned)




def _cascade_signature(outbound: sqlite3.Row) -> str:
    payload = {
        "id": int(outbound["id"]),
        "tag": str(outbound["tag"]),
        "enabled": int(outbound["enabled"]),
        "address": str(outbound["address"]),
        "port": int(outbound["port"]),
        "uuid": str(outbound["uuid"]),
        "flow": str(outbound["flow"]),
        "network": str(outbound["network"]),
        "security": str(outbound["security"]),
        "server_name": str(outbound["server_name"]),
        "public_key": str(outbound["public_key"]),
        "short_id": str(outbound["short_id"]),
        "fingerprint": str(outbound["fingerprint"]),
        "spider_x": str(outbound["spider_x"]),
        "xhttp_host": str(outbound["xhttp_host"]),
        "xhttp_path": str(outbound["xhttp_path"]),
        "xhttp_mode": str(outbound["xhttp_mode"]),
        "allow_insecure": int(outbound["allow_insecure"]),
        "alpn": str(outbound["alpn"]),
        "config_json": str(outbound["config_json"]),
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _cascade_settings_row() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM cascade_settings WHERE id = 1").fetchone()
    if row is None:
        raise XPanelError("настройки каскада не инициализированы")
    return row


def _cascade_candidate_outbound(settings: sqlite3.Row | None = None) -> sqlite3.Row | None:
    settings = settings or _cascade_settings_row()
    outbound_id = int(settings["outbound_id"] or 0)
    if outbound_id:
        try:
            return find_outbound(outbound_id)
        except XPanelError:
            pass

    routing = get_routing_settings()
    default_tag = str(routing["default_outbound_tag"] or "")
    rows = list_custom_outbounds()
    for row in rows:
        tag = str(row["tag"])
        name = str(row["name"])
        if (
            tag == default_tag
            and default_tag not in RESERVED_OUTBOUND_TAGS
            and (tag.lower().startswith("cascade-") or "cascade" in name.lower() or "каскад" in name.lower())
        ):
            return row
    for row in rows:
        tag = str(row["tag"])
        name = str(row["name"])
        if tag.lower().startswith("cascade-") or "cascade" in name.lower() or "каскад" in name.lower():
            return row
    return None


def _cascade_exit_name_from_label(label: str, address: str) -> str:
    value = unquote(str(label or "")).strip()
    value = re.sub(r"/(?:Primary|Backup|Alt|#\d+)$", "", value, flags=re.IGNORECASE).strip()
    value = re.sub(r"^Cascade\s*[·:|-]\s*", "", value, flags=re.IGNORECASE).strip()
    return value or str(address or "Выходной сервер")


def _cascade_service_access() -> dict[str, object]:
    settings = _cascade_settings_row()
    user_id = int(settings["service_user_id"] or 0)
    result: dict[str, object] = {
        "configured": False, "ready": False, "user_id": 0, "link": "",
        "error": "", "name": "",
    }
    if not user_id:
        return result
    try:
        user = find_user(user_id)
    except XPanelError:
        return result
    result.update({"configured": True, "user_id": user_id, "name": str(user["name"])})
    try:
        server = get_server()
        user = find_user(user_id)
        links = _make_links_for_profile(user, server, "raw_reality")
        link = next((str(item["link"]) for item in links if item.get("kind") == "reality"), "")
        if not link:
            raise XPanelError("не удалось сформировать VLESS REALITY-ссылку")
        result.update({"ready": True, "link": link})
    except (ValueError, XPanelError, FileNotFoundError, OSError) as exc:
        result["error"] = str(exc)
    return result


def ensure_cascade_service_access() -> dict[str, object]:
    # Every SG-Panel publishes the managed Reality TCP channel. The user does
    # not need to switch the visible Xray Server profile before creating the
    # private server-to-server Cascade link.
    settings = _cascade_settings_row()
    user_id = int(settings["service_user_id"] or 0)
    user = None
    if user_id:
        try:
            user = find_user(user_id)
        except XPanelError:
            user = None
    if user is None:
        for candidate in list_users():
            if str(candidate["comment"] or "") == CASCADE_SERVICE_COMMENT:
                user = candidate
                break
    desired = f"Cascade · {get_instance_name()}"[:80]
    if user is None:
        base = desired
        names = {str(item["name"]).casefold() for item in list_users()}
        number = 2
        while desired.casefold() in names:
            suffix = f" {number}"
            desired = base[: 80 - len(suffix)] + suffix
            number += 1
        user = add_user(desired, comment=CASCADE_SERVICE_COMMENT)
    else:
        if not bool(user["enabled"]):
            user = set_user_enabled(int(user["id"]), True)
        if str(user["comment"] or "") != CASCADE_SERVICE_COMMENT or str(user["name"]) != desired:
            collision = next(
                (item for item in list_users() if int(item["id"]) != int(user["id"]) and str(item["name"]).casefold() == desired.casefold()),
                None,
            )
            if collision is None:
                user = update_user(
                    int(user["id"]), name=desired, user_uuid=str(user["uuid"]),
                    comment=CASCADE_SERVICE_COMMENT, expiry_at=user["expiry_at"],
                )
    with connect() as con:
        con.execute(
            "UPDATE cascade_settings SET service_user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            (int(user["id"]),),
        )
    access = _cascade_service_access()
    if not access["ready"]:
        raise XPanelError(str(access["error"] or "не удалось создать доступ Cascade"))
    return access



CASCADE_NODE_WORKER_MINIMUM = (0, 7, 0)
CASCADE_NODE_ACCESS_STATE = Path(os.environ.get("SG_NODE_CASCADE_STATE", "/var/lib/sg-node/cascade-access.json"))
CASCADE_NODE_INBOUND_TAG = "sg-cascade-reality-in"


def _inject_persistent_node_cascade_access(config: dict[str, object]) -> dict[str, object]:
    """Keep Controller-managed Cascade access across local SG-Panel applies."""
    if not CASCADE_NODE_ACCESS_STATE.is_file():
        return config
    try:
        state = json.loads(CASCADE_NODE_ACCESS_STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise XPanelError(f"не удалось прочитать состояние Node Cascade: {exc}") from exc
    if not isinstance(state, dict) or str(state.get("format") or "") != "sg-cascade-access-v1":
        raise XPanelError("состояние Node Cascade имеет неизвестный формат")
    try:
        service_uuid = str(uuidlib.UUID(str(state.get("service_uuid") or "")))
        port = int(state.get("port") or 0)
    except (ValueError, TypeError) as exc:
        raise XPanelError("состояние Node Cascade содержит некорректные UUID или порт") from exc
    if not 1 <= port <= 65535:
        raise XPanelError("состояние Node Cascade содержит некорректный порт")
    mode = str(state.get("mode") or "dedicated")
    if mode not in {"reuse", "dedicated"}:
        raise XPanelError("состояние Node Cascade содержит неизвестный режим")
    controller = str(state.get("controller") or "Controller")[:64]
    service_email = str(state.get("service_email") or f"Cascade · {controller}")[:100]

    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise XPanelError("config.inbounds должен быть массивом")
    cleaned: list[object] = []
    for inbound in inbounds:
        if isinstance(inbound, dict) and str(inbound.get("tag") or "") == CASCADE_NODE_INBOUND_TAG:
            continue
        if isinstance(inbound, dict):
            settings = inbound.get("settings")
            if isinstance(settings, dict) and isinstance(settings.get("clients"), list):
                settings["clients"] = [
                    client for client in settings["clients"]
                    if not (
                        isinstance(client, dict)
                        and (
                            str(client.get("id") or "") == service_uuid
                            or str(client.get("email") or "") == service_email
                        )
                    )
                ]
        cleaned.append(inbound)
    inbounds[:] = cleaned

    selected: dict[str, object] | None = None
    if mode == "reuse":
        inbound_tag = str(state.get("inbound_tag") or "").strip()
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            if inbound_tag and str(inbound.get("tag") or "") != inbound_tag:
                continue
            if int(inbound.get("port") or 0) != port or str(inbound.get("protocol") or "") != "vless":
                continue
            stream = inbound.get("streamSettings")
            settings = inbound.get("settings")
            if not isinstance(stream, dict) or not isinstance(settings, dict):
                continue
            if str(stream.get("network") or "tcp") not in {"tcp", "raw"} or str(stream.get("security") or "") != "reality":
                continue
            if not isinstance(settings.get("clients"), list):
                continue
            selected = inbound
            break
        if selected is None:
            raise XPanelError("Reality TCP Inbound для сохранённого Node Cascade больше не найден")
    else:
        target = str(state.get("target") or "").strip()
        server_name = str(state.get("server_name") or "").strip()
        private_key = str(state.get("private_key") or "").strip()
        short_id = str(state.get("short_id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+:[0-9]{1,5}", target):
            raise XPanelError("состояние Node Cascade содержит некорректный Reality target")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", server_name):
            raise XPanelError("состояние Node Cascade содержит некорректный serverName")
        if not re.fullmatch(r"[A-Za-z0-9_-]{30,80}", private_key):
            raise XPanelError("состояние Node Cascade содержит некорректный private key")
        if not re.fullmatch(r"[0-9a-f]{2,32}", short_id):
            raise XPanelError("состояние Node Cascade содержит некорректный short ID")
        occupied = {
            int(item.get("port") or 0)
            for item in inbounds
            if isinstance(item, dict) and str(item.get("port") or "").isdigit()
        }
        if port in occupied:
            raise XPanelError(f"служебный порт Cascade {port} занят другим Inbound")
        selected = {
            "tag": CASCADE_NODE_INBOUND_TAG,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": target,
                    "xver": 0,
                    "serverNames": [server_name],
                    "privateKey": private_key,
                    "shortIds": [short_id],
                },
            },
        }
        inbounds.append(selected)

    settings = selected.get("settings") if isinstance(selected, dict) else None
    clients = settings.get("clients") if isinstance(settings, dict) else None
    if not isinstance(clients, list):
        raise XPanelError("Reality TCP Inbound для Node Cascade не содержит clients")
    clients.append({
        "id": service_uuid,
        "email": service_email,
        "flow": "xtls-rprx-vision",
        "level": 0,
    })

    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise XPanelError("config.outbounds должен быть массивом")
    direct = next((item for item in outbounds if isinstance(item, dict) and str(item.get("tag") or "") == "direct"), None)
    if direct is None:
        outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    elif str(direct.get("protocol") or "") != "freedom":
        raise XPanelError("outbound direct должен использовать freedom для Node Cascade")

    routing = config.get("routing")
    if not isinstance(routing, dict):
        routing = {"domainStrategy": "AsIs", "rules": []}
        config["routing"] = routing
    rules = routing.get("rules")
    if not isinstance(rules, list):
        rules = []
        routing["rules"] = rules
    rules[:] = [
        rule for rule in rules
        if not (
            isinstance(rule, dict)
            and (
                (
                    isinstance(rule.get("inboundTag"), list)
                    and CASCADE_NODE_INBOUND_TAG in [str(value) for value in rule.get("inboundTag", [])]
                )
                or (
                    isinstance(rule.get("user"), list)
                    and service_email in [str(value) for value in rule.get("user", [])]
                )
            )
        )
    ]
    rules.insert(0, {"type": "field", "user": [service_email], "outboundTag": "direct"})
    return config


def _node_worker_version_tuple(value: object) -> tuple[int, int, int]:
    numbers = [int(item) for item in re.findall(r"\d+", str(value or ""))[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _cluster_cascade_node(node_id: int) -> dict[str, object]:
    from .node_manager import find_node, list_node_jobs

    node = find_node(int(node_id))
    if bool(node.get("is_local")):
        raise XPanelError("для Cluster Cascade выберите подключённую SG-Node, а не Controller")
    if str(node.get("effective_state") or node.get("state") or "") != "online":
        raise XPanelError("выходная SG-Node должна быть в сети")
    if not str(node.get("public_address") or "").strip():
        raise XPanelError("у SG-Node не определён публичный адрес")
    worker_version = str(node.get("worker_version") or "").strip()
    if _node_worker_version_tuple(worker_version) < CASCADE_NODE_WORKER_MINIMUM:
        shown = worker_version or "не определена"
        raise XPanelError(
            "На SG-Node установлен старый Worker " + shown
            + ". Установите UI19 на этой ноде тем же обновлением и повторите один раз."
        )
    active = [
        job for job in list_node_jobs(int(node_id), limit=100)
        if str(job.get("status") or "") in {"queued", "running"}
    ]
    if active:
        raise XPanelError("на выбранной SG-Node уже выполняется другое задание")
    return node


def _cluster_cascade_link(values: dict[str, object], service_uuid: str, exit_name: str) -> str:
    address = str(values.get("address") or "").strip()
    port = int(values.get("public_port") or values.get("port") or 0)
    public_key = str(values.get("public_key") or "").strip()
    short_id = str(values.get("short_id") or "").strip()
    server_name = str(values.get("server_name") or "").strip()
    if not address or not 1 <= port <= 65535:
        raise XPanelError("SG-Node не вернула адрес и порт служебного профиля")
    if not public_key or not short_id or not server_name:
        raise XPanelError("SG-Node не вернула параметры REALITY служебного профиля")
    query = [
        "type=tcp",
        "security=reality",
        f"pbk={quote(public_key, safe='-_')}",
        f"fp={quote(str(values.get('fingerprint') or 'firefox'), safe='-_')}",
        f"sni={quote(server_name, safe='')}",
        f"sid={quote(short_id, safe='')}",
        f"flow={quote(str(values.get('flow') or 'xtls-rprx-vision'), safe='-_')}",
        f"spx={quote(str(values.get('spider_x') or '/'), safe='')}",
    ]
    label = quote(f"Cascade · {get_instance_name()} → {exit_name}", safe="")
    return f"vless://{service_uuid}@{address}:{port}?{'&'.join(query)}#{label}"


def connect_cascade_cluster_node(node_id: int, *, dry_run: bool = False) -> dict[str, object]:
    """Queue one safe local-merge operation on a managed SG-Node.

    The Controller never sends the node's complete Xray config. Worker UI19
    reads the live file locally, merges only a dedicated Cascade inbound, tests
    the complete future config and rolls back on failure.
    """
    from .node_manager import create_node_job

    settings = _cascade_settings_row()
    current_node_id = int(settings["exit_node_id"] or 0)
    current_job_id = int(settings["cluster_service_job_id"] or 0)
    if (
        str(settings["mode"] or "") == "cluster"
        and current_node_id == int(node_id)
        and int(settings["outbound_id"] or 0)
    ):
        overview = get_cascade_overview()
        if overview.get("configured"):
            overview["already_configured"] = True
            return overview
    node = _cluster_cascade_node(int(node_id))
    existing_uuid = str(settings["cluster_service_uuid"] or "").strip()
    service_uuid = existing_uuid if existing_uuid and current_node_id == int(node_id) else str(uuidlib.uuid4())
    exit_name = str(node.get("name") or node.get("public_address") or "SG-Node")
    server = get_server()
    target = str(server["dest"] or "www.bing.com:443").strip()
    server_name = target.rsplit(":", 1)[0].strip() if ":" in target else "www.bing.com"
    payload = {
        "worker_operation": "upsert_cascade_access",
        "action": "upsert",
        "service_uuid": service_uuid,
        "controller": get_instance_name(),
        "target": target,
        "server_name": server_name,
        "preferred_ports": [64441, 64442, 64443, 64444, 64445],
        "preserve_live_config": True,
    }
    if dry_run:
        return {"node": node, "service_uuid": service_uuid, "payload": payload}

    job = create_node_job(
        int(node_id),
        job_type="apply_xray_config",
        title=f"Cascade exit · {get_instance_name()}",
        payload=payload,
    )
    with connect() as con:
        con.execute(
            """
            UPDATE cascade_settings SET mode='cluster', exit_node_id=?, exit_name=?,
                cluster_service_uuid=?, cluster_service_job_id=?, service_user_id=NULL,
                last_test_state='', last_test_ip='', last_test_country='', last_test_colo='',
                last_test_warp='', last_test_detail='', tested_signature='',
                last_test_at=NULL, enabled_at=NULL, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (int(node_id), exit_name, service_uuid, int(job["id"])),
        )
    result = get_cascade_overview()
    result["cluster_job"] = job
    return result


def finalize_cascade_cluster_job(job_id: int) -> dict[str, object]:
    """Import Worker-returned REALITY metadata, test and enable the route."""
    from .node_manager import find_node, find_node_job

    job = find_node_job(int(job_id))
    if str(job.get("status") or "") != "succeeded":
        raise XPanelError("служебный профиль Cascade на SG-Node не был успешно применён")
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    if str(payload.get("worker_operation") or "") != "upsert_cascade_access":
        raise XPanelError("задание не относится к автоматической настройке Cascade")
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    if str(result.get("action") or "") != "upsert":
        raise XPanelError("SG-Node не подтвердила создание служебного профиля Cascade")

    settings = _cascade_settings_row()
    if str(settings["mode"] or "") != "cluster" or int(settings["cluster_service_job_id"] or 0) != int(job_id):
        raise XPanelError("это задание Cascade уже не является текущим")
    node_id = int(settings["exit_node_id"] or 0)
    node = find_node(node_id)
    service_uuid = str(settings["cluster_service_uuid"] or payload.get("service_uuid") or "").strip()
    exit_name = str(settings["exit_name"] or node.get("name") or "SG-Node")
    link_values = dict(result)
    link_values["address"] = str(node.get("public_address") or "").strip()
    service_link = _cluster_cascade_link(link_values, service_uuid, exit_name)
    parse_vless_share_link(service_link)
    imported = import_cascade_link(service_link)
    outbound = imported.get("outbound") if isinstance(imported, dict) else None
    outbound_id = int((outbound or {}).get("id") or 0) if isinstance(outbound, dict) else 0
    if not outbound_id:
        current = _cascade_candidate_outbound()
        outbound_id = int(current["id"] or 0) if current is not None else 0
    with connect() as con:
        con.execute(
            """
            UPDATE cascade_settings SET mode='cluster', exit_node_id=?, exit_name=?,
                cluster_service_uuid=?, cluster_service_job_id=?, outbound_id=?,
                updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (node_id, exit_name, service_uuid, int(job_id), outbound_id or None),
        )

    test_result = test_cascade()
    set_cascade_enabled(True)
    try:
        apply_config()
    except Exception:
        set_cascade_enabled(False)
        try:
            apply_config()
        except Exception:
            pass
        raise
    overview = get_cascade_overview()
    overview["service_link"] = service_link
    overview["test_result"] = test_result
    return overview


def _remove_cluster_cascade_access(settings: sqlite3.Row, *, dry_run: bool = False) -> None:
    from .node_manager import create_node_job, find_node, list_node_jobs

    node_id = int(settings["exit_node_id"] or 0)
    service_uuid = str(settings["cluster_service_uuid"] or "").strip()
    if not node_id or not service_uuid:
        return
    node = find_node(node_id)
    if str(node.get("effective_state") or node.get("state") or "") != "online":
        raise XPanelError("сначала верните выходную SG-Node в сеть, чтобы удалить служебный доступ Cascade")
    worker_version = str(node.get("worker_version") or "").strip()
    if _node_worker_version_tuple(worker_version) < CASCADE_NODE_WORKER_MINIMUM:
        raise XPanelError("на выходной SG-Node требуется Worker UI19 для безопасного удаления Cascade")
    if any(str(job.get("status") or "") in {"queued", "running"} for job in list_node_jobs(node_id, limit=100)):
        raise XPanelError("на выходной SG-Node уже выполняется другое задание")
    if dry_run:
        return
    create_node_job(
        node_id,
        job_type="apply_xray_config",
        title=f"Удаление Cascade exit · {get_instance_name()}",
        payload={
            "worker_operation": "upsert_cascade_access",
            "action": "remove",
            "service_uuid": service_uuid,
            "controller": get_instance_name(),
            "preserve_live_config": True,
        },
    )


def remove_cascade(*, dry_run: bool = False) -> dict[str, object]:
    settings = _cascade_settings_row()
    if str(settings["mode"] or "external") == "cluster":
        _remove_cluster_cascade_access(settings, dry_run=dry_run)
    if dry_run:
        return get_cascade_overview()
    outbound = _cascade_candidate_outbound(settings)
    service_user_id = int(settings["service_user_id"] or 0)
    routing = get_routing_settings()
    if outbound is not None and str(routing["default_outbound_tag"]) == str(outbound["tag"]):
        update_routing_settings(
            domain_strategy=str(routing["domain_strategy"]),
            default_outbound_tag="direct",
            sniffing_enabled=bool(routing["sniffing_enabled"]),
            sniffing_route_only=bool(routing["sniffing_route_only"]),
            sniff_http=bool(routing["sniff_http"]),
            sniff_tls=bool(routing["sniff_tls"]),
            sniff_quic=bool(routing["sniff_quic"]),
        )
    if outbound is not None:
        delete_outbound(int(outbound["id"]))
    if service_user_id:
        try:
            user = find_user(service_user_id)
            if str(user["comment"] or "") == CASCADE_SERVICE_COMMENT:
                delete_user(service_user_id)
        except XPanelError:
            pass
    with connect() as con:
        con.execute(
            """
            UPDATE cascade_settings SET outbound_id = NULL, exit_name = '', service_user_id = NULL,
                mode='external', exit_node_id=NULL, cluster_service_uuid='', cluster_service_job_id=NULL,
                last_test_state = '', last_test_ip = '', last_test_country = '',
                last_test_colo = '', last_test_warp = '', last_test_detail = '',
                tested_signature = '', last_test_at = NULL, enabled_at = NULL,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """
        )
    return get_cascade_overview()


def get_cascade_overview() -> dict[str, object]:
    settings = _cascade_settings_row()
    outbound = _cascade_candidate_outbound(settings)
    service_access = _cascade_service_access()
    routing = get_routing_settings()
    enabled = bool(
        outbound is not None
        and bool(outbound["enabled"])
        and str(routing["default_outbound_tag"]) == str(outbound["tag"])
    )
    signature = _cascade_signature(outbound) if outbound is not None else ""
    test_state = str(settings["last_test_state"] or "")
    test_fresh = bool(
        outbound is not None
        and test_state == "ok"
        and str(settings["tested_signature"] or "") == signature
    )
    if test_state == "ok" and not test_fresh:
        display_state = "stale"
    elif test_state.startswith("error"):
        display_state = "error"
    elif test_fresh:
        display_state = "ok"
    else:
        display_state = "untested"

    custom = []
    for row in list_custom_outbounds():
        custom.append({
            "id": int(row["id"]),
            "tag": str(row["tag"]),
            "name": str(row["name"]),
            "address": str(row["address"]),
            "port": int(row["port"]),
            "enabled": bool(row["enabled"]),
            "selected": bool(outbound is not None and int(row["id"]) == int(outbound["id"])),
        })

    cluster_node = None
    cluster_job = None
    exit_node_id = int(settings["exit_node_id"] or 0)
    if exit_node_id:
        try:
            from .node_manager import find_node, find_node_job
            cluster_node = find_node(exit_node_id)
            job_id = int(settings["cluster_service_job_id"] or 0)
            if job_id:
                cluster_job = find_node_job(job_id)
        except (ValueError, sqlite3.Error):
            cluster_node = None
            cluster_job = None

    return {
        "configured": outbound is not None,
        "mode": str(settings["mode"] or "external"),
        "exit_node_id": exit_node_id,
        "cluster_node": cluster_node,
        "cluster_job": cluster_job,
        "instance_name": get_instance_name(),
        "exit_name": str(settings["exit_name"] or (outbound["name"] if outbound is not None else "")),
        "service_access": service_access,
        "enabled": enabled,
        "outbound": dict(outbound) if outbound is not None else None,
        "default_outbound_tag": str(routing["default_outbound_tag"]),
        "test_state": display_state,
        "test_fresh": test_fresh,
        "last_test_ip": str(settings["last_test_ip"] or ""),
        "last_test_country": str(settings["last_test_country"] or ""),
        "last_test_colo": str(settings["last_test_colo"] or ""),
        "last_test_warp": str(settings["last_test_warp"] or ""),
        "last_test_detail": str(settings["last_test_detail"] or ""),
        "last_test_at": settings["last_test_at"],
        "enabled_at": settings["enabled_at"],
        "available_outbounds": custom,
    }


def _unique_cascade_tag(preferred: str, *, ignore_id: int | None = None) -> str:
    base = _validate_outbound_tag(preferred)
    with connect() as con:
        rows = con.execute("SELECT id, tag FROM outbounds").fetchall()
    existing = {
        str(row["tag"]).lower()
        for row in rows
        if ignore_id is None or int(row["id"]) != int(ignore_id)
    }
    if base.lower() not in existing:
        return base
    for number in range(2, 100):
        suffix = f"-{number}"
        candidate = (base[: 64 - len(suffix)].rstrip("-._") + suffix)
        if candidate.lower() not in existing:
            return candidate
    raise XPanelError("не удалось подобрать уникальный tag для каскада")


def select_cascade_outbound(outbound_id: int) -> dict[str, object]:
    outbound = find_outbound(outbound_id)
    if not bool(outbound["enabled"]):
        raise XPanelError("сначала включите выбранный Outbound")
    with connect() as con:
        con.execute(
            """
            UPDATE cascade_settings SET outbound_id = ?, exit_name = ?, last_test_state = '',
                last_test_ip = '', last_test_country = '', last_test_colo = '',
                last_test_warp = '', last_test_detail = '', tested_signature = '',
                last_test_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (outbound_id, str(outbound["name"])),
        )
    return get_cascade_overview()


def import_cascade_link(link: str) -> dict[str, object]:
    values = parse_vless_share_link(link)
    current = _cascade_candidate_outbound()
    routing = get_routing_settings()
    was_enabled = bool(
        current is not None
        and str(routing["default_outbound_tag"]) == str(current["tag"])
    )

    if was_enabled:
        with connect() as con:
            con.execute(
                "UPDATE routing_settings SET default_outbound_tag = 'direct', "
                "updated_at = CURRENT_TIMESTAMP WHERE id = 1"
            )

    values = dict(values)
    values["user_uuid"] = values.pop("uuid")
    source_label = str(values.pop("source_label", ""))
    values.pop("transport_label", None)
    values.pop("security_label", None)
    values.pop("vision", None)
    exit_name = _cascade_exit_name_from_label(source_label, str(values.get("address") or ""))
    values["name"] = exit_name

    if current is not None:
        values["tag"] = str(current["tag"])
        outbound = update_vless_outbound(int(current["id"]), **values)
    else:
        values["tag"] = _unique_cascade_tag("cascade-exit")
        outbound = add_vless_outbound(**values)

    with connect() as con:
        con.execute(
            """
            UPDATE cascade_settings SET outbound_id = ?, exit_name = ?, mode='external',
                exit_node_id=NULL, cluster_service_uuid='', cluster_service_job_id=NULL,
                last_test_state = '', last_test_ip = '', last_test_country = '', last_test_colo = '',
                last_test_warp = '', last_test_detail = '', tested_signature = '',
                last_test_at = NULL, enabled_at = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
            """,
            (int(outbound["id"]), exit_name),
        )
    result = get_cascade_overview()
    result["was_disabled_for_safety"] = was_enabled
    return result


def test_cascade() -> dict[str, object]:
    require_root()
    settings = _cascade_settings_row()
    outbound = _cascade_candidate_outbound(settings)
    if outbound is None:
        raise XPanelError("сначала вставьте VLESS-ссылку выходного сервера")
    if not bool(outbound["enabled"]):
        raise XPanelError("выходной сервер отключён")

    server = get_server()
    xray_bin = str(server["xray_bin"])
    if not Path(xray_bin).is_file():
        raise FileNotFoundError(f"не найден Xray: {xray_bin}")
    curl = shutil.which("curl")
    if curl is None:
        raise FileNotFoundError("не найден curl")

    port = _free_local_port()
    test_inbound = "cascade-test-in"
    document = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": test_inbound,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [build_outbound_json(outbound)],
        "routing": {"rules": [{
            "type": "field",
            "inboundTag": [test_inbound],
            "outboundTag": str(outbound["tag"]),
        }]},
    }
    fd, name = tempfile.mkstemp(prefix="sg-panel-cascade-test-", suffix=".json")
    os.close(fd)
    path = Path(name)
    proc: subprocess.Popen[str] | None = None
    ip = country = colo = warp_state = ""
    detail = ""
    state = "error"
    signature = _cascade_signature(outbound)
    try:
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.Popen(
            [xray_bin, "run", "-config", str(path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 8
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise XPanelError(
                    stderr.strip() or "тестовый Xray завершился раньше времени"
                )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    ready = True
                    break
            time.sleep(0.15)
        if not ready:
            raise XPanelError("не открылся временный SOCKS-порт проверки каскада")

        result = _run(
            [
                curl, "--silent", "--show-error", "--max-time", "25",
                "--socks5-hostname", f"127.0.0.1:{port}",
                "https://www.cloudflare.com/cdn-cgi/trace",
            ],
            timeout=30,
        )
        if result.returncode != 0:
            raise XPanelError(
                (result.stderr or result.stdout).strip()
                or "запрос через выходной сервер не выполнен"
            )
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        ip = values.get("ip", "")
        country = values.get("loc", "")
        colo = values.get("colo", "")
        warp_state = values.get("warp", "off")
        if not ip:
            raise XPanelError("выходной сервер ответил, но внешний IP не определён")
        state = "ok"
        detail = f"REALITY-соединение работает. Выходной IP: {ip}"
        return {
            "ok": True,
            "ip": ip,
            "country": country,
            "colo": colo,
            "warp": warp_state,
            "detail": detail,
        }
    except Exception as exc:
        detail = str(exc)
        raise
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        path.unlink(missing_ok=True)
        with connect() as con:
            con.execute(
                """
                UPDATE cascade_settings SET outbound_id = ?, last_test_state = ?, last_test_ip = ?,
                    last_test_country = ?, last_test_colo = ?, last_test_warp = ?,
                    last_test_detail = ?, tested_signature = ?,
                    last_test_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
                """,
                (
                    int(outbound["id"]),
                    state if state == "ok" else ("error: " + detail)[:250],
                    ip, country, colo, warp_state, detail[:500],
                    signature if state == "ok" else "",
                ),
            )


def set_cascade_enabled(enabled: bool) -> dict[str, object]:
    overview = get_cascade_overview()
    outbound = overview["outbound"]
    if outbound is None:
        raise XPanelError("сначала подключите выходной сервер")
    current = get_routing_settings()
    if enabled:
        if not overview["test_fresh"]:
            raise XPanelError(
                "сначала выполните полную проверку REALITY-соединения"
            )
        target = str(outbound["tag"])
    else:
        target = "direct"

    update_routing_settings(
        domain_strategy=str(current["domain_strategy"]),
        default_outbound_tag=target,
        sniffing_enabled=bool(current["sniffing_enabled"]),
        sniffing_route_only=bool(current["sniffing_route_only"]),
        sniff_http=bool(current["sniff_http"]),
        sniff_tls=bool(current["sniff_tls"]),
        sniff_quic=bool(current["sniff_quic"]),
    )
    with connect() as con:
        con.execute(
            "UPDATE cascade_settings SET enabled_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            (datetime.now(timezone.utc).isoformat() if enabled else None,),
        )
    return get_cascade_overview()

def _validate_api_listen(value: str) -> str:
    value = value.strip()
    if ":" not in value:
        raise ValueError("API listen должен иметь вид 127.0.0.1:10085")
    host, port_text = value.rsplit(":", 1)
    if not host:
        raise ValueError("не указан адрес API")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("порт API должен быть числом") from exc
    if not 1 <= port <= 65535:
        raise ValueError("порт API должен быть от 1 до 65535")
    return value


def _validate_xhttp_path(value: str) -> str:
    path = (value or "").strip()
    if not path.startswith("/"):
        raise ValueError("XHTTP Path должен начинаться с /")
    if len(path) > 256 or not re.fullmatch(r"/[A-Za-z0-9._~%/-]+", path):
        raise ValueError("XHTTP Path содержит недопустимые символы")
    return path


def _validate_grpc_service_name(value: str) -> str:
    name = (value or "").strip().strip("/")
    if not name or len(name) > 128:
        raise ValueError("gRPC serviceName должен содержать от 1 до 128 символов")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("gRPC serviceName: используйте латинские буквы, цифры, точку, _ или -")
    return name


def _default_tls_paths(address: str) -> tuple[str, str]:
    base = f"/etc/letsencrypt/live/{address.strip()}"
    return f"{base}/fullchain.pem", f"{base}/privkey.pem"


def _read_simple_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _reality_edge_settings(server: sqlite3.Row | None = None) -> dict[str, object]:
    values = _read_simple_env(REALITY_EDGE_STATE)
    if values.get("ENABLED") != "1":
        return {"enabled": False}
    domain = _hostname_candidate(values.get("DOMAIN", ""))
    cert = Path(values.get("CERT", ""))
    key = Path(values.get("KEY", ""))
    try:
        xray_port = int(values.get("XRAY_PORT", str(REALITY_EDGE_XRAY_PORT)))
        web_port = int(values.get("WEB_PORT", str(REALITY_EDGE_WEB_PORT)))
    except ValueError:
        return {"enabled": False}
    # RC42 Hotfix 1: old HTTPS installations used loopback TCP/9443 for the
    # REALITY fallback page. Multi-REALITY uses public TCP/9443 for slot #3,
    # and binding 0.0.0.0:9443 conflicts with 127.0.0.1:9443. Treat the old
    # internal value as migrated even before the installer rewrites the env.
    if web_port == REALITY_EDGE_LEGACY_WEB_PORT:
        web_port = REALITY_EDGE_WEB_PORT
    if not domain or not cert.is_file() or not key.is_file():
        return {"enabled": False}
    if not (1 <= xray_port <= 65535 and 1 <= web_port <= 65535):
        return {"enabled": False}
    reality_name = ""
    if server is not None:
        reality_name = _hostname_candidate(str(server["server_name"] or ""))
        if not reality_name or reality_name == domain:
            return {"enabled": False}
    return {
        "enabled": True,
        "domain": domain,
        "cert": str(cert),
        "key": str(key),
        "xray_port": xray_port,
        "web_port": web_port,
        "reality_name": reality_name,
    }


def _russia_kit_edge(server: sqlite3.Row | None = None) -> dict[str, object]:
    """Return the HTTPS domain/certificate used by the four-transport kit."""
    edge = _reality_edge_settings(server)
    if not edge.get("enabled"):
        raise XPanelError(
            "Набор РФ требует настроенный собственный домен и HTTPS панели, "
            "а REALITY SNI должен отличаться от этого домена."
        )
    return edge


def _russia_kit_tls_domain(server: sqlite3.Row) -> str:
    return str(_russia_kit_edge(server)["domain"])


def get_russia_kit_overview() -> dict[str, object]:
    server = get_server()
    try:
        edge = _russia_kit_edge(server)
        ready = True
        message = "Домен и сертификат готовы"
    except XPanelError as exc:
        edge = {"domain": ""}
        ready = False
        message = str(exc)
    return {
        "active": str(server["inbound_profile"] or "") == RUSSIA_KIT_PROFILE,
        "ready": ready,
        "message": message,
        "domain": str(edge.get("domain") or ""),
        "reality_sni": str(server["server_name"] or ""),
        "transports": ("XHTTP-REALITY", "Hysteria 2", "WebSocket-TLS", "XHTTP-TLS"),
        "xmux_mode": str(get_transport_expert_settings()["xmux_mode"] or "auto"),
    }


def get_russia_kit_diagnostics() -> dict[str, object]:
    """Inspect the generated four-transport config without claiming an external handshake."""
    server = get_server()
    active = str(server["inbound_profile"] or "") == RUSSIA_KIT_PROFILE
    checks: list[dict[str, object]] = []

    def add(key: str, label: str, ok: bool, detail: str) -> None:
        checks.append({"key": key, "label": label, "ok": bool(ok), "detail": detail})

    if not active:
        return {
            "active": False,
            "overall_ok": False,
            "checks": checks,
            "note": "Набор ещё не активирован; внешние сетевые проверки не выполнялись.",
        }
    try:
        config, _server, _users = build_config()
        by_tag = {str(item.get("tag") or ""): item for item in config.get("inbounds", [])}
        reality = by_tag.get("vless-reality-in", {})
        xhttp_tls = by_tag.get("xhttp-tls-in", {})
        websocket = by_tag.get("ws-tls-in", {})
        hysteria = by_tag.get(HYSTERIA_COMBINED_PRIMARY_TAG, {})
        stream_text, web_text = _nginx_reality_edge_configs(server)

        reality_stream = reality.get("streamSettings", {}) if isinstance(reality, dict) else {}
        add(
            "clienthello",
            "TLS ClientHello / SNI",
            "ssl_preread on;" in stream_text and str(server["server_name"] or "") in stream_text,
            "Nginx читает только SNI из ClientHello и направляет REALITY на локальный Xray.",
        )
        add(
            "xhttp_reality",
            "XHTTP-REALITY",
            reality_stream.get("network") == "xhttp"
            and reality_stream.get("security") == "reality"
            and reality_stream.get("xhttpSettings", {}).get("path") == RUSSIA_KIT_XHTTP_REALITY_PATH,
            f"TCP/443 · {RUSSIA_KIT_XHTTP_REALITY_PATH}",
        )
        xhttp_stream = xhttp_tls.get("streamSettings", {}) if isinstance(xhttp_tls, dict) else {}
        add(
            "h2",
            "H2 / XHTTP-TLS",
            xhttp_stream.get("network") == "xhttp"
            and f"location {RUSSIA_KIT_XHTTP_TLS_PATH.rstrip('/')}/" in web_text
            and f"grpc_pass grpc://127.0.0.1:{RUSSIA_KIT_XHTTP_TLS_PORT};" in web_text,
            f"TLS домена → локальный XHTTP {RUSSIA_KIT_XHTTP_TLS_PATH}",
        )
        ws_stream = websocket.get("streamSettings", {}) if isinstance(websocket, dict) else {}
        add(
            "h1",
            "H1 Upgrade / WebSocket-TLS",
            ws_stream.get("network") == "ws"
            and f"location = {RUSSIA_KIT_WS_PATH.rstrip('/') or '/'}" in web_text
            and "proxy_set_header Upgrade $http_upgrade;" in web_text,
            f"TLS домена → WebSocket {RUSSIA_KIT_WS_PATH}",
        )
        hy_stream = hysteria.get("streamSettings", {}) if isinstance(hysteria, dict) else {}
        add(
            "h3",
            "H3 / Hysteria 2",
            int(hysteria.get("port") or 0) == 443
            and hy_stream.get("network") == "hysteria"
            and "h3" in hy_stream.get("tlsSettings", {}).get("alpn", []),
            "UDP/443 · TLS 1.3 · ALPN h3",
        )
        client_extra = _effective_xhttp_extra("client")
        xmux = client_extra.get("xmux") if isinstance(client_extra, dict) else None
        add(
            "xmux",
            "XMUX",
            xmux == XMUX_REDUCED_PRESET and "maxConcurrency" not in (xmux or {}),
            "Сниженное число соединений; конфликтующий maxConcurrency отсутствует.",
        )
    except (XPanelError, ValueError, OSError, KeyError, TypeError) as exc:
        add("config", "Итоговая конфигурация", False, str(exc))
    return {
        "active": active,
        "overall_ok": bool(checks) and all(bool(item["ok"]) for item in checks),
        "checks": checks,
        "note": (
            "Проверена конфигурационная цепочка. Реальную доступность из РФ нужно подтвердить внешним клиентом."
        ),
    }


def enable_russia_kit() -> sqlite3.Row:
    """Enable the four-transport ready set without changing the classic UI."""
    server = get_server()
    _russia_kit_edge(server)
    expert = get_transport_expert_settings()
    update_transport_expert_settings(
        xhttp_mode=str(server["xhttp_mode"] or "auto"),
        xmux_mode="reduced",
        xhttp_extra_server_json=str(expert["xhttp_extra_server_json"] or "{}"),
        xhttp_extra_client_json=str(expert["xhttp_extra_client_json"] or "{}"),
        finalmask_enabled=bool(expert["finalmask_enabled"]),
        finalmask_server_json=str(expert["finalmask_server_json"] or "{}"),
        finalmask_client_json=str(expert["finalmask_client_json"] or "{}"),
        ech_mode=str(expert["ech_mode"] or "off"),
        ech_public_name=str(expert["ech_public_name"] or ""),
        ech_server_keys=str(expert["ech_server_keys"] or ""),
        ech_config_list=str(expert["ech_config_list"] or ""),
        certificate_pinning_enabled=bool(expert["certificate_pinning_enabled"]),
        certificate_pinning_sha256=str(expert["certificate_pinning_sha256"] or ""),
        certificate_pinning_source=str(expert["certificate_pinning_source"] or ""),
        tls_verify_name_mode=str(expert["tls_verify_name_mode"] or "auto"),
        tls_verify_name=str(expert["tls_verify_name"] or ""),
        client_ca_pem=str(expert["client_ca_pem"] or ""),
        client_ca_source=str(expert["client_ca_source"] or ""),
    )
    return update_server_settings(
        address=str(server["address"]),
        listen="0.0.0.0",
        port=443,
        dest=str(server["dest"]),
        server_name=str(server["server_name"]),
        private_key=str(server["private_key"]),
        public_key=str(server["public_key"]),
        short_id=str(server["short_id"]),
        fingerprint=str(server["fingerprint"]),
        flow="",
        loglevel=str(server["loglevel"]),
        api_listen=str(server["api_listen"]),
        stats_enabled=bool(server["stats_enabled"]),
        config_path=str(server["config_path"]),
        xray_bin=str(server["xray_bin"]),
        xray_service=str(server["xray_service"]),
        inbound_profile=RUSSIA_KIT_PROFILE,
        xhttp_mode=str(server["xhttp_mode"] or "auto"),
        hysteria_udp_hop_ports="",
        hysteria_instances=[
            {"id": 1, "name": "Hysteria 2", "enabled": True, "listen": "0.0.0.0", "port": 443},
            {"id": 2, "name": "Hysteria 2 #2", "enabled": False, "listen": "0.0.0.0", "port": 8443},
            {"id": 3, "name": "Hysteria 2 #3", "enabled": False, "listen": "0.0.0.0", "port": 9443},
        ],
        xhttp_instances=[
            {"id": 1, "name": "XHTTP TLS", "enabled": True, "listen": "127.0.0.1", "port": RUSSIA_KIT_XHTTP_TLS_PORT, "path": RUSSIA_KIT_XHTTP_TLS_PATH},
            {"id": 2, "name": "XHTTP #2", "enabled": False, "listen": "127.0.0.1", "port": 8447, "path": "/sg-xhttp-2"},
            {"id": 3, "name": "XHTTP #3", "enabled": False, "listen": "127.0.0.1", "port": 8448, "path": "/sg-xhttp-3"},
        ],
    )


def _validate_reality_edge_listener_ports(
    server: sqlite3.Row,
    instances: list[sqlite3.Row],
) -> None:
    edge = _reality_edge_settings(server)
    if not edge.get("enabled"):
        return
    reserved = {
        int(edge["xray_port"]): "внутренний listener основного REALITY",
        int(edge["web_port"]): "локальная HTTPS-заглушка REALITY",
    }
    for instance in instances:
        if not bool(instance["enabled"]) or int(instance["id"]) == 1:
            continue
        port = int(instance["port"])
        if port in reserved:
            raise XPanelError(
                f"REALITY #{int(instance['id'])}: TCP-порт {port} занят: {reserved[port]}. "
                "Выберите другой публичный TCP-порт."
            )


def _hostname_candidate(value: str) -> str:
    candidate = (value or "").strip().lower().rstrip(".")
    if not candidate:
        return ""
    try:
        ipaddress.ip_address(candidate)
        return ""
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", candidate):
        return candidate
    return ""


def _nginx_panel_domain() -> str:
    path = Path("/etc/nginx/sites-available/sg-panel")
    if not path.is_file():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for match in re.finditer(r"(?m)^\s*server_name\s+([^;]+);", content):
        for item in match.group(1).split():
            domain = _hostname_candidate(item)
            if domain:
                return domain
    return ""


def _certificate_candidates() -> list[dict[str, str]]:
    root = Path("/etc/letsencrypt/live")
    result: list[dict[str, str]] = []
    if not root.is_dir():
        return result
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return result
    for entry in entries:
        if entry.name == "README" or not entry.is_dir():
            continue
        cert = entry / "fullchain.pem"
        key = entry / "privkey.pem"
        if cert.exists() and key.exists():
            result.append({"domain": entry.name, "cert": str(cert), "key": str(key)})
    return result


def _listener_status(port: int, protocol: str) -> str:
    args = ["ss", "-H", "-lun"] if protocol == "udp" else ["ss", "-H", "-ltn"]
    try:
        result = _run(args, timeout=3)
    except (XPanelError, OSError):
        return "неизвестно"
    needle = f":{int(port)}"
    for line in result.stdout.splitlines():
        tokens = line.split()
        if any(token.endswith(needle) or f"]{needle}" in token for token in tokens):
            return "занят"
    return "свободен"




def _validated_xray_version() -> str:
    """Read the shared Controller/Node Xray version policy."""
    policy = Path(__file__).resolve().parents[1] / "deploy" / "xray-version.env"
    try:
        for raw in policy.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("XRAY_VERSION="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if re.fullmatch(r"v\d+\.\d+\.\d+", value):
                    return value
    except OSError:
        pass
    return "не определена"

def get_inbound_recommendations() -> dict[str, object]:
    server = get_server()
    state = _read_simple_env(Path("/etc/xpanel-mvp/panel-access.env"))
    install_state = _read_simple_env(Path("/etc/xpanel-mvp/install-complete.env"))
    candidates = _certificate_candidates()

    preferred_domains = [
        _hostname_candidate(str(state.get("PANEL_DOMAIN", ""))),
        _hostname_candidate(str(state.get("PANEL_PUBLIC_HOST", ""))),
        _hostname_candidate(str(install_state.get("PANEL_DOMAIN", ""))),
        _nginx_panel_domain(),
        _hostname_candidate(str(server["address"] or "")),
    ]
    preferred_domains = [item for item in preferred_domains if item]
    certificate = None
    for domain in preferred_domains:
        certificate = next((item for item in candidates if item["domain"] == domain), None)
        if certificate:
            break
    if certificate is None and len(candidates) == 1:
        certificate = candidates[0]

    domain = certificate["domain"] if certificate else (preferred_domains[0] if preferred_domains else "")
    cert_path = certificate["cert"] if certificate else ""
    key_path = certificate["key"] if certificate else ""
    current_address = str(server["address"] or "").strip()
    public_address = domain or current_address
    dest = str(server["dest"] or "www.bing.com:443").strip()
    reality_name = dest.rsplit(":", 1)[0].strip().strip("[]") if ":" in dest else dest
    xhttp_path = str(server["xhttp_path"] or "/sg-xhttp").strip() or "/sg-xhttp"

    profiles = {
        "raw_reality": {
            "address": current_address,
            "port": 443,
            "listen": "0.0.0.0",
            "server_name": reality_name,
            "flow": "xtls-rprx-vision",
        },
        "xhttp_reality": {
            "address": current_address,
            "port": 443,
            "listen": "0.0.0.0",
            "server_name": reality_name,
            "flow": "",
            "xhttp_path": xhttp_path,
            "xhttp_mode": str(server["xhttp_mode"] or "auto"),
        },
        "xhttp_tls": {
            "address": public_address,
            "port": 443,
            "server_name": domain,
            "transport_listen": "127.0.0.1",
            "transport_port": int(server["transport_port"] or 8443),
            "xhttp_path": xhttp_path,
            "xhttp_mode": str(server["xhttp_mode"] or "auto"),
            "tls_cert_path": cert_path,
            "tls_key_path": key_path,
        },
        "xhttp_hysteria_tls": {
            "address": public_address,
            "port": 443,
            "listen": "0.0.0.0",
            "server_name": domain,
            "transport_listen": "127.0.0.1",
            "transport_port": int(server["transport_port"] or 8443),
            "xhttp_path": xhttp_path,
            "xhttp_mode": str(server["xhttp_mode"] or "auto"),
            "tls_cert_path": cert_path,
            "tls_key_path": key_path,
            "hysteria_udp_idle_timeout": 60,
            "hysteria_masquerade_type": "",
            "hysteria_masquerade_status": 404,
            "hysteria_performance_profile": "auto",
            "hysteria_congestion": "brutal",
            "hysteria_bbr_profile": "standard",
            "hysteria_brutal_up": "0",
            "hysteria_brutal_down": "0",
            "hysteria_quic_debug": False,
            "hysteria_max_idle_timeout": 30,
            "hysteria_keepalive_period": 0,
            "hysteria_disable_pmtud": False,
            "hysteria_max_incoming_streams": 1024,
            "hysteria_udp_hop_ports": "",
            "hysteria_udp_hop_interval": "30",
        },
        "hysteria2_tls": {
            "address": public_address,
            "port": 443,
            "listen": "0.0.0.0",
            "server_name": domain,
            "tls_cert_path": cert_path,
            "tls_key_path": key_path,
            "hysteria_udp_idle_timeout": 60,
            "hysteria_masquerade_type": "",
            "hysteria_masquerade_status": 404,
            "hysteria_performance_profile": "auto",
            "hysteria_congestion": "brutal",
            "hysteria_bbr_profile": "standard",
            "hysteria_brutal_up": "0",
            "hysteria_brutal_down": "0",
            "hysteria_quic_debug": False,
            "hysteria_max_idle_timeout": 30,
            "hysteria_keepalive_period": 0,
            "hysteria_disable_pmtud": False,
            "hysteria_max_incoming_streams": 1024,
            "hysteria_udp_hop_ports": "",
            "hysteria_udp_hop_interval": "30",
        },
    }
    return {
        "domain": domain,
        "certificate_found": bool(certificate),
        "certificate_path": cert_path,
        "key_path": key_path,
        "certificate_candidates": candidates,
        "tcp_443": _listener_status(443, "tcp"),
        "udp_443": _listener_status(443, "udp"),
        "xray_recommended_version": _validated_xray_version(),
        "profiles": profiles,
    }


def get_hysteria_studio_overview() -> dict[str, object]:
    server = get_server()
    recommendations = get_inbound_recommendations()
    service = _run(["systemctl", "is-active", str(server["xray_service"])], timeout=3)
    service_state = (service.stdout or service.stderr).strip() or "unknown"
    active_users = len(_active_users(list_users()))
    cert_path = Path(str(server["tls_cert_path"] or ""))
    key_path = Path(str(server["tls_key_path"] or ""))
    cert_ready = cert_path.is_file() and key_path.is_file()
    instances = list_hysteria_inbounds()
    enabled_instances = [row for row in instances if bool(row["enabled"])]
    udp_state = _listener_status(int(server["port"] or 443), "udp")
    active = str(server["inbound_profile"] or "") in HYSTERIA_ACTIVE_PROFILES
    ports = [int(row["port"]) for row in enabled_instances]
    return {
        "active": active,
        "service": service_state,
        "endpoint": f"{server['address']}:{server['port']}/UDP",
        "instances": len(enabled_instances),
        "ports": ports,
        "ports_label": ", ".join(str(value) for value in ports),
        "users": active_users,
        "certificate_ready": cert_ready,
        "certificate_label": "готов" if cert_ready else "требует проверки",
        "udp_listener": udp_state,
        "domain": recommendations.get("domain", ""),
        "xray_version": recommendations.get("xray_recommended_version", _validated_xray_version()),
        "hop_enabled": bool(str(server["hysteria_udp_hop_ports"] or "").strip()),
    }


def get_hysteria_diagnostics() -> dict[str, object]:
    """Return a secret-safe Hysteria2 report from DB, candidate, live config and URI.

    Salamander consistency is intentionally checked across all three sources.  The
    password itself never leaves this function; only configured/matching states are
    returned to the template and diagnostic bundle.
    """
    server = get_server()
    address = str(server["address"] or "").strip()
    primary_port = int(get_xray_channels_settings()["hysteria2_port"] or 443)
    all_instances = list_hysteria_inbounds()
    enabled_instances = [row for row in all_instances if bool(row["enabled"])]
    protected_secrets = [
        str(row["obfs_password"])
        for row in all_instances
        if row["obfs_password"] is not None and str(row["obfs_password"])
    ]
    checks: list[dict[str, str]] = []

    def redact(value: object) -> str:
        return redact_hysteria_obfs_secrets(value, extra=protected_secrets)

    def add(key: str, label: str, level: str, status: str, detail: str) -> None:
        checks.append({
            "key": key,
            "label": label,
            "level": level,
            "status": redact(status),
            "detail": redact(detail),
        })

    def hysteria_inbounds(payload: object) -> list[dict[str, object]]:
        if not isinstance(payload, dict):
            return []
        return [
            item for item in payload.get("inbounds", [])
            if isinstance(item, dict)
            and str(item.get("protocol") or "").lower() == "hysteria"
            and isinstance(item.get("streamSettings"), dict)
            and str(item["streamSettings"].get("network") or "").lower() == "hysteria"
        ]

    def layer_password(inbound: dict[str, object] | None) -> tuple[bool, str]:
        if not isinstance(inbound, dict):
            return False, ""
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict):
            return False, ""
        finalmask = stream.get("finalmask")
        if not isinstance(finalmask, dict):
            return False, ""
        udp = finalmask.get("udp")
        if not isinstance(udp, list):
            return False, ""
        for layer in udp:
            if not isinstance(layer, dict):
                continue
            if str(layer.get("type") or "").strip().lower() != "salamander":
                continue
            settings = layer.get("settings")
            password = str(settings.get("password") or "") if isinstance(settings, dict) else ""
            return True, password
        return False, ""

    support = hysteria_salamander_support_status(str(server["xray_bin"]))
    any_salamander = any(str(row["obfs_mode"] or "none") == "salamander" for row in enabled_instances)
    add(
        "salamander_version",
        "Поддержка Salamander",
        "ok" if support["supported"] else ("error" if any_salamander else "warning"),
        str(support["version"] or "Версия не определена"),
        (
            "Xray поддерживает Hysteria2 Salamander FinalMask."
            if support["supported"]
            else f"Минимальная поддерживаемая версия: {support['minimum']}. {support['message']}"
        ),
    )

    try:
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(address, primary_port, type=socket.SOCK_DGRAM)})
        add("dns", "DNS", "ok", "Разрешается", ", ".join(resolved[:4]) or address)
    except OSError as exc:
        add("dns", "DNS", "error", "Ошибка", str(exc))

    cert_path = Path(str(server["tls_cert_path"] or ""))
    key_path = Path(str(server["tls_key_path"] or ""))
    if cert_path.is_file() and key_path.is_file():
        try:
            cert_proc = _run(
                ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "0", "-enddate"],
                timeout=6,
            )
            if cert_proc.returncode == 0:
                detail = (cert_proc.stdout or "сертификат и private key найдены").strip().replace("notAfter=", "Действителен до: ")
                add("tls", "TLS-сертификат", "ok", "Действителен", detail)
            else:
                add("tls", "TLS-сертификат", "error", "Недействителен", (cert_proc.stderr or cert_proc.stdout).strip())
        except (OSError, XPanelError) as exc:
            add("tls", "TLS-сертификат", "warning", "Не удалось проверить срок", str(exc))
    else:
        missing = []
        if not cert_path.is_file():
            missing.append(str(cert_path) or "certificate")
        if not key_path.is_file():
            missing.append(str(key_path) or "private key")
        add("tls", "TLS-сертификат", "error", "Файлы не найдены", ", ".join(missing))

    generated_payload: dict[str, object] = {}
    configured: list[dict[str, object]] = []
    try:
        validation = validate_generated_config()
        add(
            "config",
            "Итоговый config.json",
            "ok" if validation.get("ok") else "error",
            "xray run -test: OK" if validation.get("ok") else "Проверка не пройдена",
            str(validation.get("detail") or validation.get("message") or ""),
        )
        generated_payload, _server, users = build_config()
        configured = hysteria_inbounds(generated_payload)
        invalid_tags: list[str] = []
        for inbound in configured:
            stream = inbound.get("streamSettings", {})
            settings = inbound.get("settings", {})
            shape_ok = (
                settings.get("version") == 2
                and isinstance(stream.get("hysteriaSettings"), dict)
                and stream["hysteriaSettings"].get("version") == 2
            )
            if not shape_ok:
                invalid_tags.append(str(inbound.get("tag", "без tag")))
        expected_count = len(enabled_instances) if _always_on_https_material(server)["ready"] else 0
        all_shapes_ok = len(configured) == expected_count and not invalid_tags
        detail = (
            f"Inbound: {len(configured)}; пользователей: {len(users)}"
            if all_shapes_ok
            else (
                f"Ожидалось Inbound: {expected_count}; найдено: {len(configured)}; "
                f"ошибочные tags: {', '.join(invalid_tags) or 'нет'}"
            )
        )
        add(
            "shape",
            "Структура Hysteria 2",
            "ok" if all_shapes_ok else "error",
            "Корректна" if all_shapes_ok else "Не соответствует Hysteria 2",
            detail,
        )
    except (OSError, KeyError, IndexError, TypeError, ValueError, XPanelError) as exc:
        add("config", "Итоговый config.json", "error", "Проверка не выполнена", str(exc))

    live_payload: dict[str, object] | None = None
    config_path = Path(str(server["config_path"] or ""))
    try:
        raw_live = json.loads(config_path.read_text(encoding="utf-8"))
        live_payload = raw_live if isinstance(raw_live, dict) else None
    except (OSError, ValueError, TypeError):
        live_payload = None
    live_by_tag = {
        str(item.get("tag") or ""): item for item in hysteria_inbounds(live_payload)
    }
    candidate_by_tag = {
        str(item.get("tag") or ""): item for item in configured
    }

    for instance in enabled_instances:
        inbound_id = int(instance["id"])
        tag = "sg-hysteria2" if inbound_id == 1 else str(instance["tag"])
        mode, password = _normalise_hysteria_obfs(
            instance["obfs_mode"], instance["obfs_password"]
        )
        candidate_present, candidate_password = layer_password(candidate_by_tag.get(tag))
        live_present, live_password = layer_password(live_by_tag.get(tag))
        port = primary_port if inbound_id == 1 else int(instance["port"])
        diagnostic_uri = build_hysteria2_uri(
            auth="diagnostic-auth",
            host=address or "example.invalid",
            port=port,
            sni=address or "example.invalid",
            profile_name=str(instance["name"]),
            obfs_mode=mode,
            obfs_password=password,
        )
        query = parse_qs(urlparse(diagnostic_uri).query, keep_blank_values=True)
        uri_present = query.get("obfs") == ["salamander"] and bool(query.get("obfs-password", [""])[0])
        candidate_ok = (
            (mode == "none" and not candidate_present)
            or (mode == "salamander" and candidate_present and secrets.compare_digest(candidate_password, str(password)))
        )
        uri_ok = (mode == "none" and not uri_present) or (
            mode == "salamander"
            and uri_present
            and secrets.compare_digest(query["obfs-password"][0], str(password))
        )
        if live_payload is None:
            live_ok = False
            live_text = "live config недоступен"
        else:
            live_ok = (
                (mode == "none" and not live_present)
                or (mode == "salamander" and live_present and secrets.compare_digest(live_password, str(password)))
            )
            live_text = "runtime совпадает" if live_ok else "runtime не совпадает"
        consistent = candidate_ok and uri_ok and (live_ok if live_payload is not None else True)
        if mode == "none":
            status = "Выключена"
            detail = (
                f"Database: none; candidate: {'без слоя' if candidate_ok else 'есть лишний слой'}; "
                f"client URI: {'без параметров' if uri_ok else 'содержит obfs'}; {live_text}."
            )
        else:
            status = "Salamander"
            detail = (
                "Password: configured; "
                f"FinalMask UDP candidate: {'active' if candidate_ok else 'missing/mismatch'}; "
                f"client URI parameters: {'present' if uri_ok else 'missing/mismatch'}; {live_text}."
            )
        level = "ok" if consistent and (live_payload is not None or mode == "none") else (
            "warning" if live_payload is None and candidate_ok and uri_ok else "error"
        )
        add(
            f"salamander_{inbound_id}",
            f"Обфускация · {instance['name']}",
            level,
            status,
            detail,
        )

    try:
        service_proc = _run(["systemctl", "is-active", str(server["xray_service"])], timeout=5)
        service_state = (service_proc.stdout or service_proc.stderr).strip() or "unknown"
    except (OSError, XPanelError) as exc:
        service_state = f"ошибка: {exc}"
    add(
        "service",
        "Служба Xray",
        "ok" if service_state == "active" else "error",
        service_state,
        f"systemd unit: {server['xray_service']}",
    )

    profile_active = bool(configured)
    add(
        "profile",
        "Hysteria 2 Inbound",
        "ok" if profile_active else "warning",
        "Сформирован" if profile_active else "Ожидает TLS",
        "Always-On канал появляется в итоговом config.json после готовности домена и TLS-сертификата.",
    )
    for index, instance in enumerate(enabled_instances):
        instance_port = primary_port if int(instance["id"]) == 1 else int(instance["port"])
        udp_state = _listener_status(instance_port, "udp")
        add(
            "udp" if index == 0 else f"udp_{int(instance['id'])}",
            f"UDP listener {instance_port}",
            "ok" if udp_state == "занят" and profile_active else ("warning" if not profile_active else "error"),
            "Слушается" if udp_state == "занят" else "Не слушается",
            f"{instance['name']}. Проверена локальная таблица сокетов; внешний доступ проверяется клиентом из другой сети.",
        )

    active_users = len(_active_users(list_users()))
    add(
        "users",
        "Пользователи",
        "ok" if active_users else "warning",
        f"Активных: {active_users}",
        "Для каждого пользователя в Hysteria 2 используется индивидуальный auth; пароль Salamander общий только внутри Inbound.",
    )

    hop_ports = str(server["hysteria_udp_hop_ports"] or "").strip()
    if hop_ports:
        add(
            "hopping",
            "UDP port hopping",
            "warning",
            "Включён",
            f"Порты: {hop_ports}; откройте весь диапазон UDP в Security Group и firewall.",
        )
    else:
        active_ports = ", ".join(
            str(primary_port if int(item["id"]) == 1 else int(item["port"]))
            for item in enabled_instances
        )
        add(
            "hopping",
            "UDP port hopping",
            "ok",
            "Выключен",
            f"Используются фиксированные UDP-порты: {active_ports or primary_port}.",
        )

    try:
        journal = _run(["journalctl", "-u", str(server["xray_service"]), "-n", "80", "--no-pager"], timeout=8)
        log_lines = (journal.stdout or journal.stderr).splitlines()
    except (OSError, XPanelError) as exc:
        log_lines = [f"journalctl: {exc}"]
    suspicious = [line for line in log_lines if re.search(r"\b(error|failed|panic|fatal)\b", line, re.I)]
    add(
        "logs",
        "Журнал Xray",
        "warning" if suspicious else "ok",
        f"Найдено предупреждений: {len(suspicious)}" if suspicious else "Критических ошибок не найдено",
        " | ".join(suspicious[-3:]) if suspicious else "Проанализированы последние 80 строк журнала.",
    )
    add(
        "external",
        "Внешняя доступность UDP",
        "neutral",
        "Не подтверждена локально",
        "Для окончательной проверки подключитесь к каждому включённому UDP-порту из другой сети. Security Group провайдера панель прочитать не может.",
    )

    blocking = [item for item in checks if item["level"] == "error"]
    return {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "endpoint": f"{address}:{primary_port}/UDP",
        "active": profile_active,
        "overall_ok": not blocking,
        "blocking_count": len(blocking),
        "checks": checks,
    }


def _validate_hysteria_rate(value: str, field_label: str) -> str:
    cleaned = str(value or "0").strip().lower()
    if cleaned == "0":
        return "0"
    if len(cleaned) > 32 or not re.fullmatch(r"\d+(?:\.\d+)?\s*(?:[kmgt]?b(?:ps)?|[kmgt])?", cleaned):
        raise ValueError(f"{field_label}: используйте 0 или значение вроде 20 mbps")
    return cleaned


def _validate_hysteria_hop_ports(value: str) -> str:
    cleaned = str(value or "").strip().replace(" ", "")
    if not cleaned:
        return ""
    for part in cleaned.split(","):
        if not part:
            raise ValueError("диапазон UDP port hopping содержит пустой сегмент")
        bounds = part.split("-", 1)
        try:
            start = int(bounds[0])
            end = int(bounds[1]) if len(bounds) == 2 else start
        except ValueError as exc:
            raise ValueError("UDP port hopping: используйте порты и диапазоны, например 443,20000-20100") from exc
        if not 1 <= start <= 65535 or not 1 <= end <= 65535 or start > end:
            raise ValueError("UDP port hopping содержит недопустимый диапазон портов")
    return cleaned


def _validate_hysteria_hop_interval(value: str) -> str:
    cleaned = str(value or "30").strip().replace(" ", "")
    if not re.fullmatch(r"\d+(?:-\d+)?", cleaned):
        raise ValueError("интервал port hopping должен быть числом или диапазоном, например 30 или 15-45")
    values = [int(item) for item in cleaned.split("-")]
    if any(item < 5 for item in values) or (len(values) == 2 and values[0] > values[1]):
        raise ValueError("интервал port hopping должен быть не меньше 5 секунд")
    return cleaned


def _parse_hysteria_headers(value: str) -> dict[str, str]:
    text = str(value or "{}").strip() or "{}"
    if len(text) > 4096:
        raise ValueError("HTTP-заголовки masquerade не должны превышать 4096 символов")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"HTTP-заголовки masquerade должны быть JSON-объектом: {exc.msg}") from exc
    if not isinstance(parsed, dict) or any(not isinstance(key, str) or not isinstance(val, str) for key, val in parsed.items()):
        raise ValueError("HTTP-заголовки masquerade должны быть JSON-объектом строк")
    return parsed


def validate_server_values(
    address: str,
    port: int,
    dest: str,
    server_name: str,
    private_key: str,
    public_key: str,
    short_id: str,
    *,
    flow: str = "",
    loglevel: str = "warning",
    api_listen: str = "127.0.0.1:10085",
    listen: str = "0.0.0.0",
    inbound_profile: str = "raw_reality",
    transport_listen: str = "127.0.0.1",
    transport_port: int = 8443,
    xhttp_path: str = "/sg-xhttp",
    xhttp_mode: str = "auto",
    grpc_service_name: str = "sg-grpc",
    tls_cert_path: str = "",
    tls_key_path: str = "",
    hysteria_udp_idle_timeout: int = 60,
    hysteria_masquerade_type: str = "",
    hysteria_masquerade_url: str = "",
    hysteria_masquerade_content: str = "",
    hysteria_masquerade_status: int = 404,
    hysteria_masquerade_dir: str = "",
    hysteria_masquerade_rewrite_host: bool = True,
    hysteria_masquerade_insecure: bool = False,
    hysteria_masquerade_headers: str = "{}",
    hysteria_performance_profile: str = "auto",
    hysteria_congestion: str = "brutal",
    hysteria_bbr_profile: str = "standard",
    hysteria_brutal_up: str = "0",
    hysteria_brutal_down: str = "0",
    hysteria_quic_debug: bool = False,
    hysteria_max_idle_timeout: int = 30,
    hysteria_keepalive_period: int = 0,
    hysteria_disable_pmtud: bool = False,
    hysteria_max_incoming_streams: int = 1024,
    hysteria_udp_hop_ports: str = "",
    hysteria_udp_hop_interval: str = "30",
    hysteria_init_stream_receive_window: int = 8388608,
    hysteria_max_stream_receive_window: int = 8388608,
    hysteria_init_connection_receive_window: int = 20971520,
    hysteria_max_connection_receive_window: int = 20971520,
) -> None:
    profile = (inbound_profile or "raw_reality").strip()
    if profile not in ALLOWED_INBOUND_PROFILES:
        raise ValueError("неподдерживаемый профиль входящего подключения")
    if not address or not address.strip():
        raise ValueError("публичный адрес не может быть пустым")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", address.strip()):
        raise ValueError("публичный адрес содержит недопустимые символы")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port должен быть от 1 до 65535")
    if flow not in ALLOWED_FLOWS:
        raise ValueError("неподдерживаемый flow")
    if profile in VISION_INBOUND_PROFILES:
        if flow != "xtls-rprx-vision":
            raise ValueError(
                "Все VLESS-профили SG-Panel требуют flow: xtls-rprx-vision; "
                "Hysteria 2 не использует VLESS Flow"
            )
    elif flow:
        raise ValueError("Flow не используется выбранным профилем")
    if loglevel not in ALLOWED_LOGLEVELS:
        raise ValueError("неподдерживаемый loglevel")
    _validate_api_listen(api_listen)

    if profile in REALITY_INBOUND_PROFILES:
        fields = {
            "dest": dest,
            "server_name": server_name,
            "private_key": private_key,
            "public_key": public_key,
            "short_id": short_id,
        }
        empty = [name for name, value in fields.items() if not value or not value.strip()]
        if empty:
            raise ValueError("пустые обязательные поля REALITY: " + ", ".join(empty))
        if not re.fullmatch(r"[0-9a-fA-F]{2,32}", short_id) or len(short_id) % 2:
            raise ValueError("short_id должен быть HEX-строкой чётной длины от 2 до 32 символов")
        if ":" not in dest:
            raise ValueError("dest должен иметь вид host:port")

    if profile in XHTTP_ACTIVE_PROFILES | {"xhttp_reality"}:
        _validate_xhttp_path(xhttp_path)
        if xhttp_mode not in ALLOWED_XHTTP_MODES:
            raise ValueError("неподдерживаемый XHTTP mode")

    if profile == "grpc_tls":
        _validate_grpc_service_name(grpc_service_name)

    if profile == RUSSIA_KIT_PROFILE:
        edge = _reality_edge_settings()
        if not edge.get("enabled"):
            raise ValueError(
                "Набор РФ требует сначала настроить собственный домен и HTTPS панели. "
                "REALITY SNI должен отличаться от собственного домена."
            )
    elif profile in HYSTERIA_ACTIVE_PROFILES and not _hostname_candidate(server_name):
        raise ValueError(
            "Hysteria 2 требует ваш реальный домен и TLS-сертификат. "
            "Сначала настройте домен и HTTPS панели, затем выберите Hysteria 2."
        )

    if profile in CERTIFICATE_INBOUND_PROFILES:
        if not server_name or not server_name.strip():
            raise ValueError("для TLS укажите Server name / SNI")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", server_name.strip()):
            raise ValueError("Server name / SNI содержит недопустимые символы")
        if not tls_cert_path or not tls_cert_path.strip():
            raise ValueError("укажите путь к TLS-сертификату")
        if not tls_key_path or not tls_key_path.strip():
            raise ValueError("укажите путь к TLS private key")
        if any(ch in tls_cert_path + tls_key_path for ch in "\r\n;"):
            raise ValueError("пути TLS содержат недопустимые символы")

    if profile in TLS_INBOUND_PROFILES:
        if not transport_listen or not transport_listen.strip():
            raise ValueError("локальный listen Xray не может быть пустым")
        try:
            local_ip = ipaddress.ip_address(transport_listen.strip())
        except ValueError as exc:
            raise ValueError("локальный listen Xray должен быть IP-адресом") from exc
        if not local_ip.is_loopback:
            raise ValueError("для TLS-профиля через Nginx Xray должен слушать только loopback-адрес")
        if not 1 <= int(transport_port) <= 65535:
            raise ValueError("локальный порт Xray должен быть от 1 до 65535")

    if profile in HYSTERIA_ACTIVE_PROFILES:
        cert_file = Path(tls_cert_path)
        key_file = Path(tls_key_path)
        if not cert_file.is_file() or not key_file.is_file():
            missing = []
            if not cert_file.is_file():
                missing.append(str(cert_file))
            if not key_file.is_file():
                missing.append(str(key_file))
            raise ValueError(
                "Hysteria 2: не найдены файлы TLS-сертификата: " + ", ".join(missing)
            )
        try:
            direct_ip = ipaddress.ip_address(listen.strip())
        except ValueError as exc:
            raise ValueError("Hysteria 2 listen должен быть IP-адресом") from exc
        if direct_ip.is_loopback:
            raise ValueError("Hysteria 2 должен слушать публичный UDP-интерфейс, а не loopback")
        if not 10 <= int(hysteria_udp_idle_timeout) <= 3600:
            raise ValueError("UDP idle timeout должен быть от 10 до 3600 секунд")
        masq_type = (hysteria_masquerade_type or "").strip().lower()
        if masq_type not in {"", "string", "proxy", "file"}:
            raise ValueError("неподдерживаемый режим Hysteria masquerade")
        if masq_type == "proxy":
            parsed = urlparse((hysteria_masquerade_url or "").strip())
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("для proxy masquerade укажите полный URL http:// или https://")
        if masq_type == "file":
            directory = str(hysteria_masquerade_dir or "").strip()
            if not directory.startswith("/") or any(ch in directory for ch in "\r\n;"):
                raise ValueError("для статического сайта укажите абсолютный безопасный путь к каталогу")
        if len(hysteria_masquerade_content or "") > 8192:
            raise ValueError("текст Hysteria masquerade не должен превышать 8192 символа")
        if not 200 <= int(hysteria_masquerade_status) <= 599:
            raise ValueError("HTTP status masquerade должен быть от 200 до 599")
        _parse_hysteria_headers(hysteria_masquerade_headers)
        if hysteria_performance_profile not in ALLOWED_HYSTERIA_PRESETS:
            raise ValueError("неподдерживаемый пресет Hysteria 2")
        if hysteria_congestion not in ALLOWED_HYSTERIA_CONGESTION:
            raise ValueError("неподдерживаемый алгоритм congestion control")
        if hysteria_bbr_profile not in ALLOWED_HYSTERIA_BBR_PROFILES:
            raise ValueError("неподдерживаемый профиль BBR")
        _validate_hysteria_rate(hysteria_brutal_up, "Лимит Upload")
        _validate_hysteria_rate(hysteria_brutal_down, "Лимит Download")
        if not 4 <= int(hysteria_max_idle_timeout) <= 120:
            raise ValueError("QUIC max idle timeout должен быть от 4 до 120 секунд")
        keepalive = int(hysteria_keepalive_period)
        if keepalive != 0 and not 2 <= keepalive <= 60:
            raise ValueError("QUIC KeepAlive должен быть 0 или от 2 до 60 секунд")
        if int(hysteria_max_incoming_streams) < 8:
            raise ValueError("максимум входящих потоков не должен быть меньше 8")
        _validate_hysteria_hop_ports(hysteria_udp_hop_ports)
        _validate_hysteria_hop_interval(hysteria_udp_hop_interval)
        windows = {
            "начальное окно потока": int(hysteria_init_stream_receive_window),
            "максимальное окно потока": int(hysteria_max_stream_receive_window),
            "начальное окно соединения": int(hysteria_init_connection_receive_window),
            "максимальное окно соединения": int(hysteria_max_connection_receive_window),
        }
        if any(value < 65536 or value > 1073741824 for value in windows.values()):
            raise ValueError("QUIC-окна должны быть от 65536 до 1073741824 байт")
        if windows["начальное окно потока"] > windows["максимальное окно потока"]:
            raise ValueError("начальное окно потока не может быть больше максимального")
        if windows["начальное окно соединения"] > windows["максимальное окно соединения"]:
            raise ValueError("начальное окно соединения не может быть больше максимального")


def update_server_settings(
    *,
    address: str,
    listen: str,
    port: int,
    dest: str,
    server_name: str,
    private_key: str,
    public_key: str,
    short_id: str,
    fingerprint: str,
    flow: str,
    loglevel: str,
    api_listen: str,
    stats_enabled: bool,
    config_path: str,
    xray_bin: str,
    xray_service: str,
    inbound_profile: str | None = None,
    transport_listen: str | None = None,
    transport_port: int | None = None,
    xhttp_path: str | None = None,
    xhttp_mode: str | None = None,
    grpc_service_name: str | None = None,
    tls_cert_path: str | None = None,
    tls_key_path: str | None = None,
    hysteria_udp_idle_timeout: int | None = None,
    hysteria_masquerade_type: str | None = None,
    hysteria_masquerade_url: str | None = None,
    hysteria_masquerade_content: str | None = None,
    hysteria_masquerade_status: int | None = None,
    hysteria_masquerade_dir: str | None = None,
    hysteria_masquerade_rewrite_host: bool | None = None,
    hysteria_masquerade_insecure: bool | None = None,
    hysteria_masquerade_headers: str | None = None,
    hysteria_performance_profile: str | None = None,
    hysteria_congestion: str | None = None,
    hysteria_bbr_profile: str | None = None,
    hysteria_brutal_up: str | None = None,
    hysteria_brutal_down: str | None = None,
    hysteria_quic_debug: bool | None = None,
    hysteria_max_idle_timeout: int | None = None,
    hysteria_keepalive_period: int | None = None,
    hysteria_disable_pmtud: bool | None = None,
    hysteria_max_incoming_streams: int | None = None,
    hysteria_udp_hop_ports: str | None = None,
    hysteria_udp_hop_interval: str | None = None,
    hysteria_init_stream_receive_window: int | None = None,
    hysteria_max_stream_receive_window: int | None = None,
    hysteria_init_connection_receive_window: int | None = None,
    hysteria_max_connection_receive_window: int | None = None,
    hysteria_instances: list[dict[str, object]] | None = None,
    xhttp_instances: list[dict[str, object]] | None = None,
    reality_instances: list[dict[str, object]] | None = None,
) -> sqlite3.Row:
    current = get_server()
    profile = (inbound_profile or current["inbound_profile"] or "raw_reality").strip()
    previous_profile = str(current["inbound_profile"] or "raw_reality")
    normalized_server_name = (server_name or "").strip()
    reality_name = (dest or "").rsplit(":", 1)[0].strip().strip("[]")
    if profile != previous_profile:
        previous_name = str(current["server_name"] or "").strip()
        if profile == RUSSIA_KIT_PROFILE:
            # Keep the existing REALITY camouflage name. The own TLS domain is
            # read independently from reality-edge.env.
            normalized_server_name = previous_name or reality_name
        elif profile in CERTIFICATE_INBOUND_PROFILES and normalized_server_name in {"", previous_name, reality_name}:
            normalized_server_name = _hostname_candidate(address)
        elif profile in REALITY_INBOUND_PROFILES and normalized_server_name in {"", previous_name, address.strip()}:
            normalized_server_name = reality_name
    local_listen = (transport_listen or current["transport_listen"] or "127.0.0.1").strip()
    local_port = int(transport_port or current["transport_port"] or 8443)
    path = (xhttp_path or current["xhttp_path"] or "/sg-xhttp").strip()
    mode = (xhttp_mode or current["xhttp_mode"] or "auto").strip()
    service_name = (grpc_service_name or current["grpc_service_name"] or "sg-grpc").strip()
    tls_domain = _hostname_candidate(normalized_server_name) or _hostname_candidate(address)
    if tls_domain:
        default_cert, default_key = _default_tls_paths(tls_domain)
    else:
        default_cert, default_key = "", ""
    cert_path = (tls_cert_path if tls_cert_path is not None else current["tls_cert_path"]).strip() or default_cert
    key_path = (tls_key_path if tls_key_path is not None else current["tls_key_path"]).strip() or default_key
    if profile == RUSSIA_KIT_PROFILE:
        edge = _russia_kit_edge(current)
        cert_path = str(edge["cert"])
        key_path = str(edge["key"])
        local_listen = "127.0.0.1"
        local_port = RUSSIA_KIT_XHTTP_TLS_PORT
        path = RUSSIA_KIT_XHTTP_TLS_PATH
        listen = "0.0.0.0"
        port = 443
    hy_idle = int(hysteria_udp_idle_timeout if hysteria_udp_idle_timeout is not None else current["hysteria_udp_idle_timeout"] or 60)
    hy_masq_type = (hysteria_masquerade_type if hysteria_masquerade_type is not None else current["hysteria_masquerade_type"] or "").strip().lower()
    hy_masq_url = (hysteria_masquerade_url if hysteria_masquerade_url is not None else current["hysteria_masquerade_url"] or "").strip()
    hy_masq_content = hysteria_masquerade_content if hysteria_masquerade_content is not None else str(current["hysteria_masquerade_content"] or "")
    hy_masq_status = int(hysteria_masquerade_status if hysteria_masquerade_status is not None else current["hysteria_masquerade_status"] or 404)
    hy_masq_dir = str(hysteria_masquerade_dir if hysteria_masquerade_dir is not None else current["hysteria_masquerade_dir"] or "").strip()
    hy_masq_rewrite = bool(hysteria_masquerade_rewrite_host if hysteria_masquerade_rewrite_host is not None else current["hysteria_masquerade_rewrite_host"])
    hy_masq_insecure = bool(hysteria_masquerade_insecure if hysteria_masquerade_insecure is not None else current["hysteria_masquerade_insecure"])
    hy_masq_headers = str(hysteria_masquerade_headers if hysteria_masquerade_headers is not None else current["hysteria_masquerade_headers"] or "{}").strip() or "{}"
    hy_preset = str(hysteria_performance_profile if hysteria_performance_profile is not None else current["hysteria_performance_profile"] or "auto").strip().lower()
    hy_congestion = str(hysteria_congestion if hysteria_congestion is not None else current["hysteria_congestion"] or "brutal").strip().lower()
    hy_bbr = str(hysteria_bbr_profile if hysteria_bbr_profile is not None else current["hysteria_bbr_profile"] or "standard").strip().lower()
    hy_up = _validate_hysteria_rate(str(hysteria_brutal_up if hysteria_brutal_up is not None else current["hysteria_brutal_up"] or "0"), "Лимит Upload")
    hy_down = _validate_hysteria_rate(str(hysteria_brutal_down if hysteria_brutal_down is not None else current["hysteria_brutal_down"] or "0"), "Лимит Download")
    hy_debug = bool(hysteria_quic_debug if hysteria_quic_debug is not None else current["hysteria_quic_debug"])
    hy_max_idle = int(hysteria_max_idle_timeout if hysteria_max_idle_timeout is not None else current["hysteria_max_idle_timeout"] or 30)
    hy_keepalive = int(hysteria_keepalive_period if hysteria_keepalive_period is not None else current["hysteria_keepalive_period"] or 0)
    hy_disable_pmtud = bool(hysteria_disable_pmtud if hysteria_disable_pmtud is not None else current["hysteria_disable_pmtud"])
    hy_streams = int(hysteria_max_incoming_streams if hysteria_max_incoming_streams is not None else current["hysteria_max_incoming_streams"] or 1024)
    hy_hop_ports = _validate_hysteria_hop_ports(str(hysteria_udp_hop_ports if hysteria_udp_hop_ports is not None else current["hysteria_udp_hop_ports"] or ""))
    hy_hop_interval = _validate_hysteria_hop_interval(str(hysteria_udp_hop_interval if hysteria_udp_hop_interval is not None else current["hysteria_udp_hop_interval"] or "30"))
    hy_isrw = int(hysteria_init_stream_receive_window if hysteria_init_stream_receive_window is not None else current["hysteria_init_stream_receive_window"] or 8388608)
    hy_msrw = int(hysteria_max_stream_receive_window if hysteria_max_stream_receive_window is not None else current["hysteria_max_stream_receive_window"] or 8388608)
    hy_icrw = int(hysteria_init_connection_receive_window if hysteria_init_connection_receive_window is not None else current["hysteria_init_connection_receive_window"] or 20971520)
    hy_mcrw = int(hysteria_max_connection_receive_window if hysteria_max_connection_receive_window is not None else current["hysteria_max_connection_receive_window"] or 20971520)
    cleaned_hysteria_instances = None
    if profile in HYSTERIA_ACTIVE_PROFILES:
        cleaned_hysteria_instances = _normalise_hysteria_instances(
            hysteria_instances,
            primary_listen=listen.strip(),
            primary_port=int(port),
            hop_ports=hy_hop_ports,
        )
    cleaned_xhttp_instances = None
    if profile in XHTTP_ACTIVE_PROFILES:
        cleaned_xhttp_instances = _normalise_xhttp_instances(
            xhttp_instances,
            primary_listen=local_listen,
            primary_port=local_port,
            primary_path=path,
        )
    cleaned_reality_instances = None
    effective_short_id = short_id.strip().lower()
    if profile in {"raw_reality", RUSSIA_KIT_PROFILE}:
        if not effective_short_id:
            supplied_primary = next(
                (
                    str(item.get("short_id", "")).strip().lower()
                    for item in (reality_instances or [])
                    if int(item.get("id", 0)) == 1 and str(item.get("short_id", "")).strip()
                ),
                "",
            )
            stored_primary = next(
                (
                    str(row["short_id"] or "").strip().lower()
                    for row in list_reality_inbounds()
                    if int(row["id"]) == 1 and str(row["short_id"] or "").strip()
                ),
                "",
            )
            effective_short_id = (
                supplied_primary
                or stored_primary
                or str(current["short_id"] or "").strip().lower()
                or secrets.token_hex(8)
            )
        if profile == "raw_reality":
            cleaned_reality_instances = _normalise_reality_instances(
                reality_instances,
                primary_listen=listen.strip(),
                primary_port=int(port),
                primary_short_id=effective_short_id,
            )
    normalized_flow = "xtls-rprx-vision" if profile in VISION_INBOUND_PROFILES else ""

    validate_server_values(
        address,
        port,
        dest,
        normalized_server_name,
        private_key,
        public_key,
        effective_short_id if profile in {"raw_reality", RUSSIA_KIT_PROFILE} else short_id,
        flow=normalized_flow,
        loglevel=loglevel,
        api_listen=api_listen,
        listen=listen,
        inbound_profile=profile,
        transport_listen=local_listen,
        transport_port=local_port,
        xhttp_path=path,
        xhttp_mode=mode,
        grpc_service_name=service_name,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        hysteria_udp_idle_timeout=hy_idle,
        hysteria_masquerade_type=hy_masq_type,
        hysteria_masquerade_url=hy_masq_url,
        hysteria_masquerade_content=hy_masq_content,
        hysteria_masquerade_status=hy_masq_status,
        hysteria_masquerade_dir=hy_masq_dir,
        hysteria_masquerade_rewrite_host=hy_masq_rewrite,
        hysteria_masquerade_insecure=hy_masq_insecure,
        hysteria_masquerade_headers=hy_masq_headers,
        hysteria_performance_profile=hy_preset,
        hysteria_congestion=hy_congestion,
        hysteria_bbr_profile=hy_bbr,
        hysteria_brutal_up=hy_up,
        hysteria_brutal_down=hy_down,
        hysteria_quic_debug=hy_debug,
        hysteria_max_idle_timeout=hy_max_idle,
        hysteria_keepalive_period=hy_keepalive,
        hysteria_disable_pmtud=hy_disable_pmtud,
        hysteria_max_incoming_streams=hy_streams,
        hysteria_udp_hop_ports=hy_hop_ports,
        hysteria_udp_hop_interval=hy_hop_interval,
        hysteria_init_stream_receive_window=hy_isrw,
        hysteria_max_stream_receive_window=hy_msrw,
        hysteria_init_connection_receive_window=hy_icrw,
        hysteria_max_connection_receive_window=hy_mcrw,
    )
    fingerprint = normalise_fingerprint_profile(fingerprint)
    paths = {"config_path": config_path, "xray_bin": xray_bin, "xray_service": xray_service}
    if any(not value.strip() for value in paths.values()):
        raise ValueError("системные пути и имя службы не могут быть пустыми")
    with connect() as con:
        con.execute(
            """
            UPDATE server_settings SET
                address = ?, listen = ?, port = ?, dest = ?, server_name = ?,
                private_key = ?, public_key = ?, short_id = ?, fingerprint = ?,
                flow = ?, loglevel = ?, api_listen = ?, stats_enabled = ?,
                config_path = ?, xray_bin = ?, xray_service = ?,
                inbound_profile = ?, transport_listen = ?, transport_port = ?,
                xhttp_path = ?, xhttp_mode = ?, grpc_service_name = ?,
                tls_cert_path = ?, tls_key_path = ?,
                hysteria_udp_idle_timeout = ?, hysteria_masquerade_type = ?,
                hysteria_masquerade_url = ?, hysteria_masquerade_content = ?,
                hysteria_masquerade_status = ?, hysteria_masquerade_dir = ?,
                hysteria_masquerade_rewrite_host = ?, hysteria_masquerade_insecure = ?,
                hysteria_masquerade_headers = ?, hysteria_performance_profile = ?,
                hysteria_congestion = ?, hysteria_bbr_profile = ?,
                hysteria_brutal_up = ?, hysteria_brutal_down = ?,
                hysteria_quic_debug = ?, hysteria_max_idle_timeout = ?,
                hysteria_keepalive_period = ?, hysteria_disable_pmtud = ?,
                hysteria_max_incoming_streams = ?, hysteria_udp_hop_ports = ?,
                hysteria_udp_hop_interval = ?, hysteria_init_stream_receive_window = ?,
                hysteria_max_stream_receive_window = ?, hysteria_init_connection_receive_window = ?,
                hysteria_max_connection_receive_window = ?
            WHERE id = 1
            """,
            (
                address.strip(), listen.strip(), int(port), dest.strip(), normalized_server_name,
                private_key.strip(), public_key.strip(),
                effective_short_id if profile in {"raw_reality", RUSSIA_KIT_PROFILE} else short_id.strip(), fingerprint,
                normalized_flow, loglevel, api_listen.strip(), int(stats_enabled),
                config_path.strip(), xray_bin.strip(), xray_service.strip(),
                profile, local_listen, local_port, path, mode, service_name,
                cert_path, key_path, hy_idle, hy_masq_type, hy_masq_url,
                hy_masq_content, hy_masq_status, hy_masq_dir,
                int(hy_masq_rewrite), int(hy_masq_insecure), hy_masq_headers,
                hy_preset, hy_congestion, hy_bbr, hy_up, hy_down,
                int(hy_debug), hy_max_idle, hy_keepalive, int(hy_disable_pmtud),
                hy_streams, hy_hop_ports, hy_hop_interval,
                hy_isrw, hy_msrw, hy_icrw, hy_mcrw,
            ),
        )
    if profile in HYSTERIA_ACTIVE_PROFILES:
        update_hysteria_inbounds(
            cleaned_hysteria_instances,
            primary_listen=listen.strip(),
            primary_port=int(port),
            hop_ports=hy_hop_ports,
        )
    if profile in XHTTP_ACTIVE_PROFILES:
        update_xhttp_inbounds(
            cleaned_xhttp_instances,
            primary_listen=local_listen,
            primary_port=local_port,
            primary_path=path,
        )
    if profile == "raw_reality":
        update_reality_inbounds(
            cleaned_reality_instances,
            primary_listen=listen.strip(),
            primary_port=int(port),
            primary_short_id=effective_short_id,
        )
    return get_server()


def generate_reality_keys(xray_bin: str | None = None) -> dict[str, str]:
    binary = xray_bin or get_server()["xray_bin"]
    if not Path(binary).is_file() and shutil.which(binary) is None:
        raise FileNotFoundError(f"Xray не найден: {binary}")
    proc = _run([binary, "x25519"])
    if proc.returncode != 0:
        raise XPanelError((proc.stderr or proc.stdout).strip() or "xray x25519 завершился с ошибкой")
    output = proc.stdout + "\n" + proc.stderr
    private_match = re.search(r"(?m)^PrivateKey:\s*(\S+)\s*$", output)
    public_match = re.search(r"(?m)^(?:Password\s*\(PublicKey\)|PublicKey):\s*(\S+)\s*$", output)
    if not private_match or not public_match:
        raise XPanelError("не удалось разобрать вывод xray x25519")
    import secrets

    return {
        "private_key": private_match.group(1).strip(),
        "public_key": public_match.group(1).strip(),
        "short_id": secrets.token_hex(8),
    }


def build_rule_json(row: sqlite3.Row) -> dict[str, object]:
    cleaned: dict[str, object] = {
        "name": row["name"],
        "priority": row["priority"],
        "outbound_tag": row["outbound_tag"],
        "target_type": row["target_type"] or "outbound",
        "domains": row["domains"],
        "ips": row["ips"],
        "ports": row["ports"],
        "network": row["network"],
        "protocols": row["protocols"],
        "inbound_tags": row["inbound_tags"],
        "users": row["users"],
    }
    return _merge_rule_config(_json_object(row["config_json"]), cleaned)


def routing_json_document() -> str:
    settings = get_routing_settings()
    extra = get_routing_extra()
    rules: list[dict[str, object]] = []
    for row in list_routing_rules():
        rules.append(
            {
                "_sgPanel": {
                    "name": row["name"],
                    "priority": row["priority"],
                    "enabled": bool(row["enabled"]),
                },
                **build_rule_json(row),
            }
        )
    document: dict[str, object] = {
        "_sgPanel": {
            "format": "routing-v1",
            "defaultOutboundTag": settings["default_outbound_tag"],
            "note": "_sgPanel хранит имена, порядок и состояние правил; в config.json этот блок не попадает.",
        },
        "domainStrategy": settings["domain_strategy"],
    }
    document.update(extra)
    document["rules"] = rules
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def _balancer_tags_from_extra(extra: dict[str, object]) -> set[str]:
    value = extra.get("balancers", [])
    if value in (None, ""):
        return set()
    if not isinstance(value, list):
        raise ValueError("routing.balancers должен быть массивом")
    tags: set[str] = set()
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"balancers[{index}] должен быть объектом")
        tag = str(item.get("tag", "")).strip()
        if not tag or not OUTBOUND_TAG_RE.fullmatch(tag):
            raise ValueError(f"balancers[{index}]: некорректный tag")
        if tag in tags:
            raise ValueError(f"повторяющийся balancer tag: {tag}")
        tags.add(tag)
    return tags


def update_routing_json_document(text: str) -> dict[str, object]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ValueError("JSON маршрутизации должен быть объектом")
    document = _copy_json_object(document)
    meta = document.pop("_sgPanel", {})
    meta = meta if isinstance(meta, dict) else {}
    domain_strategy = str(document.pop("domainStrategy", "AsIs"))
    if domain_strategy not in ALLOWED_DOMAIN_STRATEGIES:
        raise ValueError("некорректная domainStrategy")
    rules_value = document.pop("rules", [])
    if not isinstance(rules_value, list):
        raise ValueError("routing.rules должен быть массивом")
    extra = document
    balancer_tags = _balancer_tags_from_extra(extra)
    outbound_tags = set(list_outbound_tags(enabled_only=True))
    default_tag = str(meta.get("defaultOutboundTag") or get_routing_settings()["default_outbound_tag"])
    if default_tag == "blocked" or default_tag not in outbound_tags:
        raise ValueError("_sgPanel.defaultOutboundTag отсутствует или отключён")

    parsed_rules: list[tuple[dict[str, object], dict[str, object], bool]] = []
    names: set[str] = set()
    for index, item in enumerate(rules_value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"rules[{index}] должен быть объектом")
        item_copy = _copy_json_object(item)
        item_meta = item_copy.get("_sgPanel")
        if not isinstance(item_meta, dict):
            item_copy["_sgPanel"] = {
                "name": f"JSON rule {index}",
                "priority": min(index * 10, 9999),
                "enabled": True,
            }
        cleaned, config, enabled = parse_rule_json_document(
            json.dumps(item_copy, ensure_ascii=False),
            fallback_name=f"JSON rule {index}",
            fallback_priority=min(index * 10, 9999),
            validate_target=False,
        )
        key = str(cleaned["name"]).casefold()
        if key in names:
            raise ValueError(f"повторяющееся название правила: {cleaned['name']}")
        names.add(key)
        if cleaned["target_type"] == "outbound":
            if cleaned["outbound_tag"] not in outbound_tags:
                raise ValueError(
                    f"правило {cleaned['name']}: outbound {cleaned['outbound_tag']} отсутствует или отключён"
                )
        elif cleaned["outbound_tag"] not in balancer_tags:
            raise ValueError(
                f"правило {cleaned['name']}: balancer {cleaned['outbound_tag']} не найден"
            )
        parsed_rules.append((cleaned, config, enabled))

    with connect() as con:
        con.execute(
            """
            UPDATE routing_settings SET domain_strategy = ?, default_outbound_tag = ?,
                extra_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (
                domain_strategy,
                default_tag,
                json.dumps(extra, ensure_ascii=False, separators=(",", ":")),
            ),
        )
        con.execute("DELETE FROM routing_rules")
        for cleaned, config, enabled in parsed_rules:
            con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, target_type, domains, ips, ports,
                     network, protocols, inbound_tags, users, config_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned["name"], cleaned["priority"], int(enabled),
                    cleaned["outbound_tag"], cleaned["target_type"], cleaned["domains"],
                    cleaned["ips"], cleaned["ports"], cleaned["network"],
                    cleaned["protocols"], cleaned["inbound_tags"], cleaned["users"],
                    json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                ),
            )
    return {
        "rules": len(parsed_rules),
        "balancers": len(balancer_tags),
        "domain_strategy": domain_strategy,
    }


def add_geo_policy(
    *,
    kind: str,
    value: str,
    outbound_tag: str,
    priority: int = 100,
    name: str = "",
) -> list[sqlite3.Row]:
    kind = (kind or "").strip().lower()
    value = (value or "").strip().lower()
    priority = int(priority)
    if outbound_tag not in set(list_outbound_tags(enabled_only=True)):
        raise ValueError("выбранный выход отсутствует или отключён")
    if not 1 <= priority <= 9998:
        raise ValueError("приоритет должен быть от 1 до 9998")
    specs: list[dict[str, object]] = []
    if kind == "ads":
        base_name = name.strip() or "Блокировка рекламы"
        specs.append({"name": base_name, "priority": priority, "domains": "geosite:category-ads-all"})
    elif kind == "private":
        base_name = name.strip() or "Локальные сети"
        specs.append({"name": base_name, "priority": priority, "ips": "geoip:private"})
    elif kind == "country":
        if not re.fullmatch(r"[a-z]{2}", value):
            raise ValueError("код страны должен состоять из двух латинских букв, например fr")
        base_name = name.strip() or f"Страна {value.upper()}"
        specs.extend(
            [
                {"name": f"{base_name} — домены", "priority": priority, "domains": f"geosite:{value}"},
                {"name": f"{base_name} — IP", "priority": priority + 1, "ips": f"geoip:{value}"},
            ]
        )
    elif kind == "geosite":
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}", value):
            raise ValueError("некорректное имя geosite-категории")
        base_name = name.strip() or f"Geosite {value}"
        specs.append({"name": base_name, "priority": priority, "domains": f"geosite:{value}"})
    else:
        raise ValueError("неизвестный шаблон гео-правила")

    cleaned_rows: list[dict[str, object]] = []
    for spec in specs:
        cleaned_rows.append(
            validate_rule_values(
                name=str(spec["name"]),
                priority=int(spec["priority"]),
                outbound_tag=outbound_tag,
                target_type="outbound",
                domains=str(spec.get("domains", "")),
                ips=str(spec.get("ips", "")),
            )
        )
    try:
        with connect() as con:
            ids: list[int] = []
            for cleaned in cleaned_rows:
                config = _merge_rule_config({}, cleaned)
                cur = con.execute(
                    """
                    INSERT INTO routing_rules
                        (name, priority, enabled, outbound_tag, target_type, domains, ips,
                         ports, network, protocols, inbound_tags, users, config_json)
                    VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cleaned["name"], cleaned["priority"], cleaned["outbound_tag"],
                        cleaned["target_type"], cleaned["domains"], cleaned["ips"],
                        cleaned["ports"], cleaned["network"], cleaned["protocols"],
                        cleaned["inbound_tags"], cleaned["users"],
                        json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                    ),
                )
                ids.append(int(cur.lastrowid))
    except sqlite3.IntegrityError as exc:
        raise XPanelError("правило с таким названием уже существует") from exc
    return [find_routing_rule(rule_id) for rule_id in ids]


def _json_object_text(value: object, *, label: str) -> tuple[dict[str, object], str]:
    text = str(value or "{}").strip() or "{}"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{label}: JSON, строка {exc.lineno}, столбец {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label}: корень JSON должен быть объектом")
    return parsed, json.dumps(parsed, ensure_ascii=False, indent=2) + "\n"


def _validate_xmux_conflicts(value: object, *, label: str, path: str = "$") -> None:
    """Reject every XMUX object that defines both mutually exclusive controls."""
    if isinstance(value, dict):
        xmux = value.get("xmux")
        if isinstance(xmux, dict):
            if "maxConnections" in xmux and "maxConcurrency" in xmux:
                raise ValueError(
                    f"{label}: XMUX {path}.xmux не может одновременно содержать "
                    "maxConnections и maxConcurrency"
                )
        for key, nested in value.items():
            _validate_xmux_conflicts(nested, label=label, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _validate_xmux_conflicts(nested, label=label, path=f"{path}[{index}]")


def _contains_custom_padding(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).casefold() in {"xpaddingbytes", "paddingbytes", "padding"}:
                return True
            if _contains_custom_padding(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_custom_padding(item) for item in value)
    return False


def _validate_finalmask_object(value: dict[str, object], *, label: str) -> None:
    """Validate the documented streamSettings.finalmask object shape."""
    allowed = {"tcp", "udp", "quicParams"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(
            f"{label}: неизвестные поля верхнего уровня: {', '.join(unknown)}; "
            "разрешены tcp, udp и quicParams"
        )

    configured = False
    for family in ("tcp", "udp"):
        if family not in value:
            continue
        entries = value[family]
        if not isinstance(entries, list):
            raise ValueError(f"{label}: {family} должен быть массивом масок")
        if entries:
            configured = True
        for index, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                raise ValueError(
                    f"{label}: {family}[{index}] должен быть JSON-объектом"
                )
            mask_type = entry.get("type")
            if not isinstance(mask_type, str) or not mask_type.strip():
                raise ValueError(
                    f"{label}: {family}[{index}].type должен быть непустой строкой"
                )
            settings = entry.get("settings", {})
            if not isinstance(settings, dict):
                raise ValueError(
                    f"{label}: {family}[{index}].settings должен быть JSON-объектом"
                )
            extra = sorted(set(entry) - {"type", "settings"})
            if extra:
                raise ValueError(
                    f"{label}: {family}[{index}] содержит неизвестные поля: "
                    f"{', '.join(extra)}"
                )

    if "quicParams" in value:
        if not isinstance(value["quicParams"], dict):
            raise ValueError(f"{label}: quicParams должен быть JSON-объектом")
        if value["quicParams"]:
            configured = True

    if value and not configured:
        raise ValueError(
            f"{label}: укажите хотя бы одну TCP/UDP-маску или непустой quicParams"
        )


def _normalise_cert_pin(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    result: list[str] = []
    for item in raw.split(","):
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", item)
        if len(cleaned) != 64:
            raise ValueError(
                "Certificate pinning: каждый SHA-256 должен содержать 64 HEX-символа"
            )
        result.append(cleaned.lower())
    return ",".join(dict.fromkeys(result))


def _normalise_tls_verify_name(mode: object, value: object) -> tuple[str, str]:
    selected = str(mode or "auto").strip().lower()
    if selected not in {"auto", "manual"}:
        raise ValueError("Проверка имени сертификата: выберите auto или manual")
    if selected == "auto":
        return selected, ""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Проверка имени сертификата: укажите имя для ручного режима")
    names: list[str] = []
    for item in raw.split(","):
        name = item.strip().rstrip(".")
        if not name:
            continue
        if name == "FromMitM":
            names.append(name)
            continue
        candidate = name.strip("[]")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            if not _hostname_candidate(candidate):
                raise ValueError(
                    "Проверка имени сертификата: используйте доменные имена или IP через запятую"
                )
        names.append(name)
    if not names:
        raise ValueError("Проверка имени сертификата: список имён пуст")
    return selected, ",".join(dict.fromkeys(names))


def _normalise_client_ca_pem(
    value: object, source: object = ""
) -> tuple[str, str, str]:
    text = str(value or "").strip()
    label = str(source or "").strip()[:240]
    if not text:
        return "", label, ""
    if len(text.encode("utf-8")) > 262144:
        raise ValueError("Пользовательский CA PEM не должен превышать 256 КБ")
    if "PRIVATE KEY" in text:
        raise ValueError("Пользовательский CA PEM не должен содержать закрытый ключ")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        text,
        flags=re.S,
    )
    if not blocks:
        raise ValueError("Пользовательский CA PEM: не найден сертификат PEM")
    normalised = "\n".join(block.strip() for block in blocks) + "\n"
    if shutil.which("openssl"):
        temp_name = ""
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
                handle.write(normalised)
                temp_name = handle.name
            check = subprocess.run(
                ["openssl", "crl2pkcs7", "-nocrl", "-certfile", temp_name, "-outform", "PEM"],
                capture_output=True,
                timeout=15,
                check=False,
            )
            if check.returncode != 0:
                detail = check.stderr.decode("utf-8", "replace").strip()
                raise ValueError(detail or "Пользовательский CA PEM не прошёл проверку OpenSSL")
        finally:
            if temp_name:
                Path(temp_name).unlink(missing_ok=True)
    return normalised, label, hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def load_client_ca_pem(path_value: object) -> dict[str, str]:
    path = Path(str(path_value or "").strip()).expanduser()
    if not path.is_file():
        raise ValueError(f"CA PEM не найден: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("CA PEM должен быть текстовым PEM-файлом") from exc
    pem, source, sha256 = _normalise_client_ca_pem(raw, str(path))
    return {"pem": pem, "source": source, "sha256": sha256}


def _validate_ech_dns_source(value: str) -> None:
    raw = str(value or "").strip()
    resolver = raw
    if "+" in raw:
        lookup_name, resolver = raw.split("+", 1)
        if not _hostname_candidate(lookup_name.strip()):
            raise ValueError("ECH DNS: перед '+' укажите корректное доменное имя")
    parsed = urlparse(resolver)
    if parsed.scheme not in {"udp", "https", "h2c"} or not parsed.hostname:
        raise ValueError("ECH DNS: используйте udp://, https:// или h2c:// источник")
    if parsed.username or parsed.password:
        raise ValueError("ECH DNS: источник не должен содержать логин или пароль")


def get_transport_expert_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute(
            "SELECT * FROM transport_expert_settings WHERE id = 1"
        ).fetchone()
    if row is None:
        raise XPanelError("экспертные настройки транспорта не инициализированы")
    return row


def update_transport_expert_settings(
    *,
    xhttp_mode: object = "auto",
    xmux_mode: object = "auto",
    xhttp_extra_server_json: object = "{}",
    xhttp_extra_client_json: object = "{}",
    finalmask_enabled: bool = False,
    finalmask_server_json: object = "{}",
    finalmask_client_json: object = "{}",
    ech_mode: str = "off",
    ech_public_name: object = "",
    ech_server_keys: object = "",
    ech_config_list: object = "",
    certificate_pinning_enabled: bool = False,
    certificate_pinning_sha256: object = "",
    certificate_pinning_source: object = "",
    tls_verify_name_mode: object = "auto",
    tls_verify_name: object = "",
    client_ca_pem: object = "",
    client_ca_source: object = "",
) -> sqlite3.Row:
    mode_xhttp = str(xhttp_mode or "auto").strip().lower()
    if mode_xhttp not in ALLOWED_XHTTP_MODES:
        raise ValueError("XHTTP Mode: разрешены auto, packet-up, stream-up и stream-one")
    mode_xmux = str(xmux_mode or "auto").strip().lower()
    if mode_xmux not in ALLOWED_XMUX_MODES:
        raise ValueError("XMUX: разрешены auto, reduced и expert")
    xhttp_server_obj, xhttp_server = _json_object_text(
        xhttp_extra_server_json, label="XHTTP Server Extra"
    )
    xhttp_client_obj, xhttp_client = _json_object_text(
        xhttp_extra_client_json, label="XHTTP Client Extra"
    )
    _validate_xmux_conflicts(xhttp_server_obj, label="XHTTP Server Extra")
    _validate_xmux_conflicts(xhttp_client_obj, label="XHTTP Client Extra")
    finalmask_server_obj, finalmask_server = _json_object_text(
        finalmask_server_json, label="FinalMask Server"
    )
    finalmask_client_obj, finalmask_client = _json_object_text(
        finalmask_client_json, label="FinalMask Client"
    )
    if finalmask_enabled and not finalmask_server_obj:
        raise ValueError("FinalMask: Server JSON не может быть пустым при включении")
    if finalmask_enabled and not finalmask_client_obj:
        raise ValueError("FinalMask: Client JSON не может быть пустым при включении")
    if finalmask_enabled:
        _validate_finalmask_object(finalmask_server_obj, label="FinalMask Server")
        _validate_finalmask_object(finalmask_client_obj, label="FinalMask Client")

    mode = str(ech_mode or "off").strip().lower()
    if mode not in {"off", "generated", "existing", "dns"}:
        raise ValueError("ECH: неизвестный режим")
    public_name = str(ech_public_name or "").strip()
    server_keys = str(ech_server_keys or "").strip()
    config_list = str(ech_config_list or "").strip()
    if mode != "off":
        if not public_name:
            raise ValueError("ECH: укажите Outer Server Name")
        if not server_keys:
            raise ValueError("ECH: отсутствует echServerKeys для серверной стороны")
        if not config_list:
            raise ValueError("ECH: отсутствует echConfigList для клиентской стороны")
    if mode == "dns":
        _validate_ech_dns_source(config_list)

    pin = _normalise_cert_pin(certificate_pinning_sha256)
    if certificate_pinning_enabled and not pin:
        raise ValueError("Certificate pinning: сначала рассчитайте или укажите SHA-256")
    pin_source = str(certificate_pinning_source or "").strip()[:240]
    verify_mode, verify_name = _normalise_tls_verify_name(
        tls_verify_name_mode, tls_verify_name
    )
    ca_pem, ca_source, ca_sha256 = _normalise_client_ca_pem(
        client_ca_pem, client_ca_source
    )

    with connect() as con:
        con.execute("UPDATE server_settings SET xhttp_mode=? WHERE id=1", (mode_xhttp,))
        con.execute(
            """
            UPDATE transport_expert_settings SET
                xmux_mode=?,
                xhttp_extra_server_json=?, xhttp_extra_client_json=?,
                finalmask_enabled=?, finalmask_server_json=?, finalmask_client_json=?,
                ech_mode=?, ech_public_name=?, ech_server_keys=?, ech_config_list=?,
                certificate_pinning_enabled=?, certificate_pinning_sha256=?,
                certificate_pinning_source=?, tls_verify_name_mode=?, tls_verify_name=?,
                client_ca_pem=?, client_ca_source=?, client_ca_sha256=?,
                last_validation_state='ok',
                last_validation_message='Серверные и клиентские форматы проверены',
                last_validation_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (
                mode_xmux, xhttp_server, xhttp_client, int(bool(finalmask_enabled)),
                finalmask_server, finalmask_client, mode, public_name,
                server_keys, config_list, int(bool(certificate_pinning_enabled)),
                pin, pin_source, verify_mode, verify_name,
                ca_pem, ca_source, ca_sha256,
            ),
        )
    return get_transport_expert_settings()

def _profile_expert_status(profile: str, expert: sqlite3.Row) -> dict[str, dict[str, str]]:
    is_xhttp = profile in {"xhttp_tls", "xhttp_reality", "xhttp_hysteria_tls", RUSSIA_KIT_PROFILE}
    is_tls = profile in CERTIFICATE_INBOUND_PROFILES
    # XHTTP/gRPC TLS is terminated by Nginx. Direct Xray TLS is used by Hysteria 2.
    ech_applicable = profile in HYSTERIA_ACTIVE_PROFILES
    xhttp_extra_configured = any(
        str(expert[name] or "").strip() not in {"", "{}"}
        for name in ("xhttp_extra_server_json", "xhttp_extra_client_json")
    )
    pinning = bool(expert["certificate_pinning_enabled"])
    custom_ca = bool(str(expert["client_ca_pem"] or "").strip())
    manual_name = str(expert["tls_verify_name_mode"] or "auto") == "manual"
    if not is_tls:
        tls_state, tls_label = "not_applicable", "Не применимо"
    elif pinning:
        tls_state, tls_label = "configured", "SHA-256 закреплён"
    elif custom_ca:
        tls_state, tls_label = "configured", "Пользовательский CA"
    elif manual_name:
        tls_state, tls_label = "configured", "System CA + отдельное имя"
    else:
        tls_state, tls_label = "neutral", "System CA — рекомендуется"
    return {
        "xhttp_extra": {
            "state": "configured" if is_xhttp and xhttp_extra_configured else ("neutral" if is_xhttp else "not_applicable"),
            "label": "Настроено" if is_xhttp and xhttp_extra_configured else ("Стандартные значения" if is_xhttp else "Не применимо"),
        },
        "finalmask": {
            "state": "configured" if bool(expert["finalmask_enabled"]) else "neutral",
            "label": "Настроено" if bool(expert["finalmask_enabled"]) else "Выключено — рекомендуется",
        },
        "ech": {
            "state": "configured" if ech_applicable and expert["ech_mode"] != "off" else ("neutral" if ech_applicable else "not_applicable"),
            "label": "Настроено" if ech_applicable and expert["ech_mode"] != "off" else ("Off — стандартный TLS" if ech_applicable else "Не применимо к текущей схеме"),
        },
        "pinning": {"state": tls_state, "label": tls_label},
        "tls_verification": {"state": tls_state, "label": tls_label},
    }


def get_transport_expert_overview() -> dict[str, object]:
    server = get_server()
    expert = get_transport_expert_settings()
    profile = str(server["inbound_profile"] or "raw_reality")
    mode = str(server["xhttp_mode"] or "auto")
    mode_labels = {
        "auto": "Автоматически — Xray-core",
        "packet-up": "Packet Up",
        "stream-up": "Stream Up",
        "stream-one": "Stream One",
    }
    xmux_mode = str(expert["xmux_mode"] or "auto")
    xmux_labels = {
        "auto": "Автоматически",
        "reduced": "Сниженное число соединений",
        "expert": "Эксперт",
    }
    tls_applicable = profile in CERTIFICATE_INBOUND_PROFILES
    ech_applicable = profile in HYSTERIA_ACTIVE_PROFILES
    xhttp_applicable = profile in {"xhttp_tls", "xhttp_reality", "xhttp_hysteria_tls", RUSSIA_KIT_PROFILE}
    verify_mode = str(expert["tls_verify_name_mode"] or "auto")
    verify_override = str(expert["tls_verify_name"] or "").strip()
    default_verify_name = (
        _russia_kit_tls_domain(server)
        if profile == RUSSIA_KIT_PROFILE and tls_applicable
        else str(server["server_name"] or "").strip() if tls_applicable else ""
    )
    effective_verify_name = verify_override if verify_mode == "manual" else default_verify_name
    ca_pem = str(expert["client_ca_pem"] or "")
    server_extra = _effective_xhttp_extra("server", expert=expert)
    client_extra = _effective_xhttp_extra("client", expert=expert)
    try:
        from .xray_update_manager import installed_xray_version
        xray_version = installed_xray_version(str(server["xray_bin"] or "/usr/local/bin/xray"))
    except (OSError, ValueError, IndexError):
        xray_version = ""
    effective = {
        "xhttp_mode": mode,
        "xhttp_mode_label": mode_labels.get(mode, mode),
        "xmux_mode": xmux_mode,
        "xmux_mode_label": xmux_labels.get(xmux_mode, xmux_mode),
        "padding_label": (
            "Эксперт" if _contains_custom_padding(server_extra) or _contains_custom_padding(client_extra)
            else "Стандартный Xray"
        ),
        "xray_version": xray_version or "не определена",
        "xhttp_server_extra": json.dumps(server_extra, ensure_ascii=False, separators=(",", ":")),
        "xhttp_client_extra": json.dumps(client_extra, ensure_ascii=False, separators=(",", ":")),
        "finalmask_server": str(expert["finalmask_server_json"] or "{}").strip() or "{}",
        "finalmask_client": str(expert["finalmask_client_json"] or "{}").strip() or "{}",
        "finalmask_enabled": bool(expert["finalmask_enabled"]),
        "ech_mode": str(expert["ech_mode"] or "off"),
        "ech_public_name": str(expert["ech_public_name"] or ""),
        "pinning_enabled": bool(expert["certificate_pinning_enabled"]),
        "pinning_sha256": str(expert["certificate_pinning_sha256"] or ""),
        "tls_verify_name_mode": verify_mode,
        "tls_verify_name": verify_override,
        "tls_verify_name_effective": effective_verify_name,
        "client_ca_enabled": bool(ca_pem.strip()),
        "client_ca_sha256": str(expert["client_ca_sha256"] or ""),
        "client_ca_source": str(expert["client_ca_source"] or ""),
    }
    return {
        "settings": expert,
        "effective": effective,
        "profile": profile,
        "context": {
            "is_reality": profile in REALITY_INBOUND_PROFILES,
            "tls_applicable": tls_applicable,
            "ech_applicable": ech_applicable,
            "xhttp_applicable": xhttp_applicable,
            "tls_terminated_by_nginx": profile in TLS_INBOUND_PROFILES or profile == RUSSIA_KIT_PROFILE,
        },
        "statuses": _profile_expert_status(profile, expert),
        "xhttp_server_example": json.dumps(
            {"xmux": {"maxConcurrency": "16-32"}},
            ensure_ascii=False, indent=2,
        ),
        "xhttp_client_example": json.dumps(
            {"xmux": {"maxConnections": 2}},
            ensure_ascii=False, indent=2,
        ),
        "xmux_reduced_preset": json.dumps(
            {"xmux": XMUX_REDUCED_PRESET}, ensure_ascii=False, indent=2
        ),
        "finalmask_example": json.dumps(
            {
                "tcp": [
                    {
                        "type": "fragment",
                        "settings": {
                            "packets": "tlshello",
                            "lengths": ["3-5", "6-8"],
                            "delays": ["10-20"],
                            "maxSplit": "3-6",
                        },
                    }
                ]
            },
            ensure_ascii=False,
            indent=2,
        ),
    }



def get_expert_core_overview() -> dict[str, object]:
    """Return the local Xray policy and the last safe update operation state."""
    server = get_server()
    try:
        from .xray_update_manager import get_xray_update_status, installed_xray_version
        installed = installed_xray_version(str(server["xray_bin"] or "/usr/local/bin/xray"))
        update_status = get_xray_update_status()
    except (OSError, ValueError, IndexError):
        installed = ""
        update_status = {"state": "unknown", "message": "Состояние обновления недоступно", "log": ""}
    return {
        "installed": installed or "не определена",
        "recommended": _validated_xray_version(),
        "service": (_run(["systemctl", "is-active", str(server["xray_service"])]).stdout.strip() or "unknown"),
        "update": update_status,
    }


def nginx_transport_document() -> str:
    """Render the Nginx frontend that belongs to the active Xray scheme."""
    server = get_server()
    profile = str(server["inbound_profile"] or "raw_reality")
    try:
        if profile == RUSSIA_KIT_PROFILE:
            stream, web = _nginx_reality_edge_configs(server)
            return stream.rstrip() + "\n\n" + web.rstrip() + "\n"
        if profile in CERTIFICATE_INBOUND_PROFILES:
            return _nginx_transport_config(server)
        if profile in REALITY_INBOUND_PROFILES and _reality_edge_settings(server).get("enabled"):
            stream, web = _nginx_reality_edge_configs(server)
            return stream.rstrip() + "\n\n" + web.rstrip() + "\n"
        return "# Текущая схема использует прямой Inbound Xray. Управляемый transport-блок Nginx не требуется.\n"
    except (XPanelError, ValueError, OSError) as exc:
        return f"# Nginx для текущей схемы пока не может быть сформирован:\n# {exc}\n"


def get_expert_scheme_diagnostics(*, run_checks: bool = False) -> dict[str, object]:
    """Small, current-scheme diagnostics for the Expert page.

    External reachability is deliberately not claimed here.  The checks cover
    the generated Xray document, local services, Nginx syntax when applicable,
    and the multi-transport chain when the ready set is active.
    """
    if not run_checks:
        return {"ran": False, "overall_ok": None, "checks": [], "note": "Проверка ещё не запускалась."}

    server = get_server()
    profile = str(server["inbound_profile"] or "raw_reality")
    checks: list[dict[str, object]] = []

    def add(key: str, label: str, ok: bool, detail: str) -> None:
        checks.append({"key": key, "label": label, "ok": bool(ok), "detail": detail})

    try:
        validation = validate_generated_config()
        add(
            "xray_config",
            "Итоговый config.json",
            bool(validation.get("ok")),
            str(validation.get("detail") or ("xray run -test: OK" if validation.get("ok") else "xray run -test: ERROR")),
        )
    except (XPanelError, ValueError, OSError, FileNotFoundError) as exc:
        add("xray_config", "Итоговый config.json", False, str(exc))

    xray_state = _run(["systemctl", "is-active", str(server["xray_service"])]).stdout.strip() or "unknown"
    add("xray_service", "Служба Xray", xray_state == "active", xray_state)

    nginx_needed = (
        profile == RUSSIA_KIT_PROFILE
        or profile in CERTIFICATE_INBOUND_PROFILES
        or (profile in REALITY_INBOUND_PROFILES and bool(_reality_edge_settings(server).get("enabled")))
    )
    if nginx_needed:
        try:
            nginx_doc = nginx_transport_document()
            generated = not nginx_doc.startswith("# Nginx для текущей схемы пока")
            nginx_test = _run(["nginx", "-t"], timeout=30)
            detail = (nginx_test.stderr or nginx_test.stdout).strip() or "nginx -t: OK"
            add("nginx", "Nginx", generated and nginx_test.returncode == 0, detail)
        except (XPanelError, OSError, FileNotFoundError) as exc:
            add("nginx", "Nginx", False, str(exc))
    else:
        add("nginx", "Nginx", True, "Для прямого Inbound транспортный блок Nginx не требуется.")

    if profile == RUSSIA_KIT_PROFILE:
        kit = get_russia_kit_diagnostics()
        for item in kit.get("checks", []):
            add(str(item.get("key") or "kit"), str(item.get("label") or "Транспорт"), bool(item.get("ok")), str(item.get("detail") or ""))

    return {
        "ran": True,
        "overall_ok": bool(checks) and all(bool(item["ok"]) for item in checks),
        "checks": checks,
        "note": "Проверяется локальная конфигурационная цепочка. Доступность из внешней сети подтверждается клиентом.",
    }

def generate_ech_pair(public_name: str) -> dict[str, str]:
    server = get_server()
    name = str(public_name or "").strip()
    if not name or len(name) > 253 or any(ch.isspace() for ch in name):
        raise ValueError("ECH: укажите корректное внешнее Server Name")
    proc = _run([str(server["xray_bin"]), "tls", "ech", "--serverName", name], timeout=20)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        raise XPanelError(output.strip() or "Xray не смог сгенерировать ECH")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    server_key = ""
    config = ""
    for line in lines:
        lower = line.lower()
        value = line.split(":", 1)[1].strip() if ":" in line else line
        if "server" in lower and "key" in lower:
            server_key = value
        elif "config" in lower and "server" not in lower:
            config = value
    # Current Xray prints two opaque base64-like values; retain a robust fallback.
    opaque = [line for line in lines if re.fullmatch(r"[A-Za-z0-9+/=_-]{32,}", line)]
    if not server_key and opaque:
        server_key = opaque[0]
    if not config and len(opaque) > 1:
        config = opaque[1]
    if not server_key or not config:
        raise XPanelError(
            "Xray сгенерировал ECH, но формат вывода не распознан; полный вывод сохранён в журнале"
        )
    return {"public_name": name, "server_keys": server_key, "config_list": config}


def calculate_certificate_pin(cert_path: str | None = None) -> dict[str, str]:
    server = get_server()
    path = Path(str(cert_path or server["tls_cert_path"] or "")).expanduser()
    if not path.is_file():
        raise ValueError(f"TLS certificate не найден: {path}")
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-outform", "DER"],
        capture_output=True, timeout=15, check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise XPanelError(detail or "не удалось прочитать TLS certificate")
    return {
        "sha256": hashlib.sha256(proc.stdout).hexdigest(),
        "source": str(path),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _current_asset_paths() -> tuple[Path, Path]:
    roots: list[Path] = []
    env_root = os.environ.get("XRAY_LOCATION_ASSET", "").strip()
    if env_root:
        roots.append(Path(env_root))
    roots.extend([Path("/usr/local/share/xray"), Path("/usr/share/xray")])
    for root in roots:
        geoip = root / "geoip.dat"
        geosite = root / "geosite.dat"
        if geoip.is_file() or geosite.is_file():
            return geoip, geosite
    return Path("/usr/local/share/xray/geoip.dat"), Path("/usr/local/share/xray/geosite.dat")


def _original_asset_paths() -> tuple[Path, Path]:
    original = GEOFILES_STATE_DIR / "original-xray"
    return original / "geoip.dat", original / "geosite.dat"


def _preserve_original_xray_assets() -> None:
    original_geoip, original_geosite = _original_asset_paths()
    if original_geoip.is_file() and original_geosite.is_file():
        return
    active_geoip, active_geosite = _current_asset_paths()
    if not active_geoip.is_file() or not active_geosite.is_file():
        return
    original_geoip.parent.mkdir(parents=True, exist_ok=True)
    if not original_geoip.is_file():
        shutil.copy2(active_geoip, original_geoip)
    if not original_geosite.is_file():
        shutil.copy2(active_geosite, original_geosite)


def _xray_bundle_paths() -> tuple[Path, Path]:
    original_geoip, original_geosite = _original_asset_paths()
    if original_geoip.is_file() and original_geosite.is_file():
        return original_geoip, original_geosite
    return _current_asset_paths()


def get_geofiles_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM geofiles_settings WHERE id=1").fetchone()
    if row is None:
        raise XPanelError("настройки GeoFiles не инициализированы")
    return row


def supported_geofiles_sources() -> dict[str, dict[str, object]]:
    return {
        key: dict(value)
        for key, value in GEOFILES_SOURCES.items()
        if bool(value.get("selectable", True))
    }


def _geofile_info(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {
            "installed": False,
            "path": str(path),
            "size": 0,
            "sha256": "",
            "updated_at": "",
        }
    stat = path.stat()
    return {
        "installed": True,
        "path": str(path),
        "size": stat.st_size,
        "sha256": _sha256_file(path),
        "updated_at": datetime.fromtimestamp(
            stat.st_mtime, timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _source_values(
    source: str,
    geoip_url: str = "",
    geosite_url: str = "",
    geoip_local_path: str = "",
    geosite_local_path: str = "",
) -> dict[str, str]:
    key = str(source or "sgclient").strip().lower()
    if key not in GEOFILES_SOURCES or not bool(
        GEOFILES_SOURCES[key].get("selectable", True)
    ):
        raise ValueError("неизвестный источник GeoFiles")
    preset = GEOFILES_SOURCES[key]
    result = {
        "source": key,
        "geoip_url": str(geoip_url or preset.get("geoip_url", "")).strip(),
        "geosite_url": str(geosite_url or preset.get("geosite_url", "")).strip(),
        "geoip_local_path": str(geoip_local_path or "").strip(),
        "geosite_local_path": str(geosite_local_path or "").strip(),
    }
    if key in {"loyalsoldier", "runetfreedom", "roscomvpn", "custom"}:
        for label, value in (
            ("GeoIP URL", result["geoip_url"]),
            ("GeoSite URL", result["geosite_url"]),
        ):
            parsed = urlparse(value)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError(f"{label}: разрешён только полный HTTPS URL")
            if parsed.username or parsed.password:
                raise ValueError(f"{label}: URL с логином или паролем не разрешён")
    if key == "local":
        for label, value in (
            ("geoip.dat", result["geoip_local_path"]),
            ("geosite.dat", result["geosite_local_path"]),
        ):
            path = Path(value).expanduser()
            if not path.is_file():
                raise ValueError(f"{label}: локальный файл не найден: {path}")
    return result


def configure_geofiles_source(**values: object) -> sqlite3.Row:
    cleaned = _source_values(
        str(values.get("source", "sgclient")),
        str(values.get("geoip_url", "")),
        str(values.get("geosite_url", "")),
        str(values.get("geoip_local_path", "")),
        str(values.get("geosite_local_path", "")),
    )
    with connect() as con:
        con.execute(
            """
            UPDATE geofiles_settings SET source=?, geoip_url=?, geosite_url=?,
                geoip_local_path=?, geosite_local_path=?, staged_manifest_json='{}',
                last_check_state='', last_check_message='', last_checked_at=NULL,
                updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (
                cleaned["source"],
                cleaned["geoip_url"],
                cleaned["geosite_url"],
                cleaned["geoip_local_path"],
                cleaned["geosite_local_path"],
            ),
        )
    return get_geofiles_settings()


def _copy_or_download_geofile(source: str, value: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source in {"local", "sgclient"}:
        shutil.copy2(Path(value).expanduser(), destination)
        return
    proc = _run(
        [
            "curl",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "120",
            "--output",
            str(destination),
            value,
        ],
        timeout=135,
    )
    if proc.returncode != 0:
        raise XPanelError(
            (proc.stderr or proc.stdout).strip() or f"не удалось скачать {value}"
        )


def _save_uploaded_geofile(stream: object, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".upload")
    total = 0
    limit = 256 * 1024 * 1024
    try:
        with temporary.open("wb") as output:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise XPanelError(
                        f"{destination.name}: размер загрузки превышает 256 МБ"
                    )
                output.write(chunk)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def validate_uploaded_geofiles(
    geoip_stream: object,
    geosite_stream: object,
    *,
    server_preset: str = "none",
    enable_block: bool = False,
    final_outbound_tag: str = "direct",
) -> dict[str, object]:
    # Upload and candidate preparation share the same lock, otherwise two web
    # workers could overwrite uploads/current before hashes are frozen.
    with _geofiles_operation_lock("загрузку и проверку"):
        upload_dir = GEOFILES_STATE_DIR / "uploads" / "current"
        geoip = upload_dir / "geoip.dat"
        geosite = upload_dir / "geosite.dat"
        _save_uploaded_geofile(geoip_stream, geoip)
        try:
            _save_uploaded_geofile(geosite_stream, geosite)
        except Exception:
            geoip.unlink(missing_ok=True)
            raise
        return _validate_geofiles_source_unlocked(
            source="local",
            geoip_local_path=str(geoip),
            geosite_local_path=str(geosite),
            server_preset=server_preset,
            enable_block=enable_block,
            final_outbound_tag=final_outbound_tag,
        )


def _record_geofiles_check_failure(message: str) -> None:
    with connect() as con:
        con.execute(
            """
            UPDATE geofiles_settings SET last_check_state='error',
                last_check_message=?, last_checked_at=CURRENT_TIMESTAMP,
                staged_manifest_json='{}', updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (str(message)[:1000],),
        )


def _read_protobuf_varint(
    data: memoryview, offset: int, limit: int
) -> tuple[int | None, int]:
    value = 0
    shift = 0
    while offset < limit and shift <= 63:
        current = int(data[offset])
        offset += 1
        value |= (current & 0x7F) << shift
        if current & 0x80 == 0:
            return value, offset
        shift += 7
    return None, offset


def _skip_protobuf_field(
    data: memoryview, offset: int, limit: int, wire: int
) -> int | None:
    if wire == 0:
        value, offset = _read_protobuf_varint(data, offset, limit)
        return offset if value is not None else None
    if wire == 1:
        offset += 8
    elif wire == 2:
        length, offset = _read_protobuf_varint(data, offset, limit)
        if length is None:
            return None
        offset += int(length)
    elif wire == 5:
        offset += 4
    else:
        return None
    return offset if offset <= limit else None


def _read_protobuf_string_field(
    data: memoryview, start: int, length: int, requested_field: int = 1
) -> str:
    end = start + length
    offset = start
    while offset < end:
        key, offset = _read_protobuf_varint(data, offset, end)
        if key is None:
            break
        field = int(key >> 3)
        wire = int(key & 7)
        if field == requested_field and wire == 2:
            value_length, value_start = _read_protobuf_varint(data, offset, end)
            if value_length is None or value_start + int(value_length) > end:
                break
            return bytes(
                data[value_start : value_start + int(value_length)]
            ).decode("utf-8", "replace")
        next_offset = _skip_protobuf_field(data, offset, end, wire)
        if next_offset is None:
            break
        offset = next_offset
    return ""


def _read_geofile_categories(path: Path) -> list[str]:
    stat = path.stat()
    cache_key = (str(path.resolve()), stat.st_size, stat.st_mtime_ns)
    cached = _GEOFILE_CATEGORY_CACHE.get(cache_key)
    if cached is not None:
        return list(cached)
    data = memoryview(path.read_bytes())
    result: set[str] = set()
    offset = 0
    limit = len(data)
    while offset < limit:
        key, offset = _read_protobuf_varint(data, offset, limit)
        if key is None:
            break
        field = int(key >> 3)
        wire = int(key & 7)
        if field == 1 and wire == 2:
            length, start = _read_protobuf_varint(data, offset, limit)
            if length is None or start + int(length) > limit:
                break
            code = _read_protobuf_string_field(
                data, start, int(length), 1
            ).strip().lower()
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", code):
                result.add(code)
            offset = start + int(length)
            continue
        next_offset = _skip_protobuf_field(data, offset, limit, wire)
        if next_offset is None:
            break
        offset = next_offset
    categories = sorted(result)
    if len(_GEOFILE_CATEGORY_CACHE) >= 8:
        _GEOFILE_CATEGORY_CACHE.clear()
    _GEOFILE_CATEGORY_CACHE[cache_key] = tuple(categories)
    return categories


def _select_geofile_validation_category(
    categories: list[str], *preferred: str
) -> str:
    available = {value.lower(): value for value in categories}
    for item in preferred:
        if item.lower() in available:
            return available[item.lower()]
    return categories[0] if categories else ""


def _detect_geofiles_family(
    geoip_categories: list[str], geosite_categories: list[str]
) -> str:
    geoip = set(geoip_categories)
    geosite = set(geosite_categories)
    if {"direct", "private", "whitelist"} <= geoip and {
        "category-ru", "category-ads", "private", "whitelist"
    } <= geosite:
        return "RoscomVPN"
    if "private" in geoip and ({"ru", "cn"} & geoip) and "category-ads-all" in geosite:
        return "Стандартный"
    return "Пользовательский"


def _analyze_geofile_pair(geoip: Path, geosite: Path) -> dict[str, object]:
    for label, path in (("geoip.dat", geoip), ("geosite.dat", geosite)):
        if not path.is_file() or path.stat().st_size < GEOFILES_MINIMUM_SIZE:
            size = path.stat().st_size if path.is_file() else 0
            raise XPanelError(
                f"{label}: файл слишком мал ({size} байт) и не похож на рабочий GeoFile"
            )
    geoip_categories = _read_geofile_categories(geoip)
    geosite_categories = _read_geofile_categories(geosite)
    if not geoip_categories:
        raise XPanelError("в geoip.dat не найдено ни одной категории")
    if not geosite_categories:
        raise XPanelError("в geosite.dat не найдено ни одной категории")
    return {
        "family": _detect_geofiles_family(geoip_categories, geosite_categories),
        "geoip_categories": geoip_categories,
        "geosite_categories": geosite_categories,
    }


def _run_geofiles_structural_test(
    geoip: Path, geosite: Path, analysis: dict[str, object]
) -> None:
    if geoip.parent.resolve() != geosite.parent.resolve():
        raise XPanelError("geoip.dat и geosite.dat должны находиться в одной временной папке")
    server = get_server()
    binary = str(server["xray_bin"])
    if not Path(binary).is_file() and shutil.which(binary) is None:
        raise FileNotFoundError(f"не найден Xray: {binary}")
    geoip_categories = list(analysis["geoip_categories"])
    geosite_categories = list(analysis["geosite_categories"])
    site_category = _select_geofile_validation_category(
        geosite_categories,
        "category-ads-all", "category-ads", "private", "whitelist", "category-ru",
    )
    ip_category = _select_geofile_validation_category(
        geoip_categories, "private", "ru", "direct", "whitelist"
    )
    rules: list[dict[str, object]] = []
    if site_category:
        rules.append({
            "type": "field",
            "domain": [f"geosite:{site_category}"],
            "outboundTag": "direct",
        })
    if ip_category:
        rules.append({
            "type": "field",
            "ip": [f"geoip:{ip_category}"],
            "outboundTag": "direct",
        })
    document = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 10888,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    config_path = geoip.parent / "sg-geofiles-test.json"
    config_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(geoip.parent)
    try:
        proc = subprocess.run(
            [binary, "run", "-test", "-config", str(config_path)],
            text=True,
            capture_output=True,
            timeout=30,
            env=env,
            check=False,
        )
    finally:
        config_path.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise XPanelError(
            (proc.stderr or proc.stdout).strip() or "Xray не принял выбранные GeoFiles"
        )


def _canonical_geo_reference(value: object) -> str:
    text = str(value or "").strip().lower()
    while text.startswith("!"):
        text = text[1:].strip()
    for prefix in ("geosite:", "geoip:"):
        if text.startswith(prefix):
            category = text[len(prefix):].split("@", 1)[0].strip()
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", category):
                return prefix + category
    return ""


def _collect_geo_references(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            result.update(_collect_geo_references(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_collect_geo_references(child))
    elif isinstance(value, str):
        reference = _canonical_geo_reference(value)
        if reference:
            result.add(reference)
    return result


def _routing_geo_reference_details() -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    with connect() as con:
        rows = con.execute(
            "SELECT name, domains, ips FROM routing_rules WHERE enabled=1 ORDER BY priority, id"
        ).fetchall()
    for row in rows:
        for value in split_values(str(row["domains"] or "")) + split_values(
            str(row["ips"] or "")
        ):
            reference = _canonical_geo_reference(value)
            if reference:
                result.setdefault(reference, set()).add(str(row["name"]))
    return result


def _geofiles_compatibility(
    geoip_categories: list[str],
    geosite_categories: list[str],
    *,
    config_document: dict[str, object] | None = None,
) -> dict[str, object]:
    available = {f"geoip:{value}" for value in geoip_categories}
    available.update(f"geosite:{value}" for value in geosite_categories)
    routing_details = _routing_geo_reference_details()
    if config_document is None:
        config_text, _, _ = render_text()
        try:
            config_document = json.loads(config_text)
        except json.JSONDecodeError as exc:
            raise XPanelError(f"будущий config.json не удалось разобрать: {exc}") from exc
    all_references = _collect_geo_references(config_document)
    missing = sorted(all_references - available)
    missing_routing = [value for value in missing if value in routing_details]
    missing_nonrouting = [value for value in missing if value not in routing_details]
    details = [
        {
            "category": value,
            "rules": sorted(routing_details.get(value, set())),
        }
        for value in missing_routing
    ]
    return {
        "compatible": not missing,
        "required_categories": sorted(all_references),
        "missing_categories": missing,
        "missing_routing_categories": missing_routing,
        "missing_routing_details": details,
        "missing_nonrouting_categories": missing_nonrouting,
    }


def _routing_state_snapshot() -> dict[str, object]:
    with connect() as con:
        rules = [
            dict(row)
            for row in con.execute(
                "SELECT * FROM routing_rules ORDER BY id"
            ).fetchall()
        ]
        routing_row = con.execute("SELECT * FROM routing_settings WHERE id=1").fetchone()
        warp_row = con.execute("SELECT * FROM warp_settings WHERE id=1").fetchone()
    return {
        "routing_rules": rules,
        "routing_settings": dict(routing_row) if routing_row else None,
        "warp_settings": dict(warp_row) if warp_row else None,
    }


def _restore_singleton_row(con: sqlite3.Connection, table: str, row: object) -> None:
    if not isinstance(row, dict):
        return
    columns = [key for key in row if key != "id"]
    if not columns:
        return
    con.execute(
        f"UPDATE {table} SET " + ",".join(f"{key}=?" for key in columns) + " WHERE id=1",
        tuple(row[key] for key in columns),
    )


def _restore_routing_state(snapshot: dict[str, object]) -> None:
    columns = (
        "id", "name", "priority", "enabled", "outbound_tag", "domains", "ips",
        "ports", "network", "protocols", "inbound_tags", "users", "target_type",
        "config_json", "managed_by", "managed_role", "created_at", "updated_at",
    )
    with connect() as con:
        con.execute("DELETE FROM routing_rules")
        for item in snapshot.get("routing_rules", []):
            row = dict(item)
            placeholders = ",".join("?" for _ in columns)
            con.execute(
                f"INSERT INTO routing_rules ({','.join(columns)}) VALUES ({placeholders})",
                tuple(
                    row.get(column, "") if column in {"managed_by", "managed_role"}
                    else row.get(column)
                    for column in columns
                ),
            )
        _restore_singleton_row(con, "routing_settings", snapshot.get("routing_settings"))
        _restore_singleton_row(con, "warp_settings", snapshot.get("warp_settings"))


def _clone_current_database(destination: Path) -> None:
    init_db()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    source = sqlite3.connect(db_path())
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def _legacy_roscom_rule_is_adoptable(row: sqlite3.Row, role: str) -> bool:
    expected_tag = "direct" if role == "direct" else "blocked"
    if str(row["outbound_tag"]) != expected_tag or str(row["target_type"] or "outbound") != "outbound":
        return False
    if any(str(row[key] or "").strip() for key in ("ports", "network", "protocols", "inbound_tags", "users")):
        return False
    domains = set(split_values(str(row["domains"] or "")))
    ips = set(split_values(str(row["ips"] or "")))
    allowed_domains = {
        f"geosite:{item}"
        for item in (ROSCOMVPN_DIRECT_GEOSITE if role == "direct" else ROSCOMVPN_BLOCK_GEOSITE)
    }
    allowed_ips = {
        f"geoip:{item}" for item in (ROSCOMVPN_DIRECT_GEOIP if role == "direct" else ())
    }
    return bool(domains or ips) and domains <= allowed_domains and ips <= allowed_ips


def _upsert_managed_routing_rule(
    *, name: str, priority: int, outbound_tag: str, domains: list[str], ips: list[str],
    enabled: bool, managed_by: str, managed_role: str,
) -> None:
    with connect() as con:
        existing = con.execute(
            "SELECT * FROM routing_rules WHERE name=?", (name,)
        ).fetchone()
    if existing is not None:
        owner = str(existing["managed_by"] or "")
        if owner != managed_by:
            legacy_ok = (
                not owner
                and managed_by == "roscomvpn-server-preset"
                and _legacy_roscom_rule_is_adoptable(existing, managed_role)
            )
            if not legacy_ok:
                raise XPanelError(
                    f"Невозможно применить preset: правило «{name}» уже существует "
                    "и не принадлежит серверному preset. Переименуйте пользовательское правило."
                )
    values = {
        "name": name,
        "priority": priority,
        "outbound_tag": outbound_tag,
        "target_type": "outbound",
        "domains": "\n".join(domains),
        "ips": "\n".join(ips),
        "ports": "",
        "network": "",
        "protocols": "",
        "inbound_tags": "",
        "users": "",
    }
    if existing is None:
        row = add_routing_rule(**values)
        rule_id = int(row["id"])
    else:
        row = update_routing_rule(int(existing["id"]), **values)
        rule_id = int(row["id"])
    set_routing_rule_enabled(rule_id, enabled)
    with connect() as con:
        con.execute(
            "UPDATE routing_rules SET managed_by=?, managed_role=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (managed_by, managed_role, rule_id),
        )


def _validated_default_outbound_tag(value: object) -> str:
    """Return an enabled concrete outbound tag suitable for the final route."""
    tag = str(value or "direct").strip() or "direct"
    if tag in {"blocked", "block"}:
        raise XPanelError("Block нельзя назначить финальным маршрутом")
    available = set(list_outbound_tags(enabled_only=True))
    if tag not in available:
        raise XPanelError(
            f"финальный outbound «{tag}» отсутствует или выключен; "
            "создайте/включите его в Outbounds и повторите проверку"
        )
    return tag


def _apply_roscomvpn_server_preset(
    geoip_categories: list[str],
    geosite_categories: list[str],
    *,
    enable_block: bool,
    final_outbound_tag: str = "direct",
) -> dict[str, object]:
    final_outbound_tag = _validated_default_outbound_tag(final_outbound_tag)
    geoip = set(geoip_categories)
    geosite = set(geosite_categories)
    direct_domains = [f"geosite:{item}" for item in ROSCOMVPN_DIRECT_GEOSITE if item in geosite]
    direct_ips = [f"geoip:{item}" for item in ROSCOMVPN_DIRECT_GEOIP if item in geoip]
    block_domains = [f"geosite:{item}" for item in ROSCOMVPN_BLOCK_GEOSITE if item in geosite]
    if not direct_domains and not direct_ips:
        raise XPanelError("выбранная пара не содержит категорий для серверного RoscomVPN preset")
    _upsert_managed_routing_rule(
        name=ROSCOMVPN_DIRECT_RULE,
        priority=100,
        outbound_tag="direct",
        domains=direct_domains,
        ips=direct_ips,
        enabled=True,
        managed_by="roscomvpn-server-preset",
        managed_role="direct",
    )
    if block_domains:
        _upsert_managed_routing_rule(
            name=ROSCOMVPN_BLOCK_RULE,
            priority=90,
            outbound_tag="blocked",
            domains=block_domains,
            ips=[],
            enabled=bool(enable_block),
            managed_by="roscomvpn-server-preset",
            managed_role="block",
        )
    else:
        with connect() as con:
            existing_block = con.execute(
                "SELECT * FROM routing_rules WHERE name=?", (ROSCOMVPN_BLOCK_RULE,)
            ).fetchone()
            if existing_block is not None:
                owner = str(existing_block["managed_by"] or "")
                if owner == "roscomvpn-server-preset" or (
                    not owner and _legacy_roscom_rule_is_adoptable(existing_block, "block")
                ):
                    con.execute(
                        "DELETE FROM routing_rules WHERE id=?", (int(existing_block["id"]),)
                    )
    with connect() as con:
        con.execute(
            "UPDATE routing_settings SET default_outbound_tag=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (final_outbound_tag,),
        )
    return {
        "name": "roscomvpn",
        "direct_domains": direct_domains,
        "direct_ips": direct_ips,
        "block_domains": block_domains,
        "block_enabled": bool(enable_block and block_domains),
        "final_outbound": final_outbound_tag,
    }



def get_roscomvpn_server_preset_overview() -> dict[str, object]:
    overview = get_geofiles_overview()
    analysis = dict(overview.get("active_analysis") or {})
    geoip = set(analysis.get("geoip_categories") or [])
    geosite = set(analysis.get("geosite_categories") or [])
    direct_domains = [item for item in ROSCOMVPN_DIRECT_GEOSITE if item in geosite]
    direct_ips = [item for item in ROSCOMVPN_DIRECT_GEOIP if item in geoip]
    block_domains = [item for item in ROSCOMVPN_BLOCK_GEOSITE if item in geosite]
    missing_direct_domains = [item for item in ROSCOMVPN_DIRECT_GEOSITE if item not in geosite]
    missing_direct_ips = [item for item in ROSCOMVPN_DIRECT_GEOIP if item not in geoip]
    missing_block_domains = [item for item in ROSCOMVPN_BLOCK_GEOSITE if item not in geosite]
    with connect() as con:
        direct_rule = con.execute(
            "SELECT enabled FROM routing_rules WHERE name=? AND managed_by='roscomvpn-server-preset'", (ROSCOMVPN_DIRECT_RULE,)
        ).fetchone()
        block_rule = con.execute(
            "SELECT enabled FROM routing_rules WHERE name=? AND managed_by='roscomvpn-server-preset'", (ROSCOMVPN_BLOCK_RULE,)
        ).fetchone()
    return {
        "available": bool(direct_domains or direct_ips),
        "source": str(overview.get("active_label") or ""),
        "family": str(analysis.get("family") or ""),
        "error": str(analysis.get("error") or ""),
        "direct_domains": direct_domains,
        "direct_ips": direct_ips,
        "block_domains": block_domains,
        "missing_direct_domains": missing_direct_domains,
        "missing_direct_ips": missing_direct_ips,
        "missing_block_domains": missing_block_domains,
        "direct_enabled": bool(direct_rule and direct_rule["enabled"]),
        "block_enabled": bool(block_rule and block_rule["enabled"]),
        "final_outbound": str(get_routing_settings()["default_outbound_tag"] or "direct"),
    }


def apply_active_roscomvpn_server_preset(
    *, enable_block: bool = False, final_outbound_tag: str = "direct"
) -> dict[str, object]:
    overview = get_geofiles_overview()
    analysis = dict(overview.get("active_analysis") or {})
    error = str(analysis.get("error") or "").strip()
    if error:
        raise XPanelError("активные GeoFiles не удалось прочитать: " + error)
    return _apply_roscomvpn_server_preset(
        list(analysis.get("geoip_categories") or []),
        list(analysis.get("geosite_categories") or []),
        enable_block=bool(enable_block),
        final_outbound_tag=final_outbound_tag,
    )


def _run_xray_test_with_assets(
    xray_bin: str, config_path: Path, asset_dir: Path
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(asset_dir)
    try:
        return subprocess.run(
            [xray_bin, "run", "-test", "-config", str(config_path)],
            text=True,
            capture_output=True,
            timeout=30,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise XPanelError("полный candidate Xray превысил тайм-аут 30 секунд") from exc


def _prepare_geofiles_candidate(
    stage: Path,
    analysis: dict[str, object],
    *,
    server_preset: str = "none",
    enable_block: bool = False,
    final_outbound_tag: str = "direct",
) -> dict[str, object]:
    candidate_db = stage / "candidate.db"
    preset_result: dict[str, object] = {"name": "none"}
    if server_preset not in {"none", "roscomvpn"}:
        raise ValueError("неизвестный серверный GeoFiles preset")

    def build() -> dict[str, object]:
        nonlocal preset_result
        if server_preset == "roscomvpn":
            preset_result = _apply_roscomvpn_server_preset(
                list(analysis["geoip_categories"]),
                list(analysis["geosite_categories"]),
                enable_block=enable_block,
                final_outbound_tag=final_outbound_tag,
            )
        config_text, server, users = render_text()
        try:
            document = json.loads(config_text)
        except json.JSONDecodeError as exc:
            raise XPanelError(f"полный будущий config.json не удалось разобрать: {exc}") from exc
        compatibility = _geofiles_compatibility(
            list(analysis["geoip_categories"]),
            list(analysis["geosite_categories"]),
            config_document=document,
        )
        if not compatibility["compatible"]:
            missing = ", ".join(compatibility["missing_categories"])
            raise XPanelError(
                "невозможно применить выбранные GeoFiles. В полной будущей конфигурации "
                f"отсутствуют категории: {missing}. Исправьте правила либо примените совместимый серверный preset"
            )
        candidate_path = stage / "candidate-config.json"
        candidate_path.write_text(config_text, encoding="utf-8")
        result = _run_xray_test_with_assets(str(server["xray_bin"]), candidate_path, stage)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise XPanelError(
                "полный будущий config.json не прошёл xray run -test со staging GeoFiles: "
                + (detail or "Xray отклонил candidate")
            )
        return {
            "config_text": config_text,
            "config_sha256": hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
            "config_path": str(candidate_path),
            "users": len(users),
            "compatibility": compatibility,
            "preset": preset_result,
            "xray_test": "ok",
        }

    if server_preset == "roscomvpn":
        _clone_current_database(candidate_db)
        try:
            with use_db_path(candidate_db):
                return build()
        finally:
            candidate_db.unlink(missing_ok=True)
    return build()


def _snapshot_geofiles_settings() -> dict[str, object]:
    return dict(get_geofiles_settings())


def _restore_geofiles_settings(snapshot: dict[str, object]) -> None:
    with connect() as con:
        _restore_singleton_row(con, "geofiles_settings", snapshot)


def _systemctl_checked(action: str, service: str, *, timeout: int = 40) -> None:
    result = _run(["systemctl", action, service], timeout=timeout)
    if result.returncode != 0:
        raise XPanelError((result.stderr or result.stdout).strip() or f"systemctl {action} {service}: ошибка")


def _confirm_xray_active(service: str) -> None:
    state = _run(["systemctl", "is-active", service], timeout=10)
    value = (state.stdout or state.stderr).strip()
    if state.returncode != 0 or value != "active":
        raise XPanelError(f"служба {service} после операции имеет состояние: {value or 'unknown'}")


def _write_json_atomic(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def validate_geofiles_source(**values: object) -> dict[str, object]:
    with _geofiles_operation_lock("проверку"):
        return _validate_geofiles_source_unlocked(**values)


def _validate_geofiles_source_unlocked(**values: object) -> dict[str, object]:
    # A check is a pure candidate operation.  Do not change the persisted source,
    # URLs or local paths until the exact checked plan is committed successfully.
    cleaned = _source_values(
        str(values.get("source", "sgclient")),
        str(values.get("geoip_url", "")),
        str(values.get("geosite_url", "")),
        str(values.get("geoip_local_path", "")),
        str(values.get("geosite_local_path", "")),
    )
    source = str(cleaned["source"])
    requested_preset = str(values.get("server_preset", "none") or "none").strip().lower()
    server_preset = "roscomvpn" if source == "roscomvpn" else requested_preset
    enable_block = bool(values.get("enable_block", False))
    final_outbound_tag = str(
        values.get("final_outbound_tag")
        or get_routing_settings()["default_outbound_tag"]
        or "direct"
    ).strip()
    if server_preset not in {"none", "roscomvpn"}:
        raise ValueError("неизвестный серверный GeoFiles preset")
    if server_preset == "roscomvpn" and source != "roscomvpn":
        raise ValueError("отдельная совместимость RoscomVPN доступна только для источника RoscomVPN")
    if server_preset == "roscomvpn":
        final_outbound_tag = _validated_default_outbound_tag(final_outbound_tag)
    else:
        final_outbound_tag = str(get_routing_settings()["default_outbound_tag"] or "direct")
    stage = GEOFILES_STATE_DIR / "staging"
    try:
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True, exist_ok=True)
        geoip_stage = stage / "geoip.dat"
        geosite_stage = stage / "geosite.dat"
        if source == "sgclient":
            bundled_geoip = GEOFILES_BUNDLED_DIR / "geoip.dat"
            bundled_geosite = GEOFILES_BUNDLED_DIR / "geosite.dat"
            if not bundled_geoip.is_file() or not bundled_geosite.is_file():
                raise XPanelError(
                    "в установке SG-Panel отсутствует штатный комплект SG Client"
                )
            for bundled in (bundled_geoip, bundled_geosite):
                expected = GEOFILES_BUNDLED_SHA256[bundled.name]
                actual = _sha256_file(bundled)
                if actual != expected:
                    raise XPanelError(
                        f"штатный {bundled.name} повреждён: SHA-256 не совпадает "
                        "с манифестом SG-Panel"
                    )
            _copy_or_download_geofile(source, str(bundled_geoip), geoip_stage)
            _copy_or_download_geofile(source, str(bundled_geosite), geosite_stage)
        elif source == "local":
            _copy_or_download_geofile(
                source, str(cleaned["geoip_local_path"]), geoip_stage
            )
            _copy_or_download_geofile(
                source, str(cleaned["geosite_local_path"]), geosite_stage
            )
        else:
            _copy_or_download_geofile(
                source, str(cleaned["geoip_url"]), geoip_stage
            )
            _copy_or_download_geofile(
                source, str(cleaned["geosite_url"]), geosite_stage
            )

        analysis = _analyze_geofile_pair(geoip_stage, geosite_stage)
        _run_geofiles_structural_test(geoip_stage, geosite_stage, analysis)
        candidate: dict[str, object] = {}
        if server_preset == "roscomvpn":
            candidate = _prepare_geofiles_candidate(
                stage,
                analysis,
                server_preset="roscomvpn",
                enable_block=enable_block,
                final_outbound_tag=final_outbound_tag,
            )
            compatibility = dict(candidate["compatibility"])
            state = "ok"
            message = (
                "RoscomVPN и полный будущий Xray config проверены в staging; "
                f"остальной трафик → {final_outbound_tag}"
            )
        else:
            config_text, _, _ = render_text()
            try:
                document = json.loads(config_text)
            except json.JSONDecodeError as exc:
                raise XPanelError(f"полный будущий config.json не удалось разобрать: {exc}") from exc
            compatibility = _geofiles_compatibility(
                list(analysis["geoip_categories"]),
                list(analysis["geosite_categories"]),
                config_document=document,
            )
            missing = list(compatibility["missing_categories"])
            if missing:
                state = "blocked"
                message = (
                    "GeoFiles исправны, но применение заблокировано. Отсутствуют категории: "
                    + ", ".join(missing)
                    + ". Исправьте правила либо включите отдельную совместимость RoscomVPN"
                )
            else:
                candidate = _prepare_geofiles_candidate(stage, analysis)
                state = "ok"
                message = "GeoFiles и полный будущий Xray config успешно проверены в staging"
        manifest = {
            "source": source,
            "source_label": str(GEOFILES_SOURCES[source]["label"]),
            "geoip_url": str(cleaned["geoip_url"]),
            "geosite_url": str(cleaned["geosite_url"]),
            "geoip_local_path": str(cleaned["geoip_local_path"]),
            "geosite_local_path": str(cleaned["geosite_local_path"]),
            "geoip": _geofile_info(geoip_stage),
            "geosite": _geofile_info(geosite_stage),
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **analysis,
            **compatibility,
            "candidate_config_sha256": candidate.get("config_sha256", ""),
            "candidate_xray_test": candidate.get("xray_test", "blocked"),
            "server_preset": server_preset,
            "block_enabled": bool(enable_block),
            "final_outbound_tag": final_outbound_tag,
            "preset_result": candidate.get("preset", {}),
        }
        with connect() as con:
            con.execute(
                """
                UPDATE geofiles_settings SET staged_manifest_json=?,
                    last_check_state=?, last_check_message=?,
                    last_checked_at=CURRENT_TIMESTAMP,
                    updated_at=CURRENT_TIMESTAMP WHERE id=1
                """,
                (json.dumps(manifest, ensure_ascii=False), state, message),
            )
        return manifest
    except Exception as exc:
        _record_geofiles_check_failure(str(exc))
        if stage.exists() and not (stage / "geoip.dat").is_file():
            shutil.rmtree(stage, ignore_errors=True)
        raise


def apply_geofiles_source(
    *,
    server_preset: str | None = None,
    enable_block: bool | None = None,
    final_outbound_tag: str | None = None,
) -> dict[str, object]:
    with _geofiles_operation_lock("применение"):
        return _apply_geofiles_source_unlocked(
            server_preset=server_preset,
            enable_block=enable_block,
            final_outbound_tag=final_outbound_tag,
        )


def _apply_geofiles_source_unlocked(
    *,
    server_preset: str | None = None,
    enable_block: bool | None = None,
    final_outbound_tag: str | None = None,
) -> dict[str, object]:
    require_root()
    settings = get_geofiles_settings()
    if settings["last_check_state"] != "ok":
        raise XPanelError("применять можно только успешно проверенный candidate GeoFiles")
    try:
        manifest = json.loads(settings["staged_manifest_json"] or "{}")
    except json.JSONDecodeError as exc:
        raise XPanelError("повреждён staged manifest GeoFiles") from exc
    stage = GEOFILES_STATE_DIR / "staging"
    staged_geoip = stage / "geoip.dat"
    staged_geosite = stage / "geosite.dat"
    if not staged_geoip.is_file() or not staged_geosite.is_file():
        raise XPanelError(
            "проверенные временные GeoFiles отсутствуют; выполните проверку снова"
        )
    if (
        _sha256_file(staged_geoip) != manifest.get("geoip", {}).get("sha256")
        or _sha256_file(staged_geosite) != manifest.get("geosite", {}).get("sha256")
    ):
        raise XPanelError("GeoFiles изменились после проверки; применение заблокировано")
    checked_preset = str(manifest.get("server_preset") or "none")
    checked_block = bool(manifest.get("block_enabled", False))
    checked_final_outbound = str(manifest.get("final_outbound_tag") or "direct")
    if server_preset is not None and str(server_preset) != checked_preset:
        raise XPanelError("режим совместимости изменён после проверки; проверьте GeoFiles снова")
    if enable_block is not None and bool(enable_block) != checked_block:
        raise XPanelError("настройка Block изменена после проверки; проверьте GeoFiles снова")
    if final_outbound_tag is not None and str(final_outbound_tag) != checked_final_outbound:
        raise XPanelError("финальный outbound изменён после проверки; проверьте GeoFiles снова")
    server_preset = checked_preset
    enable_block = checked_block
    final_outbound_tag = checked_final_outbound
    manifest_source = str(manifest.get("source") or "").strip().lower()
    if manifest_source not in GEOFILES_SOURCES:
        raise XPanelError("в staged manifest отсутствует корректный источник GeoFiles")
    if server_preset == "roscomvpn" and manifest_source != "roscomvpn":
        raise XPanelError("серверный RoscomVPN preset доступен только для источника RoscomVPN")

    analysis = {
        "family": manifest.get("family", "Пользовательский"),
        "geoip_categories": list(manifest.get("geoip_categories", [])),
        "geosite_categories": list(manifest.get("geosite_categories", [])),
    }
    # Critical pre-commit barrier: rebuild the complete future Routing/config from
    # the current database and test it against staging immediately before touching live state.
    candidate = _prepare_geofiles_candidate(
        stage,
        analysis,
        server_preset=server_preset,
        enable_block=enable_block,
        final_outbound_tag=final_outbound_tag,
    )
    candidate_text = str(candidate["config_text"])
    candidate_sha256 = str(candidate["config_sha256"])
    checked_candidate_sha256 = str(manifest.get("candidate_config_sha256") or "")
    if not checked_candidate_sha256 or candidate_sha256 != checked_candidate_sha256:
        raise XPanelError(
            "Routing, Outbounds или Xray-настройки изменились после проверки GeoFiles; "
            "live-состояние не изменено, выполните полный candidate-test снова"
        )

    active_geoip, active_geosite = _current_asset_paths()
    if active_geoip.parent.resolve() != active_geosite.parent.resolve():
        raise XPanelError("активные geoip.dat и geosite.dat должны находиться в одном каталоге")
    active_geoip.parent.mkdir(parents=True, exist_ok=True)
    _preserve_original_xray_assets()
    server = get_server()
    config_path = Path(str(server["config_path"]))
    service = str(server["xray_service"])
    config_path.parent.mkdir(parents=True, exist_ok=True)

    generation = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + "-" + candidate_sha256[:12]
    generation_dir = GEOFILES_STATE_DIR / "sets" / generation
    generation_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(staged_geoip, generation_dir / "geoip.dat")
    shutil.copy2(staged_geosite, generation_dir / "geosite.dat")
    (generation_dir / "config.json").write_text(candidate_text, encoding="utf-8")
    generation_manifest = {
        **manifest,
        "generation": generation,
        "server_preset": server_preset,
        "block_enabled": bool(enable_block),
        "final_outbound_tag": final_outbound_tag,
        "preset_result": candidate.get("preset", {}),
        "candidate_config_sha256": candidate_sha256,
        "candidate_xray_test": "ok",
        "prepared_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _write_json_atomic(generation_dir / "manifest.json", generation_manifest)

    backup = GEOFILES_STATE_DIR / "backups" / generation
    backup.mkdir(parents=True, exist_ok=False)
    asset_existed = {
        "geoip.dat": active_geoip.is_file(),
        "geosite.dat": active_geosite.is_file(),
    }
    for current in (active_geoip, active_geosite):
        if current.is_file():
            shutil.copy2(current, backup / current.name)
    config_existed = config_path.is_file()
    if config_existed:
        shutil.copy2(config_path, backup / "config.json")
    routing_snapshot = _routing_state_snapshot()
    geofiles_snapshot = _snapshot_geofiles_settings()
    _write_json_atomic(backup / "routing-before.json", routing_snapshot)
    _write_json_atomic(backup / "geofiles-settings-before.json", geofiles_snapshot)
    pre_state = (_run(["systemctl", "is-active", service], timeout=10).stdout or "unknown").strip()
    transaction = {
        "state": "prepared",
        "generation": generation,
        "backup": str(backup),
        "active_geoip": str(active_geoip),
        "active_geosite": str(active_geosite),
        "config_path": str(config_path),
        "asset_existed": asset_existed,
        "config_existed": config_existed,
        "xray_state_before": pre_state,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _write_json_atomic(GEOFILES_STATE_DIR / "transaction.json", transaction)

    live_tmp_geoip = active_geoip.with_name(active_geoip.name + ".sg-transaction")
    live_tmp_geosite = active_geosite.with_name(active_geosite.name + ".sg-transaction")
    config_tmp = config_path.with_name(config_path.name + ".sg-transaction")
    original_error: Exception | None = None
    try:
        transaction["state"] = "committing"
        _write_json_atomic(GEOFILES_STATE_DIR / "transaction.json", transaction)
        _systemctl_checked("stop", service)
        shutil.copy2(generation_dir / "geoip.dat", live_tmp_geoip)
        shutil.copy2(generation_dir / "geosite.dat", live_tmp_geosite)
        shutil.copy2(generation_dir / "config.json", config_tmp)
        os.chmod(config_tmp, 0o644)
        os.replace(live_tmp_geoip, active_geoip)
        os.replace(live_tmp_geosite, active_geosite)
        os.replace(config_tmp, config_path)

        if server_preset == "roscomvpn":
            _apply_roscomvpn_server_preset(
                list(analysis["geoip_categories"]),
                list(analysis["geosite_categories"]),
                enable_block=enable_block,
                final_outbound_tag=final_outbound_tag,
            )
        committed_text, _, _ = render_text()
        if hashlib.sha256(committed_text.encode("utf-8")).hexdigest() != candidate_sha256:
            raise XPanelError("Routing или Xray-настройки изменились между candidate-test и commit")
        geoip_info = _geofile_info(active_geoip)
        geosite_info = _geofile_info(active_geosite)
        applied_manifest = {
            **generation_manifest,
            "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        with connect() as con:
            con.execute(
                """
                UPDATE geofiles_settings SET source=?, geoip_url=?, geosite_url=?,
                    geoip_local_path=?, geosite_local_path=?, active_geoip_path=?,
                    active_geosite_path=?, active_geoip_sha256=?,
                    active_geosite_sha256=?, active_geoip_size=?,
                    active_geosite_size=?, active_source=?, staged_manifest_json=?,
                    active_generation=?, active_manifest_json=?,
                    last_applied_at=CURRENT_TIMESTAMP, last_check_state='ok',
                    last_check_message='GeoFiles и полный Xray config транзакционно применены',
                    updated_at=CURRENT_TIMESTAMP WHERE id=1
                """,
                (
                    manifest_source,
                    str(manifest.get("geoip_url") or ""),
                    str(manifest.get("geosite_url") or ""),
                    str(manifest.get("geoip_local_path") or ""),
                    str(manifest.get("geosite_local_path") or ""),
                    str(active_geoip), str(active_geosite),
                    geoip_info["sha256"], geosite_info["sha256"],
                    geoip_info["size"], geosite_info["size"],
                    manifest_source, json.dumps(applied_manifest, ensure_ascii=False),
                    generation, json.dumps(applied_manifest, ensure_ascii=False),
                ),
            )
        final_test = _run_xray_test_with_assets(str(server["xray_bin"]), config_path, active_geoip.parent)
        if final_test.returncode != 0:
            raise XPanelError(
                "применённый config.json не прошёл финальный xray run -test: "
                + ((final_test.stderr or final_test.stdout).strip() or "неизвестная ошибка")
            )
        _systemctl_checked("restart", service)
        _confirm_xray_active(service)
        transaction["state"] = "committed"
        transaction["committed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _write_json_atomic(backup / "transaction.json", transaction)
        (GEOFILES_STATE_DIR / "transaction.json").unlink(missing_ok=True)
        shutil.rmtree(stage, ignore_errors=True)
        prune_geofiles_storage(active_generation=generation)
        return {
            "source": manifest_source,
            "source_label": str(GEOFILES_SOURCES[manifest_source]["label"]),
            "backup": str(backup),
            "generation": generation,
            "geoip": geoip_info,
            "geosite": geosite_info,
            "preset": candidate.get("preset", {}),
            "service": "active",
        }
    except Exception as exc:
        original_error = exc
        transaction["state"] = "rolling_back"
        transaction["error"] = str(exc)
        _write_json_atomic(GEOFILES_STATE_DIR / "transaction.json", transaction)
        try:
            _run(["systemctl", "stop", service], timeout=40)
            for name, current in (("geoip.dat", active_geoip), ("geosite.dat", active_geosite)):
                previous = backup / name
                if previous.is_file():
                    shutil.copy2(previous, current)
                elif not asset_existed[name]:
                    current.unlink(missing_ok=True)
            old_config = backup / "config.json"
            if old_config.is_file():
                shutil.copy2(old_config, config_path)
                os.chmod(config_path, 0o644)
            elif not config_existed:
                config_path.unlink(missing_ok=True)
            _restore_routing_state(routing_snapshot)
            _restore_geofiles_settings(geofiles_snapshot)
            if config_path.is_file():
                rollback_test = _run_xray_test_with_assets(
                    str(server["xray_bin"]), config_path, active_geoip.parent
                )
                if rollback_test.returncode != 0:
                    raise XPanelError(
                        "старый config.json не прошёл xray run -test после восстановления: "
                        + ((rollback_test.stderr or rollback_test.stdout).strip() or "неизвестная ошибка")
                    )
            _systemctl_checked("restart", service)
            _confirm_xray_active(service)
            transaction["state"] = "rolled_back"
            transaction["rolled_back_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _write_json_atomic(backup / "transaction.json", transaction)
            (GEOFILES_STATE_DIR / "transaction.json").unlink(missing_ok=True)
        except Exception as rollback_exc:
            transaction["state"] = "rollback_failed"
            transaction["rollback_error"] = str(rollback_exc)
            _write_json_atomic(GEOFILES_STATE_DIR / "transaction.json", transaction)
            raise XPanelError(
                "Критическая ошибка отката: файлы или настройки могли быть восстановлены не полностью, "
                f"а Xray не подтверждён как active. Исходная ошибка: {original_error}. "
                f"Ошибка rollback: {rollback_exc}"
            ) from rollback_exc
        if isinstance(original_error, OSError) and original_error.errno in {
            errno.EACCES, errno.EPERM, errno.EROFS,
        }:
            failed_path = Path(str(original_error.filename or active_geoip.parent))
            raise XPanelError(
                "каталог ресурсов Xray недоступен для записи из службы SG-Panel: "
                f"{failed_path}. Рабочее состояние восстановлено и Xray подтверждён как active"
            ) from original_error
        raise
    finally:
        for temporary in (live_tmp_geoip, live_tmp_geosite, config_tmp):
            temporary.unlink(missing_ok=True)


def _node_geofiles_payload(node_id: int) -> dict[str, object]:
    """Build the exact active Controller generation payload for one SG-Node."""
    from .node_manager import latest_node_config

    settings = get_geofiles_settings()
    generation = str(settings["active_generation"] or "").strip()
    if not generation or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", generation):
        raise XPanelError("на Controller ещё нет активного транзакционного поколения GeoFiles")
    generation_dir = GEOFILES_STATE_DIR / "sets" / generation
    manifest_path = generation_dir / "manifest.json"
    geoip = generation_dir / "geoip.dat"
    geosite = generation_dir / "geosite.dat"
    if not manifest_path.is_file() or not geoip.is_file() or not geosite.is_file():
        raise XPanelError("активное поколение GeoFiles Controller неполно")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise XPanelError("manifest активного поколения GeoFiles повреждён") from exc
    config = latest_node_config(int(node_id))
    if not isinstance(config, dict):
        raise XPanelError("на SG-Node ещё нет сохранённого полного Xray config")
    config_sha256 = hashlib.sha256(
        json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "transfer": "controller",
        "controller_generation": generation,
        "source": str(manifest.get("source") or settings["active_source"] or "controller"),
        "source_label": str(manifest.get("source_label") or "Controller generation"),
        "geoip_sha256": _sha256_file(geoip),
        "geosite_sha256": _sha256_file(geosite),
        "manifest": manifest,
        "config": config,
        "config_sha256": config_sha256,
    }


def _node_geofiles_job_type(preferred: str) -> str:
    """Use native job types when the upgraded DB supports them, otherwise tunnel via apply_xray_config."""
    with connect() as con:
        row = con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='node_jobs'"
        ).fetchone()
    sql = str(row[0] or "") if row else ""
    return preferred if preferred in sql else "apply_xray_config"


def queue_node_geofiles_validate(node_id: int) -> dict[str, object]:
    """Queue staging and full local validation without changing live Node files."""
    from .node_manager import create_node_job

    payload = _node_geofiles_payload(int(node_id))
    generation = str(payload["controller_generation"])
    stage_payload = {**payload, "worker_operation": "stage_geofiles"}
    validate_payload = {**payload, "worker_operation": "validate_geofiles"}
    stage_job = create_node_job(
        int(node_id),
        job_type=_node_geofiles_job_type("stage_geofiles"),
        title=f"GeoFiles staging {generation}",
        payload=stage_payload,
    )
    validation_job = create_node_job(
        int(node_id),
        job_type=_node_geofiles_job_type("validate_geofiles"),
        title=f"GeoFiles validate {generation}",
        payload=validate_payload,
    )
    return {"stage_job": stage_job, "validation_job": validation_job, "generation": generation}


def _node_geofiles_was_validated(node_id: int, payload: dict[str, object]) -> bool:
    from .node_manager import list_node_jobs

    generation = str(payload.get("controller_generation") or "")
    config_sha256 = str(payload.get("config_sha256") or "")
    for job in list_node_jobs(int(node_id), limit=100):
        if str(job.get("status") or "") != "succeeded":
            continue
        job_payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        operation = str(job_payload.get("worker_operation") or job.get("job_type") or "")
        if operation != "validate_geofiles":
            continue
        if str(job_payload.get("controller_generation") or "") != generation:
            continue
        if str(job_payload.get("config_sha256") or "") != config_sha256:
            continue
        return True
    return False


def get_node_geofiles_rollout_status(node_id: int) -> dict[str, object]:
    """Describe validation/apply readiness for the exact active Controller generation."""
    from .node_manager import list_node_jobs

    try:
        payload = _node_geofiles_payload(int(node_id))
    except XPanelError as exc:
        return {
            "ready": False,
            "validated": False,
            "can_apply": False,
            "generation": "",
            "config_sha256": "",
            "state": "unavailable",
            "message": str(exc),
        }
    generation = str(payload.get("controller_generation") or "")
    config_sha256 = str(payload.get("config_sha256") or "")
    state = "not_validated"
    message = "Сначала выполните локальную проверку этой Node"
    for job in list_node_jobs(int(node_id), limit=100):
        job_payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        operation = str(job_payload.get("worker_operation") or job.get("job_type") or "")
        if operation != "validate_geofiles":
            continue
        if str(job_payload.get("controller_generation") or "") != generation:
            continue
        if str(job_payload.get("config_sha256") or "") != config_sha256:
            continue
        state = str(job.get("status") or "unknown")
        if state == "succeeded":
            message = "Это поколение и полный Node config проверены локальным Xray"
        elif state in {"queued", "running"}:
            message = "Локальная проверка поставлена в очередь" if state == "queued" else "Локальная проверка выполняется"
        else:
            detail = str(job.get("error") or job.get("message") or "").strip()
            message = "Локальная проверка не пройдена" + (f": {detail}" if detail else "")
        break
    validated = state == "succeeded"
    return {
        "ready": True,
        "validated": validated,
        "can_apply": validated,
        "generation": generation,
        "config_sha256": config_sha256,
        "state": state,
        "message": message,
    }


def queue_node_geofiles_apply(node_id: int) -> dict[str, object]:
    """Apply only an exact generation/config pair already validated locally by this Node."""
    from .node_manager import create_node_job

    payload = _node_geofiles_payload(int(node_id))
    if not _node_geofiles_was_validated(int(node_id), payload):
        raise XPanelError(
            "сначала выполните «Проверить на Node» и дождитесь успешного локального "
            "xray run -test для текущего поколения и конфигурации"
        )
    generation = str(payload["controller_generation"])
    payload = {**payload, "worker_operation": "apply_geofiles"}
    return create_node_job(
        int(node_id),
        job_type=_node_geofiles_job_type("apply_geofiles"),
        title=f"GeoFiles apply {generation}",
        payload=payload,
    )


def get_geofiles_overview() -> dict[str, object]:
    settings = get_geofiles_settings()
    active_geoip, active_geosite = _current_asset_paths()
    source_key = str(settings["active_source"] or "xray")
    try:
        staged_manifest = json.loads(settings["staged_manifest_json"] or "{}")
    except json.JSONDecodeError:
        staged_manifest = {}
    selected_key = str(staged_manifest.get("source") or settings["source"] or "sgclient")
    selection = {
        "source": selected_key,
        "geoip_url": str(staged_manifest.get("geoip_url") or settings["geoip_url"] or ""),
        "geosite_url": str(staged_manifest.get("geosite_url") or settings["geosite_url"] or ""),
        "geoip_local_path": str(staged_manifest.get("geoip_local_path") or settings["geoip_local_path"] or ""),
        "geosite_local_path": str(staged_manifest.get("geosite_local_path") or settings["geosite_local_path"] or ""),
    }
    active_analysis: dict[str, object] = {
        "family": "Не определено",
        "geoip_categories": [],
        "geosite_categories": [],
        "error": "",
    }
    if active_geoip.is_file() and active_geosite.is_file():
        try:
            active_analysis.update(_analyze_geofile_pair(active_geoip, active_geosite))
        except (OSError, XPanelError) as exc:
            active_analysis["error"] = str(exc)
    return {
        "settings": settings,
        "sources": supported_geofiles_sources(),
        "selected_source": selected_key,
        "selection": selection,
        "selected_label": str(
            GEOFILES_SOURCES.get(selected_key, {}).get("label", selected_key)
        ),
        "active_source": source_key,
        "active_label": str(
            GEOFILES_SOURCES.get(source_key, {}).get("label", source_key)
        ),
        "geoip": _geofile_info(active_geoip),
        "geosite": _geofile_info(active_geosite),
        "active_analysis": active_analysis,
        "staged_manifest": staged_manifest,
    }


def get_geodata_status() -> list[dict[str, object]]:
    overview = get_geofiles_overview()
    return [
        {"name": "geoip.dat", **overview["geoip"], "source": overview["active_label"]},
        {"name": "geosite.dat", **overview["geosite"], "source": overview["active_label"]},
    ]


def _active_users(rows: list[sqlite3.Row]) -> list[sqlite3.Row]:
    return [row for row in rows if row["enabled"] and not user_is_expired(row)]


def _reality_settings(
    server: sqlite3.Row,
    *,
    short_id: str | None = None,
    short_ids: list[str] | None = None,
) -> dict[str, object]:
    values = [str(value) for value in (short_ids or []) if str(value)]
    if not values:
        values = [short_id or server["short_id"]]
    return {
        "show": False,
        "dest": server["dest"],
        "xver": 0,
        "serverNames": [server["server_name"]],
        "privateKey": server["private_key"],
        "shortIds": values,
    }


def _controller_encryption_reality_settings(server: sqlite3.Row) -> dict[str, object]:
    settings = _reality_settings(server)
    settings["publicKey"] = str(server["public_key"] or "")
    return settings


def _sync_controller_encryption_deployments(
    pair: dict[str, str], server: sqlite3.Row | None = None
) -> None:
    server = server or get_server()
    profile = str(server["inbound_profile"] or "raw_reality")
    encryption = str(pair.get("encryption") or "")
    generation = str(pair.get("generation") or "")
    export_ready = int(
        profile in VLESSENC_SERVER_PROFILES and client_value_ready(encryption)
    )
    with connect() as con:
        local = con.execute("SELECT id FROM nodes WHERE is_local=1 LIMIT 1").fetchone()
        if local is None:
            return
        con.execute(
            """
            UPDATE nodes
            SET xray_encryption_state='ready',
                xray_encryption_generation=?,
                xray_encryption_checked_at=?,
                xray_minimum_supported=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (
                generation,
                str(pair.get("checked_at") or ""),
                MINIMUM_XRAY_LABEL,
                int(local["id"]),
            ),
        )
        con.execute(
            """
            UPDATE node_deployments
            SET client_encryption=?, reality_public_key=?, reality_short_id=?,
                reality_server_name=?, xhttp_path=?, xhttp_server_mode=?,
                xhttp_client_mode=?, encryption_generation=?, export_ready=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE node_id=? AND state!='removed'
            """,
            (
                encryption,
                str(server["public_key"] or ""),
                str(server["short_id"] or ""),
                str(server["server_name"] or ""),
                str(server["xhttp_path"] or "/sg-xhttp"),
                VLESSENC_SERVER_MODE_DEFAULT,
                str(server["xhttp_client_mode"] or VLESSENC_CLIENT_MODE_DEFAULT),
                generation,
                export_ready,
                int(local["id"]),
            ),
        )


def ensure_controller_xray_encryption(*, force: bool = False) -> dict[str, str]:
    server = get_server()
    try:
        pair = ensure_xray_encryption_pair(
            str(server["xray_bin"]),
            secret_path=XRAY_ENCRYPTION_SECRET_PATH,
            force=force,
            reality_settings=_controller_encryption_reality_settings(server),
        )
    except XrayEncryptionRuntimeError as exc:
        with connect() as con:
            con.execute(
                """
                UPDATE nodes
                SET xray_encryption_state='error', last_error=?,
                    xray_minimum_supported=?, updated_at=CURRENT_TIMESTAMP
                WHERE is_local=1
                """,
                (str(exc)[:1000], MINIMUM_XRAY_LABEL),
            )
        raise XPanelError(str(exc)) from exc
    _sync_controller_encryption_deployments(pair, server)
    return pair


def controller_xray_encryption_status() -> dict[str, object]:
    server = get_server()
    try:
        version = require_supported_xray(str(server["xray_bin"]))
        pair = read_xray_encryption_pair(XRAY_ENCRYPTION_SECRET_PATH)
        ready = client_value_ready(pair["encryption"]) and server_value_ready(pair["decryption"])
        message = "ML-KEM-768 готов" if ready else "ML-KEM-768 не готов"
    except (XrayEncryptionRuntimeError, OSError, KeyError) as exc:
        version = (0, 0, 0)
        pair = {"generation": "", "checked_at": ""}
        ready = False
        message = str(exc)
    return {
        "ready": ready,
        "message": message,
        "minimum": MINIMUM_XRAY_LABEL,
        "version": f"v{version[0]}.{version[1]}.{version[2]}" if version != (0, 0, 0) else "",
        "generation": str(pair.get("generation") or ""),
        "checked_at": str(pair.get("checked_at") or ""),
        "server_mode": VLESSENC_SERVER_MODE_DEFAULT,
        "client_mode": str(server["xhttp_client_mode"] or VLESSENC_CLIENT_MODE_DEFAULT),
        "secret_path": str(XRAY_ENCRYPTION_SECRET_PATH),
        "profile": str(server["inbound_profile"] or "raw_reality"),
    }


def _controller_vless_encryption_pair() -> dict[str, str]:
    pair = ensure_controller_xray_encryption()
    if not client_value_ready(pair.get("encryption")):
        raise XPanelError("Client Encryption ML-KEM-768 не готов")
    if not server_value_ready(pair.get("decryption")):
        raise XPanelError("Server Decryption ML-KEM-768 не готов")
    return pair


def _merge_dicts(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    result = _copy_json_object(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_dicts(result[key], value)  # type: ignore[arg-type]
        else:
            result[key] = value
    return result


def _expert_json(name: str) -> dict[str, object]:
    row = get_transport_expert_settings()
    value = row[name]
    try:
        parsed = json.loads(str(value or "{}"))
    except json.JSONDecodeError as exc:
        raise XPanelError(f"повреждён {name}: {exc}") from exc
    return parsed if isinstance(parsed, dict) else {}


def _effective_xhttp_extra(
    side: str, *, expert: sqlite3.Row | None = None
) -> dict[str, object]:
    row = expert or get_transport_expert_settings()
    field = "xhttp_extra_server_json" if side == "server" else "xhttp_extra_client_json"
    try:
        parsed = json.loads(str(row[field] or "{}"))
    except json.JSONDecodeError as exc:
        raise XPanelError(f"повреждён {field}: {exc}") from exc
    result = _copy_json_object(parsed if isinstance(parsed, dict) else {})
    mode = str(row["xmux_mode"] or "auto")
    result.pop("xmux", None)
    if mode == "expert":
        raw = parsed if isinstance(parsed, dict) else {}
        if isinstance(raw.get("xmux"), dict):
            result["xmux"] = _copy_json_object(raw["xmux"])
    elif mode == "reduced" and side == "client":
        result["xmux"] = _copy_json_object(XMUX_REDUCED_PRESET)
    _validate_xmux_conflicts(result, label=f"XHTTP {side.title()} Extra")
    return result


def _deployment_slot_display_label(slot: str, *, manual: bool) -> str:
    if not manual:
        return "Автоматически"
    return {"primary": "Основное", "backup": "Резервное", "alt": "Следующее"}.get(slot, "Следующее")


def _apply_hysteria_salamander_to_inbound(
    inbound: dict[str, object], instance: sqlite3.Row
) -> None:
    """Merge the SG-Panel managed Salamander UDP layer without replacing FinalMask.

    Expert FinalMask JSON remains authoritative for every other TCP/UDP layer
    and for ``quicParams``.  An expert Salamander layer is rejected while the
    managed switch is enabled because a clean Xray JSON cannot carry private
    ownership metadata and silently replacing it would make disable/rollback
    ambiguous.
    """
    stream = inbound.get("streamSettings")
    if not isinstance(stream, dict):
        raise XPanelError("Hysteria 2: отсутствует streamSettings")
    finalmask = stream.get("finalmask")
    finalmask = _copy_json_object(finalmask) if isinstance(finalmask, dict) else {}
    raw_udp = finalmask.get("udp")
    if raw_udp is None:
        udp_layers: list[object] = []
    elif isinstance(raw_udp, list):
        udp_layers = json.loads(json.dumps(raw_udp, ensure_ascii=False))
    else:
        raise XPanelError("Hysteria 2: finalmask.udp должен быть массивом")

    mode, password = _normalise_hysteria_obfs(
        instance["obfs_mode"], instance["obfs_password"]
    )
    foreign_salamander = [
        layer for layer in udp_layers
        if isinstance(layer, dict)
        and str(layer.get("type") or "").strip().lower() == "salamander"
    ]
    if mode == "salamander":
        if foreign_salamander:
            raise XPanelError(
                "Hysteria 2: в Expert FinalMask уже есть Salamander. "
                "Удалите его из Server JSON и управляйте режимом через карточку Inbound."
            )
        udp_layers.append({
            "type": "salamander",
            "settings": {"password": str(password)},
        })
    if udp_layers:
        finalmask["udp"] = udp_layers
    else:
        finalmask.pop("udp", None)
    if finalmask:
        stream["finalmask"] = finalmask
    else:
        stream.pop("finalmask", None)


def _hysteria_instance_for_runtime_tag(tag: str) -> sqlite3.Row | None:
    rows = list_hysteria_inbounds()
    by_id = {int(row["id"]): row for row in rows}
    if tag in {"sg-hysteria2", HYSTERIA_COMBINED_PRIMARY_TAG, HYSTERIA_INBOUND_TAGS[1]}:
        return by_id.get(1)
    for row in rows:
        if str(row["tag"]) == tag:
            return row
    return None


def _apply_transport_expert_to_inbound(inbound: dict[str, object]) -> None:
    stream = inbound.get("streamSettings")
    if not isinstance(stream, dict):
        return
    expert = get_transport_expert_settings()
    if str(stream.get("network", "")) == "xhttp":
        xhttp = stream.get("xhttpSettings")
        xhttp = xhttp if isinstance(xhttp, dict) else {}
        extra = _effective_xhttp_extra("server")
        if extra:
            existing = xhttp.get("extra")
            xhttp["extra"] = _merge_dicts(existing if isinstance(existing, dict) else {}, extra)
        else:
            xhttp.pop("extra", None)
        stream["xhttpSettings"] = xhttp
    if bool(expert["finalmask_enabled"]):
        custom = _expert_json("finalmask_server_json")
        existing = stream.get("finalmask")
        stream["finalmask"] = _merge_dicts(existing if isinstance(existing, dict) else {}, custom)
    # ECH is a server-side Xray TLS feature. XHTTP-TLS in SG-Panel is terminated
    # by Nginx, so only direct Xray TLS inbounds receive echServerKeys here.
    if str(stream.get("security", "")) == "tls" and str(expert["ech_mode"]) in {"generated", "existing", "dns"}:
        keys = str(expert["ech_server_keys"] or "").strip()
        if keys:
            tls = stream.get("tlsSettings")
            tls = tls if isinstance(tls, dict) else {}
            tls["echServerKeys"] = keys
            stream["tlsSettings"] = tls
    if str(inbound.get("protocol") or "").lower() == "hysteria":
        instance = _hysteria_instance_for_runtime_tag(str(inbound.get("tag") or ""))
        if instance is None:
            raise XPanelError("Hysteria 2: не найдено состояние Inbound для FinalMask")
        _apply_hysteria_salamander_to_inbound(inbound, instance)


def _xhttp_settings(server: sqlite3.Row) -> dict[str, object]:
    settings: dict[str, object] = {"path": server["xhttp_path"]}
    if server["xhttp_mode"] and server["xhttp_mode"] != "auto":
        settings["mode"] = server["xhttp_mode"]
    extra = _effective_xhttp_extra("server")
    if extra:
        settings["extra"] = extra
    return settings


def _hysteria_masquerade(server: sqlite3.Row) -> dict[str, object]:
    kind = str(server["hysteria_masquerade_type"] or "").strip().lower()
    if kind == "proxy":
        return {
            "type": "proxy",
            "url": str(server["hysteria_masquerade_url"] or "").strip(),
            "rewriteHost": bool(server["hysteria_masquerade_rewrite_host"]),
            "insecure": bool(server["hysteria_masquerade_insecure"]),
        }
    if kind == "file":
        return {
            "type": "file",
            "dir": str(server["hysteria_masquerade_dir"] or "").strip(),
        }
    if kind == "string":
        headers = _parse_hysteria_headers(str(server["hysteria_masquerade_headers"] or "{}"))
        if not headers:
            headers = {"content-type": "text/html; charset=utf-8"}
        return {
            "type": "string",
            "content": str(server["hysteria_masquerade_content"] or ""),
            "headers": headers,
            "statusCode": int(server["hysteria_masquerade_status"] or 404),
        }
    return {"type": ""}


def _hysteria_rate_value(value: object) -> str:
    """Return Xray Bandwidth values as JSON strings, including the unlimited value ``"0"``."""
    return str(value or "0").strip().lower() or "0"


def _hysteria_hop_interval_value(value: object) -> str | int:
    cleaned = str(value or "30").strip()
    return int(cleaned) if cleaned.isdigit() else cleaned


def _hysteria_quic_params(server: sqlite3.Row) -> dict[str, object]:
    params: dict[str, object] = {
        "congestion": str(server["hysteria_congestion"] or "brutal"),
        "bbrProfile": str(server["hysteria_bbr_profile"] or "standard"),
        "debug": bool(server["hysteria_quic_debug"]),
        "brutalUp": _hysteria_rate_value(server["hysteria_brutal_up"]),
        "brutalDown": _hysteria_rate_value(server["hysteria_brutal_down"]),
        "initStreamReceiveWindow": int(server["hysteria_init_stream_receive_window"] or 8388608),
        "maxStreamReceiveWindow": int(server["hysteria_max_stream_receive_window"] or 8388608),
        "initConnectionReceiveWindow": int(server["hysteria_init_connection_receive_window"] or 20971520),
        "maxConnectionReceiveWindow": int(server["hysteria_max_connection_receive_window"] or 20971520),
        "maxIdleTimeout": int(server["hysteria_max_idle_timeout"] or 30),
        "keepAlivePeriod": int(server["hysteria_keepalive_period"] or 0),
        "disablePathMTUDiscovery": bool(server["hysteria_disable_pmtud"]),
        "maxIncomingStreams": int(server["hysteria_max_incoming_streams"] or 1024),
    }
    hop_ports = str(server["hysteria_udp_hop_ports"] or "").strip()
    if hop_ports:
        params["udpHop"] = {
            "ports": hop_ports,
            "interval": _hysteria_hop_interval_value(server["hysteria_udp_hop_interval"]),
        }
    return params


def _build_hysteria_inbound(
    server: sqlite3.Row,
    instance: sqlite3.Row,
    users: list[dict[str, object]],
    auths: dict[int, dict[int, str]],
    *,
    tag_override: str | None = None,
) -> dict[str, object]:
    inbound_id = int(instance["id"])
    auth_map = auths.get(inbound_id, {})
    hysteria_users = [
        {
            "auth": auth_map[int(user["id"])],
            "email": str(user["name"]),
            "level": 0,
        }
        for user in users
    ]
    if str(server["inbound_profile"] or "") == RUSSIA_KIT_PROFILE:
        edge = _russia_kit_edge(server)
        tls_server_name = str(edge["domain"])
        tls_certificate_file = str(edge["cert"])
        tls_key_file = str(edge["key"])
    else:
        tls_server_name = str(server["server_name"])
        tls_certificate_file = str(server["tls_cert_path"])
        tls_key_file = str(server["tls_key_path"])
    return {
        "tag": str(tag_override or instance["tag"]),
        "listen": str(instance["listen"]),
        "port": int(instance["port"]),
        "protocol": "hysteria",
        "settings": {"version": 2, "users": hysteria_users},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "hysteriaSettings": {
                "version": 2,
                "udpIdleTimeout": int(server["hysteria_udp_idle_timeout"] or 60),
                "masquerade": _hysteria_masquerade(server),
            },
            "finalmask": {"quicParams": _hysteria_quic_params(server)},
            "tlsSettings": {
                "serverName": tls_server_name,
                "alpn": ["h3"],
                "minVersion": "1.3",
                "certificates": [
                    {
                        "certificateFile": tls_certificate_file,
                        "keyFile": tls_key_file,
                    }
                ],
            },
        },
    }


def _build_xhttp_inbound(
    server: sqlite3.Row,
    instance: sqlite3.Row,
    clients: list[dict[str, object]],
) -> dict[str, object]:
    pair = _controller_vless_encryption_pair()
    settings: dict[str, object] = {"path": str(instance["path"])}
    mode = str(server["xhttp_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT)
    settings["mode"] = mode
    return {
        "tag": str(instance["tag"]),
        "listen": str(instance["listen"]),
        "port": int(instance["port"]),
        "protocol": "vless",
        "settings": {
            "clients": clients,
            "decryption": pair["decryption"],
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": settings,
        },
    }


def _build_reality_inbound(
    server: sqlite3.Row,
    instance: sqlite3.Row,
    clients: list[dict[str, object]],
) -> dict[str, object]:
    instance_id = int(instance["id"])
    listen = str(instance["listen"])
    port = int(instance["port"])
    if instance_id == 1:
        edge = _reality_edge_settings(server)
        if edge.get("enabled"):
            listen = "127.0.0.1"
            port = int(edge["xray_port"])
    return {
        "tag": str(instance["tag"]),
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": _reality_settings(server, short_id=str(instance["short_id"])),
        },
    }


def _build_reality_vision_inbound(
    server: sqlite3.Row,
    instances: list[sqlite3.Row],
    clients: list[dict[str, object]],
) -> dict[str, object]:
    """Build one Vision handler for every enabled public REALITY entry point.

    Xray has a long-standing failure mode when several independent VLESS
    REALITY handlers use Vision simultaneously.  A single handler can listen
    on several ports and can accept several REALITY shortIds, so SG-Panel
    consolidates the public entry points instead of duplicating Vision state.
    """
    if not instances:
        raise XPanelError("не включён ни один REALITY Inbound")
    edge = _reality_edge_settings(server)
    if edge.get("enabled"):
        listen: str = "127.0.0.1"
        port: int | str = int(edge["xray_port"])
    else:
        listens = {str(item["listen"]) for item in instances}
        if len(listens) != 1:
            raise XPanelError(
                "REALITY Vision с несколькими точками входа требует одинаковый listen"
            )
        listen = listens.pop()
        port = ",".join(str(int(item["port"])) for item in instances)
    return {
        "tag": str(instances[0]["tag"]),
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": _reality_settings(
                server,
                short_ids=[str(item["short_id"]) for item in instances],
            ),
        },
    }


def _build_russia_kit_inbounds(
    server: sqlite3.Row, clients: list[dict[str, object]], users: list[sqlite3.Row]
) -> list[dict[str, object]]:
    edge = _russia_kit_edge(server)
    pair = _controller_vless_encryption_pair()
    vision_clients: list[dict[str, object]] = []
    for source in clients:
        modern = dict(source)
        modern["flow"] = "xtls-rprx-vision"
        vision_clients.append(modern)

    server_extra = _effective_xhttp_extra("server")
    reality_xhttp: dict[str, object] = {
        "path": RUSSIA_KIT_XHTTP_REALITY_PATH,
        "mode": VLESSENC_SERVER_MODE_DEFAULT,
    }
    if server_extra:
        reality_xhttp["extra"] = server_extra
    reality = {
        "tag": "vless-reality-in",
        "listen": "127.0.0.1",
        "port": int(edge["xray_port"]),
        "protocol": "vless",
        "settings": {
            "clients": vision_clients,
            "decryption": pair["decryption"],
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": reality_xhttp,
            "realitySettings": _reality_settings(server),
        },
    }
    tls_xhttp: dict[str, object] = {
        "path": RUSSIA_KIT_XHTTP_TLS_PATH,
        "mode": str(server["xhttp_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT),
    }
    if server_extra:
        tls_xhttp["extra"] = server_extra
    xhttp_tls = {
        "tag": "xhttp-tls-in",
        "listen": "127.0.0.1",
        "port": RUSSIA_KIT_XHTTP_TLS_PORT,
        "protocol": "vless",
        "settings": {
            "clients": vision_clients,
            "decryption": pair["decryption"],
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": tls_xhttp,
            "sockopt": {"trustedXForwardedFor": ["127.0.0.1"]},
        },
    }
    ws_tls = {
        "tag": "ws-tls-in",
        "listen": "127.0.0.1",
        "port": RUSSIA_KIT_WS_PORT,
        "protocol": "vless",
        "settings": {
            "clients": vision_clients,
            "decryption": pair["decryption"],
        },
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {"path": RUSSIA_KIT_WS_PATH},
            "sockopt": {"trustedXForwardedFor": ["127.0.0.1"]},
        },
    }
    auths = _ensure_device_hysteria_auths()
    hy_instance = {
        "id": 1,
        "tag": HYSTERIA_COMBINED_PRIMARY_TAG,
        "listen": "0.0.0.0",
        "port": 443,
    }
    hysteria = _build_hysteria_inbound(
        server,
        hy_instance,
        users,
        auths,
        tag_override=HYSTERIA_COMBINED_PRIMARY_TAG,
    )
    return [reality, xhttp_tls, ws_tls, hysteria]


def _build_primary_inbound(server: sqlite3.Row, clients: list[dict[str, object]]) -> dict[str, object]:
    profile = str(server["inbound_profile"] or "raw_reality")
    if profile == "hysteria2_tls":
        users = [
            {
                "auth": str(client["id"]),
                "email": str(client["email"]),
                "level": int(client.get("level", 0)),
            }
            for client in clients
        ]
        return {
            "tag": "vless-reality-in",
            "listen": server["listen"],
            "port": server["port"],
            "protocol": "hysteria",
            "settings": {"version": 2, "users": users},
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "hysteriaSettings": {
                    "version": 2,
                    "udpIdleTimeout": int(server["hysteria_udp_idle_timeout"] or 60),
                    "masquerade": _hysteria_masquerade(server),
                },
                "finalmask": {"quicParams": _hysteria_quic_params(server)},
                "tlsSettings": {
                    "serverName": server["server_name"],
                    "alpn": ["h3"],
                    "minVersion": "1.3",
                    "certificates": [
                        {
                            "certificateFile": server["tls_cert_path"],
                            "keyFile": server["tls_key_path"],
                        }
                    ],
                },
            },
        }

    decryption = "none"
    if profile in VLESSENC_SERVER_PROFILES:
        decryption = _controller_vless_encryption_pair()["decryption"]
    inbound: dict[str, object] = {
        "tag": "vless-reality-in",
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": decryption},
    }
    if profile in TLS_INBOUND_PROFILES:
        inbound["listen"] = server["transport_listen"]
        inbound["port"] = server["transport_port"]
    elif profile in REALITY_INBOUND_PROFILES:
        edge = _reality_edge_settings(server)
        if edge.get("enabled"):
            inbound["listen"] = "127.0.0.1"
            inbound["port"] = int(edge["xray_port"])
        else:
            inbound["listen"] = server["listen"]
            inbound["port"] = server["port"]
    else:
        inbound["listen"] = server["listen"]
        inbound["port"] = server["port"]

    if profile == "raw_reality":
        inbound["streamSettings"] = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": _reality_settings(server),
        }
    elif profile == "xhttp_reality":
        xhttp_settings = _xhttp_settings(server)
        xhttp_settings["mode"] = VLESSENC_SERVER_MODE_DEFAULT
        inbound["streamSettings"] = {
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": xhttp_settings,
            "realitySettings": _reality_settings(server),
        }
    elif profile == "xhttp_tls":
        inbound["streamSettings"] = {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": _xhttp_settings(server),
        }
    elif profile == "grpc_tls":
        inbound["streamSettings"] = {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {"serviceName": server["grpc_service_name"]},
        }
    else:
        raise XPanelError(f"неподдерживаемый профиль inbound: {profile}")
    return inbound


def _build_managed_config() -> tuple[dict, sqlite3.Row, list[sqlite3.Row]]:
    server = get_server()
    validate_server_values(
        server["address"],
        server["port"],
        server["dest"],
        server["server_name"],
        server["private_key"],
        server["public_key"],
        server["short_id"],
        flow=server["flow"],
        loglevel=server["loglevel"],
        api_listen=server["api_listen"],
        listen=server["listen"],
        inbound_profile=server["inbound_profile"],
        transport_listen=server["transport_listen"],
        transport_port=server["transport_port"],
        xhttp_path=server["xhttp_path"],
        xhttp_mode=server["xhttp_mode"],
        grpc_service_name=server["grpc_service_name"],
        tls_cert_path=server["tls_cert_path"],
        tls_key_path=server["tls_key_path"],
        hysteria_udp_idle_timeout=server["hysteria_udp_idle_timeout"],
        hysteria_masquerade_type=server["hysteria_masquerade_type"],
        hysteria_masquerade_url=server["hysteria_masquerade_url"],
        hysteria_masquerade_content=server["hysteria_masquerade_content"],
        hysteria_masquerade_status=server["hysteria_masquerade_status"],
    )
    with connect() as con:
        all_users = con.execute("SELECT * FROM users ORDER BY id").fetchall()
        settings = con.execute("SELECT * FROM routing_settings WHERE id = 1").fetchone()
        rules = con.execute(
            "SELECT * FROM routing_rules WHERE enabled = 1 ORDER BY priority, id"
        ).fetchall()
        custom_outbounds = con.execute(
            "SELECT * FROM outbounds WHERE enabled = 1 ORDER BY id"
        ).fetchall()
    users = _active_users(all_users)

    profile = str(server["inbound_profile"] or "")
    clients: list[dict[str, object]] = []
    for row in users:
        client: dict[str, object] = {"id": row["uuid"], "email": row["name"], "level": 0}
        if profile in VISION_INBOUND_PROFILES:
            client["flow"] = "xtls-rprx-vision"
        clients.append(client)

    if profile == "raw_reality":
        instances = [row for row in list_reality_inbounds() if bool(row["enabled"])]
        if not instances or int(instances[0]["id"]) != 1:
            raise XPanelError("Основной REALITY Inbound должен быть включён")
        _validate_reality_edge_listener_ports(server, instances)
        if str(server["flow"] or "") == "xtls-rprx-vision" and len(instances) > 1:
            inbounds = [_build_reality_vision_inbound(server, instances, clients)]
        else:
            inbounds = [
                _build_reality_inbound(server, instance, clients)
                for instance in instances
            ]
    elif profile == "hysteria2_tls":
        instances = [row for row in list_hysteria_inbounds() if bool(row["enabled"])]
        if not instances or int(instances[0]["id"]) != 1:
            raise XPanelError("Основной Hysteria 2 Inbound должен быть включён")
        auths = _ensure_device_hysteria_auths()
        inbounds = [
            _build_hysteria_inbound(server, instance, users, auths)
            for instance in instances
        ]
    elif profile == "xhttp_tls":
        instances = [row for row in list_xhttp_inbounds() if bool(row["enabled"])]
        if not instances or int(instances[0]["id"]) != 1:
            raise XPanelError("Основной XHTTP Inbound должен быть включён")
        inbounds = [
            _build_xhttp_inbound(server, instance, clients)
            for instance in instances
        ]
    elif profile == RUSSIA_KIT_PROFILE:
        inbounds = _build_russia_kit_inbounds(server, clients, users)
    elif profile == "xhttp_hysteria_tls":
        xhttp_instances = [row for row in list_xhttp_inbounds() if bool(row["enabled"])]
        hysteria_instances = [row for row in list_hysteria_inbounds() if bool(row["enabled"])]
        if not xhttp_instances or int(xhttp_instances[0]["id"]) != 1:
            raise XPanelError("Основной XHTTP Inbound должен быть включён")
        if not hysteria_instances or int(hysteria_instances[0]["id"]) != 1:
            raise XPanelError("Основной Hysteria 2 Inbound должен быть включён")
        auths = _ensure_device_hysteria_auths()
        inbounds = [
            _build_xhttp_inbound(server, instance, clients)
            for instance in xhttp_instances
        ]
        inbounds.extend(
            _build_hysteria_inbound(
                server,
                instance,
                users,
                auths,
                tag_override=(HYSTERIA_COMBINED_PRIMARY_TAG if int(instance["id"]) == 1 else None),
            )
            for instance in hysteria_instances
        )
    else:
        inbounds = [_build_primary_inbound(server, clients)]

    for inbound in inbounds:
        _apply_transport_expert_to_inbound(inbound)

    if settings["sniffing_enabled"]:
        dest_override = []
        if settings["sniff_http"]:
            dest_override.append("http")
        if settings["sniff_tls"]:
            dest_override.append("tls")
        if settings["sniff_quic"]:
            dest_override.append("quic")
        for inbound in inbounds:
            inbound["sniffing"] = {
                "enabled": True,
                "destOverride": dest_override,
                "routeOnly": bool(settings["sniffing_route_only"]),
            }

    routing_config = _json_object(settings["extra_json"])
    routing_config.pop("_sgPanel", None)
    routing_config["domainStrategy"] = settings["domain_strategy"]
    routing_config["rules"] = [build_rule_json(row) for row in rules]
    config: dict[str, object] = {
        "log": {"loglevel": server["loglevel"]},
        "inbounds": inbounds,
        "outbounds": [],
        "routing": routing_config,
    }
    dns_config = build_dns_json()
    if dns_config is not None:
        config["dns"] = dns_config
    available_outbounds: dict[str, dict[str, object]] = {
        "direct": {"tag": "direct", "protocol": "freedom", "settings": {}},
        "blocked": {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    }
    warp = get_warp_overview()
    if warp["enabled"]:
        available_outbounds[WARP_TAG] = build_warp_outbound()
    for row in custom_outbounds:
        available_outbounds[str(row["tag"])] = build_outbound_json(row)

    default_tag = str(settings["default_outbound_tag"] or "direct")
    json_only_tags = {str(item["tag"]) for item in _json_only_outbounds()}
    all_available_tags = set(available_outbounds) | json_only_tags
    if default_tag == "blocked" or default_tag not in all_available_tags:
        raise XPanelError("некорректный или отключённый outbound по умолчанию")
    referenced_tags = {
        str(row["outbound_tag"]) for row in rules if (row["target_type"] or "outbound") == "outbound"
    }
    missing = sorted(referenced_tags - all_available_tags)
    if missing:
        raise XPanelError("routing rules ссылаются на отсутствующие outbounds: " + ", ".join(missing))
    balancer_tags = _balancer_tags_from_extra(routing_config)
    missing_balancers = sorted(
        {str(row["outbound_tag"]) for row in rules if row["target_type"] == "balancer"}
        - balancer_tags
    )
    if missing_balancers:
        raise XPanelError(
            "routing rules ссылаются на отсутствующие balancers: " + ", ".join(missing_balancers)
        )

    ordered_tags = [default_tag] if default_tag in available_outbounds else []
    ordered_tags.extend(tag for tag in available_outbounds if tag != default_tag)
    config["outbounds"] = [available_outbounds[tag] for tag in ordered_tags]

    if server["stats_enabled"]:
        config["api"] = {
            "tag": "api",
            "listen": server["api_listen"],
            "services": ["StatsService"],
        }
        config["stats"] = {}
        config["policy"] = {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "statsUserOnline": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        }
    return config, server, users


def _merge_tagged_objects(
    base_items: object, managed_items: list[dict[str, object]], *, key: str = "tag"
) -> list[dict[str, object]]:
    base_list = base_items if isinstance(base_items, list) else []
    managed_by_key = {str(item.get(key, "")): item for item in managed_items}
    used: set[str] = set()
    result: list[dict[str, object]] = []
    for item in base_list:
        if not isinstance(item, dict):
            continue
        item_key = str(item.get(key, ""))
        managed = managed_by_key.get(item_key)
        if managed is None:
            result.append(_copy_json_object(item))
            continue
        merged = _deep_merge_json(item, managed)
        if isinstance(merged, dict):
            result.append(merged)
        used.add(item_key)
    for item in managed_items:
        item_key = str(item.get(key, ""))
        if item_key not in used:
            result.append(_copy_json_object(item))
    return result


def _merge_clients(base_items: object, managed_items: object) -> list[dict[str, object]]:
    base_list = base_items if isinstance(base_items, list) else []
    managed_list = managed_items if isinstance(managed_items, list) else []
    base_by_email = {
        str(item.get("email", "")): item
        for item in base_list
        if isinstance(item, dict) and item.get("email")
    }
    result: list[dict[str, object]] = []
    for item in managed_list:
        if not isinstance(item, dict):
            continue
        email = str(item.get("email", ""))
        merged = _deep_merge_json(base_by_email.get(email, {}), item)
        if isinstance(merged, dict):
            if "flow" not in item:
                merged.pop("flow", None)
            result.append(merged)
    return result


def _merge_inbounds(base_items: object, managed_items: list[dict[str, object]]) -> list[dict[str, object]]:
    managed_tags = {str(item.get("tag", "")) for item in managed_items}
    known_managed_tags = set(HYSTERIA_INBOUND_TAGS.values()) | set(XHTTP_INBOUND_TAGS.values()) | set(REALITY_INBOUND_TAGS.values()) | {HYSTERIA_COMBINED_PRIMARY_TAG}
    filtered_base = (
        [
            item for item in base_items
            if not isinstance(item, dict)
            or str(item.get("tag", "")) not in known_managed_tags
            or str(item.get("tag", "")) in managed_tags
        ]
        if isinstance(base_items, list)
        else base_items
    )
    merged = _merge_tagged_objects(filtered_base, managed_items)
    for item in merged:
        if str(item.get("tag", "")) != "vless-reality-in":
            continue
        base_match = None
        if isinstance(filtered_base, list):
            base_match = next(
                (candidate for candidate in filtered_base if isinstance(candidate, dict) and candidate.get("tag") == "vless-reality-in"),
                None,
            )
        if not isinstance(base_match, dict):
            break
        managed_match = next(
            (candidate for candidate in managed_items if candidate.get("tag") == "vless-reality-in"),
            None,
        )
        if not isinstance(managed_match, dict):
            break

        base_protocol = str(base_match.get("protocol", ""))
        managed_protocol = str(managed_match.get("protocol", ""))
        base_settings = base_match.get("settings")
        managed_settings = managed_match.get("settings")
        current_settings = item.get("settings")

        if base_protocol != managed_protocol:
            item["protocol"] = managed_protocol
            item["settings"] = _copy_json_object(managed_settings if isinstance(managed_settings, dict) else {})
        elif isinstance(base_settings, dict) and isinstance(current_settings, dict):
            if isinstance(current_settings.get("clients"), list):
                current_settings["clients"] = _merge_clients(
                    base_settings.get("clients"), current_settings.get("clients")
                )
                current_settings.pop("users", None)
            elif isinstance(current_settings.get("users"), list):
                current_settings["users"] = _merge_clients(
                    base_settings.get("users"), current_settings.get("users")
                )
                current_settings.pop("clients", None)

        base_stream = base_match.get("streamSettings")
        managed_stream = managed_match.get("streamSettings")
        if isinstance(managed_stream, dict):
            base_signature = (
                base_protocol,
                str(base_stream.get("network", "")) if isinstance(base_stream, dict) else "",
                str(base_stream.get("security", "")) if isinstance(base_stream, dict) else "",
            )
            managed_signature = (
                managed_protocol,
                str(managed_stream.get("network", "")),
                str(managed_stream.get("security", "")),
            )
            if base_signature != managed_signature:
                item["streamSettings"] = _copy_json_object(managed_stream)
        break
    return merged


def _merge_dns_config(base: object, managed: object) -> dict[str, object]:
    base_dict = base if isinstance(base, dict) else {}
    managed_dict = managed if isinstance(managed, dict) else {}
    result = _deep_merge_json(base_dict, managed_dict)
    if not isinstance(result, dict):
        return _copy_json_object(managed_dict)
    base_servers = base_dict.get("servers")
    managed_servers = managed_dict.get("servers")
    if isinstance(managed_servers, list):
        base_by_address: dict[str, dict[str, object]] = {}
        if isinstance(base_servers, list):
            for item in base_servers:
                if isinstance(item, dict) and item.get("address"):
                    base_by_address[str(item["address"])] = item
        merged_servers: list[object] = []
        for item in managed_servers:
            if isinstance(item, dict):
                address = str(item.get("address", ""))
                merged_servers.append(_deep_merge_json(base_by_address.get(address, {}), item))
            else:
                merged_servers.append(item)
        result["servers"] = merged_servers
    return result


def build_config() -> tuple[dict, sqlite3.Row, list[sqlite3.Row]]:
    managed, server, users = _build_managed_config()
    base = get_config_base_document()
    if not base:
        managed = _inject_persistent_node_cascade_access(managed)
        return managed, server, users
    result = _copy_json_object(base)
    result.pop("_sgPanel", None)
    result["log"] = _deep_merge_json(result.get("log", {}), managed["log"])
    result["inbounds"] = _merge_inbounds(result.get("inbounds"), managed["inbounds"])
    merged_outbounds = _merge_tagged_objects(result.get("outbounds"), managed["outbounds"])
    default_outbound_tag = str(get_routing_settings()["default_outbound_tag"] or "direct")
    default_index = next(
        (
            index
            for index, item in enumerate(merged_outbounds)
            if str(item.get("tag", "")) == default_outbound_tag
        ),
        None,
    )
    if default_index is not None and default_index > 0:
        merged_outbounds.insert(0, merged_outbounds.pop(default_index))
    result["outbounds"] = merged_outbounds
    result["routing"] = _deep_merge_json(result.get("routing", {}), managed["routing"])
    if "dns" in managed:
        result["dns"] = _merge_dns_config(result.get("dns"), managed["dns"])
    else:
        result.pop("dns", None)
    for key in ("api", "stats", "policy"):
        if key in managed:
            result[key] = _deep_merge_json(result.get(key, {}), managed[key])
        else:
            result.pop(key, None)
    result = _inject_persistent_node_cascade_access(result)
    return result, server, users


def _find_tagged_item(items: object, tag: str) -> dict[str, object] | None:
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and str(item.get("tag", "")) == tag:
            return item
    return None


def config_json_document() -> str:
    config, server, _users = build_config()
    document = _copy_json_object(config)
    document = {
        "_sgPanel": {
            "format": "config-v1",
            "note": "_sgPanel хранит данные GUI и не передаётся Xray.",
            "defaultOutboundTag": get_routing_settings()["default_outbound_tag"],
        },
        **document,
    }
    inbound = _find_tagged_item(document.get("inbounds"), "vless-reality-in")
    if inbound is not None:
        inbound["_sgPanel"] = {
            "address": server["address"],
            "publicPort": server["port"],
            "profile": server["inbound_profile"],
            "serverName": server["server_name"],
            "publicKey": server["public_key"],
            "fingerprint": server["fingerprint"],
            "transportListen": server["transport_listen"],
            "transportPort": server["transport_port"],
            "xhttpMode": server["xhttp_mode"],
            "grpcServiceName": server["grpc_service_name"],
            "tlsCertPath": server["tls_cert_path"],
            "tlsKeyPath": server["tls_key_path"],
            "hysteriaUdpIdleTimeout": server["hysteria_udp_idle_timeout"],
            "hysteriaMasqueradeType": server["hysteria_masquerade_type"],
            "hysteriaMasqueradeUrl": server["hysteria_masquerade_url"],
            "hysteriaMasqueradeContent": server["hysteria_masquerade_content"],
            "hysteriaMasqueradeStatus": server["hysteria_masquerade_status"],
            "hysteriaMasqueradeDir": server["hysteria_masquerade_dir"],
            "hysteriaMasqueradeRewriteHost": bool(server["hysteria_masquerade_rewrite_host"]),
            "hysteriaMasqueradeInsecure": bool(server["hysteria_masquerade_insecure"]),
            "hysteriaMasqueradeHeaders": server["hysteria_masquerade_headers"],
            "hysteriaPerformanceProfile": server["hysteria_performance_profile"],
            "hysteriaCongestion": server["hysteria_congestion"],
            "hysteriaBbrProfile": server["hysteria_bbr_profile"],
            "hysteriaBrutalUp": server["hysteria_brutal_up"],
            "hysteriaBrutalDown": server["hysteria_brutal_down"],
            "hysteriaQuicDebug": bool(server["hysteria_quic_debug"]),
            "hysteriaMaxIdleTimeout": server["hysteria_max_idle_timeout"],
            "hysteriaKeepalivePeriod": server["hysteria_keepalive_period"],
            "hysteriaDisablePmtud": bool(server["hysteria_disable_pmtud"]),
            "hysteriaMaxIncomingStreams": server["hysteria_max_incoming_streams"],
            "hysteriaUdpHopPorts": server["hysteria_udp_hop_ports"],
            "hysteriaUdpHopInterval": server["hysteria_udp_hop_interval"],
            "hysteriaInitStreamReceiveWindow": server["hysteria_init_stream_receive_window"],
            "hysteriaMaxStreamReceiveWindow": server["hysteria_max_stream_receive_window"],
            "hysteriaInitConnectionReceiveWindow": server["hysteria_init_connection_receive_window"],
            "hysteriaMaxConnectionReceiveWindow": server["hysteria_max_connection_receive_window"],
        }
        settings = inbound.get("settings")
        managed_users = None
        if isinstance(settings, dict):
            if isinstance(settings.get("clients"), list):
                managed_users = settings["clients"]
            elif isinstance(settings.get("users"), list):
                managed_users = settings["users"]
        if isinstance(managed_users, list):
            users_by_name = {str(row["name"]): row for row in list_users()}
            for client in managed_users:
                if not isinstance(client, dict):
                    continue
                row = users_by_name.get(str(client.get("email", "")))
                if row is None:
                    continue
                client["_sgPanel"] = {
                    "comment": row["comment"],
                    "expiryAt": row["expiry_at"],
                    "subscriptionEnabled": bool(row["subscription_enabled"]),
                }

    custom_by_tag = {str(row["tag"]): row for row in list_custom_outbounds()}
    if isinstance(document.get("outbounds"), list):
        for outbound in document["outbounds"]:
            if not isinstance(outbound, dict):
                continue
            row = custom_by_tag.get(str(outbound.get("tag", "")))
            if row is not None:
                outbound["_sgPanel"] = {
                    "name": row["name"],
                    "enabled": bool(row["enabled"]),
                }

    document["routing"] = json.loads(routing_json_document())

    if isinstance(document.get("dns"), dict):
        dns_servers = list_dns_servers(enabled_only=True)
        by_address = {str(row["address"]): row for row in dns_servers}
        values = document["dns"].get("servers")
        if isinstance(values, list):
            for index, item in enumerate(values):
                address = str(item.get("address", "")) if isinstance(item, dict) else str(item)
                row = by_address.get(address)
                if isinstance(item, dict) and row is not None:
                    item["_sgPanel"] = {
                        "name": row["name"],
                        "priority": row["priority"],
                    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def inbound_json_document() -> str:
    document = json.loads(config_json_document())
    inbound = _find_tagged_item(document.get("inbounds"), "vless-reality-in")
    if inbound is None:
        raise XPanelError("не найден управляемый inbound vless-reality-in")
    return json.dumps(inbound, ensure_ascii=False, indent=2) + "\n"


def update_inbound_json_document(text: str) -> dict[str, object]:
    try:
        inbound = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(inbound, dict):
        raise ValueError("Inbound должен быть JSON-объектом")
    if str(inbound.get("tag", "")) != "vless-reality-in":
        raise ValueError("Inbound должен иметь tag vless-reality-in")
    document = json.loads(config_json_document())
    values = document.get("inbounds")
    if not isinstance(values, list):
        raise ValueError("config.inbounds должен быть массивом")
    replaced = False
    for index, item in enumerate(values):
        if isinstance(item, dict) and str(item.get("tag", "")) == "vless-reality-in":
            values[index] = inbound
            replaced = True
            break
    if not replaced:
        raise ValueError("не найден управляемый inbound vless-reality-in")
    return update_config_json_document(json.dumps(document, ensure_ascii=False))


def _parse_full_config_users(inbound: dict[str, object]) -> tuple[list[dict[str, object]], str]:
    settings = inbound.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("управляемый inbound: settings должен быть объектом")
    protocol = str(inbound.get("protocol", "")).lower()
    if protocol == "hysteria":
        raw_users = settings.get("users", [])
        id_field = "auth"
        flow_supported = False
        error_path = "settings.users"
    else:
        raw_users = settings.get("clients", [])
        id_field = "id"
        flow_supported = True
        error_path = "settings.clients"
    if not isinstance(raw_users, list):
        raise ValueError(f"управляемый inbound: {error_path} должен быть массивом")
    result: list[dict[str, object]] = []
    names: set[str] = set()
    uuids: set[str] = set()
    flows: set[str] = set()
    for index, client in enumerate(raw_users, start=1):
        if not isinstance(client, dict):
            raise ValueError(f"{error_path}[{index}] должен быть объектом")
        name = str(client.get("email", "")).strip()
        if not name or len(name) > 80:
            raise ValueError(f"{error_path}[{index}]: укажите email/имя до 80 символов")
        key = name.casefold()
        if key in names:
            raise ValueError(f"повторяющийся пользователь: {name}")
        names.add(key)
        user_uuid = str(client.get(id_field, "")).strip()
        try:
            uuidlib.UUID(user_uuid)
        except ValueError as exc:
            raise ValueError(f"пользователь {name}: auth должен быть UUID SG-Panel") from exc
        if user_uuid in uuids:
            raise ValueError(f"повторяющийся UUID пользователя: {user_uuid}")
        uuids.add(user_uuid)
        flow = str(client.get("flow", "") or "") if flow_supported else ""
        if flow not in ALLOWED_FLOWS:
            raise ValueError(f"пользователь {name}: неподдерживаемый flow")
        if flow:
            flows.add(flow)
        meta = client.get("_sgPanel")
        meta = meta if isinstance(meta, dict) else {}
        result.append(
            {
                "name": name,
                "uuid": user_uuid,
                "comment": str(meta.get("comment", ""))[:500],
                "expiry_at": _normalise_expiry(str(meta.get("expiryAt", "") or "")),
                "subscription_enabled": bool(meta.get("subscriptionEnabled", True)),
            }
        )
    if len(flows) > 1:
        raise ValueError("в основном inbound все клиенты должны использовать одинаковый flow")
    return result, next(iter(flows), "")


def _parse_full_config_server(
    document: dict[str, object], inbound: dict[str, object], flow: str
) -> tuple[dict[str, object], dict[str, bool]]:
    current = get_server()
    meta = inbound.get("_sgPanel")
    meta = meta if isinstance(meta, dict) else {}
    stream = inbound.get("streamSettings")
    if not isinstance(stream, dict):
        raise ValueError("управляемый inbound: streamSettings должен быть объектом")
    protocol = str(inbound.get("protocol", "")).lower()
    if protocol not in {"vless", "hysteria"}:
        raise ValueError("основной inbound должен использовать protocol: vless или hysteria")

    network = str(stream.get("network", "tcp")).lower()
    if network == "raw":
        network = "tcp"
    security = str(stream.get("security", "none")).lower()
    profile = str(meta.get("profile", "")).strip()
    if profile not in ALLOWED_INBOUND_PROFILES:
        inferred = {
            ("vless", "tcp", "reality"): "raw_reality",
            ("vless", "xhttp", "reality"): "xhttp_reality",
            ("vless", "xhttp", "none"): "xhttp_tls",
            ("vless", "grpc", "none"): "grpc_tls",
            ("hysteria", "hysteria", "tls"): "hysteria2_tls",
        }
        profile = inferred.get((protocol, network, security), "")
    if profile not in ALLOWED_INBOUND_PROFILES:
        raise ValueError("не удалось определить профиль основного inbound")

    if profile == "raw_reality" and (network, security) != ("tcp", "reality"):
        raise ValueError("профиль RAW/TCP + REALITY не соответствует streamSettings")
    if profile == "xhttp_reality" and (network, security) != ("xhttp", "reality"):
        raise ValueError("профиль XHTTP + REALITY не соответствует streamSettings")
    if profile in XHTTP_ACTIVE_PROFILES and (network, security) != ("xhttp", "none"):
        raise ValueError("для XHTTP + TLS Xray должен принимать локальный XHTTP без TLS")
    if profile == "grpc_tls" and (network, security) != ("grpc", "none"):
        raise ValueError("для gRPC + TLS Xray должен принимать локальный gRPC без TLS")
    if profile == "hysteria2_tls" and (protocol, network, security) != ("hysteria", "hysteria", "tls"):
        raise ValueError("профиль Hysteria 2 + TLS не соответствует protocol/streamSettings")

    address = str(meta.get("address") or current["address"])
    public_port = int(meta.get("publicPort") or current["port"] or 443)
    server_name = str(meta.get("serverName") or current["server_name"] or address)
    fingerprint = str(meta.get("fingerprint") or current["fingerprint"] or "firefox")
    public_key = str(meta.get("publicKey") or current["public_key"])
    dest = str(current["dest"])
    private_key = str(current["private_key"])
    short_id = str(current["short_id"])

    if profile in REALITY_INBOUND_PROFILES:
        reality = stream.get("realitySettings")
        if not isinstance(reality, dict):
            raise ValueError("основной inbound: realitySettings не найден")
        names = reality.get("serverNames", [])
        short_ids = reality.get("shortIds", [])
        server_name = str(names[0]) if isinstance(names, list) and names else ""
        short_id = str(short_ids[0]) if isinstance(short_ids, list) and short_ids else ""
        dest = str(reality.get("dest", ""))
        private_key = str(reality.get("privateKey", ""))
        if private_key != str(current["private_key"]) and "publicKey" not in meta:
            raise ValueError(
                "при изменении Reality privateKey укажите соответствующий _sgPanel.publicKey"
            )

    xhttp_path = str(current["xhttp_path"] or "/sg-xhttp")
    xhttp_mode = str(meta.get("xhttpMode") or current["xhttp_mode"] or "auto")
    if profile in XHTTP_ACTIVE_PROFILES | {"xhttp_reality"}:
        xhttp = stream.get("xhttpSettings")
        if not isinstance(xhttp, dict):
            raise ValueError("основной inbound: xhttpSettings не найден")
        xhttp_path = str(xhttp.get("path", ""))
        xhttp_mode = str(xhttp.get("mode") or meta.get("xhttpMode") or "auto")

    grpc_service_name = str(meta.get("grpcServiceName") or current["grpc_service_name"] or "sg-grpc")
    if profile == "grpc_tls":
        grpc = stream.get("grpcSettings")
        if not isinstance(grpc, dict):
            raise ValueError("основной inbound: grpcSettings не найден")
        grpc_service_name = str(grpc.get("serviceName", ""))

    hysteria_udp_idle_timeout = int(meta.get("hysteriaUdpIdleTimeout") or current["hysteria_udp_idle_timeout"] or 60)
    hysteria_masquerade_type = str(meta.get("hysteriaMasqueradeType") or current["hysteria_masquerade_type"] or "")
    hysteria_masquerade_url = str(meta.get("hysteriaMasqueradeUrl") or current["hysteria_masquerade_url"] or "")
    hysteria_masquerade_content = str(meta.get("hysteriaMasqueradeContent") or current["hysteria_masquerade_content"] or "")
    hysteria_masquerade_status = int(meta.get("hysteriaMasqueradeStatus") or current["hysteria_masquerade_status"] or 404)
    hysteria_masquerade_dir = str(meta.get("hysteriaMasqueradeDir") or current["hysteria_masquerade_dir"] or "")
    hysteria_masquerade_rewrite_host = bool(meta.get("hysteriaMasqueradeRewriteHost", current["hysteria_masquerade_rewrite_host"]))
    hysteria_masquerade_insecure = bool(meta.get("hysteriaMasqueradeInsecure", current["hysteria_masquerade_insecure"]))
    hysteria_masquerade_headers = str(meta.get("hysteriaMasqueradeHeaders") or current["hysteria_masquerade_headers"] or "{}")
    hysteria_performance_profile = str(meta.get("hysteriaPerformanceProfile") or current["hysteria_performance_profile"] or "auto")
    hysteria_congestion = str(meta.get("hysteriaCongestion") or current["hysteria_congestion"] or "brutal")
    hysteria_bbr_profile = str(meta.get("hysteriaBbrProfile") or current["hysteria_bbr_profile"] or "standard")
    hysteria_brutal_up = str(meta.get("hysteriaBrutalUp") if meta.get("hysteriaBrutalUp") is not None else current["hysteria_brutal_up"] or "0")
    hysteria_brutal_down = str(meta.get("hysteriaBrutalDown") if meta.get("hysteriaBrutalDown") is not None else current["hysteria_brutal_down"] or "0")
    hysteria_quic_debug = bool(meta.get("hysteriaQuicDebug", current["hysteria_quic_debug"]))
    hysteria_max_idle_timeout = int(meta.get("hysteriaMaxIdleTimeout") or current["hysteria_max_idle_timeout"] or 30)
    hysteria_keepalive_period = int(meta.get("hysteriaKeepalivePeriod") if meta.get("hysteriaKeepalivePeriod") is not None else current["hysteria_keepalive_period"] or 0)
    hysteria_disable_pmtud = bool(meta.get("hysteriaDisablePmtud", current["hysteria_disable_pmtud"]))
    hysteria_max_incoming_streams = int(meta.get("hysteriaMaxIncomingStreams") or current["hysteria_max_incoming_streams"] or 1024)
    hysteria_udp_hop_ports = str(meta.get("hysteriaUdpHopPorts") or current["hysteria_udp_hop_ports"] or "")
    hysteria_udp_hop_interval = str(meta.get("hysteriaUdpHopInterval") or current["hysteria_udp_hop_interval"] or "30")
    hysteria_init_stream_receive_window = int(meta.get("hysteriaInitStreamReceiveWindow") or current["hysteria_init_stream_receive_window"] or 8388608)
    hysteria_max_stream_receive_window = int(meta.get("hysteriaMaxStreamReceiveWindow") or current["hysteria_max_stream_receive_window"] or 8388608)
    hysteria_init_connection_receive_window = int(meta.get("hysteriaInitConnectionReceiveWindow") or current["hysteria_init_connection_receive_window"] or 20971520)
    hysteria_max_connection_receive_window = int(meta.get("hysteriaMaxConnectionReceiveWindow") or current["hysteria_max_connection_receive_window"] or 20971520)
    if profile == "hysteria2_tls":
        hysteria = stream.get("hysteriaSettings")
        if not isinstance(hysteria, dict) or int(hysteria.get("version", 0) or 0) != 2:
            raise ValueError("основной inbound: hysteriaSettings.version должен быть 2")
        hysteria_udp_idle_timeout = int(hysteria.get("udpIdleTimeout", hysteria_udp_idle_timeout) or 60)
        masquerade = hysteria.get("masquerade")
        masquerade = masquerade if isinstance(masquerade, dict) else {}
        hysteria_masquerade_type = str(masquerade.get("type", "") or "")
        hysteria_masquerade_url = str(masquerade.get("url", "") or "")
        hysteria_masquerade_content = str(masquerade.get("content", "") or "")
        hysteria_masquerade_status = int(masquerade.get("statusCode", 404) or 404)
        hysteria_masquerade_dir = str(masquerade.get("dir", "") or "")
        hysteria_masquerade_rewrite_host = bool(masquerade.get("rewriteHost", hysteria_masquerade_rewrite_host))
        hysteria_masquerade_insecure = bool(masquerade.get("insecure", hysteria_masquerade_insecure))
        headers = masquerade.get("headers")
        if isinstance(headers, dict):
            hysteria_masquerade_headers = json.dumps(headers, ensure_ascii=False, indent=2)
        finalmask = stream.get("finalmask")
        finalmask = finalmask if isinstance(finalmask, dict) else {}
        quic_params = finalmask.get("quicParams")
        quic_params = quic_params if isinstance(quic_params, dict) else {}
        hysteria_congestion = str(quic_params.get("congestion") or hysteria_congestion)
        hysteria_bbr_profile = str(quic_params.get("bbrProfile") or hysteria_bbr_profile)
        hysteria_brutal_up = str(quic_params.get("brutalUp") if quic_params.get("brutalUp") is not None else hysteria_brutal_up)
        hysteria_brutal_down = str(quic_params.get("brutalDown") if quic_params.get("brutalDown") is not None else hysteria_brutal_down)
        hysteria_quic_debug = bool(quic_params.get("debug", hysteria_quic_debug))
        hysteria_max_idle_timeout = int(quic_params.get("maxIdleTimeout", hysteria_max_idle_timeout) or 30)
        hysteria_keepalive_period = int(quic_params.get("keepAlivePeriod", hysteria_keepalive_period) or 0)
        hysteria_disable_pmtud = bool(quic_params.get("disablePathMTUDiscovery", hysteria_disable_pmtud))
        hysteria_max_incoming_streams = int(quic_params.get("maxIncomingStreams", hysteria_max_incoming_streams) or 1024)
        hysteria_init_stream_receive_window = int(quic_params.get("initStreamReceiveWindow", hysteria_init_stream_receive_window) or 8388608)
        hysteria_max_stream_receive_window = int(quic_params.get("maxStreamReceiveWindow", hysteria_max_stream_receive_window) or 8388608)
        hysteria_init_connection_receive_window = int(quic_params.get("initConnectionReceiveWindow", hysteria_init_connection_receive_window) or 20971520)
        hysteria_max_connection_receive_window = int(quic_params.get("maxConnectionReceiveWindow", hysteria_max_connection_receive_window) or 20971520)
        udp_hop = quic_params.get("udpHop")
        if isinstance(udp_hop, dict):
            hysteria_udp_hop_ports = str(udp_hop.get("ports", "") or "")
            hysteria_udp_hop_interval = str(udp_hop.get("interval", "30") or "30")
        tls = stream.get("tlsSettings")
        if not isinstance(tls, dict):
            raise ValueError("основной inbound: tlsSettings не найден")
        certificates = tls.get("certificates")
        if not isinstance(certificates, list) or not certificates or not isinstance(certificates[0], dict):
            raise ValueError("Hysteria 2: tlsSettings.certificates[0] не найден")
        server_name = str(tls.get("serverName") or server_name)
        tls_cert_path = str(certificates[0].get("certificateFile") or meta.get("tlsCertPath") or current["tls_cert_path"])
        tls_key_path = str(certificates[0].get("keyFile") or meta.get("tlsKeyPath") or current["tls_key_path"])
        managed_cert, managed_key = _managed_hysteria_tls_paths()
        if Path(tls_cert_path) == managed_cert:
            tls_cert_path = str(meta.get("tlsCertPath") or current["tls_cert_path"])
        if Path(tls_key_path) == managed_key:
            tls_key_path = str(meta.get("tlsKeyPath") or current["tls_key_path"])
    else:
        tls_cert_path = ""
        tls_key_path = ""

    inbound_listen = str(inbound.get("listen", "0.0.0.0"))
    inbound_port = int(inbound.get("port", 0) or 0)
    if profile in TLS_INBOUND_PROFILES:
        listen = str(current["listen"] or "0.0.0.0")
        transport_listen = inbound_listen
        transport_port = inbound_port
    elif profile in REALITY_INBOUND_PROFILES and _reality_edge_settings(current).get("enabled"):
        listen = str(current["listen"] or "0.0.0.0")
        transport_listen = str(meta.get("transportListen") or current["transport_listen"] or "127.0.0.1")
        transport_port = int(meta.get("transportPort") or current["transport_port"] or 8443)
        public_port = int(meta.get("publicPort") or current["port"] or 443)
    else:
        listen = inbound_listen
        transport_listen = str(meta.get("transportListen") or current["transport_listen"] or "127.0.0.1")
        transport_port = int(meta.get("transportPort") or current["transport_port"] or 8443)
        public_port = inbound_port

    default_cert, default_key = _default_tls_paths(address)
    if profile != "hysteria2_tls":
        tls_cert_path = str(meta.get("tlsCertPath") or current["tls_cert_path"] or default_cert)
        tls_key_path = str(meta.get("tlsKeyPath") or current["tls_key_path"] or default_key)
    else:
        tls_cert_path = tls_cert_path or default_cert
        tls_key_path = tls_key_path or default_key

    log = document.get("log")
    log = log if isinstance(log, dict) else {}
    api = document.get("api")
    api = api if isinstance(api, dict) else {}
    normalized_flow = "xtls-rprx-vision" if profile in VISION_INBOUND_PROFILES else ""
    values = {
        "address": address,
        "listen": listen,
        "port": public_port,
        "dest": dest,
        "server_name": server_name,
        "private_key": private_key,
        "public_key": public_key,
        "short_id": short_id,
        "fingerprint": fingerprint,
        "flow": normalized_flow,
        "loglevel": str(log.get("loglevel", current["loglevel"])),
        "api_listen": str(api.get("listen", current["api_listen"])),
        "stats_enabled": any(key in document for key in ("api", "stats", "policy")),
        "config_path": str(current["config_path"]),
        "xray_bin": str(current["xray_bin"]),
        "xray_service": str(current["xray_service"]),
        "inbound_profile": profile,
        "transport_listen": transport_listen,
        "transport_port": transport_port,
        "xhttp_path": xhttp_path,
        "xhttp_mode": xhttp_mode,
        "grpc_service_name": grpc_service_name,
        "tls_cert_path": tls_cert_path,
        "tls_key_path": tls_key_path,
        "hysteria_udp_idle_timeout": hysteria_udp_idle_timeout,
        "hysteria_masquerade_type": hysteria_masquerade_type,
        "hysteria_masquerade_url": hysteria_masquerade_url,
        "hysteria_masquerade_content": hysteria_masquerade_content,
        "hysteria_masquerade_status": hysteria_masquerade_status,
        "hysteria_masquerade_dir": hysteria_masquerade_dir,
        "hysteria_masquerade_rewrite_host": hysteria_masquerade_rewrite_host,
        "hysteria_masquerade_insecure": hysteria_masquerade_insecure,
        "hysteria_masquerade_headers": hysteria_masquerade_headers,
        "hysteria_performance_profile": hysteria_performance_profile,
        "hysteria_congestion": hysteria_congestion,
        "hysteria_bbr_profile": hysteria_bbr_profile,
        "hysteria_brutal_up": hysteria_brutal_up,
        "hysteria_brutal_down": hysteria_brutal_down,
        "hysteria_quic_debug": hysteria_quic_debug,
        "hysteria_max_idle_timeout": hysteria_max_idle_timeout,
        "hysteria_keepalive_period": hysteria_keepalive_period,
        "hysteria_disable_pmtud": hysteria_disable_pmtud,
        "hysteria_max_incoming_streams": hysteria_max_incoming_streams,
        "hysteria_udp_hop_ports": hysteria_udp_hop_ports,
        "hysteria_udp_hop_interval": hysteria_udp_hop_interval,
        "hysteria_init_stream_receive_window": hysteria_init_stream_receive_window,
        "hysteria_max_stream_receive_window": hysteria_max_stream_receive_window,
        "hysteria_init_connection_receive_window": hysteria_init_connection_receive_window,
        "hysteria_max_connection_receive_window": hysteria_max_connection_receive_window,
    }
    validate_server_values(
        str(values["address"]), int(values["port"]), str(values["dest"]),
        str(values["server_name"]), str(values["private_key"]),
        str(values["public_key"]), str(values["short_id"]),
        flow=str(values["flow"]), loglevel=str(values["loglevel"]),
        api_listen=str(values["api_listen"]),
        listen=str(values["listen"]),
        inbound_profile=str(values["inbound_profile"]),
        transport_listen=str(values["transport_listen"]),
        transport_port=int(values["transport_port"]),
        xhttp_path=str(values["xhttp_path"]),
        xhttp_mode=str(values["xhttp_mode"]),
        grpc_service_name=str(values["grpc_service_name"]),
        tls_cert_path=str(values["tls_cert_path"]),
        tls_key_path=str(values["tls_key_path"]),
        hysteria_udp_idle_timeout=int(values["hysteria_udp_idle_timeout"]),
        hysteria_masquerade_type=str(values["hysteria_masquerade_type"]),
        hysteria_masquerade_url=str(values["hysteria_masquerade_url"]),
        hysteria_masquerade_content=str(values["hysteria_masquerade_content"]),
        hysteria_masquerade_status=int(values["hysteria_masquerade_status"]),
        hysteria_masquerade_dir=str(values["hysteria_masquerade_dir"]),
        hysteria_masquerade_rewrite_host=bool(values["hysteria_masquerade_rewrite_host"]),
        hysteria_masquerade_insecure=bool(values["hysteria_masquerade_insecure"]),
        hysteria_masquerade_headers=str(values["hysteria_masquerade_headers"]),
        hysteria_performance_profile=str(values["hysteria_performance_profile"]),
        hysteria_congestion=str(values["hysteria_congestion"]),
        hysteria_bbr_profile=str(values["hysteria_bbr_profile"]),
        hysteria_brutal_up=str(values["hysteria_brutal_up"]),
        hysteria_brutal_down=str(values["hysteria_brutal_down"]),
        hysteria_quic_debug=bool(values["hysteria_quic_debug"]),
        hysteria_max_idle_timeout=int(values["hysteria_max_idle_timeout"]),
        hysteria_keepalive_period=int(values["hysteria_keepalive_period"]),
        hysteria_disable_pmtud=bool(values["hysteria_disable_pmtud"]),
        hysteria_max_incoming_streams=int(values["hysteria_max_incoming_streams"]),
        hysteria_udp_hop_ports=str(values["hysteria_udp_hop_ports"]),
        hysteria_udp_hop_interval=str(values["hysteria_udp_hop_interval"]),
        hysteria_init_stream_receive_window=int(values["hysteria_init_stream_receive_window"]),
        hysteria_max_stream_receive_window=int(values["hysteria_max_stream_receive_window"]),
        hysteria_init_connection_receive_window=int(values["hysteria_init_connection_receive_window"]),
        hysteria_max_connection_receive_window=int(values["hysteria_max_connection_receive_window"]),
    )
    sniffing = inbound.get("sniffing")
    sniffing = sniffing if isinstance(sniffing, dict) else {}
    overrides = sniffing.get("destOverride", [])
    overrides = overrides if isinstance(overrides, list) else []
    sniff = {
        "enabled": bool(sniffing.get("enabled", False)),
        "route_only": bool(sniffing.get("routeOnly", False)),
        "http": "http" in overrides,
        "tls": "tls" in overrides,
        "quic": "quic" in overrides,
    }
    return values, sniff


def _parse_full_dns(document: dict[str, object]) -> dict[str, object]:
    dns = document.get("dns")
    if dns is None:
        return {"enabled": False, "settings": None, "servers": [], "hosts": []}
    if not isinstance(dns, dict):
        raise ValueError("dns должен быть объектом")
    query_strategy = str(dns.get("queryStrategy", "UseIPv4"))
    if query_strategy not in ALLOWED_DNS_QUERY_STRATEGIES:
        raise ValueError("dns.queryStrategy содержит неподдерживаемое значение")
    extra = _copy_json_object(dns)
    for key in (
        "_sgPanel", "servers", "hosts", "queryStrategy", "disableCache",
        "disableFallback", "disableFallbackIfMatch", "enableParallelQuery",
        "useSystemHosts",
    ):
        extra.pop(key, None)
    values = dns.get("servers", [])
    if not isinstance(values, list) or not values:
        raise ValueError("dns.servers должен содержать хотя бы один сервер")
    servers: list[dict[str, object]] = []
    names: set[str] = set()
    for index, item in enumerate(values, start=1):
        if isinstance(item, str):
            raw: dict[str, object] = {"address": item}
        elif isinstance(item, dict):
            raw = item
        else:
            raise ValueError(f"dns.servers[{index}] должен быть строкой или объектом")
        meta = raw.get("_sgPanel")
        meta = meta if isinstance(meta, dict) else {}
        name = str(meta.get("name") or f"JSON DNS {index}")
        if name.casefold() in names:
            name = f"{name} {index}"
        names.add(name.casefold())
        def join_value(key: str) -> str:
            value = raw.get(key, [])
            if isinstance(value, list):
                return "\n".join(str(part) for part in value)
            return str(value or "")
        cleaned = validate_dns_server_values(
            name=name,
            address=str(raw.get("address", "")),
            priority=int(meta.get("priority", index * 10)),
            domains=join_value("domains"),
            expected_ips=join_value("expectedIPs"),
            unexpected_ips=join_value("unexpectedIPs"),
            query_strategy=str(raw.get("queryStrategy", "")),
            skip_fallback=bool(raw.get("skipFallback", False)),
            final_query=bool(raw.get("finalQuery", False)),
            timeout_ms=int(raw.get("timeoutMs", 4000)),
        )
        server_config = _strip_sgpanel_metadata(raw)
        if not isinstance(server_config, dict):
            raise ValueError(f"dns.servers[{index}] не удалось нормализовать")
        cleaned["config_json"] = json.dumps(
            server_config, ensure_ascii=False, separators=(",", ":")
        )
        servers.append(cleaned)
    hosts_value = dns.get("hosts", {})
    if not isinstance(hosts_value, dict):
        raise ValueError("dns.hosts должен быть объектом")
    hosts: list[tuple[str, str]] = []
    for domain, target in hosts_value.items():
        addresses = target if isinstance(target, list) else [target]
        clean_domain, clean_addresses = _validate_dns_host(
            str(domain), "\n".join(str(item) for item in addresses)
        )
        hosts.append((clean_domain, clean_addresses))
    return {
        "enabled": True,
        "settings": {
            "query_strategy": query_strategy,
            "disable_cache": bool(dns.get("disableCache", False)),
            "disable_fallback": bool(dns.get("disableFallback", False)),
            "disable_fallback_if_match": bool(dns.get("disableFallbackIfMatch", False)),
            "enable_parallel_query": bool(dns.get("enableParallelQuery", False)),
            "use_system_hosts": bool(dns.get("useSystemHosts", True)),
        },
        "servers": servers,
        "hosts": hosts,
        "extra_json": json.dumps(extra, ensure_ascii=False, separators=(",", ":")),
    }


def _sync_full_config_users(users: list[dict[str, object]]) -> None:
    names = {str(item["name"]).casefold() for item in users}
    with connect() as con:
        existing = con.execute("SELECT * FROM users ORDER BY id").fetchall()
        by_name = {str(row["name"]).casefold(): row for row in existing}
        by_uuid = {str(row["uuid"]): row for row in existing}
        for row in existing:
            if str(row["name"]).casefold() not in names and row["enabled"]:
                con.execute(
                    "UPDATE users SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (row["id"],),
                )
        for item in users:
            row = by_name.get(str(item["name"]).casefold()) or by_uuid.get(str(item["uuid"]))
            if row is None:
                con.execute(
                    """
                    INSERT INTO users
                        (name, uuid, enabled, comment, expiry_at, subscription_enabled,
                         subscription_token)
                    VALUES (?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        item["name"], item["uuid"], item["comment"], item["expiry_at"],
                        int(item["subscription_enabled"]), secrets.token_urlsafe(32),
                    ),
                )
            else:
                con.execute(
                    """
                    UPDATE users SET name = ?, uuid = ?, enabled = 1, comment = ?, expiry_at = ?,
                        subscription_enabled = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        item["name"], item["uuid"], item["comment"], item["expiry_at"],
                        int(item["subscription_enabled"]), row["id"],
                    ),
                )


def _replace_full_config_outbounds(
    parsed: list[tuple[dict[str, object], dict[str, object], bool]]
) -> None:
    with connect() as con:
        existing = {
            str(row["tag"]): row
            for row in con.execute("SELECT * FROM outbounds ORDER BY id").fetchall()
        }
        con.execute("UPDATE outbounds SET enabled = 0, updated_at = CURRENT_TIMESTAMP")
        for cleaned, config, enabled in parsed:
            values = (
                cleaned["name"], int(enabled), cleaned["address"], cleaned["port"],
                cleaned["uuid"], cleaned["flow"], cleaned["network"], cleaned["security"],
                cleaned["server_name"], cleaned["public_key"], cleaned["short_id"],
                cleaned["fingerprint"], cleaned["spider_x"], cleaned["xhttp_host"],
                cleaned["xhttp_path"], cleaned["xhttp_mode"], cleaned["allow_insecure"],
                cleaned["alpn"], json.dumps(config, ensure_ascii=False, separators=(",", ":")),
            )
            row = existing.get(str(cleaned["tag"]))
            if row is not None:
                con.execute(
                    """
                    UPDATE outbounds SET name=?, enabled=?, address=?, port=?, uuid=?, flow=?,
                        network=?, security=?, server_name=?, public_key=?, short_id=?,
                        fingerprint=?, spider_x=?, xhttp_host=?, xhttp_path=?, xhttp_mode=?,
                        allow_insecure=?, alpn=?, config_json=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (*values, row["id"]),
                )
            else:
                con.execute(
                    """
                    INSERT INTO outbounds (
                        tag, name, type, enabled, address, port, uuid, flow,
                        network, security, server_name, public_key, short_id,
                        fingerprint, spider_x, xhttp_host, xhttp_path, xhttp_mode,
                        allow_insecure, alpn, config_json
                    ) VALUES (?, ?, 'vless_reality', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (cleaned["tag"], *values),
                )


def _replace_full_config_dns(parsed: dict[str, object]) -> None:
    with connect() as con:
        settings = parsed.get("settings")
        if not parsed["enabled"]:
            con.execute(
                "UPDATE dns_settings SET enabled = 0, extra_json = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                (str(parsed.get("extra_json", "{}")),),
            )
            return
        assert isinstance(settings, dict)
        con.execute(
            """
            UPDATE dns_settings SET enabled = 1, query_strategy = ?, disable_cache = ?,
                disable_fallback = ?, disable_fallback_if_match = ?,
                enable_parallel_query = ?, use_system_hosts = ?, extra_json = ?,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (
                settings["query_strategy"], int(settings["disable_cache"]),
                int(settings["disable_fallback"]),
                int(settings["disable_fallback_if_match"]),
                int(settings["enable_parallel_query"]), int(settings["use_system_hosts"]),
                str(parsed.get("extra_json", "{}")),
            ),
        )
        con.execute("UPDATE dns_servers SET enabled = 0, updated_at = CURRENT_TIMESTAMP")
        for item in parsed["servers"]:
            row = con.execute(
                "SELECT id FROM dns_servers WHERE name = ? COLLATE NOCASE", (item["name"],)
            ).fetchone()
            values = (
                item["address"], item["priority"], item["domains"], item["expected_ips"],
                item["unexpected_ips"], item["query_strategy"], int(item["skip_fallback"]),
                int(item["final_query"]), item["timeout_ms"], item["config_json"],
            )
            if row:
                con.execute(
                    """
                    UPDATE dns_servers SET address=?, priority=?, enabled=1, domains=?,
                        expected_ips=?, unexpected_ips=?, query_strategy=?, skip_fallback=?,
                        final_query=?, timeout_ms=?, config_json=?,
                        updated_at=CURRENT_TIMESTAMP WHERE id=?
                    """,
                    (*values, row["id"]),
                )
            else:
                con.execute(
                    """
                    INSERT INTO dns_servers
                        (name,address,priority,enabled,domains,expected_ips,unexpected_ips,
                         query_strategy,skip_fallback,final_query,timeout_ms,config_json)
                    VALUES (?,?,?,1,?,?,?,?,?,?,?,?)
                    """,
                    (item["name"], *values),
                )
        con.execute("UPDATE dns_hosts SET enabled = 0, updated_at = CURRENT_TIMESTAMP")
        for domain, addresses in parsed["hosts"]:
            row = con.execute(
                "SELECT id FROM dns_hosts WHERE domain = ? COLLATE NOCASE", (domain,)
            ).fetchone()
            if row:
                con.execute(
                    "UPDATE dns_hosts SET addresses=?,enabled=1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (addresses, row["id"]),
                )
            else:
                con.execute(
                    "INSERT INTO dns_hosts (domain,addresses,enabled) VALUES (?,?,1)",
                    (domain, addresses),
                )


def update_config_json_document(text: str) -> dict[str, object]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON: строка {exc.lineno}, столбец {exc.colno}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ValueError("config.json должен быть объектом")
    document = _copy_json_object(document)
    top_meta = document.get("_sgPanel")
    top_meta = top_meta if isinstance(top_meta, dict) else {}
    inbound = _find_tagged_item(document.get("inbounds"), "vless-reality-in")
    if inbound is None:
        raise ValueError("не найден управляемый inbound с tag vless-reality-in")
    users, flow = _parse_full_config_users(inbound)
    server_values, sniff = _parse_full_config_server(document, inbound, flow)

    outbounds_value = document.get("outbounds")
    if not isinstance(outbounds_value, list):
        raise ValueError("outbounds должен быть массивом")
    seen_tags: set[str] = set()
    parsed_outbounds: list[tuple[dict[str, object], dict[str, object], bool]] = []
    for index, item in enumerate(outbounds_value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"outbounds[{index}] должен быть объектом")
        tag = str(item.get("tag", "")).strip()
        if not tag or not OUTBOUND_TAG_RE.fullmatch(tag):
            raise ValueError(f"outbounds[{index}]: некорректный tag")
        if tag in seen_tags:
            raise ValueError(f"повторяющийся outbound tag: {tag}")
        seen_tags.add(tag)
        if tag in {"direct", "blocked"}:
            continue
        if str(item.get("protocol", "")).lower() != "vless":
            continue
        stream = item.get("streamSettings")
        stream = stream if isinstance(stream, dict) else {}
        network = str(stream.get("network", "raw")).lower()
        if network == "tcp":
            network = "raw"
        security = str(stream.get("security", "reality")).lower()
        if (network, security) not in SUPPORTED_VLESS_OUTBOUND_COMBINATIONS:
            # VLESS combinations unknown to the GUI remain JSON-only in the base document.
            continue
        candidate = _copy_json_object(item)
        candidate.setdefault("_sgPanel", {"name": tag, "enabled": True})
        parsed_outbounds.append(
            parse_outbound_json_document(json.dumps(candidate, ensure_ascii=False), fallback_name=tag)
        )

    default_tag = str(top_meta.get("defaultOutboundTag") or "")
    if not default_tag:
        routing_value = document.get("routing")
        if isinstance(routing_value, dict) and isinstance(routing_value.get("_sgPanel"), dict):
            default_tag = str(routing_value["_sgPanel"].get("defaultOutboundTag", ""))
    if not default_tag and outbounds_value:
        default_tag = str(outbounds_value[0].get("tag", "direct"))
    if not default_tag:
        default_tag = "direct"

    routing_value = document.get("routing", {})
    if not isinstance(routing_value, dict):
        raise ValueError("routing должен быть объектом")
    routing_document = _copy_json_object(routing_value)
    routing_meta = routing_document.get("_sgPanel")
    routing_meta = routing_meta if isinstance(routing_meta, dict) else {}
    routing_meta["defaultOutboundTag"] = default_tag
    routing_document["_sgPanel"] = routing_meta
    dns_parsed = _parse_full_dns(document)

    sanitized = _strip_sgpanel_metadata(document)
    if not isinstance(sanitized, dict):
        raise ValueError("не удалось подготовить config.json")
    server = get_server()
    with tempfile.NamedTemporaryFile(prefix="sg-panel-json-", suffix=".json", mode="w", delete=False) as handle:
        json.dump(sanitized, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    try:
        test = run_xray_test(str(server["xray_bin"]), Path(temp_name))
    finally:
        Path(temp_name).unlink(missing_ok=True)
    if test.returncode != 0:
        detail = (test.stderr or test.stdout).strip()
        raise XPanelError("JSON не прошёл xray run -test:\n" + (detail or "неизвестная ошибка"))

    database = db_path()
    backup = database.with_name(database.name + ".before-json")
    if database.exists():
        shutil.copy2(database, backup)
    try:
        with connect() as con:
            _set_config_base_document(con, sanitized)
        update_server_settings(**server_values)
        _sync_full_config_users(users)
        _replace_full_config_outbounds(parsed_outbounds)
        _replace_full_config_dns(dns_parsed)
        update_routing_json_document(json.dumps(routing_document, ensure_ascii=False))
        with connect() as con:
            con.execute(
                """
                UPDATE routing_settings SET sniffing_enabled=?, sniffing_route_only=?,
                    sniff_http=?, sniff_tls=?, sniff_quic=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=1
                """,
                (
                    int(sniff["enabled"]), int(sniff["route_only"]), int(sniff["http"]),
                    int(sniff["tls"]), int(sniff["quic"]),
                ),
            )
        validation = validate_generated_config()
        if not validation["ok"]:
            raise XPanelError("синхронизированный config.json не прошёл проверку:\n" + str(validation["detail"]))
    except sqlite3.IntegrityError as exc:
        if backup.exists():
            shutil.copy2(backup, database)
        raise XPanelError("JSON конфликтует с существующими уникальными данными панели") from exc
    except Exception:
        if backup.exists():
            shutil.copy2(backup, database)
        raise
    finally:
        backup.unlink(missing_ok=True)
    return {
        "users": len(users),
        "outbounds": len(seen_tags),
        "managed_outbounds": len(parsed_outbounds),
        "rules": len(list_routing_rules()),
        "dns_servers": len(dns_parsed["servers"]),
    }


def render_text() -> tuple[str, sqlite3.Row, list[sqlite3.Row]]:
    config, server, users = build_config()
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n", server, users


def _xray_service_identity(service_name: str) -> tuple[int, int]:
    """Return the uid/gid used by the Xray systemd service.

    The official installer commonly uses the special user ``nobody``.  The
    panel runs as root and places a private managed certificate copy in a
    directory readable only by that service identity.
    """
    user_result = _run(
        ["systemctl", "show", service_name, "--property=User", "--value"],
        timeout=3,
    )
    group_result = _run(
        ["systemctl", "show", service_name, "--property=Group", "--value"],
        timeout=3,
    )
    user_name = (user_result.stdout or "").strip() if user_result.returncode == 0 else ""
    group_name = (group_result.stdout or "").strip() if group_result.returncode == 0 else ""
    user_name = user_name or "root"
    try:
        user_entry = pwd.getpwnam(user_name)
    except KeyError as exc:
        raise XPanelError(f"не найден системный пользователь службы Xray: {user_name}") from exc
    if group_name:
        try:
            group_entry = grp.getgrnam(group_name)
        except KeyError as exc:
            raise XPanelError(f"не найдена системная группа службы Xray: {group_name}") from exc
        gid = group_entry.gr_gid
    else:
        gid = user_entry.pw_gid
    return user_entry.pw_uid, gid


def _managed_hysteria_tls_paths() -> tuple[Path, Path]:
    directory = Path(os.environ.get("XPANEL_HYSTERIA_TLS_DIR", str(HYSTERIA_TLS_DIR)))
    return directory / "fullchain.pem", directory / "privkey.pem"


def _copy_tls_file_atomic(source: Path, destination: Path, gid: int) -> None:
    if not source.is_file():
        raise XPanelError(f"TLS-файл не найден: {source}")
    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise XPanelError(f"не удалось прочитать TLS-файл {source}: {exc}") from exc
    if not payload:
        raise XPanelError(f"TLS-файл пуст: {source}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temp_path, 0, gid)
        os.chmod(temp_path, 0o640)
        os.replace(temp_path, destination)
    finally:
        temp_path.unlink(missing_ok=True)


def _snapshot_hysteria_tls_material() -> dict[str, object]:
    cert_path, key_path = _managed_hysteria_tls_paths()
    directory = cert_path.parent
    files: dict[str, object] = {}
    for path in (cert_path, key_path):
        if path.exists():
            stat = path.stat()
            files[path.name] = {
                "data": path.read_bytes(),
                "mode": stat.st_mode & 0o777,
                "uid": stat.st_uid,
                "gid": stat.st_gid,
            }
    return {
        "directory_existed": directory.exists(),
        "directory_mode": (directory.stat().st_mode & 0o777) if directory.exists() else None,
        "directory_uid": directory.stat().st_uid if directory.exists() else None,
        "directory_gid": directory.stat().st_gid if directory.exists() else None,
        "files": files,
    }


def _restore_hysteria_tls_material(snapshot: dict[str, object]) -> None:
    cert_path, key_path = _managed_hysteria_tls_paths()
    directory = cert_path.parent
    files = snapshot.get("files") if isinstance(snapshot.get("files"), dict) else {}
    if files or snapshot.get("directory_existed"):
        directory.mkdir(parents=True, exist_ok=True)
        directory_mode = snapshot.get("directory_mode")
        directory_uid = snapshot.get("directory_uid")
        directory_gid = snapshot.get("directory_gid")
        if isinstance(directory_uid, int) and isinstance(directory_gid, int):
            os.chown(directory, directory_uid, directory_gid)
        if isinstance(directory_mode, int):
            os.chmod(directory, directory_mode)
    for path in (cert_path, key_path):
        item = files.get(path.name) if isinstance(files, dict) else None
        if isinstance(item, dict):
            path.write_bytes(bytes(item.get("data", b"")))
            uid = item.get("uid")
            gid = item.get("gid")
            mode = item.get("mode")
            if isinstance(uid, int) and isinstance(gid, int):
                os.chown(path, uid, gid)
            if isinstance(mode, int):
                os.chmod(path, mode)
        else:
            path.unlink(missing_ok=True)
    if not snapshot.get("directory_existed") and directory.exists():
        try:
            directory.rmdir()
        except OSError:
            pass


def _sync_hysteria_tls_material(server: sqlite3.Row) -> tuple[Path, Path]:
    try:
        inbound_profile = str(server["inbound_profile"] or "")
    except (KeyError, IndexError):
        inbound_profile = ""
    if inbound_profile == RUSSIA_KIT_PROFILE:
        edge = _russia_kit_edge(server)
        source_cert = Path(str(edge["cert"]))
        source_key = Path(str(edge["key"]))
    else:
        source_cert = Path(str(server["tls_cert_path"]))
        source_key = Path(str(server["tls_key_path"]))
    _uid, gid = _xray_service_identity(str(server["xray_service"]))
    cert_path, key_path = _managed_hysteria_tls_paths()
    directory = cert_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    os.chown(directory, 0, gid)
    os.chmod(directory, 0o750)
    _copy_tls_file_atomic(source_cert, cert_path, gid)
    _copy_tls_file_atomic(source_key, key_path, gid)
    return cert_path, key_path


def _runtime_hysteria_config_text(text: str, cert_path: Path, key_path: Path) -> str:
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise XPanelError(f"не удалось подготовить runtime-конфигурацию Hysteria 2: {exc}") from exc
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise XPanelError("не найден массив Hysteria 2 inbound")
    updated = 0
    for inbound in inbounds:
        if not isinstance(inbound, dict) or str(inbound.get("protocol", "")).lower() != "hysteria":
            continue
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict):
            raise XPanelError("у Hysteria 2 отсутствует streamSettings")
        tls = stream.get("tlsSettings")
        if not isinstance(tls, dict):
            raise XPanelError("у Hysteria 2 отсутствует tlsSettings")
        certificates = tls.get("certificates")
        if not isinstance(certificates, list) or not certificates or not isinstance(certificates[0], dict):
            raise XPanelError("у Hysteria 2 отсутствует TLS-сертификат")
        certificates[0]["certificateFile"] = str(cert_path)
        certificates[0]["keyFile"] = str(key_path)
        updated += 1
    if not updated:
        raise XPanelError("не найден управляемый Hysteria 2 inbound")
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"


def sync_hysteria_tls_material(*, restart: bool = False) -> dict[str, object]:
    require_root()
    server = get_server()
    if str(server["inbound_profile"] or "") not in HYSTERIA_ACTIVE_PROFILES:
        return {"active": False, "restarted": False}
    snapshot = _snapshot_hysteria_tls_material()
    try:
        cert_path, key_path = _sync_hysteria_tls_material(server)
        if restart:
            result = _run(["systemctl", "restart", str(server["xray_service"])], timeout=30)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()
                raise XPanelError(f"Xray не перезапустился после обновления TLS: {detail}")
            if _run(["systemctl", "is-active", "--quiet", str(server["xray_service"])]).returncode != 0:
                raise XPanelError("Xray не активен после обновления TLS")
        return {
            "active": True,
            "restarted": restart,
            "certificate": str(cert_path),
            "private_key": str(key_path),
        }
    except Exception:
        _restore_hysteria_tls_material(snapshot)
        if restart:
            _run(["systemctl", "restart", str(server["xray_service"])], timeout=30)
        raise


def run_xray_test(xray_bin: str, config_path: Path) -> subprocess.CompletedProcess[str]:
    return _run([xray_bin, "run", "-test", "-config", str(config_path)], timeout=30)


def validate_generated_config() -> dict[str, object]:
    text, server, users = render_text()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="sg-panel-", encoding="utf-8", delete=False
    ) as fh:
        fh.write(text)
        path = Path(fh.name)
    try:
        result = run_xray_test(server["xray_bin"], path)
        detail = (result.stderr or result.stdout).strip()
        return {
            "ok": result.returncode == 0,
            "detail": detail,
            "users": len(users),
            "json": text,
        }
    finally:
        path.unlink(missing_ok=True)


def _nginx_transport_paths() -> tuple[Path, Path]:
    available = Path(os.environ.get(
        "XPANEL_NGINX_TRANSPORT_CONF",
        "/etc/nginx/sites-available/sg-panel-xray-transport",
    ))
    enabled = Path(os.environ.get(
        "XPANEL_NGINX_TRANSPORT_LINK",
        "/etc/nginx/sites-enabled/sg-panel-xray-transport",
    ))
    return available, enabled


def _nginx_reality_edge_paths() -> tuple[Path, Path, Path]:
    stream_conf = Path(os.environ.get(
        "XPANEL_NGINX_REALITY_STREAM_CONF",
        "/etc/nginx/modules-enabled/90-sg-panel-reality-edge.conf",
    ))
    available = Path(os.environ.get(
        "XPANEL_NGINX_REALITY_WEB_CONF",
        "/etc/nginx/sites-available/sg-panel-reality-placeholder",
    ))
    enabled = Path(os.environ.get(
        "XPANEL_NGINX_REALITY_WEB_LINK",
        "/etc/nginx/sites-enabled/sg-panel-reality-placeholder",
    ))
    return stream_conf, available, enabled


def _nginx_placeholder_block() -> str:
    return '''    location = / {
        root /var/www/sg-panel-placeholder;
        try_files /index.html =404;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;
    }

    location = /index.html {
        root /var/www/sg-panel-placeholder;
        try_files /index.html =404;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;
    }

    location / {
        return 404;
    }'''


def _nginx_transport_config(server: sqlite3.Row) -> str:
    profile = str(server["inbound_profile"])
    if profile not in CERTIFICATE_INBOUND_PROFILES:
        raise ValueError("Nginx transport нужен только для TLS-профиля")
    cert = Path(str(server["tls_cert_path"]))
    key = Path(str(server["tls_key_path"]))
    if not cert.is_file():
        raise XPanelError(f"не найден TLS-сертификат: {cert}")
    if not key.is_file():
        raise XPanelError(f"не найден TLS private key: {key}")
    public_port = int(server["port"])
    placeholder = _nginx_placeholder_block()
    proxy_block = ""
    http2 = ""
    if profile in TLS_INBOUND_PROFILES:
        http2 = " http2"
        if profile in XHTTP_ACTIVE_PROFILES:
            instances = [row for row in list_xhttp_inbounds() if bool(row["enabled"])]
            if not instances or int(instances[0]["id"]) != 1:
                raise XPanelError("Основной XHTTP Inbound должен быть включён")
            blocks: list[str] = []
            for instance in instances:
                target_host = str(instance["listen"])
                if ":" in target_host and not target_host.startswith("["):
                    target_host = f"[{target_host}]"
                target = f"{target_host}:{int(instance['port'])}"
                path = str(instance["path"]).rstrip("/") + "/"
                blocks.append(
                    f"    # {instance['name']} · {instance['tag']}\n"
                    f"    location {path} {{\n"
                    "        grpc_socket_keepalive on;\n"
                    "        grpc_read_timeout 1h;\n"
                    "        grpc_send_timeout 1h;\n"
                    "        client_body_timeout 1h;\n"
                    "        send_timeout 1h;\n"
                    "        client_max_body_size 100m;\n"
                    "        chunked_transfer_encoding on;\n"
                    "        grpc_set_header Host $host;\n"
                    "        grpc_set_header X-Real-IP $remote_addr;\n"
                    "        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                    "        grpc_set_header X-Forwarded-Proto $scheme;\n"
                    f"        grpc_pass grpc://{target};\n"
                    "    }\n\n"
                )
            proxy_block = "".join(blocks)
        else:
            target_host = str(server["transport_listen"])
            if ":" in target_host and not target_host.startswith("["):
                target_host = f"[{target_host}]"
            target = f"{target_host}:{server['transport_port']}"
            service = str(server["grpc_service_name"]).strip("/")
            proxy_block = (
                f"    location /{service} {{\n"
                "        grpc_socket_keepalive on;\n"
                "        grpc_read_timeout 1h;\n"
                "        grpc_send_timeout 1h;\n"
                "        grpc_set_header Host $host;\n"
                "        grpc_set_header X-Real-IP $remote_addr;\n"
                "        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                "        grpc_set_header X-Forwarded-Proto $scheme;\n"
                f"        grpc_pass grpc://{target};\n"
                "    }\n\n"
            )
    return f"""# Managed by SG-Panel. Manual changes may be overwritten.
server {{
    listen {public_port} ssl{http2};
    listen [::]:{public_port} ssl{http2};
    server_name {server['server_name']};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SGXRAY:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

{proxy_block}{placeholder}
}}
"""


def _nginx_reality_edge_configs(server: sqlite3.Row) -> tuple[str, str]:
    edge = _reality_edge_settings(server)
    if not edge.get("enabled"):
        raise XPanelError(
            "HTTPS fallback для REALITY не готов: настройте собственный домен и HTTPS панели"
        )
    domain = str(edge["domain"])
    reality_name = str(edge["reality_name"])
    cert = str(edge["cert"])
    key = str(edge["key"])
    xray_port = int(edge["xray_port"])
    web_port = int(edge["web_port"])
    instances = [row for row in list_reality_inbounds() if bool(row["enabled"])]
    vision_multi = (
        str(server["inbound_profile"] or "") == "raw_reality"
        and str(server["flow"] or "") == "xtls-rprx-vision"
        and len(instances) > 1
    )
    extra_servers = ""
    if vision_multi:
        for instance in instances[1:]:
            public_port = int(instance["port"])
            public_listen = str(instance["listen"] or "0.0.0.0").strip()
            if public_listen in {"0.0.0.0", "::"}:
                listen_directives = (
                    f"        listen {public_port};\n"
                    f"        listen [::]:{public_port};\n"
                )
            elif ":" in public_listen:
                listen_directives = f"        listen [{public_listen}]:{public_port};\n"
            else:
                listen_directives = f"        listen {public_listen}:{public_port};\n"
            safe_name = str(instance["name"]).replace("\r", " ").replace("\n", " ")
            extra_servers += (
                f"\n    # {safe_name} · public REALITY Vision entry point\n"
                "    server {\n"
                f"{listen_directives}"
                f"        proxy_pass 127.0.0.1:{xray_port};\n"
                "        proxy_connect_timeout 5s;\n"
                "        proxy_timeout 1h;\n"
                "    }\n"
            )
    stream = f'''# Managed by SG-Panel. Top-level Nginx stream router for REALITY TCP entry points.
stream {{
    map $ssl_preread_server_name $sg_panel_443_backend {{
        hostnames;
        {reality_name} 127.0.0.1:{xray_port};
        default 127.0.0.1:{web_port};
    }}

    server {{
        listen 443;
        listen [::]:443;
        proxy_pass $sg_panel_443_backend;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
    }}
{extra_servers}}}
'''
    placeholder = _nginx_placeholder_block()
    kit_proxy = ""
    if str(server["inbound_profile"] or "") == RUSSIA_KIT_PROFILE:
        xhttp_path = RUSSIA_KIT_XHTTP_TLS_PATH.rstrip("/") + "/"
        ws_path = RUSSIA_KIT_WS_PATH.rstrip("/") or "/"
        kit_proxy = f'''    # Ready set: XHTTP over the own TLS domain
    location {xhttp_path} {{
        grpc_socket_keepalive on;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        client_body_timeout 1h;
        send_timeout 1h;
        client_max_body_size 100m;
        chunked_transfer_encoding on;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto $scheme;
        grpc_pass grpc://127.0.0.1:{RUSSIA_KIT_XHTTP_TLS_PORT};
    }}

    # Ready set: WebSocket over the own TLS domain
    location = {ws_path} {{
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_pass http://127.0.0.1:{RUSSIA_KIT_WS_PORT};
    }}

'''
    web = f'''# Managed by SG-Panel. Local HTTPS placeholder behind the TCP 443 router.
server {{
    listen 127.0.0.1:{web_port} ssl;
    server_name {domain};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SGFALLBACK:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

{kit_proxy}{placeholder}
}}
'''
    return stream, web


def _nginx_test_reload() -> None:
    if shutil.which("nginx") is None:
        raise XPanelError("Nginx не установлен")
    test = _run(["nginx", "-t"], timeout=30)
    if test.returncode != 0:
        raise XPanelError((test.stderr or test.stdout).strip() or "nginx -t завершился с ошибкой")
    reload_result = _run(["systemctl", "reload", "nginx"], timeout=30)
    if reload_result.returncode != 0:
        raise XPanelError(
            (reload_result.stderr or reload_result.stdout).strip()
            or "не удалось перезагрузить Nginx"
        )
    if _run(["systemctl", "is-active", "--quiet", "nginx"]).returncode != 0:
        raise XPanelError("после reload служба Nginx не активна")


def _write_atomic_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(text, encoding="utf-8")
    os.chmod(temp, mode)
    os.replace(temp, path)


def _enable_nginx_transport(server: sqlite3.Row) -> None:
    available, enabled = _nginx_transport_paths()
    _write_atomic_text(available, _nginx_transport_config(server))
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.unlink(missing_ok=True)
    enabled.symlink_to(available)
    _nginx_test_reload()


def _disable_nginx_transport(*, reload: bool = True) -> bool:
    _available, enabled = _nginx_transport_paths()
    if not enabled.exists() and not enabled.is_symlink():
        return False
    enabled.unlink(missing_ok=True)
    if reload:
        _nginx_test_reload()
    return True


def _enable_reality_edge(server: sqlite3.Row) -> None:
    stream_text, web_text = _nginx_reality_edge_configs(server)
    stream_conf, available, enabled = _nginx_reality_edge_paths()
    module_dir = Path("/etc/nginx/modules-enabled")
    if not module_dir.is_dir() or not any(module_dir.glob("*mod-stream*.conf")):
        raise XPanelError("не установлен модуль Nginx stream: установите libnginx-mod-stream")
    _write_atomic_text(stream_conf, stream_text)
    _write_atomic_text(available, web_text)
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.unlink(missing_ok=True)
    enabled.symlink_to(available)
    _nginx_test_reload()


def _disable_reality_edge(*, reload: bool = True) -> bool:
    stream_conf, _available, enabled = _nginx_reality_edge_paths()
    changed = False
    if enabled.exists() or enabled.is_symlink():
        enabled.unlink(missing_ok=True)
        changed = True
    if stream_conf.exists():
        stream_conf.unlink(missing_ok=True)
        changed = True
    if changed and reload:
        _nginx_test_reload()
    return changed


def _snapshot_path(path: Path) -> dict[str, object]:
    return {
        "exists": path.exists(),
        "is_symlink": path.is_symlink(),
        "target": os.readlink(path) if path.is_symlink() else "",
        "text": path.read_text(encoding="utf-8") if path.exists() and not path.is_symlink() else "",
    }


def _restore_path_snapshot(path: Path, snapshot: dict[str, object]) -> None:
    path.unlink(missing_ok=True)
    if not snapshot.get("exists") and not snapshot.get("is_symlink"):
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if snapshot.get("is_symlink"):
        path.symlink_to(str(snapshot.get("target", "")))
    else:
        path.write_text(str(snapshot.get("text", "")), encoding="utf-8")
        os.chmod(path, 0o644)


def _snapshot_nginx_frontends() -> dict[str, object]:
    transport_available, transport_enabled = _nginx_transport_paths()
    stream_conf, edge_available, edge_enabled = _nginx_reality_edge_paths()
    paths = [transport_available, transport_enabled, stream_conf, edge_available, edge_enabled]
    return {str(path): _snapshot_path(path) for path in paths}


def _restore_nginx_frontends(snapshot: dict[str, object]) -> None:
    transport_available, transport_enabled = _nginx_transport_paths()
    stream_conf, edge_available, edge_enabled = _nginx_reality_edge_paths()
    for path in (transport_enabled, stream_conf, edge_enabled):
        path.unlink(missing_ok=True)
    for path in (transport_available, transport_enabled, stream_conf, edge_available, edge_enabled):
        _restore_path_snapshot(path, dict(snapshot.get(str(path), {})))
    if shutil.which("nginx") is not None:
        _nginx_test_reload()


def _prepare_nginx_frontend() -> None:
    changed = _disable_nginx_transport(reload=False)
    changed = _disable_reality_edge(reload=False) or changed
    if changed:
        _nginx_test_reload()


def _activate_nginx_frontend(server: sqlite3.Row) -> str:
    profile = str(server["inbound_profile"] or "raw_reality")
    if profile == RUSSIA_KIT_PROFILE:
        _enable_reality_edge(server)
        return "russia-kit-sni-edge"
    if profile in CERTIFICATE_INBOUND_PROFILES:
        _enable_nginx_transport(server)
        return "tls-placeholder" if profile == "hysteria2_tls" else "tls-transport"
    if profile in REALITY_INBOUND_PROFILES and _reality_edge_settings(server).get("enabled"):
        _enable_reality_edge(server)
        return "reality-sni-edge"
    return "direct"

def apply_config() -> dict[str, object]:
    require_root()
    text, server, users = render_text()
    config_path = Path(server["config_path"])
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_name = tempfile.mkstemp(
        prefix=".config.", suffix=".json", dir=str(config_path.parent), text=True
    )
    temp_path = Path(temp_name)
    backup_path: Path | None = None
    nginx_snapshot = _snapshot_nginx_frontends()
    previous_config: bytes | None = config_path.read_bytes() if config_path.exists() else None
    profile = str(server["inbound_profile"] or "raw_reality")
    hysteria_tls_snapshot = _snapshot_hysteria_tls_material() if profile in HYSTERIA_ACTIVE_PROFILES else None
    try:
        if profile in HYSTERIA_ACTIVE_PROFILES:
            runtime_cert, runtime_key = _sync_hysteria_tls_material(server)
            text = _runtime_hysteria_config_text(text, runtime_cert, runtime_key)
        temp_handle = os.fdopen(temp_fd, "w", encoding="utf-8")
        temp_fd = -1
        with temp_handle as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_path, 0o644)
        test = run_xray_test(server["xray_bin"], temp_path)
        if test.returncode != 0:
            detail = (test.stderr or test.stdout).strip()
            raise XPanelError(f"новый config.json не прошёл xray run -test:\n{detail}")

        if profile == RUSSIA_KIT_PROFILE:
            _nginx_reality_edge_configs(server)
        elif profile in CERTIFICATE_INBOUND_PROFILES:
            _nginx_transport_config(server)
        elif profile in REALITY_INBOUND_PROFILES and _reality_edge_settings(server).get("enabled"):
            _nginx_reality_edge_configs(server)
        if config_path.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            backup_path = config_path.with_name(f"{config_path.name}.bak-{stamp}")
            shutil.copy2(config_path, backup_path)

        _prepare_nginx_frontend()

        os.replace(temp_path, config_path)
        restart = _run(["systemctl", "restart", server["xray_service"]], timeout=30)
        if restart.returncode != 0:
            detail = (restart.stderr or restart.stdout).strip()
            raise XPanelError(f"Xray не перезапустился: {detail}")
        if _run(["systemctl", "is-active", "--quiet", server["xray_service"]]).returncode != 0:
            raise XPanelError("после перезапуска служба Xray не активна")

        frontend = _activate_nginx_frontend(server)

        return {
            "config_path": str(config_path),
            "backup_path": str(backup_path) if backup_path else None,
            "enabled_users": len(users),
            "enabled_rules": len([r for r in list_routing_rules() if r["enabled"]]),
            "service": "active",
            "profile": profile,
            "nginx_transport": profile in TLS_INBOUND_PROFILES,
            "nginx_frontend": frontend,
        }
    except Exception:
        try:
            if previous_config is None:
                config_path.unlink(missing_ok=True)
            else:
                config_path.write_bytes(previous_config)
                os.chmod(config_path, 0o644)
            _disable_nginx_transport(reload=False)
            _disable_reality_edge(reload=False)
            if shutil.which("nginx") is not None:
                _nginx_test_reload()
            if hysteria_tls_snapshot is not None:
                _restore_hysteria_tls_material(hysteria_tls_snapshot)
            _run(["systemctl", "restart", server["xray_service"]], timeout=30)
            _restore_nginx_frontends(nginx_snapshot)
        except Exception:
            pass
        raise
    finally:
        if temp_fd >= 0:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        temp_path.unlink(missing_ok=True)


def restart_xray() -> str:
    require_root()
    server = get_server()
    proc = _run(["systemctl", "restart", server["xray_service"]], timeout=30)
    if proc.returncode != 0:
        raise XPanelError((proc.stderr or proc.stdout).strip() or "ошибка restart")
    state = _run(["systemctl", "is-active", server["xray_service"]])
    result = (state.stdout or state.stderr).strip() or "unknown"
    if result != "active":
        raise XPanelError(f"служба после restart имеет состояние: {result}")
    return result


def _parse_stats_output(text: str) -> dict[str, int]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    result: dict[str, int] = {}
    for item in payload.get("stat", []):
        name = str(item.get("name", ""))
        try:
            value = int(item.get("value", 0))
        except (TypeError, ValueError):
            value = 0
        if name:
            result[name] = value
    return result


def query_stats(*, reset: bool = False) -> dict[str, int]:
    server = get_server()
    if not server["stats_enabled"]:
        return {}
    args = [server["xray_bin"], "api", "statsquery", f"--server={server['api_listen']}"]
    if reset:
        args.append("-reset=true")
    proc = _run(args, timeout=15)
    if proc.returncode != 0:
        raise XPanelError((proc.stderr or proc.stdout).strip() or "не удалось получить статистику")
    return _parse_stats_output(proc.stdout)


def _query_online(server: sqlite3.Row, email: str) -> bool | None:
    proc = _run(
        [
            server["xray_bin"],
            "api",
            "statsonline",
            f"--server={server['api_listen']}",
            f"--email={email}",
        ],
        timeout=4,
    )
    if proc.returncode != 0:
        return None
    text = (proc.stdout or "").lower()
    if '"value"' in text:
        match = re.search(r'"value"\s*:\s*(\d+|true|false)', text)
        if match:
            return match.group(1) not in {"0", "false"}
    return bool(text.strip())


def _traffic_iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _traffic_online_value(value: object) -> bool | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number < 0:
        return None
    return bool(number)


def _traffic_snapshot_from_db(
    users: list[sqlite3.Row], *, error: str = ""
) -> dict[int, dict[str, object]]:
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    month_prefix = now.strftime("%Y-%m-")
    result: dict[int, dict[str, object]] = {}
    with connect() as con:
        totals = {
            int(row["user_id"]): row
            for row in con.execute("SELECT * FROM user_traffic_totals").fetchall()
        }
        today_rows = {
            int(row["user_id"]): row
            for row in con.execute(
                "SELECT * FROM user_traffic_daily WHERE day = ?", (today,)
            ).fetchall()
        }
        month_rows = {
            int(row["user_id"]): row
            for row in con.execute(
                """
                SELECT user_id, COALESCE(SUM(uplink), 0) AS uplink,
                       COALESCE(SUM(downlink), 0) AS downlink
                FROM user_traffic_daily
                WHERE day LIKE ?
                GROUP BY user_id
                """,
                (month_prefix + "%",),
            ).fetchall()
        }

    for user in users:
        user_id = int(user["id"])
        row = totals.get(user_id)
        daily = today_rows.get(user_id)
        monthly = month_rows.get(user_id)
        session_uplink = int(row["session_uplink"] or 0) if row else 0
        session_downlink = int(row["session_downlink"] or 0) if row else 0
        lifetime_uplink = int(row["uplink_total"] or 0) if row else 0
        lifetime_downlink = int(row["downlink_total"] or 0) if row else 0
        today_uplink = int(daily["uplink"] or 0) if daily else 0
        today_downlink = int(daily["downlink"] or 0) if daily else 0
        month_uplink = int(monthly["uplink"] or 0) if monthly else 0
        month_downlink = int(monthly["downlink"] or 0) if monthly else 0
        uplink_bps = int(row["uplink_bps"] or 0) if row else 0
        downlink_bps = int(row["downlink_bps"] or 0) if row else 0
        result[user_id] = {
            # Backward-compatible live Xray counters.
            "uplink": session_uplink,
            "downlink": session_downlink,
            "total": session_uplink + session_downlink,
            "session_uplink": session_uplink,
            "session_downlink": session_downlink,
            "session_total": session_uplink + session_downlink,
            # Persistent counters maintained by SG-Panel.
            "today_uplink": today_uplink,
            "today_downlink": today_downlink,
            "today_total": today_uplink + today_downlink,
            "month_uplink": month_uplink,
            "month_downlink": month_downlink,
            "month_total": month_uplink + month_downlink,
            "lifetime_uplink": lifetime_uplink,
            "lifetime_downlink": lifetime_downlink,
            "lifetime_total": lifetime_uplink + lifetime_downlink,
            "uplink_bps": uplink_bps,
            "downlink_bps": downlink_bps,
            "total_bps": uplink_bps + downlink_bps,
            "online": _traffic_online_value(row["online_state"]) if row else None,
            "last_seen_at": str(row["last_seen_at"] or "") if row else "",
            "last_collected_at": str(row["last_collected_at"] or "") if row else "",
            "reset_at": str(row["reset_at"] or "") if row else "",
            "error": error,
        }
    return result


def collect_traffic_snapshot(
    *, include_online: bool = False, now: datetime | None = None
) -> dict[int, dict[str, object]]:
    """Collect Xray counters and persist monotonic deltas in SQLite.

    Xray resets its counters when the service restarts or when statsquery is
    called with reset=true. SG-Panel stores the previous raw value and treats a
    lower value as a new Xray session, so all-time and daily totals survive
    restarts, updates and config applies.
    """
    users = list_users()
    server = get_server()
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    collected_at = _traffic_iso(current)
    day = current.date().isoformat()
    raw: dict[str, int] = {}
    error = ""
    stats_enabled = bool(server["stats_enabled"])
    if stats_enabled:
        try:
            raw = query_stats()
        except (XPanelError, FileNotFoundError) as exc:
            error = str(exc)
    else:
        error = "Stats API Xray выключен"

    online_values: dict[int, bool | None] = {}
    if include_online and stats_enabled and not error and users:
        # statsonline accepts one e-mail at a time. Run independent checks in a
        # small bounded pool so dozens of clients do not make the collector
        # wait four seconds per user. The web page reads this cached result and
        # therefore never blocks on a chain of Xray subprocesses.
        worker_count = min(8, len(users))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(_query_online, server, str(user["name"])): int(user["id"])
                for user in users
            }
            for future in as_completed(futures):
                user_id = futures[future]
                try:
                    online_values[user_id] = future.result()
                except (XPanelError, FileNotFoundError):
                    online_values[user_id] = None

    with connect() as con:
        for user in users:
            user_id = int(user["id"])
            prefix = f"user>>>{user['name']}>>>traffic>>>"
            raw_uplink = max(0, int(raw.get(prefix + "uplink", 0)))
            raw_downlink = max(0, int(raw.get(prefix + "downlink", 0)))
            previous = con.execute(
                "SELECT * FROM user_traffic_totals WHERE user_id = ?", (user_id,)
            ).fetchone()

            if previous is None:
                # Preserve traffic already accumulated in the current Xray
                # process before SG-Panel's persistent collector was installed.
                delta_uplink = raw_uplink if stats_enabled and not error else 0
                delta_downlink = raw_downlink if stats_enabled and not error else 0
                prior_uplink_total = 0
                prior_downlink_total = 0
                prior_online = -1
                prior_last_seen = None
                prior_collected = None
            else:
                prior_raw_uplink = int(previous["last_raw_uplink"] or 0)
                prior_raw_downlink = int(previous["last_raw_downlink"] or 0)
                if stats_enabled and not error:
                    delta_uplink = (
                        raw_uplink - prior_raw_uplink
                        if raw_uplink >= prior_raw_uplink
                        else raw_uplink
                    )
                    delta_downlink = (
                        raw_downlink - prior_raw_downlink
                        if raw_downlink >= prior_raw_downlink
                        else raw_downlink
                    )
                else:
                    delta_uplink = 0
                    delta_downlink = 0
                    raw_uplink = int(previous["session_uplink"] or 0)
                    raw_downlink = int(previous["session_downlink"] or 0)
                prior_uplink_total = int(previous["uplink_total"] or 0)
                prior_downlink_total = int(previous["downlink_total"] or 0)
                prior_online = int(previous["online_state"])
                prior_last_seen = previous["last_seen_at"]
                prior_collected = previous["last_collected_at"]

            elapsed = 0.0
            if prior_collected:
                try:
                    old_time = datetime.fromisoformat(str(prior_collected))
                    if old_time.tzinfo is None:
                        old_time = old_time.replace(tzinfo=timezone.utc)
                    elapsed = max((current - old_time.astimezone(timezone.utc)).total_seconds(), 0.0)
                except ValueError:
                    elapsed = 0.0
            uplink_bps = int(delta_uplink / elapsed) if elapsed >= 1 else 0
            downlink_bps = int(delta_downlink / elapsed) if elapsed >= 1 else 0

            online = online_values.get(user_id)
            online_state = prior_online if online is None else (1 if online else 0)
            last_seen = prior_last_seen
            if delta_uplink > 0 or delta_downlink > 0 or online is True:
                last_seen = collected_at

            con.execute(
                """
                INSERT INTO user_traffic_totals (
                    user_id, uplink_total, downlink_total,
                    last_raw_uplink, last_raw_downlink,
                    session_uplink, session_downlink,
                    uplink_bps, downlink_bps, online_state,
                    last_seen_at, last_collected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    uplink_total = excluded.uplink_total,
                    downlink_total = excluded.downlink_total,
                    last_raw_uplink = excluded.last_raw_uplink,
                    last_raw_downlink = excluded.last_raw_downlink,
                    session_uplink = excluded.session_uplink,
                    session_downlink = excluded.session_downlink,
                    uplink_bps = excluded.uplink_bps,
                    downlink_bps = excluded.downlink_bps,
                    online_state = excluded.online_state,
                    last_seen_at = excluded.last_seen_at,
                    last_collected_at = excluded.last_collected_at
                """,
                (
                    user_id,
                    prior_uplink_total + delta_uplink,
                    prior_downlink_total + delta_downlink,
                    raw_uplink,
                    raw_downlink,
                    raw_uplink,
                    raw_downlink,
                    uplink_bps,
                    downlink_bps,
                    online_state,
                    last_seen,
                    collected_at,
                ),
            )
            if delta_uplink or delta_downlink:
                con.execute(
                    """
                    INSERT INTO user_traffic_daily (user_id, day, uplink, downlink)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, day) DO UPDATE SET
                        uplink = uplink + excluded.uplink,
                        downlink = downlink + excluded.downlink
                    """,
                    (user_id, day, delta_uplink, delta_downlink),
                )

    return _traffic_snapshot_from_db(users, error=error)


def get_user_stats(*, include_online: bool = True) -> dict[int, dict[str, object]]:
    return collect_traffic_snapshot(include_online=include_online)


def get_user_traffic_history(user_id: int, *, days: int = 14) -> list[dict[str, object]]:
    find_user(user_id)
    days = max(1, min(int(days), 90))
    today = datetime.now(timezone.utc).date()
    start = (today - timedelta(days=days - 1)).isoformat()
    with connect() as con:
        rows = {
            str(row["day"]): row
            for row in con.execute(
                """
                SELECT day, uplink, downlink FROM user_traffic_daily
                WHERE user_id = ? AND day >= ? ORDER BY day
                """,
                (user_id, start),
            ).fetchall()
        }
    values: list[dict[str, object]] = []
    maximum = 0
    for offset in range(days - 1, -1, -1):
        day_value = today - timedelta(days=offset)
        key = day_value.isoformat()
        row = rows.get(key)
        uplink = int(row["uplink"] or 0) if row else 0
        downlink = int(row["downlink"] or 0) if row else 0
        total = uplink + downlink
        maximum = max(maximum, total)
        values.append(
            {
                "day": key,
                "label": day_value.strftime("%d.%m"),
                "uplink": uplink,
                "downlink": downlink,
                "total": total,
            }
        )
    for item in values:
        item["percent"] = round(int(item["total"]) * 100 / maximum) if maximum else 0
    return values


def reset_stats(user_id: int | None = None) -> None:
    """Reset SG-Panel persistent history and establish a fresh Xray baseline."""
    users = list_users()
    if user_id is not None:
        selected = find_user(user_id)
        users = [selected]
    server = get_server()
    raw: dict[str, int] = {}
    if bool(server["stats_enabled"]):
        try:
            raw = query_stats()
        except (XPanelError, FileNotFoundError):
            raw = {}
    now = _traffic_iso(datetime.now(timezone.utc))
    ids = [int(user["id"]) for user in users]
    with connect() as con:
        if user_id is None:
            con.execute("DELETE FROM user_traffic_daily")
        elif ids:
            con.execute("DELETE FROM user_traffic_daily WHERE user_id = ?", (ids[0],))
        for user in users:
            uid = int(user["id"])
            prefix = f"user>>>{user['name']}>>>traffic>>>"
            raw_uplink = max(0, int(raw.get(prefix + "uplink", 0)))
            raw_downlink = max(0, int(raw.get(prefix + "downlink", 0)))
            con.execute(
                """
                INSERT INTO user_traffic_totals (
                    user_id, uplink_total, downlink_total,
                    last_raw_uplink, last_raw_downlink,
                    session_uplink, session_downlink,
                    uplink_bps, downlink_bps, online_state,
                    last_collected_at, reset_at
                ) VALUES (?, 0, 0, ?, ?, ?, ?, 0, 0, -1, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    uplink_total = 0,
                    downlink_total = 0,
                    last_raw_uplink = excluded.last_raw_uplink,
                    last_raw_downlink = excluded.last_raw_downlink,
                    session_uplink = excluded.session_uplink,
                    session_downlink = excluded.session_downlink,
                    uplink_bps = 0,
                    downlink_bps = 0,
                    last_collected_at = excluded.last_collected_at,
                    reset_at = excluded.reset_at
                """,
                (uid, raw_uplink, raw_downlink, raw_uplink, raw_downlink, now, now),
            )


def user_expiring_soon(
    user: sqlite3.Row | dict[str, object], *, days: int = 7, now: datetime | None = None
) -> bool:
    value = user["expiry_at"]
    if not value or user_is_expired(user, now=now):  # type: ignore[arg-type]
        return False
    try:
        expiry = datetime.fromisoformat(str(value))
    except ValueError:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return expiry <= current + timedelta(days=days)


def qr_png_base64(payload: str) -> dict[str, str]:
    """Encode a share link as QR without allowing oversized ML-KEM links to crash the page."""
    value = str(payload or "")
    if not value:
        return {"data": "", "error": "Пустая ссылка не может быть преобразована в QR."}
    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_L
        from qrcode.exceptions import DataOverflowError
    except Exception as exc:
        return {"data": "", "error": f"QR временно недоступен: {exc}"}
    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_L,
            box_size=6,
            border=2,
        )
        qr.add_data(value, optimize=0)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return {"data": base64.b64encode(buffer.getvalue()).decode("ascii"), "error": ""}
    except (DataOverflowError, ValueError, OverflowError):
        return {
            "data": "",
            "error": (
                "Ссылка содержит полный ML-KEM/VLESS Encryption и слишком длинна для QR. "
                "Скопируйте Connection URI или используйте URL подписки."
            ),
        }
    except Exception as exc:
        return {"data": "", "error": f"QR временно недоступен: {exc}"}

def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def _prune_named_directories(root: Path, *, keep: int, protected: set[str] | None = None) -> list[str]:
    protected = protected or set()
    if not root.is_dir():
        return []
    candidates = [item for item in root.iterdir() if item.is_dir() and item.name not in protected]
    candidates.sort(key=lambda item: (item.stat().st_mtime_ns, item.name), reverse=True)
    removed: list[str] = []
    for item in candidates[max(0, int(keep)):]:
        _remove_path(item)
        removed.append(item.name)
    return removed


def prune_geofiles_storage(*, active_generation: str = "") -> dict[str, list[str]]:
    """Bound successful GeoFiles history while never deleting the active generation."""
    active = str(active_generation or "").strip()
    protected = {active} if active else set()
    removed_sets = _prune_named_directories(
        GEOFILES_STATE_DIR / "sets", keep=GEOFILES_SET_RETENTION, protected=protected
    )
    removed_backups = _prune_named_directories(
        GEOFILES_STATE_DIR / "backups", keep=GEOFILES_BACKUP_RETENTION, protected=protected
    )
    removed_staging: list[str] = []
    staging_root = GEOFILES_STATE_DIR / "staging"
    if staging_root.exists():
        age = time.time() - staging_root.stat().st_mtime
        transaction = GEOFILES_STATE_DIR / "transaction.json"
        if age > GEOFILES_STAGING_MAX_AGE_HOURS * 3600 and not transaction.exists():
            _remove_path(staging_root)
            removed_staging.append(staging_root.name)
    return {"sets": removed_sets, "backups": removed_backups, "staging": removed_staging}


def prune_panel_backups(*, keep: int = PANEL_BACKUP_RETENTION) -> list[str]:
    """Keep the newest complete backup groups (db/json/config), not isolated files."""
    root = backup_dir()
    if not root.is_dir():
        return []
    db_files = sorted(
        root.glob("sg-panel-*.db"),
        key=lambda item: (item.stat().st_mtime_ns, item.name),
        reverse=True,
    )
    removed: list[str] = []
    for db_file in db_files[max(1, int(keep)):]:
        stem = db_file.stem
        for suffix in (".db", ".json", ".config.json"):
            (root / f"{stem}{suffix}").unlink(missing_ok=True)
        removed.append(stem)
    return removed


def format_bytes(value: int | float) -> str:
    number = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    if index == 0:
        return f"{int(number)} {units[index]}"
    return f"{number:.2f} {units[index]}"



def _read_meminfo_bytes() -> dict[str, int]:
    values: dict[str, int] = {}
    path = Path("/proc/meminfo")
    if not path.exists():
        return values
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.split()
        if not parts:
            continue
        try:
            values[key] = int(parts[0]) * 1024
        except ValueError:
            continue
    return values


def _service_rss_bytes(service_name: str) -> int:
    try:
        result = _run(
            ["systemctl", "show", service_name, "--property=MainPID", "--value"],
            timeout=3,
        )
        pid = int(result.stdout.strip() or "0")
    except (ValueError, XPanelError, OSError):
        return 0
    if pid <= 0:
        return 0
    status = Path(f"/proc/{pid}/status")
    if not status.exists():
        return 0
    try:
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _read_positive_integer(path: Path) -> int:
    try:
        value = path.read_text(encoding="ascii").strip()
        if not value or value == "max":
            return 0
        return max(0, int(value))
    except (OSError, ValueError):
        return 0


def _service_memory_snapshot(service_name: str) -> dict[str, int]:
    """Return cgroup-v2 memory for a complete systemd service.

    The cgroup split prevents file cache and kernel allocations belonging to
    SG-Panel, Xray or Nginx from being counted twice in the memory dial.  A
    portable MainPID RSS fallback keeps the page useful in tests and on
    systems where cgroup-v2 accounting is unavailable.
    """
    snapshot = {
        "current": 0,
        "peak": 0,
        "anon": 0,
        "file": 0,
        "kernel": 0,
        "shmem": 0,
    }
    try:
        result = _run(
            ["systemctl", "show", service_name, "--property=ControlGroup", "--value"],
            timeout=3,
        )
        control_group = result.stdout.strip() if result.returncode == 0 else ""
    except (XPanelError, OSError):
        control_group = ""

    if control_group and control_group != "/":
        cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/")
        snapshot["current"] = _read_positive_integer(cgroup / "memory.current")
        snapshot["peak"] = _read_positive_integer(cgroup / "memory.peak")
        try:
            for line in (cgroup / "memory.stat").read_text(encoding="ascii").splitlines():
                key, raw = line.split(None, 1)
                if key in snapshot:
                    snapshot[key] = max(0, int(raw))
        except (OSError, ValueError):
            pass
        if snapshot["current"]:
            if not snapshot["peak"]:
                snapshot["peak"] = snapshot["current"]
            return snapshot

    rss = _service_rss_bytes(service_name)
    snapshot.update(current=rss, peak=rss, anon=rss)
    return snapshot


def _format_uptime(seconds: float) -> str:
    total = max(0, int(seconds))
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days} д {hours} ч"
    if hours:
        return f"{hours} ч {minutes} мин"
    return f"{minutes} мин"


def _memory_status(available_percent: float) -> tuple[str, str]:
    """Describe real memory headroom using Linux MemAvailable.

    Page cache is intentionally treated as reclaimable. Existing swap usage by
    itself is not a current-pressure signal and must not turn a healthy small
    server red.
    """
    if available_percent <= 8:
        return "critical", "Критически мало памяти"
    if available_percent <= 15:
        return "high", "Мало доступной памяти"
    if available_percent <= 25:
        return "warning", "Запас памяти снижается"
    return "normal", "Памяти достаточно"


def _build_memory_segments(
    values: dict[str, int],
    panel: dict[str, int],
    xray: dict[str, int],
    nginx: dict[str, int],
) -> dict[str, object]:
    """Build mutually exclusive sectors whose byte totals equal MemTotal."""
    total = max(0, int(values.get("MemTotal", 0)))
    free = min(total, max(0, int(values.get("MemFree", 0)))) if total else 0
    available = min(total, max(0, int(values.get("MemAvailable", 0)))) if total else 0
    swap_total = max(0, int(values.get("SwapTotal", 0)))
    swap_free = max(0, int(values.get("SwapFree", 0)))
    swap_used = max(0, swap_total - swap_free)

    global_cache = max(
        0,
        int(values.get("Cached", 0))
        + int(values.get("Buffers", 0))
        + int(values.get("SReclaimable", 0))
        - int(values.get("Shmem", 0)),
    )
    global_kernel = max(
        0,
        int(values.get("SUnreclaim", 0))
        + int(values.get("KernelStack", 0))
        + int(values.get("PageTables", 0))
        + int(values.get("Percpu", 0)),
    )

    snapshots = (panel, xray, nginx)
    current_values: list[int] = []
    remaining_for_services = max(0, total - min(free, total))
    for snapshot in snapshots:
        current = min(remaining_for_services, max(0, int(snapshot.get("current", 0))))
        current_values.append(current)
        remaining_for_services -= current
    panel_current, xray_current, nginx_current = current_values

    service_file = sum(max(0, int(item.get("file", 0))) for item in snapshots)
    service_kernel = sum(max(0, int(item.get("kernel", 0))) for item in snapshots)
    cache = max(0, global_cache - service_file)
    kernel = max(0, global_kernel - service_kernel)

    fixed = panel_current + xray_current + nginx_current + free
    remaining = max(0, total - fixed)
    cache = min(cache, remaining)
    remaining -= cache
    kernel = min(kernel, remaining)
    remaining -= kernel
    other = remaining

    raw_segments = [
        ("panel", "SG-Panel", panel_current, "#4f9bff"),
        ("xray", "Xray", xray_current, "#f07d8c"),
        ("nginx", "Nginx", nginx_current, "#9b7bff"),
        ("kernel", "Ядро Linux и сеть", kernel, "#ff9f5a"),
        ("other", "ОС и остальные процессы", other, "#38c6c2"),
        ("cache", "Файловый кэш", cache, "#e7c45b"),
        ("free", "Свободно", free, "#4ecb86"),
    ]
    cumulative = 0.0
    segments: list[dict[str, object]] = []
    gradient_parts: list[str] = []
    for key, label, value, color in raw_segments:
        exact_percent = (value / total * 100.0) if total else 0.0
        start_percent = cumulative
        cumulative += exact_percent
        end_percent = cumulative
        segment = {
            "key": key,
            "label": label,
            "value": value,
            "human": format_bytes(value),
            "percent": round(exact_percent, 1),
            "start_percent": round(start_percent, 4),
            "end_percent": round(end_percent, 4),
            "tone": f"memory-segment-{key}",
            "color": color,
        }
        segments.append(segment)
        if value > 0:
            gradient_parts.append(
                f"{color} {segment['start_percent']}% {segment['end_percent']}%"
            )
    if segments and total:
        segments[-1]["end_percent"] = 100.0
        if gradient_parts:
            last = segments[-1]
            gradient_parts[-1] = (
                f"{last['color']} {last['start_percent']}% 100%"
                if last["value"] > 0
                else gradient_parts[-1]
            )
    if not gradient_parts:
        gradient_parts.append("rgba(255,255,255,.08) 0% 100%")

    used = max(0, total - available)
    used_percent = round((used / total * 100.0), 1) if total else 0.0
    available_percent = round((available / total * 100.0), 1) if total else 0.0
    status_class, status_label = (
        _memory_status(available_percent)
        if total
        else ("normal", "Нет данных о памяти")
    )
    return {
        "total": total,
        "used": used,
        "available": available,
        "free": free,
        "used_percent": used_percent,
        "available_percent": available_percent,
        "status_class": status_class,
        "status_label": status_label,
        "segments": segments,
        "segment_map": {item["key"]: item for item in segments},
        "ring_style": "conic-gradient(" + ", ".join(gradient_parts) + ")",
        "panel_current": panel_current,
        "panel_peak": max(panel_current, int(panel.get("peak", 0))),
        "xray_current": xray_current,
        "xray_peak": max(xray_current, int(xray.get("peak", 0))),
        "nginx_current": nginx_current,
        "nginx_peak": max(nginx_current, int(nginx.get("peak", 0))),
        "cache": cache,
        "kernel": kernel,
        "other": other,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "method": (
            "Состояние оценивается по Linux MemAvailable: файловый кэш считается "
            "освобождаемым и сам по себе не является дефицитом памяти. SG-Panel, "
            "Xray и Nginx считаются по systemd cgroup вместе с дочерними процессами."
        ),
    }


def _system_resource_overview(xray_service: str) -> dict[str, object]:
    mem = _read_meminfo_bytes()
    memory_total = int(mem.get("MemTotal", 0))
    memory_available = int(mem.get("MemAvailable", 0))
    memory_used = max(memory_total - memory_available, 0)
    swap_total = int(mem.get("SwapTotal", 0))
    swap_free = int(mem.get("SwapFree", 0))
    swap_used = max(swap_total - swap_free, 0)
    try:
        disk = shutil.disk_usage("/")
        disk_total = int(disk.total)
        disk_free = int(disk.free)
    except OSError:
        disk_total = 0
        disk_free = 0
    disk_used = max(disk_total - disk_free, 0)
    cpu_count = max(os.cpu_count() or 1, 1)
    try:
        load_1m, load_5m, load_15m = os.getloadavg()
    except (AttributeError, OSError):
        load_1m = load_5m = load_15m = 0.0
    cpu_percent = min(max(load_1m * 100 / cpu_count, 0.0), 100.0)
    try:
        uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        uptime_seconds = 0.0

    def percent(used: int, total: int) -> int:
        return round(used * 100 / total) if total else 0

    panel_memory = _service_memory_snapshot("xpanel-web")
    xray_memory = _service_memory_snapshot(xray_service)
    nginx_memory = _service_memory_snapshot("nginx")
    memory = _build_memory_segments(mem, panel_memory, xray_memory, nginx_memory)

    return {
        "cpu_percent": round(cpu_percent),
        "cpu_cores": cpu_count,
        "load_1m": round(load_1m, 2),
        "load_5m": round(load_5m, 2),
        "load_15m": round(load_15m, 2),
        "memory_total": memory_total,
        "memory_used": memory_used,
        "memory_percent": memory["used_percent"],
        "memory_available_percent": memory["available_percent"],
        "memory_total_human": format_bytes(memory_total),
        "memory_used_human": format_bytes(memory_used),
        "memory_available_human": format_bytes(memory_available),
        "memory_free_human": format_bytes(int(memory["free"])),
        "memory_cache_human": format_bytes(int(memory["cache"])),
        "memory_kernel_human": format_bytes(int(memory["kernel"])),
        "memory_other_human": format_bytes(int(memory["other"])),
        "memory_segments": memory["segments"],
        "memory_segment_map": memory["segment_map"],
        "memory_ring_style": memory["ring_style"],
        "memory_status_class": memory["status_class"],
        "memory_status_label": memory["status_label"],
        "memory_method": memory["method"],
        "swap_total": swap_total,
        "swap_used": swap_used,
        "swap_percent": percent(swap_used, swap_total),
        "swap_total_human": format_bytes(swap_total),
        "swap_used_human": format_bytes(swap_used),
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_percent": percent(disk_used, disk_total),
        "disk_total_human": format_bytes(disk_total),
        "disk_used_human": format_bytes(disk_used),
        "disk_free_human": format_bytes(disk_free),
        "xray_memory_human": format_bytes(int(memory["xray_current"])),
        "xray_memory_peak_human": format_bytes(int(memory["xray_peak"])),
        "panel_memory_human": format_bytes(int(memory["panel_current"])),
        "panel_memory_peak_human": format_bytes(int(memory["panel_peak"])),
        "nginx_memory_human": format_bytes(int(memory["nginx_current"])),
        "nginx_memory_peak_human": format_bytes(int(memory["nginx_peak"])),
        "uptime_human": _format_uptime(uptime_seconds),
    }

def get_status() -> dict[str, object]:
    server = get_server()
    users = list_users()
    total = len(users)
    enabled = len(_active_users(users))
    expired = len([row for row in users if user_is_expired(row)])
    with connect() as con:
        rules_total = int(con.execute("SELECT COUNT(*) FROM routing_rules").fetchone()[0])
        rules_enabled = int(
            con.execute("SELECT COUNT(*) FROM routing_rules WHERE enabled = 1").fetchone()[0]
        )
        custom_outbounds_total = int(con.execute("SELECT COUNT(*) FROM outbounds").fetchone()[0])
        custom_outbounds_enabled = int(
            con.execute("SELECT COUNT(*) FROM outbounds WHERE enabled = 1").fetchone()[0]
        )
        settings = con.execute("SELECT * FROM routing_settings WHERE id = 1").fetchone()
        dns_settings = con.execute("SELECT * FROM dns_settings WHERE id = 1").fetchone()
        dns_servers_total = int(con.execute("SELECT COUNT(*) FROM dns_servers").fetchone()[0])
        dns_servers_enabled = int(con.execute("SELECT COUNT(*) FROM dns_servers WHERE enabled = 1").fetchone()[0])
        subscription_settings = con.execute(
            "SELECT * FROM subscription_settings WHERE id = 1"
        ).fetchone()
        subscriptions_enabled = int(
            con.execute(
                "SELECT COUNT(*) FROM users WHERE subscription_enabled = 1"
            ).fetchone()[0]
        )
    service = _run(["systemctl", "is-active", server["xray_service"]])
    state = (service.stdout or service.stderr).strip() or "unknown"
    config_path = Path(server["config_path"])
    config_detail = ""
    if config_path.exists():
        test = run_xray_test(server["xray_bin"], config_path)
        config_state = "OK" if test.returncode == 0 else "ERROR"
        if test.returncode != 0:
            config_detail = (test.stderr or test.stdout).strip()
    else:
        config_state = "missing"
    traffic_total = 0
    stats_error = ""
    try:
        traffic_total = sum(int(item["lifetime_total"]) for item in get_user_stats(include_online=False).values())
    except Exception as exc:  # dashboard must stay available even if API is down
        stats_error = str(exc)
    profile_labels = {
        "raw_reality": "VLESS REALITY TCP · XTLS VISION",
        "xhttp_tls": "VLESS XHTTP-TLS + Encryption + Vision",
        "xhttp_reality": "VLESS XHTTP + Encryption + Vision",
        "grpc_tls": "gRPC-TLS + Encryption + Vision",
        "hysteria2_tls": "Hysteria 2",
        "xhttp_hysteria_tls": "XHTTP-TLS + Vision + Hysteria 2",
    }
    config_updated_at = ""
    if config_path.exists():
        config_updated_at = datetime.fromtimestamp(
            config_path.stat().st_mtime, timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    return {
        "db_path": str(db_path()),
        "total_users": total,
        "enabled_users": enabled,
        "expired_users": expired,
        "rules_total": rules_total,
        "rules_enabled": rules_enabled,
        "custom_outbounds_total": custom_outbounds_total,
        "custom_outbounds_enabled": custom_outbounds_enabled,
        "default_outbound_tag": settings["default_outbound_tag"],
        "sniffing_enabled": bool(settings["sniffing_enabled"]),
        "domain_strategy": settings["domain_strategy"],
        "dns_enabled": bool(dns_settings["enabled"]),
        "dns_query_strategy": dns_settings["query_strategy"],
        "dns_servers_total": dns_servers_total,
        "dns_servers_enabled": dns_servers_enabled,
        "subscriptions_global_enabled": bool(subscription_settings["enabled"]),
        "subscriptions_enabled": subscriptions_enabled,
        "subscription_base_url": subscription_settings["base_url"],
        "service": state,
        "config_state": config_state,
        "config_path": str(config_path),
        "config_detail": config_detail,
        "address": server["address"],
        "port": server["port"],
        "inbound_profile": server["inbound_profile"],
        "inbound_profile_label": profile_labels.get(
            str(server["inbound_profile"]), str(server["inbound_profile"])
        ),
        "config_updated_at": config_updated_at,
        "overall_ok": state == "active" and config_state == "OK",
        "transport_listen": server["transport_listen"],
        "transport_port": server["transport_port"],
        "xhttp_path": server["xhttp_path"],
        "grpc_service_name": server["grpc_service_name"],
        "dest": server["dest"],
        "server_name": server["server_name"],
        "stats_enabled": bool(server["stats_enabled"]),
        "api_listen": server["api_listen"],
        "traffic_total": traffic_total,
        "traffic_total_human": format_bytes(traffic_total),
        "stats_error": stats_error,
        "system": _system_resource_overview(str(server["xray_service"])),
    }


SAVED_LINK_PROFILE_LABELS = {
    "raw_reality": "VLESS REALITY TCP · XTLS VISION",
    "xhttp_tls": "VLESS XHTTP-TLS + Encryption + Vision",
    "xhttp_reality": "VLESS XHTTP + Encryption + Vision",
    "hysteria2_tls": "Hysteria 2",
    "grpc_tls": "VLESS gRPC-TLS + Encryption + Vision",
    "ws_tls": "VLESS WebSocket-TLS + Encryption + Vision",
}


def _client_link_title(user_name: str, instance_id: int | None = None) -> str:
    name = str(user_name or "").strip()
    if instance_id is None:
        return name
    return f"{name}/Профиль {int(instance_id)}"


def _compact_json_query(value: dict[str, object]) -> str:
    return quote(json.dumps(value, ensure_ascii=False, separators=(",", ":")), safe="")


def _client_expert_query(profile: str) -> str:
    expert = get_transport_expert_settings()
    parts: list[str] = []
    if profile in {"xhttp_tls", "xhttp_reality"}:
        extra = _effective_xhttp_extra("client")
        if extra:
            parts.append("extra=" + _compact_json_query(extra))
    if bool(expert["finalmask_enabled"]):
        finalmask = _expert_json("finalmask_client_json")
        if finalmask:
            parts.append("fm=" + _compact_json_query(finalmask))
    if profile in {"xhttp_tls", "grpc_tls", "ws_tls"}:
        if bool(expert["certificate_pinning_enabled"]):
            pin = str(expert["certificate_pinning_sha256"] or "").strip()
            if pin:
                parts.append("pcs=" + quote(pin, safe=""))
        if str(expert["tls_verify_name_mode"] or "auto") == "manual":
            verify_name = str(expert["tls_verify_name"] or "").strip()
            if verify_name:
                parts.append("vcn=" + quote(verify_name, safe=""))
        # ECH is not added for XHTTP/gRPC here because SG-Panel terminates
        # their TLS in Nginx and does not configure an ECH-capable frontend.
    return ("&" + "&".join(parts)) if parts else ""


def _geofiles_client_metadata() -> dict[str, object]:
    geofiles = get_geofiles_overview()
    return {
        "source": geofiles["active_source"],
        "sourceLabel": geofiles["active_label"],
        "geoipUrl": str(geofiles["settings"]["geoip_url"] or ""),
        "geositeUrl": str(geofiles["settings"]["geosite_url"] or ""),
        "geoip": {
            "sha256": geofiles["geoip"]["sha256"],
            "size": geofiles["geoip"]["size"],
            "updatedAt": geofiles["geoip"]["updated_at"],
        },
        "geosite": {
            "sha256": geofiles["geosite"]["sha256"],
            "size": geofiles["geosite"]["size"],
            "updatedAt": geofiles["geosite"]["updated_at"],
        },
    }


def _tls_client_contract(
    profile: str, server: sqlite3.Row, expert: sqlite3.Row
) -> dict[str, object]:
    applicable = profile in CERTIFICATE_INBOUND_PROFILES or profile == "ws_tls"
    if not applicable:
        return {
            "applicable": False,
            "reason": "REALITY использует собственные serverName, public key и short ID; TLS certificate extras не применяются.",
        }

    server_name = _link_sni_for_profile(server, profile)
    verify_mode = str(expert["tls_verify_name_mode"] or "auto")
    verify_override = (
        str(expert["tls_verify_name"] or "").strip()
        if verify_mode == "manual"
        else ""
    )
    pin_enabled = bool(expert["certificate_pinning_enabled"])
    pin = str(expert["certificate_pinning_sha256"] or "").strip() if pin_enabled else ""
    ca_pem = str(expert["client_ca_pem"] or "").strip()
    if pin and ca_pem:
        verification_mode = "pinned_sha256_and_custom_ca"
    elif pin:
        verification_mode = "pinned_sha256"
    elif ca_pem:
        verification_mode = "custom_ca_plus_system_ca"
    else:
        verification_mode = "system_ca"

    ech_applicable = profile in HYSTERIA_ACTIVE_PROFILES
    ech_mode = str(expert["ech_mode"] or "off")
    ech_enabled = ech_applicable and ech_mode != "off"
    ech_source = "disabled"
    if ech_enabled:
        ech_source = "dns_https_record" if ech_mode == "dns" else "sg_panel_profile"

    return {
        "applicable": True,
        "source": "SG-Panel",
        "serverName": server_name,
        "verification": {
            "mode": verification_mode,
            "systemCaEnabled": True,
            "expectedCertificateName": verify_override or server_name,
            "verifyPeerCertByName": verify_override,
            "verifyPeerCertByNameSource": "administrator" if verify_override else "serverName",
            "pinnedPeerCertSha256": pin,
            "pinnedPeerCertSha256Source": str(expert["certificate_pinning_source"] or "") if pin else "",
            "customCaPem": ca_pem,
            "customCaPemSha256": str(expert["client_ca_sha256"] or "") if ca_pem else "",
            "customCaPemSource": str(expert["client_ca_source"] or "") if ca_pem else "",
            "disableSystemRoot": False,
        },
        "ech": {
            "applicable": ech_applicable,
            "enabled": ech_enabled,
            "mode": ech_mode if ech_applicable else "off",
            "publicName": str(expert["ech_public_name"] or "") if ech_enabled else "",
            "configList": str(expert["ech_config_list"] or "") if ech_enabled else "",
            "source": ech_source,
            "note": (
                "TLS этого профиля завершается в Nginx; ECH Xray для него не экспортируется."
                if not ech_applicable
                else ""
            ),
        },
    }


def managed_client_export(
    identifier: str | int, *, device_id: int | None = None
) -> dict[str, object]:
    """Backward-compatible managed profile for one independent Access/device."""
    server = get_server()
    person = find_user(identifier)
    user = _access_identity(int(person["id"]), device_id)
    expert = get_transport_expert_settings()
    profile = "all_available_channels"
    tls_contract = _tls_client_contract("xhttp_tls", server, expert)
    tls_verification = tls_contract.get("verification", {})
    ech = tls_contract.get("ech", {})
    encryption = controller_xray_encryption_status()
    return {
        "schema": "sg-panel-managed-profile-v1",
        "managedBy": "SG-Panel",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": {
            "id": int(person["id"]),
            "name": str(person["name"]),
            "uuid": str(user["uuid"]),
            "deviceId": int(user["device_id"]),
            "deviceName": str(user["device_name"]),
            "deviceDisplayName": str(user["name"]),
        },
        "server": {
            "address": str(server["address"]),
            "profile": profile,
            "serverName": str(server["server_name"]),
            "flow": "xtls-rprx-vision",
            "channelModel": SG_ALWAYS_ON_CHANNELS_MARKER,
        },
        "xhttp": {
            "applicable": True,
            "mode": VLESSENC_CLIENT_MODE_DEFAULT,
            "serverMode": VLESSENC_SERVER_MODE_DEFAULT,
            "serverExtra": _effective_xhttp_extra("server", expert=expert),
            "clientExtra": _effective_xhttp_extra("client", expert=expert),
        },
        "vlessEncryption": {
            "ready": bool(encryption["ready"]),
            "algorithm": "ML-KEM-768",
            "minimumXray": str(encryption["minimum"]),
            "xrayVersion": str(encryption["version"]),
        },
        "finalMask": {
            "enabled": bool(expert["finalmask_enabled"]),
            "server": _expert_json("finalmask_server_json"),
            "client": _expert_json("finalmask_client_json"),
            "source": "SG-Panel" if bool(expert["finalmask_enabled"]) else "disabled",
        },
        "ech": {
            "applicable": bool(ech.get("applicable")),
            "enabled": bool(ech.get("enabled")),
            "mode": str(ech.get("mode") or "off"),
            "publicName": str(ech.get("publicName") or ""),
            "configList": str(ech.get("configList") or ""),
            "source": str(ech.get("source") or "disabled"),
            "note": str(ech.get("note") or ""),
        },
        "certificatePinning": {
            "applicable": True,
            "enabled": bool(tls_verification.get("pinnedPeerCertSha256")),
            "pinnedPeerCertSha256": str(tls_verification.get("pinnedPeerCertSha256") or ""),
            "source": str(tls_verification.get("pinnedPeerCertSha256Source") or ""),
        },
        "tlsVerification": tls_verification,
        "geoFiles": _geofiles_client_metadata(),
    }


def _managed_connection_contract(
    item: dict[str, object],
    server: sqlite3.Row,
    user: sqlite3.Row,
    expert: sqlite3.Row,
) -> dict[str, object]:
    profile = str(item.get("profile") or server["inbound_profile"] or "raw_reality")
    transport_map = {
        "raw_reality": "tcp",
        "xhttp_tls": "xhttp",
        "xhttp_reality": "xhttp",
        "grpc_tls": "grpc",
        "hysteria2_tls": "hysteria2",
        "ws_tls": "ws",
    }
    security = "reality" if profile in {"raw_reality", "xhttp_reality"} else "tls"
    finalmask_enabled = bool(expert["finalmask_enabled"])
    connection: dict[str, object] = {
        "id": str(item.get("key") or f"{profile}-{item.get('id', 1)}"),
        "title": str(item.get("client_title") or user["name"]),
        "profile": profile,
        "protocol": "hysteria2" if profile == "hysteria2_tls" else "vless",
        "transport": transport_map.get(profile, str(item.get("kind") or "unknown")),
        "security": security,
        "endpoint": {
            "address": str(item.get("deployment_public_host") or server["address"]),
            "port": int(item.get("port") or server["port"]),
        },
        "uri": str(item.get("link") or ""),
        "active": True,
        "priority": int(item.get("transport_priority") or 100),
        "selection": {
            "mode": "automatic",
            "probeBeforeUse": True,
            "fallbackAllowed": True,
        },
        "deployment": {
            "source": str(item.get("source") or "controller"),
            "slot": str(item.get("deployment_slot") or "primary"),
            "slotLabel": str(item.get("deployment_slot_label") or "Автоматически"),
            "node": str(item.get("deployment_node") or "controller"),
            "nodeName": str(item.get("deployment_node_name") or "Controller"),
        },
        "credential": {
            "type": "auth" if profile == "hysteria2_tls" else "uuid",
            "value": str(item.get("auth") or user["uuid"]),
            "source": "SG-Panel",
        },
        "managedFields": {
            "serverAuthoritative": [
                "security", "transport", "endpoint", "credential", "serverName",
                "flow", "reality", "tls", "xhttp", "grpc"
            ],
            "ordinaryUserEditable": [],
            "expertOverrideAllowed": ["finalMask"],
        },
        "finalMask": {
            "enabled": finalmask_enabled,
            "config": _expert_json("finalmask_client_json") if finalmask_enabled else {},
            "source": "SG-Panel" if finalmask_enabled else "disabled",
        },
    }
    if profile == "hysteria2_tls" and item.get("authority_ports"):
        connection["endpoint"]["portSpec"] = str(item["authority_ports"])
    if profile in {"xhttp_tls", "xhttp_reality"}:
        is_remote_xhttp = str(item.get("source") or "controller") == "sg-node"
        connection["xhttp"] = {
            "mode": (
                str(item.get("remote_mode") or item.get("xhttp_client_mode") or VLESSENC_CLIENT_MODE_DEFAULT)
                if profile == "xhttp_reality"
                else str(item.get("xhttp_client_mode") or server["xhttp_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT)
            ),
            "serverMode": (
                str(item.get("xhttp_server_mode") or VLESSENC_SERVER_MODE_DEFAULT)
                if profile == "xhttp_reality"
                else str(item.get("xhttp_server_mode") or server["xhttp_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT)
            ),
            "extra": _effective_xhttp_extra("client", expert=expert),
            "path": str(item.get("remote_path") or item.get("path") or server["xhttp_path"] or ""),
            "source": "SG-Node deployment" if is_remote_xhttp else "SG-Panel",
        }
    if profile in {"xhttp_reality", "xhttp_tls", "grpc_tls", "ws_tls"}:
        is_remote_vlessenc = str(item.get("source") or "controller") == "sg-node"
        encryption = str(item.get("remote_encryption") or item.get("encryption") or "")
        if not encryption and not is_remote_vlessenc:
            encryption = str(_controller_vless_encryption_pair()["encryption"])
        connection["flow"] = {
            "value": "xtls-rprx-vision",
            "source": "SG-Node deployment" if is_remote_vlessenc else "SG-Panel",
        }
        connection["vlessEncryption"] = {
            "algorithm": "ML-KEM-768",
            "encryption": encryption,
            "ready": client_value_ready(encryption),
            "source": "SG-Node deployment" if is_remote_vlessenc else "SG-Panel",
        }
    if profile == "ws_tls":
        connection["websocket"] = {
            "path": str(item.get("path") or RUSSIA_KIT_WS_PATH),
            "host": str(item.get("host") or _link_sni_for_profile(server, profile)),
            "source": "SG-Panel",
        }
    if profile == "grpc_tls":
        connection["grpc"] = {
            "serviceName": str(server["grpc_service_name"] or ""),
            "source": "SG-Panel",
        }
    if profile in {"raw_reality", "xhttp_reality"}:
        is_remote = str(item.get("source") or "controller") == "sg-node"
        connection["reality"] = {
            "source": "SG-Node deployment" if is_remote else "SG-Panel",
            "serverName": str(item.get("remote_sni") or _link_sni_for_profile(server, profile)),
            "publicKey": str(item.get("remote_public_key") or server["public_key"]),
            "shortId": str(item.get("remote_short_id") or item.get("short_id") or server["short_id"]),
            "fingerprint": fingerprint_for_xray(
                str(item.get("remote_fingerprint") or server["fingerprint"])
            ),
            "spiderX": str(item.get("remote_spider_x") or "/"),
            "flow": (
                str(item.get("remote_flow") or "") if is_remote
                else "xtls-rprx-vision" if profile in {"raw_reality", "xhttp_reality"} else ""
            ),
            "flowSource": "SG-Node deployment" if is_remote else "SG-Panel",
        }
        connection["tls"] = {
            "applicable": False,
            "reason": "REALITY profile: ECH, certificate SHA-256 and CA PEM are intentionally absent.",
        }
    else:
        connection["tls"] = _tls_client_contract(profile, server, expert)
    return connection


def managed_client_export_v2(
    identifier: str | int, *, device_id: int | None = None
) -> dict[str, object]:
    """Authoritative SG Client contract for one Access/device."""
    server = get_server()
    person = find_user(identifier)
    user = _access_identity(int(person["id"]), device_id)
    expert = get_transport_expert_settings()
    links = make_cluster_links(
        int(person["id"]), allow_disabled=True, device_id=int(user["device_id"])
    )
    return {
        "schema": "sg-panel-managed-profile-v2",
        "contractVersion": 2,
        "managedBy": "SG-Panel",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": {
            "id": int(person["id"]),
            "name": str(person["name"]),
            "uuid": str(user["uuid"]),
            "deviceId": int(user["device_id"]),
            "deviceName": str(user["device_name"]),
            "deviceDisplayName": str(user["name"]),
        },
        "server": {
            "address": str(server["address"]),
            "activeProfile": str(server["inbound_profile"] or "raw_reality"),
        },
        "contract": {
            "ordinaryUserAction": "import_and_connect",
            "serverDependentValues": "must_not_be_invented_or_enabled_locally",
            "trustOnFirstUse": False,
            "connectionSelection": "automatic_reachability_then_priority",
            "adaptiveReconnect": True,
        },
        "connections": [
            _managed_connection_contract(dict(item), server, user, expert)
            for item in links
        ],
        "geoFiles": _geofiles_client_metadata(),
    }


def _link_sni_for_profile(server: sqlite3.Row, profile: str) -> str:
    current = str(server["inbound_profile"] or "raw_reality")
    if current == RUSSIA_KIT_PROFILE:
        if profile in {"raw_reality", "xhttp_reality"}:
            return str(server["server_name"] or "").strip()
        return _russia_kit_tls_domain(server)
    if profile in REALITY_INBOUND_PROFILES:
        if current in REALITY_INBOUND_PROFILES:
            value = str(server["server_name"] or "").strip()
        else:
            value = str(server["dest"] or "").rsplit(":", 1)[0].strip().strip("[]")
    else:
        if current in CERTIFICATE_INBOUND_PROFILES:
            value = str(server["server_name"] or "").strip()
        else:
            value = _hostname_candidate(str(server["address"] or "")) or str(server["server_name"] or "").strip()
    return value


def _make_russia_kit_links(
    user: sqlite3.Row, server: sqlite3.Row
) -> list[dict[str, object]]:
    domain = _russia_kit_tls_domain(server)
    address = str(server["address"] or "").strip()
    fp = quote(fingerprint_for_xray(str(server["fingerprint"])), safe="")
    reality_sni = quote(str(server["server_name"] or ""), safe="")
    tls_sni = quote(domain, safe="")
    pair = _controller_vless_encryption_pair()
    encrypted = quote(pair["encryption"], safe="-._~")
    reality_mode = quote(
        str(server["xhttp_client_mode"] or VLESSENC_CLIENT_MODE_DEFAULT), safe="-_"
    )
    tls_mode_value = str(server["xhttp_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT)
    tls_mode = quote(tls_mode_value, safe="-_")
    client_extra = _client_expert_query("xhttp_tls")
    base_vless_reality = f"vless://{user['uuid']}@{address}:443"
    reality_query = (
        f"encryption={encrypted}"
        f"&flow=xtls-rprx-vision&type=xhttp&security=reality"
        f"&pbk={quote(str(server['public_key']), safe='-_')}"
        f"&fp={fp}&sni={reality_sni}&sid={quote(str(server['short_id']), safe='')}"
        f"&path={quote(RUSSIA_KIT_XHTTP_REALITY_PATH, safe='')}"
        f"&mode={reality_mode}&spx=%2F{_client_expert_query('xhttp_reality')}"
    )
    auths = _ensure_device_hysteria_auths()
    auth = str(auths[1][int(user["id"])])
    hysteria_primary = next(row for row in list_hysteria_inbounds() if int(row["id"]) == 1)
    tls_base = f"vless://{user['uuid']}@{domain}:443"
    ws_query = (
        f"encryption={encrypted}&flow=xtls-rprx-vision"
        f"&type=ws&security=tls&fp={fp}&sni={tls_sni}&host={quote(domain, safe='')}"
        f"&path={quote(RUSSIA_KIT_WS_PATH, safe='')}{_client_expert_query('ws_tls')}"
    )
    xhttp_tls_query = (
        f"encryption={encrypted}&flow=xtls-rprx-vision"
        f"&type=xhttp&security=tls&fp={fp}&sni={tls_sni}&host={quote(domain, safe='')}"
        f"&path={quote(RUSSIA_KIT_XHTTP_TLS_PATH, safe='')}"
        f"&mode={tls_mode}{client_extra}"
    )
    titles = {
        "xhttp_reality": f"{user['name']} · XHTTP REALITY",
        "hysteria2_tls": f"{user['name']} · Hysteria 2",
        "ws_tls": f"{user['name']} · WebSocket TLS",
        "xhttp_tls": f"{user['name']} · XHTTP TLS",
    }
    common_vless = {
        "flow": "xtls-rprx-vision",
        "encryption": pair["encryption"],
    }
    return [
        {
            "id": 1, "key": "russia-xhttp-reality", "profile": "xhttp_reality", "transport_priority": 10,
            "kind": "xhttp", "name": "XHTTP REALITY", "client_title": titles["xhttp_reality"],
            "tag": "vless-reality-in", "listen": "127.0.0.1", "port": 443,
            "local_port": int(_russia_kit_edge(server)["xray_port"]),
            "path": RUSSIA_KIT_XHTTP_REALITY_PATH,
            **common_vless,
            "xhttp_server_mode": VLESSENC_SERVER_MODE_DEFAULT,
            "xhttp_client_mode": str(server["xhttp_client_mode"] or VLESSENC_CLIENT_MODE_DEFAULT),
            "link": f"{base_vless_reality}?{reality_query}#{quote(titles['xhttp_reality'], safe='')}",
        },
        {
            "id": 1, "key": "russia-hysteria2", "profile": "hysteria2_tls", "transport_priority": 20,
            "kind": "hysteria", "name": "Hysteria 2", "client_title": titles["hysteria2_tls"],
            "tag": HYSTERIA_COMBINED_PRIMARY_TAG, "listen": "0.0.0.0", "port": 443,
            "authority_ports": "443", "auth": auth, "deployment_public_host": domain,
            "obfs_mode": str(hysteria_primary["obfs_mode"] or "none"),
            "obfs_password_configured": bool(hysteria_primary["obfs_password"]),
            "link": build_hysteria2_uri(
                auth=auth, host=domain, port=443, sni=domain,
                profile_name=titles["hysteria2_tls"],
                obfs_mode=str(hysteria_primary["obfs_mode"] or "none"),
                obfs_password=(str(hysteria_primary["obfs_password"]) if hysteria_primary["obfs_password"] is not None else None),
            ),
        },
        {
            "id": 1, "key": "russia-ws-tls", "profile": "ws_tls", "transport_priority": 30,
            "kind": "ws", "name": "WebSocket TLS", "client_title": titles["ws_tls"],
            "tag": "ws-tls-in", "listen": "127.0.0.1", "port": 443,
            "local_port": RUSSIA_KIT_WS_PORT, "path": RUSSIA_KIT_WS_PATH, "host": domain,
            "deployment_public_host": domain,
            **common_vless,
            "link": f"{tls_base}?{ws_query}#{quote(titles['ws_tls'], safe='')}",
        },
        {
            "id": 1, "key": "russia-xhttp-tls", "profile": "xhttp_tls", "transport_priority": 40,
            "kind": "xhttp", "name": "XHTTP TLS", "client_title": titles["xhttp_tls"],
            "tag": "xhttp-tls-in", "listen": "127.0.0.1", "port": 443,
            "local_port": RUSSIA_KIT_XHTTP_TLS_PORT, "path": RUSSIA_KIT_XHTTP_TLS_PATH,
            "deployment_public_host": domain,
            **common_vless,
            "xhttp_server_mode": tls_mode_value,
            "xhttp_client_mode": tls_mode_value,
            "link": f"{tls_base}?{xhttp_tls_query}#{quote(titles['xhttp_tls'], safe='')}",
        },
    ]


def _make_links_for_profile(
    user: sqlite3.Row, server: sqlite3.Row, profile: str
) -> list[dict[str, object]]:
    sni = quote(_link_sni_for_profile(server, profile), safe="")
    result: list[dict[str, object]] = []

    if profile == "raw_reality":
        base = f"vless://{user['uuid']}@{server['address']}"
        fp = quote(fingerprint_for_xray(str(server["fingerprint"])), safe="")
        flow = f"&flow={quote(server['flow'], safe='-_')}" if server["flow"] else ""
        for instance in list_reality_inbounds():
            if not bool(instance["enabled"]):
                continue
            instance_id = int(instance["id"])
            title = _client_link_title(str(user["name"]), instance_id)
            query = (
                f"encryption=none&type=tcp&security=reality"
                f"&pbk={quote(server['public_key'], safe='-_')}"
                f"&fp={fp}&sni={sni}&sid={quote(str(instance['short_id']), safe='')}"
                f"{flow}&spx=%2F{_client_expert_query(profile)}"
            )
            result.append({
                "id": instance_id,
                "key": f"reality-{instance_id}",
                "profile": profile,
                "kind": "reality",
                "name": str(instance["name"]),
                "client_title": title,
                "tag": str(instance["tag"]),
                "listen": str(instance["listen"]),
                "port": int(instance["port"]),
                "short_id": str(instance["short_id"]),
                "link": f"{base}:{int(instance['port'])}?{query}#{quote(title, safe='')}",
            })
        if not result:
            raise XPanelError("не включён ни один REALITY Inbound")
        return result

    if profile == "xhttp_tls":
        pair = _controller_vless_encryption_pair()
        encrypted = quote(pair["encryption"], safe="-._~")
        base = f"vless://{user['uuid']}@{server['address']}:{server['port']}"
        fp = quote(fingerprint_for_xray(str(server["fingerprint"])), safe="")
        mode_value = str(server["xhttp_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT)
        mode = quote(mode_value, safe="-_")
        for instance in list_xhttp_inbounds():
            if not bool(instance["enabled"]):
                continue
            instance_id = int(instance["id"])
            title = _client_link_title(str(user["name"]), instance_id)
            query = (
                f"encryption={encrypted}&flow=xtls-rprx-vision"
                f"&type=xhttp&security=tls&fp={fp}&sni={sni}"
                f"&host={quote(server['address'], safe='')}"
                f"&path={quote(str(instance['path']), safe='')}"
                f"&mode={mode}{_client_expert_query(profile)}"
            )
            result.append({
                "id": instance_id,
                "key": f"xhttp-{instance_id}",
                "profile": profile,
                "kind": "xhttp",
                "name": str(instance["name"]),
                "client_title": title,
                "tag": str(instance["tag"]),
                "listen": str(instance["listen"]),
                "port": int(server["port"]),
                "local_port": int(instance["port"]),
                "path": str(instance["path"]),
                "flow": "xtls-rprx-vision",
                "encryption": pair["encryption"],
                "xhttp_server_mode": mode_value,
                "xhttp_client_mode": mode_value,
                "link": f"{base}?{query}#{quote(title, safe='')}",
            })
        if not result:
            raise XPanelError("не включён ни один XHTTP Inbound")
        return result

    if profile == "hysteria2_tls":
        auths = _ensure_device_hysteria_auths()
        for instance in list_hysteria_inbounds():
            if not bool(instance["enabled"]):
                continue
            inbound_id = int(instance["id"])
            raw_auth = str(auths[inbound_id][int(user["id"])])
            host = str(server["address"])
            hop_ports = str(server["hysteria_udp_hop_ports"] or "").strip()
            authority_ports = (
                hop_ports if inbound_id == 1 and hop_ports else str(instance["port"])
            )
            title = _client_link_title(str(user["name"]), inbound_id)
            result.append({
                "id": inbound_id,
                "key": f"hysteria-{inbound_id}",
                "profile": profile,
                "kind": "hysteria",
                "name": str(instance["name"]),
                "client_title": title,
                "tag": str(instance["tag"]),
                "listen": str(instance["listen"]),
                "port": int(instance["port"]),
                "authority_ports": authority_ports,
                "auth": raw_auth,
                "obfs_mode": str(instance["obfs_mode"] or "none"),
                "obfs_password_configured": bool(instance["obfs_password"]),
                "link": build_hysteria2_uri(
                    auth=raw_auth, host=host, port=authority_ports,
                    sni=_link_sni_for_profile(server, profile), profile_name=title,
                    obfs_mode=str(instance["obfs_mode"] or "none"),
                    obfs_password=(str(instance["obfs_password"]) if instance["obfs_password"] is not None else None),
                ),
            })
        if not result:
            raise XPanelError("не включён ни один Hysteria 2 Inbound")
        return result

    name = quote(str(user["name"]), safe="")
    base = f"vless://{user['uuid']}@{server['address']}:{server['port']}"
    fp = quote(fingerprint_for_xray(str(server["fingerprint"])), safe="")
    pair = _controller_vless_encryption_pair()
    encrypted = quote(pair["encryption"], safe="-._~")
    if profile == "xhttp_reality":
        client_mode_value = str(server["xhttp_client_mode"] or VLESSENC_CLIENT_MODE_DEFAULT)
        client_mode = quote(client_mode_value, safe="-_")
        query = (
            f"encryption={encrypted}"
            f"&flow=xtls-rprx-vision&type=xhttp&security=reality"
            f"&pbk={quote(server['public_key'], safe='-_')}"
            f"&fp={fp}&sni={sni}&sid={quote(server['short_id'], safe='')}"
            f"&path={quote(server['xhttp_path'], safe='')}"
            f"&mode={client_mode}&spx=%2F{_client_expert_query(profile)}"
        )
        server_mode_value = VLESSENC_SERVER_MODE_DEFAULT
    elif profile == "grpc_tls":
        client_mode_value = ""
        server_mode_value = ""
        query = (
            f"encryption={encrypted}&flow=xtls-rprx-vision"
            f"&type=grpc&security=tls&fp={fp}&sni={sni}"
            f"&serviceName={quote(server['grpc_service_name'], safe='-_')}"
            f"{_client_expert_query(profile)}"
        )
    else:
        raise XPanelError(f"неподдерживаемый профиль inbound: {profile}")
    return [{
        "id": 1,
        "key": f"{profile}-1",
        "profile": profile,
        "kind": "vless",
        "name": "Основной профиль",
        "client_title": str(user["name"]),
        "tag": "vless-reality-in",
        "listen": str(server["listen"]),
        "port": int(server["port"]),
        "flow": "xtls-rprx-vision",
        "encryption": pair["encryption"],
        "xhttp_server_mode": server_mode_value,
        "xhttp_client_mode": client_mode_value,
        "link": f"{base}?{query}#{name}",
    }]


def make_links(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> list[dict[str, object]]:
    server = get_server()
    person = find_user(identifier)
    user = _access_identity(int(person["id"]), device_id)
    if (not bool(user["enabled"]) or _expiry_is_past(user["expiry_at"])) and not allow_disabled:
        raise XPanelError("доступ отключён или срок действия истёк")
    profile = str(server["inbound_profile"] or "raw_reality")

    if profile == RUSSIA_KIT_PROFILE:
        return _make_russia_kit_links(user, server)
    if profile == "xhttp_hysteria_tls":
        xhttp_links = _make_links_for_profile(user, server, "xhttp_tls")
        hysteria_links = _make_links_for_profile(user, server, "hysteria2_tls")
        for item in hysteria_links:
            if int(item["id"]) == 1:
                item["tag"] = HYSTERIA_COMBINED_PRIMARY_TAG
        return xhttp_links + hysteria_links
    return _make_links_for_profile(user, server, profile)


def _deployment_sort_key(
    item: dict[str, object], *, manual_order: bool
) -> tuple[int, int, int, str]:
    if not manual_order:
        source_order = 10 if str(item.get("source") or "controller") == "controller" else 20
        return (
            source_order,
            int(item.get("deployment_priority") or 100),
            int(item.get("transport_priority") or 100),
            str(item.get("client_title") or item.get("name") or "").casefold(),
        )
    slot_order = {"primary": 10, "backup": 20, "alt": 100}
    return (
        slot_order.get(str(item.get("deployment_slot") or "alt"), 100),
        int(item.get("deployment_priority") or 100),
        int(item.get("transport_priority") or 100),
        str(item.get("client_title") or item.get("name") or "").casefold(),
    )


def _link_with_visible_title(link: str, title: str) -> str:
    base = str(link or "").split("#", 1)[0]
    return f"{base}#{quote(str(title or '').strip(), safe='')}"


def _remote_vless_metadata(link: str) -> dict[str, object]:
    """Extract authoritative transport fields from a confirmed Node URI.

    Remote SG-Node keys belong to that Node, not to the Controller. Keeping the
    parsed values next to the deployment prevents managed-profile exports from
    accidentally advertising the Controller REALITY key for a remote endpoint.
    """
    try:
        parsed = urlparse(link)
    except ValueError:
        return {}
    if parsed.scheme.lower() != "vless":
        return {}
    query = parse_qs(parsed.query, keep_blank_values=True)

    def one(name: str, default: str = "") -> str:
        values = query.get(name) or []
        return str(values[0] if values else default)

    return {
        "remote_transport": one("type", "tcp"),
        "remote_security": one("security", "reality"),
        "remote_public_key": one("pbk"),
        "remote_short_id": one("sid"),
        "remote_sni": one("sni"),
        "remote_fingerprint": one("fp", "firefox"),
        "remote_flow": one("flow"),
        "remote_encryption": one("encryption"),
        "remote_mode": one("mode"),
        "remote_spider_x": one("spx", "/"),
        "remote_path": one("path"),
    }


def make_cluster_links(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> list[dict[str, object]]:
    """Return active Controller and SG-Node endpoints in failover order.

    The local Xray links are generated live; remote links are emitted only after
    the Agent has confirmed an active deployment. This keeps a stable
    subscription URL while Controller changes the internal connection order.
    """
    person = find_user(identifier)
    user = _access_identity(int(person["id"]), device_id)
    local_links = make_links(
        int(person["id"]), allow_disabled=allow_disabled, device_id=int(user["device_id"])
    )
    manual_order = str(person["connection_order_mode"] or "auto") == "manual"
    try:
        from .node_manager import list_user_deployments
        deployments = [
            item for item in list_user_deployments(int(person["id"]))
            if int(item.get("device_id") or 0) == int(user["device_id"])
            or str(item.get("user_uuid") or "") == str(user["uuid"])
        ]
    except (ImportError, ValueError, sqlite3.Error):
        deployments = []
    local_deployment = next((item for item in deployments if bool(item.get("node_is_local"))), None)
    local_slot = str((local_deployment or {}).get("slot") or "primary")
    local_priority = int((local_deployment or {}).get("priority") or 10)
    result: list[dict[str, object]] = []
    local_visible = (
        local_deployment is None
        or (
            str(local_deployment.get("state") or "active") == "active"
            and str(local_deployment.get("desired_state") or "active") == "active"
            and bool(local_deployment.get("subscription_enabled", True))
        )
    )
    if local_visible:
        for item in local_links:
            result.append({
                **item,
                "source": "controller",
                "deployment_id": int(local_deployment["id"]) if local_deployment else None,
                "deployment_slot": local_slot,
                "deployment_slot_label": _deployment_slot_display_label(
                    local_slot, manual=manual_order
                ),
                "deployment_priority": local_priority,
                "deployment_node": "Controller",
                "deployment_node_name": "Controller",
                "subscription_visible": True,
            })
    for deployment in deployments:
        if bool(deployment.get("node_is_local")):
            continue
        if str(deployment.get("state") or "") != "active":
            continue
        if str(deployment.get("desired_state") or "active") != "active":
            continue
        if not bool(deployment.get("subscription_enabled")):
            continue
        link = str(deployment.get("client_link") or "").strip()
        if not link:
            continue
        slot = str(deployment.get("slot") or "alt")
        remote_metadata = _remote_vless_metadata(link)
        deployment_profile = str(deployment.get("profile") or "").strip().lower()
        remote_profile = (
            "xhttp_reality"
            if deployment_profile in {"vless xhttp reality", "xhttp_reality", "vless xhttp + reality"}
            or str(remote_metadata.get("remote_transport") or "").lower() == "xhttp"
            else "raw_reality"
        )
        result.append({
            "id": int(deployment["id"]),
            "key": f"deployment-{int(deployment['id'])}",
            "profile": remote_profile,
            "profile_label": "SG-Node · XHTTP Reality" if remote_profile == "xhttp_reality" else "SG-Node · Reality TCP",
            "kind": "deployment",
            "name": str(deployment.get("node_name") or "SG-Node"),
            "client_title": f"{user['name']}/{deployment.get('node_name')}",
            "tag": "sg-node-deployment",
            "listen": "",
            "port": int(deployment.get("public_port") or 0),
            "link": _link_with_visible_title(link, f"{user['name']}/{deployment.get('node_name')}"),
            "source": "sg-node",
            "deployment_id": int(deployment["id"]),
            "deployment_slot": slot,
            "deployment_slot_label": _deployment_slot_display_label(
                slot, manual=manual_order
            ),
            "deployment_priority": int(deployment.get("priority") or 100),
            "deployment_node": f"node:{int(deployment['node_id'])}",
            "deployment_node_name": str(deployment.get("node_name") or "SG-Node"),
            "deployment_public_host": str(deployment.get("public_host") or deployment.get("node_public_address") or ""),
            "subscription_visible": True,
            "active": True,
            **remote_metadata,
        })
    result.sort(key=lambda item: _deployment_sort_key(item, manual_order=manual_order))
    seen: set[str] = set()
    unique: list[dict[str, object]] = []
    for item in result:
        link = str(item.get("link") or "")
        if not link or link in seen:
            continue
        seen.add(link)
        unique.append(item)
    if not unique:
        raise XPanelError(
            "у клиента нет активных endpoints в стабильной подписке; включите Controller или подтверждённую SG-Node"
        )
    return unique



def make_cluster_saved_links(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> list[dict[str, object]]:
    local = make_saved_links(identifier, allow_disabled=allow_disabled, device_id=device_id)
    active = make_cluster_links(identifier, allow_disabled=allow_disabled, device_id=device_id)
    remote = [item for item in active if item.get("source") == "sg-node"]
    return local + remote


def make_saved_links(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> list[dict[str, object]]:
    """Return active links plus links saved for currently inactive profile families.

    The public subscription deliberately continues to use make_links(), so clients
    receive only endpoints that the server is serving right now.
    """
    server = get_server()
    person = find_user(identifier)
    user = _access_identity(int(person["id"]), device_id)
    if (not bool(user["enabled"]) or _expiry_is_past(user["expiry_at"])) and not allow_disabled:
        raise XPanelError("доступ отключён или срок действия истёк")

    current = str(server["inbound_profile"] or "raw_reality")
    active_families: set[str]
    if current == RUSSIA_KIT_PROFILE:
        active_families = {"xhttp_reality", "hysteria2_tls", "ws_tls", "xhttp_tls"}
    elif current == "xhttp_hysteria_tls":
        active_families = {"xhttp_tls", "hysteria2_tls"}
    else:
        active_families = {current}

    if current == RUSSIA_KIT_PROFILE:
        return [
            {**item, "profile_label": SAVED_LINK_PROFILE_LABELS[str(item["profile"])], "active": True}
            for item in _make_russia_kit_links(user, server)
        ]
    profiles = ("raw_reality", "xhttp_tls", "xhttp_reality", "hysteria2_tls", "ws_tls")
    if current == "grpc_tls":
        profiles = ("grpc_tls", *profiles)
    links: list[dict[str, object]] = []
    for profile in profiles:
        try:
            profile_links = _make_links_for_profile(user, server, profile)
        except XPanelError:
            continue
        is_active = profile in active_families
        for item in profile_links:
            if current == "xhttp_hysteria_tls" and profile == "hysteria2_tls" and int(item["id"]) == 1:
                item["tag"] = HYSTERIA_COMBINED_PRIMARY_TAG
            links.append({
                **item,
                "profile": profile,
                "profile_label": SAVED_LINK_PROFILE_LABELS[profile],
                "active": is_active,
            })
    return links


def make_link(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> str:
    return str(
        make_links(identifier, allow_disabled=allow_disabled, device_id=device_id)[0]["link"]
    )


def backup_dir() -> Path:
    value = os.environ.get("XPANEL_BACKUP_DIR")
    path = Path(value).expanduser().resolve() if value else DEFAULT_BACKUP_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_backup_name(name: str) -> str:
    if not re.fullmatch(r"sg-panel-\d{8}-\d{6}", name):
        raise ValueError("некорректное имя резервной копии")
    return name


def _sqlite_integrity(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, "файл SQLite отсутствует"
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as con:
            row = con.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.DatabaseError as exc:
        return False, f"SQLite: {exc}"
    detail = str(row[0] if row else "неизвестный результат")
    return detail.lower() == "ok", detail


def _backup_quick_verification(name: str) -> dict[str, object]:
    try:
        db_file = backup_file(name, "db")
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "detail": str(exc)}
    sqlite_ok, sqlite_detail = _sqlite_integrity(db_file)
    config_file = backup_dir() / f"{name}.config.json"
    config_ok = True
    config_detail = "config.json не сохранён"
    if config_file.exists():
        try:
            document = json.loads(config_file.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("корень config.json должен быть объектом")
            config_detail = "config.json читается"
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            config_ok = False
            config_detail = f"config.json: {exc}"
    return {
        "ok": sqlite_ok and config_ok,
        "detail": f"SQLite: {sqlite_detail}; {config_detail}",
    }


def verify_backup(name: str) -> dict[str, object]:
    """Verify a backup without changing the live database or configuration."""
    name = _safe_backup_name(name)
    source = backup_file(name, "db")
    quick = _backup_quick_verification(name)
    if not quick["ok"]:
        return {"name": name, "ok": False, "detail": quick["detail"], "users": 0}
    try:
        with tempfile.TemporaryDirectory(prefix="sg-panel-verify-") as temp_dir:
            candidate = Path(temp_dir) / "panel.db"
            shutil.copy2(source, candidate)
            with use_db_path(candidate):
                init_db()
                validation = validate_generated_config()
    except (OSError, sqlite3.DatabaseError, ValueError, XPanelError) as exc:
        return {"name": name, "ok": False, "detail": str(exc), "users": 0}
    return {
        "name": name,
        "ok": bool(validation["ok"]),
        "detail": str(validation.get("detail") or "Configuration OK"),
        "users": int(validation.get("users") or 0),
    }


def create_backup() -> dict[str, object]:
    target = backup_dir()
    now = datetime.now(timezone.utc)
    for offset in range(120):
        stamp = (now + timedelta(seconds=offset)).strftime("%Y%m%d-%H%M%S")
        name = f"sg-panel-{stamp}"
        db_target = target / f"{name}.db"
        if not db_target.exists():
            break
    else:
        raise XPanelError("не удалось подобрать уникальное имя резервной копии")
    _clone_live_database(db_target)
    server = get_server()
    config_source = Path(server["config_path"])
    config_target = target / f"{name}.config.json"
    if config_source.exists():
        shutil.copy2(config_source, config_target)
    with connect() as con:
        central_clients = int(con.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        deployments = int(con.execute("SELECT COUNT(*) FROM node_deployments WHERE state!='removed'").fetchone()[0])
        failover_batches = int(con.execute("SELECT COUNT(*) FROM client_failover_batches").fetchone()[0])
    manifest = {
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database": db_target.name,
        "config": config_target.name if config_target.exists() else None,
        "central_client_database": {
            "clients": central_clients,
            "deployments": deployments,
            "failover_batches": failover_batches,
        },
    }
    (target / f"{name}.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    quick = _backup_quick_verification(name)
    prune_panel_backups()
    return {
        **manifest,
        "size": db_target.stat().st_size,
        "verified": bool(quick["ok"]),
        "verification_detail": quick["detail"],
    }


def list_backups() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for db_file in sorted(backup_dir().glob("sg-panel-*.db"), reverse=True):
        name = db_file.stem
        manifest_file = db_file.with_suffix(".json")
        created = datetime.fromtimestamp(db_file.stat().st_mtime, timezone.utc).isoformat()
        config_file = backup_dir() / f"{name}.config.json"
        central_client_database: dict[str, object] = {}
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                created = manifest.get("created_at", created)
                if isinstance(manifest.get("central_client_database"), dict):
                    central_client_database = manifest["central_client_database"]
            except (json.JSONDecodeError, OSError):
                pass
        verification = _backup_quick_verification(name)
        result.append(
            {
                "name": name,
                "created_at": created,
                "size": db_file.stat().st_size,
                "size_human": format_bytes(db_file.stat().st_size),
                "has_config": config_file.exists(),
                "central_clients": int(central_client_database.get("clients") or 0),
                "deployments": int(central_client_database.get("deployments") or 0),
                "failover_batches": int(central_client_database.get("failover_batches") or 0),
                "verified": bool(verification["ok"]),
                "verification_detail": verification["detail"],
            }
        )
    return result


def backup_file(name: str, kind: str = "db") -> Path:
    name = _safe_backup_name(name)
    suffix = ".db" if kind == "db" else ".config.json"
    path = backup_dir() / f"{name}{suffix}"
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def restore_backup(name: str) -> dict[str, object]:
    """Restore the database, regenerate config.json and roll back on failure."""
    require_root()
    name = _safe_backup_name(name)
    verification = verify_backup(name)
    if not verification["ok"]:
        raise XPanelError(
            "резервная копия не прошла проверку и не может быть восстановлена:\n"
            + str(verification["detail"])
        )

    source = backup_file(name, "db")
    safety = create_backup()
    current = db_path()
    restore_temp = current.with_suffix(".restore.tmp")
    rollback_temp = current.with_suffix(".rollback.tmp")
    try:
        shutil.copy2(source, restore_temp)
        os.replace(restore_temp, current)
        init_db()
        applied = apply_config()
        return {
            "name": name,
            "safety": str(safety["name"]),
            "users": verification["users"],
            "config_path": applied["config_path"],
            "service": applied["service"],
            "rolled_back": False,
        }
    except Exception as exc:
        try:
            safety_db = backup_file(str(safety["name"]), "db")
            shutil.copy2(safety_db, rollback_temp)
            os.replace(rollback_temp, current)
            init_db()
            apply_config()
        except Exception as rollback_exc:
            raise XPanelError(
                "восстановление не удалось, автоматический откат также завершился ошибкой: "
                f"{rollback_exc}; исходная ошибка: {exc}"
            ) from exc
        raise XPanelError(
            "восстановление не применено; предыдущее рабочее состояние автоматически возвращено: "
            + str(exc)
        ) from exc
    finally:
        restore_temp.unlink(missing_ok=True)
        rollback_temp.unlink(missing_ok=True)


def delete_backup(name: str) -> None:
    name = _safe_backup_name(name)
    for suffix in (".db", ".config.json", ".json"):
        (backup_dir() / f"{name}{suffix}").unlink(missing_ok=True)


def _read_os_release() -> str:
    path = Path("/etc/os-release")
    if not path.exists():
        return platform.platform()
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values.get("PRETTY_NAME", platform.platform())


def get_diagnostics() -> dict[str, object]:
    server = get_server()
    xray_version = _run([server["xray_bin"], "version"]).stdout.splitlines()
    disk = shutil.disk_usage("/")
    mem_total = mem_available = 0
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                mem_available = int(line.split()[1]) * 1024
    tcp_ports = _run(["ss", "-lntp"]).stdout
    udp_ports = _run(["ss", "-lnup"]).stdout
    ports = "TCP:\n" + tcp_ports + "\nUDP:\n" + udp_ports
    logs = _run(["journalctl", "-u", server["xray_service"], "-n", "80", "--no-pager"]).stdout
    panel_logs = _run(["journalctl", "-u", "xpanel-web", "-n", "50", "--no-pager"]).stdout
    nginx_logs = _run(["journalctl", "-u", "nginx", "-n", "50", "--no-pager"]).stdout
    dns_settings = get_dns_settings()
    dns_servers = list_dns_servers()
    dns_test = test_dns_resolution("example.com")
    warp = get_warp_overview()
    warp_endpoint = ""
    if warp["configured"]:
        try:
            warp_endpoint = str(
                build_warp_outbound()["settings"]["peers"][0]["endpoint"]
            )
        except (KeyError, IndexError, TypeError, ValueError, XPanelError):
            warp_endpoint = "не определён"
    routing = get_routing_settings()
    return {
        "os": _read_os_release(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "xray_version": xray_version[0] if xray_version else "unknown",
        "xray_service": (_run(["systemctl", "is-active", server["xray_service"]]).stdout.strip()),
        "panel_service": (_run(["systemctl", "is-active", "xpanel-web"]).stdout.strip()),
        "nginx_service": (_run(["systemctl", "is-active", "nginx"]).stdout.strip()),
        "disk_total": format_bytes(disk.total),
        "disk_free": format_bytes(disk.free),
        "memory_total": format_bytes(mem_total),
        "memory_available": format_bytes(mem_available),
        "memory_used": format_bytes(max(mem_total - mem_available, 0)),
        "memory_used_percent": (
            round(max(mem_total - mem_available, 0) * 100 / mem_total)
            if mem_total
            else 0
        ),
        "ports": ports,
        "xray_logs": redact_hysteria_obfs_secrets(logs),
        "panel_logs": redact_hysteria_obfs_secrets(panel_logs),
        "nginx_logs": redact_hysteria_obfs_secrets(nginx_logs),
        "warp": warp,
        "warp_endpoint": warp_endpoint,
        "default_outbound_tag": routing["default_outbound_tag"],
        "server_address": server["address"],
        "server_port": server["port"],
        "inbound_profile": server["inbound_profile"],
        "transport_protocol": "TCP + UDP" if str(server["inbound_profile"]) == "xhttp_hysteria_tls" else ("UDP" if str(server["inbound_profile"]) == "hysteria2_tls" else "TCP"),
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "config_validation": validate_generated_config(),
        "dns_enabled": bool(dns_settings["enabled"]),
        "dns_query_strategy": dns_settings["query_strategy"],
        "dns_servers": [dict(row) for row in dns_servers],
        "dns_test": dns_test,
        "subscription_settings": dict(get_subscription_settings()),
        "subscription_users_enabled": len(
            [row for row in list_users() if row["subscription_enabled"]]
        ),
        "security_settings": dict(get_security_settings()),
        "security_overview": security_overview(),
    }


def diagnostic_report() -> str:
    data = get_diagnostics()
    validation = data["config_validation"]
    try:
        hysteria_report = get_hysteria_diagnostics()
        hysteria_lines = [
            f"{item['label']}: {item['status']} — {item['detail']}"
            for item in hysteria_report.get("checks", [])
            if str(item.get("key", "")).startswith("salamander")
        ]
    except Exception as exc:
        hysteria_lines = [
            "Hysteria2 obfuscation diagnostics: unavailable — "
            + redact_hysteria_obfs_secrets(exc)
        ]
    lines = [
        "SG-Panel diagnostic report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"OS: {data['os']}",
        f"Kernel: {data['kernel']}",
        f"Python: {data['python']}",
        f"Xray: {data['xray_version']}",
        f"Xray service: {data['xray_service']}",
        f"Panel service: {data['panel_service']}",
        f"Disk free: {data['disk_free']} / {data['disk_total']}",
        f"Memory used: {data['memory_used']} / {data['memory_total']} "
        f"({data['memory_used_percent']}%)",
        f"Memory available: {data['memory_available']}",
        f"Generated config: {'OK' if validation['ok'] else 'ERROR'}",
        f"DNS enabled: {data['dns_enabled']}",
        f"DNS query strategy: {data['dns_query_strategy']}",
        f"DNS servers: {len(data['dns_servers'])}",
        f"System resolution test: {'OK' if data['dns_test']['ok'] else 'ERROR'}",
        f"Subscriptions enabled: {bool(data['subscription_settings']['enabled'])}",
        f"Subscription user URLs: {data['subscription_users_enabled']}",
        f"Subscription base URL: {data['subscription_settings']['base_url'] or '(auto)'}",
        f"Admin IP allowlist: {bool(data['security_settings']['allowlist_enabled'])}",
        f"Active admin sessions: {data['security_overview']['active_sessions']}",
        f"Failed logins (24h): {data['security_overview']['failed_logins_24h']}",
        "",
        "Hysteria2 / Salamander:",
        *hysteria_lines,
        "",
        "Listening TCP and UDP ports:",
        str(data["ports"]),
        "",
        "Xray journal:",
        str(data["xray_logs"]),
        "",
        "Panel journal:",
        str(data["panel_logs"]),
    ]
    return "\n".join(lines)

# SG_GATEWAY_ALWAYS_ON_CHANNELS_V1_START
# Four independent Xray channels adapted from SG-Gateway V39.
# The legacy inbound_profile column is retained only for database compatibility;
# runtime and client exports are built from the always-on channel set below.

SG_ALWAYS_ON_CHANNELS_MARKER = "sg-gateway-always-on-v1"
SG_ALWAYS_ON_XHTTP_REALITY_DEFAULT_PORT = 8444
SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PORT = 8445
SG_ALWAYS_ON_HYSTERIA_DEFAULT_PORT = 8446
SG_ALWAYS_ON_XHTTP_REALITY_DEFAULT_PATH = "/sg-xhttp-reality"
SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PATH = "/sg-xhttp-tls"


def _ensure_xray_channels_table() -> None:
    init_db()
    with connect() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS xray_channels (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                reality_tcp_port INTEGER NOT NULL DEFAULT 443 CHECK (reality_tcp_port BETWEEN 1 AND 65535),
                xhttp_reality_port INTEGER NOT NULL DEFAULT 8444 CHECK (xhttp_reality_port BETWEEN 1 AND 65535),
                xhttp_reality_path TEXT NOT NULL DEFAULT '/sg-xhttp-reality',
                xhttp_reality_mode TEXT NOT NULL DEFAULT 'stream-one',
                xhttp_tls_port INTEGER NOT NULL DEFAULT 8445 CHECK (xhttp_tls_port BETWEEN 1 AND 65535),
                xhttp_tls_path TEXT NOT NULL DEFAULT '/sg-xhttp-tls',
                xhttp_tls_mode TEXT NOT NULL DEFAULT 'auto',
                hysteria2_port INTEGER NOT NULL DEFAULT 8446 CHECK (hysteria2_port BETWEEN 1 AND 65535),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        if con.execute("SELECT 1 FROM xray_channels WHERE id=1").fetchone() is not None:
            return

        server = con.execute(
            """
            SELECT inbound_profile, port, transport_port, xhttp_path,
                   xhttp_mode, xhttp_client_mode
            FROM server_settings WHERE id=1
            """
        ).fetchone()
        xhttp_primary = con.execute(
            "SELECT port, path FROM xhttp_inbounds WHERE id=1"
        ).fetchone()
        hysteria_primary = con.execute(
            "SELECT port FROM hysteria_inbounds WHERE id=1"
        ).fetchone()

        profile = str(server["inbound_profile"] or "raw_reality") if server else "raw_reality"
        legacy_port = int(server["port"] or 443) if server else 443
        legacy_transport_port = (
            int(server["transport_port"] or SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PORT)
            if server else SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PORT
        )
        legacy_xhttp_port = (
            int(xhttp_primary["port"] or legacy_transport_port)
            if xhttp_primary else legacy_transport_port
        )
        legacy_xhttp_path = str(
            (server["xhttp_path"] if server else "")
            or (xhttp_primary["path"] if xhttp_primary else "")
            or SG_ALWAYS_ON_XHTTP_REALITY_DEFAULT_PATH
        )
        if not legacy_xhttp_path.startswith("/"):
            legacy_xhttp_path = "/" + legacy_xhttp_path
        legacy_hysteria_port = (
            int(hysteria_primary["port"] or SG_ALWAYS_ON_HYSTERIA_DEFAULT_PORT)
            if hysteria_primary else SG_ALWAYS_ON_HYSTERIA_DEFAULT_PORT
        )

        used_tcp: set[int] = set()

        def reserve(preferred: int, *fallbacks: int) -> int:
            candidates = [preferred, *fallbacks, 8444, 8445, 8443, 9443, 9444, 10443]
            for candidate in candidates:
                port = int(candidate)
                if 1 <= port <= 65535 and port not in used_tcp:
                    used_tcp.add(port)
                    return port
            for port in range(20000, 65536):
                if port not in used_tcp:
                    used_tcp.add(port)
                    return port
            raise XPanelError("не удалось подобрать свободные порты для Always-On Xray")

        # The channel that was active before FIX36 keeps its public port and Path.
        # This is essential: existing imported links must not silently become invalid
        # merely because the panel gained additional independent channels.
        if profile == "xhttp_reality":
            xhttp_reality_port = reserve(legacy_port)
            reality_port = reserve(SG_ALWAYS_ON_XHTTP_REALITY_DEFAULT_PORT)
        else:
            reality_port = reserve(legacy_port)
            xhttp_reality_port = reserve(SG_ALWAYS_ON_XHTTP_REALITY_DEFAULT_PORT)

        if profile in {"xhttp_tls", "xhttp_hysteria_tls"}:
            xhttp_tls_port = reserve(legacy_xhttp_port, legacy_transport_port)
        else:
            xhttp_tls_port = reserve(
                legacy_xhttp_port if legacy_xhttp_port not in used_tcp else SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PORT,
                SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PORT,
            )

        # UDP and TCP may use the same numeric port, therefore Hysteria is kept
        # exactly where it was when it was the active profile.
        hysteria_port = legacy_port if profile == "hysteria2_tls" else legacy_hysteria_port
        if not 1 <= hysteria_port <= 65535:
            hysteria_port = SG_ALWAYS_ON_HYSTERIA_DEFAULT_PORT

        xhttp_reality_mode = VLESSENC_CLIENT_MODE_DEFAULT
        xhttp_tls_mode = str(
            (server["xhttp_mode"] if server else "")
            or VLESSENC_TLS_CLIENT_MODE_DEFAULT
        ).strip().lower()
        if xhttp_tls_mode not in ALLOWED_XHTTP_MODES:
            xhttp_tls_mode = VLESSENC_TLS_CLIENT_MODE_DEFAULT

        xhttp_tls_path = str(
            (xhttp_primary["path"] if xhttp_primary else "")
            or SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PATH
        )
        if not xhttp_tls_path.startswith("/"):
            xhttp_tls_path = "/" + xhttp_tls_path
        if xhttp_tls_path.rstrip("/") == legacy_xhttp_path.rstrip("/"):
            xhttp_tls_path = SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PATH
            if xhttp_tls_path.rstrip("/") == legacy_xhttp_path.rstrip("/"):
                xhttp_tls_path = "/sg-xhttp-tls-alt"

        con.execute(
            """
            INSERT INTO xray_channels (
                id, reality_tcp_port, xhttp_reality_port, xhttp_reality_path,
                xhttp_reality_mode, xhttp_tls_port, xhttp_tls_path,
                xhttp_tls_mode, hysteria2_port
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reality_port,
                xhttp_reality_port,
                legacy_xhttp_path,
                xhttp_reality_mode,
                xhttp_tls_port,
                xhttp_tls_path,
                xhttp_tls_mode,
                hysteria_port,
            ),
        )


def get_xray_channels_settings() -> sqlite3.Row:
    _ensure_xray_channels_table()
    with connect() as con:
        con.execute(
            "UPDATE xray_channels SET xhttp_reality_mode=? WHERE id=1 AND xhttp_reality_mode!=?",
            (VLESSENC_CLIENT_MODE_DEFAULT, VLESSENC_CLIENT_MODE_DEFAULT),
        )
        con.execute(
            "UPDATE server_settings SET xhttp_client_mode=? WHERE id=1 AND xhttp_client_mode!=?",
            (VLESSENC_CLIENT_MODE_DEFAULT, VLESSENC_CLIENT_MODE_DEFAULT),
        )
        row = con.execute("SELECT * FROM xray_channels WHERE id=1").fetchone()
    if row is None:
        raise XPanelError("не удалось создать настройки каналов Xray")
    return row


def _always_on_path(value: object, default: str) -> str:
    path = str(value or default).strip()
    if not path.startswith("/"):
        path = "/" + path
    _validate_xhttp_path(path)
    return path


def _always_on_mode(value: object, default: str) -> str:
    mode = str(value or default).strip().lower()
    if mode not in ALLOWED_XHTTP_MODES:
        raise ValueError("неподдерживаемый XHTTP mode")
    return mode


def update_xray_channels_settings(form: object) -> sqlite3.Row:
    current = get_xray_channels_settings()
    getter = getattr(form, "get", None)
    if getter is None:
        raise ValueError("не переданы настройки каналов Xray")

    def form_value(name: str, fallback: object) -> object:
        value = getter(name, fallback)
        return fallback if value is None or str(value).strip() == "" else value

    reality_port = int(form_value("port", current["reality_tcp_port"]))
    xhttp_reality_port = int(form_value("xhttp_reality_port", current["xhttp_reality_port"]))
    xhttp_tls_port = int(form_value("transport_port", current["xhttp_tls_port"]))
    hysteria_port = int(form_value("hysteria2_port", current["hysteria2_port"]))
    for label, port in (
        ("VLESS Reality TCP", reality_port),
        ("VLESS XHTTP Reality", xhttp_reality_port),
        ("VLESS XHTTP TLS", xhttp_tls_port),
        ("Hysteria 2", hysteria_port),
    ):
        if not 1 <= port <= 65535:
            raise ValueError(f"{label}: порт должен быть от 1 до 65535")
    tcp_ports = [reality_port, xhttp_reality_port, xhttp_tls_port]
    if len(tcp_ports) != len(set(tcp_ports)):
        raise ValueError("Reality TCP, XHTTP Reality и XHTTP TLS должны использовать разные TCP-порты")

    xhttp_reality_path = _always_on_path(
        form_value("xhttp_path", current["xhttp_reality_path"]),
        SG_ALWAYS_ON_XHTTP_REALITY_DEFAULT_PATH,
    )
    xhttp_tls_path = _always_on_path(
        form_value("xhttp_tls_path", current["xhttp_tls_path"]),
        SG_ALWAYS_ON_XHTTP_TLS_DEFAULT_PATH,
    )
    if xhttp_reality_path.rstrip("/") == xhttp_tls_path.rstrip("/"):
        raise ValueError("XHTTP Reality и XHTTP TLS должны использовать разные Path")
    # Direct XHTTP REALITY is a proven fixed contract: server auto, client stream-one.
    xhttp_reality_mode = VLESSENC_CLIENT_MODE_DEFAULT
    xhttp_tls_mode = _always_on_mode(
        form_value("xhttp_mode", current["xhttp_tls_mode"]),
        VLESSENC_TLS_CLIENT_MODE_DEFAULT,
    )

    with connect() as con:
        con.execute(
            """
            INSERT INTO xray_channels (
                id, reality_tcp_port, xhttp_reality_port, xhttp_reality_path,
                xhttp_reality_mode, xhttp_tls_port, xhttp_tls_path,
                xhttp_tls_mode, hysteria2_port, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                reality_tcp_port=excluded.reality_tcp_port,
                xhttp_reality_port=excluded.xhttp_reality_port,
                xhttp_reality_path=excluded.xhttp_reality_path,
                xhttp_reality_mode=excluded.xhttp_reality_mode,
                xhttp_tls_port=excluded.xhttp_tls_port,
                xhttp_tls_path=excluded.xhttp_tls_path,
                xhttp_tls_mode=excluded.xhttp_tls_mode,
                hysteria2_port=excluded.hysteria2_port,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                reality_port,
                xhttp_reality_port,
                xhttp_reality_path,
                xhttp_reality_mode,
                xhttp_tls_port,
                xhttp_tls_path,
                xhttp_tls_mode,
                hysteria_port,
            ),
        )
        # Keep legacy fields synchronized so older diagnostics and Expert pages
        # continue to show the authoritative primary values.
        con.execute(
            """
            UPDATE server_settings
            SET inbound_profile='raw_reality', port=?, transport_port=?,
                xhttp_path=?, xhttp_mode=?, xhttp_client_mode=?
            WHERE id=1
            """,
            (
                reality_port,
                xhttp_tls_port,
                xhttp_reality_path,
                xhttp_tls_mode,
                xhttp_reality_mode,
            ),
        )
        con.execute(
            "UPDATE reality_inbounds SET enabled=1, port=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (reality_port,),
        )
        con.execute(
            "UPDATE xhttp_inbounds SET enabled=1, port=?, path=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (xhttp_tls_port, xhttp_tls_path),
        )
        con.execute(
            "UPDATE hysteria_inbounds SET enabled=1, port=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (hysteria_port,),
        )
    return get_xray_channels_settings()


def _always_on_https_material(server: sqlite3.Row) -> dict[str, object]:
    edge = _reality_edge_settings(server)
    if edge.get("enabled"):
        return {
            "ready": True,
            "domain": str(edge["domain"]),
            "cert": str(edge["cert"]),
            "key": str(edge["key"]),
            "message": "Домен и сертификат готовы",
        }
    return {
        "ready": False,
        "domain": "",
        "cert": "",
        "key": "",
        "message": "Нужен собственный домен и HTTPS в Security",
    }


def get_xray_channels_overview() -> dict[str, object]:
    server = get_server()
    values = get_xray_channels_settings()
    https = _always_on_https_material(server)
    encryption = controller_xray_encryption_status()
    active = _run(["systemctl", "is-active", "--quiet", str(server["xray_service"])], timeout=5).returncode == 0
    active_tags: set[str] = set()
    try:
        current_payload = json.loads(Path(str(server["config_path"])).read_text(encoding="utf-8"))
        if isinstance(current_payload, dict):
            for inbound in current_payload.get("inbounds", []):
                if isinstance(inbound, dict) and inbound.get("tag"):
                    active_tags.add(str(inbound["tag"]))
    except (OSError, ValueError, TypeError):
        active_tags = set()

    def channel_status(tag: str, *, ready: bool, missing: str) -> str:
        if active and tag in active_tags:
            return "Работает сейчас"
        if ready:
            return "Готов к применению"
        return missing

    profiles = [
        {
            "id": "reality_tcp",
            "title": "VLESS Reality TCP",
            "transport": "RAW / TCP",
            "security": "REALITY",
            "flow": "xtls-rprx-vision",
            "port": int(values["reality_tcp_port"]),
            "path": "",
            "mode": "",
            "ready": True,
            "status": channel_status("vless-reality-in", ready=True, missing=""),
            "note": "Основной прямой Reality inbound с XTLS Vision.",
        },
        {
            "id": "xhttp_reality",
            "title": "VLESS XHTTP Reality",
            "transport": "XHTTP / TCP",
            "security": "REALITY",
            "flow": "xtls-rprx-vision",
            "port": int(values["xhttp_reality_port"]),
            "path": str(values["xhttp_reality_path"]),
            "mode": str(values["xhttp_reality_mode"]),
            "ready": bool(encryption.get("ready")),
            "status": channel_status(
                "sg-vless-xhttp-reality",
                ready=bool(encryption.get("ready")),
                missing="Нужен VLESS Encryption",
            ),
            "note": "XHTTP + REALITY с обязательными ML-KEM-768 и XTLS Vision.",
        },
        {
            "id": "xhttp_tls",
            "title": "VLESS XHTTP TLS",
            "transport": "XHTTP / TCP",
            "security": "TLS",
            "flow": "xtls-rprx-vision",
            "port": int(values["xhttp_tls_port"]),
            "path": str(values["xhttp_tls_path"]),
            "mode": str(values["xhttp_tls_mode"]),
            "ready": bool(https["ready"] and encryption.get("ready")),
            "status": (
                "Нужен HTTPS" if not https["ready"]
                else channel_status(
                    "sg-vless-xhttp-tls",
                    ready=bool(encryption.get("ready")),
                    missing="Нужен VLESS Encryption",
                )
            ),
            "note": "Прямой Xray TLS на отдельном TCP-порту; Nginx transport не требуется.",
        },
        {
            "id": "hysteria2",
            "title": "Hysteria 2",
            "transport": "QUIC / UDP",
            "security": "TLS",
            "flow": "",
            "port": int(values["hysteria2_port"]),
            "path": "",
            "mode": "",
            "ready": bool(https["ready"]),
            "status": (
                "Нужен HTTPS"
                if not https["ready"]
                else channel_status("sg-hysteria2", ready=True, missing="")
            ),
            "note": "Отдельный Hysteria 2 inbound на собственном UDP-порту.",
        },
    ]
    return {
        "profiles": profiles,
        "https_ready": bool(https["ready"]),
        "https_domain": str(https["domain"]),
        "https_message": str(https["message"]),
        "encryption_ready": bool(encryption.get("ready")),
        "encryption": encryption,
        "service_active": active,
        "settings": values,
        "model": SG_ALWAYS_ON_CHANNELS_MARKER,
    }


_sg_legacy_build_managed_config = _build_managed_config


def _build_managed_config() -> tuple[dict, sqlite3.Row, list[sqlite3.Row]]:
    """Build one Xray config with every server channel that is technically ready.

    The legacy ``inbound_profile`` column remains for backward-compatible data
    migration and diagnostics, but it no longer selects a mutually exclusive
    runtime profile.  Reality TCP and XHTTP Reality are always present.  XHTTP
    TLS and Hysteria 2 join the same config automatically when HTTPS material is
    available.  Optional instances 2 and 3 remain Expert-only reserve entries.
    """
    server = get_server()
    values = get_xray_channels_settings()
    validate_server_values(
        server["address"],
        int(values["reality_tcp_port"]),
        server["dest"],
        server["server_name"],
        server["private_key"],
        server["public_key"],
        server["short_id"],
        flow="xtls-rprx-vision",
        loglevel=server["loglevel"],
        api_listen=server["api_listen"],
        listen=server["listen"],
        inbound_profile="raw_reality",
        transport_listen="127.0.0.1",
        transport_port=int(values["xhttp_tls_port"]),
        xhttp_path=str(values["xhttp_reality_path"]),
        xhttp_mode=str(values["xhttp_tls_mode"]),
        grpc_service_name=server["grpc_service_name"],
        tls_cert_path=server["tls_cert_path"],
        tls_key_path=server["tls_key_path"],
        hysteria_udp_idle_timeout=server["hysteria_udp_idle_timeout"],
        hysteria_masquerade_type=server["hysteria_masquerade_type"],
        hysteria_masquerade_url=server["hysteria_masquerade_url"],
        hysteria_masquerade_content=server["hysteria_masquerade_content"],
        hysteria_masquerade_status=server["hysteria_masquerade_status"],
    )
    with connect() as con:
        settings = con.execute("SELECT * FROM routing_settings WHERE id = 1").fetchone()
        rules = con.execute(
            "SELECT * FROM routing_rules WHERE enabled = 1 ORDER BY priority, id"
        ).fetchall()
        custom_outbounds = con.execute(
            "SELECT * FROM outbounds WHERE enabled = 1 ORDER BY id"
        ).fetchall()
    users = _active_access_identities()
    vless_clients: list[dict[str, object]] = [
        {
            "id": str(row["uuid"]),
            "email": str(row["name"]),
            "level": 0,
            "flow": "xtls-rprx-vision",
        }
        for row in users
    ]
    pair = _controller_vless_encryption_pair()
    https = _always_on_https_material(server)
    inbounds: list[dict[str, object]] = []

    # 1. Classic VLESS Reality TCP + Vision.  Expert instances 2/3 are
    # consolidated into the one supported multi-port Vision handler.
    reality_instances = [row for row in list_reality_inbounds() if bool(row["enabled"])]
    if not reality_instances or int(reality_instances[0]["id"]) != 1:
        raise XPanelError("Основной REALITY Inbound должен быть включён")
    _validate_reality_edge_listener_ports(server, reality_instances)
    inbounds.append(_build_reality_vision_inbound(server, reality_instances, vless_clients))

    # 2. VLESS XHTTP Reality + ML-KEM-768 + Vision, always available.
    xhttp_extra = _effective_xhttp_extra("server")
    xhttp_reality_settings: dict[str, object] = {
        "path": str(values["xhttp_reality_path"]),
        "mode": VLESSENC_SERVER_MODE_DEFAULT,
    }
    if xhttp_extra:
        xhttp_reality_settings["extra"] = xhttp_extra
    inbounds.append(
        {
            "tag": "sg-vless-xhttp-reality",
            "listen": "0.0.0.0",
            "port": int(values["xhttp_reality_port"]),
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": pair["decryption"]},
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": _reality_settings(server),
                "xhttpSettings": xhttp_reality_settings,
            },
        }
    )

    # 3/4. TLS channels become part of the same config automatically once the
    # panel has a real domain, certificate and private key.
    if https["ready"]:
        tls_settings = {
            "serverName": str(https["domain"]),
            "minVersion": "1.2",
            "alpn": ["h2", "http/1.1"],
            "certificates": [
                {
                    "certificateFile": str(https["cert"]),
                    "keyFile": str(https["key"]),
                }
            ],
        }
        xhttp_instances = [row for row in list_xhttp_inbounds() if bool(row["enabled"])]
        if not xhttp_instances or int(xhttp_instances[0]["id"]) != 1:
            raise XPanelError("Основной XHTTP TLS Inbound должен быть включён")
        for instance in xhttp_instances:
            instance_id = int(instance["id"])
            xhttp_tls_settings: dict[str, object] = {
                "path": (
                    str(values["xhttp_tls_path"])
                    if instance_id == 1
                    else str(instance["path"])
                ),
                "mode": VLESSENC_SERVER_MODE_DEFAULT,
            }
            if xhttp_extra:
                xhttp_tls_settings["extra"] = xhttp_extra
            inbounds.append(
                {
                    "tag": (
                        "sg-vless-xhttp-tls"
                        if instance_id == 1
                        else str(instance["tag"])
                    ),
                    "listen": (
                        "0.0.0.0"
                        if instance_id == 1
                        else str(instance["listen"])
                    ),
                    "port": (
                        int(values["xhttp_tls_port"])
                        if instance_id == 1
                        else int(instance["port"])
                    ),
                    "protocol": "vless",
                    "settings": {
                        "clients": vless_clients,
                        "decryption": pair["decryption"],
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": _copy_json_object(tls_settings),
                        "xhttpSettings": xhttp_tls_settings,
                    },
                }
            )

        hysteria_instances = [row for row in list_hysteria_inbounds() if bool(row["enabled"])]
        if not hysteria_instances or int(hysteria_instances[0]["id"]) != 1:
            raise XPanelError("Основной Hysteria 2 Inbound должен быть включён")
        auths = _ensure_device_hysteria_auths()
        hysteria_tls = _copy_json_object(tls_settings)
        hysteria_tls["minVersion"] = "1.3"
        hysteria_tls["alpn"] = ["h3"]
        for instance in hysteria_instances:
            inbound_id = int(instance["id"])
            auth_map = auths.get(inbound_id, {})
            hysteria_users = [
                {
                    "auth": str(auth_map[int(row["id"])]),
                    "email": str(row["name"]),
                    "level": 0,
                }
                for row in users
            ]
            inbounds.append(
                {
                    "tag": "sg-hysteria2" if inbound_id == 1 else str(instance["tag"]),
                    "listen": str(instance["listen"]),
                    "port": (
                        int(values["hysteria2_port"])
                        if inbound_id == 1
                        else int(instance["port"])
                    ),
                    "protocol": "hysteria",
                    "settings": {"version": 2, "users": hysteria_users},
                    "streamSettings": {
                        "network": "hysteria",
                        "security": "tls",
                        "tlsSettings": _copy_json_object(hysteria_tls),
                        "hysteriaSettings": {
                            "version": 2,
                            "udpIdleTimeout": int(server["hysteria_udp_idle_timeout"] or 60),
                            "masquerade": _hysteria_masquerade(server),
                        },
                        "finalmask": {"quicParams": _hysteria_quic_params(server)},
                    },
                }
            )

    for inbound in inbounds:
        _apply_transport_expert_to_inbound(inbound)

    if settings["sniffing_enabled"]:
        dest_override = []
        if settings["sniff_http"]:
            dest_override.append("http")
        if settings["sniff_tls"]:
            dest_override.append("tls")
        if settings["sniff_quic"]:
            dest_override.append("quic")
        for inbound in inbounds:
            inbound["sniffing"] = {
                "enabled": True,
                "destOverride": dest_override,
                "routeOnly": bool(settings["sniffing_route_only"]),
            }

    routing_config = _json_object(settings["extra_json"])
    routing_config.pop("_sgPanel", None)
    routing_config["domainStrategy"] = settings["domain_strategy"]
    routing_config["rules"] = [build_rule_json(row) for row in rules]
    config: dict[str, object] = {
        "log": {"loglevel": server["loglevel"]},
        "inbounds": inbounds,
        "outbounds": [],
        "routing": routing_config,
    }
    dns_config = build_dns_json()
    if dns_config is not None:
        config["dns"] = dns_config
    available_outbounds: dict[str, dict[str, object]] = {
        "direct": {"tag": "direct", "protocol": "freedom", "settings": {}},
        "blocked": {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    }
    warp = get_warp_overview()
    if warp["enabled"]:
        available_outbounds[WARP_TAG] = build_warp_outbound()
    for row in custom_outbounds:
        available_outbounds[str(row["tag"])] = build_outbound_json(row)

    default_tag = str(settings["default_outbound_tag"] or "direct")
    json_only_tags = {str(item["tag"]) for item in _json_only_outbounds()}
    all_available_tags = set(available_outbounds) | json_only_tags
    if default_tag == "blocked" or default_tag not in all_available_tags:
        raise XPanelError("некорректный или отключённый outbound по умолчанию")
    referenced_tags = {
        str(row["outbound_tag"])
        for row in rules
        if (row["target_type"] or "outbound") == "outbound"
    }
    missing = sorted(referenced_tags - all_available_tags)
    if missing:
        raise XPanelError(
            "routing rules ссылаются на отсутствующие outbounds: " + ", ".join(missing)
        )
    balancer_tags = _balancer_tags_from_extra(routing_config)
    missing_balancers = sorted(
        {
            str(row["outbound_tag"])
            for row in rules
            if row["target_type"] == "balancer"
        }
        - balancer_tags
    )
    if missing_balancers:
        raise XPanelError(
            "routing rules ссылаются на отсутствующие balancers: "
            + ", ".join(missing_balancers)
        )

    ordered_tags = [default_tag] if default_tag in available_outbounds else []
    ordered_tags.extend(tag for tag in available_outbounds if tag != default_tag)
    config["outbounds"] = [available_outbounds[tag] for tag in ordered_tags]

    if server["stats_enabled"]:
        config["api"] = {
            "tag": "api",
            "listen": server["api_listen"],
            "services": ["StatsService"],
        }
        config["stats"] = {}
        config["policy"] = {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "statsUserOnline": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        }
    return config, server, users


def _always_on_title(user_name: str, label: str, instance_id: int = 1) -> str:
    base = f"{str(user_name).strip()} · {label}"
    return base if int(instance_id) <= 1 else f"{base}/Профиль {int(instance_id)}"


def _always_on_retitle(items: list[dict[str, object]], user_name: str, label: str, priority: int) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for item in items:
        instance_id = int(item.get("id") or 1)
        title = _always_on_title(user_name, label, instance_id)
        result.append({
            **item,
            "client_title": title,
            "transport_priority": priority + max(instance_id - 1, 0),
            "link": _link_with_visible_title(str(item.get("link") or ""), title),
            "active": True,
        })
    return result


def make_links(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> list[dict[str, object]]:
    server = get_server()
    person = find_user(identifier)
    user = _access_identity(int(person["id"]), device_id)
    if (not bool(user["enabled"]) or _expiry_is_past(user["expiry_at"])) and not allow_disabled:
        raise XPanelError("доступ отключён или срок действия истёк")
    values = get_xray_channels_settings()
    pair = _controller_vless_encryption_pair()
    address = str(server["address"] or "").strip()
    fp = quote(fingerprint_for_xray(str(server["fingerprint"])), safe="")
    reality_sni = quote(str(server["server_name"] or ""), safe="")
    links: list[dict[str, object]] = []

    links.extend(
        _always_on_retitle(
            _make_links_for_profile(user, server, "raw_reality"),
            str(user["name"]),
            "Reality TCP",
            10,
        )
    )

    encrypted = quote(pair["encryption"], safe="-._~")
    reality_mode_value = str(values["xhttp_reality_mode"] or VLESSENC_CLIENT_MODE_DEFAULT)
    reality_mode = quote(reality_mode_value, safe="-_")
    xhttp_reality_title = _always_on_title(str(user["name"]), "XHTTP Reality")
    xhttp_reality_query = (
        f"encryption={encrypted}&flow=xtls-rprx-vision&type=xhttp&security=reality"
        f"&pbk={quote(str(server['public_key']), safe='-_')}&fp={fp}"
        f"&sni={reality_sni}&sid={quote(str(server['short_id']), safe='')}"
        f"&path={quote(str(values['xhttp_reality_path']), safe='')}"
        f"&mode={reality_mode}&spx=%2F{_client_expert_query('xhttp_reality')}"
    )
    links.append(
        {
            "id": 1,
            "key": "xhttp-reality-1",
            "profile": "xhttp_reality",
            "profile_label": "VLESS XHTTP Reality · Encryption + Vision",
            "kind": "xhttp",
            "name": "XHTTP Reality",
            "client_title": xhttp_reality_title,
            "tag": "sg-vless-xhttp-reality",
            "listen": "0.0.0.0",
            "port": int(values["xhttp_reality_port"]),
            "path": str(values["xhttp_reality_path"]),
            "flow": "xtls-rprx-vision",
            "encryption": pair["encryption"],
            "xhttp_server_mode": VLESSENC_SERVER_MODE_DEFAULT,
            "xhttp_client_mode": reality_mode_value,
            "transport_priority": 20,
            "active": True,
            "link": (
                f"vless://{user['uuid']}@{address}:{int(values['xhttp_reality_port'])}"
                f"?{xhttp_reality_query}#{quote(xhttp_reality_title, safe='')}"
            ),
        }
    )

    https = _always_on_https_material(server)
    if https["ready"]:
        domain = str(https["domain"])
        tls_sni = quote(domain, safe="")
        tls_mode_value = str(values["xhttp_tls_mode"] or VLESSENC_TLS_CLIENT_MODE_DEFAULT)
        tls_mode = quote(tls_mode_value, safe="-_")
        xhttp_instances = [row for row in list_xhttp_inbounds() if bool(row["enabled"])]
        for instance in xhttp_instances:
            instance_id = int(instance["id"])
            port = (
                int(values["xhttp_tls_port"])
                if instance_id == 1
                else int(instance["port"])
            )
            path = (
                str(values["xhttp_tls_path"])
                if instance_id == 1
                else str(instance["path"])
            )
            title = _always_on_title(str(user["name"]), "XHTTP TLS", instance_id)
            query = (
                f"encryption={encrypted}&flow=xtls-rprx-vision&type=xhttp&security=tls"
                f"&fp={fp}&sni={tls_sni}&host={quote(domain, safe='')}"
                f"&path={quote(path, safe='')}&mode={tls_mode}"
                f"{_client_expert_query('xhttp_tls')}"
            )
            links.append(
                {
                    "id": instance_id,
                    "key": f"xhttp-tls-{instance_id}",
                    "profile": "xhttp_tls",
                    "profile_label": "VLESS XHTTP TLS · Encryption + Vision",
                    "kind": "xhttp",
                    "name": str(instance["name"]),
                    "client_title": title,
                    "tag": "sg-vless-xhttp-tls" if instance_id == 1 else str(instance["tag"]),
                    "listen": "0.0.0.0" if instance_id == 1 else str(instance["listen"]),
                    "port": port,
                    "path": path,
                    "flow": "xtls-rprx-vision",
                    "encryption": pair["encryption"],
                    "xhttp_server_mode": VLESSENC_SERVER_MODE_DEFAULT,
                    "xhttp_client_mode": tls_mode_value,
                    "transport_priority": 30 + max(instance_id - 1, 0),
                    "active": True,
                    "deployment_public_host": domain,
                    "link": (
                        f"vless://{user['uuid']}@{domain}:{port}"
                        f"?{query}#{quote(title, safe='')}"
                    ),
                }
            )

        auths = _ensure_device_hysteria_auths()
        hysteria_instances = [row for row in list_hysteria_inbounds() if bool(row["enabled"])]
        hop_ports = str(server["hysteria_udp_hop_ports"] or "").strip()
        for instance in hysteria_instances:
            instance_id = int(instance["id"])
            port = (
                int(values["hysteria2_port"])
                if instance_id == 1
                else int(instance["port"])
            )
            authority_ports = hop_ports if instance_id == 1 and hop_ports else str(port)
            auth = str(auths[instance_id][int(user["id"])])
            title = _always_on_title(str(user["name"]), "Hysteria 2", instance_id)
            links.append(
                {
                    "id": instance_id,
                    "key": f"hysteria2-{instance_id}",
                    "profile": "hysteria2_tls",
                    "profile_label": "Hysteria 2",
                    "kind": "hysteria",
                    "name": str(instance["name"]),
                    "client_title": title,
                    "tag": "sg-hysteria2" if instance_id == 1 else str(instance["tag"]),
                    "listen": str(instance["listen"]),
                    "port": port,
                    "authority_ports": authority_ports,
                    "auth": auth,
                    "obfs_mode": str(instance["obfs_mode"] or "none"),
                    "obfs_password_configured": bool(instance["obfs_password"]),
                    "transport_priority": 40 + max(instance_id - 1, 0),
                    "active": True,
                    "deployment_public_host": domain,
                    "link": build_hysteria2_uri(
                        auth=auth,
                        host=domain,
                        port=authority_ports,
                        sni=domain,
                        profile_name=title,
                        obfs_mode=str(instance["obfs_mode"] or "none"),
                        obfs_password=(
                            str(instance["obfs_password"])
                            if instance["obfs_password"] is not None else None
                        ),
                    ),
                }
            )
    return links



def make_saved_links(
    identifier: str | int, allow_disabled: bool = False, *, device_id: int | None = None
) -> list[dict[str, object]]:
    return make_links(identifier, allow_disabled=allow_disabled, device_id=device_id)



_sg_legacy_managed_client_export_v2 = managed_client_export_v2


def managed_client_export_v2(
    identifier: str | int, *, device_id: int | None = None
) -> dict[str, object]:
    payload = _sg_legacy_managed_client_export_v2(identifier, device_id=device_id)
    payload["server"]["activeProfile"] = "all_available_channels"
    payload["server"]["activeProfiles"] = [
        str(item.get("profile") or "") for item in payload.get("connections", [])
    ]
    payload["server"]["channelModel"] = SG_ALWAYS_ON_CHANNELS_MARKER
    return payload




def _sg_sync_always_on_tls_material(server: sqlite3.Row) -> tuple[Path, Path]:
    https = _always_on_https_material(server)
    if not https["ready"]:
        raise XPanelError("HTTPS ещё не готов")
    source_cert = Path(str(https["cert"]))
    source_key = Path(str(https["key"]))
    _uid, gid = _xray_service_identity(str(server["xray_service"]))
    cert_path, key_path = _managed_hysteria_tls_paths()
    directory = cert_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    os.chown(directory, 0, gid)
    os.chmod(directory, 0o750)
    _copy_tls_file_atomic(source_cert, cert_path, gid)
    _copy_tls_file_atomic(source_key, key_path, gid)
    return cert_path, key_path


def _sg_runtime_all_tls_config_text(text: str, cert_path: Path, key_path: Path) -> str:
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise XPanelError(f"не удалось подготовить TLS runtime-конфигурацию: {exc}") from exc
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise XPanelError("не найден массив inbound")
    updated = 0
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict) or str(stream.get("security") or "").lower() != "tls":
            continue
        tls = stream.get("tlsSettings")
        if not isinstance(tls, dict):
            raise XPanelError("у TLS inbound отсутствует tlsSettings")
        certificates = tls.get("certificates")
        if not isinstance(certificates, list) or not certificates or not isinstance(certificates[0], dict):
            raise XPanelError("у TLS inbound отсутствует сертификат")
        certificates[0]["certificateFile"] = str(cert_path)
        certificates[0]["keyFile"] = str(key_path)
        updated += 1
    if not updated:
        raise XPanelError("не найден ни один TLS inbound")
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"


def validate_generated_config() -> dict[str, object]:
    text, server, users = render_text()
    https = _always_on_https_material(server)
    if https["ready"]:
        cert_path, key_path = _sg_sync_always_on_tls_material(server)
        text = _sg_runtime_all_tls_config_text(text, cert_path, key_path)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="sg-panel-", encoding="utf-8", delete=False
    ) as fh:
        fh.write(text)
        path = Path(fh.name)
    try:
        result = run_xray_test(server["xray_bin"], path)
        detail = (result.stderr or result.stdout).strip()
        return {
            "ok": result.returncode == 0,
            "detail": detail,
            "users": len(users),
            "json": text,
        }
    finally:
        path.unlink(missing_ok=True)


def apply_config() -> dict[str, object]:
    require_root()
    text, server, users = render_text()
    config_path = Path(server["config_path"])
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_name = tempfile.mkstemp(
        prefix=".config.", suffix=".json", dir=str(config_path.parent), text=True
    )
    temp_path = Path(temp_name)
    backup_path: Path | None = None
    nginx_snapshot = _snapshot_nginx_frontends()
    previous_config: bytes | None = config_path.read_bytes() if config_path.exists() else None
    tls_snapshot = _snapshot_hysteria_tls_material()
    https = _always_on_https_material(server)
    try:
        if https["ready"]:
            runtime_cert, runtime_key = _sg_sync_always_on_tls_material(server)
            text = _sg_runtime_all_tls_config_text(text, runtime_cert, runtime_key)
        temp_handle = os.fdopen(temp_fd, "w", encoding="utf-8")
        temp_fd = -1
        with temp_handle as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_path, 0o644)
        test = run_xray_test(server["xray_bin"], temp_path)
        if test.returncode != 0:
            detail = (test.stderr or test.stdout).strip()
            raise XPanelError(f"новый config.json не прошёл xray run -test:\n{detail}")

        if _reality_edge_settings(server).get("enabled"):
            _nginx_reality_edge_configs(server)
        if config_path.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            backup_path = config_path.with_name(f"{config_path.name}.bak-{stamp}")
            shutil.copy2(config_path, backup_path)

        _prepare_nginx_frontend()
        os.replace(temp_path, config_path)
        restart = _run(["systemctl", "restart", server["xray_service"]], timeout=30)
        if restart.returncode != 0:
            detail = (restart.stderr or restart.stdout).strip()
            raise XPanelError(f"Xray не перезапустился: {detail}")
        if _run(["systemctl", "is-active", "--quiet", server["xray_service"]]).returncode != 0:
            raise XPanelError("после перезапуска служба Xray не активна")

        frontend = _activate_nginx_frontend(server)
        return {
            "config_path": str(config_path),
            "backup_path": str(backup_path) if backup_path else None,
            "enabled_users": len(users),
            "enabled_rules": len([r for r in list_routing_rules() if r["enabled"]]),
            "service": "active",
            "profile": "all_available_channels",
            "active_channels": [
                str(item.get("tag") or "")
                for item in json.loads(text).get("inbounds", [])
                if isinstance(item, dict)
            ],
            "nginx_transport": False,
            "nginx_frontend": frontend,
            "channel_model": SG_ALWAYS_ON_CHANNELS_MARKER,
        }
    except Exception:
        try:
            if previous_config is None:
                config_path.unlink(missing_ok=True)
            else:
                config_path.write_bytes(previous_config)
                os.chmod(config_path, 0o644)
            _restore_hysteria_tls_material(tls_snapshot)
            _disable_nginx_transport(reload=False)
            _disable_reality_edge(reload=False)
            if shutil.which("nginx") is not None:
                _nginx_test_reload()
            _run(["systemctl", "restart", server["xray_service"]], timeout=30)
            _restore_nginx_frontends(nginx_snapshot)
        except Exception:
            pass
        raise
    finally:
        if temp_fd >= 0:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        temp_path.unlink(missing_ok=True)

# SG_GATEWAY_ALWAYS_ON_CHANNELS_V1_END
