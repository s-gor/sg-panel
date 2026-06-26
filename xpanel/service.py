from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import time
import sqlite3
import subprocess
import tempfile
import uuid as uuidlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from .db import PROJECT_ROOT, connect, db_path, init_db
from .security import get_security_settings, security_overview


class XPanelError(RuntimeError):
    pass


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
ALLOWED_INBOUND_PROFILES = {"raw_reality", "xhttp_tls", "xhttp_reality", "grpc_tls"}
TLS_INBOUND_PROFILES = {"xhttp_tls", "grpc_tls"}
REALITY_INBOUND_PROFILES = {"raw_reality", "xhttp_reality"}
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
WARP_DIR = Path(os.environ.get("XPANEL_WARP_DIR", "/etc/xpanel-mvp/warp"))
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
    return find_user(user["id"])


def regenerate_user_uuid(identifier: str | int) -> sqlite3.Row:
    user = find_user(identifier)
    with connect() as con:
        con.execute(
            "UPDATE users SET uuid = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (str(uuidlib.uuid4()), user["id"]),
        )
    return find_user(user["id"])


def set_user_enabled(identifier: str | int, enabled: bool) -> sqlite3.Row:
    user = find_user(identifier)
    with connect() as con:
        con.execute(
            "UPDATE users SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if enabled else 0, user["id"]),
        )
    return find_user(user["id"])


def delete_user(identifier: str | int) -> sqlite3.Row:
    user = find_user(identifier)
    with connect() as con:
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


def find_subscription_user(token: str) -> sqlite3.Row:
    init_db()
    token = token.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        raise XPanelError("подписка не найдена")
    with connect() as con:
        row = con.execute(
            "SELECT * FROM users WHERE subscription_token = ?", (token,)
        ).fetchone()
    if row is None:
        raise XPanelError("подписка не найдена")
    return row


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
    return find_user(user["id"])


def regenerate_subscription_token(identifier: str | int) -> sqlite3.Row:
    user = find_user(identifier)
    for _attempt in range(5):
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
            return find_user(user["id"])
        except sqlite3.IntegrityError:
            continue
    raise XPanelError("не удалось создать уникальный token подписки")


def record_subscription_access(identifier: str | int) -> None:
    user = find_user(identifier)
    with connect() as con:
        con.execute(
            """
            UPDATE users
            SET subscription_access_count = subscription_access_count + 1,
                subscription_last_access_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (user["id"],),
        )


def make_subscription_url(
    identifier: str | int, fallback_base_url: str = ""
) -> str:
    user = find_user(identifier)
    settings = get_subscription_settings()
    base_url = str(settings["base_url"] or "").strip()
    if not base_url:
        base_url = _normalise_subscription_base_url(fallback_base_url)
    if not base_url:
        raise XPanelError("задайте публичный URL подписок или откройте страницу через GUI")
    return f"{base_url.rstrip('/')}/sub/{user['subscription_token']}"


def subscription_is_available(user: sqlite3.Row) -> bool:
    settings = get_subscription_settings()
    return bool(
        settings["enabled"]
        and user["enabled"]
        and user["subscription_enabled"]
        and not user_is_expired(user)
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
        if item.startswith(allowed_prefixes):
            continue
        if len(item) > 512:
            raise ValueError("доменное условие слишком длинное")
    return "\n".join(result)


def validate_ips(value: str | None) -> str:
    result = split_values(value)
    for item in result:
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
    item: dict[str, object] = {"address": row["address"]}
    for key, column in (("domains", "domains"), ("expectedIPs", "expected_ips"), ("unexpectedIPs", "unexpected_ips")):
        values = split_values(row[column])
        if values:
            item[key] = values
    if row["query_strategy"]:
        item["queryStrategy"] = row["query_strategy"]
    if row["skip_fallback"]:
        item["skipFallback"] = True
    if row["final_query"]:
        item["finalQuery"] = True
    if int(row["timeout_ms"]) != 4000:
        item["timeoutMs"] = int(row["timeout_ms"])
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
    result: dict[str, object] = {
        "servers": [build_dns_server_json(row) for row in servers],
        "queryStrategy": settings["query_strategy"],
        "disableCache": bool(settings["disable_cache"]),
        "disableFallback": bool(settings["disable_fallback"]),
        "disableFallbackIfMatch": bool(settings["disable_fallback_if_match"]),
        "enableParallelQuery": bool(settings["enable_parallel_query"]),
        "useSystemHosts": bool(settings["use_system_hosts"]),
    }
    hosts: dict[str, object] = {}
    for row in list_dns_hosts(enabled_only=True):
        values = split_values(row["addresses"])
        hosts[str(row["domain"])] = values[0] if len(values) == 1 else values
    if hosts:
        result["hosts"] = hosts
    return result


def preview_dns_json() -> str:
    return json.dumps({"dns": build_dns_json()}, ensure_ascii=False, indent=2) + "\n"


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
                    inbound_tags = ?, users = ?, config_json = ?, updated_at = CURRENT_TIMESTAMP
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
    return {
        **dict(row),
        "configured": configured,
        "enabled": bool(row["enabled"]) and configured,
        "helper_installed": _warp_binary().is_file(),
        "default_domains": WARP_DEFAULT_DOMAINS,
    }


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
        saved_account = WARP_DIR / "wgcf.json"
        saved_account.write_text(account_text, encoding="utf-8")
        os.chmod(saved_account, 0o600)
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


def _find_warp_rule() -> sqlite3.Row | None:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM routing_rules WHERE name = ? COLLATE NOCASE",
            (WARP_RULE_NAME,),
        ).fetchone()


def configure_warp_routing(mode: str, selected_domains: str = "") -> dict[str, object]:
    mode = (mode or "off").strip().lower()
    if mode not in {"off", "selected", "all"}:
        raise ValueError("режим WARP должен быть off, selected или all")
    warp = get_warp_overview()
    if mode != "off" and not warp["enabled"]:
        raise XPanelError("включите WARP перед настройкой маршрута")
    domains = validate_domains(selected_domains)
    if mode == "selected" and not domains:
        raise ValueError("укажите хотя бы один домен для WARP")
    rule = _find_warp_rule()
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
            config = {
                "type": "field", "outboundTag": WARP_TAG,
                "domain": split_values(domains), "network": "tcp,udp",
            }
            if rule is None:
                con.execute(
                    """
                    INSERT INTO routing_rules
                        (name, priority, enabled, outbound_tag, target_type, domains, network,
                         config_json)
                    VALUES (?, 40, 1, ?, 'outbound', ?, 'tcp,udp', ?)
                    """,
                    (
                        WARP_RULE_NAME, WARP_TAG, domains,
                        json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                    ),
                )
            else:
                con.execute(
                    """
                    UPDATE routing_rules SET enabled = 1, outbound_tag = ?, target_type = 'outbound',
                        domains = ?, ips = '', ports = '', network = 'tcp,udp', protocols = '',
                        inbound_tags = '', users = '', config_json = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        WARP_TAG, domains,
                        json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                        int(rule["id"]),
                    ),
                )
        elif rule is not None:
            con.execute(
                "UPDATE routing_rules SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (int(rule["id"]),),
            )
        con.execute(
            """
            UPDATE warp_settings SET route_mode = ?, selected_domains = ?,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (mode, domains),
        )
    return get_warp_overview()


def delete_warp() -> None:
    require_root()
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
                route_mode = 'off', selected_domains = '', last_test_state = '',
                last_test_ip = '', last_test_at = NULL, created_at = NULL,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """
        )
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
    fingerprint: str = "chrome",
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
    fingerprint = fingerprint.strip() or "chrome"
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
                "fingerprint": cleaned["fingerprint"],
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
                "fingerprint": cleaned["fingerprint"],
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
                    "fingerprint": "chrome",
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
        fingerprint=str(security_settings.get("fingerprint", "chrome")),
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
    inbound_profile: str = "raw_reality",
    transport_listen: str = "127.0.0.1",
    transport_port: int = 8443,
    xhttp_path: str = "/sg-xhttp",
    xhttp_mode: str = "auto",
    grpc_service_name: str = "sg-grpc",
    tls_cert_path: str = "",
    tls_key_path: str = "",
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
    if profile != "raw_reality" and flow:
        raise ValueError("Flow используется только в профиле RAW/TCP + REALITY")
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

    if profile in {"xhttp_tls", "xhttp_reality"}:
        _validate_xhttp_path(xhttp_path)
        if xhttp_mode not in ALLOWED_XHTTP_MODES:
            raise ValueError("неподдерживаемый XHTTP mode")

    if profile == "grpc_tls":
        _validate_grpc_service_name(grpc_service_name)

    if profile in TLS_INBOUND_PROFILES:
        if not server_name or not server_name.strip():
            raise ValueError("для TLS укажите Server name / SNI")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", server_name.strip()):
            raise ValueError("Server name / SNI содержит недопустимые символы")
        if not transport_listen or not transport_listen.strip():
            raise ValueError("локальный listen Xray не может быть пустым")
        try:
            local_ip = ipaddress.ip_address(transport_listen.strip())
        except ValueError as exc:
            raise ValueError("локальный listen Xray должен быть IP-адресом") from exc
        if not local_ip.is_loopback:
            raise ValueError("для TLS-профиля Xray должен слушать только loopback-адрес")
        if not 1 <= int(transport_port) <= 65535:
            raise ValueError("локальный порт Xray должен быть от 1 до 65535")
        if not tls_cert_path or not tls_cert_path.strip():
            raise ValueError("укажите путь к TLS-сертификату")
        if not tls_key_path or not tls_key_path.strip():
            raise ValueError("укажите путь к TLS private key")
        if any(ch in tls_cert_path + tls_key_path for ch in "\r\n;"):
            raise ValueError("пути TLS содержат недопустимые символы")


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
) -> sqlite3.Row:
    current = get_server()
    profile = (inbound_profile or current["inbound_profile"] or "raw_reality").strip()
    previous_profile = str(current["inbound_profile"] or "raw_reality")
    normalized_server_name = (server_name or "").strip()
    reality_name = (dest or "").rsplit(":", 1)[0].strip().strip("[]")
    if profile != previous_profile:
        previous_name = str(current["server_name"] or "").strip()
        if profile in TLS_INBOUND_PROFILES and normalized_server_name in {"", previous_name, reality_name}:
            normalized_server_name = address.strip()
        elif profile in REALITY_INBOUND_PROFILES and normalized_server_name in {"", previous_name, address.strip()}:
            normalized_server_name = reality_name
    local_listen = (transport_listen or current["transport_listen"] or "127.0.0.1").strip()
    local_port = int(transport_port or current["transport_port"] or 8443)
    path = (xhttp_path or current["xhttp_path"] or "/sg-xhttp").strip()
    mode = (xhttp_mode or current["xhttp_mode"] or "auto").strip()
    service_name = (grpc_service_name or current["grpc_service_name"] or "sg-grpc").strip()
    default_cert, default_key = _default_tls_paths(address)
    cert_path = (tls_cert_path if tls_cert_path is not None else current["tls_cert_path"]).strip() or default_cert
    key_path = (tls_key_path if tls_key_path is not None else current["tls_key_path"]).strip() or default_key
    normalized_flow = flow if profile == "raw_reality" else ""

    validate_server_values(
        address,
        port,
        dest,
        normalized_server_name,
        private_key,
        public_key,
        short_id,
        flow=normalized_flow,
        loglevel=loglevel,
        api_listen=api_listen,
        inbound_profile=profile,
        transport_listen=local_listen,
        transport_port=local_port,
        xhttp_path=path,
        xhttp_mode=mode,
        grpc_service_name=service_name,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
    )
    fingerprint = fingerprint.strip()
    if not fingerprint or len(fingerprint) > 40:
        raise ValueError("fingerprint не может быть пустым")
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
                tls_cert_path = ?, tls_key_path = ?
            WHERE id = 1
            """,
            (
                address.strip(), listen.strip(), int(port), dest.strip(), normalized_server_name,
                private_key.strip(), public_key.strip(), short_id.strip(), fingerprint,
                normalized_flow, loglevel, api_listen.strip(), int(stats_enabled),
                config_path.strip(), xray_bin.strip(), xray_service.strip(),
                profile, local_listen, local_port, path, mode, service_name,
                cert_path, key_path,
            ),
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


def get_geodata_status() -> list[dict[str, object]]:
    roots: list[Path] = []
    env_root = os.environ.get("XRAY_LOCATION_ASSET", "").strip()
    if env_root:
        roots.append(Path(env_root))
    roots.extend([Path("/usr/local/share/xray"), Path("/usr/share/xray")])
    result: list[dict[str, object]] = []
    for filename in ("geoip.dat", "geosite.dat"):
        found: Path | None = None
        for root in roots:
            candidate = root / filename
            if candidate.is_file():
                found = candidate
                break
        if found:
            stat = found.stat()
            result.append(
                {
                    "name": filename,
                    "installed": True,
                    "path": str(found),
                    "size": stat.st_size,
                    "updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
            )
        else:
            result.append(
                {"name": filename, "installed": False, "path": "", "size": 0, "updated_at": ""}
            )
    return result


def _active_users(rows: list[sqlite3.Row]) -> list[sqlite3.Row]:
    return [row for row in rows if row["enabled"] and not user_is_expired(row)]


def _reality_settings(server: sqlite3.Row) -> dict[str, object]:
    return {
        "show": False,
        "dest": server["dest"],
        "xver": 0,
        "serverNames": [server["server_name"]],
        "privateKey": server["private_key"],
        "shortIds": [server["short_id"]],
    }


def _xhttp_settings(server: sqlite3.Row) -> dict[str, object]:
    settings: dict[str, object] = {"path": server["xhttp_path"]}
    if server["xhttp_mode"] and server["xhttp_mode"] != "auto":
        settings["mode"] = server["xhttp_mode"]
    return settings


def _build_primary_inbound(server: sqlite3.Row, clients: list[dict[str, object]]) -> dict[str, object]:
    profile = str(server["inbound_profile"] or "raw_reality")
    inbound: dict[str, object] = {
        "tag": "vless-reality-in",
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
    }
    if profile in TLS_INBOUND_PROFILES:
        inbound["listen"] = server["transport_listen"]
        inbound["port"] = server["transport_port"]
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
        inbound["streamSettings"] = {
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": _xhttp_settings(server),
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
        inbound_profile=server["inbound_profile"],
        transport_listen=server["transport_listen"],
        transport_port=server["transport_port"],
        xhttp_path=server["xhttp_path"],
        xhttp_mode=server["xhttp_mode"],
        grpc_service_name=server["grpc_service_name"],
        tls_cert_path=server["tls_cert_path"],
        tls_key_path=server["tls_key_path"],
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

    clients: list[dict[str, object]] = []
    for row in users:
        client: dict[str, object] = {"id": row["uuid"], "email": row["name"], "level": 0}
        if server["flow"]:
            client["flow"] = server["flow"]
        clients.append(client)

    inbound = _build_primary_inbound(server, clients)
    if settings["sniffing_enabled"]:
        dest_override = []
        if settings["sniff_http"]:
            dest_override.append("http")
        if settings["sniff_tls"]:
            dest_override.append("tls")
        if settings["sniff_quic"]:
            dest_override.append("quic")
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
        "inbounds": [inbound],
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
    merged = _merge_tagged_objects(base_items, managed_items)
    for item in merged:
        if str(item.get("tag", "")) != "vless-reality-in":
            continue
        base_match = None
        if isinstance(base_items, list):
            base_match = next(
                (candidate for candidate in base_items if isinstance(candidate, dict) and candidate.get("tag") == "vless-reality-in"),
                None,
            )
        if not isinstance(base_match, dict):
            break
        managed_match = next(
            (candidate for candidate in managed_items if candidate.get("tag") == "vless-reality-in"),
            None,
        )
        base_settings = base_match.get("settings")
        current_settings = item.get("settings")
        if isinstance(base_settings, dict) and isinstance(current_settings, dict):
            current_settings["clients"] = _merge_clients(
                base_settings.get("clients"), current_settings.get("clients")
            )
        if isinstance(managed_match, dict):
            base_stream = base_match.get("streamSettings")
            managed_stream = managed_match.get("streamSettings")
            if isinstance(managed_stream, dict):
                base_signature = (
                    str(base_stream.get("network", "")) if isinstance(base_stream, dict) else "",
                    str(base_stream.get("security", "")) if isinstance(base_stream, dict) else "",
                )
                managed_signature = (
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
        }
        settings = inbound.get("settings")
        if isinstance(settings, dict) and isinstance(settings.get("clients"), list):
            users_by_name = {str(row["name"]): row for row in list_users()}
            for client in settings["clients"]:
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


def _parse_full_config_users(inbound: dict[str, object]) -> tuple[list[dict[str, object]], str]:
    settings = inbound.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("inbound vless-reality-in: settings должен быть объектом")
    clients = settings.get("clients", [])
    if not isinstance(clients, list):
        raise ValueError("inbound vless-reality-in: settings.clients должен быть массивом")
    result: list[dict[str, object]] = []
    names: set[str] = set()
    uuids: set[str] = set()
    flows: set[str] = set()
    for index, client in enumerate(clients, start=1):
        if not isinstance(client, dict):
            raise ValueError(f"settings.clients[{index}] должен быть объектом")
        name = str(client.get("email", "")).strip()
        if not name or len(name) > 80:
            raise ValueError(f"settings.clients[{index}]: укажите email/имя до 80 символов")
        key = name.casefold()
        if key in names:
            raise ValueError(f"повторяющийся пользователь: {name}")
        names.add(key)
        user_uuid = str(client.get("id", "")).strip()
        try:
            uuidlib.UUID(user_uuid)
        except ValueError as exc:
            raise ValueError(f"пользователь {name}: некорректный UUID") from exc
        if user_uuid in uuids:
            raise ValueError(f"повторяющийся UUID пользователя: {user_uuid}")
        uuids.add(user_uuid)
        flow = str(client.get("flow", "") or "")
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
    if str(inbound.get("protocol", "")).lower() != "vless":
        raise ValueError("основной inbound должен использовать protocol: vless")

    network = str(stream.get("network", "tcp")).lower()
    if network == "raw":
        network = "tcp"
    security = str(stream.get("security", "none")).lower()
    profile = str(meta.get("profile", "")).strip()
    if profile not in ALLOWED_INBOUND_PROFILES:
        inferred = {
            ("tcp", "reality"): "raw_reality",
            ("xhttp", "reality"): "xhttp_reality",
            ("xhttp", "none"): "xhttp_tls",
            ("grpc", "none"): "grpc_tls",
        }
        profile = inferred.get((network, security), "")
    if profile not in ALLOWED_INBOUND_PROFILES:
        raise ValueError("не удалось определить профиль основного inbound")

    if profile == "raw_reality" and (network, security) != ("tcp", "reality"):
        raise ValueError("профиль RAW/TCP + REALITY не соответствует streamSettings")
    if profile == "xhttp_reality" and (network, security) != ("xhttp", "reality"):
        raise ValueError("профиль XHTTP + REALITY не соответствует streamSettings")
    if profile == "xhttp_tls" and (network, security) != ("xhttp", "none"):
        raise ValueError("для XHTTP + TLS Xray должен принимать локальный XHTTP без TLS")
    if profile == "grpc_tls" and (network, security) != ("grpc", "none"):
        raise ValueError("для gRPC + TLS Xray должен принимать локальный gRPC без TLS")

    address = str(meta.get("address") or current["address"])
    public_port = int(meta.get("publicPort") or current["port"] or 443)
    server_name = str(meta.get("serverName") or current["server_name"] or address)
    fingerprint = str(meta.get("fingerprint") or current["fingerprint"] or "chrome")
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
    if profile in {"xhttp_tls", "xhttp_reality"}:
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

    inbound_listen = str(inbound.get("listen", "0.0.0.0"))
    inbound_port = int(inbound.get("port", 0) or 0)
    if profile in TLS_INBOUND_PROFILES:
        listen = str(current["listen"] or "0.0.0.0")
        transport_listen = inbound_listen
        transport_port = inbound_port
    else:
        listen = inbound_listen
        transport_listen = str(meta.get("transportListen") or current["transport_listen"] or "127.0.0.1")
        transport_port = int(meta.get("transportPort") or current["transport_port"] or 8443)
        public_port = inbound_port

    default_cert, default_key = _default_tls_paths(address)
    tls_cert_path = str(meta.get("tlsCertPath") or current["tls_cert_path"] or default_cert)
    tls_key_path = str(meta.get("tlsKeyPath") or current["tls_key_path"] or default_key)

    log = document.get("log")
    log = log if isinstance(log, dict) else {}
    api = document.get("api")
    api = api if isinstance(api, dict) else {}
    normalized_flow = flow if profile == "raw_reality" else ""
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
    }
    validate_server_values(
        str(values["address"]), int(values["port"]), str(values["dest"]),
        str(values["server_name"]), str(values["private_key"]),
        str(values["public_key"]), str(values["short_id"]),
        flow=str(values["flow"]), loglevel=str(values["loglevel"]),
        api_listen=str(values["api_listen"]),
        inbound_profile=str(values["inbound_profile"]),
        transport_listen=str(values["transport_listen"]),
        transport_port=int(values["transport_port"]),
        xhttp_path=str(values["xhttp_path"]),
        xhttp_mode=str(values["xhttp_mode"]),
        grpc_service_name=str(values["grpc_service_name"]),
        tls_cert_path=str(values["tls_cert_path"]),
        tls_key_path=str(values["tls_key_path"]),
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
                "UPDATE dns_settings SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = 1"
            )
            return
        assert isinstance(settings, dict)
        con.execute(
            """
            UPDATE dns_settings SET enabled = 1, query_strategy = ?, disable_cache = ?,
                disable_fallback = ?, disable_fallback_if_match = ?,
                enable_parallel_query = ?, use_system_hosts = ?,
                updated_at = CURRENT_TIMESTAMP WHERE id = 1
            """,
            (
                settings["query_strategy"], int(settings["disable_cache"]),
                int(settings["disable_fallback"]),
                int(settings["disable_fallback_if_match"]),
                int(settings["enable_parallel_query"]), int(settings["use_system_hosts"]),
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
                int(item["final_query"]), item["timeout_ms"],
            )
            if row:
                con.execute(
                    """
                    UPDATE dns_servers SET address=?, priority=?, enabled=1, domains=?,
                        expected_ips=?, unexpected_ips=?, query_strategy=?, skip_fallback=?,
                        final_query=?, timeout_ms=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
                    """,
                    (*values, row["id"]),
                )
            else:
                con.execute(
                    """
                    INSERT INTO dns_servers
                        (name,address,priority,enabled,domains,expected_ips,unexpected_ips,
                         query_strategy,skip_fallback,final_query,timeout_ms)
                    VALUES (?,?,?,1,?,?,?,?,?,?,?)
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


def _nginx_transport_config(server: sqlite3.Row) -> str:
    profile = str(server["inbound_profile"])
    if profile not in TLS_INBOUND_PROFILES:
        raise ValueError("Nginx transport нужен только для TLS-профиля")
    cert = Path(str(server["tls_cert_path"]))
    key = Path(str(server["tls_key_path"]))
    if not cert.is_file():
        raise XPanelError(f"не найден TLS-сертификат: {cert}")
    if not key.is_file():
        raise XPanelError(f"не найден TLS private key: {key}")
    public_port = int(server["port"])
    target_host = str(server["transport_listen"])
    if ":" in target_host and not target_host.startswith("["):
        target_host = f"[{target_host}]"
    target = f"{target_host}:{server['transport_port']}"
    if profile == "xhttp_tls":
        path = str(server["xhttp_path"]).rstrip("/") + "/"
        proxy_block = f'''    location {path} {{
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
        grpc_pass grpc://{target};
    }}'''
    else:
        service = str(server["grpc_service_name"]).strip("/")
        proxy_block = f'''    location /{service} {{
        grpc_socket_keepalive on;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto $scheme;
        grpc_pass grpc://{target};
    }}'''
    return f'''# Managed by SG-Panel. Manual changes may be overwritten.
server {{
    listen {public_port} ssl http2;
    listen [::]:{public_port} ssl http2;
    server_name {server['server_name']};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SGXRAY:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

{proxy_block}

    location / {{
        root /var/www/sg-panel-placeholder;
        index index.html;
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;
    }}
}}
'''


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


def _enable_nginx_transport(server: sqlite3.Row) -> None:
    available, enabled = _nginx_transport_paths()
    available.parent.mkdir(parents=True, exist_ok=True)
    enabled.parent.mkdir(parents=True, exist_ok=True)
    temp = available.with_name(available.name + ".tmp")
    temp.write_text(_nginx_transport_config(server), encoding="utf-8")
    os.chmod(temp, 0o644)
    os.replace(temp, available)
    enabled.unlink(missing_ok=True)
    enabled.symlink_to(available)
    _nginx_test_reload()


def _disable_nginx_transport() -> bool:
    _available, enabled = _nginx_transport_paths()
    if not enabled.exists() and not enabled.is_symlink():
        return False
    enabled.unlink(missing_ok=True)
    _nginx_test_reload()
    return True


def _snapshot_nginx_transport() -> dict[str, object]:
    available, enabled = _nginx_transport_paths()
    return {
        "available_exists": available.exists(),
        "available_text": available.read_text(encoding="utf-8") if available.exists() else "",
        "enabled": enabled.exists() or enabled.is_symlink(),
    }


def _restore_nginx_transport(snapshot: dict[str, object]) -> None:
    available, enabled = _nginx_transport_paths()
    available.parent.mkdir(parents=True, exist_ok=True)
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.unlink(missing_ok=True)
    if snapshot.get("available_exists"):
        available.write_text(str(snapshot.get("available_text", "")), encoding="utf-8")
        os.chmod(available, 0o644)
    else:
        available.unlink(missing_ok=True)
    if snapshot.get("enabled") and available.exists():
        enabled.symlink_to(available)
    if shutil.which("nginx") is not None:
        _nginx_test_reload()


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
    nginx_snapshot = _snapshot_nginx_transport()
    previous_config: bytes | None = config_path.read_bytes() if config_path.exists() else None
    profile = str(server["inbound_profile"] or "raw_reality")
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_path, 0o644)
        test = run_xray_test(server["xray_bin"], temp_path)
        if test.returncode != 0:
            detail = (test.stderr or test.stdout).strip()
            raise XPanelError(f"новый config.json не прошёл xray run -test:\n{detail}")

        if profile in TLS_INBOUND_PROFILES:
            _nginx_transport_config(server)
        if config_path.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            backup_path = config_path.with_name(f"{config_path.name}.bak-{stamp}")
            shutil.copy2(config_path, backup_path)

        if profile not in TLS_INBOUND_PROFILES:
            _disable_nginx_transport()

        os.replace(temp_path, config_path)
        restart = _run(["systemctl", "restart", server["xray_service"]], timeout=30)
        if restart.returncode != 0:
            detail = (restart.stderr or restart.stdout).strip()
            raise XPanelError(f"Xray не перезапустился: {detail}")
        if _run(["systemctl", "is-active", "--quiet", server["xray_service"]]).returncode != 0:
            raise XPanelError("после перезапуска служба Xray не активна")

        if profile in TLS_INBOUND_PROFILES:
            _enable_nginx_transport(server)

        return {
            "config_path": str(config_path),
            "backup_path": str(backup_path) if backup_path else None,
            "enabled_users": len(users),
            "enabled_rules": len([r for r in list_routing_rules() if r["enabled"]]),
            "service": "active",
            "profile": profile,
            "nginx_transport": profile in TLS_INBOUND_PROFILES,
        }
    except Exception:
        try:
            if previous_config is None:
                config_path.unlink(missing_ok=True)
            else:
                config_path.write_bytes(previous_config)
                os.chmod(config_path, 0o644)
            _restore_nginx_transport(nginx_snapshot)
            _run(["systemctl", "restart", server["xray_service"]], timeout=30)
        except Exception:
            pass
        raise
    finally:
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


def get_user_stats(*, include_online: bool = True) -> dict[int, dict[str, object]]:
    users = list_users()
    server = get_server()
    try:
        raw = query_stats()
        error = ""
    except (XPanelError, FileNotFoundError) as exc:
        raw = {}
        error = str(exc)
    result: dict[int, dict[str, object]] = {}
    for user in users:
        prefix = f"user>>>{user['name']}>>>traffic>>>"
        uplink = int(raw.get(prefix + "uplink", 0))
        downlink = int(raw.get(prefix + "downlink", 0))
        online: bool | None = None
        if include_online and server["stats_enabled"] and not error:
            try:
                online = _query_online(server, user["name"])
            except XPanelError:
                online = None
        result[int(user["id"])] = {
            "uplink": uplink,
            "downlink": downlink,
            "total": uplink + downlink,
            "online": online,
            "error": error,
        }
    return result


def reset_stats() -> None:
    query_stats(reset=True)


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
        traffic_total = sum(item["total"] for item in get_user_stats(include_online=False).values())
    except Exception as exc:  # dashboard must stay available even if API is down
        stats_error = str(exc)
    profile_labels = {
        "raw_reality": "RAW/TCP + REALITY",
        "xhttp_tls": "XHTTP + TLS",
        "xhttp_reality": "XHTTP + REALITY",
        "grpc_tls": "gRPC + TLS",
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
    }


def make_link(identifier: str | int, allow_disabled: bool = False) -> str:
    server = get_server()
    user = find_user(identifier)
    if (not user["enabled"] or user_is_expired(user)) and not allow_disabled:
        raise XPanelError("пользователь отключён или срок действия истёк")
    name = quote(user["name"], safe="")
    profile = str(server["inbound_profile"] or "raw_reality")
    base = f"vless://{user['uuid']}@{server['address']}:{server['port']}"
    fp = quote(str(server["fingerprint"]), safe="")
    sni = quote(str(server["server_name"]), safe="")

    if profile == "raw_reality":
        flow = f"&flow={quote(server['flow'], safe='-_')}" if server["flow"] else ""
        query = (
            f"type=tcp&security=reality&pbk={quote(server['public_key'], safe='-_')}"
            f"&fp={fp}&sni={sni}&sid={quote(server['short_id'], safe='')}"
            f"{flow}&spx=%2F"
        )
    elif profile == "xhttp_reality":
        mode = "" if server["xhttp_mode"] == "auto" else f"&mode={quote(server['xhttp_mode'], safe='-_')}"
        query = (
            f"type=xhttp&security=reality&pbk={quote(server['public_key'], safe='-_')}"
            f"&fp={fp}&sni={sni}&sid={quote(server['short_id'], safe='')}"
            f"&path={quote(server['xhttp_path'], safe='')}{mode}&spx=%2F"
        )
    elif profile == "xhttp_tls":
        mode = "" if server["xhttp_mode"] == "auto" else f"&mode={quote(server['xhttp_mode'], safe='-_')}"
        query = (
            f"type=xhttp&security=tls&fp={fp}&sni={sni}"
            f"&host={quote(server['address'], safe='')}"
            f"&path={quote(server['xhttp_path'], safe='')}{mode}"
        )
    elif profile == "grpc_tls":
        query = (
            f"type=grpc&security=tls&fp={fp}&sni={sni}"
            f"&serviceName={quote(server['grpc_service_name'], safe='-_')}"
        )
    else:
        raise XPanelError(f"неподдерживаемый профиль inbound: {profile}")
    return f"{base}?{query}#{name}"


def backup_dir() -> Path:
    value = os.environ.get("XPANEL_BACKUP_DIR")
    path = Path(value).expanduser().resolve() if value else DEFAULT_BACKUP_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_backup_name(name: str) -> str:
    if not re.fullmatch(r"sg-panel-\d{8}-\d{6}", name):
        raise ValueError("некорректное имя резервной копии")
    return name


def create_backup() -> dict[str, object]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"sg-panel-{stamp}"
    target = backup_dir()
    db_target = target / f"{name}.db"
    shutil.copy2(db_path(), db_target)
    server = get_server()
    config_source = Path(server["config_path"])
    config_target = target / f"{name}.config.json"
    if config_source.exists():
        shutil.copy2(config_source, config_target)
    manifest = {
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database": db_target.name,
        "config": config_target.name if config_target.exists() else None,
    }
    (target / f"{name}.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {**manifest, "size": db_target.stat().st_size}


def list_backups() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for db_file in sorted(backup_dir().glob("sg-panel-*.db"), reverse=True):
        name = db_file.stem
        manifest_file = db_file.with_suffix(".json")
        created = datetime.fromtimestamp(db_file.stat().st_mtime, timezone.utc).isoformat()
        config_file = backup_dir() / f"{name}.config.json"
        if manifest_file.exists():
            try:
                created = json.loads(manifest_file.read_text(encoding="utf-8")).get(
                    "created_at", created
                )
            except (json.JSONDecodeError, OSError):
                pass
        result.append(
            {
                "name": name,
                "created_at": created,
                "size": db_file.stat().st_size,
                "size_human": format_bytes(db_file.stat().st_size),
                "has_config": config_file.exists(),
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
    require_root()
    source = backup_file(name, "db")
    current = db_path()
    safety = backup_dir() / f"pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.db"
    if current.exists():
        shutil.copy2(current, safety)
    temp = current.with_suffix(".restore.tmp")
    shutil.copy2(source, temp)
    os.replace(temp, current)
    init_db()
    return {"name": name, "safety": str(safety)}


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
    ports = _run(["ss", "-lntp"]).stdout
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
        "xray_logs": logs,
        "panel_logs": panel_logs,
        "nginx_logs": nginx_logs,
        "warp": warp,
        "warp_endpoint": warp_endpoint,
        "default_outbound_tag": routing["default_outbound_tag"],
        "server_address": server["address"],
        "server_port": server["port"],
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
        "Listening TCP ports:",
        str(data["ports"]),
        "",
        "Xray journal:",
        str(data["xray_logs"]),
        "",
        "Panel journal:",
        str(data["panel_logs"]),
    ]
    return "\n".join(lines)
