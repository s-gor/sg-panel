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
ALLOWED_DOMAIN_STRATEGIES = {"AsIs", "IPIfNonMatch", "IPOnDemand"}
ALLOWED_DNS_QUERY_STRATEGIES = {"UseIP", "UseIPv4", "UseIPv6", "UseSystem"}
ALLOWED_DNS_SERVER_QUERY_STRATEGIES = {"", *ALLOWED_DNS_QUERY_STRATEGIES}
ALLOWED_LOGLEVELS = {"debug", "info", "warning", "error", "none"}
ALLOWED_FLOWS = {"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}
OUTBOUND_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
RESERVED_OUTBOUND_TAGS = {"direct", "blocked", "api"}
DEFAULT_BACKUP_DIR = PROJECT_ROOT / "backups"


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("для этой операции нужны права root")


def _run(args: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout)
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


def validate_ips(value: str | None) -> str:
    result = split_values(value)
    for item in result:
        if item.startswith("geoip:"):
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
    enabled_tags = set(list_outbound_tags(enabled_only=True))
    if outbound_tag not in enabled_tags:
        raise ValueError("выбранный outbound не существует или отключён")
    network = (network or "").strip().lower()
    if network not in ALLOWED_NETWORKS:
        raise ValueError("network должен быть tcp, udp, tcp,udp или пустым")
    cleaned = {
        "name": name,
        "priority": priority,
        "outbound_tag": outbound_tag,
        "domains": normalise_values(domains),
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


def add_routing_rule(**values) -> sqlite3.Row:
    cleaned = validate_rule_values(**values)
    try:
        with connect() as con:
            cur = con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, domains, ips, ports,
                     network, protocols, inbound_tags, users)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned["name"],
                    cleaned["priority"],
                    int(values.get("enabled", True)),
                    cleaned["outbound_tag"],
                    cleaned["domains"],
                    cleaned["ips"],
                    cleaned["ports"],
                    cleaned["network"],
                    cleaned["protocols"],
                    cleaned["inbound_tags"],
                    cleaned["users"],
                ),
            )
            rule_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("правило с таким названием уже существует") from exc
    return find_routing_rule(rule_id)


def update_routing_rule(rule_id: int, **values) -> sqlite3.Row:
    find_routing_rule(rule_id)
    cleaned = validate_rule_values(**values)
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE routing_rules SET
                    name = ?, priority = ?, outbound_tag = ?, domains = ?, ips = ?,
                    ports = ?, network = ?, protocols = ?, inbound_tags = ?, users = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    cleaned["name"],
                    cleaned["priority"],
                    cleaned["outbound_tag"],
                    cleaned["domains"],
                    cleaned["ips"],
                    cleaned["ports"],
                    cleaned["network"],
                    cleaned["protocols"],
                    cleaned["inbound_tags"],
                    cleaned["users"],
                    rule_id,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise XPanelError("правило с таким названием уже существует") from exc
    return find_routing_rule(rule_id)


def set_routing_rule_enabled(rule_id: int, enabled: bool) -> sqlite3.Row:
    rule = find_routing_rule(rule_id)
    if enabled and rule["outbound_tag"] not in set(list_outbound_tags(enabled_only=True)):
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


def list_outbounds() -> list[dict[str, object]]:
    result = _system_outbounds()
    for row in list_custom_outbounds():
        item = dict(row)
        item.update(
            {
                "protocol": "vless",
                "system": False,
                "description": f"VLESS REALITY cascade to {row['address']}:{row['port']}",
            }
        )
        result.append(item)
    return result


def list_outbound_tags(*, enabled_only: bool = False) -> list[str]:
    tags = ["direct", "blocked"]
    tags.extend(str(row["tag"]) for row in list_custom_outbounds(enabled_only=enabled_only))
    return tags


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


def validate_vless_outbound_values(
    *,
    tag: str,
    name: str,
    address: str,
    port: int,
    user_uuid: str,
    flow: str,
    server_name: str,
    public_key: str,
    short_id: str,
    fingerprint: str,
    spider_x: str = "",
) -> dict[str, object]:
    tag = _validate_outbound_tag(tag)
    name = name.strip()
    address = address.strip()
    server_name = server_name.strip()
    public_key = public_key.strip()
    short_id = short_id.strip().lower()
    fingerprint = fingerprint.strip() or "chrome"
    spider_x = spider_x.strip()
    if not name:
        raise ValueError("название outbound не может быть пустым")
    if not address:
        raise ValueError("адрес второго Xray-сервера не может быть пустым")
    if not 1 <= int(port) <= 65535:
        raise ValueError("порт должен быть от 1 до 65535")
    try:
        uuidlib.UUID(user_uuid.strip())
    except ValueError as exc:
        raise ValueError("некорректный UUID второго сервера") from exc
    if flow not in ALLOWED_FLOWS:
        raise ValueError("неподдерживаемый flow")
    if not server_name:
        raise ValueError("serverName не может быть пустым")
    if not public_key:
        raise ValueError("Reality password/public key не может быть пустым")
    if short_id and (not re.fullmatch(r"[0-9a-f]{2,16}", short_id) or len(short_id) % 2):
        raise ValueError("shortId должен содержать чётное число hex-символов, максимум 16")
    return {
        "tag": tag,
        "name": name,
        "address": address,
        "port": int(port),
        "uuid": user_uuid.strip(),
        "flow": flow,
        "server_name": server_name,
        "public_key": public_key,
        "short_id": short_id,
        "fingerprint": fingerprint,
        "spider_x": spider_x,
    }


def add_vless_outbound(**values) -> sqlite3.Row:
    cleaned = validate_vless_outbound_values(**values)
    try:
        with connect() as con:
            cur = con.execute(
                """
                INSERT INTO outbounds (
                    tag, name, type, enabled, address, port, uuid, flow,
                    network, security, server_name, public_key, short_id,
                    fingerprint, spider_x
                ) VALUES (?, ?, 'vless_reality', 1, ?, ?, ?, ?, 'raw', 'reality', ?, ?, ?, ?, ?)
                """,
                (
                    cleaned["tag"], cleaned["name"], cleaned["address"], cleaned["port"],
                    cleaned["uuid"], cleaned["flow"], cleaned["server_name"],
                    cleaned["public_key"], cleaned["short_id"], cleaned["fingerprint"],
                    cleaned["spider_x"],
                ),
            )
            outbound_id = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise XPanelError("outbound с таким tag уже существует") from exc
    return find_outbound(outbound_id)


def update_vless_outbound(outbound_id: int, **values) -> sqlite3.Row:
    current = find_outbound(outbound_id)
    cleaned = validate_vless_outbound_values(**values)
    try:
        with connect() as con:
            con.execute(
                """
                UPDATE outbounds SET
                    tag = ?, name = ?, address = ?, port = ?, uuid = ?, flow = ?,
                    server_name = ?, public_key = ?, short_id = ?, fingerprint = ?,
                    spider_x = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    cleaned["tag"], cleaned["name"], cleaned["address"], cleaned["port"],
                    cleaned["uuid"], cleaned["flow"], cleaned["server_name"],
                    cleaned["public_key"], cleaned["short_id"], cleaned["fingerprint"],
                    cleaned["spider_x"], outbound_id,
                ),
            )
            if cleaned["tag"] != current["tag"]:
                con.execute(
                    "UPDATE routing_rules SET outbound_tag = ?, updated_at = CURRENT_TIMESTAMP WHERE outbound_tag = ?",
                    (cleaned["tag"], current["tag"]),
                )
                con.execute(
                    "UPDATE routing_settings SET default_outbound_tag = ?, updated_at = CURRENT_TIMESTAMP WHERE default_outbound_tag = ?",
                    (cleaned["tag"], current["tag"]),
                )
    except sqlite3.IntegrityError as exc:
        raise XPanelError("outbound с таким tag уже существует") from exc
    return find_outbound(outbound_id)


def set_outbound_enabled(outbound_id: int, enabled: bool) -> sqlite3.Row:
    outbound = find_outbound(outbound_id)
    if not enabled:
        settings = get_routing_settings()
        if settings["default_outbound_tag"] == outbound["tag"]:
            raise XPanelError("сначала выберите другой outbound по умолчанию")
        with connect() as con:
            used = con.execute(
                "SELECT COUNT(*) FROM routing_rules WHERE enabled = 1 AND outbound_tag = ?",
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
            "SELECT COUNT(*) FROM routing_rules WHERE outbound_tag = ?", (outbound["tag"],)
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
    reality = {
        "serverName": row["server_name"],
        "fingerprint": row["fingerprint"],
        "password": row["public_key"],
        "shortId": row["short_id"],
        "spiderX": row["spider_x"],
    }
    settings: dict[str, object] = {
        "address": row["address"],
        "port": row["port"],
        "id": row["uuid"],
        "encryption": "none",
        "level": 0,
    }
    if row["flow"]:
        settings["flow"] = row["flow"]
    return {
        "tag": row["tag"],
        "protocol": "vless",
        "settings": settings,
        "streamSettings": {
            "network": row["network"],
            "security": row["security"],
            "realitySettings": reality,
        },
    }


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
) -> None:
    fields = {
        "address": address,
        "dest": dest,
        "server_name": server_name,
        "private_key": private_key,
        "public_key": public_key,
        "short_id": short_id,
    }
    empty = [name for name, value in fields.items() if not value or not value.strip()]
    if empty:
        raise ValueError("пустые обязательные поля: " + ", ".join(empty))
    if not 1 <= int(port) <= 65535:
        raise ValueError("port должен быть от 1 до 65535")
    if not re.fullmatch(r"[0-9a-fA-F]{2,32}", short_id) or len(short_id) % 2:
        raise ValueError("short_id должен быть HEX-строкой чётной длины от 2 до 32 символов")
    if ":" not in dest:
        raise ValueError("dest должен иметь вид host:port")
    if flow not in ALLOWED_FLOWS:
        raise ValueError("неподдерживаемый flow")
    if loglevel not in ALLOWED_LOGLEVELS:
        raise ValueError("неподдерживаемый loglevel")
    _validate_api_listen(api_listen)


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
) -> sqlite3.Row:
    validate_server_values(
        address,
        port,
        dest,
        server_name,
        private_key,
        public_key,
        short_id,
        flow=flow,
        loglevel=loglevel,
        api_listen=api_listen,
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
                config_path = ?, xray_bin = ?, xray_service = ?
            WHERE id = 1
            """,
            (
                address.strip(),
                listen.strip(),
                int(port),
                dest.strip(),
                server_name.strip(),
                private_key.strip(),
                public_key.strip(),
                short_id.strip(),
                fingerprint,
                flow,
                loglevel,
                api_listen.strip(),
                int(stats_enabled),
                config_path.strip(),
                xray_bin.strip(),
                xray_service.strip(),
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
    rule: dict[str, object] = {"type": "field", "outboundTag": row["outbound_tag"]}
    mappings = (
        ("domain", "domains"),
        ("ip", "ips"),
        ("protocol", "protocols"),
        ("inboundTag", "inbound_tags"),
        ("user", "users"),
    )
    for json_key, db_key in mappings:
        values = split_values(row[db_key])
        if values:
            rule[json_key] = values
    if row["ports"]:
        rule["port"] = row["ports"]
    if row["network"]:
        rule["network"] = row["network"]
    return rule


def _active_users(rows: list[sqlite3.Row]) -> list[sqlite3.Row]:
    return [row for row in rows if row["enabled"] and not user_is_expired(row)]


def build_config() -> tuple[dict, sqlite3.Row, list[sqlite3.Row]]:
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

    inbound: dict[str, object] = {
        "tag": "vless-reality-in",
        "listen": server["listen"],
        "port": server["port"],
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": server["dest"],
                "xver": 0,
                "serverNames": [server["server_name"]],
                "privateKey": server["private_key"],
                "shortIds": [server["short_id"]],
            },
        },
    }
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

    config: dict[str, object] = {
        "log": {"loglevel": server["loglevel"]},
        "inbounds": [inbound],
        "outbounds": [],
        "routing": {
            "domainStrategy": settings["domain_strategy"],
            "rules": [build_rule_json(row) for row in rules],
        },
    }
    dns_config = build_dns_json()
    if dns_config is not None:
        config["dns"] = dns_config
    available_outbounds: dict[str, dict[str, object]] = {
        "direct": {"tag": "direct", "protocol": "freedom", "settings": {}},
        "blocked": {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    }
    for row in custom_outbounds:
        available_outbounds[str(row["tag"])] = build_outbound_json(row)

    default_tag = str(settings["default_outbound_tag"] or "direct")
    if default_tag == "blocked" or default_tag not in available_outbounds:
        raise XPanelError("некорректный или отключённый outbound по умолчанию")
    referenced_tags = {str(row["outbound_tag"]) for row in rules}
    missing = sorted(referenced_tags - set(available_outbounds))
    if missing:
        raise XPanelError("routing rules ссылаются на отсутствующие outbounds: " + ", ".join(missing))

    ordered_tags = [default_tag]
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
        if config_path.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            backup_path = config_path.with_name(f"{config_path.name}.bak-{stamp}")
            shutil.copy2(config_path, backup_path)
        os.replace(temp_path, config_path)
        restart = _run(["systemctl", "restart", server["xray_service"]], timeout=30)
        if restart.returncode != 0:
            detail = (restart.stderr or restart.stdout).strip()
            if backup_path and backup_path.exists():
                shutil.copy2(backup_path, config_path)
                _run(["systemctl", "restart", server["xray_service"]], timeout=30)
                raise XPanelError(
                    "Xray не перезапустился; предыдущая конфигурация восстановлена. " + detail
                )
            raise XPanelError(f"Xray не перезапустился: {detail}")
        if _run(["systemctl", "is-active", "--quiet", server["xray_service"]]).returncode != 0:
            raise XPanelError("после перезапуска служба Xray не активна")
        return {
            "config_path": str(config_path),
            "backup_path": str(backup_path) if backup_path else None,
            "enabled_users": len(users),
            "enabled_rules": len([r for r in list_routing_rules() if r["enabled"]]),
            "service": "active",
        }
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
    flow = f"&flow={quote(server['flow'], safe='-_')}" if server["flow"] else ""
    return (
        f"vless://{user['uuid']}@{server['address']}:{server['port']}"
        f"?type=tcp&security=reality&pbk={quote(server['public_key'], safe='-_')}"
        f"&fp={quote(server['fingerprint'], safe='')}&sni={quote(server['server_name'], safe='')}"
        f"&sid={quote(server['short_id'], safe='')}{flow}&spx=%2F#{name}"
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
    dns_settings = get_dns_settings()
    dns_servers = list_dns_servers()
    dns_test = test_dns_resolution("example.com")
    return {
        "os": _read_os_release(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "xray_version": xray_version[0] if xray_version else "unknown",
        "xray_service": (_run(["systemctl", "is-active", server["xray_service"]]).stdout.strip()),
        "panel_service": (_run(["systemctl", "is-active", "xpanel-web"]).stdout.strip()),
        "disk_total": format_bytes(disk.total),
        "disk_free": format_bytes(disk.free),
        "memory_total": format_bytes(mem_total),
        "memory_available": format_bytes(mem_available),
        "ports": ports,
        "xray_logs": logs,
        "panel_logs": panel_logs,
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
        f"Memory available: {data['memory_available']} / {data['memory_total']}",
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
