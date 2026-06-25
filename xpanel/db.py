from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "panel.db"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS server_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    address TEXT NOT NULL,
    listen TEXT NOT NULL DEFAULT '0.0.0.0',
    port INTEGER NOT NULL DEFAULT 443 CHECK (port BETWEEN 1 AND 65535),
    dest TEXT NOT NULL,
    server_name TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    short_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT 'chrome',
    flow TEXT NOT NULL DEFAULT '',
    loglevel TEXT NOT NULL DEFAULT 'warning',
    api_listen TEXT NOT NULL DEFAULT '127.0.0.1:10085',
    stats_enabled INTEGER NOT NULL DEFAULT 0 CHECK (stats_enabled IN (0, 1)),
    config_path TEXT NOT NULL DEFAULT '/usr/local/etc/xray/config.json',
    xray_bin TEXT NOT NULL DEFAULT '/usr/local/bin/xray',
    xray_service TEXT NOT NULL DEFAULT 'xray'
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    uuid TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    expiry_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    subscription_enabled INTEGER NOT NULL DEFAULT 1 CHECK (subscription_enabled IN (0, 1)),
    subscription_token TEXT,
    subscription_access_count INTEGER NOT NULL DEFAULT 0,
    subscription_last_access_at TEXT
);

CREATE TABLE IF NOT EXISTS subscription_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    base_url TEXT NOT NULL DEFAULT '',
    profile_title TEXT NOT NULL DEFAULT 'SG-Panel',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS routing_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    domain_strategy TEXT NOT NULL DEFAULT 'AsIs'
        CHECK (domain_strategy IN ('AsIs', 'IPIfNonMatch', 'IPOnDemand')),
    default_outbound_tag TEXT NOT NULL DEFAULT 'direct',
    sniffing_enabled INTEGER NOT NULL DEFAULT 1 CHECK (sniffing_enabled IN (0, 1)),
    sniffing_route_only INTEGER NOT NULL DEFAULT 1 CHECK (sniffing_route_only IN (0, 1)),
    sniff_http INTEGER NOT NULL DEFAULT 1 CHECK (sniff_http IN (0, 1)),
    sniff_tls INTEGER NOT NULL DEFAULT 1 CHECK (sniff_tls IN (0, 1)),
    sniff_quic INTEGER NOT NULL DEFAULT 1 CHECK (sniff_quic IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS dns_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    query_strategy TEXT NOT NULL DEFAULT 'UseIPv4'
        CHECK (query_strategy IN ('UseIP', 'UseIPv4', 'UseIPv6', 'UseSystem')),
    disable_cache INTEGER NOT NULL DEFAULT 0 CHECK (disable_cache IN (0, 1)),
    disable_fallback INTEGER NOT NULL DEFAULT 0 CHECK (disable_fallback IN (0, 1)),
    disable_fallback_if_match INTEGER NOT NULL DEFAULT 0 CHECK (disable_fallback_if_match IN (0, 1)),
    enable_parallel_query INTEGER NOT NULL DEFAULT 0 CHECK (enable_parallel_query IN (0, 1)),
    use_system_hosts INTEGER NOT NULL DEFAULT 1 CHECK (use_system_hosts IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    address TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 9999),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    domains TEXT NOT NULL DEFAULT '',
    expected_ips TEXT NOT NULL DEFAULT '',
    unexpected_ips TEXT NOT NULL DEFAULT '',
    query_strategy TEXT NOT NULL DEFAULT ''
        CHECK (query_strategy IN ('', 'UseIP', 'UseIPv4', 'UseIPv6', 'UseSystem')),
    skip_fallback INTEGER NOT NULL DEFAULT 0 CHECK (skip_fallback IN (0, 1)),
    final_query INTEGER NOT NULL DEFAULT 0 CHECK (final_query IN (0, 1)),
    timeout_ms INTEGER NOT NULL DEFAULT 4000 CHECK (timeout_ms BETWEEN 100 AND 60000),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE COLLATE NOCASE,
    addresses TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS outbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'vless_reality'
        CHECK (type IN ('vless_reality')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    address TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    uuid TEXT NOT NULL,
    flow TEXT NOT NULL DEFAULT 'xtls-rprx-vision',
    network TEXT NOT NULL DEFAULT 'raw',
    security TEXT NOT NULL DEFAULT 'reality',
    server_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    short_id TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT 'chrome',
    spider_x TEXT NOT NULL DEFAULT '',
    xhttp_host TEXT NOT NULL DEFAULT '',
    xhttp_path TEXT NOT NULL DEFAULT '/',
    xhttp_mode TEXT NOT NULL DEFAULT 'auto',
    allow_insecure INTEGER NOT NULL DEFAULT 0 CHECK (allow_insecure IN (0, 1)),
    alpn TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS routing_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    priority INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 9999),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    outbound_tag TEXT NOT NULL,
    domains TEXT NOT NULL DEFAULT '',
    ips TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL DEFAULT '',
    network TEXT NOT NULL DEFAULT '' CHECK (network IN ('', 'tcp', 'udp', 'tcp,udp')),
    protocols TEXT NOT NULL DEFAULT '',
    inbound_tags TEXT NOT NULL DEFAULT '',
    users TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    session_timeout_minutes INTEGER NOT NULL DEFAULT 60
        CHECK (session_timeout_minutes BETWEEN 5 AND 1440),
    max_login_attempts INTEGER NOT NULL DEFAULT 5
        CHECK (max_login_attempts BETWEEN 3 AND 20),
    lockout_minutes INTEGER NOT NULL DEFAULT 15
        CHECK (lockout_minutes BETWEEN 1 AND 1440),
    allowlist_enabled INTEGER NOT NULL DEFAULT 0 CHECK (allowlist_enabled IN (0, 1)),
    allowed_networks TEXT NOT NULL DEFAULT '',
    trust_proxy_headers INTEGER NOT NULL DEFAULT 0 CHECK (trust_proxy_headers IN (0, 1)),
    subscription_plain_enabled INTEGER NOT NULL DEFAULT 1 CHECK (subscription_plain_enabled IN (0, 1)),
    subscription_json_enabled INTEGER NOT NULL DEFAULT 1 CHECK (subscription_json_enabled IN (0, 1)),
    subscription_allowlist_enabled INTEGER NOT NULL DEFAULT 0
        CHECK (subscription_allowlist_enabled IN (0, 1)),
    subscription_allowed_networks TEXT NOT NULL DEFAULT '',
    audit_retention_days INTEGER NOT NULL DEFAULT 90
        CHECK (audit_retention_days BETWEEN 7 AND 3650),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_last_seen
    ON admin_sessions(last_seen_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    user_agent TEXT NOT NULL DEFAULT '',
    attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip_address, attempted_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL DEFAULT 1 CHECK (success IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created
    ON audit_log(created_at);
"""

DEFAULT_PRIVATE_IPS = """10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16
::1/128
fc00::/7
fe80::/10"""


def db_path() -> Path:
    value = os.environ.get("XPANEL_DB")
    return Path(value).expanduser().resolve() if value else DEFAULT_DB_PATH


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA foreign_keys = ON")
        yield con
        con.commit()
    finally:
        con.close()


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table})")}


def _ensure_column(con: sqlite3.Connection, table: str, name: str, ddl: str) -> None:
    if name not in _columns(con, table):
        con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def _migrate(con: sqlite3.Connection) -> None:
    # v0.5 server settings
    _ensure_column(con, "server_settings", "flow", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "loglevel", "TEXT NOT NULL DEFAULT 'warning'")
    _ensure_column(con, "server_settings", "api_listen", "TEXT NOT NULL DEFAULT '127.0.0.1:10085'")
    _ensure_column(con, "server_settings", "stats_enabled", "INTEGER NOT NULL DEFAULT 0")

    # v0.5 users
    _ensure_column(con, "users", "comment", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "users", "expiry_at", "TEXT")
    _ensure_column(con, "users", "updated_at", "TEXT")
    con.execute("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)")

    # v0.6 routing and custom outbounds
    _ensure_column(con, "routing_settings", "default_outbound_tag", "TEXT NOT NULL DEFAULT 'direct'")
    _ensure_column(con, "routing_rules", "users", "TEXT NOT NULL DEFAULT ''")

    # v0.7 DNS tables are created by SCHEMA.

    # v0.9.5 VLESS outbound transports and TLS options
    _ensure_column(con, "outbounds", "network", "TEXT NOT NULL DEFAULT 'raw'")
    _ensure_column(con, "outbounds", "security", "TEXT NOT NULL DEFAULT 'reality'")
    _ensure_column(con, "outbounds", "xhttp_host", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "outbounds", "xhttp_path", "TEXT NOT NULL DEFAULT '/'")
    _ensure_column(con, "outbounds", "xhttp_mode", "TEXT NOT NULL DEFAULT 'auto'")
    _ensure_column(con, "outbounds", "allow_insecure", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "outbounds", "alpn", "TEXT NOT NULL DEFAULT ''")
    con.execute("UPDATE outbounds SET network = 'raw' WHERE network IS NULL OR network = ''")
    con.execute("UPDATE outbounds SET security = 'reality' WHERE security IS NULL OR security = ''")
    con.execute("UPDATE outbounds SET xhttp_path = '/' WHERE xhttp_path IS NULL OR xhttp_path = ''")
    con.execute("UPDATE outbounds SET xhttp_mode = 'auto' WHERE xhttp_mode IS NULL OR xhttp_mode = ''")

    # v0.8 persistent subscription URLs
    _ensure_column(con, "users", "subscription_enabled", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(con, "users", "subscription_token", "TEXT")
    _ensure_column(con, "users", "subscription_access_count", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "users", "subscription_last_access_at", "TEXT")
    con.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_subscription_token "
        "ON users(subscription_token)"
    )


def init_db() -> Path:
    path = db_path()
    with connect() as con:
        con.executescript(SCHEMA)
        _migrate(con)
        con.execute(
            """
            INSERT OR IGNORE INTO routing_settings (
                id, domain_strategy, default_outbound_tag,
                sniffing_enabled, sniffing_route_only,
                sniff_http, sniff_tls, sniff_quic
            ) VALUES (1, 'AsIs', 'direct', 1, 1, 1, 1, 1)
            """
        )
        con.execute(
            """
            INSERT OR IGNORE INTO dns_settings (
                id, enabled, query_strategy, disable_cache, disable_fallback,
                disable_fallback_if_match, enable_parallel_query, use_system_hosts
            ) VALUES (1, 0, 'UseIPv4', 0, 0, 0, 0, 1)
            """
        )
        con.execute(
            """
            INSERT OR IGNORE INTO subscription_settings (
                id, enabled, base_url, profile_title
            ) VALUES (1, 0, '', 'SG-Panel')
            """
        )
        con.execute(
            """
            INSERT OR IGNORE INTO security_settings (
                id, session_timeout_minutes, max_login_attempts, lockout_minutes,
                allowlist_enabled, allowed_networks, trust_proxy_headers,
                subscription_plain_enabled, subscription_json_enabled,
                subscription_allowlist_enabled, subscription_allowed_networks,
                audit_retention_days
            ) VALUES (1, 60, 5, 15, 0, '', 0, 1, 1, 0, '', 90)
            """
        )
        missing_tokens = con.execute(
            "SELECT id FROM users WHERE subscription_token IS NULL OR subscription_token = ''"
        ).fetchall()
        for row in missing_tokens:
            while True:
                token = secrets.token_urlsafe(32)
                try:
                    con.execute(
                        "UPDATE users SET subscription_token = ? WHERE id = ?",
                        (token, row["id"]),
                    )
                    break
                except sqlite3.IntegrityError:
                    continue
        dns_count = int(con.execute("SELECT COUNT(*) FROM dns_servers").fetchone()[0])
        if dns_count == 0:
            con.executemany(
                """
                INSERT INTO dns_servers
                    (name, address, priority, enabled, timeout_ms)
                VALUES (?, ?, ?, 1, 4000)
                """,
                (
                    ("Cloudflare DOH Local", "https+local://1.1.1.1/dns-query", 10),
                    ("Google DOH Local", "https+local://dns.google/dns-query", 20),
                    ("System DNS", "localhost", 90),
                ),
            )
        count = int(con.execute("SELECT COUNT(*) FROM routing_rules").fetchone()[0])
        if count == 0:
            con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, protocols)
                VALUES (?, ?, 1, 'blocked', ?)
                """,
                ("Block BitTorrent", 10, "bittorrent"),
            )
            con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, ips)
                VALUES (?, ?, 1, 'blocked', ?)
                """,
                ("Block private networks", 20, DEFAULT_PRIVATE_IPS),
            )
    return path
