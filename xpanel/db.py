from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "panel.db"
_DB_PATH_OVERRIDE: ContextVar[Path | None] = ContextVar("xpanel_db_path_override", default=None)

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
    stats_enabled INTEGER NOT NULL DEFAULT 1 CHECK (stats_enabled IN (0, 1)),
    config_path TEXT NOT NULL DEFAULT '/usr/local/etc/xray/config.json',
    xray_bin TEXT NOT NULL DEFAULT '/usr/local/bin/xray',
    xray_service TEXT NOT NULL DEFAULT 'xray',
    inbound_profile TEXT NOT NULL DEFAULT 'raw_reality',
    transport_listen TEXT NOT NULL DEFAULT '127.0.0.1',
    transport_port INTEGER NOT NULL DEFAULT 8443 CHECK (transport_port BETWEEN 1 AND 65535),
    xhttp_path TEXT NOT NULL DEFAULT '/sg-xhttp',
    xhttp_mode TEXT NOT NULL DEFAULT 'auto',
    grpc_service_name TEXT NOT NULL DEFAULT 'sg-grpc',
    tls_cert_path TEXT NOT NULL DEFAULT '',
    tls_key_path TEXT NOT NULL DEFAULT '',
    hysteria_udp_idle_timeout INTEGER NOT NULL DEFAULT 60 CHECK (hysteria_udp_idle_timeout BETWEEN 10 AND 3600),
    hysteria_masquerade_type TEXT NOT NULL DEFAULT '' CHECK (hysteria_masquerade_type IN ('', 'string', 'proxy')),
    hysteria_masquerade_url TEXT NOT NULL DEFAULT '',
    hysteria_masquerade_content TEXT NOT NULL DEFAULT '',
    hysteria_masquerade_status INTEGER NOT NULL DEFAULT 404 CHECK (hysteria_masquerade_status BETWEEN 200 AND 599),
    hysteria_masquerade_dir TEXT NOT NULL DEFAULT '',
    hysteria_masquerade_rewrite_host INTEGER NOT NULL DEFAULT 1 CHECK (hysteria_masquerade_rewrite_host IN (0, 1)),
    hysteria_masquerade_insecure INTEGER NOT NULL DEFAULT 0 CHECK (hysteria_masquerade_insecure IN (0, 1)),
    hysteria_masquerade_headers TEXT NOT NULL DEFAULT '{}',
    hysteria_performance_profile TEXT NOT NULL DEFAULT 'auto' CHECK (hysteria_performance_profile IN ('auto', 'mobile', 'speed', 'limited', 'custom')),
    hysteria_congestion TEXT NOT NULL DEFAULT 'brutal' CHECK (hysteria_congestion IN ('reno', 'bbr', 'brutal', 'force-brutal')),
    hysteria_bbr_profile TEXT NOT NULL DEFAULT 'standard' CHECK (hysteria_bbr_profile IN ('conservative', 'standard', 'aggressive')),
    hysteria_brutal_up TEXT NOT NULL DEFAULT '0',
    hysteria_brutal_down TEXT NOT NULL DEFAULT '0',
    hysteria_quic_debug INTEGER NOT NULL DEFAULT 0 CHECK (hysteria_quic_debug IN (0, 1)),
    hysteria_max_idle_timeout INTEGER NOT NULL DEFAULT 30 CHECK (hysteria_max_idle_timeout BETWEEN 4 AND 120),
    hysteria_keepalive_period INTEGER NOT NULL DEFAULT 0 CHECK (hysteria_keepalive_period = 0 OR hysteria_keepalive_period BETWEEN 2 AND 60),
    hysteria_disable_pmtud INTEGER NOT NULL DEFAULT 0 CHECK (hysteria_disable_pmtud IN (0, 1)),
    hysteria_max_incoming_streams INTEGER NOT NULL DEFAULT 1024 CHECK (hysteria_max_incoming_streams >= 8),
    hysteria_udp_hop_ports TEXT NOT NULL DEFAULT '',
    hysteria_udp_hop_interval TEXT NOT NULL DEFAULT '30',
    hysteria_init_stream_receive_window INTEGER NOT NULL DEFAULT 8388608,
    hysteria_max_stream_receive_window INTEGER NOT NULL DEFAULT 8388608,
    hysteria_init_connection_receive_window INTEGER NOT NULL DEFAULT 20971520,
    hysteria_max_connection_receive_window INTEGER NOT NULL DEFAULT 20971520
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

CREATE TABLE IF NOT EXISTS user_traffic_totals (
    user_id INTEGER PRIMARY KEY,
    uplink_total INTEGER NOT NULL DEFAULT 0 CHECK (uplink_total >= 0),
    downlink_total INTEGER NOT NULL DEFAULT 0 CHECK (downlink_total >= 0),
    last_raw_uplink INTEGER NOT NULL DEFAULT 0 CHECK (last_raw_uplink >= 0),
    last_raw_downlink INTEGER NOT NULL DEFAULT 0 CHECK (last_raw_downlink >= 0),
    session_uplink INTEGER NOT NULL DEFAULT 0 CHECK (session_uplink >= 0),
    session_downlink INTEGER NOT NULL DEFAULT 0 CHECK (session_downlink >= 0),
    uplink_bps INTEGER NOT NULL DEFAULT 0 CHECK (uplink_bps >= 0),
    downlink_bps INTEGER NOT NULL DEFAULT 0 CHECK (downlink_bps >= 0),
    online_state INTEGER NOT NULL DEFAULT -1 CHECK (online_state IN (-1, 0, 1)),
    last_seen_at TEXT,
    last_collected_at TEXT,
    reset_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_traffic_daily (
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0 CHECK (uplink >= 0),
    downlink INTEGER NOT NULL DEFAULT 0 CHECK (downlink >= 0),
    PRIMARY KEY (user_id, day),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_traffic_daily_day
    ON user_traffic_daily(day);

CREATE TABLE IF NOT EXISTS subscription_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    base_url TEXT NOT NULL DEFAULT '',
    profile_title TEXT NOT NULL DEFAULT 'SG-Panel',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS config_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    document_json TEXT NOT NULL DEFAULT '{}',
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
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    extra_json TEXT NOT NULL DEFAULT '{}'
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
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    extra_json TEXT NOT NULL DEFAULT '{}'
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
    config_json TEXT NOT NULL DEFAULT '{}',
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
    config_json TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS warp_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    outbound_json TEXT NOT NULL DEFAULT '',
    account_json TEXT NOT NULL DEFAULT '',
    route_mode TEXT NOT NULL DEFAULT 'off'
        CHECK (route_mode IN ('off', 'selected', 'all')),
    selected_domains TEXT NOT NULL DEFAULT '',
    last_test_state TEXT NOT NULL DEFAULT '',
    last_test_ip TEXT NOT NULL DEFAULT '',
    last_test_at TEXT,
    created_at TEXT,
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
    target_type TEXT NOT NULL DEFAULT 'outbound',
    config_json TEXT NOT NULL DEFAULT '',
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
    override = _DB_PATH_OVERRIDE.get()
    if override is not None:
        return override
    value = os.environ.get("XPANEL_DB")
    return Path(value).expanduser().resolve() if value else DEFAULT_DB_PATH


@contextmanager
def use_db_path(path: str | Path) -> Iterator[Path]:
    """Temporarily route DB access in the current context to another SQLite file."""
    resolved = Path(path).expanduser().resolve()
    token = _DB_PATH_OVERRIDE.set(resolved)
    try:
        yield resolved
    finally:
        _DB_PATH_OVERRIDE.reset(token)


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
    _ensure_column(con, "server_settings", "stats_enabled", "INTEGER NOT NULL DEFAULT 1")

    # v0.10 RC29: Clients & Traffic Studio depends on the local Xray Stats API.
    # Enable it once for existing installations. A migration marker prevents a
    # later init-db call from overriding an administrator who disables it again.
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    migration_name = "rc29-enable-xray-stats"
    applied = con.execute(
        "SELECT 1 FROM schema_migrations WHERE name = ?", (migration_name,)
    ).fetchone()
    if applied is None:
        con.execute("UPDATE server_settings SET stats_enabled = 1")
        con.execute(
            "INSERT INTO schema_migrations (name) VALUES (?)", (migration_name,)
        )

    # v0.10 RC3 inbound profiles
    _ensure_column(con, "server_settings", "inbound_profile", "TEXT NOT NULL DEFAULT 'raw_reality'")
    _ensure_column(con, "server_settings", "transport_listen", "TEXT NOT NULL DEFAULT '127.0.0.1'")
    _ensure_column(con, "server_settings", "transport_port", "INTEGER NOT NULL DEFAULT 8443")
    _ensure_column(con, "server_settings", "xhttp_path", "TEXT NOT NULL DEFAULT '/sg-xhttp'")
    _ensure_column(con, "server_settings", "xhttp_mode", "TEXT NOT NULL DEFAULT 'auto'")
    _ensure_column(con, "server_settings", "grpc_service_name", "TEXT NOT NULL DEFAULT 'sg-grpc'")
    _ensure_column(con, "server_settings", "tls_cert_path", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "tls_key_path", "TEXT NOT NULL DEFAULT ''")

    # v0.10 RC22 native Hysteria 2 inbound
    _ensure_column(con, "server_settings", "hysteria_udp_idle_timeout", "INTEGER NOT NULL DEFAULT 60")
    _ensure_column(con, "server_settings", "hysteria_masquerade_type", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "hysteria_masquerade_url", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "hysteria_masquerade_content", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "hysteria_masquerade_status", "INTEGER NOT NULL DEFAULT 404")
    con.execute("UPDATE server_settings SET hysteria_udp_idle_timeout=60 WHERE hysteria_udp_idle_timeout IS NULL OR hysteria_udp_idle_timeout < 10")
    con.execute("UPDATE server_settings SET hysteria_masquerade_type='' WHERE hysteria_masquerade_type IS NULL OR hysteria_masquerade_type NOT IN ('', 'string', 'proxy')")
    con.execute("UPDATE server_settings SET hysteria_masquerade_url='' WHERE hysteria_masquerade_url IS NULL")
    con.execute("UPDATE server_settings SET hysteria_masquerade_content='' WHERE hysteria_masquerade_content IS NULL")
    con.execute("UPDATE server_settings SET hysteria_masquerade_status=404 WHERE hysteria_masquerade_status IS NULL OR hysteria_masquerade_status < 200 OR hysteria_masquerade_status > 599")

    # v0.10 RC26 Hysteria Studio
    _ensure_column(con, "server_settings", "hysteria_masquerade_dir", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "hysteria_masquerade_rewrite_host", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(con, "server_settings", "hysteria_masquerade_insecure", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "server_settings", "hysteria_masquerade_headers", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(con, "server_settings", "hysteria_performance_profile", "TEXT NOT NULL DEFAULT 'auto'")
    _ensure_column(con, "server_settings", "hysteria_congestion", "TEXT NOT NULL DEFAULT 'brutal'")
    _ensure_column(con, "server_settings", "hysteria_bbr_profile", "TEXT NOT NULL DEFAULT 'standard'")
    _ensure_column(con, "server_settings", "hysteria_brutal_up", "TEXT NOT NULL DEFAULT '0'")
    _ensure_column(con, "server_settings", "hysteria_brutal_down", "TEXT NOT NULL DEFAULT '0'")
    _ensure_column(con, "server_settings", "hysteria_quic_debug", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "server_settings", "hysteria_max_idle_timeout", "INTEGER NOT NULL DEFAULT 30")
    _ensure_column(con, "server_settings", "hysteria_keepalive_period", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "server_settings", "hysteria_disable_pmtud", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "server_settings", "hysteria_max_incoming_streams", "INTEGER NOT NULL DEFAULT 1024")
    _ensure_column(con, "server_settings", "hysteria_udp_hop_ports", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "hysteria_udp_hop_interval", "TEXT NOT NULL DEFAULT '30'")
    _ensure_column(con, "server_settings", "hysteria_init_stream_receive_window", "INTEGER NOT NULL DEFAULT 8388608")
    _ensure_column(con, "server_settings", "hysteria_max_stream_receive_window", "INTEGER NOT NULL DEFAULT 8388608")
    _ensure_column(con, "server_settings", "hysteria_init_connection_receive_window", "INTEGER NOT NULL DEFAULT 20971520")
    _ensure_column(con, "server_settings", "hysteria_max_connection_receive_window", "INTEGER NOT NULL DEFAULT 20971520")
    con.execute("UPDATE server_settings SET hysteria_masquerade_headers='{}' WHERE hysteria_masquerade_headers IS NULL OR hysteria_masquerade_headers=''")
    con.execute("UPDATE server_settings SET hysteria_performance_profile='auto' WHERE hysteria_performance_profile IS NULL OR hysteria_performance_profile NOT IN ('auto','mobile','speed','limited','custom')")
    con.execute("UPDATE server_settings SET hysteria_congestion='brutal' WHERE hysteria_congestion IS NULL OR hysteria_congestion NOT IN ('reno','bbr','brutal','force-brutal')")
    con.execute("UPDATE server_settings SET hysteria_bbr_profile='standard' WHERE hysteria_bbr_profile IS NULL OR hysteria_bbr_profile NOT IN ('conservative','standard','aggressive')")
    con.execute("UPDATE server_settings SET hysteria_brutal_up='0' WHERE hysteria_brutal_up IS NULL OR hysteria_brutal_up=''")
    con.execute("UPDATE server_settings SET hysteria_brutal_down='0' WHERE hysteria_brutal_down IS NULL OR hysteria_brutal_down=''")
    con.execute("UPDATE server_settings SET hysteria_max_idle_timeout=30 WHERE hysteria_max_idle_timeout IS NULL OR hysteria_max_idle_timeout < 4 OR hysteria_max_idle_timeout > 120")
    con.execute("UPDATE server_settings SET hysteria_keepalive_period=0 WHERE hysteria_keepalive_period IS NULL OR (hysteria_keepalive_period != 0 AND (hysteria_keepalive_period < 2 OR hysteria_keepalive_period > 60))")
    con.execute("UPDATE server_settings SET hysteria_max_incoming_streams=1024 WHERE hysteria_max_incoming_streams IS NULL OR hysteria_max_incoming_streams < 8")
    con.execute("UPDATE server_settings SET hysteria_udp_hop_interval='30' WHERE hysteria_udp_hop_interval IS NULL OR hysteria_udp_hop_interval=''")
    con.execute("UPDATE server_settings SET hysteria_init_stream_receive_window=8388608 WHERE hysteria_init_stream_receive_window IS NULL OR hysteria_init_stream_receive_window < 65536")
    con.execute("UPDATE server_settings SET hysteria_max_stream_receive_window=8388608 WHERE hysteria_max_stream_receive_window IS NULL OR hysteria_max_stream_receive_window < 65536")
    con.execute("UPDATE server_settings SET hysteria_init_connection_receive_window=20971520 WHERE hysteria_init_connection_receive_window IS NULL OR hysteria_init_connection_receive_window < 65536")
    con.execute("UPDATE server_settings SET hysteria_max_connection_receive_window=20971520 WHERE hysteria_max_connection_receive_window IS NULL OR hysteria_max_connection_receive_window < 65536")
    con.execute("UPDATE server_settings SET inbound_profile='raw_reality' WHERE inbound_profile IS NULL OR inbound_profile=''")
    con.execute("UPDATE server_settings SET transport_listen='127.0.0.1' WHERE transport_listen IS NULL OR transport_listen=''")
    con.execute("UPDATE server_settings SET transport_port=8443 WHERE transport_port IS NULL OR transport_port=0")
    con.execute("UPDATE server_settings SET xhttp_path='/sg-xhttp' WHERE xhttp_path IS NULL OR xhttp_path=''")
    con.execute("UPDATE server_settings SET xhttp_mode='auto' WHERE xhttp_mode IS NULL OR xhttp_mode=''")
    con.execute("UPDATE server_settings SET grpc_service_name='sg-grpc' WHERE grpc_service_name IS NULL OR grpc_service_name=''")

    # v0.5 users
    _ensure_column(con, "users", "comment", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "users", "expiry_at", "TEXT")
    _ensure_column(con, "users", "updated_at", "TEXT")
    con.execute("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)")

    # v0.6 routing and custom outbounds
    _ensure_column(con, "routing_settings", "default_outbound_tag", "TEXT NOT NULL DEFAULT 'direct'")
    _ensure_column(con, "routing_rules", "users", "TEXT NOT NULL DEFAULT ''")

    # v0.7 DNS tables are created by SCHEMA.

    # v0.10 RC12 contextual DNS JSON preserves fields unknown to the forms.
    _ensure_column(con, "dns_settings", "extra_json", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(con, "dns_servers", "config_json", "TEXT NOT NULL DEFAULT '{}'")
    con.execute("UPDATE dns_settings SET extra_json = '{}' WHERE extra_json IS NULL OR extra_json = ''")
    con.execute("UPDATE dns_servers SET config_json = '{}' WHERE config_json IS NULL OR config_json = ''")

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

    # v0.10 bidirectional form / JSON editing
    _ensure_column(con, "outbounds", "config_json", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "routing_rules", "target_type", "TEXT NOT NULL DEFAULT 'outbound'")
    _ensure_column(con, "routing_rules", "config_json", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "routing_settings", "extra_json", "TEXT NOT NULL DEFAULT '{}'")
    con.execute("UPDATE routing_rules SET target_type = 'outbound' WHERE target_type IS NULL OR target_type = ''")
    con.execute("UPDATE routing_settings SET extra_json = '{}' WHERE extra_json IS NULL OR extra_json = ''")

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
            "INSERT OR IGNORE INTO config_settings (id, document_json) VALUES (1, '{}')"
        )
        con.execute(
            """
            INSERT OR IGNORE INTO warp_settings (
                id, enabled, outbound_json, account_json, route_mode, selected_domains
            ) VALUES (1, 0, '', '', 'off', '')
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
