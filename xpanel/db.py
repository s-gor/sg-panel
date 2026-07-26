from __future__ import annotations

import json
import os
import re
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
    instance_name TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL,
    listen TEXT NOT NULL DEFAULT '0.0.0.0',
    port INTEGER NOT NULL DEFAULT 443 CHECK (port BETWEEN 1 AND 65535),
    dest TEXT NOT NULL,
    server_name TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    short_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT 'firefox',
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
    xhttp_client_mode TEXT NOT NULL DEFAULT 'stream-one',
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


CREATE TABLE IF NOT EXISTS xray_channels (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    reality_tcp_port INTEGER NOT NULL DEFAULT 443 CHECK (reality_tcp_port BETWEEN 1 AND 65535),
    xhttp_reality_port INTEGER NOT NULL DEFAULT 8444 CHECK (xhttp_reality_port BETWEEN 1 AND 65535),
    xhttp_reality_path TEXT NOT NULL DEFAULT '/sg-xhttp-reality',
    xhttp_reality_mode TEXT NOT NULL DEFAULT 'stream-one'
        CHECK (xhttp_reality_mode IN ('stream-one', 'stream-up', 'packet-up', 'auto')),
    xhttp_tls_port INTEGER NOT NULL DEFAULT 8445 CHECK (xhttp_tls_port BETWEEN 1 AND 65535),
    xhttp_tls_path TEXT NOT NULL DEFAULT '/sg-xhttp-tls',
    xhttp_tls_mode TEXT NOT NULL DEFAULT 'auto'
        CHECK (xhttp_tls_mode IN ('stream-one', 'stream-up', 'packet-up', 'auto')),
    hysteria2_port INTEGER NOT NULL DEFAULT 8446 CHECK (hysteria2_port BETWEEN 1 AND 65535),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hysteria_inbounds (
    id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 3),
    name TEXT NOT NULL,
    tag TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    listen TEXT NOT NULL DEFAULT '0.0.0.0',
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    obfs_mode TEXT NOT NULL DEFAULT 'none' CHECK (obfs_mode IN ('none', 'salamander')),
    obfs_password TEXT,
    obfs_updated_at TEXT,
    obfs_updated_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hysteria_user_auth (
    inbound_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    auth TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (inbound_id, user_id),
    FOREIGN KEY (inbound_id) REFERENCES hysteria_inbounds(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS xhttp_inbounds (
    id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 3),
    name TEXT NOT NULL,
    tag TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    listen TEXT NOT NULL DEFAULT '127.0.0.1',
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    path TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reality_inbounds (
    id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 3),
    name TEXT NOT NULL,
    tag TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    listen TEXT NOT NULL DEFAULT '0.0.0.0',
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    short_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    subscription_last_access_at TEXT,
    connection_order_mode TEXT NOT NULL DEFAULT 'auto'
        CHECK (connection_order_mode IN ('auto', 'manual'))
);

-- FIX35: one person may have several independent Access/device identities.
-- The legacy users.uuid/token columns remain the compatibility mirror for the
-- primary device so upgrades never rotate an existing working credential.
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    uuid TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    expiry_at TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    subscription_enabled INTEGER NOT NULL DEFAULT 1 CHECK (subscription_enabled IN (0, 1)),
    subscription_token TEXT UNIQUE,
    subscription_access_count INTEGER NOT NULL DEFAULT 0,
    subscription_last_access_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_one_primary
    ON devices(user_id) WHERE is_primary = 1;
CREATE INDEX IF NOT EXISTS idx_devices_user
    ON devices(user_id, id);

CREATE TABLE IF NOT EXISTS device_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'applied', 'disabled', 'error')),
    engine_object_id TEXT NOT NULL DEFAULT '',
    config_json TEXT NOT NULL DEFAULT '{}',
    rotated_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (device_id, engine),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_credentials_engine
    ON device_credentials(engine, status);

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
    fingerprint TEXT NOT NULL DEFAULT 'firefox',
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

CREATE TABLE IF NOT EXISTS cascade_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    outbound_id INTEGER,
    exit_name TEXT NOT NULL DEFAULT '',
    service_user_id INTEGER,
    mode TEXT NOT NULL DEFAULT 'external',
    exit_node_id INTEGER,
    cluster_service_uuid TEXT NOT NULL DEFAULT '',
    cluster_service_job_id INTEGER,
    last_test_state TEXT NOT NULL DEFAULT '',
    last_test_ip TEXT NOT NULL DEFAULT '',
    last_test_country TEXT NOT NULL DEFAULT '',
    last_test_colo TEXT NOT NULL DEFAULT '',
    last_test_warp TEXT NOT NULL DEFAULT '',
    last_test_detail TEXT NOT NULL DEFAULT '',
    tested_signature TEXT NOT NULL DEFAULT '',
    last_test_at TEXT,
    enabled_at TEXT,
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
    selected_ips TEXT NOT NULL DEFAULT '',
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
    managed_by TEXT NOT NULL DEFAULT '',
    managed_role TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);



CREATE TABLE IF NOT EXISTS transport_expert_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    xmux_mode TEXT NOT NULL DEFAULT 'auto' CHECK (xmux_mode IN ('auto', 'reduced', 'expert')),
    xhttp_extra_server_json TEXT NOT NULL DEFAULT '{}',
    xhttp_extra_client_json TEXT NOT NULL DEFAULT '{}',
    finalmask_enabled INTEGER NOT NULL DEFAULT 0 CHECK (finalmask_enabled IN (0, 1)),
    finalmask_server_json TEXT NOT NULL DEFAULT '{}',
    finalmask_client_json TEXT NOT NULL DEFAULT '{}',
    ech_mode TEXT NOT NULL DEFAULT 'off' CHECK (ech_mode IN ('off', 'generated', 'existing', 'dns')),
    ech_public_name TEXT NOT NULL DEFAULT '',
    ech_server_keys TEXT NOT NULL DEFAULT '',
    ech_config_list TEXT NOT NULL DEFAULT '',
    certificate_pinning_enabled INTEGER NOT NULL DEFAULT 0 CHECK (certificate_pinning_enabled IN (0, 1)),
    certificate_pinning_sha256 TEXT NOT NULL DEFAULT '',
    certificate_pinning_source TEXT NOT NULL DEFAULT '',
    tls_verify_name_mode TEXT NOT NULL DEFAULT 'auto' CHECK (tls_verify_name_mode IN ('auto', 'manual')),
    tls_verify_name TEXT NOT NULL DEFAULT '',
    client_ca_pem TEXT NOT NULL DEFAULT '',
    client_ca_source TEXT NOT NULL DEFAULT '',
    client_ca_sha256 TEXT NOT NULL DEFAULT '',
    last_validation_state TEXT NOT NULL DEFAULT '',
    last_validation_message TEXT NOT NULL DEFAULT '',
    last_validation_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS geofiles_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source TEXT NOT NULL DEFAULT 'sgclient'
        CHECK (source IN ('sgclient', 'xray', 'loyalsoldier', 'runetfreedom', 'roscomvpn', 'custom', 'local')),
    geoip_url TEXT NOT NULL DEFAULT '',
    geosite_url TEXT NOT NULL DEFAULT '',
    geoip_local_path TEXT NOT NULL DEFAULT '',
    geosite_local_path TEXT NOT NULL DEFAULT '',
    active_geoip_path TEXT NOT NULL DEFAULT '/usr/local/share/xray/geoip.dat',
    active_geosite_path TEXT NOT NULL DEFAULT '/usr/local/share/xray/geosite.dat',
    active_geoip_sha256 TEXT NOT NULL DEFAULT '',
    active_geosite_sha256 TEXT NOT NULL DEFAULT '',
    active_geoip_size INTEGER NOT NULL DEFAULT 0,
    active_geosite_size INTEGER NOT NULL DEFAULT 0,
    active_source TEXT NOT NULL DEFAULT 'xray',
    active_generation TEXT NOT NULL DEFAULT '',
    active_manifest_json TEXT NOT NULL DEFAULT '{}',
    staged_manifest_json TEXT NOT NULL DEFAULT '{}',
    last_check_state TEXT NOT NULL DEFAULT '',
    last_check_message TEXT NOT NULL DEFAULT '',
    last_checked_at TEXT,
    last_applied_at TEXT,
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
    panel_exposure_mode TEXT NOT NULL DEFAULT 'direct'
        CHECK (panel_exposure_mode IN ('direct', 'cloudflare_proxy', 'cloudflare_tunnel')),
    cloudflare_hostname TEXT NOT NULL DEFAULT '',
    cloudflare_origin_lockdown INTEGER NOT NULL DEFAULT 0
        CHECK (cloudflare_origin_lockdown IN (0, 1)),
    cloudflare_access_enabled INTEGER NOT NULL DEFAULT 0
        CHECK (cloudflare_access_enabled IN (0, 1)),
    cloudflare_tunnel_name TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role TEXT NOT NULL DEFAULT 'regional'
        CHECK (role IN ('primary', 'backup', 'regional', 'entry', 'exit', 'test')),
    location TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    is_local INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('local', 'pending', 'online', 'offline', 'revoked')),
    agent_id TEXT UNIQUE,
    agent_token_hash TEXT,
    public_address TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    platform_version TEXT NOT NULL DEFAULT '',
    architecture TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    agent_state TEXT NOT NULL DEFAULT '',
    worker_version TEXT NOT NULL DEFAULT '',
    worker_state TEXT NOT NULL DEFAULT '',
    xray_version TEXT NOT NULL DEFAULT '',
    xray_state TEXT NOT NULL DEFAULT '',
    nginx_version TEXT NOT NULL DEFAULT '',
    nginx_state TEXT NOT NULL DEFAULT '',
    inbound_profile TEXT NOT NULL DEFAULT '',
    xray_encryption_state TEXT NOT NULL DEFAULT '',
    xray_encryption_generation TEXT NOT NULL DEFAULT '',
    xray_encryption_checked_at TEXT,
    xray_minimum_supported TEXT NOT NULL DEFAULT 'v26.6.27',
    geofiles_generation TEXT NOT NULL DEFAULT '',
    geofiles_source TEXT NOT NULL DEFAULT '',
    geofiles_geoip_sha256 TEXT NOT NULL DEFAULT '',
    geofiles_geosite_sha256 TEXT NOT NULL DEFAULT '',
    cpu_percent REAL,
    memory_percent REAL,
    disk_percent REAL,
    load1 REAL,
    client_count INTEGER CHECK (client_count IS NULL OR client_count >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    last_seen_at TEXT,
    registered_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_single_local
    ON nodes(is_local) WHERE is_local = 1;
CREATE INDEX IF NOT EXISTS idx_nodes_state ON nodes(state);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen_at);

CREATE TABLE IF NOT EXISTS node_enrollment_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_hint TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_node_enrollment_node
    ON node_enrollment_tokens(node_id, created_at DESC);

CREATE TABLE IF NOT EXISTS node_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    level TEXT NOT NULL DEFAULT 'info'
        CHECK (level IN ('info', 'success', 'warning', 'error')),
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_node_events_node_created
    ON node_events(node_id, created_at DESC);

CREATE TABLE IF NOT EXISTS node_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    job_type TEXT NOT NULL CHECK (job_type IN ('apply_xray_config','stage_geofiles','validate_geofiles','apply_geofiles','rollback_geofiles','get_geofiles_manifest')),
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    title TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    client_link TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_at TEXT,
    completed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_node_jobs_node_status
    ON node_jobs(node_id, status, id);

CREATE TABLE IF NOT EXISTS node_deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    user_id INTEGER,
    device_id INTEGER,
    user_uuid TEXT NOT NULL,
    device_uuid TEXT NOT NULL DEFAULT '',
    user_name TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    profile TEXT NOT NULL DEFAULT '',
    public_host TEXT NOT NULL DEFAULT '',
    public_port INTEGER,
    client_link TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'removing', 'removed', 'error')),
    last_job_id INTEGER,
    last_message TEXT NOT NULL DEFAULT '',
    slot TEXT NOT NULL DEFAULT 'alt'
        CHECK (slot IN ('primary', 'backup', 'alt')),
    priority INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 9999),
    subscription_enabled INTEGER NOT NULL DEFAULT 1
        CHECK (subscription_enabled IN (0, 1)),
    desired_state TEXT NOT NULL DEFAULT 'active'
        CHECK (desired_state IN ('active', 'standby', 'removed')),
    last_verified_at TEXT,
    client_encryption TEXT NOT NULL DEFAULT '',
    reality_public_key TEXT NOT NULL DEFAULT '',
    reality_short_id TEXT NOT NULL DEFAULT '',
    reality_server_name TEXT NOT NULL DEFAULT '',
    xhttp_path TEXT NOT NULL DEFAULT '',
    xhttp_server_mode TEXT NOT NULL DEFAULT 'auto',
    xhttp_client_mode TEXT NOT NULL DEFAULT 'stream-one',
    encryption_generation TEXT NOT NULL DEFAULT '',
    export_ready INTEGER NOT NULL DEFAULT 0 CHECK (export_ready IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (node_id, user_uuid),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
    FOREIGN KEY (last_job_id) REFERENCES node_jobs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_node_deployments_user
    ON node_deployments(user_id, state);
CREATE INDEX IF NOT EXISTS idx_node_deployments_node
    ON node_deployments(node_id, state);
CREATE TABLE IF NOT EXISTS client_failover_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node_id INTEGER,
    target_node_id INTEGER NOT NULL,
    mode TEXT NOT NULL DEFAULT 'prepare_backup'
        CHECK (mode IN ('prepare_backup', 'make_primary', 'copy')),
    status TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned', 'queued', 'running', 'succeeded', 'failed', 'cancelled')),
    total_clients INTEGER NOT NULL DEFAULT 0 CHECK (total_clients >= 0),
    succeeded_clients INTEGER NOT NULL DEFAULT 0 CHECK (succeeded_clients >= 0),
    failed_clients INTEGER NOT NULL DEFAULT 0 CHECK (failed_clients >= 0),
    node_job_id INTEGER,
    summary TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_node_id) REFERENCES nodes(id) ON DELETE SET NULL,
    FOREIGN KEY (target_node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (node_job_id) REFERENCES node_jobs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_client_failover_batches_target
    ON client_failover_batches(target_node_id, status, id DESC);

CREATE TABLE IF NOT EXISTS client_failover_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    deployment_id INTEGER,
    status TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned', 'queued', 'succeeded', 'failed', 'skipped')),
    message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (batch_id, user_id),
    FOREIGN KEY (batch_id) REFERENCES client_failover_batches(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (deployment_id) REFERENCES node_deployments(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_client_failover_targets_batch
    ON client_failover_targets(batch_id, status);

CREATE TABLE IF NOT EXISTS user_deletion_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT NOT NULL,
    user_uuid TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS user_deletion_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    job_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (request_id, node_id),
    FOREIGN KEY (request_id) REFERENCES user_deletion_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (job_id) REFERENCES node_jobs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_deletion_targets_job
    ON user_deletion_targets(job_id);

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


def _migrate_users_to_devices(con: sqlite3.Connection) -> None:
    """Create one primary Access for every legacy user without rotating UUIDs.

    The users row remains the person/central catalogue record.  Its UUID and
    subscription token mirror the primary device for backwards-compatible
    links, old backups and Node deployment metadata.
    """
    users = con.execute(
        "SELECT * FROM users ORDER BY id"
    ).fetchall()
    for user in users:
        user_id = int(user["id"])
        token = str(user["subscription_token"] or "") or secrets.token_urlsafe(32)
        if not user["subscription_token"]:
            con.execute(
                "UPDATE users SET subscription_token=? WHERE id=?",
                (token, user_id),
            )
        primary = con.execute(
            "SELECT * FROM devices WHERE user_id=? AND is_primary=1 ORDER BY id LIMIT 1",
            (user_id,),
        ).fetchone()
        if primary is None:
            cursor = con.execute(
                """
                INSERT INTO devices (
                    user_id, name, uuid, enabled, comment, expiry_at, is_primary,
                    subscription_enabled, subscription_token,
                    subscription_access_count, subscription_last_access_at, created_at
                ) VALUES (?, 'Основной доступ', ?, ?, '', ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, str(user["uuid"]), int(user["enabled"]), user["expiry_at"],
                    int(user["subscription_enabled"]), token,
                    int(user["subscription_access_count"] or 0),
                    user["subscription_last_access_at"], user["created_at"],
                ),
            )
            device_id = int(cursor.lastrowid)
        else:
            device_id = int(primary["id"])
            # Primary is the exact compatibility mirror.  This is intentionally
            # idempotent and never changes a non-primary device credential.
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
                    user["subscription_last_access_at"], device_id,
                ),
            )
        # Preserve every legacy Hysteria credential.  Older SG-Panel builds
        # stored one auth per (inbound_id, user_id); the device model stores the
        # same map in the primary Access credential.  Migration must never
        # rotate auths for inbound 2/3 because existing client links depend on
        # those exact values.
        legacy_auth_rows = con.execute(
            "SELECT inbound_id, auth FROM hysteria_user_auth WHERE user_id=? ORDER BY inbound_id",
            (user_id,),
        ).fetchall()
        legacy_auths = {
            str(int(row["inbound_id"])): str(row["auth"])
            for row in legacy_auth_rows
            if str(row["auth"] or "").strip()
        }
        legacy_auths.setdefault("1", str(user["uuid"]))

        credential = con.execute(
            "SELECT * FROM device_credentials WHERE device_id=? AND engine='xray'",
            (device_id,),
        ).fetchone()
        payload: dict[str, object]
        if credential is None:
            payload = {"hysteria_auths": legacy_auths}
            con.execute(
                """
                INSERT INTO device_credentials
                    (device_id, engine, status, engine_object_id, config_json)
                VALUES (?, 'xray', 'applied', ?, ?)
                """,
                (
                    device_id,
                    str(user["uuid"]),
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                ),
            )
        else:
            try:
                decoded = json.loads(str(credential["config_json"] or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                decoded = {}
            payload = decoded if isinstance(decoded, dict) else {}
            auths = payload.get("hysteria_auths")
            if not isinstance(auths, dict):
                auths = {}
            old_single = str(payload.get("hysteria_auth") or "").strip()
            if old_single and not str(auths.get("1") or "").strip():
                auths["1"] = old_single
            for inbound_id, auth in legacy_auths.items():
                if not str(auths.get(inbound_id) or "").strip():
                    auths[inbound_id] = auth
            payload["hysteria_auths"] = auths
            payload.pop("hysteria_auth", None)
            con.execute(
                """
                UPDATE device_credentials
                SET engine_object_id=?, config_json=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    str(user["uuid"]),
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    int(credential["id"]),
                ),
            )

    # Link existing Controller/Node deployments to the migrated device.
    con.execute(
        """
        UPDATE node_deployments
        SET device_id=(SELECT d.id FROM devices d WHERE d.uuid=node_deployments.user_uuid LIMIT 1),
            device_uuid=user_uuid,
            device_name=COALESCE((SELECT d.name FROM devices d WHERE d.uuid=node_deployments.user_uuid LIMIT 1), '')
        WHERE device_id IS NULL OR device_id=0 OR device_uuid=''
        """
    )


def _migrate(con: sqlite3.Connection) -> None:
    # v0.5 server settings
    _ensure_column(con, "server_settings", "flow", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "server_settings", "loglevel", "TEXT NOT NULL DEFAULT 'warning'")
    _ensure_column(con, "server_settings", "api_listen", "TEXT NOT NULL DEFAULT '127.0.0.1:10085'")
    _ensure_column(con, "server_settings", "stats_enabled", "INTEGER NOT NULL DEFAULT 1")

    # v0.10 RC46 Multi-Node service health fields. The CREATE TABLE schema
    # already contains them for new databases; these guards keep preview and
    # restored databases forward-compatible.
    _ensure_column(con, "nodes", "xray_state", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "nginx_state", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "agent_state", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "worker_version", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "worker_state", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "geofiles_generation", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "geofiles_source", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "geofiles_geoip_sha256", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "geofiles_geosite_sha256", "TEXT NOT NULL DEFAULT ''")

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

    # v0.10 RC64 visible panel identity and simplified Cascade roles.
    _ensure_column(con, "server_settings", "instance_name", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "cascade_settings", "exit_name", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "cascade_settings", "service_user_id", "INTEGER")
    _ensure_column(con, "cascade_settings", "mode", "TEXT NOT NULL DEFAULT 'external'")
    _ensure_column(con, "cascade_settings", "exit_node_id", "INTEGER")
    _ensure_column(con, "cascade_settings", "cluster_service_uuid", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "cascade_settings", "cluster_service_job_id", "INTEGER")
    con.execute("UPDATE server_settings SET instance_name='' WHERE instance_name IS NULL")
    con.execute("UPDATE cascade_settings SET exit_name='' WHERE exit_name IS NULL")
    con.execute("UPDATE cascade_settings SET mode='external' WHERE mode IS NULL OR mode NOT IN ('external','cluster')")
    con.execute("UPDATE cascade_settings SET cluster_service_uuid='' WHERE cluster_service_uuid IS NULL")

    # v0.10 RC51 panel exposure modes and safe Cloudflare metadata.
    _ensure_column(con, "security_settings", "panel_exposure_mode", "TEXT NOT NULL DEFAULT 'direct'")
    _ensure_column(con, "security_settings", "cloudflare_hostname", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "security_settings", "cloudflare_origin_lockdown", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "security_settings", "cloudflare_access_enabled", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "security_settings", "cloudflare_tunnel_name", "TEXT NOT NULL DEFAULT ''")
    con.execute("UPDATE security_settings SET panel_exposure_mode='direct' WHERE panel_exposure_mode IS NULL OR panel_exposure_mode NOT IN ('direct','cloudflare_proxy','cloudflare_tunnel')")
    con.execute("UPDATE security_settings SET cloudflare_hostname='' WHERE cloudflare_hostname IS NULL")
    con.execute("UPDATE security_settings SET cloudflare_tunnel_name='' WHERE cloudflare_tunnel_name IS NULL")

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

    # FIX40 UI23: Hysteria2 Salamander is stored per inbound.  Existing
    # databases remain compatible and default to an unchanged, unobfuscated
    # transport.  Re-running the migration is intentionally idempotent.
    _ensure_column(con, "hysteria_inbounds", "obfs_mode", "TEXT NOT NULL DEFAULT 'none'")
    _ensure_column(con, "hysteria_inbounds", "obfs_password", "TEXT")
    _ensure_column(con, "hysteria_inbounds", "obfs_updated_at", "TEXT")
    _ensure_column(con, "hysteria_inbounds", "obfs_updated_by", "TEXT NOT NULL DEFAULT ''")
    con.execute(
        "UPDATE hysteria_inbounds SET obfs_mode='none' "
        "WHERE obfs_mode IS NULL OR obfs_mode NOT IN ('none','salamander')"
    )
    # Some early Hysteria2 schemas created obfs_password as NOT NULL.
    # SQLite cannot relax that constraint with ALTER TABLE, so keep an empty
    # string for those legacy tables while new databases use NULL. Both values
    # are normalised as "not configured" by the service layer.
    password_column = next(
        (
            row
            for row in con.execute("PRAGMA table_info(hysteria_inbounds)").fetchall()
            if str(row["name"]) == "obfs_password"
        ),
        None,
    )
    disabled_password = "" if password_column is not None and int(password_column["notnull"]) else None
    con.execute(
        "UPDATE hysteria_inbounds SET obfs_password=? WHERE obfs_mode='none'",
        (disabled_password,),
    )
    con.execute(
        "UPDATE hysteria_inbounds SET obfs_updated_by='' "
        "WHERE obfs_updated_by IS NULL"
    )

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


    # SG-Panel 050: advanced transport settings and managed GeoFiles.
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS transport_expert_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            xmux_mode TEXT NOT NULL DEFAULT 'auto',
            xhttp_extra_server_json TEXT NOT NULL DEFAULT '{}',
            xhttp_extra_client_json TEXT NOT NULL DEFAULT '{}',
            finalmask_enabled INTEGER NOT NULL DEFAULT 0 CHECK (finalmask_enabled IN (0, 1)),
            finalmask_server_json TEXT NOT NULL DEFAULT '{}',
            finalmask_client_json TEXT NOT NULL DEFAULT '{}',
            ech_mode TEXT NOT NULL DEFAULT 'off',
            ech_public_name TEXT NOT NULL DEFAULT '',
            ech_server_keys TEXT NOT NULL DEFAULT '',
            ech_config_list TEXT NOT NULL DEFAULT '',
            certificate_pinning_enabled INTEGER NOT NULL DEFAULT 0 CHECK (certificate_pinning_enabled IN (0, 1)),
            certificate_pinning_sha256 TEXT NOT NULL DEFAULT '',
            certificate_pinning_source TEXT NOT NULL DEFAULT '',
            tls_verify_name_mode TEXT NOT NULL DEFAULT 'auto',
            tls_verify_name TEXT NOT NULL DEFAULT '',
            client_ca_pem TEXT NOT NULL DEFAULT '',
            client_ca_source TEXT NOT NULL DEFAULT '',
            client_ca_sha256 TEXT NOT NULL DEFAULT '',
            last_validation_state TEXT NOT NULL DEFAULT '',
            last_validation_message TEXT NOT NULL DEFAULT '',
            last_validation_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS geofiles_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            source TEXT NOT NULL DEFAULT 'sgclient',
            geoip_url TEXT NOT NULL DEFAULT '',
            geosite_url TEXT NOT NULL DEFAULT '',
            geoip_local_path TEXT NOT NULL DEFAULT '',
            geosite_local_path TEXT NOT NULL DEFAULT '',
            active_geoip_path TEXT NOT NULL DEFAULT '/usr/local/share/xray/geoip.dat',
            active_geosite_path TEXT NOT NULL DEFAULT '/usr/local/share/xray/geosite.dat',
            active_geoip_sha256 TEXT NOT NULL DEFAULT '',
            active_geosite_sha256 TEXT NOT NULL DEFAULT '',
            active_geoip_size INTEGER NOT NULL DEFAULT 0,
            active_geosite_size INTEGER NOT NULL DEFAULT 0,
            active_source TEXT NOT NULL DEFAULT 'xray',
            active_generation TEXT NOT NULL DEFAULT '',
            active_manifest_json TEXT NOT NULL DEFAULT '{}',
            staged_manifest_json TEXT NOT NULL DEFAULT '{}',
            last_check_state TEXT NOT NULL DEFAULT '',
            last_check_message TEXT NOT NULL DEFAULT '',
            last_checked_at TEXT,
            last_applied_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # GitHub main: flexible GeoFiles sources and structural validation.
    # Existing RC70 databases used a restrictive CHECK with xray/v2fly. Rebuild
    # this single-row table once so new source identifiers can be stored without
    # weakening constraints for the rest of the database.
    migration_name = "main-flexible-geofiles-sources"
    applied = con.execute(
        "SELECT 1 FROM schema_migrations WHERE name = ?", (migration_name,)
    ).fetchone()
    if applied is None:
        table_sql_row = con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='geofiles_settings'"
        ).fetchone()
        table_sql = str(table_sql_row[0] or "") if table_sql_row else ""
        if "'sgclient'" not in table_sql or "'roscomvpn'" not in table_sql:
            con.execute("ALTER TABLE geofiles_settings RENAME TO geofiles_settings_legacy")
            con.execute(
                """
                CREATE TABLE geofiles_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    source TEXT NOT NULL DEFAULT 'sgclient'
                        CHECK (source IN ('sgclient', 'xray', 'loyalsoldier', 'runetfreedom', 'roscomvpn', 'custom', 'local')),
                    geoip_url TEXT NOT NULL DEFAULT '',
                    geosite_url TEXT NOT NULL DEFAULT '',
                    geoip_local_path TEXT NOT NULL DEFAULT '',
                    geosite_local_path TEXT NOT NULL DEFAULT '',
                    active_geoip_path TEXT NOT NULL DEFAULT '/usr/local/share/xray/geoip.dat',
                    active_geosite_path TEXT NOT NULL DEFAULT '/usr/local/share/xray/geosite.dat',
                    active_geoip_sha256 TEXT NOT NULL DEFAULT '',
                    active_geosite_sha256 TEXT NOT NULL DEFAULT '',
                    active_geoip_size INTEGER NOT NULL DEFAULT 0,
                    active_geosite_size INTEGER NOT NULL DEFAULT 0,
                    active_source TEXT NOT NULL DEFAULT 'xray',
                    staged_manifest_json TEXT NOT NULL DEFAULT '{}',
                    last_check_state TEXT NOT NULL DEFAULT '',
                    last_check_message TEXT NOT NULL DEFAULT '',
                    last_checked_at TEXT,
                    last_applied_at TEXT,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            con.execute(
                """
                INSERT INTO geofiles_settings (
                    id, source, geoip_url, geosite_url, geoip_local_path,
                    geosite_local_path, active_geoip_path, active_geosite_path,
                    active_geoip_sha256, active_geosite_sha256, active_geoip_size,
                    active_geosite_size, active_source, staged_manifest_json,
                    last_check_state, last_check_message, last_checked_at,
                    last_applied_at, updated_at
                )
                SELECT id,
                    CASE source WHEN 'xray' THEN 'sgclient'
                                WHEN 'v2fly' THEN 'roscomvpn'
                                ELSE source END,
                    geoip_url, geosite_url, geoip_local_path, geosite_local_path,
                    active_geoip_path, active_geosite_path, active_geoip_sha256,
                    active_geosite_sha256, active_geoip_size, active_geosite_size,
                    active_source, '{}', '', '', NULL, last_applied_at, updated_at
                FROM geofiles_settings_legacy
                """
            )
            con.execute("DROP TABLE geofiles_settings_legacy")
        else:
            con.execute(
                "UPDATE geofiles_settings SET source='sgclient', staged_manifest_json='{}', "
                "last_check_state='', last_check_message='', last_checked_at=NULL "
                "WHERE source='xray'"
            )
        con.execute(
            "INSERT INTO schema_migrations (name) VALUES (?)", (migration_name,)
        )

    # Preview 9 GeoFiles transaction generations.
    _ensure_column(con, "geofiles_settings", "active_generation", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "geofiles_settings", "active_manifest_json", "TEXT NOT NULL DEFAULT '{}'")

    # LIVE1 XMUX: explicit safe modes. Connection ordering is per client.
    _ensure_column(con, "transport_expert_settings", "xmux_mode", "TEXT NOT NULL DEFAULT 'auto'")
    _ensure_column(con, "users", "connection_order_mode", "TEXT NOT NULL DEFAULT 'auto'")
    con.execute("UPDATE transport_expert_settings SET xmux_mode='auto' WHERE xmux_mode IS NULL OR xmux_mode NOT IN ('auto','reduced','expert')")
    con.execute("UPDATE users SET connection_order_mode='auto' WHERE connection_order_mode IS NULL OR connection_order_mode NOT IN ('auto','manual')")

    # RC51: empty expert fields are normalized to visible neutral values.
    con.execute("UPDATE transport_expert_settings SET xhttp_extra_server_json='{}' WHERE xhttp_extra_server_json IS NULL OR TRIM(xhttp_extra_server_json)=''")
    con.execute("UPDATE transport_expert_settings SET xhttp_extra_client_json='{}' WHERE xhttp_extra_client_json IS NULL OR TRIM(xhttp_extra_client_json)=''")
    con.execute("UPDATE transport_expert_settings SET finalmask_server_json='{}' WHERE finalmask_server_json IS NULL OR TRIM(finalmask_server_json)=''")
    con.execute("UPDATE transport_expert_settings SET finalmask_client_json='{}' WHERE finalmask_client_json IS NULL OR TRIM(finalmask_client_json)=''")
    con.execute("UPDATE transport_expert_settings SET ech_mode='off' WHERE ech_mode IS NULL OR ech_mode NOT IN ('off','generated','existing','dns')")

    # RC53: explicit SG Client contract for TLS name checks and private CA bundles.
    _ensure_column(con, "transport_expert_settings", "tls_verify_name_mode", "TEXT NOT NULL DEFAULT 'auto'")
    _ensure_column(con, "transport_expert_settings", "tls_verify_name", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "transport_expert_settings", "client_ca_pem", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "transport_expert_settings", "client_ca_source", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "transport_expert_settings", "client_ca_sha256", "TEXT NOT NULL DEFAULT ''")
    con.execute("UPDATE transport_expert_settings SET tls_verify_name_mode='auto' WHERE tls_verify_name_mode IS NULL OR tls_verify_name_mode NOT IN ('auto','manual')")
    con.execute("UPDATE transport_expert_settings SET tls_verify_name='' WHERE tls_verify_name IS NULL")
    con.execute("UPDATE transport_expert_settings SET client_ca_pem='' WHERE client_ca_pem IS NULL")
    con.execute("UPDATE transport_expert_settings SET client_ca_source='' WHERE client_ca_source IS NULL")
    con.execute("UPDATE transport_expert_settings SET client_ca_sha256='' WHERE client_ca_sha256 IS NULL")

    # v0.5 users
    _ensure_column(con, "users", "comment", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "users", "expiry_at", "TEXT")
    _ensure_column(con, "users", "updated_at", "TEXT")
    con.execute("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)")

    # v0.6 routing and custom outbounds
    _ensure_column(con, "routing_settings", "default_outbound_tag", "TEXT NOT NULL DEFAULT 'direct'")
    _ensure_column(con, "routing_rules", "users", "TEXT NOT NULL DEFAULT ''")

    # v0.10 RC56: WARP selection stores domain/geosite and IP/geoip conditions separately.
    _ensure_column(con, "warp_settings", "selected_ips", "TEXT NOT NULL DEFAULT ''")

    # v0.10 RC67: remove the short-lived RC66 HTTP/SOCKS experiment.
    # Existing RC66 databases may still contain its private table and routing
    # rules. They are removed once so a missing experimental outbound cannot
    # block generation of the normal Xray configuration after upgrade.
    legacy_proxy_table = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='proxy_outbounds'"
    ).fetchone()
    if legacy_proxy_table is not None:
        legacy_tags = [
            str(row[0])
            for row in con.execute("SELECT tag FROM proxy_outbounds").fetchall()
            if str(row[0] or "").strip()
        ]
        if legacy_tags:
            placeholders = ",".join("?" for _ in legacy_tags)
            con.execute(
                f"UPDATE routing_settings SET default_outbound_tag='direct', "
                f"updated_at=CURRENT_TIMESTAMP WHERE default_outbound_tag IN ({placeholders})",
                legacy_tags,
            )
            con.execute(
                f"DELETE FROM routing_rules WHERE target_type='outbound' "
                f"AND outbound_tag IN ({placeholders})",
                legacy_tags,
            )
        con.execute("DROP TABLE proxy_outbounds")
        con.execute(
            "INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)",
            ("rc67-remove-experimental-proxy",),
        )

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
    _ensure_column(con, "routing_rules", "managed_by", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "routing_rules", "managed_role", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "routing_settings", "extra_json", "TEXT NOT NULL DEFAULT '{}'")
    con.execute("UPDATE routing_rules SET target_type = 'outbound' WHERE target_type IS NULL OR target_type = ''")
    con.execute("UPDATE routing_settings SET extra_json = '{}' WHERE extra_json IS NULL OR extra_json = ''")

    # Preview 8 central client deployment model. Existing installations already
    # have node_deployments; these columns make Controller the source of truth
    # for Primary / Backup / Alt order and subscription visibility.
    _ensure_column(con, "node_deployments", "slot", "TEXT NOT NULL DEFAULT 'alt'")
    _ensure_column(con, "node_deployments", "priority", "INTEGER NOT NULL DEFAULT 100")
    _ensure_column(con, "node_deployments", "subscription_enabled", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(con, "node_deployments", "desired_state", "TEXT NOT NULL DEFAULT 'active'")
    _ensure_column(con, "node_deployments", "last_verified_at", "TEXT")
    con.execute("UPDATE node_deployments SET slot='alt' WHERE slot IS NULL OR slot NOT IN ('primary','backup','alt')")
    con.execute("UPDATE node_deployments SET priority=100 WHERE priority IS NULL OR priority < 1")
    con.execute("UPDATE node_deployments SET subscription_enabled=1 WHERE subscription_enabled IS NULL")
    con.execute("UPDATE node_deployments SET desired_state='active' WHERE desired_state IS NULL OR desired_state NOT IN ('active','standby','removed')")

    # V39: per-server XHTTP REALITY / ML-KEM deployment metadata.
    _ensure_column(con, "node_deployments", "client_encryption", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "reality_public_key", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "reality_short_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "reality_server_name", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "xhttp_path", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "xhttp_server_mode", "TEXT NOT NULL DEFAULT 'auto'")
    _ensure_column(con, "node_deployments", "xhttp_client_mode", "TEXT NOT NULL DEFAULT 'stream-one'")
    _ensure_column(con, "node_deployments", "encryption_generation", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "export_ready", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "server_settings", "xhttp_client_mode", "TEXT NOT NULL DEFAULT 'stream-one'")
    _ensure_column(con, "nodes", "xray_encryption_state", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "xray_encryption_generation", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "nodes", "xray_encryption_checked_at", "TEXT")
    _ensure_column(con, "nodes", "xray_minimum_supported", "TEXT NOT NULL DEFAULT 'v26.6.27'")
    con.execute("UPDATE server_settings SET xhttp_client_mode='stream-one' WHERE xhttp_client_mode IS NULL OR xhttp_client_mode NOT IN ('auto','packet-up','stream-up','stream-one')")
    con.execute("UPDATE node_deployments SET xhttp_server_mode='auto' WHERE xhttp_server_mode IS NULL OR xhttp_server_mode NOT IN ('auto','packet-up','stream-up','stream-one')")
    con.execute("UPDATE node_deployments SET xhttp_client_mode='stream-one' WHERE xhttp_client_mode IS NULL OR xhttp_client_mode NOT IN ('auto','packet-up','stream-up','stream-one')")
    con.execute("UPDATE node_deployments SET export_ready=0 WHERE export_ready IS NULL")
    con.execute(
        "UPDATE node_deployments SET export_ready=1 "
        "WHERE TRIM(COALESCE(client_link,'')) LIKE 'vless://%' "
        "AND LOWER(COALESCE(profile,'')) NOT LIKE '%xhttp%'"
    )
    con.execute("UPDATE nodes SET xray_minimum_supported='v26.6.27' WHERE xray_minimum_supported IS NULL OR TRIM(xray_minimum_supported)=''")

    # Create this index only after ALTER TABLE. Existing Preview 7 databases
    # still have the old node_deployments shape when SCHEMA is executed.
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_deployments_user_slot "
        "ON node_deployments(user_id, slot, priority)"
    )

    # v0.8 persistent subscription URLs
    _ensure_column(con, "users", "subscription_enabled", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(con, "users", "subscription_token", "TEXT")
    _ensure_column(con, "users", "subscription_access_count", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(con, "users", "subscription_last_access_at", "TEXT")
    con.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_subscription_token "
        "ON users(subscription_token)"
    )

    # FIX35 central Access/device catalogue and deployment linkage.
    _ensure_column(con, "node_deployments", "device_id", "INTEGER")
    _ensure_column(con, "node_deployments", "device_uuid", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(con, "node_deployments", "device_name", "TEXT NOT NULL DEFAULT ''")
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_deployments_device "
        "ON node_deployments(device_id, state)"
    )
    _migrate_users_to_devices(con)


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
            "INSERT OR IGNORE INTO transport_expert_settings (id) VALUES (1)"
        )
        con.execute(
            "INSERT OR IGNORE INTO cascade_settings (id) VALUES (1)"
        )
        con.execute(
            "INSERT OR IGNORE INTO geofiles_settings (id) VALUES (1)"
        )
        server_row = con.execute(
            """
            SELECT inbound_profile, listen, port, short_id, transport_listen,
                   transport_port, xhttp_path
            FROM server_settings WHERE id = 1
            """
        ).fetchone()
        primary_enabled = 1
        primary_listen = str(server_row["listen"] or "0.0.0.0") if server_row else "0.0.0.0"
        primary_port = int(server_row["port"] or 443) if server_row else 443
        con.executemany(
            """
            INSERT OR IGNORE INTO hysteria_inbounds
                (id, name, tag, enabled, listen, port)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (1, "Hysteria 2 — основной", "vless-reality-in", primary_enabled, primary_listen, primary_port),
                (2, "Hysteria 2 — резервный", "hysteria2-secondary-in", 0, "0.0.0.0", 8443),
                (3, "Hysteria 2 — дополнительный", "hysteria2-tertiary-in", 0, "0.0.0.0", 9443),
            ),
        )
        con.execute(
            "UPDATE hysteria_inbounds SET enabled=1 WHERE id=1 AND enabled!=1"
        )
        xhttp_listen = str(server_row["transport_listen"] or "127.0.0.1") if server_row else "127.0.0.1"
        xhttp_port = int(server_row["transport_port"] or 8443) if server_row else 8443
        xhttp_path = str(server_row["xhttp_path"] or "/sg-xhttp") if server_row else "/sg-xhttp"
        xhttp_defaults = (
            (1, "XHTTP — основной", "vless-reality-in", 1, xhttp_listen, xhttp_port, xhttp_path),
            (2, "XHTTP — резервный", "xhttp-secondary-in", 0, "127.0.0.1", 8444, f"/sg-xhttp-{secrets.token_hex(6)}"),
            (3, "XHTTP — дополнительный", "xhttp-tertiary-in", 0, "127.0.0.1", 8445, f"/sg-xhttp-{secrets.token_hex(6)}"),
        )
        con.executemany(
            """
            INSERT OR IGNORE INTO xhttp_inbounds
                (id, name, tag, enabled, listen, port, path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            xhttp_defaults,
        )
        con.execute(
            """
            UPDATE xhttp_inbounds
            SET enabled=1, listen=?, port=?, path=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (xhttp_listen, xhttp_port, xhttp_path),
        )
        existing_primary_reality = con.execute(
            "SELECT short_id FROM reality_inbounds WHERE id = 1"
        ).fetchone()
        server_reality_short_id = str(server_row["short_id"] or "").strip().lower() if server_row else ""
        stored_primary_short_id = (
            str(existing_primary_reality["short_id"] or "").strip().lower()
            if existing_primary_reality else ""
        )

        def valid_reality_short_id(value: str) -> bool:
            return bool(re.fullmatch(r"[0-9a-f]{2,32}", value)) and len(value) % 2 == 0

        if valid_reality_short_id(server_reality_short_id):
            reality_short_id = server_reality_short_id
        elif valid_reality_short_id(stored_primary_short_id):
            reality_short_id = stored_primary_short_id
        else:
            reality_short_id = secrets.token_hex(8)

        # server_settings.short_id is the legacy source used by links and forms.
        # Keep it synchronized with the primary Multi-REALITY slot so an RC41
        # migration from an empty legacy field never leaves the UI blank.
        if server_row:
            con.execute(
                "UPDATE server_settings SET short_id = ? WHERE id = 1",
                (reality_short_id,),
            )

        reality_defaults = (
            (1, "REALITY — основной", "vless-reality-in", 1, primary_listen, primary_port, reality_short_id),
            (2, "REALITY — резервный", "reality-secondary-in", 0, "0.0.0.0", 8443, secrets.token_hex(8)),
            (3, "REALITY — дополнительный", "reality-tertiary-in", 0, "0.0.0.0", 9443, secrets.token_hex(8)),
        )
        con.executemany(
            """
            INSERT OR IGNORE INTO reality_inbounds
                (id, name, tag, enabled, listen, port, short_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            reality_defaults,
        )
        con.execute(
            """
            UPDATE reality_inbounds
            SET enabled=1, listen=?, port=?, short_id=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (primary_listen, primary_port, reality_short_id),
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
        con.execute(
            """
            INSERT OR IGNORE INTO nodes (
                name, slug, role, location, description, is_local, state
            ) VALUES (
                'Основной сервер', 'local', 'primary', '',
                'Сервер, на котором работает центральная SG-Panel', 1, 'local'
            )
            """
        )
        con.execute(
            """
            UPDATE nodes
            SET is_local = 1, role = 'primary', state = 'local',
                updated_at = CURRENT_TIMESTAMP
            WHERE slug = 'local'
            """
        )
        # Every client is a central Controller record. Mirror the local
        # deployment into the same table used for SG-Node deployments so the
        # UI, subscriptions, backups and future failover operations share one
        # consistent model. Links for the local server are generated live.
        con.execute(
            """
            INSERT INTO node_deployments (
                node_id, user_id, user_uuid, user_name, profile, public_host,
                public_port, client_link, state, last_message, slot, priority,
                subscription_enabled, desired_state, last_verified_at
            )
            SELECT n.id, u.id, u.uuid, u.name,
                   COALESCE(s.inbound_profile, 'raw_reality'),
                   COALESCE(s.address, ''), COALESCE(s.port, 443), '',
                   'active', 'Локальное развёртывание Controller',
                   'primary', 10, 1,
                   CASE WHEN COALESCE(u.enabled, 1)=1 THEN 'active' ELSE 'standby' END,
                   CURRENT_TIMESTAMP
            FROM users u
            JOIN nodes n ON n.is_local = 1
            LEFT JOIN server_settings s ON s.id = 1
            ON CONFLICT(node_id, user_uuid) DO UPDATE SET
                user_id=excluded.user_id, user_name=excluded.user_name,
                profile=excluded.profile, public_host=excluded.public_host,
                public_port=excluded.public_port, state='active',
                desired_state=excluded.desired_state,
                last_message='Локальное развёртывание Controller',
                updated_at=CURRENT_TIMESTAMP
            """
        )
        con.execute(
            """
            DELETE FROM node_deployments
            WHERE node_id IN (SELECT id FROM nodes WHERE is_local = 1)
              AND (user_id IS NULL OR user_id NOT IN (SELECT id FROM users))
            """
        )
        con.execute(
            """
            UPDATE node_deployments AS local_deployment
            SET slot = CASE WHEN EXISTS (
                    SELECT 1 FROM node_deployments remote_deployment
                    JOIN nodes remote_node ON remote_node.id=remote_deployment.node_id
                    WHERE remote_deployment.user_id=local_deployment.user_id
                      AND remote_node.is_local=0
                      AND remote_deployment.slot='primary'
                      AND remote_deployment.state='active'
                      AND remote_deployment.desired_state='active'
                ) THEN 'backup' ELSE 'primary' END,
                priority = CASE WHEN EXISTS (
                    SELECT 1 FROM node_deployments remote_deployment
                    JOIN nodes remote_node ON remote_node.id=remote_deployment.node_id
                    WHERE remote_deployment.user_id=local_deployment.user_id
                      AND remote_node.is_local=0
                      AND remote_deployment.slot='primary'
                      AND remote_deployment.state='active'
                      AND remote_deployment.desired_state='active'
                ) THEN 20 ELSE 10 END,
                desired_state=CASE
                    WHEN user_id IN (SELECT id FROM users WHERE enabled=1) THEN 'active'
                    ELSE 'standby' END
            WHERE node_id IN (SELECT id FROM nodes WHERE is_local = 1)
            """
        )
        con.execute(
            """
            UPDATE node_deployments
            SET slot = CASE
                    WHEN node_id IN (SELECT id FROM nodes WHERE role='backup') THEN 'backup'
                    ELSE 'alt' END,
                priority = CASE
                    WHEN node_id IN (SELECT id FROM nodes WHERE role='backup') THEN 20
                    ELSE 100 END
            WHERE node_id IN (SELECT id FROM nodes WHERE is_local = 0)
              AND slot='alt' AND priority=100
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
