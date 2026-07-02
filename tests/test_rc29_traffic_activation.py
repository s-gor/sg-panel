from __future__ import annotations

import argparse
import os
import sqlite3
import tempfile
from pathlib import Path

from xpanel.cli import cmd_set_server
from xpanel.db import connect, init_db
from xpanel.service import add_user, build_config

ROOT = Path(__file__).resolve().parents[1]


def _create_rc28_database(
    path: Path, *, stats_enabled: int = 0, insert_server: bool = True
) -> None:
    """Create the minimum legacy schema needed to exercise the RC29 migration."""
    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE server_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                address TEXT NOT NULL,
                listen TEXT NOT NULL DEFAULT '0.0.0.0',
                port INTEGER NOT NULL DEFAULT 443,
                dest TEXT NOT NULL,
                server_name TEXT NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                short_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL DEFAULT 'chrome',
                flow TEXT NOT NULL DEFAULT '',
                loglevel TEXT NOT NULL DEFAULT 'warning',
                api_listen TEXT NOT NULL DEFAULT '127.0.0.1:10085',
                stats_enabled INTEGER NOT NULL DEFAULT 0,
                config_path TEXT NOT NULL DEFAULT '/usr/local/etc/xray/config.json',
                xray_bin TEXT NOT NULL DEFAULT '/usr/local/bin/xray',
                xray_service TEXT NOT NULL DEFAULT 'xray'
            )
            """
        )
        if insert_server:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, dest, server_name, private_key, public_key,
                    short_id, stats_enabled
                ) VALUES (1, 'vpn.example.com', 'www.bing.com:443', 'www.bing.com',
                          'private', 'public', '0011223344556677', ?)
                """,
                (stats_enabled,),
            )
        con.commit()
    finally:
        con.close()


def test_rc29_migration_enables_stats_once_on_existing_installation() -> None:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "panel.db"
        _create_rc28_database(path, stats_enabled=0)
        os.environ["XPANEL_DB"] = str(path)
        try:
            init_db()
            with connect() as con:
                server = con.execute(
                    "SELECT stats_enabled FROM server_settings WHERE id = 1"
                ).fetchone()
                marker = con.execute(
                    "SELECT 1 FROM schema_migrations "
                    "WHERE name = 'rc29-enable-xray-stats'"
                ).fetchone()
            assert server is not None and server["stats_enabled"] == 1
            assert marker is not None

            # A later explicit administrator choice must survive init-db.
            with connect() as con:
                con.execute("UPDATE server_settings SET stats_enabled = 0 WHERE id = 1")
            init_db()
            with connect() as con:
                value = con.execute(
                    "SELECT stats_enabled FROM server_settings WHERE id = 1"
                ).fetchone()[0]
            assert value == 0
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_migrated_config_contains_user_stats_api_and_policy() -> None:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "panel.db"
        _create_rc28_database(path, stats_enabled=0)
        os.environ["XPANEL_DB"] = str(path)
        try:
            init_db()
            add_user("Speed Test")
            config, _server, _users = build_config()
            assert config["api"]["services"] == ["StatsService"]
            assert config["stats"] == {}
            assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
            assert config["policy"]["levels"]["0"]["statsUserDownlink"] is True
            clients = config["inbounds"][0]["settings"]["clients"]
            assert clients[0]["email"] == "Speed Test"
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_set_server_enables_stats_in_an_empty_legacy_database() -> None:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "panel.db"
        _create_rc28_database(path, insert_server=False)
        os.environ["XPANEL_DB"] = str(path)
        try:
            result = cmd_set_server(
                argparse.Namespace(
                    address="vpn.example.com",
                    listen="0.0.0.0",
                    port=443,
                    dest="www.bing.com:443",
                    server_name="www.bing.com",
                    private_key="private",
                    public_key="public",
                    short_id="0011223344556677",
                    fingerprint="chrome",
                    config_path="/tmp/config.json",
                    xray_bin="/bin/true",
                    xray_service="xray",
                )
            )
            assert result == 0
            with connect() as con:
                value = con.execute(
                    "SELECT stats_enabled FROM server_settings WHERE id = 1"
                ).fetchone()[0]
            assert value == 1
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_new_server_row_uses_enabled_stats_default() -> None:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "panel.db"
        os.environ["XPANEL_DB"] = str(path)
        try:
            init_db()
            with connect() as con:
                con.execute(
                    """
                    INSERT INTO server_settings (
                        id, address, dest, server_name, private_key,
                        public_key, short_id
                    ) VALUES (1, 'vpn.example.com', 'www.bing.com:443',
                              'www.bing.com', 'private', 'public',
                              '0011223344556677')
                    """
                )
                value = con.execute(
                    "SELECT stats_enabled FROM server_settings WHERE id = 1"
                ).fetchone()[0]
            assert value == 1
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_upgrade_script_applies_xray_config_and_protects_rollback() -> None:
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "cp -a /usr/local/etc/xray/config.json" in script
    assert 'log "Включаю Stats API и безопасно применяю конфигурацию Xray"' in script
    assert ".venv/bin/python -m xpanel apply" in script
    assert "systemctl restart xray" in script
    assert "systemctl is-active --quiet xpanel-traffic.timer" in script
    assert ".venv/bin/python -m xpanel collect-traffic --online --strict" in script


def test_first_install_validates_real_traffic_collector() -> None:
    script = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    assert "systemctl is-active --quiet xpanel-traffic.timer" in script
    assert ".venv/bin/python -m xpanel collect-traffic --online --strict" in script
