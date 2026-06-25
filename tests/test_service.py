from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xpanel.db import connect, init_db
from xpanel.service import add_user, apply_config, make_link


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        self.config = root / "config.json"
        self.xray = root / "xray"
        self.xray.write_text("fake")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "192.168.1.200", "0.0.0.0", 443,
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(self.config), str(self.xray), "xray",
                ),
            )
        self.user = add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_link(self):
        link = make_link(self.user["id"])
        self.assertTrue(link.startswith("vless://"))
        self.assertIn("@192.168.1.200:443", link)

    @patch("xpanel.service.os.geteuid", return_value=0)
    @patch("xpanel.service.subprocess.run")
    def test_apply_uses_json_temp_file(self, run, _geteuid):
        def side_effect(args, **kwargs):
            if "-config" in args:
                path = Path(args[args.index("-config") + 1])
                self.assertEqual(path.suffix, ".json")
            if args[:2] == ["systemctl", "is-active"] and "--quiet" not in args:
                return FakeCompleted(stdout="active\n")
            return FakeCompleted()
        run.side_effect = side_effect
        result = apply_config()
        self.assertEqual(result["service"], "active")
        self.assertTrue(self.config.exists())


if __name__ == "__main__":
    unittest.main()

class RoutingServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "192.168.1.200", "0.0.0.0", 443,
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )
        add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_default_routing_is_in_config(self):
        from xpanel.service import build_config
        config, _server, _users = build_config()
        self.assertEqual(config["routing"]["domainStrategy"], "AsIs")
        self.assertTrue(config["inbounds"][0]["sniffing"]["enabled"])
        rules = config["routing"]["rules"]
        self.assertEqual(rules[0]["protocol"], ["bittorrent"])
        self.assertEqual(rules[0]["outboundTag"], "blocked")
        self.assertIn("192.168.0.0/16", rules[1]["ip"])

class V05ServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        os.environ["XPANEL_BACKUP_DIR"] = str(root / "backups")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    stats_enabled, config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    "192.168.1.200", "0.0.0.0", 443,
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)
        os.environ.pop("XPANEL_BACKUP_DIR", None)

    def test_stats_api_is_generated(self):
        from xpanel.service import build_config, add_user
        add_user("StatsUser")
        config, _server, _users = build_config()
        self.assertEqual(config["api"]["listen"], "127.0.0.1:10085")
        self.assertIn("StatsService", config["api"]["services"])
        self.assertEqual(config["stats"], {})
        self.assertTrue(config["policy"]["levels"]["0"]["statsUserUplink"])

    def test_user_edit_and_backup(self):
        from xpanel.service import add_user, create_backup, update_user, list_backups
        user = add_user("Before", comment="old")
        updated = update_user(
            user["id"],
            name="After",
            user_uuid=user["uuid"],
            comment="new",
            expiry_at="2030-01-01T12:00",
        )
        self.assertEqual(updated["name"], "After")
        self.assertEqual(updated["comment"], "new")
        created = create_backup()
        self.assertTrue(created["name"].startswith("sg-panel-"))
        self.assertEqual(len(list_backups()), 1)


class V06OutboundTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "192.168.1.200", "0.0.0.0", 443,
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )
        add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_vless_outbound_and_user_route_in_config(self):
        from xpanel.service import add_routing_rule, add_vless_outbound, build_config, update_routing_settings
        outbound = add_vless_outbound(
            tag="eu-exit", name="EU", address="eu.example.com", port=443,
            user_uuid="11111111-1111-4111-8111-111111111111",
            flow="xtls-rprx-vision", server_name="www.microsoft.com",
            public_key="public-password", short_id="aabbccdd",
            fingerprint="chrome", spider_x="/",
        )
        update_routing_settings(
            domain_strategy="AsIs", sniffing_enabled=True, sniffing_route_only=True,
            sniff_http=True, sniff_tls=True, sniff_quic=True,
            default_outbound_tag="eu-exit",
        )
        add_routing_rule(
            name="Sergey through EU", priority=30, outbound_tag="eu-exit",
            users="Sergey", domains="domain:example.com",
        )
        config, _server, _users = build_config()
        self.assertEqual(config["outbounds"][0]["tag"], "eu-exit")
        self.assertEqual(config["outbounds"][0]["streamSettings"]["security"], "reality")
        self.assertEqual(config["outbounds"][0]["streamSettings"]["realitySettings"]["password"], "public-password")
        self.assertIn("Sergey", config["routing"]["rules"][-1]["user"])
        self.assertEqual(outbound["tag"], "eu-exit")


class V07DnsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "192.168.1.200", "0.0.0.0", 443,
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )
        add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_dns_defaults_and_config(self):
        from xpanel.service import (
            add_dns_host, build_config, get_dns_settings,
            list_dns_servers, update_dns_settings,
        )
        self.assertFalse(bool(get_dns_settings()["enabled"]))
        self.assertEqual(len(list_dns_servers()), 3)
        update_dns_settings(
            enabled=True,
            query_strategy="UseIPv4",
            disable_cache=False,
            disable_fallback=False,
            disable_fallback_if_match=False,
            enable_parallel_query=True,
            use_system_hosts=True,
        )
        add_dns_host(domain="server.local", addresses="192.168.1.200")
        config, _server, _users = build_config()
        self.assertEqual(config["dns"]["queryStrategy"], "UseIPv4")
        self.assertTrue(config["dns"]["enableParallelQuery"])
        self.assertEqual(config["dns"]["hosts"]["server.local"], "192.168.1.200")
        self.assertEqual(
            config["dns"]["servers"][0]["address"],
            "https+local://1.1.1.1/dns-query",
        )

    def test_dns_server_validation(self):
        from xpanel.service import add_dns_server
        with self.assertRaises(ValueError):
            add_dns_server(name="bad", address="fakedns", priority=100)


class V08SubscriptionServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "vpn.example.com", "0.0.0.0", 443,
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_persistent_url_and_rotation(self):
        from xpanel.service import (
            add_user, get_subscription_settings, make_subscription_url,
            regenerate_subscription_token, update_subscription_settings,
        )
        user = add_user("Subscriber")
        self.assertTrue(user["subscription_token"])
        self.assertFalse(bool(get_subscription_settings()["enabled"]))
        update_subscription_settings(
            enabled=True,
            base_url="https://panel.example.com/",
            profile_title="SG-Panel",
        )
        first_url = make_subscription_url(user["id"])
        self.assertTrue(first_url.startswith("https://panel.example.com/sub/"))
        changed = regenerate_subscription_token(user["id"])
        second_url = make_subscription_url(changed["id"])
        self.assertNotEqual(first_url, second_url)

    def test_existing_user_gets_token_during_migration(self):
        from xpanel.service import add_user, set_user_subscription_enabled
        user = add_user("Existing")
        updated = set_user_subscription_enabled(user["id"], False)
        self.assertFalse(bool(updated["subscription_enabled"]))
        self.assertGreaterEqual(len(updated["subscription_token"]), 20)


class V08MigrationTest(unittest.TestCase):
    def test_v07_users_table_is_migrated(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "panel.db"
            con = sqlite3.connect(database)
            con.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    uuid TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    comment TEXT NOT NULL DEFAULT '',
                    expiry_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            con.execute(
                "INSERT INTO users (name, uuid) VALUES (?, ?)",
                ("OldUser", "11111111-1111-4111-8111-111111111111"),
            )
            con.commit()
            con.close()
            os.environ["XPANEL_DB"] = str(database)
            try:
                init_db()
                with connect() as migrated:
                    row = migrated.execute(
                        "SELECT * FROM users WHERE name = 'OldUser'"
                    ).fetchone()
                    settings = migrated.execute(
                        "SELECT * FROM subscription_settings WHERE id = 1"
                    ).fetchone()
                self.assertTrue(row["subscription_token"])
                self.assertTrue(bool(row["subscription_enabled"]))
                self.assertFalse(bool(settings["enabled"]))
            finally:
                os.environ.pop("XPANEL_DB", None)

class V09SecurityMigrationTest(unittest.TestCase):
    def test_security_tables_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["XPANEL_DB"] = str(Path(tmp) / "panel.db")
            try:
                init_db()
                with connect() as con:
                    settings = con.execute("SELECT * FROM security_settings WHERE id = 1").fetchone()
                    self.assertEqual(settings["max_login_attempts"], 5)
                    for table in ("admin_sessions", "login_attempts", "audit_log"):
                        row = con.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                            (table,),
                        ).fetchone()
                        self.assertIsNotNone(row)
            finally:
                os.environ.pop("XPANEL_DB", None)
