from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("XPANEL_SECRET_KEY", "test-json-secret")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from werkzeug.security import generate_password_hash

from xpanel.db import connect, init_db
from xpanel.web import create_app


class JsonEditorsWebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["XPANEL_DB"] = str(Path(self.tmp.name) / "panel.db")
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
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "0011223344556677", "chrome",
                    "/tmp/config.json", "/bin/true", "xray",
                ),
            )
        self.apply_patcher = patch(
            "xpanel.web.apply_config",
            return_value={
                "enabled_users": 1,
                "enabled_rules": 1,
                "service": "active",
                "profile": "raw_reality",
            },
        )
        self.apply_patcher.start()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-json-secret",
                "PASSWORD_HASH": generate_password_hash("correct-password"),
            }
        )
        self.client = self.app.test_client()
        self.client.post("/login", data={"password": "correct-password"})

    def tearDown(self):
        self.apply_patcher.stop()
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def csrf(self) -> str:
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_json_pages_are_available(self):
        for path, marker in (
            ("/outbounds/json/new", b"JSON"),
            ("/routing/json", b"routing-v1"),
            ("/routing/rules/json/new", b"geosite:category-ads-all"),
            ("/config/json", b"config-v1"),
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(marker, response.data)

    def test_create_outbound_and_routing_rule_from_json(self):
        outbound = {
            "_sgPanel": {"name": "EU", "enabled": True},
            "tag": "eu-exit",
            "protocol": "vless",
            "settings": {
                "address": "eu.example.com",
                "port": 443,
                "id": "11111111-1111-4111-8111-111111111111",
                "encryption": "none",
                "flow": "xtls-rprx-vision",
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.bing.com",
                    "fingerprint": "chrome",
                    "password": "public-password",
                    "shortId": "aabbccdd",
                    "spiderX": "",
                },
            },
        }
        response = self.client.post(
            "/outbounds/json/new",
            data={"csrf_token": self.csrf(), "json_config": json.dumps(outbound)},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"eu-exit", response.data)
        self.assertIn(b"JSON", response.data)

        rule = {
            "_sgPanel": {"name": "EU domains", "priority": 30, "enabled": True},
            "type": "field",
            "domain": ["geosite:fr"],
            "outboundTag": "eu-exit",
        }
        response = self.client.post(
            "/routing/rules/json/new",
            data={"csrf_token": self.csrf(), "json_config": json.dumps(rule)},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"EU domains", response.data)


    def test_full_config_json_page_saves_known_value(self):
        response = self.client.get("/config/json")
        self.assertEqual(response.status_code, 200)
        from xpanel.service import config_json_document, get_server
        document = json.loads(config_json_document())
        document["log"]["loglevel"] = "info"
        document["outbounds"].append(
            {
                "tag": "json-socks",
                "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]},
            }
        )
        response = self.client.post(
            "/config/json",
            data={"csrf_token": self.csrf(), "json_config": json.dumps(document)},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_server()["loglevel"], "info")
        self.assertIn("JSON синхронизирован".encode("utf-8"), response.data)
        response = self.client.get("/outbounds")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"json-socks", response.data)
        self.assertIn("Полный JSON".encode("utf-8"), response.data)

    def test_geo_country_preset(self):
        response = self.client.post(
            "/routing/presets/add",
            data={
                "csrf_token": self.csrf(),
                "kind": "country",
                "value": "fr",
                "outbound_tag": "direct",
                "priority": "100",
                "name": "France",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("France — домены".encode("utf-8"), response.data)
        self.assertIn("France — IP".encode("utf-8"), response.data)


if __name__ == "__main__":
    unittest.main()
