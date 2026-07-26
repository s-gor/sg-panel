from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from xpanel.db import connect, init_db
from xpanel.service import (
    add_user,
    build_config,
    config_json_document,
    find_outbound,
    get_dns_settings,
    get_server,
    list_dns_servers,
    list_outbound_tags,
    list_routing_rules,
    list_users,
    update_config_json_document,
)


class FullConfigJsonServiceTest(unittest.TestCase):
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
                    "panel.example.com", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )
        self.user = add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_schema_contains_config_document(self):
        with connect() as con:
            columns = {row["name"] for row in con.execute("PRAGMA table_info(config_settings)")}
        self.assertIn("document_json", columns)

    def test_full_json_updates_gui_and_preserves_advanced_sections(self):
        document = json.loads(config_json_document())
        document["log"]["loglevel"] = "info"
        document["observatory"] = {
            "subjectSelector": ["json-socks"],
            "probeURL": "https://www.google.com/generate_204",
        }
        inbound = document["inbounds"][0]
        inbound["port"] = 8443
        inbound["streamSettings"]["sockopt"] = {"tcpFastOpen": True}
        inbound["settings"]["clients"][0]["id"] = "11111111-1111-4111-8111-111111111111"

        document["outbounds"].append(
            {
                "_sgPanel": {"name": "EU", "enabled": True},
                "tag": "eu-exit",
                "protocol": "vless",
                "settings": {
                    "address": "eu.example.com",
                    "port": 443,
                    "id": "22222222-2222-4222-8222-222222222222",
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
                    "sockopt": {"tcpKeepAliveIdle": 60},
                },
            }
        )
        document["outbounds"].append(
            {
                "tag": "json-socks",
                "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]},
            }
        )
        document["routing"]["rules"].append(
            {
                "_sgPanel": {"name": "JSON SOCKS", "priority": 30, "enabled": True},
                "type": "field",
                "domain": ["domain:example.com"],
                "outboundTag": "json-socks",
            }
        )
        document["dns"] = {
            "queryStrategy": "UseIPv4",
            "servers": [
                {
                    "_sgPanel": {"name": "Cloudflare", "priority": 10},
                    "address": "https+local://1.1.1.1/dns-query",
                    "timeoutMs": 5000,
                    "customOption": "keep",
                }
            ],
            "hosts": {"example.test": "127.0.0.1"},
            "disableCache": True,
            "useSystemHosts": True,
        }

        result = update_config_json_document(json.dumps(document))
        self.assertEqual(result["users"], 1)
        self.assertIn("json-socks", list_outbound_tags())
        self.assertIn("eu-exit", list_outbound_tags())
        self.assertEqual(get_server()["port"], 8443)
        self.assertEqual(get_server()["loglevel"], "info")
        self.assertEqual(list_users()[0]["uuid"], "11111111-1111-4111-8111-111111111111")
        self.assertTrue(get_dns_settings()["enabled"])
        self.assertEqual(list_dns_servers(enabled_only=True)[0]["timeout_ms"], 5000)
        self.assertEqual(list_routing_rules()[-1]["outbound_tag"], "json-socks")

        config, _server, _users = build_config()
        self.assertEqual(config["observatory"]["subjectSelector"], ["json-socks"])
        self.assertTrue(config["inbounds"][0]["streamSettings"]["sockopt"]["tcpFastOpen"])
        json_socks = next(item for item in config["outbounds"] if item["tag"] == "json-socks")
        self.assertEqual(json_socks["protocol"], "socks")
        eu = next(item for item in config["outbounds"] if item["tag"] == "eu-exit")
        self.assertEqual(eu["streamSettings"]["sockopt"]["tcpKeepAliveIdle"], 60)
        dns_server = config["dns"]["servers"][0]
        self.assertEqual(dns_server["customOption"], "keep")

    def test_invalid_managed_vless_is_rejected(self):
        document = json.loads(config_json_document())
        document["outbounds"].append(
            {
                "tag": "broken-vless",
                "protocol": "vless",
                "settings": {"address": "", "port": 443, "id": "bad"},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {},
                },
            }
        )
        with self.assertRaises(ValueError):
            update_config_json_document(json.dumps(document))


if __name__ == "__main__":
    unittest.main()
