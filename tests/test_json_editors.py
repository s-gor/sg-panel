from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from xpanel.db import connect, init_db
from xpanel.service import (
    add_geo_policy,
    add_user,
    add_vless_outbound_json,
    build_config,
    build_outbound_json,
    find_outbound,
    get_routing_settings,
    list_routing_rules,
    routing_json_document,
    update_routing_json_document,
    update_vless_outbound,
)


class JsonEditorsServiceTest(unittest.TestCase):
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
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(root / "config.json"), "/bin/true", "xray",
                ),
            )
        add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def test_json_columns_are_migrated(self):
        with connect() as con:
            outbound_columns = {row["name"] for row in con.execute("PRAGMA table_info(outbounds)")}
            rule_columns = {row["name"] for row in con.execute("PRAGMA table_info(routing_rules)")}
            settings_columns = {row["name"] for row in con.execute("PRAGMA table_info(routing_settings)")}
        self.assertIn("config_json", outbound_columns)
        self.assertIn("config_json", rule_columns)
        self.assertIn("target_type", rule_columns)
        self.assertIn("extra_json", settings_columns)

    def test_outbound_json_preserves_unknown_fields_after_form_edit(self):
        document = {
            "_sgPanel": {"name": "EU", "enabled": True},
            "tag": "eu-exit",
            "protocol": "vless",
            "settings": {
                "address": "eu.example.com",
                "port": 443,
                "id": "11111111-1111-4111-8111-111111111111",
                "encryption": "none",
                "flow": "xtls-rprx-vision",
                "customSetting": "keep-me",
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "sockopt": {"tcpFastOpen": True},
                "realitySettings": {
                    "serverName": "www.bing.com",
                    "fingerprint": "chrome",
                    "password": "public-password",
                    "shortId": "aabbccdd",
                    "spiderX": "",
                },
            },
            "mux": {"enabled": False},
        }
        row = add_vless_outbound_json(json.dumps(document))
        update_vless_outbound(
            row["id"],
            tag="eu-exit",
            name="Europe",
            address="new.example.com",
            port=443,
            user_uuid=row["uuid"],
            flow="xtls-rprx-vision",
            network="raw",
            security="reality",
            server_name="www.bing.com",
            public_key="public-password",
            short_id="aabbccdd",
            fingerprint="chrome",
            spider_x="",
            xhttp_host="",
            xhttp_path="/",
            xhttp_mode="auto",
            allow_insecure=False,
            alpn="",
        )
        config = build_outbound_json(find_outbound(row["id"]))
        self.assertEqual(config["settings"]["address"], "new.example.com")
        self.assertEqual(config["settings"]["customSetting"], "keep-me")
        self.assertTrue(config["streamSettings"]["sockopt"]["tcpFastOpen"])
        self.assertEqual(config["mux"], {"enabled": False})

    def test_routing_json_roundtrip_with_balancer(self):
        document = {
            "_sgPanel": {"defaultOutboundTag": "direct"},
            "domainStrategy": "IPIfNonMatch",
            "balancers": [{"tag": "europe", "selector": ["eu-"]}],
            "rules": [
                {
                    "_sgPanel": {"name": "Ads", "priority": 10, "enabled": True},
                    "type": "field",
                    "domain": ["geosite:category-ads-all"],
                    "outboundTag": "blocked",
                    "attrs": "advanced-field",
                },
                {
                    "_sgPanel": {"name": "Europe", "priority": 20, "enabled": True},
                    "type": "field",
                    "domain": ["geosite:fr"],
                    "balancerTag": "europe",
                },
            ],
        }
        result = update_routing_json_document(json.dumps(document))
        self.assertEqual(result["rules"], 2)
        self.assertEqual(result["balancers"], 1)
        self.assertEqual(get_routing_settings()["domain_strategy"], "IPIfNonMatch")
        rules = list_routing_rules()
        self.assertEqual(rules[1]["target_type"], "balancer")
        exported = json.loads(routing_json_document())
        self.assertEqual(exported["rules"][0]["attrs"], "advanced-field")
        config, _server, _users = build_config()
        self.assertEqual(config["routing"]["balancers"][0]["tag"], "europe")
        self.assertEqual(config["routing"]["rules"][1]["balancerTag"], "europe")
        self.assertNotIn("_sgPanel", config["routing"]["rules"][0])

    def test_country_policy_creates_separate_domain_and_ip_rules(self):
        rows = add_geo_policy(
            kind="country",
            value="fr",
            outbound_tag="direct",
            priority=100,
            name="France",
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["domains"], "geosite:fr")
        self.assertEqual(rows[1]["ips"], "geoip:fr")
        self.assertEqual(rows[0]["priority"], 100)
        self.assertEqual(rows[1]["priority"], 101)


if __name__ == "__main__":
    unittest.main()
