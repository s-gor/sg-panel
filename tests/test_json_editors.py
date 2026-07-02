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
    dns_json_document,
    find_outbound,
    get_routing_settings,
    get_server,
    inbound_json_document,
    list_dns_hosts,
    list_dns_servers,
    list_routing_rules,
    routing_json_document,
    update_dns_json_document,
    update_inbound_json_document,
    update_routing_json_document,
    update_vless_outbound,
    update_users_json_document,
    users_json_document,
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
            dns_settings_columns = {row["name"] for row in con.execute("PRAGMA table_info(dns_settings)")}
            dns_server_columns = {row["name"] for row in con.execute("PRAGMA table_info(dns_servers)")}
        self.assertIn("config_json", outbound_columns)
        self.assertIn("config_json", rule_columns)
        self.assertIn("target_type", rule_columns)
        self.assertIn("extra_json", settings_columns)
        self.assertIn("extra_json", dns_settings_columns)
        self.assertIn("config_json", dns_server_columns)

    def test_users_context_json_roundtrip_preserves_subscription_and_routes(self):
        with connect() as con:
            original = con.execute(
                "SELECT id, subscription_token FROM users WHERE name = 'Sergey'"
            ).fetchone()
            con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, users, config_json)
                VALUES ('Sergey only', 10, 1, 'direct', 'Sergey', '{}')
                """
            )
        document = json.loads(users_json_document())
        document["users"][0]["name"] = "Sergey JSON"
        document["users"][0]["comment"] = "edited as JSON"
        document["users"].append(
            {
                "name": "Irina",
                "uuid": "99999999-9999-4999-8999-999999999999",
                "enabled": False,
                "comment": "disabled device",
                "expiryAt": None,
                "subscriptionEnabled": True,
            }
        )
        result = update_users_json_document(json.dumps(document))
        self.assertEqual(len(result), 2)
        with connect() as con:
            renamed = con.execute(
                "SELECT * FROM users WHERE name = 'Sergey JSON'"
            ).fetchone()
            added = con.execute("SELECT * FROM users WHERE name = 'Irina'").fetchone()
            rule = con.execute(
                "SELECT users, enabled FROM routing_rules WHERE name = 'Sergey only'"
            ).fetchone()
        self.assertEqual(renamed["id"], original["id"])
        self.assertEqual(renamed["subscription_token"], original["subscription_token"])
        self.assertEqual(renamed["comment"], "edited as JSON")
        self.assertFalse(bool(added["enabled"]))
        self.assertEqual(rule["users"], "Sergey JSON")
        self.assertTrue(bool(rule["enabled"]))

    def test_users_json_never_broadens_rule_when_user_is_removed(self):
        with connect() as con:
            con.execute(
                """
                INSERT INTO routing_rules
                    (name, priority, enabled, outbound_tag, users, config_json)
                VALUES ('Only user', 10, 1, 'direct', 'Sergey', '{}')
                """
            )
        update_users_json_document(json.dumps({"users": []}))
        with connect() as con:
            count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            rule = con.execute(
                "SELECT users, enabled FROM routing_rules WHERE name = 'Only user'"
            ).fetchone()
        self.assertEqual(count, 0)
        self.assertEqual(rule["users"], "")
        self.assertFalse(bool(rule["enabled"]))

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


    def test_inbound_context_json_roundtrip(self):
        document = json.loads(inbound_json_document())
        self.assertEqual(document["tag"], "vless-reality-in")
        document["port"] = 8443
        document["streamSettings"]["realitySettings"]["serverNames"] = [
            "www.example.com"
        ]
        document["streamSettings"]["realitySettings"]["dest"] = (
            "www.example.com:443"
        )
        result = update_inbound_json_document(json.dumps(document))
        server = get_server()
        self.assertEqual(server["port"], 8443)
        self.assertEqual(server["server_name"], "www.example.com")
        self.assertEqual(server["dest"], "www.example.com:443")
        self.assertEqual(result["users"], 1)

    def test_dns_context_json_roundtrip(self):
        document = json.loads(dns_json_document())
        document["_sgPanel"]["enabled"] = True
        document["queryStrategy"] = "UseIP"
        document["clientIp"] = "203.0.113.10"
        document["servers"][0]["customOption"] = {"keep": True}
        document["hosts"] = {
            "router.local": "192.168.1.1",
            "cluster.local": ["192.168.1.10", "192.168.1.11"],
        }
        result = update_dns_json_document(json.dumps(document))
        self.assertTrue(result["enabled"])
        self.assertGreaterEqual(result["servers"], 1)
        self.assertEqual(result["hosts"], 2)
        exported = json.loads(dns_json_document())
        self.assertEqual(exported["queryStrategy"], "UseIP")
        self.assertEqual(exported["clientIp"], "203.0.113.10")
        self.assertEqual(exported["servers"][0]["customOption"], {"keep": True})
        self.assertEqual(exported["hosts"]["router.local"], "192.168.1.1")
        self.assertEqual(len(list_dns_hosts(enabled_only=True)), 2)
        self.assertGreaterEqual(len(list_dns_servers(enabled_only=True)), 1)

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
