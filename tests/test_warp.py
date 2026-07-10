from __future__ import annotations

import json
import os
import stat
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xpanel.db import connect, init_db
from xpanel import service
from xpanel.service import (
    build_config,
    build_warp_outbound,
    configure_warp_routing,
    create_warp,
    delete_warp,
    get_routing_settings,
    get_warp_overview,
    list_outbound_tags,
    update_warp_json_document,
    warp_json_document,
    set_warp_enabled,
    update_routing_settings,
)


SAMPLE_WARP = {
    "protocol": "wireguard",
    "settings": {
        "secretKey": "test-secret-key",
        "address": ["172.16.0.2/32", "2606:4700:110::2/128"],
        "peers": [
            {
                "publicKey": "test-public-key",
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "endpoint": "162.159.192.1:2408",
            }
        ],
        "reserved": [1, 2, 3],
        "mtu": 1280,
    },
    "tag": "wireguard",
}


class WarpServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(self.root / "panel.db")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint, flow,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "vpn.example.com", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "0011223344556677", "chrome",
                    "xtls-rprx-vision", str(self.root / "config.json"),
                    "/bin/true", "xray",
                ),
            )

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def enable_sample(self):
        outbound = service._normalise_warp_outbound(SAMPLE_WARP)
        with connect() as con:
            con.execute(
                "UPDATE warp_settings SET enabled = 1, outbound_json = ? WHERE id = 1",
                (json.dumps(outbound),),
            )
        return outbound

    def test_warp_table_defaults(self):
        warp = get_warp_overview()
        self.assertFalse(warp["configured"])
        self.assertFalse(warp["enabled"])
        self.assertEqual(warp["route_mode"], "off")

    def test_hostname_endpoint_is_pinned_to_verified_ipv4(self):
        sample = json.loads(json.dumps(SAMPLE_WARP))
        sample["settings"]["peers"][0]["endpoint"] = "engage.cloudflareclient.com:2408"
        outbound = service._normalise_warp_outbound(sample)
        self.assertEqual(
            outbound["settings"]["peers"][0]["endpoint"],
            "162.159.192.1:2408",
        )

    def test_warp_outbound_is_normalised_and_added_to_config(self):
        self.enable_sample()
        config, _server, _users = build_config()
        warp = next(item for item in config["outbounds"] if item["tag"] == "warp")
        self.assertEqual(warp["protocol"], "wireguard")
        self.assertTrue(warp["settings"]["noKernelTun"])
        self.assertEqual(warp["settings"]["mtu"], 1280)
        self.assertIn("warp", list_outbound_tags(enabled_only=True))


    def test_warp_context_json_roundtrip(self):
        self.enable_sample()
        document = json.loads(warp_json_document())
        document["_sgPanel"]["enabled"] = True
        document["_sgPanel"]["routeMode"] = "selected"
        document["_sgPanel"]["selectedDomains"] = [
            "domain:example.com",
            "geosite:spotify",
        ]
        document["_sgPanel"]["selectedIps"] = ["geoip:ru"]
        document["settings"]["mtu"] = 1360
        result = update_warp_json_document(json.dumps(document))
        self.assertTrue(result["enabled"])
        self.assertEqual(result["route_mode"], "selected")
        self.assertIn("domain:example.com", result["selected_domains"])
        self.assertEqual(result["selected_ips"], "geoip:ru")
        outbound = build_warp_outbound()
        self.assertEqual(outbound["settings"]["mtu"], 1360)
        config, _server, _users = build_config()
        rules = [
            item for item in config["routing"]["rules"]
            if item.get("outboundTag") == "warp"
        ]
        self.assertEqual(len(rules), 2)
        domain_rule = next(item for item in rules if "domain" in item)
        ip_rule = next(item for item in rules if "ip" in item)
        self.assertEqual(
            domain_rule["domain"], ["domain:example.com", "geosite:spotify"]
        )
        self.assertEqual(ip_rule["ip"], ["geoip:ru"])
        self.assertNotIn("ip", domain_rule)
        self.assertNotIn("domain", ip_rule)

    def test_selected_domains_create_managed_rule(self):
        self.enable_sample()
        configure_warp_routing(
            "selected", "domain:google.com\ndomain:spotify.com"
        )
        config, _server, _users = build_config()
        rule = next(
            item for item in config["routing"]["rules"]
            if item.get("outboundTag") == "warp"
        )
        self.assertEqual(rule["network"], "tcp,udp")
        self.assertEqual(rule["domain"], ["domain:google.com", "domain:spotify.com"])
        self.assertEqual(get_routing_settings()["default_outbound_tag"], "direct")

    def test_russian_sites_preset_creates_separate_domain_and_ip_rules(self):
        self.enable_sample()
        result = configure_warp_routing(
            "selected", service.WARP_RUSSIA_DOMAINS, service.WARP_RUSSIA_IPS
        )
        self.assertEqual(result["selected_domains"], "geosite:category-ru")
        self.assertEqual(result["selected_ips"], "geoip:ru")
        self.assertEqual(len(result["managed_rules"]), 2)

        config, _server, _users = build_config()
        rules = [
            item for item in config["routing"]["rules"]
            if item.get("outboundTag") == "warp"
        ]
        self.assertEqual(len(rules), 2)
        self.assertEqual(
            next(item for item in rules if "domain" in item)["domain"],
            ["geosite:category-ru"],
        )
        self.assertEqual(
            next(item for item in rules if "ip" in item)["ip"],
            ["geoip:ru"],
        )
        self.assertFalse(any("domain" in item and "ip" in item for item in rules))

    def test_selected_mode_accepts_ip_only(self):
        self.enable_sample()
        configure_warp_routing("selected", "", "geoip:ru")
        config, _server, _users = build_config()
        rules = [
            item for item in config["routing"]["rules"]
            if item.get("outboundTag") == "warp"
        ]
        self.assertEqual(rules, [
            {
                "type": "field",
                "outboundTag": "warp",
                "network": "tcp,udp",
                "ip": ["geoip:ru"],
            }
        ])

    def test_geoip_in_domain_field_has_clear_guidance(self):
        self.enable_sample()
        with self.assertRaisesRegex(ValueError, "IP / GeoIP / CIDR"):
            configure_warp_routing("selected", "geoip:ru", "")

    def test_geosite_in_ip_field_has_clear_guidance(self):
        self.enable_sample()
        with self.assertRaisesRegex(ValueError, "Домены / Geosite"):
            configure_warp_routing("selected", "", "geosite:category-ru")

    def test_rc55_database_migrates_selected_ips_without_resetting_domains(self):
        legacy_path = self.root / "legacy-rc55.db"
        with sqlite3.connect(legacy_path) as con:
            con.execute(
                """
                CREATE TABLE warp_settings (
                    id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
                    outbound_json TEXT NOT NULL DEFAULT '', account_json TEXT NOT NULL DEFAULT '',
                    route_mode TEXT NOT NULL DEFAULT 'off', selected_domains TEXT NOT NULL DEFAULT '',
                    last_test_state TEXT NOT NULL DEFAULT '', last_test_ip TEXT NOT NULL DEFAULT '',
                    last_test_at TEXT, created_at TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            con.execute(
                "INSERT INTO warp_settings (id, route_mode, selected_domains) VALUES (1, 'selected', 'domain:example.com')"
            )
        current = os.environ["XPANEL_DB"]
        os.environ["XPANEL_DB"] = str(legacy_path)
        try:
            init_db()
            with connect() as con:
                row = con.execute(
                    "SELECT selected_domains, selected_ips FROM warp_settings WHERE id=1"
                ).fetchone()
            self.assertEqual(row["selected_domains"], "domain:example.com")
            self.assertEqual(row["selected_ips"], "")
        finally:
            os.environ["XPANEL_DB"] = current

    def test_all_traffic_makes_warp_default(self):
        self.enable_sample()
        configure_warp_routing("selected", "domain:google.com")
        configure_warp_routing("all", "domain:google.com")
        config, _server, _users = build_config()
        self.assertEqual(config["outbounds"][0]["tag"], "warp")
        self.assertFalse(any(
            item.get("outboundTag") == "warp" for item in config["routing"]["rules"]
        ))
        self.assertEqual(get_routing_settings()["default_outbound_tag"], "warp")


    def test_all_traffic_reorders_outbounds_even_with_saved_base_json(self):
        self.enable_sample()
        with connect() as con:
            con.execute(
                "UPDATE config_settings SET document_json = ? WHERE id = 1",
                (
                    json.dumps(
                        {
                            "outbounds": [
                                {"tag": "direct", "protocol": "freedom", "settings": {}},
                                {"tag": "blocked", "protocol": "blackhole", "settings": {}},
                                service.build_warp_outbound(),
                            ]
                        }
                    ),
                ),
            )
        configure_warp_routing("all", "")
        config, _server, _users = build_config()
        self.assertEqual(
            [item["tag"] for item in config["outbounds"][:3]],
            ["warp", "direct", "blocked"],
        )

    def test_default_outbound_selector_synchronises_warp_all_mode(self):
        self.enable_sample()
        update_routing_settings(
            domain_strategy="AsIs",
            sniffing_enabled=True,
            sniffing_route_only=True,
            sniff_http=True,
            sniff_tls=True,
            sniff_quic=True,
            default_outbound_tag="warp",
        )
        self.assertEqual(get_warp_overview()["route_mode"], "all")

        update_routing_settings(
            domain_strategy="AsIs",
            sniffing_enabled=True,
            sniffing_route_only=True,
            sniff_http=True,
            sniff_tls=True,
            sniff_quic=True,
            default_outbound_tag="direct",
        )
        self.assertEqual(get_warp_overview()["route_mode"], "off")

    def test_disabling_warp_resets_routes(self):
        self.enable_sample()
        configure_warp_routing("all", "")
        set_warp_enabled(False)
        warp = get_warp_overview()
        self.assertFalse(warp["enabled"])
        self.assertEqual(warp["route_mode"], "off")
        self.assertEqual(get_routing_settings()["default_outbound_tag"], "direct")
        self.assertNotIn("warp", list_outbound_tags(enabled_only=True))

    def test_create_warp_does_not_save_when_exact_candidate_fails_validation(self):
        binary = self.root / "wgcf-cli"
        binary.write_text("fake", encoding="utf-8")
        binary.chmod(0o755)
        warp_dir = self.root / "warp"

        def fake_run(args, *, timeout=15, cwd=None):
            if args[-1] == "register":
                workdir = Path(cwd)
                (workdir / "wgcf.json").write_text('{"account":"secret"}', encoding="utf-8")
            elif args[-2:] == ["generate", "--xray"]:
                workdir = Path(cwd)
                (workdir / "wgcf.xray.json").write_text(json.dumps(SAMPLE_WARP), encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch.object(service, "WARP_DIR", warp_dir), \
             patch.object(service, "_warp_binary", return_value=binary), \
             patch.object(service, "_run", side_effect=fake_run), \
             patch.object(service, "validate_generated_config", return_value={
                 "ok": False, "detail": "candidate rejected", "users": 0, "json": "{}"
             }), \
             patch.object(service, "require_root"):
            with self.assertRaisesRegex(service.XPanelError, "candidate rejected"):
                create_warp()

        self.assertFalse((warp_dir / "wgcf.json").exists())
        overview = get_warp_overview()
        self.assertFalse(overview["configured"])
        self.assertFalse(overview["enabled"])

    def test_delete_warp_does_not_change_live_state_when_candidate_fails(self):
        self.enable_sample()
        warp_dir = self.root / "warp"
        warp_dir.mkdir(parents=True)
        account = warp_dir / "wgcf.json"
        account.write_text("secret", encoding="utf-8")

        with patch.object(service, "WARP_DIR", warp_dir), \
             patch.object(service, "validate_generated_config", return_value={
                 "ok": False, "detail": "delete rejected", "users": 0, "json": "{}"
             }), \
             patch.object(service, "require_root"):
            with self.assertRaisesRegex(service.XPanelError, "delete rejected"):
                delete_warp()

        self.assertTrue(account.exists())
        overview = get_warp_overview()
        self.assertTrue(overview["configured"])
        self.assertTrue(overview["enabled"])

    def test_create_warp_uses_generated_xray_json_and_protects_account(self):
        binary = self.root / "wgcf-cli"
        binary.write_text("fake", encoding="utf-8")
        binary.chmod(0o755)
        warp_dir = self.root / "warp"

        def fake_run(args, *, timeout=15, cwd=None):
            if args[-1] == "register":
                workdir = Path(cwd)
                (workdir / "wgcf.json").write_text('{"account":"secret"}', encoding="utf-8")
            elif args[-2:] == ["generate", "--xray"]:
                workdir = Path(cwd)
                (workdir / "wgcf.xray.json").write_text(json.dumps(SAMPLE_WARP), encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch.object(service, "WARP_DIR", warp_dir), \
             patch.object(service, "_warp_binary", return_value=binary), \
             patch.object(service, "_run", side_effect=fake_run), \
             patch.object(service, "require_root"):
            result = create_warp()

        self.assertTrue(result["enabled"])
        account = warp_dir / "wgcf.json"
        self.assertTrue(account.is_file())
        self.assertEqual(stat.S_IMODE(account.stat().st_mode), 0o600)
        config, _server, _users = build_config()
        self.assertTrue(any(item["tag"] == "warp" for item in config["outbounds"]))


if __name__ == "__main__":
    unittest.main()
