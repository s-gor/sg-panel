from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xpanel.db import connect, init_db
from xpanel import service
from xpanel.service import (
    build_config,
    configure_warp_routing,
    create_warp,
    get_routing_settings,
    get_warp_overview,
    list_outbound_tags,
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

    def test_create_warp_uses_generated_xray_json_and_protects_account(self):
        binary = self.root / "wgcf-cli"
        binary.write_text("fake", encoding="utf-8")
        binary.chmod(0o755)
        warp_dir = self.root / "warp"

        def fake_run(args, *, timeout=15, cwd=None):
            cwd = Path(cwd)
            if args[-1] == "register":
                (cwd / "wgcf.json").write_text('{"account":"secret"}', encoding="utf-8")
            elif args[-2:] == ["generate", "--xray"]:
                (cwd / "wgcf.xray.json").write_text(json.dumps(SAMPLE_WARP), encoding="utf-8")
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
