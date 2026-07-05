from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from xpanel.db import connect, init_db
import xpanel.service as service


ROOT = Path(__file__).resolve().parents[1]


class Rc30FallbackHotfixTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        self.old_edge_state = service.REALITY_EDGE_STATE
        service.REALITY_EDGE_STATE = root / "reality-edge.env"
        self.cert = root / "fullchain.pem"
        self.key = root / "privkey.pem"
        self.cert.write_text("certificate", encoding="utf-8")
        self.key.write_text("private key", encoding="utf-8")
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
                    "xtls-rprx-vision", str(root / "config.json"), "/bin/true", "xray",
                ),
            )
        self.user = service.add_user("Test-Client")

    def tearDown(self):
        service.REALITY_EDGE_STATE = self.old_edge_state
        os.environ.pop("XPANEL_DB", None)
        self.tmp.cleanup()

    def enable_edge(self):
        service.REALITY_EDGE_STATE.write_text(
            "\n".join(
                [
                    "ENABLED=1",
                    "DOMAIN=panel.example.com",
                    f"CERT={self.cert}",
                    f"KEY={self.key}",
                    "XRAY_PORT=8444",
                    "WEB_PORT=9443",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def test_reality_edge_moves_only_runtime_listener(self):
        self.enable_edge()
        config, server, _users = service.build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 8444)
        self.assertEqual(server["port"], 443)
        link = service.make_link(self.user["id"])
        self.assertIn("@vpn.example.com:443?", link)


    def test_raw_reality_uses_sni_router_without_changing_remote_target(self):
        self.enable_edge()
        config, server, _users = service.build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 8444)
        self.assertEqual(
            inbound["streamSettings"]["realitySettings"]["dest"],
            "www.bing.com:443",
        )
        stream, web = service._nginx_reality_edge_configs(server)
        self.assertIn("www.bing.com 127.0.0.1:8444;", stream)
        self.assertIn("default 127.0.0.1:10443;", stream)
        self.assertIn("ssl_preread on;", stream)
        self.assertIn("server_name panel.example.com;", web)

    def test_multi_reality_keeps_public_9443_and_moves_internal_fallback(self):
        self.enable_edge()
        rows = {int(row["id"]): row for row in service.list_reality_inbounds()}
        service.update_server_settings(
            address="vpn.example.com", listen="0.0.0.0", port=443,
            dest="www.bing.com:443", server_name="www.bing.com",
            private_key="private", public_key="public", short_id="0011223344556677",
            fingerprint="chrome", flow="xtls-rprx-vision", loglevel="warning",
            api_listen="127.0.0.1:10085", stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"), xray_bin="/bin/true",
            xray_service="xray", inbound_profile="raw_reality",
            reality_instances=[
                {"id": 1, "name": "Primary", "enabled": True, "listen": "0.0.0.0", "port": 443, "short_id": "0011223344556677"},
                {"id": 2, "name": "Backup", "enabled": True, "listen": "0.0.0.0", "port": 8443, "short_id": str(rows[2]["short_id"])},
                {"id": 3, "name": "Alt", "enabled": True, "listen": "0.0.0.0", "port": 9443, "short_id": str(rows[3]["short_id"])},
            ],
        )
        config, server, _users = service.build_config()
        self.assertEqual(len(config["inbounds"]), 1)
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 8444)
        self.assertEqual(
            len(inbound["streamSettings"]["realitySettings"]["shortIds"]), 3
        )
        stream, web = service._nginx_reality_edge_configs(server)
        self.assertIn("default 127.0.0.1:10443;", stream)
        self.assertIn("listen 8443;", stream)
        self.assertIn("listen 9443;", stream)
        self.assertEqual(stream.count("proxy_pass 127.0.0.1:8444;"), 2)
        self.assertIn("listen 127.0.0.1:10443 ssl;", web)
        self.assertNotIn("127.0.0.1:9443 ssl", web)

    def test_reality_extra_port_cannot_use_internal_edge_listener(self):
        self.enable_edge()
        rows = {int(row["id"]): row for row in service.list_reality_inbounds()}
        service.update_server_settings(
            address="vpn.example.com", listen="0.0.0.0", port=443,
            dest="www.bing.com:443", server_name="www.bing.com",
            private_key="private", public_key="public", short_id="0011223344556677",
            fingerprint="chrome", flow="xtls-rprx-vision", loglevel="warning",
            api_listen="127.0.0.1:10085", stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"), xray_bin="/bin/true",
            xray_service="xray", inbound_profile="raw_reality",
            reality_instances=[
                {"id": 1, "name": "Primary", "enabled": True, "listen": "0.0.0.0", "port": 443, "short_id": "0011223344556677"},
                {"id": 2, "name": "Backup", "enabled": True, "listen": "0.0.0.0", "port": 8444, "short_id": str(rows[2]["short_id"])},
                {"id": 3, "name": "Alt", "enabled": False, "listen": "0.0.0.0", "port": 9443, "short_id": str(rows[3]["short_id"])},
            ],
        )
        with self.assertRaisesRegex(service.XPanelError, "TCP-порт 8444 занят"):
            service.build_config()

    def test_xhttp_and_grpc_tls_keep_transport_and_placeholder(self):
        for profile in ("xhttp_tls", "grpc_tls"):
            with self.subTest(profile=profile):
                server = service.update_server_settings(
                    address="panel.example.com", listen="0.0.0.0", port=443,
                    dest="www.bing.com:443", server_name="panel.example.com",
                    private_key="private", public_key="public", short_id="0011223344556677",
                    fingerprint="chrome", flow="", loglevel="warning",
                    api_listen="127.0.0.1:10085", stats_enabled=False,
                    config_path=str(Path(self.tmp.name) / "config.json"), xray_bin="/bin/true",
                    xray_service="xray", inbound_profile=profile,
                    transport_listen="127.0.0.1", transport_port=8443,
                    xhttp_path="/sg-test", xhttp_mode="auto", grpc_service_name="sg-grpc",
                    tls_cert_path=str(self.cert), tls_key_path=str(self.key),
                )
                nginx = service._nginx_transport_config(server)
                self.assertIn("listen 443 ssl http2;", nginx)
                self.assertIn("root /var/www/sg-panel-placeholder;", nginx)
                self.assertIn("grpc_pass grpc://127.0.0.1:8443;", nginx)
                if profile == "xhttp_tls":
                    self.assertIn("location /sg-test/", nginx)
                else:
                    self.assertIn("location /sg-grpc", nginx)

    def test_xhttp_reality_keeps_remote_reality_target(self):
        self.enable_edge()
        service.update_server_settings(
            address="vpn.example.com", listen="0.0.0.0", port=443,
            dest="www.bing.com:443", server_name="www.bing.com",
            private_key="private", public_key="public", short_id="0011223344556677",
            fingerprint="chrome", flow="", loglevel="warning",
            api_listen="127.0.0.1:10085", stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"), xray_bin="/bin/true",
            xray_service="xray", inbound_profile="xhttp_reality",
            transport_listen="127.0.0.1", transport_port=8443,
            xhttp_path="/sg-test", xhttp_mode="auto", grpc_service_name="sg-grpc",
            tls_cert_path="", tls_key_path="",
        )
        config, server, _users = service.build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 8444)
        self.assertEqual(
            inbound["streamSettings"]["realitySettings"]["dest"],
            "www.bing.com:443",
        )
        stream, web = service._nginx_reality_edge_configs(server)
        self.assertIn("www.bing.com 127.0.0.1:8444;", stream)
        self.assertIn("default 127.0.0.1:10443;", stream)
        self.assertIn("ssl_preread on;", stream)
        self.assertIn("listen 127.0.0.1:10443 ssl;", web)
        self.assertIn("server_name panel.example.com;", web)

    def test_full_json_roundtrip_preserves_public_port_with_edge(self):
        self.enable_edge()
        document = service.config_json_document()
        parsed = json.loads(document)
        inbound = parsed["inbounds"][0]
        self.assertEqual(inbound["port"], 8444)
        self.assertEqual(inbound["_sgPanel"]["publicPort"], 443)
        service.update_config_json_document(document)
        server = service.get_server()
        self.assertEqual(server["listen"], "0.0.0.0")
        self.assertEqual(server["port"], 443)

    def test_hysteria_uses_tcp_443_placeholder_beside_udp_443(self):
        server = service.update_server_settings(
            address="panel.example.com", listen="0.0.0.0", port=443,
            dest="www.bing.com:443", server_name="panel.example.com",
            private_key="private", public_key="public", short_id="0011223344556677",
            fingerprint="chrome", flow="", loglevel="warning",
            api_listen="127.0.0.1:10085", stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"), xray_bin="/bin/true",
            xray_service="xray", inbound_profile="hysteria2_tls",
            transport_listen="127.0.0.1", transport_port=8443,
            xhttp_path="/sg-test", xhttp_mode="auto", grpc_service_name="sg-grpc",
            tls_cert_path=str(self.cert), tls_key_path=str(self.key),
            hysteria_udp_idle_timeout=60,
        )
        nginx = service._nginx_transport_config(server)
        self.assertIn("listen 443 ssl;", nginx)
        self.assertNotIn("grpc_pass", nginx)
        self.assertIn("root /var/www/sg-panel-placeholder;", nginx)

    def test_edge_is_disabled_when_reality_sni_matches_site_domain(self):
        self.enable_edge()
        with connect() as con:
            con.execute("UPDATE server_settings SET server_name='panel.example.com' WHERE id=1")
        server = service.get_server()
        self.assertFalse(service._reality_edge_settings(server)["enabled"])
        config, _server, _users = service.build_config()
        self.assertEqual(config["inbounds"][0]["listen"], "0.0.0.0")
        self.assertEqual(config["inbounds"][0]["port"], 443)

    def test_install_scripts_publish_placeholder_and_stream_module(self):
        http = (ROOT / "deploy" / "configure-http.sh").read_text(encoding="utf-8")
        https = (ROOT / "deploy" / "configure-https.sh").read_text(encoding="utf-8")
        install = (ROOT / "deploy" / "ec2-first-install.sh").read_text(encoding="utf-8")
        self.assertIn("listen 80;", http)
        self.assertIn("SG Digital Systems", http)
        self.assertIn("libnginx-mod-stream", install)
        self.assertIn("REALITY_EDGE_STATE", https)
        self.assertIn("WEB_PORT=10443", https)
        self.assertIn("migrate_reality_edge_web_port", install)
        self.assertIn("WEB_PORT=9443", install)
        self.assertIn("WEB_PORT=10443", install)
        self.assertIn(".venv/bin/python -m xpanel apply", https)
        self.assertIn("https://$DOMAIN/", https)

    def test_login_hexagon_uses_sg_text(self):
        login = (ROOT / "xpanel" / "templates" / "login.html").read_text(encoding="utf-8")
        css = (ROOT / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn('class="logo-sg">SG</text>', login)
        self.assertIn(".logo-sg", css)


if __name__ == "__main__":
    unittest.main()
