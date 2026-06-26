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
    make_link,
    _nginx_transport_config,
    update_config_json_document,
    update_server_settings,
)


class InboundProfilesTest(unittest.TestCase):
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
        self.cert_path = root / "fullchain.pem"
        self.key_path = root / "privkey.pem"
        self.cert_path.write_text("test certificate", encoding="utf-8")
        self.key_path.write_text("test private key", encoding="utf-8")
        self.user = add_user("Sergey")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def switch(self, profile: str):
        return update_server_settings(
            address="vpn.example.com",
            listen="0.0.0.0",
            port=443,
            dest="www.bing.com:443",
            server_name="vpn.example.com" if profile in {"xhttp_tls", "grpc_tls"} else "www.bing.com",
            private_key="private",
            public_key="public",
            short_id="0011223344556677",
            fingerprint="chrome",
            flow="xtls-rprx-vision",
            loglevel="warning",
            api_listen="127.0.0.1:10085",
            stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"),
            xray_bin="/bin/true",
            xray_service="xray",
            inbound_profile=profile,
            transport_listen="127.0.0.1",
            transport_port=8443,
            xhttp_path="/sg-test-path",
            xhttp_mode="auto",
            grpc_service_name="sg-grpc",
            tls_cert_path=str(self.cert_path),
            tls_key_path=str(self.key_path),
        )

    def test_raw_reality_profile(self):
        self.switch("raw_reality")
        config, _server, _users = build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "0.0.0.0")
        self.assertEqual(inbound["port"], 443)
        self.assertEqual(inbound["streamSettings"]["network"], "tcp")
        self.assertEqual(inbound["streamSettings"]["security"], "reality")
        self.assertEqual(inbound["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        link = make_link(self.user["id"])
        self.assertIn("type=tcp", link)
        self.assertIn("security=reality", link)
        self.assertIn("flow=xtls-rprx-vision", link)

    def test_xhttp_tls_profile(self):
        server = self.switch("xhttp_tls")
        self.assertEqual(server["flow"], "")
        config, _server, _users = build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 8443)
        self.assertEqual(inbound["streamSettings"]["network"], "xhttp")
        self.assertEqual(inbound["streamSettings"]["security"], "none")
        self.assertEqual(inbound["streamSettings"]["xhttpSettings"]["path"], "/sg-test-path")
        self.assertNotIn("flow", inbound["settings"]["clients"][0])
        link = make_link(self.user["id"])
        self.assertIn("type=xhttp", link)
        self.assertIn("security=tls", link)
        self.assertIn("host=vpn.example.com", link)
        self.assertIn("path=%2Fsg-test-path", link)

    def test_xhttp_reality_profile(self):
        self.switch("xhttp_reality")
        config, _server, _users = build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "0.0.0.0")
        self.assertEqual(inbound["port"], 443)
        self.assertEqual(inbound["streamSettings"]["network"], "xhttp")
        self.assertEqual(inbound["streamSettings"]["security"], "reality")
        self.assertNotIn("flow", inbound["settings"]["clients"][0])
        link = make_link(self.user["id"])
        self.assertIn("type=xhttp", link)
        self.assertIn("security=reality", link)
        self.assertIn("pbk=public", link)

    def test_grpc_tls_profile(self):
        self.switch("grpc_tls")
        config, _server, _users = build_config()
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 8443)
        self.assertEqual(inbound["streamSettings"]["network"], "grpc")
        self.assertEqual(inbound["streamSettings"]["security"], "none")
        self.assertEqual(inbound["streamSettings"]["grpcSettings"]["serviceName"], "sg-grpc")
        link = make_link(self.user["id"])
        self.assertIn("type=grpc", link)
        self.assertIn("security=tls", link)
        self.assertIn("serviceName=sg-grpc", link)


    def test_xhttp_tls_nginx_config(self):
        server = self.switch("xhttp_tls")
        nginx = _nginx_transport_config(server)
        self.assertIn("listen 443 ssl http2;", nginx)
        self.assertIn("location /sg-test-path/", nginx)
        self.assertIn("grpc_pass grpc://127.0.0.1:8443;", nginx)
        self.assertIn("client_max_body_size 100m;", nginx)
        self.assertIn("chunked_transfer_encoding on;", nginx)

    def test_grpc_tls_nginx_config(self):
        server = self.switch("grpc_tls")
        nginx = _nginx_transport_config(server)
        self.assertIn("listen 443 ssl http2;", nginx)
        self.assertIn("location /sg-grpc", nginx)
        self.assertIn("grpc_pass grpc://127.0.0.1:8443;", nginx)

    def test_gui_switch_replaces_incompatible_stream_settings(self):
        self.switch("raw_reality")
        update_config_json_document(config_json_document())
        self.switch("xhttp_tls")
        config, _server, _users = build_config()
        inbound = config["inbounds"][0]
        stream = inbound["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["security"], "none")
        self.assertNotIn("realitySettings", stream)
        self.assertNotIn("flow", inbound["settings"]["clients"][0])

    def test_switch_from_reality_to_tls_replaces_reality_sni_with_public_domain(self):
        server = update_server_settings(
            address="vpn.example.com",
            listen="0.0.0.0",
            port=443,
            dest="www.bing.com:443",
            server_name="www.bing.com",
            private_key="private",
            public_key="public",
            short_id="0011223344556677",
            fingerprint="chrome",
            flow="xtls-rprx-vision",
            loglevel="warning",
            api_listen="127.0.0.1:10085",
            stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"),
            xray_bin="/bin/true",
            xray_service="xray",
            inbound_profile="xhttp_tls",
            transport_listen="127.0.0.1",
            transport_port=8443,
            xhttp_path="/sg-test-path",
            xhttp_mode="auto",
            grpc_service_name="sg-grpc",
            tls_cert_path=str(self.cert_path),
            tls_key_path=str(self.key_path),
        )
        self.assertEqual(server["server_name"], "vpn.example.com")
        self.assertEqual(server["flow"], "")

    def test_switch_from_tls_to_reality_replaces_tls_sni_with_reality_target(self):
        self.switch("xhttp_tls")
        server = update_server_settings(
            address="vpn.example.com",
            listen="0.0.0.0",
            port=443,
            dest="www.bing.com:443",
            server_name="vpn.example.com",
            private_key="private",
            public_key="public",
            short_id="0011223344556677",
            fingerprint="chrome",
            flow="",
            loglevel="warning",
            api_listen="127.0.0.1:10085",
            stats_enabled=False,
            config_path=str(Path(self.tmp.name) / "config.json"),
            xray_bin="/bin/true",
            xray_service="xray",
            inbound_profile="xhttp_reality",
            transport_listen="127.0.0.1",
            transport_port=8443,
            xhttp_path="/sg-test-path",
            xhttp_mode="auto",
            grpc_service_name="sg-grpc",
            tls_cert_path=str(self.cert_path),
            tls_key_path=str(self.key_path),
        )
        self.assertEqual(server["server_name"], "www.bing.com")
        self.assertEqual(server["flow"], "")

    def test_full_json_round_trip_preserves_profile(self):
        self.switch("xhttp_tls")
        document = json.loads(config_json_document())
        self.assertEqual(document["inbounds"][0]["_sgPanel"]["profile"], "xhttp_tls")
        result = update_config_json_document(json.dumps(document))
        self.assertEqual(result["users"], 1)
        config, server, _users = build_config()
        self.assertEqual(server["inbound_profile"], "xhttp_tls")
        self.assertEqual(config["inbounds"][0]["streamSettings"]["network"], "xhttp")


if __name__ == "__main__":
    unittest.main()
