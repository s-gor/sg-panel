from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from werkzeug.security import generate_password_hash

from xpanel.db import connect, init_db
from xpanel.web import create_app


class WebTest(unittest.TestCase):
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
                "enabled_rules": 2,
                "service": "active",
                "profile": "raw_reality",
            },
        )
        self.apply_mock = self.apply_patcher.start()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "PASSWORD_HASH": generate_password_hash("correct-password"),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.apply_patcher.stop()
        self.tmp.cleanup()
        os.environ.pop("XPANEL_DB", None)

    def login(self):
        response = self.client.post(
            "/login", data={"password": "correct-password"}, follow_redirects=False
        )
        self.assertEqual(response.status_code, 302)

    def csrf(self) -> str:
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_login_uses_ser_g_panel_branding(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SG-Panel", response.data)
        self.assertIn("ЗАЩИЩЁННЫЙ ВХОД".encode("utf-8"), response.data)

    def test_login_rejects_wrong_password(self):
        response = self.client.post("/login", data={"password": "wrong"})
        self.assertEqual(response.status_code, 401)

    def test_user_workflow_and_qr(self):
        self.login()
        response = self.client.post(
            "/users/add",
            data={"name": "Sergey", "csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sergey", response.data)

        response = self.client.get("/users/1/link")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"vless://", response.data)
        self.assertIn(b"data:image/png;base64", response.data)

        response = self.client.post(
            "/users/1/toggle",
            data={"csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertIn(b"disabled", response.data)

    def test_post_requires_csrf(self):
        self.login()
        response = self.client.post("/users/add", data={"name": "NoToken"})
        self.assertEqual(response.status_code, 400)

    def test_routing_page_and_add_rule(self):
        self.login()
        response = self.client.get("/routing")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Block BitTorrent", response.data)
        response = self.client.post(
            "/routing/rules/add",
            data={
                "csrf_token": self.csrf(),
                "name": "Block test domain",
                "priority": "30",
                "outbound_tag": "blocked",
                "domains": "domain:example.test",
                "ips": "",
                "ports": "",
                "network": "",
                "protocols": "",
                "inbound_tags": "",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Block test domain", response.data)


if __name__ == "__main__":
    unittest.main()

class V05WebTest(WebTest):
    def test_new_admin_pages(self):
        self.login()
        for path, marker in (
            ("/settings", b"PRIMARY INBOUND"),
            ("/config", b"Stats API listen"),
            ("/backups", b"MANUAL SNAPSHOT"),
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(marker, response.data)

    def test_user_edit(self):
        self.login()
        self.client.post(
            "/users/add",
            data={"name": "EditMe", "csrf_token": self.csrf()},
        )
        response = self.client.post(
            "/users/1/edit",
            data={
                "csrf_token": self.csrf(),
                "name": "Edited",
                "uuid": "11111111-1111-4111-8111-111111111111",
                "comment": "phone",
                "expiry_at": "2030-01-01T12:00",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Edited", response.data)


class V06WebTest(WebTest):
    def test_outbound_add_and_routing_selector(self):
        self.login()
        response = self.client.post(
            "/outbounds/add",
            data={
                "csrf_token": self.csrf(),
                "tag": "eu-exit",
                "name": "EU",
                "address": "eu.example.com",
                "port": "443",
                "uuid": "11111111-1111-4111-8111-111111111111",
                "flow": "xtls-rprx-vision",
                "server_name": "www.bing.com",
                "public_key": "public-password",
                "short_id": "aabbccdd",
                "fingerprint": "chrome",
                "spider_x": "/",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"eu-exit", response.data)
        routing = self.client.get("/routing")
        self.assertIn(b"eu-exit", routing.data)

class V096StyleTest(WebTest):
    def test_versioned_stylesheet_and_compact_actions(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"app.css?v=0.10.0-rc8", response.data)
        css = (Path(__file__).parents[1] / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn("Calm Slate", css)
        self.assertIn("v0.9.7 — unified readable interface", css)
        self.assertIn(".button.full { width: 100%; }", css)
        self.assertIn("justify-self: start", css)
        self.assertIn(".outbound-choice-row", css)
        self.assertIn(".outbound-planned-list", css)
        self.assertIn("content: \"✓\"", css)



class RC7WorkflowWebTest(WebTest):
    def test_dashboard_is_read_only_and_diagnostics_owns_service_actions(self):
        self.login()
        status_data = {
            "overall_ok": True, "service": "active", "config_state": "OK",
            "inbound_profile_label": "RAW/TCP + REALITY",
            "address": "vpn.example.com", "port": 443,
            "default_outbound_tag": "warp",
            "enabled_users": 1, "total_users": 1, "expired_users": 0,
            "traffic_total_human": "1 GB", "stats_enabled": True,
            "config_updated_at": "2026-06-26 13:42 UTC",
        }
        with patch("xpanel.web.get_status", return_value=status_data):
            dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn(b'action="/apply"', dashboard.data)
        self.assertNotIn(b'action="/restart"', dashboard.data)
        self.assertIn("Всё работает".encode("utf-8"), dashboard.data)

        diagnostics_data = {
            "os": "Ubuntu", "kernel": "test", "python": "3.13",
            "xray_version": "Xray test", "xray_service": "active",
            "panel_service": "active", "nginx_service": "active",
            "disk_total": "10 GB", "disk_free": "5 GB",
            "memory_total": "2 GB", "memory_available": "1 GB",
            "memory_used": "1 GB", "memory_used_percent": 50,
            "ports": "tcp", "xray_logs": "xray", "panel_logs": "panel",
            "nginx_logs": "nginx",
            "config_validation": {"ok": True, "users": 1, "detail": "", "json": "{}"},
            "dns_enabled": True, "dns_query_strategy": "UseIPv4",
            "dns_servers": [], "dns_test": {"ok": True, "latency_ms": 1, "detail": ""},
            "subscription_settings": {"enabled": 0}, "subscription_users_enabled": 0,
            "security_settings": {"allowlist_enabled": 0, "allowed_networks": ""},
            "security_overview": {"active_sessions": 1, "failed_logins_24h": 0},
            "warp": {"configured": True, "enabled": True, "last_test_state": "on",
                     "last_test_ip": "2a09::1", "last_test_at": "now"},
            "warp_endpoint": "162.159.192.1:2408",
            "default_outbound_tag": "warp",
            "server_address": "vpn.example.com", "server_port": 443,
        }
        with patch("xpanel.web.get_diagnostics", return_value=diagnostics_data):
            diagnostics = self.client.get("/diagnostics")
        self.assertEqual(diagnostics.status_code, 200)
        self.assertIn("Перезапустить Xray".encode("utf-8"), diagnostics.data)
        self.assertIn(b"162.159.192.1:2408", diagnostics.data)

    def test_routing_change_is_applied_immediately(self):
        self.login()
        response = self.client.post(
            "/routing/settings",
            data={
                "csrf_token": self.csrf(),
                "domain_strategy": "AsIs",
                "default_outbound_tag": "direct",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.apply_mock.assert_called_once()
        self.assertIn("Настройки сохранены и применены".encode("utf-8"), response.data)


class V07DnsWebTest(WebTest):
    def test_dns_page_and_enable(self):
        self.login()
        response = self.client.get("/dns")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Cloudflare DOH Local", response.data)
        response = self.client.post(
            "/dns/settings",
            data={
                "csrf_token": self.csrf(),
                "enabled": "on",
                "query_strategy": "UseIPv4",
                "use_system_hosts": "on",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'&#34;queryStrategy&#34;: &#34;UseIPv4&#34;', response.data)

    def test_add_dns_host(self):
        self.login()
        response = self.client.post(
            "/dns/hosts/add",
            data={
                "csrf_token": self.csrf(),
                "domain": "router.local",
                "addresses": "192.168.1.1",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"router.local", response.data)


class V08SubscriptionWebTest(WebTest):
    def _create_user_and_enable_global(self):
        self.login()
        response = self.client.post(
            "/users/add",
            data={"name": "Subscriber", "csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            "/subscriptions/settings",
            data={
                "csrf_token": self.csrf(),
                "enabled": "on",
                "profile_title": "SG-Panel Test",
                "base_url": "http://panel.test:8080",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with connect() as con:
            return con.execute("SELECT * FROM users WHERE name = 'Subscriber'").fetchone()

    def test_subscription_page_and_public_formats(self):
        user = self._create_user_and_enable_global()
        page = self.client.get("/subscriptions")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"http://panel.test:8080/sub/", page.data)

        response = self.client.get(f"/sub/{user['subscription_token']}")
        self.assertEqual(response.status_code, 200)
        decoded = base64.b64decode(response.data.strip()).decode("utf-8")
        self.assertIn("vless://", decoded)
        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")

        plain = self.client.get(f"/sub/{user['subscription_token']}?format=plain")
        self.assertEqual(plain.status_code, 200)
        self.assertTrue(plain.data.startswith(b"vless://"))

        structured = self.client.get(f"/sub/{user['subscription_token']}?format=json")
        self.assertEqual(structured.status_code, 200)
        payload = json.loads(structured.data)
        self.assertEqual(payload["profile"], "SG-Panel Test")
        self.assertEqual(payload["user"], "Subscriber")

    def test_subscription_disable_and_token_rotation(self):
        user = self._create_user_and_enable_global()
        old_token = user["subscription_token"]
        response = self.client.post(
            f"/users/{user['id']}/subscription/regenerate",
            data={"csrf_token": self.csrf()},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with connect() as con:
            updated = con.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        self.assertNotEqual(old_token, updated["subscription_token"])
        self.assertEqual(self.client.get(f"/sub/{old_token}").status_code, 404)
        self.assertEqual(self.client.get(f"/sub/{updated['subscription_token']}").status_code, 200)

        self.client.post(
            f"/users/{user['id']}/subscription/toggle",
            data={"csrf_token": self.csrf()},
        )
        self.assertEqual(self.client.get(f"/sub/{updated['subscription_token']}").status_code, 404)

class V09SecurityWebTest(WebTest):
    def test_security_page_and_headers(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))
        self.login()
        response = self.client.get("/security")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Безопасность панели".encode(), response.data)
        self.assertIn(b"ADMIN SESSIONS", response.data)

    def test_login_lockout(self):
        with connect() as con:
            con.execute(
                "UPDATE security_settings SET max_login_attempts = 3, lockout_minutes = 15 WHERE id = 1"
            )
        for _ in range(2):
            response = self.client.post("/login", data={"password": "wrong"})
            self.assertEqual(response.status_code, 401)
        response = self.client.post("/login", data={"password": "wrong"})
        self.assertEqual(response.status_code, 429)
        response = self.client.post("/login", data={"password": "correct-password"})
        self.assertEqual(response.status_code, 429)

    def test_login_lockout_can_be_cleared(self):
        from xpanel.security import clear_failed_login_attempts

        with connect() as con:
            con.execute(
                "UPDATE security_settings SET max_login_attempts = 3, lockout_minutes = 15 WHERE id = 1"
            )
        for _ in range(3):
            self.client.post("/login", data={"password": "wrong"})

        self.assertEqual(
            self.client.post("/login", data={"password": "correct-password"}).status_code,
            429,
        )
        self.assertEqual(clear_failed_login_attempts("127.0.0.1"), 3)
        self.assertEqual(
            self.client.post("/login", data={"password": "correct-password"}).status_code,
            302,
        )

    def test_subscription_formats_can_be_disabled(self):
        self.login()
        self.client.post(
            "/users/add",
            data={"name": "SecSub", "csrf_token": self.csrf()},
        )
        self.client.post(
            "/subscriptions/settings",
            data={
                "csrf_token": self.csrf(),
                "enabled": "on",
                "profile_title": "Security",
                "base_url": "http://panel.test:8080",
            },
        )
        with connect() as con:
            con.execute(
                "UPDATE security_settings SET subscription_plain_enabled = 0, subscription_json_enabled = 0 WHERE id = 1"
            )
            user = con.execute("SELECT * FROM users WHERE name = 'SecSub'").fetchone()
        token = user["subscription_token"]
        self.assertEqual(self.client.get(f"/sub/{token}").status_code, 200)
        self.assertEqual(self.client.get(f"/sub/{token}?format=plain").status_code, 404)
        self.assertEqual(self.client.get(f"/sub/{token}?format=json").status_code, 404)

    def test_admin_allowlist_denies_unlisted_address(self):
        with connect() as con:
            con.execute(
                "UPDATE security_settings SET allowlist_enabled = 1, allowed_networks = '192.168.1.0/24' WHERE id = 1"
            )
        response = self.client.get(
            "/login", environ_base={"REMOTE_ADDR": "203.0.113.10"}
        )
        self.assertEqual(response.status_code, 403)

class V095OutboundWebTest(WebTest):
    def test_outbound_page_explains_supported_combinations(self):
        self.login()
        response = self.client.get("/outbounds")
        self.assertEqual(response.status_code, 200)
        self.assertIn("VLESS + RAW/TCP + REALITY".encode("utf-8"), response.data)
        self.assertIn("VLESS + XHTTP + TLS".encode("utf-8"), response.data)
        self.assertIn("XHTTP — это транспорт VLESS".encode("utf-8"), response.data)
        self.assertIn(b"direct", response.data)
        self.assertIn(b"blocked", response.data)

    def test_add_xhttp_tls_outbound(self):
        self.login()
        response = self.client.post(
            "/outbounds/add",
            data={
                "csrf_token": self.csrf(),
                "protocol": "vless",
                "tag": "xhttp-tls",
                "name": "XHTTP TLS",
                "address": "cdn.example.com",
                "port": "443",
                "uuid": "11111111-1111-4111-8111-111111111111",
                "flow": "",
                "network": "xhttp",
                "security": "tls",
                "server_name": "cdn.example.com",
                "fingerprint": "chrome",
                "xhttp_host": "cdn.example.com",
                "xhttp_path": "/api/connect",
                "xhttp_mode": "stream-up",
                "alpn": "h2,http/1.1",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"xhttp-tls", response.data)
        with connect() as con:
            row = con.execute("SELECT * FROM outbounds WHERE tag = 'xhttp-tls'").fetchone()
        self.assertEqual(row["network"], "xhttp")
        self.assertEqual(row["security"], "tls")
        self.assertEqual(row["xhttp_mode"], "stream-up")

class RC5ProfilesAndWarpWebTest(WebTest):
    def test_settings_shows_three_current_profiles_without_grpc_card(self):
        self.login()
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"RAW/TCP + REALITY", response.data)
        self.assertIn(b"XHTTP + TLS", response.data)
        self.assertIn(b"XHTTP + REALITY", response.data)
        self.assertNotIn(b"<strong>gRPC + TLS</strong>", response.data)

    def test_outbounds_page_contains_warp_manager(self):
        self.login()
        response = self.client.get("/outbounds")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Cloudflare", response.data)
        self.assertIn(b"WARP", response.data)
        self.assertIn("Создать WARP".encode("utf-8"), response.data)


class RC5NavigationAndSeparationWebTest(WebTest):
    def test_navigation_uses_clear_technical_names_in_workflow_order(self):
        self.login()
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        labels = [
            ">Inbound<",
            ">Outbounds<",
            ">Routing<",
            ">DNS<",
            ">Xray Config<",
        ]
        positions = [html.index(label) for label in labels]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn(">Сервер<", html)
        self.assertNotIn(">Выходы<", html)
        self.assertNotIn(">Маршрутизация<", html)
        self.assertNotIn(">Конфиг<", html)

    def test_warp_management_and_routing_are_separate(self):
        self.login()
        outbounds = self.client.get("/outbounds")
        self.assertEqual(outbounds.status_code, 200)
        self.assertIn(b"WARP Outbound", outbounds.data)
        self.assertIn("Открыть Routing".encode("utf-8"), outbounds.data)
        self.assertNotIn(b'name="route_mode"', outbounds.data)

        routing = self.client.get("/routing")
        self.assertEqual(routing.status_code, 200)
        self.assertIn(b"WARP Routing", routing.data)
        self.assertIn("Открыть Outbounds".encode("utf-8"), routing.data)

    def test_password_is_on_security_not_inbound(self):
        self.login()
        inbound = self.client.get("/settings")
        security = self.client.get("/security")
        self.assertNotIn('name="current_password"'.encode(), inbound.data)
        self.assertIn('name="current_password"'.encode(), security.data)
        self.assertIn("Сменить пароль".encode("utf-8"), security.data)

    def test_xray_runtime_settings_live_on_config_page(self):
        self.login()
        inbound = self.client.get("/settings")
        config = self.client.get("/config")
        self.assertNotIn(b'name="api_listen"', inbound.data)
        self.assertIn(b'name="api_listen"', config.data)
        self.assertIn(b'Xray Config', config.data)

    def test_inbound_save_preserves_runtime_settings(self):
        self.login()
        with connect() as con:
            con.execute(
                "UPDATE server_settings SET loglevel = 'error', api_listen = '127.0.0.1:19085', "
                "stats_enabled = 0, config_path = '/tmp/kept.json', xray_bin = '/bin/true', "
                "xray_service = 'kept-xray' WHERE id = 1"
            )
        response = self.client.post(
            "/settings/server",
            data={
                "csrf_token": self.csrf(),
                "inbound_profile": "raw_reality",
                "address": "192.168.1.200",
                "listen": "0.0.0.0",
                "port": "443",
                "server_name": "www.bing.com",
                "fingerprint": "chrome",
                "flow": "xtls-rprx-vision",
                "dest": "www.bing.com:443",
                "private_key": "private",
                "public_key": "public",
                "short_id": "0011223344556677",
                "transport_listen": "127.0.0.1",
                "transport_port": "8443",
                "xhttp_path": "/sg-xhttp",
                "xhttp_mode": "auto",
                "tls_cert_path": "/tmp/fullchain.pem",
                "tls_key_path": "/tmp/privkey.pem",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with connect() as con:
            row = con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
        self.assertEqual(row["loglevel"], "error")
        self.assertEqual(row["api_listen"], "127.0.0.1:19085")
        self.assertEqual(row["stats_enabled"], 0)
        self.assertEqual(row["config_path"], "/tmp/kept.json")
        self.assertEqual(row["xray_service"], "kept-xray")

    def test_config_runtime_save_preserves_inbound(self):
        self.login()
        with connect() as con:
            before = con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
        response = self.client.post(
            "/config/runtime",
            data={
                "csrf_token": self.csrf(),
                "loglevel": "info",
                "api_listen": "127.0.0.1:18085",
                "stats_enabled": "on",
                "config_path": "/tmp/config-new.json",
                "xray_bin": "/bin/true",
                "xray_service": "xray-new",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with connect() as con:
            after = con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
        self.assertEqual(after["address"], before["address"])
        self.assertEqual(after["private_key"], before["private_key"])
        self.assertEqual(after["inbound_profile"], before["inbound_profile"])
        self.assertEqual(after["loglevel"], "info")
        self.assertEqual(after["api_listen"], "127.0.0.1:18085")
        self.assertEqual(after["stats_enabled"], 1)
        self.assertEqual(after["config_path"], "/tmp/config-new.json")
        self.assertEqual(after["xray_service"], "xray-new")
