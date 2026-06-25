from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

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
                    "www.microsoft.com:443", "www.microsoft.com",
                    "private", "public", "0011223344556677", "chrome",
                    "/tmp/config.json", "/bin/true", "xray",
                ),
            )
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "PASSWORD_HASH": generate_password_hash("correct-password"),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
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
            ("/settings", b"Stats API listen"),
            ("/config", b"GENERATED JSON"),
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
                "server_name": "www.microsoft.com",
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

class V092StyleTest(WebTest):
    def test_versioned_stylesheet_and_compact_actions(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"app.css?v=0.9.4", response.data)
        css = (Path(__file__).parents[1] / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn("Calm Slate", css)
        self.assertIn("v0.9.4 — EC2 Ready", css)
        self.assertIn(".button.full { width: 100%; }", css)
        self.assertIn("justify-self: start", css)



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
