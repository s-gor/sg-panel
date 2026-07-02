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

from itsdangerous import URLSafeTimedSerializer
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
        self.apply_mock = self.apply_patcher.start()
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

    def validated_post(
        self, path: str, data: dict[str, object], *, follow_redirects: bool = True
    ):
        payload = dict(data)
        payload["csrf_token"] = self.csrf()
        validation_payload = dict(payload)
        validation_payload["action"] = "validate"
        validation = self.client.post(path, data=validation_payload)
        self.assertEqual(validation.status_code, 200, validation.data.decode("utf-8", "replace"))
        body = json.loads(validation.data)
        self.assertTrue(body.get("ok"), body)
        self.assertTrue(body.get("token"), body)
        save_payload = dict(payload)
        save_payload["validation_token"] = body["token"]
        return self.client.post(
            path, data=save_payload, follow_redirects=follow_redirects
        )

    def test_json_pages_are_available(self):
        for path, marker in (
            ("/users/json", b"users-v1"),
            ("/settings/json", b"vless-reality-in"),
            ("/outbounds/json/new", b"JSON"),
            ("/routing/json", b"routing-v1"),
            ("/routing/rules/json/new", b"geosite:category-ads-all"),
            ("/dns/json", b"_sgPanel"),
            ("/config/json", b"config-v1"),
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(marker, response.data)

    def test_users_json_requires_validation_and_saves_exact_draft(self):
        from xpanel.service import users_json_document

        document = json.loads(users_json_document())
        document["users"].append(
            {
                "name": "JSON User",
                "uuid": "88888888-8888-4888-8888-888888888888",
                "enabled": True,
                "comment": "created by contextual JSON",
                "expiryAt": None,
                "subscriptionEnabled": True,
            }
        )
        source = json.dumps(document)
        rejected = self.client.post(
            "/users/json",
            data={"csrf_token": self.csrf(), "json_config": source},
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("Сначала нажмите".encode("utf-8"), rejected.data)

        saved = self.validated_post(
            "/users/json",
            data={"json_config": source},
            follow_redirects=True,
        )
        self.assertEqual(saved.status_code, 200)
        self.assertIn(b"JSON User", saved.data)
        with connect() as con:
            row = con.execute(
                "SELECT comment FROM users WHERE name = 'JSON User'"
            ).fetchone()
        self.assertEqual(row["comment"], "created by contextual JSON")

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
        response = self.validated_post(
            "/outbounds/json/new",
            data={"csrf_token": self.csrf(), "json_config": json.dumps(outbound)},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"eu-exit", response.data)
        self.assertIn(b"JSON", response.data)
        self.assertGreaterEqual(self.apply_mock.call_count, 1)
        self.assertIn("сохранены и применены".encode("utf-8"), response.data)

        rule = {
            "_sgPanel": {"name": "EU domains", "priority": 30, "enabled": True},
            "type": "field",
            "domain": ["geosite:fr"],
            "outboundTag": "eu-exit",
        }
        response = self.validated_post(
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
        response = self.validated_post(
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



    def test_generated_user_uuid_is_the_exact_validated_uuid(self):
        payload = {"name": "Validated UUID", "comment": "phone", "expiry_at": ""}
        validation = self.client.post(
            "/users/add",
            data={
                **payload,
                "csrf_token": self.csrf(),
                "action": "validate",
            },
        )
        self.assertEqual(validation.status_code, 200)
        body = json.loads(validation.data)
        signed = URLSafeTimedSerializer(
            "test-json-secret", salt="sg-panel-config-validation-v1"
        ).loads(body["token"])
        validated_uuid = signed["claims"]["user_uuid"]
        saved = self.client.post(
            "/users/add",
            data={
                **payload,
                "csrf_token": self.csrf(),
                "validation_token": body["token"],
            },
        )
        self.assertEqual(saved.status_code, 302)
        with connect() as con:
            row = con.execute(
                "SELECT uuid FROM users WHERE name = ?", (payload["name"],)
            ).fetchone()
        self.assertEqual(row["uuid"], validated_uuid)

    def test_validation_is_required_and_draft_does_not_touch_live_database(self):
        outbound = {
            "_sgPanel": {"name": "Draft", "enabled": True},
            "tag": "draft-exit",
            "protocol": "vless",
            "settings": {
                "address": "draft.example.com",
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
            },
        }
        source = json.dumps(outbound)
        with connect() as con:
            before = con.execute("SELECT COUNT(*) FROM outbounds").fetchone()[0]

        rejected = self.client.post(
            "/outbounds/json/new",
            data={"csrf_token": self.csrf(), "json_config": source},
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("Сначала нажмите".encode("utf-8"), rejected.data)

        validation = self.client.post(
            "/outbounds/json/new",
            data={
                "csrf_token": self.csrf(),
                "json_config": source,
                "action": "validate",
            },
        )
        self.assertEqual(validation.status_code, 200)
        body = json.loads(validation.data)
        self.assertTrue(body["ok"])
        self.assertTrue(body["token"])
        with connect() as con:
            after_validation = con.execute("SELECT COUNT(*) FROM outbounds").fetchone()[0]
        self.assertEqual(after_validation, before)

        changed = json.loads(source)
        changed["_sgPanel"]["name"] = "Changed after validation"
        rejected_changed = self.client.post(
            "/outbounds/json/new",
            data={
                "csrf_token": self.csrf(),
                "json_config": json.dumps(changed),
                "validation_token": body["token"],
            },
        )
        self.assertEqual(rejected_changed.status_code, 400)
        self.assertIn("Данные изменились после проверки".encode("utf-8"), rejected_changed.data)

    def test_validation_token_expires_when_live_configuration_changes(self):
        outbound = {
            "_sgPanel": {"name": "Revision", "enabled": True},
            "tag": "revision-exit",
            "protocol": "vless",
            "settings": {
                "address": "revision.example.com",
                "port": 443,
                "id": "33333333-3333-4333-8333-333333333333",
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
        source = json.dumps(outbound)
        validation = self.client.post(
            "/outbounds/json/new",
            data={
                "csrf_token": self.csrf(),
                "json_config": source,
                "action": "validate",
            },
        )
        body = json.loads(validation.data)
        with connect() as con:
            con.execute(
                "UPDATE routing_settings SET domain_strategy = 'IPIfNonMatch' WHERE id = 1"
            )
        rejected = self.client.post(
            "/outbounds/json/new",
            data={
                "csrf_token": self.csrf(),
                "json_config": source,
                "validation_token": body["token"],
            },
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("изменилась после проверки".encode("utf-8"), rejected.data)


    def test_validation_token_is_single_use(self):
        payload = {
            "loglevel": "warning",
            "api_listen": "127.0.0.1:10085",
            "config_path": "/tmp/config.json",
            "xray_bin": "/bin/true",
            "xray_service": "xray",
        }
        validation = self.client.post(
            "/config/runtime",
            data={
                **payload,
                "csrf_token": self.csrf(),
                "action": "validate",
            },
        )
        body = json.loads(validation.data)
        self.assertTrue(body["ok"])
        save_data = {
            **payload,
            "csrf_token": self.csrf(),
            "validation_token": body["token"],
        }
        first = self.client.post("/config/runtime", data=save_data)
        self.assertEqual(first.status_code, 302)
        second = self.client.post(
            "/config/runtime", data=save_data, follow_redirects=True
        )
        self.assertEqual(second.status_code, 200)
        self.assertTrue(
            "уже использован".encode("utf-8") in second.data
            or "изменилась после проверки".encode("utf-8") in second.data
        )

    def test_validation_ui_is_present_and_save_starts_disabled(self):
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"data-validated-form", response.data)
        self.assertIn("Проверить конфигурацию".encode("utf-8"), response.data)
        self.assertIn(b"validation_token", response.data)
        self.assertIn(b"saveButton.dataset.saveButton", response.data)

    def test_geo_country_preset(self):
        response = self.validated_post(
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
