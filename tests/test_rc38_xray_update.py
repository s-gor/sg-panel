from __future__ import annotations

import json
import os
import subprocess
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
from xpanel.xray_update_manager import (
    check_xray_updates,
    normalize_xray_version,
    start_xray_update,
    xray_version_key,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, payload: object):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit: int = -1) -> bytes:
        if limit is None or limit < 0:
            return self.payload
        return self.payload[:limit]


def release(tag: str, *, prerelease: bool, asset: str = "Xray-linux-64.zip") -> dict:
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": prerelease,
        "published_at": "2026-07-04T00:00:00Z",
        "html_url": f"https://github.com/XTLS/Xray-core/releases/tag/{tag}",
        "assets": [
            {"name": asset},
            {"name": f"{asset}.dgst"},
        ],
    }


class XrayVersionTest(unittest.TestCase):
    def test_numeric_version_parser(self):
        self.assertEqual(normalize_xray_version("26.5.9"), "v26.5.9")
        self.assertEqual(normalize_xray_version("v26.6.27"), "v26.6.27")
        self.assertEqual(normalize_xray_version("v26.6.27-beta"), "")
        self.assertGreater(xray_version_key("v26.6.27"), xray_version_key("v26.5.9"))

    def test_stable_channel_uses_latest_full_release_and_blocks_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ), patch(
            "xpanel.xray_update_manager.installed_xray_version",
            return_value="v26.5.9",
        ), patch(
            "xpanel.xray_update_manager.platform.machine", return_value="x86_64"
        ), patch(
            "xpanel.xray_update_manager.urllib.request.urlopen",
            return_value=FakeResponse(release("v26.3.27", prerelease=False)),
        ) as request:
            result = check_xray_updates(channel="stable", force=True)
        self.assertIn("/releases/latest", request.call_args.args[0].full_url)
        self.assertEqual(result["latest"], "v26.3.27")
        self.assertFalse(result["available"])
        self.assertTrue(result["installed_newer"])

    def test_prerelease_channel_selects_newest_prerelease_only(self):
        payload = [
            release("v26.6.22", prerelease=True),
            release("v26.3.27", prerelease=False),
            release("v26.6.27", prerelease=True),
        ]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ), patch(
            "xpanel.xray_update_manager.installed_xray_version",
            return_value="v26.5.9",
        ), patch(
            "xpanel.xray_update_manager.platform.machine", return_value="x86_64"
        ), patch(
            "xpanel.xray_update_manager.urllib.request.urlopen",
            return_value=FakeResponse(payload),
        ):
            result = check_xray_updates(channel="prerelease", force=True)
        self.assertEqual(result["latest"], "v26.6.27")
        self.assertTrue(result["available"])
        self.assertTrue(result["prerelease"])
        self.assertEqual(result["asset"], "Xray-linux-64.zip")

    def test_prerelease_response_larger_than_old_one_megabyte_limit_is_complete(self):
        item = release("v26.6.27", prerelease=True)
        item["body"] = "x" * 1_100_000
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ), patch(
            "xpanel.xray_update_manager.installed_xray_version",
            return_value="v26.5.9",
        ), patch(
            "xpanel.xray_update_manager.platform.machine", return_value="x86_64"
        ), patch(
            "xpanel.xray_update_manager.urllib.request.urlopen",
            return_value=FakeResponse([item]),
        ):
            result = check_xray_updates(channel="prerelease", force=True)
        self.assertEqual(result["latest"], "v26.6.27")
        self.assertTrue(result["available"])
        self.assertEqual(result["error"], "")

    def test_release_without_official_digest_is_rejected(self):
        payload = release("v26.6.27", prerelease=True)
        payload["assets"] = [{"name": "Xray-linux-64.zip"}]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ), patch(
            "xpanel.xray_update_manager.installed_xray_version",
            return_value="v26.5.9",
        ), patch(
            "xpanel.xray_update_manager.platform.machine", return_value="x86_64"
        ), patch(
            "xpanel.xray_update_manager.urllib.request.urlopen",
            return_value=FakeResponse([payload]),
        ):
            result = check_xray_updates(channel="prerelease", force=True)
        self.assertFalse(result["available"])
        self.assertIn("официальный релиз", result["error"])


class XrayStartTest(unittest.TestCase):
    def test_start_uses_separate_transient_unit_and_safe_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            (project / "deploy").mkdir(parents=True)
            script = project / "deploy" / "update-xray.sh"
            script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            xray = root / "xray"
            xray.write_text("binary", encoding="utf-8")
            xray.chmod(0o755)
            config = root / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            state = root / "state"
            env = {
                "XPANEL_PROJECT_DIR": str(project),
                "XPANEL_UPDATE_STATE_DIR": str(state),
                "XPANEL_UPDATE_TEST_MODE": "1",
            }
            calls: list[list[str]] = []

            def fake_run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.dict(os.environ, env), patch(
                "xpanel.xray_update_manager.installed_xray_version",
                return_value="v26.5.9",
            ), patch(
                "xpanel.xray_update_manager.xray_update_in_progress",
                return_value=False,
            ), patch(
                "xpanel.update_manager.update_in_progress", return_value=False
            ), patch(
                "xpanel.xray_update_manager.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ), patch(
                "xpanel.xray_update_manager.subprocess.run", side_effect=fake_run
            ):
                result = start_xray_update(
                    "v26.6.27",
                    "prerelease",
                    xray_bin=str(xray),
                    config_path=str(config),
                    xray_service="xray",
                )

            self.assertEqual(result["unit"], "sg-panel-xray-update.service")
            command = calls[-1]
            self.assertIn("--unit=sg-panel-xray-update", command)
            self.assertIn("--setenv=XPANEL_XRAY_UPDATE_VERSION=v26.6.27", command)
            self.assertIn("--setenv=XPANEL_XRAY_UPDATE_CHANNEL=prerelease", command)
            self.assertIn(f"--setenv=XPANEL_XRAY_BIN={xray}", command)
            self.assertEqual(command[-2:], ["/bin/bash", str(script)])

    def test_start_rejects_downgrade(self):
        with patch(
            "xpanel.xray_update_manager.installed_xray_version",
            return_value="v26.5.9",
        ):
            with self.assertRaisesRegex(ValueError, "не новее"):
                start_xray_update("v26.3.27", "stable")


class XrayUpdateWebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["XPANEL_DB"] = str(Path(self.tmp.name) / "panel.db")
        os.environ["XPANEL_UPDATE_STATE_DIR"] = str(Path(self.tmp.name) / "updates")
        init_db()
        config = Path(self.tmp.name) / "config.json"
        config.write_text("{}\n", encoding="utf-8")
        xray = Path(self.tmp.name) / "xray"
        xray.write_text("binary", encoding="utf-8")
        xray.chmod(0o755)
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
                    "192.0.2.10", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(config), str(xray), "xray",
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
        os.environ.pop("XPANEL_UPDATE_STATE_DIR", None)

    def login(self):
        response = self.client.post("/login", data={"password": "correct-password"})
        self.assertEqual(response.status_code, 302)

    def csrf(self) -> str:
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_prerelease_button_rechecks_and_starts_xray_job(self):
        self.login()
        info = {
            "channel": "prerelease",
            "current": "v26.5.9",
            "latest": "v26.6.27",
            "available": True,
            "installed_newer": False,
            "checked_at": "2026-07-04T12:00:00+00:00",
            "error": "",
        }
        with patch("xpanel.web.update_in_progress", return_value=False), patch(
            "xpanel.web.xray_update_in_progress", return_value=False
        ), patch("xpanel.web.check_xray_updates", return_value=info), patch(
            "xpanel.web.start_xray_update",
            return_value={
                "unit": "sg-panel-xray-update.service",
                "version": "v26.6.27",
                "channel": "prerelease",
            },
        ) as start:
            response = self.client.post(
                "/updates/xray/start",
                data={
                    "csrf_token": self.csrf(),
                    "channel": "prerelease",
                    "version": "v26.6.27",
                },
            )
        self.assertEqual(response.status_code, 302)
        with connect() as con:
            server = con.execute(
                "SELECT xray_bin, config_path, xray_service FROM server_settings WHERE id=1"
            ).fetchone()
        start.assert_called_once_with(
            "v26.6.27",
            "prerelease",
            xray_bin=server["xray_bin"],
            config_path=server["config_path"],
            xray_service=server["xray_service"],
        )


class XrayUpdatePackageTest(unittest.TestCase):
    def test_shell_updater_has_verification_lock_listener_check_and_rollback(self):
        script = (ROOT / "deploy" / "update-xray.sh").read_text(encoding="utf-8")
        for marker in (
            "flock -n 9",
            "Xray-linux-64.zip",
            ".dgst",
            "sha256sum",
            "run -test -config",
            "expected-listeners.tsv",
            "ss -H -lun",
            "ss -H -ltn",
            "status rollback",
            "status rolled_back",
            "xray-update-rollback",
        ):
            self.assertIn(marker, script)
        self.assertNotIn("install-release.sh", script)

    def test_shell_updater_treats_xray_hysteria_as_udp(self):
        script = (ROOT / "deploy" / "update-xray.sh").read_text(encoding="utf-8")
        self.assertIn(
            'protocol in {"hysteria", "hysteria2", "dokodemo-door-udp"}',
            script,
        )
        self.assertIn('stream_network in {"hysteria", "hysteria2"}', script)

    def test_listener_inventory_outputs_hysteria_ports_as_udp(self):
        script = (ROOT / "deploy" / "update-xray.sh").read_text(encoding="utf-8")
        start_marker = 'python3 - "$CONFIG" "$TMP_DIR/expected-listeners.tsv" <<\'PY\'\n'
        start = script.index(start_marker) + len(start_marker)
        end = script.index("\nPY\n", start)
        inventory_code = script[start:end]
        config = {
            "inbounds": [
                {
                    "tag": "vless-reality-in",
                    "port": 443,
                    "protocol": "hysteria",
                    "streamSettings": {"network": "hysteria"},
                },
                {
                    "tag": "hysteria2-secondary-in",
                    "port": 8443,
                    "protocol": "hysteria",
                    "streamSettings": {"network": "hysteria"},
                },
                {
                    "tag": "hysteria2-tertiary-in",
                    "port": 9443,
                    "protocol": "hysteria",
                    "streamSettings": {"network": "hysteria"},
                },
                {
                    "tag": "raw-reality-in",
                    "port": 10443,
                    "protocol": "vless",
                    "streamSettings": {"network": "tcp"},
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "config.json"
            target = root / "listeners.tsv"
            source.write_text(json.dumps(config), encoding="utf-8")
            subprocess.run(
                ["python3", "-c", inventory_code, str(source), str(target)],
                check=True,
                text=True,
                capture_output=True,
            )
            rows = target.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            rows,
            [
                "udp\t443\tvless-reality-in",
                "udp\t8443\thysteria2-secondary-in",
                "udp\t9443\thysteria2-tertiary-in",
                "tcp\t10443\traw-reality-in",
            ],
        )

    def test_listener_inventory_expands_multi_port_reality_listener(self):
        script = (ROOT / "deploy" / "update-xray.sh").read_text(encoding="utf-8")
        start_marker = 'python3 - "$CONFIG" "$TMP_DIR/expected-listeners.tsv" <<\'PY\'\n'
        start = script.index(start_marker) + len(start_marker)
        end = script.index("\nPY\n", start)
        inventory_code = script[start:end]
        config = {
            "inbounds": [
                {
                    "tag": "vless-reality-in",
                    "port": "443,8443,9443",
                    "protocol": "vless",
                    "streamSettings": {"network": "tcp"},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "config.json"
            target = root / "listeners.tsv"
            source.write_text(json.dumps(config), encoding="utf-8")
            subprocess.run(
                ["python3", "-c", inventory_code, str(source), str(target)],
                check=True,
                text=True,
                capture_output=True,
            )
            rows = target.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            rows,
            [
                "tcp\t443\tvless-reality-in",
                "tcp\t8443\tvless-reality-in",
                "tcp\t9443\tvless-reality-in",
            ],
        )

    def test_installer_preserves_xray_newer_than_recommended(self):
        script = (ROOT / "deploy" / "ec2-first-install.sh").read_text(encoding="utf-8")
        self.assertIn("Сохраняю установленный Xray", script)
        self.assertIn("он новее рекомендуемой версии", script)
        self.assertIn("старее рекомендуемой", script)
        self.assertNotIn(
            'run_stage "Обновление Xray до $XRAY_VERSION с автоматическим откатом"',
            script,
        )

    def test_template_has_two_channels_and_independent_xray_log(self):
        template = (ROOT / "xpanel" / "templates" / "updates.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("Стабильная версия", template)
        self.assertIn("Предварительная версия", template)
        self.assertIn("Установить для теста", template)
        self.assertIn("xray_updates_start", template)
        self.assertIn("xray_updates_status", template)
        self.assertIn("ЖУРНАЛ XRAY", template)
        self.assertIn("data-inline-confirm", template)
        self.assertIn("update-inline-confirm", template)
        self.assertIn("confirmPanel.scrollIntoView", template)
        self.assertNotIn("<dialog", template)
        self.assertNotIn("showModal()", template)
        self.assertNotIn("window.open", template)
        self.assertNotIn("onsubmit=\"return confirm('Установить предварительную", template)


if __name__ == "__main__":
    unittest.main()
