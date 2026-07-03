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
from xpanel.update_manager import (
    check_for_updates,
    normalized_version,
    start_panel_update,
    version_key,
)
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, payload: object):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _limit: int = -1) -> bytes:
        return self.payload


class UpdateVersionTest(unittest.TestCase):
    def test_version_parser_accepts_publication_suffixes(self):
        self.assertEqual(normalized_version("v0.10.0-rc30-final-docs1"), "v0.10.0-rc30")
        self.assertGreater(version_key("v0.10.0"), version_key("v0.10.0-rc99"))
        self.assertGreater(version_key("v0.10.0-rc31"), version_key("v0.10.0-rc30"))
        self.assertEqual(normalized_version("v0.10.0-rc35/unsafe"), "")
        self.assertEqual(version_key("v0.10.0-rc35garbage"), (-1, -1, -1, -1, -1))

    def test_update_check_selects_newest_application_version(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ), patch(
            "xpanel.update_manager.urllib.request.urlopen",
            return_value=FakeResponse(
                [
                    {"name": "v0.10.0-rc30-final-docs1"},
                    {"name": "v0.10.0-rc35"},
                    {"name": "not-a-release"},
                ]
            ),
        ):
            result = check_for_updates(force=True)
        self.assertEqual(result["latest"], "v0.10.0-rc35")
        self.assertEqual(result["latest_ref"], "v0.10.0-rc35")
        self.assertTrue(result["available"])

    def test_update_check_does_not_report_an_older_remote_tag_as_latest(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ), patch(
            "xpanel.update_manager.urllib.request.urlopen",
            return_value=FakeResponse([{"name": "v0.10.0-rc30-final-docs1"}]),
        ):
            result = check_for_updates(force=True)
        self.assertEqual(result["current"], "v0.10.0-rc34")
        self.assertEqual(result["latest"], "v0.10.0-rc34")
        self.assertEqual(result["latest_ref"], "v0.10.0-rc34")
        self.assertFalse(result["available"])

    def test_cached_check_is_ignored_after_installed_version_changes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"XPANEL_UPDATE_STATE_DIR": tmp}
        ):
            Path(tmp, "check.json").write_text(
                json.dumps({
                    "current": "v0.10.0-rc33",
                    "latest": "v0.10.0-rc34",
                    "latest_ref": "v0.10.0-rc34",
                    "available": True,
                    "checked_at": "2099-01-01T00:00:00+00:00",
                    "error": "",
                }),
                encoding="utf-8",
            )
            with patch(
                "xpanel.update_manager.urllib.request.urlopen",
                return_value=FakeResponse([{"name": "v0.10.0-rc35"}]),
            ) as request:
                result = check_for_updates(force=False)
        request.assert_called_once()
        self.assertEqual(result["current"], "v0.10.0-rc34")
        self.assertEqual(result["latest"], "v0.10.0-rc35")

    def test_start_rejects_unsafe_ref_before_systemd(self):
        with self.assertRaises(ValueError):
            start_panel_update("v0.10.0-rc35", "v0.10.0-rc35/unsafe")

    def test_failed_systemd_launch_is_persisted_as_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            (project / "deploy").mkdir(parents=True)
            (project / "deploy" / "update-from-github.sh").write_text(
                "#!/usr/bin/env bash\n", encoding="utf-8"
            )
            state = Path(tmp) / "state"
            env = {
                "XPANEL_PROJECT_DIR": str(project),
                "XPANEL_UPDATE_STATE_DIR": str(state),
                "XPANEL_UPDATE_TEST_MODE": "1",
            }
            completed = [
                subprocess.CompletedProcess(["systemctl"], 0, "", ""),
                subprocess.CompletedProcess(["systemd-run"], 1, "", "launch failed"),
            ]
            with patch.dict(os.environ, env), patch(
                "xpanel.update_manager.update_in_progress", return_value=False
            ), patch(
                "xpanel.update_manager.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ), patch(
                "xpanel.update_manager.subprocess.run", side_effect=completed
            ):
                with self.assertRaisesRegex(Exception, "launch failed"):
                    start_panel_update("v0.10.0-rc35", "v0.10.0-rc35")
            payload = json.loads((state / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["state"], "error")
            self.assertIn("launch failed", payload["message"])

    def test_successful_launch_uses_transient_systemd_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            (project / "deploy").mkdir(parents=True)
            script = project / "deploy" / "update-from-github.sh"
            script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            state = Path(tmp) / "state"
            env = {
                "XPANEL_PROJECT_DIR": str(project),
                "XPANEL_UPDATE_STATE_DIR": str(state),
                "XPANEL_UPDATE_TEST_MODE": "1",
            }
            calls = []
            def fake_run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")
            with patch.dict(os.environ, env), patch(
                "xpanel.update_manager.update_in_progress", return_value=False
            ), patch(
                "xpanel.update_manager.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ), patch(
                "xpanel.update_manager.subprocess.run", side_effect=fake_run
            ):
                result = start_panel_update("v0.10.0-rc35", "v0.10.0-rc35")
            self.assertEqual(result["unit"], "sg-panel-update.service")
            command = calls[-1]
            self.assertIn("--unit=sg-panel-update", command)
            self.assertIn("--collect", command)
            self.assertIn("--setenv=XPANEL_UPDATE_VERSION=v0.10.0-rc35", command)
            self.assertEqual(command[-2:], ["/bin/bash", str(script)])


class UpdateWebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["XPANEL_DB"] = str(Path(self.tmp.name) / "panel.db")
        os.environ["XPANEL_UPDATE_STATE_DIR"] = str(Path(self.tmp.name) / "updates")
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
                    "192.0.2.10", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
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
        os.environ.pop("XPANEL_UPDATE_STATE_DIR", None)

    def login(self):
        response = self.client.post("/login", data={"password": "correct-password"})
        self.assertEqual(response.status_code, 302)

    def csrf(self) -> str:
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_health_is_available_without_login(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.data)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload, {"ok": True})

    def test_health_is_not_exposed_to_remote_clients(self):
        response = self.client.get("/health", environ_base={"REMOTE_ADDR": "198.51.100.25"})
        self.assertEqual(response.status_code, 404)

    def test_updates_page_has_backups_and_updates_tabs(self):
        self.login()
        with patch(
            "xpanel.web.check_for_updates",
            return_value={
                "current": "v0.10.0-rc34",
                "latest": "v0.10.0-rc35",
                "latest_ref": "v0.10.0-rc35",
                "available": True,
                "checked_at": "2026-07-03T12:00:00+00:00",
                "error": "",
            },
        ), patch(
            "xpanel.web.get_update_status",
            return_value={"state": "idle", "message": "", "log": ""},
        ), patch("xpanel.web.update_in_progress", return_value=False):
            response = self.client.get("/updates")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Backups", response.data)
        self.assertIn(b"Updates", response.data)
        self.assertIn("Автоматический откат".encode("utf-8"), response.data)
        self.assertIn(b"v0.10.0-rc35", response.data)
        self.assertIn(b"/home/ubuntu/sg-panel-main", response.data)
        self.assertNotIn(b"cd /opt/xpanel-mvp", response.data)

    def test_update_start_rechecks_version_and_launches_job(self):
        self.login()
        info = {
            "current": "v0.10.0-rc34",
            "latest": "v0.10.0-rc35",
            "latest_ref": "v0.10.0-rc35",
            "available": True,
            "checked_at": "2026-07-03T12:00:00+00:00",
            "error": "",
        }
        with patch("xpanel.web.check_for_updates", return_value=info), patch(
            "xpanel.web.start_panel_update",
            return_value={
                "unit": "sg-panel-update.service",
                "version": "v0.10.0-rc35",
                "ref": "v0.10.0-rc35",
            },
        ) as start:
            response = self.client.post(
                "/updates/start",
                data={
                    "csrf_token": self.csrf(),
                    "version": "v0.10.0-rc35",
                    "ref": "v0.10.0-rc35",
                },
            )
        self.assertEqual(response.status_code, 302)
        start.assert_called_once_with("v0.10.0-rc35", "v0.10.0-rc35")


class UpdatePackageTest(unittest.TestCase):
    def test_updater_has_lock_backup_validation_and_rollback(self):
        script = (ROOT / "deploy" / "update-from-github.sh").read_text(encoding="utf-8")
        for marker in (
            "flock -n 9",
            "Создание полной страховочной копии",
            "backup_database",
            "backup_certificates",
            "xray run -test",
            "nginx -t",
            "status rollback",
            "status rolled_back",
            "Previous",  # absent by design; keep Russian user-facing log only
        ):
            if marker == "Previous":
                self.assertNotIn(marker, script)
            else:
                self.assertIn(marker, script)
        self.assertIn("/root/sg-panel-backups/${STAMP}-update-rollback", script)
        self.assertIn("SQLite, Xray, WARP, DNS, Traffic Rules, Outbounds", script)
        self.assertIn("wait_for_health", script)
        self.assertIn("/etc/nginx/sites-available/sg-panel-xray-transport", script)
        self.assertIn("/etc/nginx/modules-enabled/90-sg-panel-reality-edge.conf", script)
        self.assertIn("/usr/local/etc/xray/sg-panel-tls", script)
        self.assertIn("xray.service", script)
        self.assertIn("Предыдущая рабочая версия восстановлена и проверена", script)
        self.assertIn("Автоматический откат выполнен не полностью", script)
        self.assertIn("flock -n 9", script)

    def test_service_grants_only_managed_update_state_write_path(self):
        script = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
        self.assertIn("/var/lib/sg-panel-update", script)
        self.assertIn("chmod 0700 /var/lib/sg-panel-update", script)
        self.assertNotIn("ReadWritePaths=/root", script)

    def test_local_update_wrapper_uses_same_safe_updater(self):
        script = (ROOT / "deploy" / "update-from-local-source.sh").read_text(encoding="utf-8")
        self.assertIn("XPANEL_UPDATE_SOURCE_DIR", script)
        self.assertIn("deploy/update-from-github.sh", script)


if __name__ == "__main__":
    unittest.main()
