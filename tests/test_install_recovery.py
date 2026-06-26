from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EC2 = ROOT / "deploy" / "ec2-first-install.sh"
BOOTSTRAP = ROOT / "install-from-github.sh"
PURGE = ROOT / "deploy" / "purge-test-server.sh"
README = ROOT / "README.md"


class InstallRecoveryTest(unittest.TestCase):
    def test_incomplete_install_returns_to_wizard(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn("Обнаружена незавершённая установка", text)
        self.assertIn("Повторно запускаю мастер", text)
        self.assertIn("configured_https_is_usable", text)
        self.assertNotIn("обнаружена неполная старая установка", text)

    def test_completion_marker_is_written_only_after_https_check(self):
        text = EC2.read_text(encoding="utf-8")
        check_pos = text.index('wait_for_gui || fail')
        marker_pos = text.index('write_install_marker "$PANEL_DOMAIN" "$PANEL_HTTPS_PORT"')
        self.assertGreater(marker_pos, check_pos)

    def test_reconfigure_is_forwarded_by_bootstrap(self):
        ec2_text = EC2.read_text(encoding="utf-8")
        bootstrap_text = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("--reconfigure", ec2_text)
        self.assertIn('INSTALLER_ARGS=("$@")', bootstrap_text)
        self.assertIn('"${INSTALLER_ARGS[@]}"', bootstrap_text)

    def test_existing_password_is_preserved_during_recovery(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn("Существующий пароль администратора будет сохранён", text)
        self.assertIn("Обновляю домен и Reality-параметры", text)

    def test_purge_uses_safe_working_directory_and_english_confirmation(self):
        text = PURGE.read_text(encoding="utf-8")
        self.assertIn("cd /", text)
        self.assertIn("DELETE ALL", text)
        self.assertIn("wait_for_package_manager", text)

    def test_readme_documents_recovery(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("незавершённое состояние", text)
        self.assertIn("--reconfigure", text)


if __name__ == "__main__":
    unittest.main()

class RC5ServicePermissionsTest(unittest.TestCase):
    def test_web_service_can_write_managed_nginx_files(self):
        root = Path(__file__).parents[1]
        text = (root / "deploy" / "install-service.sh").read_text(encoding="utf-8")
        self.assertIn("/etc/nginx", text)
        self.assertIn("/var/www/sg-panel-placeholder", text)

    def test_upgrade_installs_wgcf_helper_without_breaking_panel_upgrade(self):
        root = Path(__file__).parents[1]
        text = (root / "install-or-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("deploy/install-wgcf-cli.sh", text)
        self.assertIn("WARNING: wgcf-cli was not installed", text)
