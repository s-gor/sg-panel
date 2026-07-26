from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNINSTALL = ROOT / "deploy" / "uninstall.sh"
PURGE = ROOT / "deploy" / "purge-test-server.sh"
FULL_UNINSTALL = ROOT / "deploy" / "full-uninstall.sh"
ROOT_FULL_UNINSTALL = ROOT / "FULL-UNINSTALL-SG-PANEL.sh"
README = ROOT / "README.md"


class UninstallSafetyTest(unittest.TestCase):
    def test_safe_defaults_preserve_xray_and_backups(self):
        text = UNINSTALL.read_text(encoding="utf-8")
        self.assertIn("REMOVE_XRAY=0", text)
        self.assertIn("REMOVE_BACKUPS=0", text)
        self.assertIn("--remove-xray", text)
        self.assertIn("--remove-backups", text)

    def test_old_purge_all_is_refused(self):
        text = UNINSTALL.read_text(encoding="utf-8")
        self.assertIn("--purge-all", text)
        self.assertIn("Параметр --purge-all удалён", text)
        self.assertNotIn("PURGE_ALL=1", text)

    def test_full_purge_is_separate_and_explicit(self):
        text = PURGE.read_text(encoding="utf-8")
        self.assertIn("--destroy-test-server", text)
        self.assertIn("EXPLICIT_CONFIRM=0", text)


    def test_full_uninstall_is_noninteractive_and_explicit(self):
        text = FULL_UNINSTALL.read_text(encoding="utf-8")
        self.assertIn("ASSUME_YES=0", text)
        self.assertIn("--yes", text)
        self.assertNotIn("read -r -p", text)
        self.assertNotIn("Type DELETE", text)
        self.assertIn("Отказ: для полной очистки требуется параметр --yes", text)

    def test_full_uninstall_has_green_live_progress(self):
        text = FULL_UNINSTALL.read_text(encoding="utf-8")
        self.assertIn("COLOR_GREEN", text)
        self.assertIn("local frames='|/-\\\\'", text)
        self.assertIn("Этап 1/$TOTAL_STAGES", text)
        self.assertIn("Этап 7/$TOTAL_STAGES", text)
        self.assertIn("(%s сек)", text)

    def test_full_uninstall_removes_all_sg_panel_components(self):
        text = FULL_UNINSTALL.read_text(encoding="utf-8")
        for marker in (
            "/opt/xpanel-mvp",
            "/usr/local/bin/xray",
            "/usr/local/bin/wgcf-cli",
            "/etc/nginx",
            "/etc/letsencrypt",
            "/root/sg-panel-backups",
            "/swapfile",
            "/etc/sysctl.d/99-sg-panel-port.conf",
        ):
            self.assertIn(marker, text)
        self.assertIn("verify_removal", text)
        self.assertIn("SSH, сеть Ubuntu", text)

    def test_root_full_uninstall_matches_deploy_copy(self):
        self.assertEqual(
            ROOT_FULL_UNINSTALL.read_bytes(),
            FULL_UNINSTALL.read_bytes(),
        )

    def test_readme_describes_safe_default(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("безопасно по умолчанию", text)
        self.assertIn("docs/UNINSTALL.md", text)
        self.assertNotIn("uninstall-sg-panel.sh --purge-all --yes", text)


if __name__ == "__main__":
    unittest.main()
