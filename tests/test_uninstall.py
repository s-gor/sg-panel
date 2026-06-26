from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNINSTALL = ROOT / "deploy" / "uninstall.sh"
PURGE = ROOT / "deploy" / "purge-test-server.sh"
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

    def test_readme_describes_safe_default(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("безопасно по умолчанию", text)
        self.assertIn("docs/UNINSTALL.md", text)
        self.assertNotIn("uninstall-sg-panel.sh --purge-all --yes", text)


if __name__ == "__main__":
    unittest.main()
