from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install-or-upgrade.sh"


def test_fresh_install_storage_preflight_uses_existing_parent():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "SG_PANEL_FRESH_INSTALL_STORAGE_FIX1" in text
    assert 'disk_check_path="$TARGET"' in text
    assert 'disk_check_path="$(dirname -- "$TARGET")"' in text
    assert '[[ -e "$disk_check_path" ]] || disk_check_path="/"' in text
    assert "$disk_check_path" in text


def test_fresh_install_storage_fix_keeps_target_identity():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'TARGET="/opt/xpanel-mvp"' in text
