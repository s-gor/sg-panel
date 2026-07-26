from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def test_outer_full_success_is_exact_three_service_lines():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    success = _section(text, "show_result(){", "\n}\n\nmain(){")
    assert success.count("%sactive%s") == 3
    assert "Полный журнал:" not in success
    assert "Журнал внутренней установки:" not in success
    assert "Резервная копия:" not in success
    assert "ЖУРНАЛ" not in success
    assert "ПАНЕЛЬ" not in success


def test_full_ec2_suppresses_nested_updater_summary():
    text = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    assert 'SG_PANEL_SUPPRESS_SUCCESS_SUMMARY=1 bash "$SOURCE_DIR/install-or-upgrade.sh"' in text
    tail = text.split('ACTIVE_XRAY_VERSION=', 1)[1]
    assert tail.count("%sactive%s") == 3
    assert "ЖУРНАЛ" not in tail
    assert "Резервная копия:" not in tail


def test_standalone_updater_has_three_lines_and_nested_guard():
    text = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    success = text.split("ROLLBACK_NEEDED=0", 1)[1]
    assert 'SG_PANEL_SUPPRESS_SUCCESS_SUMMARY:-0' in success
    assert success.count("%sactive%s") == 3
    assert "Резервная копия:" not in success
    assert "[SG-Panel] Журнал:" not in success


def test_failure_paths_keep_log_locations():
    full = (ROOT / "install.sh").read_text(encoding="utf-8")
    updater = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "Полный журнал: %s" in full
    assert "Журнал внутренней установки: %s" in full
    assert "Полный журнал: %s" in updater
