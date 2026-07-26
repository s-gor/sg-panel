from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_logs_page_uses_closed_component_panels() -> None:
    html = (ROOT / "xpanel/templates/diagnostics.html").read_text(encoding="utf-8")
    assert "Служебные сообщения" in html
    assert "Один журнал за раз" not in html
    assert "diagnosticLogSelect" not in html
    for target in (
        "diagnostic-log-xray",
        "diagnostic-log-nginx",
        "diagnostic-log-panel",
        "diagnostic-log-ports",
        "diagnostic-log-config",
    ):
        assert f'id="{target}"' in html
    assert html.count('class="diagnostic-log-panel"') == 5


def test_maintenance_exposes_full_verified_restore() -> None:
    html = (ROOT / "xpanel/templates/backups.html").read_text(encoding="utf-8")
    assert "Полное безопасное восстановление" in html
    assert "Восстановить полностью" in html
    assert "автоматический откат" in html
    assert "backups_verify" in html
    assert "Восстановить DB" not in html


def test_restore_service_verifies_applies_and_rolls_back() -> None:
    service = (ROOT / "xpanel/service.py").read_text(encoding="utf-8")
    assert "def verify_backup" in service
    assert 'con.execute("PRAGMA integrity_check")' in service
    assert "validation = validate_generated_config()" in service
    assert "safety = create_backup()" in service
    assert "applied = apply_config()" in service
    assert "предыдущее рабочее состояние автоматически возвращено" in service


def test_installer_spinner_is_explicitly_green() -> None:
    script = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    assert "COLOR_GREEN=$'\\033[1;32m'" in script
    assert '"$COLOR_GREEN" "${frames:frame_index%4:1}" "$COLOR_RESET"' in script
    assert "[SG-Panel] [%sOK%s]" in script
