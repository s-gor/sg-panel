from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def wrapper() -> str:
    return (ROOT / "SG-PANEL-UI23-CAP6-FULL-CLEAN.run").read_text(
        encoding="utf-8"
    )


def test_full_wrapper_validates_downloads_before_installing():
    text = wrapper()
    assert "download_file()" in text
    assert "--retry-all-errors" in text
    assert 'bash -n "$CORE_INSTALLER"' in text
    assert 'python3 -m zipfile -t "$SOURCE_ZIP"' in text
    assert text.index('bash -n "$CORE_INSTALLER"') < text.index(
        'log "Подготовка постоянной защиты прав GeoFiles..."'
    )


def test_full_wrapper_has_no_duplicate_service_restarts():
    text = wrapper()
    tail = text.split('bash "$CORE_INSTALLER" --source-zip "$SOURCE_ZIP"', 1)[1]
    assert "systemctl restart xray" not in tail
    assert "systemctl restart xpanel-web" not in tail
    assert 'wait_for_service_active xray "Xray"' in tail
    assert 'wait_for_service_active xpanel-web "SG-Panel"' in tail
    assert 'wait_for_service_active nginx "Nginx"' in tail


def test_full_wrapper_is_pinned_and_checks_the_real_panel_endpoint():
    text = wrapper()
    assert re.search(r'^COMMIT="[0-9a-f]{40}"$', text, re.MULTILINE)
    assert "verify_panel_endpoint()" in text
    assert "grep -Fq FIX40" in text
