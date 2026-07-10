from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(text: str) -> str:
    return "".join(text.split())


def test_hotfix16_reality_warning_has_vertical_air():
    css = compact((ROOT / "xpanel/static/app.css").read_text(encoding="utf-8"))
    selector = ".inbound-settings-form>.ui-form-section.is-last-visible-profile-section.reality-multi-panel>.ui-warning-note:last-child"
    assert selector + "{margin-top:16px;margin-bottom:14px;}" in css
    assert ".inbound-settings-form>.validation-gate{margin-top:0;}" in css


def test_hotfix16_cache_revision_and_installer_guard():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "RC46 Preview 3 Hotfix 16" in css
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert 'grep -q "SG-Panel RC70 — Latte light theme preview"' in installer
    assert "GUI не подключает CSS SG-Panel RC70" in installer
