from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hotfix19_history_tables_have_inner_shells_and_scroll_classes():
    template = (ROOT / "xpanel/templates/security.html").read_text(encoding="utf-8")
    assert template.count('class="ui-card ui-table-card security-history-card"') == 2
    assert template.count('class="security-history-table-shell"') == 2
    assert template.count('class="table-wrap security-history-scroll"') == 2
    assert 'class="security-login-table"' in template
    assert 'class="security-audit-table"' in template


def test_hotfix19_css_limits_each_history_to_four_rows_with_frame():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "SG-Panel 054" in css
    assert ".security-history-table-shell" in css
    assert "border: 1px solid var(--line-soft);" in css
    assert "max-height: 308px; /* 44px header + four 66px rows */" in css
    assert "overflow-y: auto;" in css
    assert "height: 66px;" in css
    assert "min-width: 0;" in css


def test_hotfix19_cache_revision_and_installer_guard():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert "SG-Panel RC70" in installer
