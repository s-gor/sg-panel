from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(text: str) -> str:
    return "".join(text.split())


def test_hotfix17_security_uses_full_width_standard_cards():
    html = (ROOT / "xpanel/templates/security.html").read_text(encoding="utf-8")
    css = compact((ROOT / "xpanel/static/app.css").read_text(encoding="utf-8"))

    assert 'class="ui-card security-status-card security-status-card-wide"' in html
    assert 'class="security-checks security-checks-grid"' in html
    assert 'class="ui-form security-settings-stack"' in html
    assert html.count('class="ui-card security-settings-card') == 2
    assert 'class="ui-top-grid security-main-grid"' not in html
    assert 'class="security-subscription-options"' in html

    assert ".security-page.ui-page-wide{width:min(1540px,100%);max-width:1540px;" in css
    assert ".security-status-card-wide.security-checks-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));" in css
    assert ".security-status-support{display:grid;grid-template-columns:minmax(0,1.35fr)minmax(330px,.65fr);" in css
    assert ".security-subscription-options{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));" in css


def test_hotfix17_keeps_technical_terms_in_english():
    html = (ROOT / "xpanel/templates/security.html").read_text(encoding="utf-8")

    for term in (
        "Public access",
        "Panel backend",
        "IP allowlist",
        "Listen",
        "Secure cookie",
        "Panel IP allowlist",
        "Allowed IP/CIDR",
        "Trust X-Forwarded-For",
        "Plain format",
        "JSON format",
        "Subscription IP allowlist",
        "Allowed subscription networks",
    ):
        assert term in html

    assert "Разрешить plain-формат" not in html
    assert "Разрешить JSON-формат" not in html


def test_hotfix17_cache_revision_and_installer_guard():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "SG-Panel 054" in css
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert 'grep -q "SG-Panel RC70 — Latte light theme preview"' in installer
    assert "GUI не подключает CSS SG-Panel RC70" in installer
