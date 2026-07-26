from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def test_rc68_version_and_ui_revision():
    assert '__version__ = "0.10.0-rc70"' in read("xpanel/__init__.py")
    assert "sg070" in read("xpanel/templates/base.html")
    assert "sg070" in read("xpanel/templates/login.html")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_UI_REVISION="sg070"' in read("install-or-upgrade.sh")

def test_luxury_jade_palette_and_name():
    legacy_css = read("xpanel/static/app.css")
    jade = read("xpanel/static/luxury-jade-depth.css")
    base = read("xpanel/templates/base.html")
    login = read("xpanel/templates/login.html")
    assert "SG-Panel RC70 — Latte light theme preview" in legacy_css
    for token in ("--jade-page: #E5ECE7", "--jade-ivory-top: #FEFCF7", "--jade-text: #29312C", "--jade-accent: #456F5C", "--jade-champagne: #B88A45"):
        assert token in jade
    assert "<b>SG Luxury Jade Depth</b>" in base
    assert "Тема SG Luxury Jade Depth" in login

def test_dark_graphite_root_palette_is_untouched():
    css = read("xpanel/static/app.css")
    assert "--bg: #0d131b;" in css
    assert "--panel: #17212e;" in css
