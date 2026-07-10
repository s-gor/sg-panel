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

def test_latte_palette_and_name():
    css = read("xpanel/static/app.css")
    base = read("xpanel/templates/base.html")
    login = read("xpanel/templates/login.html")
    assert "SG-Panel RC70 — Latte light theme preview" in css
    for token in ("--bg:#D8CEC2", "--panel:#EEE6DC", "--text:#2A2723", "--accent:#2F7A62", "background:linear-gradient(180deg,#624B39,#49372A)"):
        assert token in css
    assert "<b>Латте</b>" in base
    assert "Тема Латте" in login

def test_dark_graphite_root_palette_is_untouched():
    css = read("xpanel/static/app.css")
    assert "--bg: #0d131b;" in css
    assert "--panel: #17212e;" in css
