from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(text: str) -> str:
    return "".join(text.split())


def test_hotfix14_restores_shared_routing_workspace_and_insets_inner_sections():
    routing = (ROOT / "xpanel/templates/routing.html").read_text(encoding="utf-8")
    css = compact((ROOT / "xpanel/static/app.css").read_text(encoding="utf-8"))

    assert "document.body.classList.add('ui-standard-page','routing-page')" in routing
    assert 'class="routing-table-shell"' in routing
    assert ".rc20-awg-shell.routing-page.ui-page-wide{" in css
    assert "width:min(1540px,100%);max-width:1540px;" in css
    assert ".routing-page.geo-policy-form{padding:18px20px18px;}" in css
    assert ".routing-page.routing-table-shell{min-width:0;padding:020px18px;}" in css
    assert ".routing-page.routing-table-shell>.table-wrap{margin:0;border:1pxsolidvar(--border);border-radius:10px;overflow-x:auto;}" in css
    assert "width:min(1440px,100%)" not in css


def test_hotfix14_bumps_cache_and_installer_validation():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "RC46 Preview 3 Hotfix 14" in css
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert 'grep -q "SG-Panel RC70 — Latte light theme preview"' in installer
