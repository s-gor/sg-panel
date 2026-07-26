from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_clients_page_uses_same_wide_shell_as_network():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)

    assert "'ui-standard-page','clients-studio-page','clients-network-scale'" in html
    assert '<div class="ui-page ui-page-wide clients-page-shell clients-awg-page">' in html
    assert html.index('clients-page-shell') < html.index('clients-awg-filter-panel')
    assert html.index('clients-awg-master-detail') < html.index('<dialog id="add-client-dialog"')

    assert ".rc20-awg-shell.clients-studio-page.clients-page-shell{width:min(1540px,100%);max-width:1540px;" in packed
    assert "body.clients-studio-page.clients-page-shell>.clients-summary-grid" in packed
    assert "width:100%;max-width:none;margin:0;" in packed


def test_clients_controls_cards_and_table_have_network_scale():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)

    assert ".clients-network-scale.clients-studio-toolbar{min-height:86px;" in packed
    assert ".clients-network-scale.clients-summary-grid{grid-template-columns:repeat(4,minmax(0,1fr));" in packed
    assert ".clients-network-scale.clients-filter-panelinput" in packed
    assert ".clients-network-scale.clients-studio-table{min-width:1080px;" in packed
    assert ".clients-network-scale.client-avatar{width:42px;height:42px;" in packed
    assert ".clients-network-scale.client-action{min-height:36px;" in packed


def test_hotfix9_cache_and_installer_revision():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in script
    assert "SG-Panel RC70" in script
    assert "GUI не подключает CSS SG-Panel RC70" in script
