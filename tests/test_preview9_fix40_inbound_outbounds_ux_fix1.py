from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def test_xray_server_is_explicitly_inbound() -> None:
    page = read("xpanel/templates/settings.html")
    assert "{% block heading %}Входящие подключения{% endblock %}" in page
    assert "Клиент → SG-Panel" in page
    assert "Четыре канала подключения" in page
    assert "Все доступные каналы" not in page

def test_direct_block_and_warp_share_one_system_section() -> None:
    page = read("xpanel/templates/outbounds.html")
    system_start = page.index('class="ob-system-panel ob-unified-system-panel"')
    user_start = page.index('class="ob-user-outputs-panel"')
    system = page[system_start:user_start]
    assert "Direct — прямой доступ" in system
    assert "Block — блокировка" in system
    assert "WARP — Cloudflare" in system
    assert "ob-warp-system-row" in system
    assert '<section class="warp-panel"' not in page
    assert "Пользовательские выходы" in page

def test_new_stylesheet_is_scoped_and_loaded_last() -> None:
    base = read("xpanel/templates/base.html")
    css = read("xpanel/static/fix40-inbound-outbounds-ux-fix1.css")
    assert base.index("fix40-ui-remaining-fix2.css") < base.index("fix40-inbound-outbounds-ux-fix1.css")
    assert "inbound-outbounds-ux-fix1" in base
    assert "body.server-settings-page" in css
    assert "body.outbounds-page" in css
    assert ".topbar-heading h1" not in css

def test_warp_management_remains_functional_without_backend_change() -> None:
    page = read("xpanel/templates/outbounds.html")
    for endpoint in ("warp_create", "warp_test", "warp_regenerate", "warp_toggle", "warp_delete", "warp_json_page"):
        assert endpoint in page
