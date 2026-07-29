from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def test_xray_server_is_explicitly_inbound() -> None:
    template = read("xpanel/templates/settings.html")
    assert "{% block heading %}Connections{% endblock %}" in template
    assert "Reality TCP · XHTTP Reality · XHTTP TLS · Hysteria 2" in template
    assert "<h2>Xray Server</h2>" in template
    assert "Клиент → SG-Panel" in template
    for profile in (
        "VLESS Reality TCP",
        "VLESS XHTTP Reality",
        "VLESS XHTTP TLS",
        "Hysteria 2",
    ):
        assert profile in template
def test_direct_block_and_warp_share_one_system_section() -> None:
    template = read("xpanel/templates/outbounds.html")
    assert "outbounds-gateway-style2" in template
    assert "System outbounds" in template
    assert "WARP Outbound" in template
    assert "Custom outbounds" in template
    assert template.index("System outbounds") < template.index("WARP Outbound") < template.index("Custom outbounds")
    assert "ob-unified-system-panel" not in template
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
