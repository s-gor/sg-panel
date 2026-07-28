from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")

def test_final_vmware_menu_order_and_labels():
    base = read("xpanel/templates/base.html")
    expected = [
        "<b>System</b>",
        "<b>Clients</b>",
        "<b>Security</b>",
        "<b>Connections</b>",
        "<b>Outbounds</b>",
        "<b>Routing</b>",
        "<b>Cluster</b>",
        "<b>Cascade</b>",
        "<b>DNS</b>",
        "<b>Maintenance</b>",
        "<b>Help</b>",
        "<b>Expert</b>",
    ]
    positions = [base.index(x) for x in expected]
    assert positions == sorted(positions)
    assert "<b>Connections</b><small>Xray · Vision · Hysteria 2</small>" in base
    assert "<b>Outbounds</b><small>Direct · Block · WARP</small>" in base

def test_connections_naming_keeps_four_profiles():
    settings = read("xpanel/templates/settings.html")
    assert "{% block title %}Connections — SG-Panel{% endblock %}" in settings
    assert "{% block section %}CONNECTIONS{% endblock %}" in settings
    assert "{% block heading %}Connections{% endblock %}" in settings
    assert "Reality TCP · XHTTP Reality · XHTTP TLS · Hysteria 2" in settings
    assert "<h2>Xray Server</h2>" in settings
    for profile in (
        "VLESS Reality TCP",
        "VLESS XHTTP Reality",
        "VLESS XHTTP TLS",
        "Hysteria 2",
    ):
        assert profile in settings

def test_outbounds_gateway_style_is_loaded_and_scoped():
    base = read("xpanel/templates/base.html")
    outbounds = read("xpanel/templates/outbounds.html")
    css = read("xpanel/static/fix40-outbounds-gateway-style2.css")
    assert "fix40-outbounds-gateway-style2.css" in base
    assert "outbounds-gateway-style2" in outbounds
    assert "System outbounds" in outbounds
    assert "WARP Outbound" in outbounds
    assert "Маршрутизация настраивается отдельно" in outbounds
    assert "Custom outbounds" in outbounds
    assert "Outbounds Gateway Style 2" in css
