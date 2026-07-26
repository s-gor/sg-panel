from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_routing_and_geofiles_keep_sgclient096_contract_without_duplicate_tabs() -> None:
    routing = read("xpanel/templates/routing.html")
    geofiles = read("xpanel/templates/geofiles.html")
    panel = read("xpanel/templates/_geofiles_panel_fix39.html")
    css = read("xpanel/static/fix40-global-jade-routing-vision-hotfix4.css")
    for marker in (
        "Весь остальной трафик",
        "Пользовательские правила",
        "Только включённый реальный Outbound",
    ):
        assert marker in routing
    assert 'data-r096-tab="' not in routing
    assert "{% include '_geofiles_panel_fix39.html' %}" in geofiles
    assert "category-ads-all" in panel
    assert "Global Jade / Routing / Vision Hotfix 4" in css
    assert "routing-sgclient096-fix39.css" in read("xpanel/templates/base.html")


def test_geofiles_is_standalone_and_actions_return_to_it() -> None:
    base = read("xpanel/templates/base.html")
    web = read("xpanel/web.py")
    assert '>GeoFiles</a>' not in base
    assert 'render_template(\n            "geofiles.html"' in web
    assert 'return redirect(url_for("routing_page") + "#geofiles")' not in web
    assert web.count('return redirect(url_for("geofiles_page"))') >= 3


def test_transactional_roscom_contract_is_visible_and_preserved() -> None:
    routing = read("xpanel/templates/routing.html")
    geofiles = read("xpanel/templates/_geofiles_panel_fix39.html")
    service = read("xpanel/service.py")
    combined = routing + geofiles
    for marker in (
        "protobuf",
        "category-ads-all",
        "необязательный Block",
        "Совместимая серверная основа обязательна",
    ):
        assert marker in combined
    for marker in (
        "Оба файла всегда загружаются, проверяются и применяются вместе",
        "полный будущий Routing и полный Xray config",
        "xray run -test",
        "Rollback считается успешным",
        "Построить совместимую серверную основу",
    ):
        assert marker in geofiles
    for marker in (
        "_read_geofile_categories",
        "_detect_geofiles_family",
        "_routing_geo_reference_details",
        "_prepare_geofiles_candidate",
        "_restore_routing_state",
        "prune_geofiles_storage",
    ):
        assert marker in service


def test_no_gateway_architecture_or_generic_vpn_is_imported() -> None:
    template = read("xpanel/templates/routing.html")
    service = read("xpanel/service.py")
    assert "SG_GATEWAY_" not in template
    assert "/opt/sg-gateway" not in template
    assert "Direct / VPN / Block" not in template
    assert '"vpn"' not in template.lower()
    assert "routing_outbound_options" in service
    assert "queue_node_geofiles_apply" in service


def test_fix36_vision_and_device_contracts_remain_packaged() -> None:
    settings = read("xpanel/templates/settings.html")
    db = read("xpanel/db.py")
    service = read("xpanel/service.py")
    for marker in ("ML-KEM-768", "XTLS Vision", "stream-one", "Server mode"):
        assert marker in settings
    assert "CREATE TABLE IF NOT EXISTS devices" in db
    assert "CREATE TABLE IF NOT EXISTS device_credentials" in db
    assert "device_id" in service
