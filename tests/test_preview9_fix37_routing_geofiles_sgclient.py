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
        "Выбранная конфигурация",
        "Пользовательские правила",
        "Базовая схема",
        "Фактические правила текущей схемы",
    ):
        assert marker in routing
    assert 'data-r096-tab="' not in routing
    assert "{% include '_geofiles_panel_fix39.html' %}" in geofiles
    assert "Безопасная проверка:" in panel
    assert "category-ads-all" not in panel
    assert "Global Jade / Routing / Vision Hotfix 4" in css
    assert "routing-sgclient096-fix39.css" in read("xpanel/templates/base.html")


def test_geofiles_actions_use_unified_rc80_planner() -> None:
    web = read("xpanel/web.py")
    base = read("xpanel/templates/base.html")
    template = read("xpanel/templates/routing_unified_planner_preview4.html")
    assert "def routing_unified_planner_preview4_page" in web
    assert '"routing_unified_planner_preview4.html"' in web
    assert "routing_unified_planner_preview4_page" in base
    assert "GeoFiles" in template


def test_transactional_roscom_contract_is_visible_and_preserved() -> None:
    routing = read("xpanel/templates/routing.html")
    geofiles = read("xpanel/templates/_geofiles_panel_fix39.html")
    service = read("xpanel/service.py")
    combined = routing + geofiles
    for marker in (
        "protobuf",
        "необязательный Block",
        "Совместимая серверная основа обязательна",
        "Безопасная проверка:",
    ):
        assert marker in combined
    assert "category-ads-all" not in combined
    for marker in (
        "Оба файла всегда загружаются, проверяются и применяются вместе",
        "полный future Routing/Xray config",
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
