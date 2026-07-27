from __future__ import annotations

import json
from pathlib import Path

import pytest

from xpanel import service
from xpanel.db import connect, init_db

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def geofiles(*, geosite: list[str] | None = None, geoip: list[str] | None = None) -> dict[str, object]:
    return {
        "active_label": "Test GeoFiles",
        "active_analysis": {
            "family": "Test",
            "error": "",
            "geosite_categories": geosite or [],
            "geoip_categories": geoip or [],
        },
    }


def values(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "preset": "custom",
        "local_action": "direct",
        "russia_scope": "none",
        "russia_action": "direct",
        "blocked_action": "direct",
        "ads_action": "direct",
        "default_action": "direct",
        "custom_direct_domains": "",
        "custom_direct_ips": "",
        "custom_warp_domains": "",
        "custom_warp_ips": "",
        "custom_block_domains": "",
        "custom_block_ips": "",
        "domain_strategy": "AsIs",
        "sniffing_enabled": True,
        "sniffing_route_only": True,
        "sniff_http": True,
        "sniff_tls": True,
        "sniff_quic": True,
    }
    result.update(overrides)
    return result


def test_unified_routing_page_uses_gateway_structure_without_gateway_runtime() -> None:
    routing = read("xpanel/templates/routing.html")
    base = read("xpanel/templates/base.html")
    css = read("xpanel/static/routing-unified-preview1.css")
    web = read("xpanel/web.py")
    service_text = read("xpanel/service.py")
    for marker in (
        "Выбранная конфигурация",
        "Базовая схема",
        "Российская маршрутизация",
        "Фактические правила текущей схемы",
        "Сохранить и применить",
    ):
        assert marker in routing
    assert "routing-unified-preview1.css" in base
    assert "Unified Routing Preview 1" in css
    assert '@app.post("/routing/unified")' in web
    assert "def apply_unified_routing" in service_text
    assert "UNIFIED_ROUTING_MANAGED_BY" in service_text
    assert "/opt/sg-gateway" not in routing


def test_unified_routing_preserves_manual_rules_and_stores_gui_metadata(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    monkeypatch.setattr(service, "get_geofiles_overview", lambda: geofiles())
    with connect() as con:
        con.execute(
            "INSERT INTO routing_rules (name,priority,enabled,outbound_tag,domains,target_type) "
            "VALUES ('Manual keep',55,1,'direct','domain:example.com','outbound')"
        )

    result = service.apply_unified_routing(**values())
    assert result["managed_rules"] == 1
    with connect() as con:
        names = {row[0] for row in con.execute("SELECT name FROM routing_rules")}
        extra = json.loads(
            con.execute("SELECT extra_json FROM routing_settings WHERE id=1").fetchone()[0]
        )
    assert "Manual keep" in names
    assert "Локальная сеть" in names
    assert extra["_sgPanel"][service.UNIFIED_ROUTING_META_KEY]["preset"] == "custom"
    assert "_sgPanel" not in service.get_routing_extra()


def test_ads_block_preset_creates_real_block_rule_and_enforces_preset_defaults(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    monkeypatch.setattr(
        service,
        "get_geofiles_overview",
        lambda: geofiles(geosite=["category-ads-all"], geoip=["private"]),
    )
    result = service.apply_unified_routing(
        **values(
            preset="ads_block",
            ads_action="direct",
            default_action="blocked",
        )
    )
    assert result["preset"] == "ads_block"
    with connect() as con:
        ads = con.execute(
            "SELECT outbound_tag,domains,managed_by FROM routing_rules WHERE managed_role='ads'"
        ).fetchone()
        default_tag = con.execute(
            "SELECT default_outbound_tag FROM routing_settings WHERE id=1"
        ).fetchone()[0]
    assert ads["outbound_tag"] == "blocked"
    assert ads["domains"] == "geosite:category-ads-all"
    assert ads["managed_by"] == service.UNIFIED_ROUTING_MANAGED_BY
    assert default_tag == "direct"


def test_russia_sites_and_ip_requires_exact_active_categories(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    monkeypatch.setattr(
        service,
        "get_geofiles_overview",
        lambda: geofiles(geosite=["tld-ru"], geoip=["private"]),
    )
    with pytest.raises(service.XPanelError, match="geosite:category-ru.*geoip:ru"):
        service.apply_unified_routing(
            **values(russia_scope="sites_ip", russia_action="direct")
        )


def test_local_network_cannot_be_sent_to_nonlocal_outbound(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    monkeypatch.setattr(service, "get_geofiles_overview", lambda: geofiles())
    with connect() as con:
        con.execute(
            """
            INSERT INTO outbounds
                (name,tag,address,port,uuid,flow,security,server_name,public_key,short_id,
                 fingerprint,network,xhttp_mode,xhttp_path,enabled)
            VALUES
                ('Custom exit','custom-exit','203.0.113.8',443,
                 '11111111-1111-1111-1111-111111111111','',
                 'reality','example.com','public-key','abcd','firefox','raw','auto','/',1)
            """
        )
    with pytest.raises(ValueError, match="только Direct или Block"):
        service.apply_unified_routing(
            **values(local_action="custom-exit", preset="custom")
        )
    # A fixed preset is authoritative and ignores contradictory posted values.
    result = service.apply_unified_routing(
        **values(local_action="custom-exit", preset="direct")
    )
    assert result["preset"] == "direct"


def test_unified_routing_initial_state_reflects_existing_configuration(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()

    # Existing rules without unified metadata must never be mislabeled as Direct.
    existing = service.get_unified_routing_model()
    assert existing["preset"] == "custom"
    assert existing["default_action"] == "direct"

    # Only a truly empty direct configuration can be represented as the Direct preset.
    monkeypatch.setattr(service, "list_routing_rules", lambda: [])
    clean = service.get_unified_routing_model()
    assert clean["preset"] == "direct"
    assert clean["default_action"] == "direct"
