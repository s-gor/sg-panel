from __future__ import annotations

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
        "preset": "all_warp",
        "local_action": "direct",
        "russia_scope": "none",
        "russia_action": "direct",
        "blocked_action": "blocked",
        "ads_action": "blocked",
        "default_action": "warp",
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


def enable_warp(monkeypatch) -> None:
    monkeypatch.setattr(
        service,
        "get_warp_overview",
        lambda: {"configured": True, "enabled": True},
    )


def test_all_warp_applies_without_optional_block_or_ads_categories(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    enable_warp(monkeypatch)
    monkeypatch.setattr(service, "get_geofiles_overview", lambda: geofiles())

    result = service.apply_unified_routing(**values())

    assert result["preset"] == "all_warp"
    assert result["default_outbound_tag"] == "warp"
    assert len(result["warnings"]) == 2
    with connect() as con:
        assert con.execute(
            "SELECT default_outbound_tag FROM routing_settings WHERE id=1"
        ).fetchone()[0] == "warp"
        roles = {
            row[0]
            for row in con.execute(
                "SELECT managed_role FROM routing_rules WHERE managed_by=?",
                (service.UNIFIED_ROUTING_MANAGED_BY,),
            )
        }
    assert "local" in roles
    assert "blocked" not in roles
    assert "ads" not in roles


def test_category_specific_presets_remain_strict(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    enable_warp(monkeypatch)
    monkeypatch.setattr(service, "get_geofiles_overview", lambda: geofiles())
    with pytest.raises(service.XPanelError, match="заблокированных ресурсов"):
        service.apply_unified_routing(**values(preset="blocked_warp"))


def test_final_system_replaces_experimental_layers_and_labels_current_vs_selected() -> None:
    base = read("xpanel/templates/base.html")
    routing = read("xpanel/templates/routing.html")
    css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    assert "fix40-ui23-repair4-final-system1.css" in base
    assert "fix40-global-buttons-preview3-outline.css" not in base
    assert "routing-unified-final-gateway-grid.css" not in base
    assert "СЕЙЧАС РАБОТАЕТ" in routing
    assert "ВЫБРАНО В ФОРМЕ" in routing
    assert "Схема не применена" in base
    assert "Direct · WARP · Block" in routing
    assert "position:static !important" in css
