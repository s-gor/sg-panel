from __future__ import annotations

from pathlib import Path

import pytest

from xpanel.db import connect, init_db
from xpanel import service

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def add_real_outbound(tag: str, *, enabled: bool = True) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO outbounds
                (name,tag,address,port,uuid,flow,security,server_name,public_key,short_id,
                 fingerprint,network,xhttp_mode,xhttp_path,enabled)
            VALUES
                (?,?,'203.0.113.10',443,
                 '11111111-1111-1111-1111-111111111111','xtls-rprx-vision',
                 'reality','example.com','public-key','abcd','firefox','raw','auto','/',?)
            """,
            ("Audit exit", tag, int(enabled)),
        )


def roscom_overview() -> dict[str, object]:
    return {
        "active_label": "RoscomVPN",
        "active_analysis": {
            "family": "RoscomVPN",
            "error": "",
            "geosite_categories": [
                "private", "whitelist", "category-ru", "apple", "category-ads"
            ],
            "geoip_categories": ["private", "direct"],
        },
    }


def test_roscomvpn_final_route_is_a_real_selected_outbound(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    add_real_outbound("audit-exit")
    monkeypatch.setattr(service, "get_geofiles_overview", roscom_overview)

    result = service.apply_active_roscomvpn_server_preset(
        enable_block=False,
        final_outbound_tag="audit-exit",
    )
    assert result["final_outbound"] == "audit-exit"
    with connect() as con:
        final = con.execute(
            "SELECT default_outbound_tag FROM routing_settings WHERE id=1"
        ).fetchone()[0]
        direct = con.execute(
            "SELECT outbound_tag,domains,ips FROM routing_rules WHERE name=?",
            (service.ROSCOMVPN_DIRECT_RULE,),
        ).fetchone()
    assert final == "audit-exit"
    assert direct["outbound_tag"] == "direct"
    assert "geosite:category-ru" in direct["domains"]
    assert "geoip:direct" in direct["ips"]


def test_roscomvpn_final_route_rejects_disabled_or_block_outbound(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    add_real_outbound("disabled-exit", enabled=False)
    monkeypatch.setattr(service, "get_geofiles_overview", roscom_overview)

    with pytest.raises(service.XPanelError, match="отсутствует или выключен"):
        service.apply_active_roscomvpn_server_preset(
            final_outbound_tag="disabled-exit"
        )
    with pytest.raises(service.XPanelError, match="Block нельзя"):
        service.apply_active_roscomvpn_server_preset(
            final_outbound_tag="blocked"
        )


def test_geofiles_check_freezes_the_exact_plan_before_apply() -> None:
    module = read("xpanel/unified_planner_preview4.py")
    assert "def validate_plan" in module
    assert "def apply_checked_plan" in module
    assert '"kind": "unified-routing-geofiles-xray"' in module
    assert "xray run -test" in module


def test_roscomvpn_can_be_validated_in_the_same_staging_flow() -> None:
    module = read("xpanel/unified_planner_preview4.py")
    assert 'if family == "RoscomVPN":' in module
    assert '("category-ru", "whitelist")' in module
    assert '("direct", "whitelist")' in module
    assert "def validate_plan" in module


def test_node_geofiles_is_two_phase_and_apply_requires_validation() -> None:
    service_text = read("xpanel/service.py")
    web = read("xpanel/web.py")
    worker = read("node_agent/sg_node_worker.py")
    for marker in (
        "def queue_node_geofiles_validate(",
        '"worker_operation": "stage_geofiles"',
        '"worker_operation": "validate_geofiles"',
        "def _node_geofiles_was_validated(",
        "сначала выполните «Проверить на Node»",
    ):
        assert marker in service_text
    assert '"/network/nodes/<int:node_id>/geofiles/validate"' in web
    assert "def stage_geofiles(" in worker
    assert "def validate_geofiles(" in worker


def test_fix38_ui_keeps_routing_and_geofiles_without_duplicate_tabs() -> None:
    routing = read("xpanel/templates/routing.html")
    geofiles = read("xpanel/templates/geofiles.html")
    base = read("xpanel/templates/base.html")
    css = read("xpanel/static/routing-sgclient096-fix39.css")
    assert 'data-r096-tab="' not in routing
    assert '_geofiles_panel_fix39.html' not in routing
    assert "{% include '_geofiles_panel_fix39.html' %}" in geofiles
    assert "routing-sgclient096-fix39.css" in base
    assert "SG-Panel FIX39 · SG Client 096 Routing" in css
    assert "Direct / VPN / Block" not in routing
    assert "remove_missing" not in routing
