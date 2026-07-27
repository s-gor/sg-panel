from pathlib import Path

from xpanel.db import connect, init_db
from xpanel import service

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_routing_ui_is_server_scoped_and_has_no_synthetic_vpn_target() -> None:
    template = read("xpanel/templates/routing.html")
    assert "{% block section %}ROUTING{% endblock %}" in template
    assert "реально существующие Outbounds" in template
    assert "полного Xray candidate" in template
    assert "Базовая схема" in template
    assert "routing_outbound_options" in read("xpanel/web.py")
    assert "generic or synthetic \"VPN\"" in read("xpanel/service.py")
    assert "Direct / VPN / Block" not in template


def test_real_outbound_catalog_contains_only_system_targets_on_clean_db(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    options = service.routing_outbound_options(enabled_only=True)
    assert [item["tag"] for item in options] == ["direct", "blocked"]
    assert [item["label"] for item in options] == ["Direct", "Block"]
    assert all(item["configured"] for item in options)
    assert not any(item["tag"].lower() == "vpn" for item in options)


def test_roscomvpn_preset_uses_only_present_categories_and_explicit_block(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    monkeypatch.setattr(
        service,
        "get_geofiles_overview",
        lambda: {
            "active_label": "RoscomVPN",
            "active_analysis": {
                "family": "RoscomVPN",
                "error": "",
                "geosite_categories": [
                    "private", "whitelist", "category-ru", "apple", "category-ads"
                ],
                "geoip_categories": ["private", "direct"],
            },
        },
    )

    result = service.apply_active_roscomvpn_server_preset(enable_block=False)
    assert result["final_outbound"] == "direct"
    assert result["block_enabled"] is False
    with connect() as con:
        direct = con.execute(
            "SELECT outbound_tag,domains,ips,enabled,managed_by,managed_role FROM routing_rules WHERE name=?",
            (service.ROSCOMVPN_DIRECT_RULE,),
        ).fetchone()
        blocked = con.execute(
            "SELECT outbound_tag,domains,enabled,managed_by,managed_role FROM routing_rules WHERE name=?",
            (service.ROSCOMVPN_BLOCK_RULE,),
        ).fetchone()
        final = con.execute(
            "SELECT default_outbound_tag FROM routing_settings WHERE id=1"
        ).fetchone()[0]
    assert direct["outbound_tag"] == "direct"
    assert direct["enabled"] == 1
    assert direct["managed_by"] == "roscomvpn-server-preset"
    assert direct["managed_role"] == "direct"
    assert direct["domains"].splitlines() == [
        "geosite:private", "geosite:whitelist", "geosite:category-ru", "geosite:apple"
    ]
    assert direct["ips"].splitlines() == ["geoip:private", "geoip:direct"]
    assert "geosite:microsoft" not in direct["domains"]
    assert blocked["outbound_tag"] == "blocked"
    assert blocked["domains"] == "geosite:category-ads"
    assert blocked["enabled"] == 0
    assert blocked["managed_by"] == "roscomvpn-server-preset"
    assert blocked["managed_role"] == "block"
    assert final == "direct"

    result = service.apply_active_roscomvpn_server_preset(enable_block=True)
    assert result["block_enabled"] is True
    with connect() as con:
        assert con.execute(
            "SELECT enabled FROM routing_rules WHERE name=?",
            (service.ROSCOMVPN_BLOCK_RULE,),
        ).fetchone()[0] == 1


def test_rule_overview_marks_missing_outbound_without_rewriting_rule(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            "INSERT INTO routing_rules (name,priority,enabled,outbound_tag,domains,target_type) "
            "VALUES ('Keep me',25,0,'removed-outbound','domain:example.com','outbound')"
        )
    rows = service.routing_rules_overview()
    row = next(item for item in rows if item["name"] == "Keep me")
    assert row["outbound_tag"] == "removed-outbound"
    assert row["domains"] == "domain:example.com"
    assert row["route"]["kind"] == "unavailable"
    assert row["route"]["label"] == "Недоступен · removed-outbound"


def test_rule_overview_marks_disabled_outbound_unavailable(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO outbounds
                (name,tag,address,port,uuid,flow,security,server_name,public_key,short_id,
                 fingerprint,network,xhttp_mode,xhttp_path,enabled)
            VALUES
                ('Disabled exit','disabled-exit','203.0.113.9',443,
                 '11111111-1111-1111-1111-111111111111','',
                 'reality','example.com','public-key','abcd','firefox','raw','auto','/',0)
            """
        )
        con.execute(
            "INSERT INTO routing_rules (name,priority,enabled,outbound_tag,domains,target_type) "
            "VALUES ('Keep disabled',26,0,'disabled-exit','domain:disabled.example','outbound')"
        )
    rows = service.routing_rules_overview()
    row = next(item for item in rows if item["name"] == "Keep disabled")
    assert row["domains"] == "domain:disabled.example"
    assert row["route"]["kind"] == "unavailable"
    assert row["route"]["type_label"] == "DISABLED"
    assert row["route"]["configured"] is True


def test_roscomvpn_uses_only_the_geofiles_transaction_path() -> None:
    template = read("xpanel/templates/routing.html")
    geofiles = read("xpanel/templates/_geofiles_panel_fix39.html")
    web = read("xpanel/web.py")
    assert "routing_roscomvpn_preset_apply" not in template
    assert "Совместимая серверная основа обязательна" in geofiles
    assert "RoscomVPN теперь проверяется и применяется только" in web


def test_roscomvpn_preset_never_overwrites_same_named_user_rule(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            "INSERT INTO routing_rules (name,priority,enabled,outbound_tag,domains,target_type) "
            "VALUES (?,50,1,'direct','domain:user.example','outbound')",
            (service.ROSCOMVPN_DIRECT_RULE,),
        )
    monkeypatch.setattr(
        service,
        "get_geofiles_overview",
        lambda: {
            "active_label": "RoscomVPN",
            "active_analysis": {
                "family": "RoscomVPN",
                "error": "",
                "geosite_categories": ["private", "category-ru"],
                "geoip_categories": ["private"],
            },
        },
    )
    try:
        service.apply_active_roscomvpn_server_preset(enable_block=False)
    except service.XPanelError as exc:
        assert "не принадлежит серверному preset" in str(exc)
    else:
        raise AssertionError("preset must reject a same-named user rule")
    with connect() as con:
        row = con.execute(
            "SELECT priority,outbound_tag,domains,managed_by FROM routing_rules WHERE name=?",
            (service.ROSCOMVPN_DIRECT_RULE,),
        ).fetchone()
    assert row["priority"] == 50
    assert row["outbound_tag"] == "direct"
    assert row["domains"] == "domain:user.example"
    assert row["managed_by"] == ""


def test_roscomvpn_without_block_categories_does_not_create_empty_rule(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    monkeypatch.setattr(
        service,
        "get_geofiles_overview",
        lambda: {
            "active_label": "Custom",
            "active_analysis": {
                "family": "Custom",
                "error": "",
                "geosite_categories": ["private"],
                "geoip_categories": ["private"],
            },
        },
    )
    result = service.apply_active_roscomvpn_server_preset(enable_block=True)
    assert result["block_domains"] == []
    assert result["block_enabled"] is False
    with connect() as con:
        assert con.execute(
            "SELECT COUNT(*) FROM routing_rules WHERE name=?",
            (service.ROSCOMVPN_BLOCK_RULE,),
        ).fetchone()[0] == 0


def test_fix33_database_migrates_managed_rule_columns(tmp_path, monkeypatch) -> None:
    import sqlite3

    database = tmp_path / "fix33-panel.db"
    with sqlite3.connect(database) as con:
        con.execute(
            """
            CREATE TABLE routing_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 100,
                enabled INTEGER NOT NULL DEFAULT 1,
                outbound_tag TEXT NOT NULL DEFAULT 'direct',
                domains TEXT NOT NULL DEFAULT '',
                ips TEXT NOT NULL DEFAULT '',
                ports TEXT NOT NULL DEFAULT '',
                network TEXT NOT NULL DEFAULT '',
                protocols TEXT NOT NULL DEFAULT '',
                inbound_tags TEXT NOT NULL DEFAULT '',
                users TEXT NOT NULL DEFAULT '',
                target_type TEXT NOT NULL DEFAULT 'outbound',
                config_json TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        before = {row[1] for row in con.execute("PRAGMA table_info(routing_rules)")}
    assert "managed_by" not in before
    assert "managed_role" not in before

    monkeypatch.setenv("XPANEL_DB", str(database))
    init_db()
    with sqlite3.connect(database) as con:
        after = {row[1] for row in con.execute("PRAGMA table_info(routing_rules)")}
        defaults = {
            row[1]: row[4] for row in con.execute("PRAGMA table_info(routing_rules)")
        }
    assert {"managed_by", "managed_role"} <= after
    assert defaults["managed_by"] == "''"
    assert defaults["managed_role"] == "''"
