from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "multi-reality-module")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from xpanel.db import connect, init_db
from xpanel.service import (
    add_user,
    build_config,
    get_server,
    list_reality_inbounds,
    make_links,
    update_server_settings,
    update_subscription_settings,
)
from xpanel.web import create_app


def _server_values(root: Path, **overrides):
    rows = {int(row["id"]): row for row in list_reality_inbounds()}
    values = {
        "address": "vpn.example.com",
        "listen": "0.0.0.0",
        "port": 443,
        "dest": "www.bing.com:443",
        "server_name": "www.bing.com",
        "private_key": "private",
        "public_key": "public",
        "short_id": "0011223344556677",
        "fingerprint": "chrome",
        "flow": "xtls-rprx-vision",
        "loglevel": "warning",
        "api_listen": "127.0.0.1:10085",
        "stats_enabled": False,
        "config_path": str(root / "config.json"),
        "xray_bin": "/bin/true",
        "xray_service": "xray",
        "inbound_profile": "raw_reality",
        "reality_instances": [
            {
                "id": 1,
                "name": "REALITY — основной",
                "enabled": True,
                "listen": "0.0.0.0",
                "port": 443,
                "short_id": "0011223344556677",
            },
            {
                "id": 2,
                "name": "REALITY — резервный",
                "enabled": True,
                "listen": "0.0.0.0",
                "port": 8443,
                "short_id": str(rows[2]["short_id"]),
            },
            {
                "id": 3,
                "name": "REALITY — дополнительный",
                "enabled": True,
                "listen": "0.0.0.0",
                "port": 9443,
                "short_id": str(rows[3]["short_id"]),
            },
        ],
    }
    values.update(overrides)
    return values


@pytest.fixture()
def panel(tmp_path: Path):
    os.environ["XPANEL_DB"] = str(tmp_path / "panel.db")
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, flow,
                config_path, xray_bin, xray_service
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "chrome",
                "xtls-rprx-vision", str(tmp_path / "config.json"),
                "/bin/true", "xray",
            ),
        )
    init_db()
    user = add_user("Test Client")
    yield tmp_path, user
    os.environ.pop("XPANEL_DB", None)


def test_three_reality_vision_entry_points_use_one_xray_inbound(panel):
    root, user = panel
    update_server_settings(**_server_values(root))

    config, server, _users = build_config()
    assert server["flow"] == "xtls-rprx-vision"
    assert len(config["inbounds"]) == 1
    inbound = config["inbounds"][0]
    assert inbound["tag"] == "vless-reality-in"
    assert inbound["listen"] == "0.0.0.0"
    assert inbound["port"] == "443,8443,9443"
    assert inbound["streamSettings"]["network"] == "tcp"
    assert inbound["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"
    short_ids = inbound["streamSettings"]["realitySettings"]["shortIds"]
    assert short_ids[0] == "0011223344556677"
    assert len(short_ids) == 3
    assert len(set(short_ids)) == 3
    assert inbound["settings"]["clients"][0]["id"] == user["uuid"]


def test_three_reality_links_include_vision_ports_and_compact_names(panel):
    root, user = panel
    update_server_settings(**_server_values(root))

    links = make_links(user["id"])
    assert [item["key"] for item in links] == ["reality-1", "reality-2", "reality-3"]
    assert [item["kind"] for item in links] == ["reality"] * 3
    assert [item["port"] for item in links] == [443, 8443, 9443]
    assert [unquote(urlsplit(str(item["link"])).fragment) for item in links] == [
        "Test Client/Профиль 1",
        "Test Client/Профиль 2",
        "Test Client/Профиль 3",
    ]
    for item in links:
        parts = urlsplit(str(item["link"]))
        query = parse_qs(parts.query)
        assert query["security"] == ["reality"]
        assert query["type"] == ["tcp"]
        assert query["flow"] == ["xtls-rprx-vision"]
        assert query["sid"] == [str(item["short_id"])]


def test_reality_without_vision_keeps_three_independent_inbounds(panel):
    root, user = panel
    values = _server_values(root, flow="")
    update_server_settings(**values)
    assert all("flow=" not in str(item["link"]) for item in make_links(user["id"]))
    config = build_config()[0]
    assert [item["tag"] for item in config["inbounds"]] == [
        "vless-reality-in",
        "reality-secondary-in",
        "reality-tertiary-in",
    ]
    assert [item["port"] for item in config["inbounds"]] == [443, 8443, 9443]
    assert all("flow" not in item["settings"]["clients"][0] for item in config["inbounds"])


def test_duplicate_reality_tcp_ports_are_rejected(panel):
    root, _user = panel
    values = _server_values(root)
    values["reality_instances"][2]["port"] = 8443
    with pytest.raises(ValueError, match="Конфликт REALITY: TCP-порт"):
        update_server_settings(**values)


def test_duplicate_reality_short_ids_are_rejected(panel):
    root, _user = panel
    values = _server_values(root)
    values["reality_instances"][2]["short_id"] = values["reality_instances"][1]["short_id"]
    with pytest.raises(ValueError, match="Конфликт REALITY: Short ID"):
        update_server_settings(**values)


def test_disabled_extra_reality_inbounds_are_not_rendered(panel):
    root, _user = panel
    values = _server_values(root)
    values["reality_instances"][1]["enabled"] = False
    values["reality_instances"][2]["enabled"] = False
    update_server_settings(**values)
    config = build_config()[0]
    assert [item["tag"] for item in config["inbounds"]] == ["vless-reality-in"]


def test_rc40_migration_creates_disabled_stable_extra_reality_slots(tmp_path: Path):
    os.environ["XPANEL_DB"] = str(tmp_path / "migration.db")
    try:
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint, flow,
                    config_path, xray_bin, xray_service, inbound_profile
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "vpn.example.com", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "aabbccddeeff0011", "chrome", "",
                    str(tmp_path / "config.json"), "/bin/true", "xray", "raw_reality",
                ),
            )
        init_db()
        first = list_reality_inbounds()
        assert [int(row["id"]) for row in first] == [1, 2, 3]
        assert [bool(row["enabled"]) for row in first] == [True, False, False]
        assert str(first[0]["short_id"]) == "aabbccddeeff0011"
        extra_ids = [str(first[1]["short_id"]), str(first[2]["short_id"])]
        init_db()
        second = list_reality_inbounds()
        assert [str(second[1]["short_id"]), str(second[2]["short_id"])] == extra_ids
    finally:
        os.environ.pop("XPANEL_DB", None)


def test_blank_legacy_short_id_is_synchronised_with_existing_primary_slot(tmp_path: Path):
    os.environ["XPANEL_DB"] = str(tmp_path / "blank-short-id.db")
    try:
        init_db()
        preserved = "1122334455667788"
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint, flow,
                    config_path, xray_bin, xray_service, inbound_profile
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "vpn.example.com", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "", "chrome", "",
                    str(tmp_path / "config.json"), "/bin/true", "xray", "raw_reality",
                ),
            )
            con.execute(
                "UPDATE reality_inbounds SET short_id = ? WHERE id = 1",
                (preserved,),
            )

        init_db()
        assert str(get_server()["short_id"]) == preserved
        assert str(list_reality_inbounds()[0]["short_id"]) == preserved

        init_db()
        assert str(get_server()["short_id"]) == preserved
        assert str(list_reality_inbounds()[0]["short_id"]) == preserved
    finally:
        os.environ.pop("XPANEL_DB", None)


def test_blank_submitted_primary_short_id_preserves_stored_value(panel):
    root, _user = panel
    preserved = "8899aabbccddeeff"
    with connect() as con:
        con.execute("UPDATE server_settings SET short_id = '' WHERE id = 1")
        con.execute(
            "UPDATE reality_inbounds SET short_id = ? WHERE id = 1",
            (preserved,),
        )

    values = _server_values(root, short_id="")
    values["reality_instances"][0]["short_id"] = ""
    update_server_settings(**values)

    assert str(get_server()["short_id"]) == preserved
    assert str(list_reality_inbounds()[0]["short_id"]) == preserved


def test_subscription_contains_all_enabled_reality_links(panel):
    root, user = panel
    update_server_settings(**_server_values(root))
    update_subscription_settings(
        enabled=True, base_url="https://panel.example.com", profile_title="SG-Panel"
    )
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "multi-reality-subscription",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    response = app.test_client().get(f"/sub/{user['subscription_token']}?format=plain")
    assert response.status_code == 200
    lines = [line for line in response.get_data(as_text=True).splitlines() if line]
    assert len(lines) == 3
    assert any("@vpn.example.com:443?" in line for line in lines)
    assert any("@vpn.example.com:8443?" in line for line in lines)
    assert any("@vpn.example.com:9443?" in line for line in lines)


def test_settings_and_link_templates_expose_multi_reality_controls():
    settings = Path("xpanel/templates/settings.html").read_text(encoding="utf-8")
    link = Path("xpanel/templates/link.html").read_text(encoding="utf-8")
    assert "До трёх VLESS REALITY точек входа" in settings
    assert 'name="reality_instance_1_name"' in settings
    assert 'name="reality_instance_{{ item.id }}_enabled"' in settings
    assert 'name="reality_instance_{{ item.id }}_short_id"' in settings
    assert 'value="{{ reality_inbounds[0].short_id or server.short_id }}"' in settings
    assert "data-reality-instance-toggle" in settings
    assert "updateRealityInstanceToggle" in settings
    assert "item.profile_label" in link
    assert "Short ID" in link
