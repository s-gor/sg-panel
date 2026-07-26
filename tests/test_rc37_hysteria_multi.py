from __future__ import annotations

import json
import os
import tempfile
import re
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "multi-hysteria-module")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from xpanel.db import SCHEMA, connect, init_db
from xpanel.service import (
    add_user,
    delete_user,
    build_config,
    config_json_document,
    list_hysteria_inbounds,
    make_links,
    update_config_json_document,
    update_server_settings,
    update_subscription_settings,
)
from xpanel.web import create_app


def _server_values(root: Path, cert: Path, key: Path, **overrides):
    values = {
        "address": "vpn.example.com",
        "listen": "0.0.0.0",
        "port": 443,
        "dest": "www.bing.com:443",
        "server_name": "vpn.example.com",
        "private_key": "private",
        "public_key": "public",
        "short_id": "0011223344556677",
        "fingerprint": "chrome",
        "flow": "",
        "loglevel": "warning",
        "api_listen": "127.0.0.1:10085",
        "stats_enabled": False,
        "config_path": str(root / "config.json"),
        "xray_bin": "/bin/true",
        "xray_service": "xray",
        "inbound_profile": "hysteria2_tls",
        "transport_listen": "127.0.0.1",
        "transport_port": 8443,
        "xhttp_path": "/sg-xhttp",
        "xhttp_mode": "auto",
        "grpc_service_name": "sg-grpc",
        "tls_cert_path": str(cert),
        "tls_key_path": str(key),
        "hysteria_udp_idle_timeout": 60,
        "hysteria_masquerade_type": "",
        "hysteria_masquerade_url": "",
        "hysteria_masquerade_content": "",
        "hysteria_masquerade_status": 404,
        "hysteria_instances": [
            {"id": 1, "name": "Основной", "enabled": True, "listen": "0.0.0.0", "port": 443},
            {"id": 2, "name": "Резервный", "enabled": True, "listen": "0.0.0.0", "port": 8443},
            {"id": 3, "name": "Дополнительный", "enabled": True, "listen": "0.0.0.0", "port": 9443},
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
                "private", "public", "0011223344556677", "chrome", "",
                str(tmp_path / "config.json"), "/bin/true", "xray",
            ),
        )
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("certificate", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    user = add_user("Test Client")
    yield tmp_path, cert, key, user
    os.environ.pop("XPANEL_DB", None)


def test_three_hysteria_inbounds_render_with_unique_tags_ports_and_auth(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))

    config, _server, _users = build_config()
    inbounds = config["inbounds"]
    assert [item["tag"] for item in inbounds] == [
        "vless-reality-in",
        "hysteria2-secondary-in",
        "hysteria2-tertiary-in",
    ]
    assert [item["port"] for item in inbounds] == [443, 8443, 9443]
    auths = [item["settings"]["users"][0]["auth"] for item in inbounds]
    assert auths[0] == user["uuid"]
    assert len(set(auths)) == 3

    links = make_links(user["id"])
    assert len(links) == 3
    assert [item["port"] for item in links] == [443, 8443, 9443]
    assert all(str(item["link"]).startswith("hysteria2://") for item in links)
    assert ":443/" in str(links[0]["link"])
    assert ":8443/" in str(links[1]["link"])
    assert ":9443/" in str(links[2]["link"])
    from urllib.parse import unquote, urlsplit
    assert [unquote(urlsplit(str(item["link"])).fragment) for item in links] == [
        "Test Client/Профиль 1",
        "Test Client/Профиль 2",
        "Test Client/Профиль 3",
    ]
    assert all("Hysteria 2" not in unquote(urlsplit(str(item["link"])).fragment) for item in links)

    second_auths = [
        item["settings"]["users"][0]["auth"]
        for item in build_config()[0]["inbounds"]
    ]
    assert second_auths == auths


def test_duplicate_udp_ports_are_rejected(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key)
    values["hysteria_instances"][2]["port"] = 8443
    with pytest.raises(ValueError, match="Конфликт Hysteria 2"):
        update_server_settings(**values)


def test_port_hopping_is_rejected_with_multiple_inbounds(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key, hysteria_udp_hop_ports="20000-20100")
    with pytest.raises(ValueError, match="port hopping"):
        update_server_settings(**values)


def test_disabled_extra_inbounds_do_not_survive_config_base_merge(panel):
    root, cert, key, _user = panel
    update_server_settings(**_server_values(root, cert, key))
    update_config_json_document(config_json_document())

    values = _server_values(root, cert, key)
    values["hysteria_instances"][1]["enabled"] = False
    values["hysteria_instances"][2]["enabled"] = False
    update_server_settings(**values)
    config, _server, _users = build_config()
    assert [item["tag"] for item in config["inbounds"]] == ["vless-reality-in"]


def test_schema_always_contains_three_slots(panel):
    rows = list_hysteria_inbounds()
    assert [int(row["id"]) for row in rows] == [1, 2, 3]
    assert [str(row["tag"]) for row in rows] == [
        "vless-reality-in",
        "hysteria2-secondary-in",
        "hysteria2-tertiary-in",
    ]


def test_settings_template_exposes_three_hysteria_instance_controls():
    html = Path("xpanel/templates/settings.html").read_text(encoding="utf-8")
    assert 'name="hysteria_instance_1_name"' in html
    assert 'name="hysteria_instance_{{ item.id }}_enabled"' in html
    assert 'data-hysteria-instance-toggle' in html
    assert '<span class="switch" aria-hidden="true"></span>' in html
    assert "updateHysteriaInstanceToggle" in html
    assert "checkbox.checked ? 'Отключить' : 'Включить'" in html
    assert 'hysteria_inbounds[1:]' in html
    assert "До трёх Hysteria 2 одновременно" in html


def test_string_false_does_not_enable_optional_inbound(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key)
    values["hysteria_instances"][1]["enabled"] = "false"
    values["hysteria_instances"][2]["enabled"] = "0"
    update_server_settings(**values)
    config, _server, _users = build_config()
    assert [item["tag"] for item in config["inbounds"]] == ["vless-reality-in"]


def test_duplicate_instance_names_are_rejected(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key)
    values["hysteria_instances"][2]["name"] = "резервный"
    values["hysteria_instances"][1]["name"] = "Резервный"
    with pytest.raises(ValueError, match="название уже используется"):
        update_server_settings(**values)


def test_primary_slot_is_enabled_for_existing_hysteria_database(tmp_path: Path):
    os.environ["XPANEL_DB"] = str(tmp_path / "migration.db")
    try:
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service, inbound_profile
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "vpn.example.com", "0.0.0.0", 443,
                    "www.bing.com:443", "vpn.example.com",
                    "private", "public", "0011223344556677", "chrome",
                    str(tmp_path / "config.json"), "/bin/true", "xray", "hysteria2_tls",
                ),
            )
            con.execute("UPDATE hysteria_inbounds SET enabled=0 WHERE id=1")
        init_db()
        rows = list_hysteria_inbounds()
        assert bool(rows[0]["enabled"]) is True
        assert int(rows[0]["port"]) == 443
    finally:
        os.environ.pop("XPANEL_DB", None)


def test_subscription_contains_all_enabled_hysteria_links(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    update_subscription_settings(
        enabled=True, base_url="https://panel.example.com", profile_title="SG-Panel"
    )
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "multi-hysteria-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    response = client.get(f"/sub/{user['subscription_token']}?format=plain")
    assert response.status_code == 200
    lines = [line for line in response.get_data(as_text=True).splitlines() if line]
    assert len(lines) == 3
    assert any(":443/" in line for line in lines)
    assert any(":8443/" in line for line in lines)
    assert any(":9443/" in line for line in lines)

    response = client.get(f"/sub/{user['subscription_token']}?format=json")
    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["links"]) == 3
    assert payload["link"] == payload["links"][0]["link"]



def test_switching_away_from_hysteria_does_not_leak_extra_inbounds(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    raw_values = _server_values(
        root,
        cert,
        key,
        inbound_profile="raw_reality",
        server_name="www.bing.com",
        flow="xtls-rprx-vision",
    )
    update_server_settings(**raw_values)
    config, _server, _users = build_config()
    assert len(config["inbounds"]) == 1
    assert config["inbounds"][0]["protocol"] == "vless"
    assert config["inbounds"][0]["tag"] == "vless-reality-in"
    links = make_links(user["id"])
    assert len(links) == 1
    assert str(links[0]["link"]).startswith("vless://")


def test_deleting_user_removes_all_hysteria_auth_rows(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    build_config()
    with connect() as con:
        assert con.execute(
            "SELECT COUNT(*) FROM hysteria_user_auth WHERE user_id=?", (user["id"],)
        ).fetchone()[0] == 3
    delete_user(user["id"])
    with connect() as con:
        assert con.execute(
            "SELECT COUNT(*) FROM hysteria_user_auth WHERE user_id=?", (user["id"],)
        ).fetchone()[0] == 0


def test_rc36_database_is_migrated_without_losing_server_or_users(tmp_path: Path):
    database = tmp_path / "rc36.db"
    old_schema = re.sub(
        r"\nCREATE TABLE IF NOT EXISTS hysteria_inbounds \(.*?\n\);\n\n"
        r"CREATE TABLE IF NOT EXISTS hysteria_user_auth \(.*?\n\);\n",
        "\n",
        SCHEMA,
        flags=re.S,
    )
    con = sqlite3.connect(database)
    try:
        con.executescript(old_schema)
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint,
                config_path, xray_bin, xray_service, inbound_profile
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "old.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "old.example.com",
                "private", "public", "0011223344556677", "chrome",
                str(tmp_path / "config.json"), "/bin/true", "xray", "hysteria2_tls",
            ),
        )
        con.execute(
            "INSERT INTO users (name,uuid,enabled,subscription_token) VALUES (?,?,1,?)",
            ("Existing", "11111111-1111-4111-8111-111111111111", "token"),
        )
        con.commit()
    finally:
        con.close()

    os.environ["XPANEL_DB"] = str(database)
    try:
        init_db()
        rows = list_hysteria_inbounds()
        assert [int(row["port"]) for row in rows] == [443, 8443, 9443]
        assert bool(rows[0]["enabled"]) is True
        with connect() as migrated:
            server = migrated.execute("SELECT address,inbound_profile FROM server_settings WHERE id=1").fetchone()
            user = migrated.execute("SELECT name,uuid FROM users WHERE name='Existing'").fetchone()
        assert server["address"] == "old.example.com"
        assert server["inbound_profile"] == "hysteria2_tls"
        assert user["uuid"] == "11111111-1111-4111-8111-111111111111"
    finally:
        os.environ.pop("XPANEL_DB", None)


def test_user_link_page_renders_three_direct_qr_cards(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "multi-hysteria-link-page",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    login = client.post("/login", data={"password": "correct-password"})
    assert login.status_code == 302
    response = client.get(f"/users/{user['id']}/link")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert body.count("Hysteria 2 · РАБОТАЕТ") == 3
    assert ":443/UDP" in body
    assert ":8443/UDP" in body
    assert ":9443/UDP" in body
