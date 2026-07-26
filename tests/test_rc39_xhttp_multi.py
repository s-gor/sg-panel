from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "multi-xhttp-module")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from xpanel.db import SCHEMA, connect, init_db
from xpanel.service import (
    _nginx_transport_config,
    add_user,
    build_config,
    config_json_document,
    list_xhttp_inbounds,
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
        "inbound_profile": "xhttp_tls",
        "transport_listen": "127.0.0.1",
        "transport_port": 8443,
        "xhttp_path": "/existing-path",
        "xhttp_mode": "stream-one",
        "grpc_service_name": "sg-grpc",
        "tls_cert_path": str(cert),
        "tls_key_path": str(key),
        "xhttp_instances": [
            {
                "id": 1,
                "name": "XHTTP — основной",
                "enabled": True,
                "listen": "127.0.0.1",
                "port": 8443,
                "path": "/existing-path",
            },
            {
                "id": 2,
                "name": "XHTTP — резервный",
                "enabled": True,
                "listen": "127.0.0.1",
                "port": 8444,
                "path": "/reserve-path",
            },
            {
                "id": 3,
                "name": "XHTTP — дополнительный",
                "enabled": True,
                "listen": "127.0.0.1",
                "port": 8445,
                "path": "/extra-path",
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
                config_path, xray_bin, xray_service,
                inbound_profile, transport_listen, transport_port, xhttp_path
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "vpn.example.com",
                "private", "public", "0011223344556677", "chrome", "",
                str(tmp_path / "config.json"), "/bin/true", "xray",
                "xhttp_tls", "127.0.0.1", 8443, "/existing-path",
            ),
        )
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("certificate", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    user = add_user("Test Client")
    yield tmp_path, cert, key, user
    os.environ.pop("XPANEL_DB", None)


def test_three_xhttp_inbounds_render_with_unique_tags_paths_and_ports(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))

    config, _server, _users = build_config()
    inbounds = config["inbounds"]
    assert [item["tag"] for item in inbounds] == [
        "vless-reality-in",
        "xhttp-secondary-in",
        "xhttp-tertiary-in",
    ]
    assert [item["listen"] for item in inbounds] == ["127.0.0.1"] * 3
    assert [item["port"] for item in inbounds] == [8443, 8444, 8445]
    assert [item["streamSettings"]["xhttpSettings"]["path"] for item in inbounds] == [
        "/existing-path", "/reserve-path", "/extra-path"
    ]
    assert all(item["streamSettings"]["xhttpSettings"]["mode"] == "stream-one" for item in inbounds)
    assert all(item["settings"]["clients"][0]["id"] == user["uuid"] for item in inbounds)


def test_three_xhttp_links_keep_public_port_and_use_unique_paths(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    links = make_links(user["id"])
    assert len(links) == 3
    assert [item["port"] for item in links] == [443, 443, 443]
    assert [item["local_port"] for item in links] == [8443, 8444, 8445]
    assert [item["path"] for item in links] == [
        "/existing-path", "/reserve-path", "/extra-path"
    ]
    fragments = [unquote(urlsplit(str(item["link"])).fragment) for item in links]
    assert fragments == [
        "Test Client/Профиль 1",
        "Test Client/Профиль 2",
        "Test Client/Профиль 3",
    ]
    for item, expected_path in zip(links, ["/existing-path", "/reserve-path", "/extra-path"]):
        parsed = urlsplit(str(item["link"]))
        query = parse_qs(parsed.query)
        assert parsed.port == 443
        assert query["type"] == ["xhttp"]
        assert query["security"] == ["tls"]
        assert query["path"] == [expected_path]
        assert query["mode"] == ["stream-one"]


def test_nginx_contains_three_unique_locations_and_targets(panel):
    root, cert, key, _user = panel
    server = update_server_settings(**_server_values(root, cert, key))
    text = _nginx_transport_config(server)
    for path, port in (
        ("/existing-path/", 8443),
        ("/reserve-path/", 8444),
        ("/extra-path/", 8445),
    ):
        assert f"location {path}" in text
        assert f"grpc_pass grpc://127.0.0.1:{port};" in text
    assert text.count("grpc_pass grpc://") == 3


def test_duplicate_xhttp_paths_are_rejected(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key)
    values["xhttp_instances"][2]["path"] = "/reserve-path/"
    with pytest.raises(ValueError, match="Конфликт XHTTP: Path"):
        update_server_settings(**values)


def test_duplicate_xhttp_local_endpoints_are_rejected(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key)
    values["xhttp_instances"][2]["port"] = 8444
    with pytest.raises(ValueError, match="Конфликт XHTTP"):
        update_server_settings(**values)


def test_non_loopback_xhttp_listener_is_rejected(panel):
    root, cert, key, _user = panel
    values = _server_values(root, cert, key)
    values["xhttp_instances"][1]["listen"] = "0.0.0.0"
    with pytest.raises(ValueError, match="только loopback"):
        update_server_settings(**values)


def test_disabled_optional_xhttp_inbounds_do_not_survive_base_merge(panel):
    root, cert, key, _user = panel
    update_server_settings(**_server_values(root, cert, key))
    update_config_json_document(config_json_document())
    values = _server_values(root, cert, key)
    values["xhttp_instances"][1]["enabled"] = False
    values["xhttp_instances"][2]["enabled"] = False
    update_server_settings(**values)
    config, _server, _users = build_config()
    assert [item["tag"] for item in config["inbounds"]] == ["vless-reality-in"]


def test_schema_always_contains_three_xhttp_slots(panel):
    rows = list_xhttp_inbounds()
    assert [int(row["id"]) for row in rows] == [1, 2, 3]
    assert [str(row["tag"]) for row in rows] == [
        "vless-reality-in", "xhttp-secondary-in", "xhttp-tertiary-in"
    ]
    assert bool(rows[0]["enabled"]) is True
    assert str(rows[0]["path"]) == "/existing-path"
    assert str(rows[1]["path"]).startswith("/sg-xhttp-")
    assert str(rows[2]["path"]).startswith("/sg-xhttp-")
    assert rows[1]["path"] != rows[2]["path"]


def test_settings_template_exposes_three_xhttp_controls():
    html = Path("xpanel/templates/settings.html").read_text(encoding="utf-8")
    assert "До трёх XHTTP-TLS Inbound одновременно" in html
    assert 'name="xhttp_instance_1_name"' in html
    assert 'name="xhttp_instance_{{ item.id }}_enabled"' in html
    assert 'name="xhttp_instance_{{ item.id }}_path"' in html
    assert "data-xhttp-instance-toggle" in html
    assert "updateXhttpInstanceToggle" in html
    assert "Готов к применению" in html


def test_subscription_contains_all_enabled_xhttp_links(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    update_subscription_settings(
        enabled=True, base_url="https://panel.example.com", profile_title="SG-Panel"
    )
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "multi-xhttp-subscription",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    response = client.get(f"/sub/{user['subscription_token']}?format=plain")
    assert response.status_code == 200
    lines = [line for line in response.get_data(as_text=True).splitlines() if line]
    assert len(lines) == 3
    assert any("path=%2Fexisting-path" in line for line in lines)
    assert any("path=%2Freserve-path" in line for line in lines)
    assert any("path=%2Fextra-path" in line for line in lines)


def test_user_link_page_renders_three_xhttp_qr_cards(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "multi-xhttp-link-page",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    response = client.get(f"/users/{user['id']}/link")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert body.count("VLESS XHTTP-TLS · РАБОТАЕТ") == 3
    assert "/existing-path" in body
    assert "/reserve-path" in body
    assert "/extra-path" in body
    assert "127.0.0.1:8443" in body
    assert "127.0.0.1:8444" in body
    assert "127.0.0.1:8445" in body


def test_rc38_database_migrates_xhttp_slots_without_losing_primary(tmp_path: Path):
    database = tmp_path / "rc38.db"
    old_schema = re.sub(
        r"\nCREATE TABLE IF NOT EXISTS xhttp_inbounds \(.*?\n\);\n",
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
                config_path, xray_bin, xray_service, inbound_profile,
                transport_listen, transport_port, xhttp_path
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "old.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "old.example.com",
                "private", "public", "0011223344556677", "chrome",
                str(tmp_path / "config.json"), "/bin/true", "xray", "xhttp_tls",
                "127.0.0.1", 8555, "/legacy-path",
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
        rows = list_xhttp_inbounds()
        assert int(rows[0]["port"]) == 8555
        assert str(rows[0]["path"]) == "/legacy-path"
        assert bool(rows[1]["enabled"]) is False
        with connect() as migrated:
            user = migrated.execute("SELECT name,uuid FROM users WHERE name='Existing'").fetchone()
        assert user["uuid"] == "11111111-1111-4111-8111-111111111111"
    finally:
        os.environ.pop("XPANEL_DB", None)
