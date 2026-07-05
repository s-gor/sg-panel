from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "mixed-inbounds-module")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from xpanel.db import connect, init_db
from xpanel.service import (
    _nginx_transport_config,
    add_user,
    build_config,
    make_links,
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
        "inbound_profile": "xhttp_hysteria_tls",
        "transport_listen": "127.0.0.1",
        "transport_port": 8443,
        "xhttp_path": "/existing-path",
        "xhttp_mode": "stream-one",
        "grpc_service_name": "sg-grpc",
        "tls_cert_path": str(cert),
        "tls_key_path": str(key),
        "hysteria_udp_idle_timeout": 60,
        "hysteria_masquerade_type": "",
        "hysteria_masquerade_url": "",
        "hysteria_masquerade_content": "",
        "hysteria_masquerade_status": 404,
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


def test_mixed_profile_builds_three_xhttp_and_three_hysteria_inbounds(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))

    config, server, _users = build_config()
    assert server["inbound_profile"] == "xhttp_hysteria_tls"
    inbounds = config["inbounds"]
    assert [item["tag"] for item in inbounds] == [
        "vless-reality-in",
        "xhttp-secondary-in",
        "xhttp-tertiary-in",
        "hysteria2-primary-in",
        "hysteria2-secondary-in",
        "hysteria2-tertiary-in",
    ]

    xhttp = inbounds[:3]
    hysteria = inbounds[3:]
    assert [item["port"] for item in xhttp] == [8443, 8444, 8445]
    assert [item["streamSettings"]["network"] for item in xhttp] == ["xhttp"] * 3
    assert [item["streamSettings"]["xhttpSettings"]["path"] for item in xhttp] == [
        "/existing-path", "/reserve-path", "/extra-path"
    ]
    assert all(item["settings"]["clients"][0]["id"] == user["uuid"] for item in xhttp)

    assert [item["port"] for item in hysteria] == [443, 8443, 9443]
    assert [item["streamSettings"]["network"] for item in hysteria] == ["hysteria"] * 3
    assert hysteria[0]["settings"]["users"][0]["auth"] == user["uuid"]
    assert len({item["settings"]["users"][0]["auth"] for item in hysteria}) == 3

    # TCP/8443 for local XHTTP and UDP/8443 for public Hysteria are valid together.
    assert xhttp[0]["port"] == hysteria[1]["port"] == 8443


def test_mixed_profile_returns_six_unique_client_links(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))

    links = make_links(user["id"])
    assert len(links) == 6
    assert [item["key"] for item in links] == [
        "xhttp-1", "xhttp-2", "xhttp-3",
        "hysteria-1", "hysteria-2", "hysteria-3",
    ]
    assert [item["kind"] for item in links] == ["xhttp"] * 3 + ["hysteria"] * 3
    assert links[3]["tag"] == "hysteria2-primary-in"

    xhttp_links = links[:3]
    hysteria_links = links[3:]
    assert all(str(item["link"]).startswith("vless://") for item in xhttp_links)
    assert all(str(item["link"]).startswith("hysteria2://") for item in hysteria_links)
    assert [parse_qs(urlsplit(str(item["link"])).query)["path"][0] for item in xhttp_links] == [
        "/existing-path", "/reserve-path", "/extra-path"
    ]
    assert [item["port"] for item in hysteria_links] == [443, 8443, 9443]
    assert [unquote(urlsplit(str(item["link"])).fragment) for item in xhttp_links] == [
        "Test Client/Primary",
        "Test Client/Backup",
        "Test Client/Alt",
    ]
    assert [unquote(urlsplit(str(item["link"])).fragment) for item in hysteria_links] == [
        "Test Client/Primary",
        "Test Client/Backup",
        "Test Client/Alt",
    ]


def test_mixed_profile_nginx_exposes_only_xhttp_paths_on_tcp_443(panel):
    root, cert, key, _user = panel
    server = update_server_settings(**_server_values(root, cert, key))
    text = _nginx_transport_config(server)
    assert "listen 443 ssl http2;" in text
    for path, port in (
        ("/existing-path/", 8443),
        ("/reserve-path/", 8444),
        ("/extra-path/", 8445),
    ):
        assert f"location {path}" in text
        assert f"grpc_pass grpc://127.0.0.1:{port};" in text
    assert "9443" not in text


def test_mixed_subscription_contains_all_six_links(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    update_subscription_settings(
        enabled=True, base_url="https://panel.example.com", profile_title="SG-Panel"
    )
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "mixed-subscription",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    response = app.test_client().get(f"/sub/{user['subscription_token']}?format=plain")
    assert response.status_code == 200
    lines = [line for line in response.get_data(as_text=True).splitlines() if line]
    assert len(lines) == 6
    assert sum(line.startswith("vless://") for line in lines) == 3
    assert sum(line.startswith("hysteria2://") for line in lines) == 3


def test_mixed_link_page_renders_six_qr_cards_with_unique_ids(panel):
    root, cert, key, user = panel
    update_server_settings(**_server_values(root, cert, key))
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "mixed-link-page",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    response = client.get(f"/users/{user['id']}/link")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert body.count("VLESS XHTTP-TLS · РАБОТАЕТ") == 3
    assert body.count("Hysteria 2 · РАБОТАЕТ") == 3
    assert 'id="link-xhttp-1"' in body
    for key_name in (
        "xhttp-2", "xhttp-3",
        "hysteria-1", "hysteria-2", "hysteria-3",
    ):
        assert f'id="link-{key_name}"' in body


def test_rc40_ui_contains_mixed_profile_and_responsive_xhttp_layout():
    html = Path("xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = Path("xpanel/static/app.css").read_text(encoding="utf-8")
    assert 'value="xhttp_hysteria_tls"' in html
    assert "XHTTP-TLS + Hysteria 2" in html
    assert 'data-profile-section="hysteria2_tls xhttp_hysteria_tls"' in html
    assert 'data-profile-section="xhttp_tls xhttp_hysteria_tls"' in html
    assert ".xhttp-instance-grid" in css
    assert "minmax(340px, 1fr)" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in css
    assert "grid-template-columns: minmax(0, 1fr)" in css
    assert "XHTTP-TLS Inbound:" in html
    assert "Hysteria 2 Inbound:" in html
    assert "XHTTP-TLS: TCP/" in html


def test_mixed_settings_summary_uses_precise_profile_names_and_live_counts(panel):
    root, cert, key, _user = panel
    update_server_settings(**_server_values(root, cert, key))
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "mixed-summary",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    response = client.get("/settings")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for label in (
        "VLESS REALITY",
        "VLESS XHTTP-TLS",
        "VLESS XHTTP-REALITY",
        "Hysteria 2",
        "XHTTP-TLS + Hysteria 2",
    ):
        assert label in body
    assert "XHTTP-TLS Inbound: 3" in body
    assert "Hysteria 2 Inbound: 3" in body
    assert "XHTTP-TLS: TCP/443 · 3 Path" in body
    assert "Hysteria 2: UDP/443, UDP/8443, UDP/9443" in body
