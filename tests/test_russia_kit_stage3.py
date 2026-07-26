from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "russia-kit-stage3")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
import xpanel.service as service
from xpanel.service import (
    XMUX_REDUCED_PRESET,
    RUSSIA_KIT_PROFILE,
    add_user,
    build_config,
    enable_russia_kit,
    get_transport_expert_settings,
    get_russia_kit_diagnostics,
    make_links,
    managed_client_export_v2,
    set_user_subscription_enabled,
    update_subscription_settings,
)
from xpanel.web import create_app


@pytest.fixture()
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    legacy_cert = tmp_path / "legacy-fullchain.pem"
    legacy_key = tmp_path / "legacy-privkey.pem"
    cert.write_text("certificate", encoding="utf-8")
    key.write_text("private-key", encoding="utf-8")
    legacy_cert.write_text("legacy-certificate", encoding="utf-8")
    legacy_key.write_text("legacy-private-key", encoding="utf-8")
    edge = tmp_path / "reality-edge.env"
    edge.write_text(
        "\n".join(
            (
                "ENABLED=1",
                "DOMAIN=vpn.example.com",
                f"CERT={cert}",
                f"KEY={key}",
                "XRAY_PORT=8444",
                "WEB_PORT=10443",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(service, "REALITY_EDGE_STATE", edge)
    monkeypatch.setattr(service, "HYSTERIA_TLS_DIR", tmp_path / "hysteria-tls")
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, flow,
                config_path, xray_bin, xray_service, inbound_profile,
                transport_listen, transport_port, xhttp_path, xhttp_mode,
                tls_cert_path, tls_key_path
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "203.0.113.10", "0.0.0.0", 443,
                "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "firefox",
                "xtls-rprx-vision", str(tmp_path / "config.json"),
                "/bin/true", "xray", "raw_reality",
                "127.0.0.1", 8443, "/sg-xhttp", "auto",
                str(legacy_cert), str(legacy_key),
            ),
        )
    user = add_user("Russia Kit Client")
    return tmp_path, user


def _query(link: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(link).query)


def test_russia_kit_is_selected_in_classic_xray_server_not_expert(panel):
    _root, _user = panel
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "russia-kit-stage3-selector",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302

    classic = client.get("/settings").get_data(as_text=True)
    assert 'name="inbound_profile" value="russia_kit"' in classic
    assert "Набор РФ · 4 транспорта" in classic
    assert "После проверки нажмите «Сохранить и применить»" in classic
    assert "управление в Expert" not in classic

    expert = client.get("/settings/advanced").get_data(as_text=True)
    assert "Применить набор РФ" not in expert
    assert "settings/advanced/russia-kit/activate" not in expert
    assert "Схема и основные параметры выбираются в Xray Server" in expert


def test_enable_russia_kit_builds_four_independent_inbounds(panel):
    _root, user = panel
    server = enable_russia_kit()
    assert server["inbound_profile"] == RUSSIA_KIT_PROFILE
    assert int(server["port"]) == 443
    assert get_transport_expert_settings()["xmux_mode"] == "reduced"

    config, _server, _users = build_config()
    inbounds = config["inbounds"]
    assert [item["tag"] for item in inbounds[:4]] == [
        "vless-reality-in",
        "xhttp-tls-in",
        "ws-tls-in",
        "hysteria2-primary-in",
    ]
    assert [item["streamSettings"]["network"] for item in inbounds[:4]] == [
        "xhttp", "xhttp", "ws", "hysteria"
    ]
    assert inbounds[0]["streamSettings"]["security"] == "reality"
    assert inbounds[1]["streamSettings"]["security"] == "none"
    assert inbounds[2]["streamSettings"]["security"] == "none"
    assert inbounds[3]["streamSettings"]["security"] == "tls"
    hy_tls = inbounds[3]["streamSettings"]["tlsSettings"]
    assert hy_tls["serverName"] == "vpn.example.com"
    assert hy_tls["certificates"][0]["certificateFile"] == str(_root / "fullchain.pem")
    assert hy_tls["certificates"][0]["keyFile"] == str(_root / "privkey.pem")
    assert inbounds[0]["settings"]["clients"][0]["id"] == user["uuid"]
    assert inbounds[1]["streamSettings"]["sockopt"]["trustedXForwardedFor"] == ["127.0.0.1"]
    assert inbounds[2]["streamSettings"]["sockopt"]["trustedXForwardedFor"] == ["127.0.0.1"]


def test_one_subscription_contains_four_links_and_exact_xmux(panel):
    _root, user = panel
    enable_russia_kit()
    links = make_links(user["id"])
    assert [item["profile"] for item in links] == [
        "xhttp_reality", "hysteria2_tls", "ws_tls", "xhttp_tls"
    ]
    assert [item["port"] for item in links] == [443, 443, 443, 443]
    assert all("Primary" not in item["client_title"] for item in links)
    assert all("Backup" not in item["client_title"] for item in links)

    reality = _query(str(links[0]["link"]))
    assert reality["type"] == ["xhttp"]
    assert reality["security"] == ["reality"]
    assert reality["path"] == ["/sg-rf-reality"]
    assert urlsplit(str(links[0]["link"])).hostname == "203.0.113.10"

    hysteria = urlsplit(str(links[1]["link"]))
    assert hysteria.scheme == "hysteria2"
    assert hysteria.hostname == "vpn.example.com"

    ws = _query(str(links[2]["link"]))
    assert ws["type"] == ["ws"]
    assert ws["security"] == ["tls"]
    assert ws["path"] == ["/sg-rf-ws"]
    assert ws["host"] == ["vpn.example.com"]

    tls_xhttp = _query(str(links[3]["link"]))
    assert tls_xhttp["type"] == ["xhttp"]
    assert tls_xhttp["security"] == ["tls"]
    assert tls_xhttp["path"] == ["/sg-rf-xhttp"]
    extra = json.loads(unquote(tls_xhttp["extra"][0]))
    assert extra["xmux"] == XMUX_REDUCED_PRESET
    assert "maxConcurrency" not in extra["xmux"]


def test_nginx_sni_edge_routes_reality_xhttp_and_websocket(panel):
    _root, _user = panel
    server = enable_russia_kit()
    stream, web = service._nginx_reality_edge_configs(server)
    assert "www.bing.com 127.0.0.1:8444;" in stream
    assert "default 127.0.0.1:10443;" in stream
    assert "listen 443;" in stream
    assert "location /sg-rf-xhttp/" in web
    assert "grpc_pass grpc://127.0.0.1:8443;" in web
    assert "location = /sg-rf-ws" in web
    assert "proxy_set_header Upgrade $http_upgrade;" in web
    assert "proxy_pass http://127.0.0.1:8446;" in web
    assert "return 404;" in web


def test_managed_v2_exports_four_transport_contracts(panel):
    _root, user = panel
    enable_russia_kit()
    managed = managed_client_export_v2(user["id"])
    assert managed["server"]["activeProfile"] == RUSSIA_KIT_PROFILE
    assert [item["transport"] for item in managed["connections"]] == [
        "xhttp", "hysteria2", "ws", "xhttp"
    ]
    assert [item["security"] for item in managed["connections"]] == [
        "reality", "tls", "tls", "tls"
    ]
    assert managed["connections"][0]["reality"]["serverName"] == "www.bing.com"
    assert managed["connections"][1]["tls"]["serverName"] == "vpn.example.com"
    assert managed["connections"][2]["websocket"]["path"] == "/sg-rf-ws"
    assert managed["connections"][3]["xhttp"]["extra"]["xmux"] == XMUX_REDUCED_PRESET


def test_configuration_diagnostics_cover_clienthello_h1_h2_h3_and_xmux(panel):
    _root, _user = panel
    enable_russia_kit()
    result = get_russia_kit_diagnostics()
    assert result["overall_ok"] is True
    checks = {item["key"]: item for item in result["checks"]}
    assert set(checks) == {"clienthello", "xhttp_reality", "h2", "h1", "h3", "xmux"}
    assert all(item["ok"] for item in checks.values())


def test_expert_exposes_kit_but_classic_xray_layout_remains(panel):
    _root, _user = panel
    enable_russia_kit()
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "russia-kit-stage3-web",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    expert = client.get("/settings/advanced").get_data(as_text=True)
    assert "Набор РФ · 4 транспорта" in expert
    assert "Подключения клиента" in expert
    assert "4 вариантов" in expert
    assert "Проверка текущей схемы" in expert
    assert "Применить набор РФ" not in expert

    classic = client.get("/settings").get_data(as_text=True)
    assert "Основное подключение" in classic
    assert "Обнаружено автоматически" in classic
    assert "READY PROFILES" not in classic
    assert "Набор РФ · 4 транспорта" in classic
    assert "maxConnections" not in classic


class _FakeQrImage:
    def save(self, buffer, format="PNG"):
        buffer.write(b"fake-png")


def test_public_subscription_json_plain_and_qr_expose_all_four_transports(panel, monkeypatch):
    _root, user = panel
    enable_russia_kit()
    user = set_user_subscription_enabled(user["id"], True)
    update_subscription_settings(enabled=True, base_url="https://panel.example.com", profile_title="SG-Panel")

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "russia-kit-stage3-subscription",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()

    plain = client.get(f"/sub/{user['subscription_token']}?format=plain")
    assert plain.status_code == 200
    lines = [line for line in plain.get_data(as_text=True).splitlines() if line]
    assert len(lines) == 4
    assert [urlsplit(line).scheme for line in lines] == ["vless", "hysteria2", "vless", "vless"]
    assert "type=xhttp" in lines[0]
    assert "type=ws" in lines[2]
    assert "security=tls" in lines[3]

    managed = client.get(f"/sub/{user['subscription_token']}?format=json")
    assert managed.status_code == 200
    body = managed.get_json()
    assert len(body["links"]) == 4
    assert len(body["managedV2"]["connections"]) == 4
    assert body["managedV2"]["contract"]["connectionSelection"] == "automatic_reachability_then_priority"
    assert body["managedV2"]["contract"]["adaptiveReconnect"] is True

    qr_values: list[str] = []
    import qrcode

    def fake_make(value):
        qr_values.append(str(value))
        return _FakeQrImage()

    monkeypatch.setattr(qrcode, "make", fake_make)
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    page = client.get(f"/users/{user['id']}/link")
    assert page.status_code == 200
    assert qr_values[:4] == lines
    assert qr_values[4] == f"https://panel.example.com/sub/{user['subscription_token']}"
    html = page.get_data(as_text=True)
    assert "XHTTP REALITY" in html
    assert "Hysteria 2" in html
    assert "WebSocket TLS" in html
    assert "XHTTP TLS" in html
    assert "vpn.example.com:443/UDP" in html
    assert "vpn.example.com:443/TCP · /sg-rf-ws" in html
    assert "vpn.example.com:443/TCP · /sg-rf-xhttp" in html
    assert "203.0.113.10:443/TCP · /sg-rf-reality" in html



def test_runtime_hysteria_tls_copy_uses_ready_set_domain_certificate(panel, monkeypatch):
    root, _user = panel
    enable_russia_kit()
    server = service.get_server()
    monkeypatch.setattr(service, "_xray_service_identity", lambda _name: (0, os.getgid()))
    cert_path, key_path = service._sync_hysteria_tls_material(server)
    assert cert_path.read_text(encoding="utf-8") == "certificate"
    assert key_path.read_text(encoding="utf-8") == "private-key"
    assert cert_path.parent == root / "hysteria-tls"
