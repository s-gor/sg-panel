from __future__ import annotations

import io
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "live1-xmux-stage1")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.service import (
    XMUX_REDUCED_PRESET,
    add_user,
    build_config,
    get_transport_expert_overview,
    get_transport_expert_settings,
    make_links,
    managed_client_export,
    managed_client_export_v2,
    update_subscription_settings,
    update_transport_expert_settings,
    update_user_connection_order_mode,
)
from xpanel.node_manager import create_node, list_node_jobs
from xpanel.web import create_app


@pytest.fixture()
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("placeholder", encoding="utf-8")
    key.write_text("placeholder", encoding="utf-8")
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
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "vpn.example.com",
                "private", "public", "0011223344556677", "firefox", "",
                str(tmp_path / "config.json"), "/bin/true", "xray",
                "xhttp_tls", "127.0.0.1", 8443, "/sg-xhttp", "auto",
                str(cert), str(key),
            ),
        )
    user = add_user("LIVE1 Client")
    return tmp_path, user


def _link_extra(link: str) -> dict[str, object]:
    query = parse_qs(urlsplit(link).query)
    return json.loads(unquote(query["extra"][0])) if "extra" in query else {}


def test_conflicting_xmux_controls_are_blocked_before_save(panel):
    with pytest.raises(ValueError, match="maxConnections и maxConcurrency"):
        update_transport_expert_settings(
            xmux_mode="expert",
            xhttp_extra_client_json=(
                '{"xmux":{"maxConnections":2,"maxConcurrency":"8-16"}}'
            ),
        )
    with pytest.raises(ValueError, match="maxConnections и maxConcurrency"):
        update_transport_expert_settings(
            xmux_mode="auto",
            xhttp_extra_server_json=(
                '{"downloadSettings":{"xhttpSettings":{"extra":'
                '{"xmux":{"maxConnections":2,"maxConcurrency":4}}}}}'
            ),
        )


def test_xmux_modes_apply_only_the_selected_effective_policy(panel):
    _root, user = panel
    update_transport_expert_settings(
        xmux_mode="auto",
        xhttp_extra_server_json='{"xmux":{"maxConnections":9},"marker":"server"}',
        xhttp_extra_client_json='{"xmux":{"maxConnections":8},"marker":"client"}',
    )
    config, _server, _users = build_config()
    server_extra = config["inbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]
    assert server_extra == {"marker": "server"}
    assert _link_extra(str(make_links(user["id"])[0]["link"])) == {"marker": "client"}

    update_transport_expert_settings(
        xmux_mode="reduced",
        xhttp_extra_server_json='{"marker":"server"}',
        xhttp_extra_client_json='{"marker":"client"}',
    )
    config, _server, _users = build_config()
    server_extra = config["inbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]
    client_extra = _link_extra(str(make_links(user["id"])[0]["link"]))
    assert "xmux" not in server_extra
    assert client_extra["xmux"] == XMUX_REDUCED_PRESET
    assert "maxConcurrency" not in client_extra["xmux"]

    update_transport_expert_settings(
        xmux_mode="expert",
        xhttp_extra_server_json='{"xmux":{"maxConnections":4}}',
        xhttp_extra_client_json='{"xmux":{"maxConcurrency":"8-16"}}',
    )
    config, _server, _users = build_config()
    assert config["inbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["xmux"] == {
        "maxConnections": 4
    }
    assert _link_extra(str(make_links(user["id"])[0]["link"]))["xmux"] == {
        "maxConcurrency": "8-16"
    }


def test_xhttp_extra_survives_config_link_qr_subscription_and_sg_client_contract(
    panel, monkeypatch: pytest.MonkeyPatch
):
    _root, user = panel
    update_transport_expert_settings(
        xhttp_mode="stream-one",
        xmux_mode="expert",
        xhttp_extra_server_json='{"xmux":{"maxConnections":4},"serverMarker":true}',
        xhttp_extra_client_json='{"xmux":{"maxConnections":2},"clientMarker":true}',
    )
    update_subscription_settings(
        enabled=True, base_url="https://panel.example.com", profile_title="SG-Panel"
    )

    config, _server, _users = build_config()
    assert config["inbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["serverMarker"] is True

    direct_link = str(make_links(user["id"])[0]["link"])
    assert _link_extra(direct_link)["clientMarker"] is True

    v1 = managed_client_export(user["id"])
    v2 = managed_client_export_v2(user["id"])
    assert v1["xhttp"]["serverExtra"]["serverMarker"] is True
    assert v1["xhttp"]["clientExtra"]["clientMarker"] is True
    assert v2["connections"][0]["xhttp"]["extra"]["clientMarker"] is True

    captured: list[str] = []

    class FakeImage:
        def save(self, target: io.BytesIO, format: str = "PNG") -> None:
            target.write(b"fake-png")

    import qrcode

    def fake_make(value: object) -> FakeImage:
        captured.append(str(value))
        return FakeImage()

    monkeypatch.setattr(qrcode, "make", fake_make)
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "live1-qr-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    page = client.get(f"/users/{user['id']}/link")
    assert page.status_code == 200
    assert any(value.startswith("vless://") and _link_extra(value).get("clientMarker") is True for value in captured)

    subscription = client.get(f"/sub/{user['subscription_token']}?format=json")
    assert subscription.status_code == 200
    payload = subscription.get_json()
    assert _link_extra(payload["links"][0]["link"])["clientMarker"] is True
    assert payload["managedV2"]["connections"][0]["xhttp"]["extra"]["clientMarker"] is True


def test_normal_overview_is_human_readable_and_json_is_closed_in_expert(panel):
    _root, user = panel
    update_transport_expert_settings(
        xmux_mode="auto",
        xhttp_extra_client_json='{"privateMarker":"hidden-in-expert"}',
    )
    overview = get_transport_expert_overview()
    assert overview["effective"]["xmux_mode_label"] == "Автоматически"
    assert overview["effective"]["padding_label"] == "Стандартный Xray"
    assert overview["effective"]["xhttp_mode_label"] == "Автоматически — Xray-core"
    assert user["connection_order_mode"] == "auto"

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "live1-overview-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    body = client.get("/settings/advanced").get_data(as_text=True)
    overview_html, expert_html = body.split("Ручной JSON XHTTP и XMUX", 1)
    assert "privateMarker" not in overview_html
    assert "privateMarker" in expert_html
    assert "XMUX" in overview_html
    assert "Padding" in overview_html
    assert "Версия Xray" in overview_html



def test_ordinary_cluster_history_hides_legacy_connection_roles(panel):
    _root, _user = panel
    node = create_node("Paris Node", public_address="203.0.113.20")
    node_id = int(node["id"])
    with connect() as con:
        con.execute(
            "UPDATE nodes SET state='online', registered_at=CURRENT_TIMESTAMP, last_seen_at=CURRENT_TIMESTAMP WHERE id=?",
            (node_id,),
        )
        con.execute(
            """
            INSERT INTO node_jobs (
                node_id, job_type, status, title, payload_json, result_json, client_link
            ) VALUES (?, 'apply_xray_config', 'succeeded', ?, '{}', '{}', ?)
            """,
            (
                node_id,
                "Подготовить Backup · LIVE1/Primary",
                "vless://uuid@example.com:443?type=tcp#LIVE1/Backup",
            ),
        )
    job = list_node_jobs(node_id)[0]
    assert not re.search(r"\b(?:Primary|Backup|Alt)\b", job["display_title"])
    assert not re.search(r"\b(?:Primary|Backup|Alt)\b", unquote(urlsplit(job["display_client_link"]).fragment))
    assert "LIVE1" in unquote(urlsplit(job["display_client_link"]).fragment)


def test_ordinary_templates_do_not_show_connection_role_controls(panel):
    _root, user = panel
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "live1-role-ui-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    for path in ("/users", "/network/nodes", "/settings", "/subscriptions"):
        body = client.get(path).get_data(as_text=True)
        assert not re.search(r"\b(?:Primary|Backup|Alt)\b", body)
    ordinary = client.get(f"/users?client={user['id']}").get_data(as_text=True)
    assert "Ручное управление находится в разделе Expert" in ordinary
    assert "Основное" not in ordinary and "Резервное" not in ordinary
    update_user_connection_order_mode(user["id"], "manual")
    ordinary_after_legacy_manual = client.get(f"/users?client={user['id']}").get_data(as_text=True)
    assert "Основное" not in ordinary_after_legacy_manual
    assert "Резервное" not in ordinary_after_legacy_manual
    expert = client.get("/settings/advanced").get_data(as_text=True)
    assert "Управление подключениями клиентов" not in expert
    assert "Итоговые конфигурации" in expert
