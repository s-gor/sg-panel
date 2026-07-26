from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc69-test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.node_manager import create_enrollment_token, create_node, has_active_enrollment
from xpanel.service import add_user
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def db_env():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["XPANEL_DB"] = str(Path(tmp) / "panel.db")
        init_db()
        with connect() as con:
            con.execute(
                """
                INSERT INTO server_settings (
                    id, address, listen, port, dest, server_name,
                    private_key, public_key, short_id, fingerprint,
                    config_path, xray_bin, xray_service
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "192.0.2.10", "0.0.0.0", 443,
                    "www.example.com:443", "www.example.com",
                    "private", "public", "0011223344556677", "firefox",
                    str(Path(tmp) / "config.json"), "/bin/true", "xray",
                ),
            )
        yield
        os.environ.pop("XPANEL_DB", None)


def client():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "rc69-test-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    result = app.test_client()
    assert result.post("/login", data={"password": "correct-password"}).status_code == 302
    return result


def test_connected_node_immediately_unlocks_first_profile(db_env):
    web = client()
    add_user("Node User")
    node = create_node("RC69 Node", role="regional")
    enrollment = create_enrollment_token(node["id"])
    assert has_active_enrollment(node["id"]) is True

    registered = web.post(
        "/api/node/v1/register",
        json={
            "enrollment_token": enrollment["token"],
            "agent_id": "rc69-agent",
            "metadata": {
                "public_address": "198.51.100.69",
                "platform": "Ubuntu",
                "platform_version": "26.04",
                "architecture": "x86_64",
                "agent_version": "0.5.0",
                "agent_state": "active",
                "worker_version": "0.5.0",
                "worker_state": "active",
                "xray_version": "Xray 26.5.9",
                "xray_state": "inactive",
                "nginx_version": "nginx/1.28.3",
                "nginx_state": "inactive",
            },
        },
    )
    assert registered.status_code == 200
    assert has_active_enrollment(node["id"]) is False

    page = web.get(f"/network/nodes/{node['id']}").get_data(as_text=True)
    assert "Проверить и развернуть" in page
    assert "Нода подключена" in page
    assert "Создать новую команду" in page
    assert "Сначала подключите ноду" not in page
    assert "Первый профиль ещё не развёрнут" in page
    assert page.count("ожидает первого профиля") >= 2

    live = web.get(f"/network/nodes/{node['id']}/live").get_json()
    assert live["enrollment_pending"] is False
    assert live["node"]["first_profile_pending"] is True
    assert live["node"]["inbound_profile"] == "Первый профиль ещё не развёрнут"


def test_node_page_auto_refreshes_after_enrollment_and_contains_overflow_guard():
    template = (ROOT / "xpanel/templates/node_detail.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "data-node-enrollment-card" in template
    assert "payload.enrollment_pending === false" in template
    assert "window.location.replace(window.location.href)" in template
    assert "pollNode();" in template
    assert "body.node-detail-page" in css
    assert "overflow-x: clip" in css
    assert ".node-command code" in css
    assert "overscroll-behavior-inline: contain" in css
    assert "SG-Panel RC70 — Cluster completion and node-detail overflow hotfix" in css
