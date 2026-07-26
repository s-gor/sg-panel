from __future__ import annotations

import html
import os
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc54-test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect as connect_db, init_db
from xpanel.node_manager import create_enrollment_token, create_node, find_node, list_node_jobs
from xpanel.service import add_user, normalise_fingerprint_profile
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def db_env():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["XPANEL_DB"] = str(Path(tmp) / "panel.db")
        init_db()
        with connect_db() as con:
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
                    "private", "public", "0011223344556677", "chrome",
                    str(Path(tmp) / "config.json"), "/bin/true", "xray",
                ),
            )
        yield Path(tmp)
        os.environ.pop("XPANEL_DB", None)


def app_client():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "rc54-test-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    response = client.post("/login", data={"password": "correct-password"})
    assert response.status_code == 302
    return client


def csrf(client) -> str:
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_cluster_page_is_an_explicit_five_step_wizard(db_env):
    client = app_client()
    body = client.get("/network/nodes").get_data(as_text=True)
    for step in range(1, 6):
        assert f"ШАГ {step}" in body
    assert "Скопировать команду полной установки SG-Node" in body
    assert "Добавить подготовленную SG-Node" in body
    assert "Скопировать команду подключения" in body
    assert "Agent, Worker, heartbeat, публичный адрес" in body
    assert "RAW/TCP · порт 64441 · XTLS Vision · Firefox" in body
    assert ">Добавить ноду<" not in body

    detail_template = (ROOT / "xpanel/templates/node_detail.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert 'class="button primary node-deploy-submit"' in detail_template
    assert ">Проверить и развернуть<" in detail_template
    assert "Проверить и развернуть на ноде" not in detail_template
    assert ".node-deploy-submit" in css
    assert "justify-self: end" in css
    assert "min-width: 280px" in css


def test_public_commands_are_single_line_and_bootstrap_clean_ubuntu(db_env):
    client = app_client()
    page = client.get("/network/nodes").get_data(as_text=True)
    prepare = html.unescape(re.search(r'id="nodePrepareCommand">(.*?)</code>', page, re.S).group(1))
    assert "\n" not in prepare
    assert prepare.startswith("sudo bash -c ")
    assert "apt-get install -y -qq ca-certificates curl" in prepare
    assert "/node/install-sg-node.sh" in prepare
    assert "--token" not in prepare

    created = client.post(
        "/network/nodes/add",
        data={"csrf_token": csrf(client), "name": "RC54 Node", "role": "regional", "public_address": "node.example.com"},
    )
    detail = created.get_data(as_text=True)
    connect = html.unescape(re.search(r'id="nodeInstallCommand">(.*?)</code>', detail, re.S).group(1))
    assert "\n" not in connect
    assert connect.startswith("sudo bash -c ")
    assert "/node/connect.sh" in connect
    assert "--token" in connect
    assert "/node/install-sg-node.sh" not in connect
    with connect_db() as con:
        assert con.execute("SELECT public_address FROM nodes WHERE name='RC54 Node'").fetchone()[0] == "node.example.com"


def test_connect_requires_ready_to_connect_with_clear_error():
    script = (ROOT / "deploy/connect-node.sh").read_text(encoding="utf-8")
    assert "^STATUS=(ready_to_connect|connected)$" in script
    assert "SG-Node ещё не подготовлена. Сначала выполните полную установку SG-Node." in script
    assert "verify_real_heartbeat" in script
    assert "systemctl enable --now sg-node-worker.service" in script
    assert "systemctl enable --now sg-node-agent.service" in script


def test_new_token_revokes_previous_unused_token(db_env):
    node = create_node("Token Rotation", role="test")
    first = create_enrollment_token(node["id"])
    second = create_enrollment_token(node["id"])
    with connect_db() as con:
        rows = con.execute(
            "SELECT token_hint, revoked_at FROM node_enrollment_tokens WHERE node_id=? ORDER BY id",
            (node["id"],),
        ).fetchall()
    assert first["token"][-8:] == rows[0]["token_hint"]
    assert rows[0]["revoked_at"]
    assert second["token"][-8:] == rows[1]["token_hint"]
    assert rows[1]["revoked_at"] is None


def test_controller_falls_back_to_request_public_ip_and_reports_worker(db_env):
    client = app_client()
    node = create_node("Public Address", role="regional")
    enrollment = create_enrollment_token(node["id"])
    response = client.post(
        "/api/node/v1/register",
        json={
            "enrollment_token": enrollment["token"],
            "agent_id": "agent-public-address",
            "metadata": {
                "agent_version": "0.5.0",
                "agent_state": "active",
                "worker_version": "0.5.0",
                "worker_state": "active",
                "platform": "Ubuntu",
            },
        },
        headers={"X-Real-IP": "3.120.16.149"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 200
    agent_token = response.get_json()["agent_token"]
    stored = find_node(node["id"])
    assert stored["public_address"] == "3.120.16.149"
    assert stored["agent_state"] == "active"
    assert stored["worker_state"] == "active"
    assert stored["worker_version"] == "0.5.0"

    heartbeat = client.post(
        "/api/node/v1/heartbeat",
        json={"agent_version": "0.5.0", "agent_state": "active", "worker_version": "0.5.0", "worker_state": "active"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert heartbeat.status_code == 200
    assert find_node(node["id"])["public_address"] == "3.120.16.149"


def test_new_defaults_are_firefox_but_existing_chrome_is_preserved(db_env):
    assert normalise_fingerprint_profile(None) == "firefox"
    installer = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    assert "--fingerprint firefox" in installer
    assert "--fingerprint chrome" not in installer
    with connect_db() as con:
        server_default = next(row for row in con.execute("PRAGMA table_info(server_settings)") if row["name"] == "fingerprint")
        outbound_default = next(row for row in con.execute("PRAGMA table_info(outbounds)") if row["name"] == "fingerprint")
        assert server_default["dflt_value"] == "'firefox'"
        assert outbound_default["dflt_value"] == "'firefox'"
        assert con.execute("SELECT fingerprint FROM server_settings WHERE id=1").fetchone()[0] == "chrome"
    init_db()
    with connect_db() as con:
        assert con.execute("SELECT fingerprint FROM server_settings WHERE id=1").fetchone()[0] == "chrome"


def test_first_node_profile_is_64441_vision_firefox(db_env):
    client = app_client()
    user = add_user("Node Firefox User")
    node = create_node("Reality Node", role="regional")
    enrollment = create_enrollment_token(node["id"])
    registered = client.post(
        "/api/node/v1/register",
        json={
            "enrollment_token": enrollment["token"],
            "agent_id": "agent-reality-node",
            "metadata": {"public_address": "198.51.100.20", "xray_version": "Xray 26.5.9", "xray_state": "inactive"},
        },
    )
    assert registered.status_code == 200

    with patch("xpanel.web.generate_reality_keys", return_value={
        "private_key": "private-key",
        "public_key": "public-key",
        "short_id": "0011223344556677",
    }):
        response = client.post(
            f"/network/nodes/{node['id']}/deploy/reality",
            data={
                "csrf_token": csrf(client),
                "user_id": user["id"],
                "public_host": "198.51.100.20",
                "port": "64441",
                "dest": "www.example.com:443",
                "server_name": "www.example.com",
            },
        )
    assert response.status_code == 302
    job = list_node_jobs(node["id"])[0]
    config = job["payload"]["config"]
    inbound = config["inbounds"][0]
    assert inbound["port"] == 64441
    assert inbound["streamSettings"]["network"] == "tcp"
    assert inbound["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"
    assert "fp=firefox" in job["client_link"]


def test_diagnostics_resource_line_uses_memory_available_not_disk_free():
    template = (ROOT / "xpanel/templates/diagnostics.html").read_text(encoding="utf-8")
    assert "diagnostics.memory_available }} доступно" in template
    assert "diagnostics.disk_free }} свободно" not in template
