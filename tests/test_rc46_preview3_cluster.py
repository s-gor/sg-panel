from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.node_manager import (
    claim_node_job,
    complete_node_job,
    create_enrollment_token,
    create_node,
    create_node_job,
    find_node,
    list_node_deployments,
    list_node_jobs,
    register_node,
    user_deletion_request,
)
from xpanel.service import add_user, find_user
from xpanel.web import create_app


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
                    "private", "public", "0011223344556677", "chrome",
                    str(Path(tmp) / "config.json"), "/bin/true", "xray",
                ),
            )
        yield Path(tmp)
        os.environ.pop("XPANEL_DB", None)


def pilot_config(user_uuid: str, user_name: str = "Cluster User") -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "sg-node-reality-in",
                "listen": "0.0.0.0",
                "port": 8443,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": user_uuid,
                            "email": user_name,
                            "flow": "xtls-rprx-vision",
                            "level": 0,
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": "www.example.com:443",
                        "xver": 0,
                        "serverNames": ["www.example.com"],
                        "privateKey": "abcdefghijklmnopqrstuvwxyzABCDE_1234567890",
                        "shortIds": ["0011223344556677"],
                    },
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
    }


def create_registered_node(name: str = "Germany Node"):
    node = create_node(name, role="test")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(
        enrollment["token"],
        agent_id=f"agent-{node['id']}",
        metadata={"xray_state": "active", "nginx_state": "active", "agent_version": "0.4.0"},
    )
    return node, registered


def create_successful_deployment(node, registered, user):
    config = pilot_config(str(user["uuid"]), str(user["name"]))
    encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
    job = create_node_job(
        node["id"],
        job_type="apply_xray_config",
        title=f"VLESS REALITY · {user['name']} · TCP 8443",
        payload={
            "profile": "VLESS REALITY",
            "config": config,
            "config_sha256": hashlib.sha256(encoded).hexdigest(),
            "client_count": 1,
            "deployment": {
                "action": "upsert",
                "user_id": int(user["id"]),
                "user_uuid": str(user["uuid"]),
                "user_name": str(user["name"]),
                "profile": "VLESS REALITY",
                "public_host": "198.51.100.20",
                "public_port": 8443,
            },
        },
        client_link=f"vless://{user['uuid']}@198.51.100.20:8443#test",
    )
    claimed = claim_node_job(registered["agent_token"])
    assert claimed and claimed["id"] == job["id"]
    complete_node_job(
        registered["agent_token"], job["id"], ok=True,
        result={"message": "Конфигурация проверена и применена на ноде"},
    )
    return job


def login(client):
    response = client.post("/login", data={"password": "correct-password"})
    assert response.status_code == 302
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_cluster_page_and_node_detail_use_background_polling(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    login(client)
    node, _ = create_registered_node()

    page = client.get("/network/nodes")
    assert page.status_code == 200
    assert "SG-Panel Cluster".encode() in page.data
    assert b">Cluster<" in page.data

    detail = client.get(f"/network/nodes/{node['id']}")
    assert detail.status_code == 200
    assert b"window.location.reload" not in detail.data
    assert f"/network/nodes/{node['id']}/live".encode() in detail.data
    detail_body = detail.get_data(as_text=True)
    assert "ui-page-wide node-detail-shell" not in detail_body
    assert "node-history-panel" in detail_body
    assert "button.dataset.copyLabel" in detail_body
    assert "button.disabled = false" in detail_body

    live = client.get(f"/network/nodes/{node['id']}/live")
    assert live.status_code == 200
    body = live.get_json()
    assert body["ok"] is True
    assert body["node"]["effective_state"] == "online"
    assert "jobs_html" in body
    jobs_template = (Path(__file__).resolve().parents[1] / "xpanel" / "templates" / "_node_jobs.html").read_text(encoding="utf-8")
    assert "node-job-spinner" in jobs_template


def test_old_failed_job_is_collapsed_as_resolved_after_success(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    login(client)
    user = add_user("History User")
    node, registered = create_registered_node("History Node")
    config = pilot_config(str(user["uuid"]), str(user["name"]))

    failed = create_node_job(node["id"], job_type="apply_xray_config", title="First", payload={"profile": "VLESS REALITY", "config": config})
    claim_node_job(registered["agent_token"])
    complete_node_job(registered["agent_token"], failed["id"], ok=False, result={"message": "old failure"})

    create_successful_deployment(node, registered, user)
    detail = client.get(f"/network/nodes/{node['id']}")
    assert detail.status_code == 200
    assert "Исправлено".encode() in detail.data
    assert "Предыдущее задание исправлено".encode() in detail.data
    assert detail.data.find("Применено".encode()) < detail.data.find("История заданий".encode())


def test_node_delete_uses_single_confirmation_in_ui_and_no_typed_acknowledgement(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = login(client)
    user = add_user("Node Delete User")
    node, registered = create_registered_node("Delete Node")
    create_successful_deployment(node, registered, user)
    assert list_node_deployments(node["id"])

    page = client.get(f"/network/nodes/{node['id']}")
    body = page.get_data(as_text=True)
    assert "Удалить ноду" in body
    assert "Опасная зона" not in body
    assert 'name="confirmation"' not in body
    assert "Delete Node" in body
    assert "data-node-delete-open" in body
    assert "data-node-delete-confirm" in body
    assert "return confirm(" not in body.split('data-node-delete-open', 1)[1]

    removed = client.post(
        f"/network/nodes/{node['id']}/delete",
        data={"csrf_token": csrf},
    )
    assert removed.status_code == 302
    with pytest.raises(ValueError):
        find_node(node["id"])


def test_user_delete_cleans_node_then_removes_identity(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = login(client)
    user = add_user("Delete Everywhere")
    node, registered = create_registered_node("Cleanup Node")
    create_successful_deployment(node, registered, user)

    with patch("xpanel.web.validate_generated_config", return_value={"ok": True, "detail": "ok", "users": 0}), patch("xpanel.web.apply_config", return_value={"enabled_users": 0, "enabled_rules": 0}):
        response = client.post(
            f"/users/{user['id']}/delete",
            data={"csrf_token": csrf},
        )
        assert response.status_code == 302
        assert find_user(user["id"])["enabled"] == 0
        deletion = user_deletion_request(user["id"])
        assert deletion and deletion["status"] == "running"
        jobs = list_node_jobs(node["id"])
        cleanup = jobs[0]
        assert cleanup["payload"]["deployment"]["action"] == "remove"
        clients = cleanup["payload"]["config"]["inbounds"][0]["settings"]["clients"]
        assert clients == []

        claimed = client.post(
            "/api/node/v1/jobs/next",
            headers={"Authorization": f"Bearer {registered['agent_token']}"},
            json={},
        )
        assert claimed.status_code == 200
        assert claimed.get_json()["job"]["id"] == cleanup["id"]
        completed = client.post(
            f"/api/node/v1/jobs/{cleanup['id']}/complete",
            headers={"Authorization": f"Bearer {registered['agent_token']}"},
            json={"ok": True, "result": {"message": "Пользователь удалён с ноды"}},
        )
        assert completed.status_code == 200

    with pytest.raises(Exception):
        find_user(user["id"])
    deployment = list_node_deployments(node["id"], include_removed=True)[0]
    assert deployment["state"] == "removed"


def test_preview3_installers_use_green_progress_and_logs():
    root = Path(__file__).resolve().parents[1]
    upgrade = (root / "install-or-upgrade.sh").read_text(encoding="utf-8")
    bootstrap = (root / "install-from-github.sh").read_text(encoding="utf-8")
    agent = (root / "deploy" / "install-node-agent.sh").read_text(encoding="utf-8")

    for text in (upgrade, bootstrap, agent):
        assert "spinner_loop" in text
        assert "GREEN" in text
        assert "Журнал" in text or "LOG_FILE" in text
    assert "COLOR_GREEN" in upgrade
    assert "GREEN=" in bootstrap
    assert "run_stage" in upgrade
    assert "Последние полезные строки журнала" in upgrade
    assert "Все параметры приняты" in upgrade
    assert 'bash "$TMP_INSTALLER" "$@"' in bootstrap


def test_user_delete_without_nodes_removes_identity_immediately(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = login(client)
    user = add_user("Local Only")

    with patch("xpanel.web.validate_generated_config", return_value={"ok": True, "detail": "ok", "users": 0}), patch("xpanel.web.apply_config", return_value={"enabled_users": 0, "enabled_rules": 0}):
        response = client.post(
            f"/users/{user['id']}/delete",
            data={"csrf_token": csrf},
        )
        assert response.status_code == 302

    with pytest.raises(Exception):
        find_user(user["id"])


def test_node_delete_waits_for_active_job(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = login(client)
    node, _registered = create_registered_node("Busy Node")
    create_node_job(
        node["id"],
        job_type="apply_xray_config",
        title="Busy",
        payload={"profile": "VLESS REALITY", "config": pilot_config("8234eb73-c3e2-4f65-8448-9a8e11657e66")},
    )
    response = client.post(
        f"/network/nodes/{node['id']}/delete",
        data={"csrf_token": csrf},
    )
    assert response.status_code == 302
    assert find_node(node["id"])["name"] == "Busy Node"


def test_registered_node_has_tokenless_component_update_command(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    login(client)
    node, _registered = create_registered_node("Update Node")
    page = client.get(f"/network/nodes/{node['id']}")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Обновить все компоненты SG-Node" in body
    assert "nodeUpdateCommand" in body
    command = body.split('id="nodeUpdateCommand">', 1)[1].split("</code>", 1)[0]
    assert "/node/install-sg-node.sh" in command
    assert "--panel" in command
    assert "--token" not in command

    installer = (Path(__file__).resolve().parents[1] / "deploy" / "connect-node.sh").read_text(encoding="utf-8")
    assert "replace_registration" in installer
    assert "verify_real_heartbeat" in installer


def test_clients_page_shows_simple_delete_for_selected_user(db_env):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    login(client)
    user = add_user("Visible Delete")

    page = client.get(f"/users?client={user['id']}")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Опасная зона" not in body
    assert f'/users/{user["id"]}/delete' in body
    assert 'name="confirmation"' not in body
    assert "Visible Delete" in body
    assert "data-client-delete-open" in body
    assert "data-client-delete-confirm" in body
    assert "return confirm(" not in body.split('data-client-delete-open', 1)[1]
    assert ">Удалить</button>" in body
    assert "client-detail-standard" in body


def test_node_agent_reports_ec2_public_address_not_private_hostname(monkeypatch):
    from node_agent import sg_node_agent

    monkeypatch.delenv("SG_NODE_PUBLIC_ADDRESS", raising=False)
    monkeypatch.setattr(sg_node_agent, "aws_public_ipv4", lambda: "3.120.16.149")
    monkeypatch.setattr(sg_node_agent.socket, "getfqdn", lambda: "ip-172-31-45-31.eu-central-1.compute.internal")
    monkeypatch.setattr(sg_node_agent.socket, "gethostbyname", lambda _name: "172.31.45.31")

    assert sg_node_agent.AGENT_VERSION == "0.5.0"
    assert sg_node_agent.public_address() == "3.120.16.149"


def test_node_agent_does_not_label_private_ipv4_as_public(monkeypatch):
    from node_agent import sg_node_agent

    monkeypatch.delenv("SG_NODE_PUBLIC_ADDRESS", raising=False)
    monkeypatch.setattr(sg_node_agent, "aws_public_ipv4", lambda: "")
    monkeypatch.setattr(sg_node_agent.socket, "getfqdn", lambda: "ip-172-31-45-31")
    monkeypatch.setattr(sg_node_agent.socket, "gethostbyname", lambda _name: "172.31.45.31")

    assert sg_node_agent.public_address() == ""
