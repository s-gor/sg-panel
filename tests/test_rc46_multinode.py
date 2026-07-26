from __future__ import annotations

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
    create_enrollment_token,
    create_node,
    find_node,
    heartbeat_node,
    list_nodes,
    register_node,
    revoke_node,
)
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


def test_init_db_creates_single_local_node(db_env):
    nodes = list_nodes()
    assert len(nodes) == 1
    assert nodes[0]["slug"] == "local"
    assert nodes[0]["is_local"] == 1
    assert nodes[0]["role"] == "primary"

    init_db()
    assert len(list_nodes()) == 1


def test_one_time_enrollment_and_heartbeat(db_env):
    node = create_node("Germany Backup", role="backup", location="Frankfurt")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(
        enrollment["token"],
        agent_id="agent-germany-1",
        metadata={
            "platform": "Ubuntu",
            "platform_version": "24.04",
            "agent_version": "0.1.0",
            "xray_version": "Xray 26.6.1",
            "xray_state": "active",
            "nginx_version": "nginx/1.24.0",
            "nginx_state": "active",
            "cpu_percent": 12,
        },
    )
    assert registered["node"]["effective_state"] == "online"
    assert registered["node"]["role_label"] == "Резервный"
    assert registered["node"]["xray_state"] == "active"
    assert registered["node"]["nginx_state"] == "active"
    assert registered["agent_token"]

    with pytest.raises(ValueError, match="уже использован"):
        register_node(enrollment["token"], agent_id="agent-replay", metadata={})

    result = heartbeat_node(
        registered["agent_token"],
        {
            "platform": "Ubuntu",
            "platform_version": "24.04",
            "agent_version": "0.1.0",
            "xray_state": "failed",
            "nginx_state": "active",
            "memory_percent": 31,
            "disk_percent": 42,
        },
    )
    assert result["ok"] is True
    refreshed = find_node(node["id"])
    assert refreshed["memory_percent"] == 31
    assert refreshed["disk_percent"] == 42
    assert refreshed["xray_state"] == "failed"
    assert refreshed["nginx_state"] == "active"


def test_revoke_invalidates_agent_token(db_env):
    node = create_node("Finland Test", role="test")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(enrollment["token"], agent_id="agent-fi", metadata={})
    revoke_node(node["id"])
    with pytest.raises(PermissionError, match="Неизвестный токен|отозван"):
        heartbeat_node(registered["agent_token"], {})


def test_network_ui_and_public_agent_api(db_env):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()

    with patch("xpanel.web.get_status", return_value={
        "overall_ok": True,
        "enabled_users": 2,
        "inbound_profile_label": "VLESS REALITY",
        "config_detail": "",
        "service": "active",
        "system": {"cpu_percent": 8, "memory_percent": 22, "disk_percent": 17},
    }):
        response = client.get("/network/nodes")
        assert response.status_code == 302
        login = client.post("/login", data={"password": "correct-password"})
        assert login.status_code == 302
        page = client.get("/network/nodes")
        assert page.status_code == 200
        assert "SG-Panel Cluster".encode() in page.data
        assert "Основной сервер".encode() in page.data

        with client.session_transaction() as session:
            csrf = session["csrf_token"]
        created = client.post(
            "/network/nodes/add",
            data={
                "csrf_token": csrf,
                "name": "France Regional",
                "role": "regional",
                "location": "Paris",
                "description": "Test node",
            },
        )
        assert created.status_code == 200
        assert b"curl -fsSL" in created.data
        assert "France Regional".encode() in created.data

    node = next(item for item in list_nodes() if item["slug"] == "france-regional")
    enrollment = create_enrollment_token(node["id"])
    registration = client.post(
        "/api/node/v1/register",
        json={
            "enrollment_token": enrollment["token"],
            "agent_id": "web-agent-fr",
            "metadata": {
                "platform": "Ubuntu",
                "agent_version": "0.1.0",
                "xray_state": "active",
                "nginx_state": "active",
            },
        },
    )
    assert registration.status_code == 200
    body = registration.get_json()
    assert body["ok"] is True
    assert body["agent_token"]

    heartbeat = client.post(
        "/api/node/v1/heartbeat",
        headers={"Authorization": f"Bearer {body['agent_token']}"},
        data=json.dumps({"platform": "Ubuntu", "cpu_percent": 9}),
        content_type="application/json",
    )
    assert heartbeat.status_code == 200
    assert heartbeat.get_json()["ok"] is True

    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    replacement = client.post(
        f"/network/nodes/{node['id']}/enrollment",
        data={"csrf_token": csrf},
    )
    assert replacement.status_code == 200
    assert b"--replace-registration" not in replacement.data
    assert b"/node/connect.sh" in replacement.data
    assert "Переподключить ноду".encode() in replacement.data


def test_agent_files_are_exposed_and_syntax_valid(db_env):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    installer = client.get("/node/install.sh")
    source = client.get("/node/agent.py")
    uninstaller = client.get("/node/uninstall.sh")
    assert installer.status_code == 200
    assert b"install-node-agent" not in installer.data
    assert b"sg-node-agent.service" in installer.data
    assert b"--replace-registration" in installer.data  # accepted only for backward compatibility
    assert b"replace_registration" in installer.data
    assert b"verify_real_heartbeat" in installer.data
    assert b"enrollment_token" in installer.data
    assert source.status_code == 200
    assert b"AGENT_VERSION" in source.data
    assert uninstaller.status_code == 200
    assert b"Xray, Nginx and VPN configuration were not changed" in uninstaller.data


def test_node_job_claim_and_completion(db_env):
    from xpanel.node_manager import (
        claim_node_job,
        complete_node_job,
        create_node_job,
        find_node_job,
    )

    node = create_node("Deployment Test", role="test")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(
        enrollment["token"],
        agent_id="agent-deployment",
        metadata={"xray_state": "active"},
    )
    job = create_node_job(
        node["id"],
        job_type="apply_xray_config",
        title="VLESS REALITY test",
        payload={"profile": "VLESS REALITY", "config": {"inbounds": [], "outbounds": []}},
        client_link="vless://example",
    )
    assert job["status"] == "queued"

    claimed = claim_node_job(registered["agent_token"])
    assert claimed is not None
    assert claimed["id"] == job["id"]
    assert claimed["status"] == "running"
    assert claim_node_job(registered["agent_token"]) is None

    completed = complete_node_job(
        registered["agent_token"],
        job["id"],
        ok=True,
        result={"message": "applied", "profile": "VLESS REALITY"},
    )
    assert completed["status"] == "succeeded"
    assert completed["result"]["message"] == "applied"
    assert find_node_job(job["id"])["client_link"] == "vless://example"


def test_job_api_is_bound_to_registered_node(db_env):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    node = create_node("API Job Node", role="test")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(enrollment["token"], agent_id="api-job-agent", metadata={})

    from xpanel.node_manager import create_node_job
    job = create_node_job(
        node["id"],
        job_type="apply_xray_config",
        title="API job",
        payload={"profile": "VLESS REALITY", "config": {"inbounds": [], "outbounds": []}},
    )
    headers = {"Authorization": f"Bearer {registered['agent_token']}"}
    claimed = client.post("/api/node/v1/jobs/next", headers=headers, json={})
    assert claimed.status_code == 200
    assert claimed.get_json()["job"]["id"] == job["id"]

    completed = client.post(
        f"/api/node/v1/jobs/{job['id']}/complete",
        headers=headers,
        json={"ok": False, "result": {"message": "test failure"}},
    )
    assert completed.status_code == 200
    assert completed.get_json()["job"]["status"] == "failed"


def test_preview2_reality_deployment_route_queues_job(db_env):
    from xpanel.node_manager import list_node_jobs
    from xpanel.service import add_user

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    client.post("/login", data={"password": "correct-password"})

    user = add_user("Preview User")
    node = create_node("Preview Germany", role="test")
    enrollment = create_enrollment_token(node["id"])
    register_node(
        enrollment["token"],
        agent_id="preview2-agent",
        metadata={"xray_state": "active", "nginx_state": "active"},
    )
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    with patch(
        "xpanel.web.generate_reality_keys",
        return_value={
            "private_key": "private-key",
            "public_key": "public-key",
            "short_id": "0011223344556677",
        },
    ):
        response = client.post(
            f"/network/nodes/{node['id']}/deploy/reality",
            data={
                "csrf_token": csrf,
                "user_id": str(user["id"]),
                "public_host": "198.51.100.20",
                "port": "8443",
                "dest": "www.example.com:443",
                "server_name": "www.example.com",
            },
        )
    assert response.status_code == 302
    jobs = list_node_jobs(node["id"])
    assert len(jobs) == 1
    assert jobs[0]["status"] == "queued"
    assert jobs[0]["payload"]["profile"] == "VLESS REALITY"
    assert "198.51.100.20:8443" in jobs[0]["client_link"]


def test_worker_source_is_public_and_installer_fetches_it(db_env):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    worker = client.get("/node/worker.py")
    installer = client.get("/node/install.sh")
    assert worker.status_code == 200
    assert b"WORKER_VERSION" in worker.data
    assert b"-test" in worker.data
    assert b"/node/worker.py" in installer.data
    assert b"sg-node-worker.service" in installer.data
