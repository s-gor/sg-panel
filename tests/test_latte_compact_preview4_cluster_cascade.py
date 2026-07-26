from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", "scrypt:32768:8:1$test$test")

from xpanel.db import connect, init_db
from xpanel.node_manager import (
    claim_node_job,
    complete_node_job,
    create_enrollment_token,
    create_node,
    create_node_job,
    list_node_jobs,
    register_node,
)
from xpanel.service import connect_cascade_cluster_node, get_cascade_overview, remove_cascade

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def panel_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,flow,config_path,xray_bin,xray_service,instance_name
            ) VALUES (1,'controller.example','0.0.0.0',443,'www.bing.com:443',
                'www.bing.com','private','public','0011223344556677','firefox',
                'xtls-rprx-vision',?, '/bin/true','xray','Controller')
            """,
            (str(tmp_path / "config.json"),),
        )
    return tmp_path


def _node_config(user_uuid: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "sg-node-reality-in",
            "listen": "0.0.0.0",
            "port": 64441,
            "protocol": "vless",
            "settings": {"clients": [{
                "id": user_uuid,
                "email": "Pilot",
                "flow": "xtls-rprx-vision",
                "level": 0,
            }], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": "www.bing.com:443",
                    "xver": 0,
                    "serverNames": ["www.bing.com"],
                    "privateKey": "private",
                    "shortIds": ["aabbccdd"],
                },
            },
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
    }


def _online_node_with_profile():
    node = create_node("Paris Exit", role="regional", public_address="198.51.100.20")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(
        enrollment["token"],
        agent_id="agent-paris",
        metadata={"public_address": "198.51.100.20", "xray_state": "active"},
    )
    pilot_uuid = "11111111-1111-4111-8111-111111111111"
    config = _node_config(pilot_uuid)
    encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
    link = (
        f"vless://{pilot_uuid}@198.51.100.20:64441"
        "?type=tcp&security=reality&pbk=Public_Key-123&fp=firefox"
        "&sni=www.bing.com&sid=aabbccdd&flow=xtls-rprx-vision&spx=%2F"
        "#Pilot%2FParis%20Exit%2FPrimary"
    )
    job = create_node_job(
        node["id"], job_type="apply_xray_config", title="Pilot",
        payload={
            "profile": "VLESS REALITY",
            "config": config,
            "config_sha256": hashlib.sha256(encoded).hexdigest(),
            "client_count": 1,
        },
        client_link=link,
    )
    claimed = claim_node_job(registered["agent_token"])
    assert claimed and claimed["id"] == job["id"]
    complete_node_job(registered["agent_token"], job["id"], ok=True, result={"message": "ok"})
    return node, registered


def test_cluster_master_is_closed_and_cascade_has_two_modes():
    nodes = (ROOT / "xpanel/templates/nodes.html").read_text(encoding="utf-8")
    cascade = (ROOT / "xpanel/templates/cascade.html").read_text(encoding="utf-8")
    assert 'class="cluster-awg-steps"' in nodes
    assert 'cluster-awg-node-form' in nodes
    assert 'Подготовить чистую Ubuntu как SG-Node' in nodes
    assert "Из Cluster" in cascade
    assert "Другой сервер" in cascade
    assert "cascade_cluster_connect" in cascade
    assert "data-cascade-mode-panel=\"cluster\"" in cascade
    assert "data-cascade-mode-panel=\"external\"" in cascade


def test_cluster_cascade_adds_dedicated_service_client_and_outbound(panel_db):
    node, _ = _online_node_with_profile()
    preview = connect_cascade_cluster_node(node["id"], dry_run=True)
    assert preview["link"].startswith("vless://")
    assert "Cascade" in preview["link"]

    result = connect_cascade_cluster_node(node["id"])
    assert result["configured"] is True
    assert result["mode"] == "cluster"
    assert result["exit_node_id"] == node["id"]
    assert result["exit_name"] == "Paris Exit"
    assert result["enabled"] is False

    jobs = list_node_jobs(node["id"], limit=5)
    queued = jobs[0]
    assert queued["status"] == "queued"
    config = queued["payload"]["config"]
    clients = config["inbounds"][0]["settings"]["clients"]
    cascade_clients = [item for item in clients if str(item.get("email", "")).startswith("Cascade · ")]
    assert len(cascade_clients) == 1
    with connect() as con:
        settings = con.execute("SELECT cluster_service_uuid FROM cascade_settings WHERE id=1").fetchone()
    assert cascade_clients[0]["id"] == settings["cluster_service_uuid"]


def test_cluster_cascade_removal_queues_remote_cleanup(panel_db):
    node, registered = _online_node_with_profile()
    connect_cascade_cluster_node(node["id"])
    claimed = claim_node_job(registered["agent_token"])
    assert claimed and claimed["payload"]["cascade"]["action"] == "upsert"
    complete_node_job(registered["agent_token"], claimed["id"], ok=True, result={"message": "ok"})

    remove_cascade(dry_run=True)
    cleaned = remove_cascade()
    assert cleaned["configured"] is False
    cleanup = list_node_jobs(node["id"], limit=2)[0]
    assert cleanup["status"] == "queued"
    assert cleanup["payload"]["cascade"]["action"] == "remove"
    clients = cleanup["payload"]["config"]["inbounds"][0]["settings"]["clients"]
    assert not any(str(item.get("email", "")).startswith("Cascade · ") for item in clients)
