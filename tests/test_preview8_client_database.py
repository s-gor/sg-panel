from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.node_manager import (
    attach_failover_job,
    claim_node_job,
    complete_node_job,
    create_enrollment_token,
    create_failover_batch,
    create_node,
    create_node_job,
    find_failover_batch,
    list_node_deployments,
    list_node_jobs,
    list_user_deployments,
    register_node,
    update_deployment_policy,
)
from xpanel.service import (
    add_user,
    create_backup,
    make_cluster_links,
    regenerate_user_uuid,
    update_user_connection_order_mode,
)
from xpanel.web import create_app


@pytest.fixture()
def panel_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    monkeypatch.setenv("XPANEL_BACKUP_DIR", str(tmp_path / "backups"))
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


def _login(client):
    response = client.post("/login", data={"password": "correct-password"})
    assert response.status_code == 302
    with client.session_transaction() as session:
        return session["csrf_token"]


def _node_config(users: list[tuple[str, str]]) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "sg-node-reality-in",
            "listen": "0.0.0.0",
            "port": 64441,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {"id": uuid, "email": name, "flow": "xtls-rprx-vision", "level": 0}
                    for uuid, name in users
                ],
                "decryption": "none",
            },
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


def _online_node(name: str = "Paris Backup"):
    node = create_node(name, role="backup", public_address="198.51.100.20")
    enrollment = create_enrollment_token(node["id"])
    registered = register_node(
        enrollment["token"],
        agent_id=f"agent-{node['id']}",
        metadata={"public_address": "198.51.100.20", "xray_state": "active"},
    )
    return node, registered


def _complete_first_deployment(node, registered, user, slot="backup"):
    config = _node_config([(str(user["uuid"]), str(user["name"]))])
    encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode()
    link = (
        f"vless://{user['uuid']}@198.51.100.20:64441"
        "?type=tcp&security=reality&pbk=Public_Key-123&fp=firefox"
        "&sni=www.bing.com&sid=aabbccdd&flow=xtls-rprx-vision&spx=%2F"
        f"#{user['name']}%2FParis%2FBackup"
    )
    job = create_node_job(
        node["id"], job_type="apply_xray_config", title="Initial",
        payload={
            "profile": "VLESS REALITY",
            "config": config,
            "config_sha256": hashlib.sha256(encoded).hexdigest(),
            "client_count": 1,
            "deployments": [{
                "action": "upsert", "user_id": int(user["id"]),
                "user_uuid": str(user["uuid"]), "user_name": str(user["name"]),
                "profile": "VLESS REALITY", "public_host": "198.51.100.20",
                "public_port": 64441, "client_link": link, "slot": slot,
                "subscription_enabled": True, "desired_state": "active",
            }],
        },
        client_link=link,
    )
    assert claim_node_job(registered["agent_token"])["id"] == job["id"]
    complete_node_job(registered["agent_token"], job["id"], ok=True, result={"message": "ok"})
    return job


def test_new_client_has_central_controller_deployment(panel_db):
    user = add_user("Central Client")
    deployments = list_user_deployments(user["id"])
    assert len(deployments) == 1
    local = deployments[0]
    assert local["node_is_local"] == 1
    assert local["slot"] == "primary"
    assert local["state"] == "active"
    assert local["subscription_enabled"] is True


def test_remote_primary_demotes_controller_and_survives_init(panel_db):
    user = add_user("Failover Client")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    remote = next(item for item in list_user_deployments(user["id"]) if not item["node_is_local"])
    update_user_connection_order_mode(user["id"], "manual")
    update_deployment_policy(remote["id"], slot="primary", subscription_enabled=True)
    deployments = list_user_deployments(user["id"])
    assert [item["slot"] for item in deployments] == ["primary", "backup"]
    assert deployments[0]["node_id"] == node["id"]
    init_db()
    deployments = list_user_deployments(user["id"])
    assert deployments[0]["node_id"] == node["id"]
    assert next(item for item in deployments if item["node_is_local"])["slot"] == "backup"


def test_cluster_subscription_orders_remote_primary_before_controller(panel_db):
    user = add_user("Subscription Failover")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    remote = next(item for item in list_user_deployments(user["id"]) if not item["node_is_local"])
    update_user_connection_order_mode(user["id"], "manual")
    update_deployment_policy(remote["id"], slot="primary", subscription_enabled=True)
    links = make_cluster_links(user["id"])
    assert links[0]["source"] == "sg-node"
    assert links[0]["deployment_slot"] == "primary"
    assert any(item["source"] == "controller" and item["deployment_slot"] == "backup" for item in links)


def test_connection_order_mode_is_independent_per_client(panel_db):
    automatic = add_user("Automatic Client")
    manual = add_user("Manual Client")
    automatic_node, automatic_registered = _online_node("Automatic Node")
    manual_node, manual_registered = _online_node("Manual Node")
    _complete_first_deployment(automatic_node, automatic_registered, automatic)
    _complete_first_deployment(manual_node, manual_registered, manual)

    automatic_remote = next(
        item for item in list_user_deployments(automatic["id"]) if not item["node_is_local"]
    )
    manual_remote = next(
        item for item in list_user_deployments(manual["id"]) if not item["node_is_local"]
    )
    update_deployment_policy(automatic_remote["id"], slot="primary", subscription_enabled=True)
    update_deployment_policy(manual_remote["id"], slot="primary", subscription_enabled=True)
    update_user_connection_order_mode(manual["id"], "manual")

    automatic_links = make_cluster_links(automatic["id"])
    manual_links = make_cluster_links(manual["id"])

    assert automatic_links[0]["source"] == "controller"
    assert automatic_links[0]["deployment_slot_label"] == "Автоматически"
    assert manual_links[0]["source"] == "sg-node"
    assert manual_links[0]["deployment_slot_label"] == "Основное"


def test_uuid_rotation_disables_stale_remote_deployment(panel_db):
    user = add_user("Rotate Client")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    rotated = regenerate_user_uuid(user["id"], "22222222-2222-4222-8222-222222222222")
    deployments = list_user_deployments(rotated["id"], include_removed=True)
    local = next(item for item in deployments if item["node_is_local"])
    remote = next(item for item in deployments if not item["node_is_local"])
    assert local["user_uuid"] == rotated["uuid"]
    assert local["state"] == "active"
    assert local["slot"] == "primary"
    assert remote["state"] == "error"
    assert remote["subscription_enabled"] is False


def test_multi_deployment_job_and_batch_complete_together(panel_db):
    first = add_user("One")
    second = add_user("Two")
    node, registered = _online_node()
    config = _node_config([(str(first["uuid"]), str(first["name"])), (str(second["uuid"]), str(second["name"]))])
    batch = create_failover_batch(target_node_id=node["id"], user_ids=[first["id"], second["id"]], mode="prepare_backup")
    deployments = []
    for user in (first, second):
        link = f"vless://{user['uuid']}@198.51.100.20:64441?type=tcp&security=reality&pbk=x#{user['name']}"
        deployments.append({
            "action": "upsert", "user_id": int(user["id"]), "user_uuid": str(user["uuid"]),
            "user_name": str(user["name"]), "profile": "VLESS REALITY",
            "public_host": "198.51.100.20", "public_port": 64441,
            "client_link": link, "slot": "backup", "subscription_enabled": True,
        })
    job = create_node_job(node["id"], job_type="apply_xray_config", title="Batch", payload={"config": config, "deployments": deployments})
    attach_failover_job(batch["id"], job["id"])
    assert len(list_node_deployments(node["id"])) == 2
    claim_node_job(registered["agent_token"])
    complete_node_job(registered["agent_token"], job["id"], ok=True, result={"message": "all good"})
    assert all(item["state"] == "active" for item in list_node_deployments(node["id"]))
    completed = find_failover_batch(batch["id"])
    assert completed["status"] == "succeeded"
    assert completed["succeeded_clients"] == 2


def test_clients_and_cluster_show_central_database_ui(panel_db):
    user = add_user("UI Client")
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    _login(client)
    users_page = client.get(f"/users?client={user['id']}")
    assert users_page.status_code == 200
    body = users_page.get_data(as_text=True)
    assert "Доступные точки" in body
    assert "Controller хранит одну запись клиента" in body
    cluster = client.get("/network/nodes")
    assert cluster.status_code == 200
    cluster_body = cluster.get_data(as_text=True)
    assert "ЕДИНАЯ БАЗА CLIENTS" not in cluster_body
    assert "стабильную подписку" not in cluster_body
    assert "Открыть Clients" in cluster_body


def test_bulk_route_merges_clients_without_replacing_existing(panel_db):
    first = add_user("Existing")
    second = add_user("New Client")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, first)
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = _login(client)
    response = client.post(
        f"/network/nodes/{node['id']}/clients/deploy",
        data={
            "csrf_token": csrf,
            "mode": "prepare_backup",
            "user_ids": [str(second["id"])],
            "public_host": "198.51.100.20",
            "port": "64441",
            "dest": "www.bing.com:443",
            "server_name": "www.bing.com",
        },
    )
    assert response.status_code == 302
    job = list_node_jobs(node["id"])[0]
    clients = job["payload"]["config"]["inbounds"][0]["settings"]["clients"]
    assert {item["id"] for item in clients} == {str(first["uuid"]), str(second["uuid"])}
    assert len(job["payload"]["deployments"]) == 1


def test_disabled_client_keeps_controller_deployment_on_standby(panel_db):
    from xpanel.service import set_user_enabled

    user = add_user("Standby Client")
    set_user_enabled(user["id"], False)
    init_db()
    deployment = next(item for item in list_user_deployments(user["id"]) if item["node_is_local"])
    assert deployment["state"] == "active"
    assert deployment["desired_state"] == "standby"


def test_unverified_deployment_cannot_become_primary(panel_db):
    user = add_user("Pending Client")
    node, _registered = _online_node()
    with connect() as con:
        cursor = con.execute(
            """
            INSERT INTO node_deployments
                (node_id, user_id, user_uuid, user_name, state, slot, priority)
            VALUES (?, ?, ?, ?, 'pending', 'backup', 20)
            """,
            (node["id"], user["id"], user["uuid"], user["name"]),
        )
        deployment_id = int(cursor.lastrowid)
    with pytest.raises(ValueError, match="проверенное активное"):
        update_deployment_policy(deployment_id, slot="primary", subscription_enabled=True)


def test_subscription_visibility_can_hide_controller_endpoint(panel_db):
    user = add_user("Remote Only")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    deployments = list_user_deployments(user["id"])
    local = next(item for item in deployments if item["node_is_local"])
    update_deployment_policy(local["id"], slot="backup", subscription_enabled=False)
    links = make_cluster_links(user["id"])
    assert links
    assert all(item["source"] == "sg-node" for item in links)


def test_managed_v2_uses_remote_reality_credentials(panel_db):
    from xpanel.service import managed_client_export_v2

    user = add_user("Managed Remote")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    remote = next(item for item in list_user_deployments(user["id"]) if not item["node_is_local"])
    update_deployment_policy(remote["id"], slot="primary", subscription_enabled=True)
    document = managed_client_export_v2(user["id"])
    remote_connection = next(
        item for item in document["connections"]
        if item["deployment"]["source"] == "sg-node"
    )
    assert remote_connection["reality"]["publicKey"] == "Public_Key-123"
    assert remote_connection["reality"]["shortId"] == "aabbccdd"
    assert remote_connection["reality"]["serverName"] == "www.bing.com"
    assert remote_connection["reality"]["source"] == "SG-Node deployment"


def test_preview7_database_migrates_deployment_columns(tmp_path, monkeypatch):
    import sqlite3

    path = tmp_path / "preview7.db"
    with sqlite3.connect(path) as con:
        # Preview 7 already had this table without failover policy columns.
        # Referenced tables may be created later by the current SCHEMA.
        con.executescript(
            """
            CREATE TABLE node_deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id INTEGER NOT NULL,
                user_id INTEGER,
                user_uuid TEXT NOT NULL,
                user_name TEXT NOT NULL DEFAULT '',
                profile TEXT NOT NULL DEFAULT '',
                public_host TEXT NOT NULL DEFAULT '',
                public_port INTEGER,
                client_link TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'pending',
                last_job_id INTEGER,
                last_message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (node_id, user_uuid)
            );
            """
        )
    monkeypatch.setenv("XPANEL_DB", str(path))
    init_db()
    with sqlite3.connect(path) as con:
        columns = {row[1] for row in con.execute("PRAGMA table_info(node_deployments)")}
        indexes = {row[1] for row in con.execute("PRAGMA index_list(node_deployments)")}
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"slot", "priority", "subscription_enabled", "desired_state", "last_verified_at"} <= columns
    assert "idx_node_deployments_user_slot" in indexes
    assert {"client_failover_batches", "client_failover_targets"} <= tables


def test_backup_contains_central_deployments_and_failover_history(panel_db, monkeypatch):
    import sqlite3
    from xpanel.service import backup_file, create_backup

    monkeypatch.setenv("XPANEL_BACKUP_DIR", str(panel_db / "backups"))
    user = add_user("Backup Central")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    batch = create_failover_batch(target_node_id=node["id"], user_ids=[user["id"]], mode="prepare_backup")
    backup = create_backup()
    with sqlite3.connect(backup_file(backup["name"], "db")) as con:
        deployment_count = con.execute("SELECT COUNT(*) FROM node_deployments WHERE user_id=?", (user["id"],)).fetchone()[0]
        batch_count = con.execute("SELECT COUNT(*) FROM client_failover_batches WHERE id=?", (batch["id"],)).fetchone()[0]
    assert deployment_count == 2
    assert batch_count == 1
    assert backup["verified"] is True


def test_failed_bulk_job_closes_failover_batch(panel_db):
    from xpanel.node_manager import list_failover_batches

    user = add_user("Busy Node Client")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user)
    create_node_job(
        node["id"], job_type="apply_xray_config", title="Busy",
        payload={"config": _node_config([(str(user["uuid"]), str(user["name"]))])},
    )
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = _login(client)
    response = client.post(
        f"/network/nodes/{node['id']}/clients/deploy",
        data={
            "csrf_token": csrf,
            "mode": "prepare_backup",
            "public_host": "198.51.100.20",
            "port": "64441",
            "dest": "www.bing.com:443",
            "server_name": "www.bing.com",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    batch = list_failover_batches(limit=1)[0]
    assert batch["status"] == "failed"
    assert batch["failed_clients"] == 1
    assert "уже выполняется другое задание" in batch["summary"]


def test_preview7_database_migrates_before_new_deployment_index(tmp_path, monkeypatch):
    database = tmp_path / "legacy-panel.db"
    monkeypatch.setenv("XPANEL_DB", str(database))
    monkeypatch.setenv("XPANEL_BACKUP_DIR", str(tmp_path / "backups"))
    with sqlite3.connect(database) as con:
        con.execute(
            """
            CREATE TABLE node_deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id INTEGER NOT NULL,
                user_id INTEGER,
                user_uuid TEXT NOT NULL,
                user_name TEXT NOT NULL DEFAULT '',
                profile TEXT NOT NULL DEFAULT '',
                public_host TEXT NOT NULL DEFAULT '',
                public_port INTEGER,
                client_link TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'pending',
                last_job_id INTEGER,
                last_message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (node_id, user_uuid)
            )
            """
        )
    init_db()
    with sqlite3.connect(database) as con:
        columns = {row[1] for row in con.execute("PRAGMA table_info(node_deployments)")}
        indexes = {row[1] for row in con.execute("PRAGMA index_list(node_deployments)")}
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"slot", "priority", "subscription_enabled", "desired_state", "last_verified_at"} <= columns
    assert "idx_node_deployments_user_slot" in indexes
    assert {"client_failover_batches", "client_failover_targets"} <= tables


def test_last_active_subscription_endpoint_cannot_be_hidden(panel_db):
    user = add_user("Only Endpoint")
    local = list_user_deployments(user["id"])[0]
    with pytest.raises(ValueError, match="последний активный endpoint"):
        update_deployment_policy(local["id"], slot="backup", subscription_enabled=False)
    current = list_user_deployments(user["id"])[0]
    assert current["subscription_enabled"] is True


def test_backup_manifest_records_central_client_database(panel_db):
    add_user("Backup Client")
    backup = create_backup()
    central = backup["central_client_database"]
    assert central["clients"] == 1
    assert central["deployments"] == 1
    assert central["failover_batches"] == 0


def test_bulk_deployment_records_verified_safety_backup(panel_db):
    user = add_user("Backup Before Batch")
    node, _registered = _online_node()
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = _login(client)
    response = client.post(
        f"/network/nodes/{node['id']}/clients/deploy",
        data={
            "csrf_token": csrf,
            "mode": "prepare_backup",
            "user_ids": [str(user["id"])],
            "public_host": "198.51.100.20",
            "port": "64441",
            "dest": "www.bing.com:443",
            "server_name": "www.bing.com",
        },
    )
    assert response.status_code == 302
    batch = find_failover_batch(1)
    assert batch["details"]["safety_backup"].startswith("sg-panel-")
    assert batch["details"]["safety_backup_verified"] is True


def test_redeploy_after_uuid_rotation_removes_stale_node_credential(panel_db):
    user = add_user("Rotate And Redeploy")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user, slot="primary")
    old_uuid = str(user["uuid"])
    rotated = regenerate_user_uuid(user["id"], "33333333-3333-4333-8333-333333333333")

    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "PASSWORD_HASH": generate_password_hash("correct-password")})
    client = app.test_client()
    csrf = _login(client)
    response = client.post(
        f"/users/{rotated['id']}/deploy",
        data={
            "csrf_token": csrf,
            "node_id": str(node["id"]),
            "slot": "primary",
            "public_host": "198.51.100.20",
            "port": "64441",
            "dest": "www.bing.com:443",
            "server_name": "www.bing.com",
        },
    )
    assert response.status_code == 302
    job = list_node_jobs(node["id"])[0]
    clients = job["payload"]["config"]["inbounds"][0]["settings"]["clients"]
    assert {item["id"] for item in clients} == {str(rotated["uuid"])}
    actions = {(item["action"], item["user_uuid"]) for item in job["payload"]["deployments"]}
    assert ("remove", old_uuid) in actions
    assert ("upsert", str(rotated["uuid"])) in actions

    assert claim_node_job(registered["agent_token"])["id"] == job["id"]
    complete_node_job(registered["agent_token"], job["id"], ok=True, result={"message": "rotated"})
    deployments = list_user_deployments(rotated["id"], include_removed=True)
    stale = next(item for item in deployments if item["user_uuid"] == old_uuid)
    current = next(item for item in deployments if item["user_uuid"] == str(rotated["uuid"]) and not item["node_is_local"])
    local = next(item for item in deployments if item["node_is_local"])
    assert stale["state"] == "removed"
    assert current["state"] == "active"
    assert current["slot"] == "backup"
    assert local["slot"] == "primary"


def test_disable_and_reenable_require_explicit_remote_redeployment(panel_db):
    from xpanel.service import set_user_enabled

    user = add_user("Remote Disable")
    node, registered = _online_node()
    _complete_first_deployment(node, registered, user, slot="primary")

    disabled = set_user_enabled(user["id"], False)
    assert disabled["enabled"] == 0
    deployments = list_user_deployments(user["id"], include_removed=True)
    remote = next(item for item in deployments if not item["node_is_local"])
    local = next(item for item in deployments if item["node_is_local"])
    assert remote["state"] == "error"
    assert remote["desired_state"] == "standby"
    assert remote["subscription_enabled"] is False
    assert "raw-профиль требует синхронизации" in remote["last_message"]
    assert local["desired_state"] == "standby"

    enabled = set_user_enabled(user["id"], True)
    assert enabled["enabled"] == 1
    deployments = list_user_deployments(user["id"], include_removed=True)
    remote = next(item for item in deployments if not item["node_is_local"])
    local = next(item for item in deployments if item["node_is_local"])
    assert local["desired_state"] == "active"
    assert remote["state"] == "error"
    assert remote["desired_state"] == "standby"
    assert remote["subscription_enabled"] is False
    assert "требуется повторное развёртывание" in remote["last_message"]
