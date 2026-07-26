from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from jinja2 import Environment

from xpanel import service

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_worker():
    path = ROOT / "node_agent/sg_node_worker.py"
    spec = importlib.util.spec_from_file_location("sg_node_worker_ui19_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ui19_cascade_is_one_click_and_role_based() -> None:
    page = read("xpanel/templates/cascade.html")
    css = read("xpanel/static/fix40-cascade-steps-ui20.css")
    base = read("xpanel/templates/base.html")
    help_page = read("xpanel/templates/help.html")
    Environment().parse(page)
    for marker in (
        "Через какую ноду выходить в интернет?",
        "SG-Panel сама создаст недостающий служебный профиль",
        "Включить Cascade",
        "На каком сервере вы сейчас?",
        "Этот сервер должен быть выходом",
        "К этому серверу подключаются клиенты",
        "Создать ссылку",
        "Подключить Cascade",
        "cascade-node-choice-list",
        "data-cascade-pending",
    ):
        assert marker in page
    assert 'id="cascade-exit-node"' not in page
    assert "<select" not in page
    assert "cascade-role-explainer" not in page
    assert "cascade-external-checklist" not in page
    assert "fix40-cascade-steps-ui20.css" in base
    assert ".cascade-node-choice.is-selected" in css
    assert ".cascade-external-role-grid" in css
    assert "SG-Node уже подключена в Cluster" in help_page
    assert "Сделать этот сервер выходом" not in help_page
    assert "Подключить и проверить" not in help_page


def test_ui19_controller_never_sends_complete_node_config(monkeypatch) -> None:
    import xpanel.node_manager as node_manager

    monkeypatch.setattr(
        node_manager,
        "find_node",
        lambda node_id: {
            "id": node_id,
            "name": "USA-Node",
            "is_local": False,
            "effective_state": "online",
            "public_address": "54.172.225.137",
            "worker_version": "0.7.0",
        },
    )
    monkeypatch.setattr(node_manager, "list_node_jobs", lambda node_id, limit=100: [])
    monkeypatch.setattr(
        service,
        "_cascade_settings_row",
        lambda: {
            "mode": "external",
            "exit_node_id": None,
            "outbound_id": None,
            "cluster_service_uuid": "",
            "cluster_service_job_id": None,
        },
    )
    monkeypatch.setattr(
        service,
        "get_server",
        lambda: {"dest": "www.bing.com:443"},
    )
    monkeypatch.setattr(service, "get_instance_name", lambda: "SG-Panel")

    prepared = service.connect_cascade_cluster_node(17, dry_run=True)
    payload = prepared["payload"]
    assert payload["worker_operation"] == "upsert_cascade_access"
    assert payload["preserve_live_config"] is True
    assert payload["action"] == "upsert"
    assert "config" not in payload
    assert "config_sha256" not in payload


def test_ui19_rejects_old_worker_before_queue(monkeypatch) -> None:
    import xpanel.node_manager as node_manager

    monkeypatch.setattr(
        node_manager,
        "find_node",
        lambda node_id: {
            "id": node_id,
            "name": "Old-Node",
            "is_local": False,
            "effective_state": "online",
            "public_address": "203.0.113.10",
            "worker_version": "0.6.0",
        },
    )
    monkeypatch.setattr(node_manager, "list_node_jobs", lambda node_id, limit=100: [])
    try:
        service._cluster_cascade_node(3)
    except service.XPanelError as exc:
        assert "UI19" in str(exc)
        assert "0.6.0" in str(exc)
    else:
        raise AssertionError("old Worker must be rejected")


def test_ui19_worker_merges_cascade_into_live_config(monkeypatch, tmp_path: Path) -> None:
    worker = load_worker()
    config_path = tmp_path / "config.json"
    original = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "existing-client-in",
            "listen": "0.0.0.0",
            "port": 8444,
            "protocol": "vless",
            "settings": {"clients": [{"id": "existing-client"}]},
            "streamSettings": {"network": "xhttp", "security": "reality"},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "domain": ["example.com"], "outboundTag": "direct"}]},
    }
    config_path.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(worker, "XRAY_CONFIG", config_path)
    monkeypatch.setattr(worker, "CASCADE_STATE", tmp_path / "cascade-access.json")
    monkeypatch.setattr(worker, "_cascade_port_available", lambda port, used: port == 64441)
    monkeypatch.setattr(
        worker,
        "_xray_reality_keypair",
        lambda: {"private_key": "private", "public_key": "public", "short_id": "0011223344556677"},
    )
    captured = {}

    def fake_apply(job_id, config, *, backup_label):
        captured["config"] = config
        captured["backup_label"] = backup_label
        return {"config_sha256": "abc", "backup_path": "/backup"}

    monkeypatch.setattr(worker, "_apply_merged_xray_config", fake_apply)
    result = worker.upsert_cascade_access(
        42,
        {
            "action": "upsert",
            "service_uuid": "11111111-1111-4111-8111-111111111111",
            "controller": "SG-Panel",
            "target": "www.bing.com:443",
            "server_name": "www.bing.com",
            "preferred_ports": [64441],
        },
    )
    candidate = captured["config"]
    assert original["inbounds"][0] == candidate["inbounds"][0]
    dedicated = next(item for item in candidate["inbounds"] if item["tag"] == "sg-cascade-reality-in")
    assert dedicated["port"] == 64441
    assert dedicated["settings"]["clients"][0]["id"] == "11111111-1111-4111-8111-111111111111"
    assert candidate["routing"]["rules"][0]["user"] == ["Cascade · SG-Panel"]
    assert candidate["routing"]["rules"][1] == original["routing"]["rules"][0]
    assert result["public_port"] == 64441
    assert result["public_key"] == "public"
    assert result["worker_version"] == "0.7.0"



def test_ui19_worker_prefers_existing_reality_tcp_without_new_port(monkeypatch, tmp_path: Path) -> None:
    worker = load_worker()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "inbounds": [{
            "tag": "vless-reality-in",
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {"clients": [{"id": "ordinary", "email": "Ordinary"}], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "target": "www.bing.com:443",
                    "serverNames": ["www.bing.com"],
                    "privateKey": "P" * 43,
                    "shortIds": ["0011223344556677"],
                },
            },
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"rules": []},
    }), encoding="utf-8")
    monkeypatch.setattr(worker, "XRAY_CONFIG", config_path)
    monkeypatch.setattr(worker, "CASCADE_STATE", tmp_path / "cascade-access.json")
    monkeypatch.setattr(worker, "_xray_public_from_private", lambda value: "PUBLIC")
    monkeypatch.setattr(worker, "_cascade_port_available", lambda port, used: (_ for _ in ()).throw(AssertionError("new port must not be requested")))
    captured = {}
    monkeypatch.setattr(worker, "_apply_merged_xray_config", lambda job_id, config, *, backup_label: captured.setdefault("config", config) or {})
    result = worker.upsert_cascade_access(50, {
        "action": "upsert",
        "service_uuid": "11111111-1111-4111-8111-111111111111",
        "controller": "SG-Panel",
        "target": "www.bing.com:443",
    })
    candidate = captured["config"]
    assert len(candidate["inbounds"]) == 1
    clients = candidate["inbounds"][0]["settings"]["clients"]
    assert [item["id"] for item in clients] == ["ordinary", "11111111-1111-4111-8111-111111111111"]
    assert result["access_mode"] == "reuse"
    assert result["public_port"] == 443
    assert result["public_key"] == "PUBLIC"
    state = json.loads((tmp_path / "cascade-access.json").read_text(encoding="utf-8"))
    assert state["mode"] == "reuse"
    assert state["inbound_tag"] == "vless-reality-in"
    assert state["private_key"] == ""


def test_ui19_worker_does_not_remove_unrelated_cascade_named_client(monkeypatch, tmp_path: Path) -> None:
    worker = load_worker()
    config_path = tmp_path / "config.json"
    old_uuid = "22222222-2222-4222-8222-222222222222"
    new_uuid = "11111111-1111-4111-8111-111111111111"
    state_path = tmp_path / "cascade-access.json"
    state_path.write_text(json.dumps({
        "format": "sg-cascade-access-v1",
        "service_uuid": old_uuid,
        "service_email": "Cascade · Old Controller",
    }), encoding="utf-8")
    config_path.write_text(json.dumps({
        "inbounds": [{
            "tag": "vless-reality-in",
            "port": 443,
            "protocol": "vless",
            "settings": {"clients": [
                {"id": old_uuid, "email": "Cascade · Old Controller"},
                {"id": "33333333-3333-4333-8333-333333333333", "email": "Cascade · Personal Client"},
            ], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "target": "www.bing.com:443",
                    "serverNames": ["www.bing.com"],
                    "privateKey": "P" * 43,
                    "shortIds": ["0011223344556677"],
                },
            },
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"rules": [
            {"type": "field", "user": ["Cascade · Old Controller"], "outboundTag": "direct"},
            {"type": "field", "user": ["Cascade · Personal Client"], "outboundTag": "direct"},
        ]},
    }), encoding="utf-8")
    monkeypatch.setattr(worker, "XRAY_CONFIG", config_path)
    monkeypatch.setattr(worker, "CASCADE_STATE", state_path)
    monkeypatch.setattr(worker, "_xray_public_from_private", lambda value: "PUBLIC")
    captured = {}
    monkeypatch.setattr(worker, "_apply_merged_xray_config", lambda job_id, config, *, backup_label: captured.setdefault("config", config) or {})
    worker.upsert_cascade_access(51, {
        "action": "upsert",
        "service_uuid": new_uuid,
        "controller": "New Controller",
        "target": "www.bing.com:443",
    })
    clients = captured["config"]["inbounds"][0]["settings"]["clients"]
    assert "33333333-3333-4333-8333-333333333333" in [item["id"] for item in clients]
    assert old_uuid not in [item["id"] for item in clients]
    assert new_uuid in [item["id"] for item in clients]
    users = [rule.get("user") for rule in captured["config"]["routing"]["rules"] if isinstance(rule, dict)]
    assert ["Cascade · Personal Client"] in users
    assert ["Cascade · Old Controller"] not in users


def test_ui19_worker_remove_preserves_everything_else(monkeypatch, tmp_path: Path) -> None:
    worker = load_worker()
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({
            "inbounds": [
                {"tag": "existing", "port": 443},
                {"tag": "sg-cascade-reality-in", "port": 64441},
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
            "routing": {"rules": [
                {"type": "field", "inboundTag": ["sg-cascade-reality-in"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            ]},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "XRAY_CONFIG", config_path)
    monkeypatch.setattr(worker, "CASCADE_STATE", tmp_path / "cascade-access.json")
    captured = {}
    monkeypatch.setattr(
        worker,
        "_apply_merged_xray_config",
        lambda job_id, config, *, backup_label: captured.setdefault("config", config) or {},
    )
    result = worker.upsert_cascade_access(
        43,
        {"action": "remove", "service_uuid": "11111111-1111-4111-8111-111111111111"},
    )
    candidate = captured["config"]
    assert [item["tag"] for item in candidate["inbounds"]] == ["existing"]
    assert candidate["routing"]["rules"] == [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}
    ]
    assert result["action"] == "remove"



def test_ui19_full_panel_reinjects_persistent_node_cascade(monkeypatch, tmp_path: Path) -> None:
    state_path = tmp_path / "cascade-access.json"
    state_path.write_text(json.dumps({
        "format": "sg-cascade-access-v1",
        "port": 64441,
        "service_uuid": "11111111-1111-4111-8111-111111111111",
        "controller": "SG-Panel",
        "target": "www.bing.com:443",
        "server_name": "www.bing.com",
        "private_key": "A" * 43,
        "public_key": "B" * 43,
        "short_id": "0011223344556677",
    }), encoding="utf-8")
    monkeypatch.setattr(service, "CASCADE_NODE_ACCESS_STATE", state_path)
    config = {
        "inbounds": [{"tag": "ordinary", "port": 443}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"rules": [{"type": "field", "domain": ["example.com"], "outboundTag": "direct"}]},
    }
    updated = service._inject_persistent_node_cascade_access(config)
    assert [item["tag"] for item in updated["inbounds"]] == ["ordinary", "sg-cascade-reality-in"]
    assert updated["routing"]["rules"][0]["user"] == ["Cascade · SG-Panel"]
    assert updated["routing"]["rules"][1]["domain"] == ["example.com"]


def test_ui19_external_link_does_not_require_visible_raw_profile() -> None:
    body = read("xpanel/service.py")
    ensure = body.split("def ensure_cascade_service_access", 1)[1].split("CASCADE_NODE_WORKER_MINIMUM", 1)[0]
    assert "inbound_profile" not in ensure
    assert "XTLS Vision" not in ensure
    access = body.split("def _cascade_service_access", 1)[1].split("def ensure_cascade_service_access", 1)[0]
    assert "make_links" in access


def test_ui19_agent_completion_uses_background_finalize() -> None:
    web = read("xpanel/web.py")
    assert "threading.Thread(" in web
    assert "cascade-finalize-" in web
    assert "finalize_cascade_cluster_job(int(completed_job_id))" in web
    assert "Agent's 20-second HTTP timeout" in web


def test_ui19_same_update_refreshes_connected_node_runtime() -> None:
    upgrade = read("install-or-upgrade.sh")
    assert "node_runtime_stage" in upgrade
    assert 'install -D -o root -g root -m 0755 "$TARGET/node_agent/sg_node_worker.py" /usr/local/libexec/sg-node-worker.py' in upgrade
    assert "systemctl restart sg-node-worker.service" in upgrade
    assert "systemctl restart sg-node-agent.service" in upgrade


def test_ui19_node_title_has_country_flag_and_dead_confirm_is_removed() -> None:
    detail = read("xpanel/templates/node_detail.html")
    assert "node-title-with-flag" in detail
    assert "node.country_code" in detail
    assert "data-node-deploy-submit" in detail
    assert "data-confirm-button=" not in detail
