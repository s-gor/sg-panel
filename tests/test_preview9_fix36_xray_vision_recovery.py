from __future__ import annotations

import base64
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from xpanel import node_manager, service
from xpanel.db import connect, init_db
from xpanel.xray_encryption import build_mlkem_pair, client_value_ready

ROOT = Path(__file__).resolve().parents[1]


def _pair() -> dict[str, str]:
    seed = base64.urlsafe_b64encode(b"S" * 32).decode().rstrip("=")
    client = base64.urlsafe_b64encode(b"C" * 160).decode().rstrip("=")
    encryption, decryption = build_mlkem_pair(seed, client)
    return {
        "encryption": encryption,
        "decryption": decryption,
        "generation": "fix36-test",
        "checked_at": "now",
    }


def _setup(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    monkeypatch.setenv(
        "XPANEL_XRAY_ENCRYPTION_SECRET", str(tmp_path / "xray-secrets.env")
    )
    init_db()
    pair = _pair()
    monkeypatch.setattr(service, "_controller_vless_encryption_pair", lambda: pair)
    monkeypatch.setattr(
        service, "ensure_controller_xray_encryption", lambda force=False: pair
    )
    monkeypatch.setattr(
        service,
        "controller_xray_encryption_status",
        lambda: {
            "ready": True,
            "version": "v26.6.27",
            "minimum": "v26.6.27",
            "server_mode": "auto",
            "client_mode": "stream-one",
            "generation": pair["generation"],
        },
    )
    monkeypatch.setattr(
        service,
        "_always_on_https_material",
        lambda _server: {
            "ready": False,
            "domain": "",
            "cert": "",
            "key": "",
            "message": "not configured",
        },
    )
    monkeypatch.setattr(
        service,
        "_run",
        lambda *args, **kwargs: type(
            "Result", (), {"returncode": 1, "stdout": "", "stderr": ""}
        )(),
    )
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,flow,config_path,xray_bin,xray_service
            ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "203.0.113.10",
                "0.0.0.0",
                443,
                "www.bing.com:443",
                "www.bing.com",
                "private",
                "controller-public",
                "0123456789abcdef",
                "firefox",
                "xtls-rprx-vision",
                str(tmp_path / "config.json"),
                "/bin/true",
                "xray",
            ),
        )
    return pair


def test_xray_server_page_exposes_fixed_vision_contract() -> None:
    text = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    for expected in (
        "Четыре независимых канала",
        "VLESS Encryption",
        "ML-KEM-768",
        "XTLS Vision",
        "Server mode",
        "auto",
        "Client mode",
        "stream-one",
        'name="flow" value="xtls-rprx-vision"',
        'name="xhttp_reality_mode" value="stream-one"',
    ):
        assert expected in text
    assert "Выбор серверной схемы" not in text
    assert "Выбор карточки ещё не переключает сервер" not in text


def test_always_on_config_and_device_links_use_mlkem_and_vision(tmp_path, monkeypatch) -> None:
    pair = _setup(tmp_path, monkeypatch)
    person = service.add_user("Alice")
    phone = service.add_device(int(person["id"]), name="Телефон")
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("CERT", encoding="utf-8")
    key.write_text("KEY", encoding="utf-8")
    monkeypatch.setattr(
        service,
        "_always_on_https_material",
        lambda _server: {
            "ready": True,
            "domain": "vpn.example.com",
            "cert": str(cert),
            "key": str(key),
            "message": "ready",
        },
    )

    config, _server, _accesses = service.build_config()
    by_tag = {item["tag"]: item for item in config["inbounds"]}
    assert {
        "vless-reality-in",
        "sg-vless-xhttp-reality",
        "sg-vless-xhttp-tls",
        "sg-hysteria2",
    }.issubset(by_tag)

    raw = by_tag["vless-reality-in"]
    assert raw["settings"]["decryption"] == "none"
    assert raw["settings"]["clients"][1]["id"] == str(phone["uuid"])
    assert raw["settings"]["clients"][1]["flow"] == "xtls-rprx-vision"

    xhttp = by_tag["sg-vless-xhttp-reality"]
    assert xhttp["settings"]["decryption"] == pair["decryption"]
    assert xhttp["settings"]["clients"][1]["id"] == str(phone["uuid"])
    assert xhttp["settings"]["clients"][1]["flow"] == "xtls-rprx-vision"
    assert xhttp["streamSettings"]["network"] == "xhttp"
    assert xhttp["streamSettings"]["xhttpSettings"]["mode"] == "auto"

    links = service.make_links(
        int(person["id"]), device_id=int(phone["id"])
    )
    reality = next(item for item in links if item["profile"] == "xhttp_reality")
    parsed = urlsplit(str(reality["link"]))
    query = parse_qs(parsed.query)
    assert parsed.username == str(phone["uuid"])
    assert query["flow"] == ["xtls-rprx-vision"]
    assert query["mode"] == ["stream-one"]
    assert query["encryption"] == [pair["encryption"]]
    assert client_value_ready(query["encryption"][0])

    export = service.managed_client_export_v2(
        int(person["id"]), device_id=int(phone["id"])
    )
    assert export["user"]["uuid"] == str(phone["uuid"])
    assert export["user"]["deviceId"] == int(phone["id"])
    assert export["server"]["channelModel"] == "sg-gateway-always-on-v1"


def test_node_deployment_keeps_device_uuid_and_builds_xhttp_link(tmp_path, monkeypatch) -> None:
    _setup(tmp_path, monkeypatch)
    with connect() as con:
        con.execute(
            """
            INSERT INTO nodes(
                name,slug,role,is_local,state,public_address,xray_version,
                xray_state,last_seen_at
            ) VALUES('Node Paris','node-paris','regional',0,'online',
                     '198.51.100.8','26.6.27','active',CURRENT_TIMESTAMP)
            """
        )
        node_id = int(
            con.execute("SELECT id FROM nodes WHERE slug='node-paris'").fetchone()["id"]
        )
    person = service.add_user("Alice")
    phone = service.add_device(int(person["id"]), name="Телефон")
    payload = {
        "deployments": [
            {
                "action": "upsert",
                "user_id": int(person["id"]),
                "device_id": int(phone["id"]),
                "device_uuid": str(phone["uuid"]),
                "device_name": str(phone["name"]),
                "user_uuid": str(phone["uuid"]),
                "user_name": "Alice",
                "profile": "VLESS XHTTP REALITY",
                "public_host": "198.51.100.8",
                "public_port": 64441,
                "client_link": "",
                "reality_public_key": "node-public",
                "reality_short_id": "1234567890abcdef",
                "reality_server_name": "node.example.com",
                "xhttp_path": "/sg-xhttp-reality",
                "xhttp_server_mode": "auto",
                "xhttp_client_mode": "stream-one",
                "slot": "backup",
                "priority": 20,
                "subscription_enabled": True,
                "desired_state": "active",
            }
        ]
    }
    job = {"id": 1, "node_id": node_id, "payload": payload, "result": {}}
    with connect() as con:
        con.execute(
            "INSERT INTO node_jobs(id,node_id,job_type,status,title,payload_json) "
            "VALUES(1,?,'apply_xray_config','queued','test','{}')",
            (node_id,),
        )
    node_manager._record_deployment_job(job)
    node_pair = _pair()
    job["result"] = {
        "client_encryption": node_pair["encryption"],
        "encryption_generation": "node-generation",
        "encryption_checked_at": "now",
        "xray_minimum_supported": "v26.6.27",
        "xhttp_server_mode": "auto",
        "xhttp_client_mode": "stream-one",
    }
    node_manager._complete_deployment_job(job, ok=True, message="ok")
    with connect() as con:
        row = con.execute(
            "SELECT * FROM node_deployments WHERE node_id=? AND device_id=?",
            (node_id, int(phone["id"])),
        ).fetchone()
    assert row is not None
    assert row["user_uuid"] == str(phone["uuid"])
    assert row["device_uuid"] == str(phone["uuid"])
    assert row["state"] == "active"
    query = parse_qs(urlsplit(str(row["client_link"])).query)
    assert query["type"] == ["xhttp"]
    assert query["flow"] == ["xtls-rprx-vision"]
    assert query["mode"] == ["stream-one"]
    assert query["encryption"] == [node_pair["encryption"]]


def test_remote_node_xhttp_metadata_is_exported_from_node_not_controller(tmp_path, monkeypatch) -> None:
    pair = _setup(tmp_path, monkeypatch)
    with connect() as con:
        con.execute(
            """
            INSERT INTO nodes(
                name,slug,role,is_local,state,public_address,xray_version,
                xray_state,last_seen_at
            ) VALUES('Node Paris','node-paris','regional',0,'online',
                     '198.51.100.8','26.6.27','active',CURRENT_TIMESTAMP)
            """
        )
        node_id = int(
            con.execute("SELECT id FROM nodes WHERE slug='node-paris'").fetchone()["id"]
        )
    person = service.add_user("Alice")
    phone = service.add_device(int(person["id"]), name="Телефон")
    params = {
        "encryption": pair["encryption"],
        "flow": "xtls-rprx-vision",
        "type": "xhttp",
        "security": "reality",
        "pbk": "node-public",
        "fp": "firefox",
        "sni": "node.example.com",
        "sid": "1234567890abcdef",
        "path": "/sg-xhttp-reality",
        "mode": "stream-one",
        "spx": "/",
    }
    link = (
        f"vless://{phone['uuid']}@198.51.100.8:64441?"
        f"{urlencode(params)}#Alice%2FTelefon"
    )
    with connect() as con:
        con.execute(
            """
            INSERT INTO node_deployments(
                node_id,user_id,device_id,user_uuid,device_uuid,user_name,
                device_name,profile,public_host,public_port,client_link,state,
                slot,priority,subscription_enabled,desired_state,
                client_encryption,reality_public_key,reality_short_id,
                reality_server_name,xhttp_path,xhttp_server_mode,
                xhttp_client_mode,encryption_generation,export_ready,last_verified_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,CURRENT_TIMESTAMP)
            """,
            (
                node_id,
                int(person["id"]),
                int(phone["id"]),
                str(phone["uuid"]),
                str(phone["uuid"]),
                "Alice",
                "Телефон",
                "VLESS XHTTP REALITY",
                "198.51.100.8",
                64441,
                link,
                "active",
                "backup",
                20,
                1,
                "active",
                pair["encryption"],
                "node-public",
                "1234567890abcdef",
                "node.example.com",
                "/sg-xhttp-reality",
                "auto",
                "stream-one",
                "node-generation",
            ),
        )

    links = service.make_cluster_links(
        int(person["id"]), device_id=int(phone["id"])
    )
    remote = next(item for item in links if item.get("source") == "sg-node")
    assert remote["profile"] == "xhttp_reality"
    assert remote["remote_transport"] == "xhttp"

    export = service.managed_client_export_v2(
        int(person["id"]), device_id=int(phone["id"])
    )
    connection = next(
        item
        for item in export["connections"]
        if item.get("deployment", {}).get("source") == "sg-node"
    )
    assert connection["profile"] == "xhttp_reality"
    assert connection["flow"] == {
        "value": "xtls-rprx-vision",
        "source": "SG-Node deployment",
    }
    assert connection["vlessEncryption"]["ready"] is True
    assert connection["vlessEncryption"]["source"] == "SG-Node deployment"
    assert connection["xhttp"]["mode"] == "stream-one"
    assert connection["xhttp"]["serverMode"] == "auto"
    assert connection["reality"]["publicKey"] == "node-public"


def test_upgrade_preserves_active_xhttp_reality_port_and_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "legacy-panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,flow,config_path,xray_bin,xray_service,
                inbound_profile,transport_port,xhttp_path,xhttp_mode,xhttp_client_mode
            ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "54.93.213.239",
                "0.0.0.0",
                443,
                "www.bing.com:443",
                "www.bing.com",
                "private",
                "public",
                "0123456789abcdef",
                "firefox",
                "xtls-rprx-vision",
                str(tmp_path / "config.json"),
                "/usr/local/bin/xray",
                "xray",
                "xhttp_reality",
                8445,
                "/existing-xhttp-path",
                "auto",
                "stream-one",
            ),
        )
        con.execute(
            "UPDATE xhttp_inbounds SET port=8445,path='/legacy-tls-path' WHERE id=1"
        )
    channels = service.get_xray_channels_settings()
    assert channels["xhttp_reality_port"] == 443
    assert channels["xhttp_reality_path"] == "/existing-xhttp-path"
    assert channels["xhttp_reality_mode"] == "stream-one"
    assert channels["reality_tcp_port"] != 443
    assert channels["xhttp_tls_port"] not in {
        channels["reality_tcp_port"], channels["xhttp_reality_port"]
    }


def test_upgrade_backup_and_rollback_include_controller_mlkem_secret() -> None:
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "OLD_XRAY_SECRET_EXISTS=0" in script
    assert 'cp -a /etc/xpanel-mvp/xray-secrets.env "$BACKUP_ROOT/xray-secrets.env"' in script
    assert 'cp -a "$BACKUP_ROOT/xray-secrets.env" /etc/xpanel-mvp/xray-secrets.env' in script
    assert "chmod 0600 /etc/xpanel-mvp/xray-secrets.env" in script


def test_upgrade_enforces_minimum_xray_before_mlkem_apply() -> None:
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "source deploy/xray-version.env" in script
    assert 'XPANEL_XRAY_UPDATE_VERSION="$required"' in script
    assert "bash deploy/update-xray.sh" in script
    assert "ML-KEM-768" in script
    assert script.index("bash deploy/update-xray.sh") < script.index(".venv/bin/python -m xpanel apply")
