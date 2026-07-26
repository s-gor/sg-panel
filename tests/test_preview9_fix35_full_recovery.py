from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
from pathlib import Path

from xpanel.db import connect, init_db
from xpanel import service
from xpanel.xray_encryption import build_mlkem_pair

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8", errors="replace")


def seed_server(tmp_path: Path) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,
                private_key,public_key,short_id,fingerprint,
                config_path,xray_bin,xray_service
            ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "192.0.2.10", "0.0.0.0", 443,
                "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "firefox",
                str(tmp_path / "config.json"), "/bin/true", "xray",
            ),
        )
        con.execute(
            "UPDATE subscription_settings "
            "SET enabled=1, base_url='https://panel.example' WHERE id=1"
        )


def setup_catalogue(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    monkeypatch.setenv("XPANEL_XRAY_ENCRYPTION_SECRET", str(tmp_path / "xray-secrets.env"))
    init_db()
    seed_server(tmp_path)
    seed = base64.urlsafe_b64encode(b"S" * 32).decode().rstrip("=")
    client = base64.urlsafe_b64encode(b"C" * 160).decode().rstrip("=")
    encryption, decryption = build_mlkem_pair(seed, client)
    pair = {"encryption": encryption, "decryption": decryption, "generation": "test", "checked_at": "now"}
    monkeypatch.setattr(service, "_controller_vless_encryption_pair", lambda: pair)
    monkeypatch.setattr(service, "ensure_controller_xray_encryption", lambda force=False: pair)
    monkeypatch.setattr(service, "controller_xray_encryption_status", lambda: {
        "ready": True, "version": "v26.6.27", "minimum": "v26.6.27",
        "server_mode": "auto", "client_mode": "stream-one",
    })
    monkeypatch.setattr(service, "_always_on_https_material", lambda server: {
        "ready": False, "domain": "", "cert": "", "key": "", "message": "not configured",
    })
    person = service.add_user("Sergey")
    primary = service.find_device(int(person["id"]))
    phone = service.add_device(int(person["id"]), name="Телефон")
    laptop = service.add_device(int(person["id"]), name="Ноутбук")
    return person, primary, phone, laptop


def test_legacy_user_migrates_to_one_primary_access_without_rotating_secrets(tmp_path, monkeypatch) -> None:
    db = tmp_path / "legacy.db"
    token = "legacy_subscription_token_1234567890"
    with sqlite3.connect(db) as con:
        con.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                uuid TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                comment TEXT NOT NULL DEFAULT '',
                expiry_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                subscription_enabled INTEGER NOT NULL DEFAULT 1,
                subscription_token TEXT,
                subscription_access_count INTEGER NOT NULL DEFAULT 0,
                subscription_last_access_at TEXT,
                connection_order_mode TEXT NOT NULL DEFAULT 'auto'
            )
            """
        )
        con.execute(
            "INSERT INTO users (name,uuid,subscription_token) VALUES (?,?,?)",
            ("Legacy", "11111111-1111-1111-1111-111111111111", token),
        )
    monkeypatch.setenv("XPANEL_DB", str(db))
    init_db()
    user = service.find_user("Legacy")
    devices = service.list_user_devices(int(user["id"]))
    assert len(devices) == 1
    assert devices[0]["name"] == "Основной доступ"
    assert devices[0]["is_primary"] == 1
    assert devices[0]["uuid"] == user["uuid"]
    assert devices[0]["subscription_token"] == token


def test_legacy_hysteria_auths_are_preserved_for_all_inbounds(tmp_path, monkeypatch) -> None:
    db = tmp_path / "legacy-hysteria.db"
    user_uuid = "22222222-2222-2222-2222-222222222222"
    expected = {
        "1": user_uuid,
        "2": "legacy-hysteria-auth-two",
        "3": "legacy-hysteria-auth-three",
    }
    with sqlite3.connect(db) as con:
        con.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                uuid TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                comment TEXT NOT NULL DEFAULT '',
                expiry_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                subscription_enabled INTEGER NOT NULL DEFAULT 1,
                subscription_token TEXT,
                subscription_access_count INTEGER NOT NULL DEFAULT 0,
                subscription_last_access_at TEXT,
                connection_order_mode TEXT NOT NULL DEFAULT 'auto'
            )
            """
        )
        con.execute(
            """
            CREATE TABLE hysteria_inbounds (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                tag TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 0,
                listen TEXT NOT NULL DEFAULT '0.0.0.0',
                port INTEGER NOT NULL,
                obfs_type TEXT NOT NULL DEFAULT '',
                obfs_password TEXT NOT NULL DEFAULT '',
                up_mbps INTEGER NOT NULL DEFAULT 100,
                down_mbps INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con.execute(
            """
            CREATE TABLE hysteria_user_auth (
                inbound_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                auth TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (inbound_id, user_id)
            )
            """
        )
        user_id = int(con.execute(
            "INSERT INTO users (name,uuid,subscription_token) VALUES (?,?,?)",
            ("Legacy Hysteria", user_uuid, "legacy-hysteria-token-1234567890"),
        ).lastrowid)
        for inbound_id in (1, 2, 3):
            con.execute(
                "INSERT INTO hysteria_inbounds (id,name,tag,port) VALUES (?,?,?,?)",
                (inbound_id, f"Hysteria {inbound_id}", f"hysteria-{inbound_id}", 8443 + inbound_id),
            )
            con.execute(
                "INSERT INTO hysteria_user_auth (inbound_id,user_id,auth) VALUES (?,?,?)",
                (inbound_id, user_id, expected[str(inbound_id)]),
            )

    monkeypatch.setenv("XPANEL_DB", str(db))
    init_db()
    user = service.find_user("Legacy Hysteria")
    primary = service.find_device(int(user["id"]))
    payload = json.loads(str(primary["credential"]["config_json"]))
    assert payload["hysteria_auths"] == expected

    # A repeated migration may fill a missing legacy key, but it must never
    # overwrite a newer device-scoped secret that already exists.
    newer_auth_two = "newer-device-auth-two"
    with connect() as con:
        con.execute(
            "UPDATE device_credentials SET config_json=? WHERE device_id=? AND engine='xray'",
            (
                json.dumps(
                    {"hysteria_auths": {"1": expected["1"], "2": newer_auth_two}},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                int(primary["id"]),
            ),
        )
    init_db()
    repeated = service.find_device(int(user["id"]), int(primary["id"]))
    repeated_payload = json.loads(str(repeated["credential"]["config_json"]))
    assert repeated_payload["hysteria_auths"]["2"] == newer_auth_two
    assert repeated_payload["hysteria_auths"]["3"] == expected["3"]

    # Running the normal credential completion path must not replace any of
    # the migrated secrets with fresh random values.
    generated = service._ensure_device_hysteria_auths()
    assert generated[1][int(primary["id"])] == expected["1"]
    assert generated[2][int(primary["id"])] == newer_auth_two
    assert generated[3][int(primary["id"])] == expected["3"]
    current = service.find_device(int(user["id"]), int(primary["id"]))
    current_payload = json.loads(str(current["credential"]["config_json"]))
    assert current_payload["hysteria_auths"] == {
        "1": expected["1"],
        "2": newer_auth_two,
        "3": expected["3"],
    }


def test_one_person_has_independent_device_uuid_token_and_local_deployment(tmp_path, monkeypatch) -> None:
    person, primary, phone, laptop = setup_catalogue(tmp_path, monkeypatch)
    devices = service.list_user_devices(int(person["id"]))
    assert [item["name"] for item in devices] == ["Основной доступ", "Телефон", "Ноутбук"]
    assert len({str(item["uuid"]) for item in devices}) == 3
    assert len({str(item["subscription_token"]) for item in devices}) == 3
    with connect() as con:
        rows = con.execute(
            "SELECT device_id,user_uuid,device_name,state FROM node_deployments "
            "WHERE user_id=? ORDER BY device_id",
            (int(person["id"]),),
        ).fetchall()
    assert {int(row["device_id"]) for row in rows} == {
        int(primary["id"]), int(phone["id"]), int(laptop["id"])
    }
    assert {str(row["user_uuid"]) for row in rows} == {
        str(primary["uuid"]), str(phone["uuid"]), str(laptop["uuid"])
    }


def test_disabling_one_device_keeps_person_and_other_devices_active(tmp_path, monkeypatch) -> None:
    person, primary, phone, laptop = setup_catalogue(tmp_path, monkeypatch)
    service.set_device_enabled(int(person["id"]), int(phone["id"]), False)
    user = service.find_user(int(person["id"]))
    devices = {item["name"]: item for item in service.list_user_devices(int(person["id"]))}
    assert user["enabled"] == 1
    assert devices["Основной доступ"]["enabled"] == 1
    assert devices["Телефон"]["enabled"] == 0
    assert devices["Ноутбук"]["enabled"] == 1

    config, _server, _rules = service.build_config()
    text = json.dumps(config, ensure_ascii=False)
    assert str(primary["uuid"]) in text
    assert str(laptop["uuid"]) in text
    assert str(phone["uuid"]) not in text


def test_device_subscription_and_managed_export_are_device_scoped(tmp_path, monkeypatch) -> None:
    person, _primary, phone, laptop = setup_catalogue(tmp_path, monkeypatch)
    found_user, found_device = service.find_subscription_access(str(laptop["subscription_token"]))
    assert int(found_user["id"]) == int(person["id"])
    assert int(found_device["id"]) == int(laptop["id"])
    assert service.subscription_is_available(found_user, found_device)

    export = service.managed_client_export_v2(
        int(person["id"]), device_id=int(laptop["id"])
    )
    assert export["schema"] == "sg-panel-managed-profile-v2"
    assert export["user"]["deviceId"] == int(laptop["id"])
    assert export["user"]["deviceName"] == "Ноутбук"
    assert export["user"]["uuid"] == str(laptop["uuid"])
    assert all(str(laptop["uuid"]) in item["uri"] for item in export["connections"])
    assert not any(str(phone["uuid"]) in item["uri"] for item in export["connections"])


def test_users_json_v2_roundtrip_preserves_device_ids_tokens_and_credentials(tmp_path, monkeypatch) -> None:
    person, _primary, _phone, _laptop = setup_catalogue(tmp_path, monkeypatch)
    before_devices = service.list_user_devices(int(person["id"]))
    before = {
        str(item["uuid"]): (
            int(item["id"]), str(item["subscription_token"]),
            str(item["credential"]["engine"]),
            str(item["credential"]["status"]),
            str(item["credential"]["engine_object_id"]),
            str(item["credential"]["config_json"]),
            str(item["credential"]["rotated_at"] or ""),
        )
        for item in before_devices
    }
    document = service.users_json_document()
    parsed = json.loads(document)
    assert parsed["_sgPanel"]["format"] == "users-devices-v2"
    assert len(parsed["users"][0]["devices"]) == 3

    service.update_users_json_document(document)
    current = service.find_user("Sergey")
    after = {
        str(item["uuid"]): (
            int(item["id"]), str(item["subscription_token"]),
            str(item["credential"]["engine"]),
            str(item["credential"]["status"]),
            str(item["credential"]["engine_object_id"]),
            str(item["credential"]["config_json"]),
            str(item["credential"]["rotated_at"] or ""),
        )
        for item in service.list_user_devices(int(current["id"]))
    }
    assert after == before


def test_qr_overflow_is_controlled_instead_of_raising() -> None:
    normal = service.qr_png_base64("vless://example")
    assert normal["data"]
    assert normal["error"] == ""
    oversized = service.qr_png_base64("x" * 100_000)
    assert oversized["data"] == ""
    assert "слишком длинна для QR" in oversized["error"]


def test_geofiles_retention_protects_active_and_removes_old_history(tmp_path, monkeypatch) -> None:
    root = tmp_path / "geofiles"
    monkeypatch.setattr(service, "GEOFILES_STATE_DIR", root)
    monkeypatch.setattr(service, "GEOFILES_SET_RETENTION", 2)
    monkeypatch.setattr(service, "GEOFILES_BACKUP_RETENTION", 2)
    monkeypatch.setattr(service, "GEOFILES_STAGING_MAX_AGE_HOURS", 1)
    now = time.time()
    for group in ("sets", "backups"):
        for index, name in enumerate(("old-a", "active", "new-b", "old-c")):
            path = root / group / name
            path.mkdir(parents=True, exist_ok=True)
            os.utime(path, (now - (index + 1) * 100, now - (index + 1) * 100))
    staging = root / "staging"
    staging.mkdir(parents=True)
    os.utime(staging, (now - 7200, now - 7200))

    removed = service.prune_geofiles_storage(active_generation="active")
    assert (root / "sets" / "active").is_dir()
    assert (root / "backups" / "active").is_dir()
    assert len(list((root / "sets").iterdir())) <= 3  # keep two newest plus protected active
    assert len(list((root / "backups").iterdir())) <= 3
    assert not staging.exists()
    assert removed["staging"] == ["staging"]


def test_panel_backup_retention_deletes_complete_old_groups(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XPANEL_BACKUP_DIR", str(tmp_path / "backups"))
    root = service.backup_dir()
    now = time.time()
    names = [f"sg-panel-2026072{index}-010101" for index in range(1, 5)]
    for index, name in enumerate(names):
        for suffix in (".db", ".json", ".config.json"):
            path = root / f"{name}{suffix}"
            path.write_text("x", encoding="utf-8")
            os.utime(path, (now - index * 100, now - index * 100))
    removed = service.prune_panel_backups(keep=2)
    assert len(removed) == 2
    remaining = {path.stem for path in root.glob("*.db")}
    assert remaining == set(names[:2])
    for name in removed:
        assert not (root / f"{name}.db").exists()
        assert not (root / f"{name}.json").exists()
        assert not (root / f"{name}.config.json").exists()


def test_internal_dialog_replaces_native_browser_dialogs() -> None:
    templates = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (ROOT / "xpanel" / "templates").rglob("*.html")
    )
    lowered = templates.lower()
    assert "window.sgdialogconfirm" in lowered
    assert "window.sgdialogalert" in lowered
    assert "data-confirm" in lowered
    for native in ("window.confirm(", "window.alert(", "window.prompt("):
        assert native not in lowered


def test_clients_templates_are_person_and_device_scoped() -> None:
    clients = read("xpanel/templates/users.html")
    subscriptions = read("xpanel/templates/subscriptions.html")
    web = read("xpanel/web.py")
    assert "Основной доступ" in clients
    assert "+ Добавить устройство" in clients
    assert "selected_devices" in clients
    assert "device_regenerate_uuid_route" in clients
    assert "subscription_entries" in subscriptions
    assert "find_subscription_access" in web
    assert "device_id" in web


def test_routing_has_only_concrete_targets_and_no_synthetic_vpn_language() -> None:
    checked = "\n".join(
        read(relative)
        for relative in (
            "xpanel/templates/routing.html",
            "xpanel/templates/rule_edit.html",
            "xpanel/service.py",
            "xpanel/web.py",
        )
    )
    for obsolete in (
        "Весь интернет через VPN",
        "остальное через VPN",
        "заблокированное через VPN",
        "VPN / Outbound",
        "all_vpn",
        "blocked_vpn",
        "ru_direct",
    ):
        assert obsolete not in checked
    routing = read("xpanel/templates/routing.html")
    service_text = read("xpanel/service.py")
    for concrete in ("Direct", "Block"):
        assert concrete in routing
    for concrete in ("warp", "cascade"):
        assert concrete in service_text.lower()
    assert "Неявного универсального выхода нет" in routing


def test_destructive_compatibility_and_old_installer_behaviour_are_absent() -> None:
    runtime_paths = [ROOT / "xpanel", ROOT / "node_agent", ROOT / "deploy"]
    runtime = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for item in runtime_paths
        for path in item.rglob("*")
        if path.is_file() and path.suffix in {".py", ".html", ".md", ".sh"}
    ).lower()
    assert "remove_missing" not in runtime
    assert "compatibility_action" not in runtime

    install = read("install.sh") + "\n" + read("install-or-upgrade.sh") + "\n" + read("deploy/ec2-first-install.sh")
    lowered = install.lower()
    assert "dist-upgrade" not in lowered
    assert "614400" not in lowered
    assert "не менее 600 mib" not in lowered
    assert "fallocate -l" not in lowered
    assert "mkswap" not in lowered
    assert "swapon " not in lowered
    assert "prune_upgrade_backups" in install


def test_fix35_css_and_cache_revision_are_loaded() -> None:
    base = read("xpanel/templates/base.html")
    css = read("xpanel/static/fix35-full-recovery.css")
    assert "fix35-full-recovery.css" in base
    assert "sg070-preview9-fix36-xray-vision-recovery" in base
    assert "sg-global-dialog" in base
    assert ".client-device-card" in css
    assert ".qr-overflow-note" in css


def test_primary_deployment_policy_is_scoped_to_one_device_not_whole_person(tmp_path, monkeypatch) -> None:
    from xpanel import node_manager

    person, primary, phone, laptop = setup_catalogue(tmp_path, monkeypatch)
    with connect() as con:
        remote_id = int(con.execute(
            "INSERT INTO nodes (name,slug,role,state,public_address) "
            "VALUES ('Node A','node-a','regional','online','198.51.100.20')"
        ).lastrowid)
        for device in (phone, laptop):
            con.execute(
                """
                INSERT INTO node_deployments (
                    node_id,user_id,device_id,user_uuid,device_uuid,user_name,device_name,
                    profile,public_host,public_port,state,slot,priority,
                    subscription_enabled,desired_state
                ) VALUES (?,?,?,?,?,?,?,?,?,443,'active','backup',20,1,'active')
                """,
                (
                    remote_id, int(person["id"]), int(device["id"]),
                    str(device["uuid"]), str(device["uuid"]), str(person["name"]),
                    str(device["name"]), "raw_reality", "198.51.100.20",
                ),
            )
        phone_remote_id = int(con.execute(
            "SELECT id FROM node_deployments WHERE node_id=? AND device_id=?",
            (remote_id, int(phone["id"])),
        ).fetchone()[0])

    node_manager.update_deployment_policy(phone_remote_id, slot="primary")
    with connect() as con:
        rows = con.execute(
            "SELECT device_id,node_id,slot FROM node_deployments "
            "WHERE user_id=? AND state!='removed'",
            (int(person["id"]),),
        ).fetchall()
    by_key = {(int(row["device_id"]), int(row["node_id"])): str(row["slot"]) for row in rows}
    local_node_id = next(
        node_id for (device_id, node_id), slot in by_key.items()
        if device_id == int(primary["id"])
    )
    assert by_key[(int(phone["id"]), remote_id)] == "primary"
    assert by_key[(int(phone["id"]), local_node_id)] == "backup"
    assert by_key[(int(laptop["id"]), local_node_id)] == "primary"
