from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from jinja2 import Environment

from xpanel import service
from xpanel.db import connect, init_db

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def panel_db(tmp_path: Path):
    old_db = os.environ.get("XPANEL_DB")
    old_backups = os.environ.get("XPANEL_BACKUP_DIR")
    os.environ["XPANEL_DB"] = str(tmp_path / "panel.db")
    os.environ["XPANEL_BACKUP_DIR"] = str(tmp_path / "backups")
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,config_path,xray_bin,xray_service
            ) VALUES (1,'vpn.example.com','0.0.0.0',443,'www.bing.com:443',
                      'vpn.example.com','private','public','0011223344556677',
                      'firefox',?, '/usr/local/bin/xray','xray')
            """,
            (str(tmp_path / "config.json"),),
        )
    try:
        yield tmp_path
    finally:
        if old_db is None:
            os.environ.pop("XPANEL_DB", None)
        else:
            os.environ["XPANEL_DB"] = old_db
        if old_backups is None:
            os.environ.pop("XPANEL_BACKUP_DIR", None)
        else:
            os.environ["XPANEL_BACKUP_DIR"] = old_backups


def test_ui23_migrates_old_hysteria_table_idempotently(tmp_path: Path) -> None:
    database = tmp_path / "old.db"
    con = sqlite3.connect(database)
    con.execute(
        """
        CREATE TABLE hysteria_inbounds (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, tag TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0, listen TEXT NOT NULL,
            port INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    con.execute(
        "INSERT INTO hysteria_inbounds(id,name,tag,enabled,listen,port) VALUES(1,'Old','old',1,'0.0.0.0',443)"
    )
    con.commit(); con.close()
    previous = os.environ.get("XPANEL_DB")
    os.environ["XPANEL_DB"] = str(database)
    try:
        init_db(); init_db()
        with connect() as migrated:
            row = migrated.execute(
                "SELECT obfs_mode,obfs_password,obfs_updated_at,obfs_updated_by FROM hysteria_inbounds WHERE id=1"
            ).fetchone()
        assert row["obfs_mode"] == "none"
        assert row["obfs_password"] is None
        assert row["obfs_updated_by"] == ""
    finally:
        if previous is None:
            os.environ.pop("XPANEL_DB", None)
        else:
            os.environ["XPANEL_DB"] = previous


def test_ui23_generates_strong_base64url_passwords() -> None:
    values = {service.generate_hysteria_obfs_password() for _ in range(20)}
    assert len(values) == 20
    assert all(len(value) == 32 for value in values)
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{32}", value) for value in values)


def test_ui23_uri_builder_encodes_salamander_and_ipv6() -> None:
    secret = "p a+ss/&=#Ю"
    uri = service.build_hysteria2_uri(
        auth="a@b:c",
        host="2001:db8::1",
        port=443,
        sni="vpn.example.com",
        profile_name="SG Франция #1",
        obfs_mode="salamander",
        obfs_password=secret,
    )
    assert uri.startswith("hysteria2://a%40b%3Ac@[2001:db8::1]:443/")
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    assert query["obfs"] == ["salamander"]
    assert query["obfs-password"] == [secret]
    assert query["sni"] == ["vpn.example.com"]
    assert parsed.fragment == "SG%20%D0%A4%D1%80%D0%B0%D0%BD%D1%86%D0%B8%D1%8F%20%231"


def test_ui23_uri_without_salamander_has_no_obfs_parameters() -> None:
    uri = service.build_hysteria2_uri(
        auth="auth", host="vpn.example.com", port=443,
        sni="vpn.example.com", profile_name="Normal",
    )
    query = parse_qs(urlparse(uri).query)
    assert "obfs" not in query
    assert "obfs-password" not in query


def test_ui23_merges_finalmask_without_losing_quic_tcp_or_udp() -> None:
    inbound = {
        "tag": "sg-hysteria2",
        "protocol": "hysteria",
        "streamSettings": {
            "network": "hysteria",
            "finalmask": {
                "quicParams": {"maxIdleTimeout": 30},
                "tcp": [{"type": "noise", "settings": {"packet": "x"}}],
                "udp": [{"type": "sudoku", "settings": {"size": 9}}],
            },
        },
    }
    service._apply_hysteria_salamander_to_inbound(
        inbound,
        {"obfs_mode": "salamander", "obfs_password": "secret"},
    )
    finalmask = inbound["streamSettings"]["finalmask"]
    assert finalmask["quicParams"] == {"maxIdleTimeout": 30}
    assert finalmask["tcp"][0]["type"] == "noise"
    assert finalmask["udp"][0]["type"] == "sudoku"
    assert finalmask["udp"][1] == {
        "type": "salamander", "settings": {"password": "secret"}
    }
    assert "_managed_by" not in json.dumps(inbound)


def test_ui23_managed_salamander_does_not_overwrite_expert_layer() -> None:
    inbound = {
        "protocol": "hysteria",
        "streamSettings": {
            "network": "hysteria",
            "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "expert"}}]},
        },
    }
    with pytest.raises(service.XPanelError, match="Expert FinalMask"):
        service._apply_hysteria_salamander_to_inbound(
            inbound, {"obfs_mode": "salamander", "obfs_password": "managed"}
        )


def test_ui23_none_preserves_foreign_finalmask_layers() -> None:
    inbound = {
        "protocol": "hysteria",
        "streamSettings": {
            "network": "hysteria",
            "finalmask": {
                "quicParams": {"keepAlivePeriod": 10},
                "udp": [{"type": "sudoku", "settings": {}}],
            },
        },
    }
    service._apply_hysteria_salamander_to_inbound(
        inbound, {"obfs_mode": "none", "obfs_password": None}
    )
    assert inbound["streamSettings"]["finalmask"] == {
        "quicParams": {"keepAlivePeriod": 10},
        "udp": [{"type": "sudoku", "settings": {}}],
    }


def test_ui23_blocks_old_xray_before_enabling(panel_db: Path, monkeypatch) -> None:
    monkeypatch.setattr(service, "_installed_xray_version", lambda binary: (26, 3, 26))
    with pytest.raises(service.XPanelError, match="v26.3.27"):
        service.update_hysteria_obfuscation(
            1, mode="salamander", password="secret", actor="admin"
        )
    with connect() as con:
        row = con.execute("SELECT obfs_mode,obfs_password FROM hysteria_inbounds WHERE id=1").fetchone()
    assert row["obfs_mode"] == "none"
    assert row["obfs_password"] is None


def test_ui23_persists_obfs_and_backup_contains_same_password(panel_db: Path, monkeypatch) -> None:
    monkeypatch.setattr(service, "_installed_xray_version", lambda binary: (26, 6, 27))
    service.update_hysteria_obfuscation(
        1, mode="salamander", password="same-secret", actor="admin"
    )
    backup = service.create_backup()
    with sqlite3.connect(service.backup_file(str(backup["name"]), "db")) as con:
        row = con.execute(
            "SELECT obfs_mode,obfs_password,obfs_updated_by FROM hysteria_inbounds WHERE id=1"
        ).fetchone()
    assert row == ("salamander", "same-secret", "admin")


def test_ui23_make_links_uses_one_salamander_uri_source(panel_db: Path, monkeypatch) -> None:
    monkeypatch.setattr(service, "_installed_xray_version", lambda binary: (26, 6, 27))
    monkeypatch.setattr(
        service, "_always_on_https_material",
        lambda server: {"ready": True, "domain": "vpn.example.com", "cert": "/c", "key": "/k", "message": "ok"},
    )
    monkeypatch.setattr(
        service, "_controller_vless_encryption_pair",
        lambda: {"encryption": "mlkem768x25519plus.native.0rtt", "decryption": "mlkem768x25519plus.native.0rtt"},
    )
    service.update_hysteria_obfuscation(
        1, mode="salamander", password="profile-secret", actor="admin"
    )
    user = service.add_user("Salamander Client")
    links = service.make_links(int(user["id"]))
    hysteria = next(item for item in links if item["kind"] == "hysteria")
    query = parse_qs(urlparse(str(hysteria["link"])).query)
    assert query["obfs"] == ["salamander"]
    assert query["obfs-password"] == ["profile-secret"]
    assert hysteria["obfs_password_configured"] is True
    qr = service.qr_png_base64(str(hysteria["link"]))
    assert isinstance(qr, dict) and len(str(qr.get("data") or "")) > 100 and not qr.get("error")


def test_ui23_diagnostics_never_exposes_password(panel_db: Path, monkeypatch) -> None:
    secret = "NEVER-PRINT-THIS-SALAMANDER-SECRET"
    with connect() as con:
        con.execute(
            "UPDATE hysteria_inbounds SET obfs_mode='salamander',obfs_password=? WHERE id=1",
            (secret,),
        )
    inbound = {
        "tag": "sg-hysteria2", "protocol": "hysteria",
        "settings": {"version": 2, "users": []},
        "streamSettings": {
            "network": "hysteria", "hysteriaSettings": {"version": 2},
            "finalmask": {
                "quicParams": {},
                "udp": [{"type": "salamander", "settings": {"password": secret}}],
            },
        },
    }
    live = panel_db / "config.json"
    live.write_text(json.dumps({"inbounds": [inbound]}), encoding="utf-8")
    monkeypatch.setattr(service, "hysteria_salamander_support_status", lambda x=None: {"supported": True, "version": "v26.6.27", "minimum": "v26.3.27", "message": "ok"})
    monkeypatch.setattr(service, "validate_generated_config", lambda: {"ok": True, "detail": "xray run -test: OK", "users": 0})
    monkeypatch.setattr(service, "build_config", lambda: ({"inbounds": [inbound]}, service.get_server(), []))
    monkeypatch.setattr(service, "_always_on_https_material", lambda server: {"ready": True})
    monkeypatch.setattr(service.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("203.0.113.1", 0))])
    monkeypatch.setattr(service, "_listener_status", lambda port, proto: "занят")
    monkeypatch.setattr(service, "_run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "active\n", "stderr": ""})())
    report = service.get_hysteria_diagnostics()
    rendered = json.dumps(report, ensure_ascii=False)
    assert secret not in rendered
    assert "Password: configured" in rendered
    assert "client URI parameters: present" in rendered


def test_ui23_templates_use_internal_modal_and_no_browser_confirm() -> None:
    settings = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    expert = (ROOT / "xpanel/templates/expert_inbound.html").read_text(encoding="utf-8")
    Environment().parse(settings)
    Environment().parse(expert)
    for marker in (
        "Обфускация FinalMask", "Salamander", "Пароль Salamander",
        "data-salamander-generate", "sgDialogConfirm", "salamander_confirmation",
    ):
        assert marker in settings
    assert "window.confirm(" not in settings + expert
    assert "window.prompt(" not in settings + expert
    assert "_managed_by" not in settings + expert


def test_ui23_worker_already_validates_and_rolls_back_full_node_config() -> None:
    worker = (ROOT / "node_agent/sg_node_worker.py").read_text(encoding="utf-8")
    assert "def apply_xray_config" in worker
    assert "[str(XRAY_BIN), \"run\", \"-test\", \"-config\", str(temp_config)]" in worker
    assert "shutil.copy2(backup, XRAY_CONFIG)" in worker
    assert "systemctl" in worker and "restart" in worker


def test_ui23_update_inbounds_enforces_xray_minimum_before_write(panel_db: Path, monkeypatch) -> None:
    monkeypatch.setattr(service, "_installed_xray_version", lambda binary: (26, 3, 26))
    before = [dict(row) for row in service.list_hysteria_inbounds()]
    values = [dict(row) for row in before]
    values[0]["obfs_mode"] = "salamander"
    values[0]["obfs_password"] = "must-not-be-written"
    with pytest.raises(service.XPanelError, match="v26.3.27"):
        service.update_hysteria_inbounds(
            values,
            primary_listen="0.0.0.0",
            primary_port=443,
        )
    after = [dict(row) for row in service.list_hysteria_inbounds()]
    assert after[0]["obfs_mode"] == "none"
    assert after[0]["obfs_password"] is None


def test_ui23_full_generated_config_contains_clean_salamander_layer(panel_db: Path, monkeypatch) -> None:
    monkeypatch.setattr(service, "_installed_xray_version", lambda binary: (26, 6, 27))
    monkeypatch.setattr(
        service,
        "_always_on_https_material",
        lambda server: {
            "ready": True,
            "domain": "vpn.example.com",
            "cert": "/tmp/fullchain.pem",
            "key": "/tmp/privkey.pem",
            "message": "ok",
        },
    )
    monkeypatch.setattr(
        service,
        "_controller_vless_encryption_pair",
        lambda: {
            "encryption": "mlkem768x25519plus.native.0rtt",
            "decryption": "mlkem768x25519plus.native.0rtt",
        },
    )
    service.update_hysteria_obfuscation(
        1, mode="salamander", password="candidate-secret", actor="admin"
    )
    payload, _server, _users = service.build_config()
    inbound = next(
        item for item in payload["inbounds"]
        if item.get("tag") == "sg-hysteria2"
    )
    finalmask = inbound["streamSettings"]["finalmask"]
    assert "quicParams" in finalmask
    assert finalmask["udp"][-1] == {
        "type": "salamander",
        "settings": {"password": "candidate-secret"},
    }
    assert "_managed_by" not in json.dumps(payload)


def test_ui23_diagnostics_redacts_secret_even_from_xray_journal(panel_db: Path, monkeypatch) -> None:
    secret = "JOURNAL-MUST-NOT-LEAK"
    with connect() as con:
        con.execute(
            "UPDATE hysteria_inbounds SET obfs_mode='salamander',obfs_password=? WHERE id=1",
            (secret,),
        )
    inbound = {
        "tag": "sg-hysteria2",
        "protocol": "hysteria",
        "settings": {"version": 2, "users": []},
        "streamSettings": {
            "network": "hysteria",
            "hysteriaSettings": {"version": 2},
            "finalmask": {
                "quicParams": {},
                "udp": [{"type": "salamander", "settings": {"password": secret}}],
            },
        },
    }
    config_path = panel_db / "config.json"
    config_path.write_text(json.dumps({"inbounds": [inbound]}), encoding="utf-8")
    monkeypatch.setattr(
        service,
        "hysteria_salamander_support_status",
        lambda x=None: {
            "supported": True,
            "version": "v26.6.27",
            "minimum": "v26.3.27",
            "message": "ok",
        },
    )
    monkeypatch.setattr(
        service,
        "validate_generated_config",
        lambda: {"ok": True, "detail": f"candidate error {secret}", "users": 0},
    )
    monkeypatch.setattr(service, "build_config", lambda: ({"inbounds": [inbound]}, service.get_server(), []))
    monkeypatch.setattr(service, "_always_on_https_material", lambda server: {"ready": True})
    monkeypatch.setattr(service.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("203.0.113.1", 0))])
    monkeypatch.setattr(service, "_listener_status", lambda port, proto: "занят")

    def fake_run(command, *args, **kwargs):
        output = f"fatal: invalid salamander password {secret}\n" if command[0] == "journalctl" else "active\n"
        return type("R", (), {"returncode": 0, "stdout": output, "stderr": ""})()

    monkeypatch.setattr(service, "_run", fake_run)
    rendered = json.dumps(service.get_hysteria_diagnostics(), ensure_ascii=False)
    assert secret not in rendered
    assert "[REDACTED]" in rendered


def test_ui23_release_and_installers_require_salamander_contract() -> None:
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in (ROOT / "xpanel/__init__.py").read_text(encoding="utf-8")
    for relative in ("install-or-upgrade.sh", "install.sh", "deploy/ec2-first-install.sh"):
        body = (ROOT / relative).read_text(encoding="utf-8")
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
        assert "HYSTERIA_SALAMANDER_MIN_VERSION = (26, 3, 27)" in body
        assert "data-hysteria-salamander-card" in body
    assert 'LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"' in (ROOT / "install.sh").read_text(encoding="utf-8")


def test_ui23_repair2_legacy_inbound_mapping_defaults_to_no_obfuscation() -> None:
    assert service._hysteria_obfs_values({"id": 1, "name": "Legacy"}) == ("none", None)
    inbound = {
        "protocol": "hysteria",
        "streamSettings": {
            "network": "hysteria",
            "finalmask": {"quicParams": {"keepAlivePeriod": 10}},
        },
    }
    service._apply_hysteria_salamander_to_inbound(inbound, {"id": 1})
    assert inbound["streamSettings"]["finalmask"] == {
        "quicParams": {"keepAlivePeriod": 10}
    }


def test_ui23_repair2_not_null_prerelease_schema_can_disable_and_resave(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "legacy-not-null.db"
    con = sqlite3.connect(database)
    con.execute(
        """
        CREATE TABLE hysteria_inbounds (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            tag TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            listen TEXT NOT NULL,
            port INTEGER NOT NULL,
            obfs_mode TEXT NOT NULL DEFAULT 'none',
            obfs_password TEXT NOT NULL DEFAULT '',
            obfs_updated_at TEXT,
            obfs_updated_by TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    con.execute(
        """
        INSERT INTO hysteria_inbounds(
            id,name,tag,enabled,listen,port,obfs_mode,obfs_password
        ) VALUES(1,'Legacy','sg-hysteria2',1,'0.0.0.0',443,'none','')
        """
    )
    con.commit()
    con.close()

    previous = os.environ.get("XPANEL_DB")
    os.environ["XPANEL_DB"] = str(database)
    monkeypatch.setattr(service, "_require_hysteria_salamander_support", lambda binary=None: (26, 6, 27))
    try:
        init_db()
        values = [dict(row) for row in service.list_hysteria_inbounds()]
        service.update_hysteria_inbounds(
            values, primary_listen="0.0.0.0", primary_port=443
        )
        service.update_hysteria_obfuscation(
            1, mode="salamander", password="repair2-secret", actor="admin"
        )
        service.update_hysteria_obfuscation(
            1, mode="none", password=None, actor="admin"
        )
        with connect() as migrated:
            row = migrated.execute(
                "SELECT obfs_mode,obfs_password FROM hysteria_inbounds WHERE id=1"
            ).fetchone()
        assert row["obfs_mode"] == "none"
        assert row["obfs_password"] == ""
    finally:
        if previous is None:
            os.environ.pop("XPANEL_DB", None)
        else:
            os.environ["XPANEL_DB"] = previous
