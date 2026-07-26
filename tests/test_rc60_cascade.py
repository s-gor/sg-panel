from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", "scrypt:32768:8:1$test$test")

from xpanel import service
from xpanel.db import connect, init_db
from xpanel.service import (
    get_cascade_overview,
    get_routing_settings,
    import_cascade_link,
    set_cascade_enabled,
    test_cascade as run_cascade_test,
)

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def cascade_link() -> str:
    return (
        "vless://11111111-1111-4111-8111-111111111111@3.95.58.154:443"
        "?type=tcp&security=reality&pbk=Public_Key-123&fp=firefox"
        "&sni=www.bing.com&sid=aabbccdd&flow=xtls-rprx-vision&spx=%2F"
        "#Cascade-CC1-to-CC2"
    )


@pytest.fixture()
def panel_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,flow,config_path,xray_bin,xray_service
            ) VALUES (1,'cc1.example.com','0.0.0.0',443,'www.bing.com:443',
                'www.bing.com','private','public','0011223344556677','firefox',
                'xtls-rprx-vision',?, '/bin/true','xray')
            """,
            (str(tmp_path / "config.json"),),
        )
    return tmp_path


def test_cascade_has_dedicated_top_level_page_and_clear_sequence():
    base = read("xpanel/templates/base.html")
    page = read("xpanel/templates/cascade.html")
    assert "url_for('cascade_page')" in base
    assert "<b>Cascade</b>" in base
    assert "Клиент" in page
    assert "Сделать этот сервер выходом" in page
    assert "Подключить и проверить" in page
    assert "Включить Cascade" in page
    assert "Удалить Cascade" in page
    assert "cascade.instance_name" in page
    assert "cascade.exit_name" in page


def test_import_creates_managed_exit_but_keeps_direct_until_test(panel_db):
    result = import_cascade_link(cascade_link())
    assert result["configured"] is True
    assert result["enabled"] is False
    assert result["outbound"]["tag"] == "cascade-exit"
    assert result["outbound"]["address"] == "3.95.58.154"
    assert get_routing_settings()["default_outbound_tag"] == "direct"
    with connect() as con:
        settings = con.execute("SELECT * FROM cascade_settings WHERE id=1").fetchone()
        assert settings["outbound_id"] == result["outbound"]["id"]
        assert settings["last_test_state"] == ""


def test_cascade_cannot_be_enabled_before_full_test(panel_db):
    import_cascade_link(cascade_link())
    with pytest.raises(service.XPanelError, match="полную проверку"):
        set_cascade_enabled(True)
    assert get_routing_settings()["default_outbound_tag"] == "direct"


def test_full_reality_test_records_exit_ip_and_unlocks_enable(panel_db, monkeypatch):
    imported = import_cascade_link(cascade_link())

    class FakeProcess:
        stderr = None
        stdout = None
        def poll(self):
            return None
        def terminate(self):
            return None
        def wait(self, timeout=None):
            return 0
        def kill(self):
            return None

    class FakeSocket:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def settimeout(self, timeout):
            return None
        def connect_ex(self, address):
            return 0

    monkeypatch.setattr(service, "require_root", lambda: None)
    monkeypatch.setattr(service, "_free_local_port", lambda: 18080)
    monkeypatch.setattr(service.subprocess, "Popen", lambda *a, **k: FakeProcess())
    monkeypatch.setattr(service.socket, "socket", FakeSocket)
    monkeypatch.setattr(service.shutil, "which", lambda name: "/usr/bin/curl")
    monkeypatch.setattr(
        service,
        "_run",
        lambda *a, **k: subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="ip=3.95.58.154\nloc=US\ncolo=IAD\nwarp=off\n",
            stderr="",
        ),
    )

    result = run_cascade_test()
    assert result["ip"] == "3.95.58.154"
    assert result["country"] == "US"
    assert result["colo"] == "IAD"

    overview = get_cascade_overview()
    assert overview["test_state"] == "ok"
    assert overview["test_fresh"] is True
    assert overview["last_test_ip"] == "3.95.58.154"
    assert overview["outbound"]["id"] == imported["outbound"]["id"]

    enabled = set_cascade_enabled(True)
    assert enabled["enabled"] is True
    assert get_routing_settings()["default_outbound_tag"] == "cascade-exit"

    disabled = set_cascade_enabled(False)
    assert disabled["enabled"] is False
    assert get_routing_settings()["default_outbound_tag"] == "direct"


def test_changing_exit_invalidates_old_test(panel_db):
    imported = import_cascade_link(cascade_link())
    row = imported["outbound"]
    signature = service._cascade_signature(service.find_outbound(row["id"]))
    with connect() as con:
        con.execute(
            "UPDATE cascade_settings SET last_test_state='ok', tested_signature=?, last_test_ip='3.95.58.154' WHERE id=1",
            (signature,),
        )
        con.execute(
            "UPDATE outbounds SET server_name='www.cloudflare.com', updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (row["id"],),
        )
    overview = get_cascade_overview()
    assert overview["test_state"] == "stale"
    assert overview["test_fresh"] is False


def test_cascade_page_renders_for_authenticated_admin(panel_db):
    from werkzeug.security import generate_password_hash
    from xpanel.web import create_app

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "cascade-web-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    response = client.get("/cascade")
    assert response.status_code == 200
    assert b">Cascade<" in response.data
    assert b'action="/cascade/import"' in response.data
    assert b'action="/cascade/access/create"' in response.data


def test_cascade_import_post_creates_exit_without_exposing_manual_fields(panel_db, monkeypatch):
    from werkzeug.security import generate_password_hash
    import xpanel.web as web_module

    monkeypatch.setattr(web_module, "apply_config", lambda: {"ok": True})
    monkeypatch.setattr(web_module, "test_cascade", lambda: {"ip": "3.95.58.154"})
    app = web_module.create_app({
        "TESTING": True,
        "SECRET_KEY": "cascade-post-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    response = client.post(
        "/cascade/import",
        data={"csrf_token": csrf, "vless_link": cascade_link()},
    )
    assert response.status_code == 302
    overview = get_cascade_overview()
    assert overview["configured"] is True
    assert overview["outbound"]["tag"] == "cascade-exit"
    assert overview["enabled"] is False
