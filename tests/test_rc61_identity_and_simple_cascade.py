from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", "scrypt:32768:8:1$test$test")

from xpanel.db import connect, init_db
from xpanel.service import get_instance_name, update_instance_name

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

@pytest.fixture()
def panel_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute("""
            INSERT INTO server_settings (
                id,instance_name,address,listen,port,dest,server_name,private_key,
                public_key,short_id,fingerprint,flow,config_path,xray_bin,xray_service
            ) VALUES (1,'CC1 · Frankfurt','cc1.example.com','0.0.0.0',443,
                'www.bing.com:443','www.bing.com','private','public','0011223344556677',
                'firefox','xtls-rprx-vision',?, '/bin/true','xray')
        """, (str(tmp_path / "config.json"),))
    return tmp_path

def test_instance_name_is_persistent_and_global(panel_db):
    assert get_instance_name() == "CC1 · Frankfurt"
    update_instance_name("CC2 · Virginia")
    assert get_instance_name() == "CC2 · Virginia"
    base = read("xpanel/templates/base.html")
    login = read("xpanel/templates/login.html")
    diagnostics = read("xpanel/templates/diagnostics.html")
    assert 'class="instance-badge"' in base
    assert "{{ instance_identity }}" in base
    assert "login-instance-name" in login
    assert "system_instance_name" in diagnostics

def test_cascade_is_simple_and_hides_manual_routing_terms():
    page = read("xpanel/templates/cascade.html")
    assert "Сделать этот сервер выходом" in page
    assert "Подключить и проверить" in page
    assert "Включить Cascade" in page
    assert "Удалить Cascade" in page
    assert "Внутренний tag" not in page
    assert "Default Outbound" not in page

def test_installers_use_old_green_bar_spinner_and_collect_instance_name():
    for path in ("install.sh", "install-or-upgrade.sh", "deploy/ec2-first-install.sh"):
        script = read(path)
        assert "local frames='|/-\\'" in script
        assert "${frames:frame_index%4:1}" in script
    assert "Имя этого сервера в панели" in read("install.sh")
    assert 'INSTANCE_NAME="$INSTANCE_NAME"' in read("install.sh")
    assert "Имя этого сервера в панели" in read("deploy/ec2-first-install.sh")

def test_exit_server_creates_and_removes_managed_access(panel_db):
    from xpanel.service import ensure_cascade_service_access, get_cascade_overview, remove_cascade

    access = ensure_cascade_service_access()
    assert access["ready"] is True
    assert access["name"] == "Cascade · CC1 · Frankfurt"
    assert str(access["link"]).startswith("vless://")
    assert "fp=firefox" in str(access["link"])

    overview = get_cascade_overview()
    assert overview["service_access"]["configured"] is True
    assert overview["service_access"]["ready"] is True

    cleaned = remove_cascade()
    assert cleaned["service_access"]["configured"] is False
    with connect() as con:
        assert con.execute(
            "SELECT COUNT(*) FROM users WHERE comment = ?",
            ("SG-Panel managed Cascade service access",),
        ).fetchone()[0] == 0

def test_web_can_rename_instance_and_create_cascade_access(panel_db, monkeypatch):
    from werkzeug.security import generate_password_hash
    import xpanel.web as web_module
    from xpanel.service import get_cascade_overview

    monkeypatch.setattr(web_module, "apply_config", lambda: {"ok": True})
    app = web_module.create_app({
        "TESTING": True,
        "SECRET_KEY": "rc61-web-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    with client.session_transaction() as session:
        csrf = session["csrf_token"]

    response = client.post(
        "/system/instance-name",
        data={"csrf_token": csrf, "instance_name": "Virginia Exit"},
    )
    assert response.status_code == 302
    assert get_instance_name() == "Virginia Exit"

    response = client.post("/cascade/access/create", data={"csrf_token": csrf})
    assert response.status_code == 302
    overview = get_cascade_overview()
    assert overview["service_access"]["ready"] is True
    assert overview["service_access"]["name"] == "Cascade · Virginia Exit"
