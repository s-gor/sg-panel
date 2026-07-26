from pathlib import Path
import os
import tempfile

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


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


def login(client):
    response = client.post("/login", data={"password": "correct-password"})
    assert response.status_code == 302


def test_full_node_installer_provisions_every_runtime_before_connection():
    script = (ROOT / "deploy" / "install-sg-node.sh").read_text(encoding="utf-8")
    assert 'SCRIPT_VERSION="1.2"' in script
    assert 'XRAY_VERSION="__SG_PANEL_XRAY_VERSION__"' in script
    assert 'xray-version.env' in script
    assert "nginx certbot python3-certbot-nginx" in script
    assert "/opt/sg-node/sg_node_agent.py" in script
    assert "/usr/local/libexec/sg-node-worker.py" in script
    assert "/usr/local/sbin/sg-node-connect" in script
    assert "STATUS=ready_to_connect" not in script  # status is selected dynamically for updates
    assert 'node_status="ready_to_connect"' in script
    assert "HYSTERIA2_RUNTIME=xray" in script
    assert "Firewall: не изменялся" in script
    assert "FULL_PANEL_PRESENT" in script
    assert "SG-Panel, Nginx, Xray, клиенты и настройки: сохранены" in script
    assert '[[ $FULL_PANEL_PRESENT -eq 1 ]]' in script
    assert '--token) ENROLLMENT_TOKEN=' in script


def test_connection_always_replaces_token_and_requires_real_heartbeat():
    script = (ROOT / "deploy" / "connect-node.sh").read_text(encoding="utf-8")
    assert "Замена прежней регистрации" in script
    assert "Получение нового Agent token" in script
    assert "Подтверждение реального heartbeat" in script
    assert "verify_real_heartbeat" in script
    assert "/api/node/v1/heartbeat" in script
    assert "data = {" in script
    assert "'enrollment_token': sys.argv[2]" in script
    assert "agent_token" not in script.split("data = {", 1)[1].split("}", 1)[0]
    assert "--replace-registration" in script  # ignored compatibility flag, not required by UI


def test_controller_exposes_simple_install_and_connect_commands(db_env):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    login(client)

    page = client.get("/network/nodes")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Подключить SG-Node" in body
    assert "Одна команда сама определит" in body
    assert "cluster-node-connect-form" in body

    full = client.get("/node/install-sg-node.sh")
    connect = client.get("/node/connect.sh")
    assert full.status_code == 200
    assert connect.status_code == 200
    assert "Полная установка SG-Node".encode() in full.data
    assert b"verify_real_heartbeat" in connect.data


def test_node_detail_uses_one_connection_command_and_64441(db_env):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    login(client)
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    response = client.post(
        "/network/nodes/add",
        data={
            "csrf_token": csrf,
            "name": "Node One",
            "role": "regional",
            "location": "Lab",
            "description": "test",
        },
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Скопировать команду" in body
    assert "/node/install-sg-node.sh" in body
    assert "--token" in body
    assert "--replace-registration" not in body
    template = (ROOT / 'xpanel/templates/node_detail.html').read_text(encoding='utf-8')
    assert 'value="64441"' in template
    assert "02 · Установить Xray Runtime" not in body


def test_hotfix21_revision_and_docs():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    docs = (ROOT / "docs/MULTI-NODE.md").read_text(encoding="utf-8")
    assert "sg070" in base
    assert "SG-Panel 054" in css
    assert "Переподключить ноду" in docs
    assert "64441" in docs
