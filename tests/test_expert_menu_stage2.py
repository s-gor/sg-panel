from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "expert-stage2")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.service import add_user
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, flow,
                config_path, xray_bin, xray_service, inbound_profile,
                transport_listen, transport_port, xhttp_path, xhttp_mode
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "203.0.113.10", "0.0.0.0", 443, "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "firefox", "xtls-rprx-vision",
                str(tmp_path / "config.json"), "/bin/true", "xray", "xhttp_reality",
                "127.0.0.1", 8443, "/sg-xhttp", "auto",
            ),
        )
    user = add_user("Stage2 Client")
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "expert-stage2-test",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    return client, user


def test_ordinary_xray_restores_preview9_layout_and_clients_stay_simple(panel):
    client, user = panel
    settings = client.get("/settings").get_data(as_text=True)
    assert "Основное подключение" in settings
    assert "Выбор серверной схемы" in settings
    assert "Обнаружено автоматически" in settings
    assert "VLESS XHTTP-REALITY" in settings
    assert "Панель настроит профиль сама" not in settings
    assert "READY PROFILES" not in settings
    assert "maxConnections" not in settings
    assert "Ручной порядок" not in settings
    assert "<b>Expert</b>" in settings

    clients = client.get(f"/users?client={user['id']}").get_data(as_text=True)
    assert "Ручное управление находится в разделе Expert" in clients
    assert "Основное" not in clients
    assert "Резервное" not in clients
    assert "JSON клиента" not in clients


def test_expert_is_current_scheme_technical_continuation(panel):
    client, _user = panel
    expert = client.get("/settings/advanced").get_data(as_text=True)
    assert "Фактическое состояние" in expert
    assert "Подключения текущей схемы" in expert
    assert "Server Extra · JSON" in expert
    assert "Итоговые конфигурации" in expert
    assert "Проверка текущей схемы" in expert
    assert "Ядро Xray" not in expert
    assert "Применить набор РФ" not in expert
    assert "Управление подключениями клиентов" not in expert
    assert "Включить редактирование" not in expert
    assert "data-expert-edit-fieldset" not in expert
    assert "Проверить и применить параметры" in expert
    assert "Технические инструменты" not in expert
    assert ">Транспорты</a>" not in expert
    assert ">Подключения</a>" in expert
    assert ">Резервные Inbound</a>" in expert
    assert ">Xray Config</a>" in expert
    assert ">Ядро Xray</a>" not in expert
    assert ">Состояние</a>" not in expert
    assert ">Параметры</a>" not in expert
    assert ">Диагностика</a>" not in expert



def test_expert_saves_in_one_step_without_unlock_or_validation_token(panel, monkeypatch):
    client, _user = panel
    import xpanel.web as web_module

    monkeypatch.setattr(web_module, "apply_config", lambda: {"ok": True})
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    response = client.post(
        "/settings/advanced",
        data={
            "csrf_token": csrf,
            "xmux_mode": "reduced",
            "xhttp_mode": "auto",
        },
    )
    assert response.status_code == 302
    with connect() as con:
        row = con.execute("SELECT xmux_mode FROM transport_expert_settings WHERE id=1").fetchone()
    assert row["xmux_mode"] == "reduced"



def test_expert_restores_saved_values_when_apply_fails(panel, monkeypatch):
    client, _user = panel
    import xpanel.web as web_module
    from xpanel.service import XPanelError

    def fail_apply():
        raise XPanelError("test apply failure")

    monkeypatch.setattr(web_module, "apply_config", fail_apply)
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    response = client.post(
        "/settings/advanced",
        data={
            "csrf_token": csrf,
            "xmux_mode": "reduced",
            "xhttp_mode": "stream-up",
        },
    )
    assert response.status_code == 302
    with connect() as con:
        expert = con.execute("SELECT xmux_mode FROM transport_expert_settings WHERE id=1").fetchone()
        server = con.execute("SELECT xhttp_mode FROM server_settings WHERE id=1").fetchone()
    assert expert["xmux_mode"] == "auto"
    assert server["xhttp_mode"] == "auto"


def test_shared_xray_policy_is_used_everywhere_and_node_scripts_are_standalone(panel):
    client, _user = panel
    policy = (ROOT / "deploy/xray-version.env").read_text(encoding="utf-8")
    assert 'XRAY_VERSION="v26.6.27"' in policy

    for relative in (
        "deploy/ec2-first-install.sh",
        "deploy/install-node-runtime.sh",
        "deploy/install-sg-node.sh",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert 'XRAY_VERSION="v26.5.9"' not in source
        assert "xray-version.env" in source

    root_node_installer = (ROOT / "01-install-sg-node.sh").read_text(encoding="utf-8")
    assert 'XRAY_VERSION="v26.5.9"' not in root_node_installer
    assert 'XRAY_VERSION="v26.6.27"' in root_node_installer
    assert "deploy/xray-version.env" in root_node_installer

    for url in ("/node/install-sg-node.sh", "/node/runtime.sh"):
        response = client.get(url)
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "v26.6.27" in body
        assert "__SG_PANEL_XRAY_VERSION__" not in body
        result = subprocess.run(["bash", "-n"], input=body, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr


def test_sidebar_has_separate_expert_section(panel):
    client, _user = panel
    body = client.get("/settings/advanced").get_data(as_text=True)
    assert re.search(r'<a href="/settings/advanced" class="active">\s*<svg', body)
    assert "Подключения, резервные Inbound и JSON" in body
    assert "Inbound вручную" not in body
    assert "Ядро Xray" not in body
    assert "Резервные Inbound" in body
