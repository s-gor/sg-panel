from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc42-saved-links")
os.environ.setdefault(
    "XPANEL_PASSWORD_HASH",
    "scrypt:32768:8:1$U3eHbDYMmG1WDUwR$04acb0a1ed98b1050d9fa9c8cecb595899c02fda95fdb3c28cc68f18c676f5f47228e0240f9dc165e32eab448f128f633f0b5b5b92b7e3f76608cf8bbdbdd12f",
)

from xpanel.db import connect, init_db
from xpanel.service import (
    add_user,
    list_reality_inbounds,
    make_links,
    make_saved_links,
    update_server_settings,
    update_subscription_settings,
)
from xpanel.web import create_app


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy" / "ec2-first-install.sh"


@pytest.fixture()
def reality_panel(tmp_path: Path):
    os.environ["XPANEL_DB"] = str(tmp_path / "panel.db")
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, flow,
                config_path, xray_bin, xray_service
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "chrome",
                "xtls-rprx-vision", str(tmp_path / "config.json"),
                "/bin/true", "xray",
            ),
        )
    init_db()
    user = add_user("Test 3")
    slots = {int(row["id"]): row for row in list_reality_inbounds()}
    update_server_settings(
        address="vpn.example.com",
        listen="0.0.0.0",
        port=443,
        dest="www.bing.com:443",
        server_name="www.bing.com",
        private_key="private",
        public_key="public",
        short_id="0011223344556677",
        fingerprint="chrome",
        flow="xtls-rprx-vision",
        loglevel="warning",
        api_listen="127.0.0.1:10085",
        stats_enabled=False,
        config_path=str(tmp_path / "config.json"),
        xray_bin="/bin/true",
        xray_service="xray",
        inbound_profile="raw_reality",
        reality_instances=[
            {
                "id": 1,
                "name": "REALITY — основной",
                "enabled": True,
                "listen": "0.0.0.0",
                "port": 443,
                "short_id": "0011223344556677",
            },
            {
                "id": 2,
                "name": "REALITY — резервный",
                "enabled": True,
                "listen": "0.0.0.0",
                "port": 8443,
                "short_id": str(slots[2]["short_id"]),
            },
            {
                "id": 3,
                "name": "REALITY — дополнительный",
                "enabled": True,
                "listen": "0.0.0.0",
                "port": 9443,
                "short_id": str(slots[3]["short_id"]),
            },
        ],
    )
    yield tmp_path, user
    os.environ.pop("XPANEL_DB", None)


def test_multi_links_use_short_english_roles(reality_panel):
    _root, user = reality_panel
    links = make_links(user["id"])
    assert [unquote(urlsplit(str(item["link"])).fragment) for item in links] == [
        "Test 3/Primary",
        "Test 3/Backup",
        "Test 3/Alt",
    ]


def test_saved_links_keep_inactive_profiles_visible(reality_panel):
    _root, user = reality_panel
    saved = make_saved_links(user["id"])
    active = [item for item in saved if item["active"]]
    inactive = [item for item in saved if not item["active"]]

    assert len(active) == 3
    assert {item["profile"] for item in active} == {"raw_reality"}
    assert {item["profile"] for item in inactive} >= {
        "xhttp_tls", "xhttp_reality", "hysteria2_tls"
    }
    assert all(item["profile_label"] for item in saved)
    inactive_xhttp = next(item for item in inactive if item["profile"] == "xhttp_tls")
    assert parse_qs(urlsplit(str(inactive_xhttp["link"])).query)["sni"] == ["vpn.example.com"]


def test_subscription_still_contains_only_active_links(reality_panel):
    _root, user = reality_panel
    update_subscription_settings(
        enabled=True,
        profile_title="SG Client",
        base_url="https://panel.example.com",
    )
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc42-subscription",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    response = client.get(f"/sub/{user['subscription_token']}?format=plain")
    assert response.status_code == 200
    lines = [line for line in response.get_data(as_text=True).splitlines() if line]
    assert len(lines) == 3
    assert all("security=reality" in line for line in lines)
    assert not any("security=tls" in line for line in lines)
    assert not any(line.startswith("hysteria2://") for line in lines)


def test_client_page_separates_active_and_saved_links(reality_panel):
    _root, user = reality_panel
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc42-client-page",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    response = client.get(f"/users/{user['id']}/link")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Активные сейчас" in body
    assert "Сохранённые, но неактивные" in body
    assert "Сейчас не работает" in body
    assert "Подписка выдаёт только соединения, которые реально активны" in body
    assert "Test 3/Primary" in body


def test_installer_starts_with_password_and_then_runs_without_prompts():
    text = INSTALLER.read_text(encoding="utf-8")
    password_prompt = text.index('prompt_value XPANEL_ADMIN_PASSWORD "Пароль администратора')
    address_prompt = text.index('prompt_value XRAY_ADDRESS "Адрес Xray')
    first_stage = text.index('stage 1 3 "Подготовка системы"')
    assert password_prompt < address_prompt < first_stage
    assert "Все параметры приняты. Дальнейшая установка не потребует ввода" in text


def test_installer_uses_awg_style_live_progress_and_persistent_log():
    text = INSTALLER.read_text(encoding="utf-8")
    for token in (
        "spinner_loop(){",
        "step_begin(){",
        "step_ok(){",
        "run_logged(){",
        "wait_for_apt(){",
        "stage 1 3",
        "stage 2 3",
        "stage 3 3",
        "SG_PANEL_INSTALL_LOG",
        '>>"$LOG_FILE" 2>&1',
        "Последние строки журнала",
    ):
        assert token in text
    assert "apt-get -o Dpkg::Use-Pty=0 update -qq" in text
    assert "ЖУРНАЛ" in text
