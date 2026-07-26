from __future__ import annotations

import os
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc51-exposure-test")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.security import get_security_settings, update_panel_exposure_settings
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    monkeypatch.setenv("XPANEL_ACCESS_STATE_FILE", str(tmp_path / "panel-access.env"))
    (tmp_path / "panel-access.env").write_text(
        "PANEL_ACCESS_MODE=https\nPANEL_PUBLIC_HOST=panel.example.com\nPANEL_PUBLIC_PORT=8443\n",
        encoding="utf-8",
    )
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
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "vpn.example.com",
                "private", "public", "0011223344556677", "chrome", "",
                str(tmp_path / "config.json"), "/bin/true", "xray",
                "raw_reality", "127.0.0.1", 8443, "/sg-xhttp", "auto",
            ),
        )
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc51-exposure-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    return app


def test_rc51_security_columns_default_to_direct(panel):
    settings = get_security_settings()
    assert settings["panel_exposure_mode"] == "direct"
    assert settings["cloudflare_hostname"] == ""
    assert settings["cloudflare_origin_lockdown"] == 0
    assert settings["cloudflare_access_enabled"] == 0


def test_rc51_panel_exposure_validation(panel):
    with pytest.raises(ValueError, match="hostname"):
        update_panel_exposure_settings(mode="cloudflare_proxy")
    with pytest.raises(ValueError, match="полным доменным"):
        update_panel_exposure_settings(mode="cloudflare_proxy", cloudflare_hostname="localhost")

    row = update_panel_exposure_settings(
        mode="cloudflare_proxy",
        cloudflare_hostname="Panel.Example.com.",
        cloudflare_origin_lockdown=True,
    )
    assert row["panel_exposure_mode"] == "cloudflare_proxy"
    assert row["cloudflare_hostname"] == "panel.example.com"
    assert row["cloudflare_origin_lockdown"] == 1


def test_rc52_advanced_is_contextual_and_available_without_unlock(panel):
    app = panel
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302

    settings_response = client.get("/settings")
    assert settings_response.status_code == 200
    settings_body = settings_response.get_data(as_text=True)
    assert "inbound-expert-entry" not in settings_body
    assert "Открыть Expert &amp; GeoFiles" not in settings_body

    legacy = client.get("/settings/expert")
    assert legacy.status_code == 302
    assert legacy.headers["Location"].endswith("/settings/advanced")

    advanced_response = client.get("/settings/advanced")
    assert advanced_response.status_code == 200
    advanced_body = advanced_response.get_data(as_text=True)
    assert "Xray Server" in advanced_body
    assert "Включить редактирование" not in advanced_body
    assert "data-expert-edit-fieldset" not in advanced_body
    assert "Vision настраивается в Inbound" not in advanced_body
    assert "Подключения текущей схемы" in advanced_body
    assert "Итоговые конфигурации" in advanced_body
    assert "Проверка текущей схемы" in advanced_body
    assert 'name="certificate_pinning_sha256"' not in advanced_body
    assert "Проверить и применить" in advanced_body

    geofiles_response = client.get("/routing/geofiles")
    assert geofiles_response.status_code == 200
    geofiles_body = geofiles_response.get_data(as_text=True)
    assert "GeoFiles" in geofiles_body
    assert "Комплект SG Client" in geofiles_body

def test_rc51_security_page_shows_three_exposure_modes(panel):
    app = panel
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    response = client.get("/security")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for text in (
        "Panel exposure",
        "Direct through Nginx",
        "Cloudflare Proxy",
        "Cloudflare Tunnel + Access",
        "Я уже ограничил origin во внешнем firewall",
        "Я уже создал Cloudflare Access application и policy",
        "Сохранить режим и проверить готовность",
        "CF-Connecting-IP",
    ):
        assert text in body


def test_rc51_client_ip_uses_cloudflare_header_only_after_declared_protection(panel):
    app = panel
    update_panel_exposure_settings(
        mode="cloudflare_proxy",
        cloudflare_hostname="panel.example.com",
        cloudflare_origin_lockdown=True,
    )
    client = app.test_client()
    response = client.post(
        "/login",
        data={"password": "correct-password"},
        headers={"CF-Connecting-IP": "198.51.100.18", "CF-Ray": "abc-FRA"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response.status_code == 302
    with connect() as con:
        row = con.execute(
            "SELECT ip_address FROM login_attempts ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row["ip_address"] == "198.51.100.18"


def test_rc51_release_markers_and_short_names():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    security = (ROOT / "xpanel/templates/security.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "sg070" in base
    assert "SG-Panel 054 — guided Cluster onboarding and Firefox REALITY defaults" in css
    assert "security_exposure_save" in security
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in installer
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
