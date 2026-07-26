from __future__ import annotations

import os
import tempfile
from pathlib import Path

from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc43-help")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.web import create_app


ROOT = Path(__file__).resolve().parents[1]


def test_help_template_covers_profiles_and_operational_sections() -> None:
    html = (ROOT / "xpanel/templates/help.html").read_text(encoding="utf-8")
    for marker in (
        'id="profiles"',
        'id="reality-vision"',
        'id="xhttp-tls"',
        'id="xhttp-reality"',
        'id="hysteria2"',
        'id="mixed"',
        'id="clients-links"',
        'id="tls-https"',
        'id="routing"',
        'id="backups"',
        'id="updates"',
        'id="diagnostics"',
    ):
        assert marker in html
    assert "XTLS Vision является параметром REALITY" in html
    assert "Активные сейчас" in html
    assert "Сохранённые, но неактивные" in html
    assert "Имя/Профиль 1" in html


def test_context_help_links_point_to_exact_sections() -> None:
    settings = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    subscriptions = (ROOT / "xpanel/templates/subscriptions.html").read_text(encoding="utf-8")
    security = (ROOT / "xpanel/templates/security.html").read_text(encoding="utf-8")
    assert "#profiles" in settings
    assert "#reality-vision" in settings
    assert "#xhttp-tls" in settings
    assert "#xhttp-reality" in settings
    assert "#hysteria2" in settings
    assert "#tls-https" in settings
    assert "#clients-links" in subscriptions
    assert "#tls-https" in security
    assert "#panel-exposure" in security


def test_help_page_is_authenticated_and_renders() -> None:
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
                    "192.168.1.200", "0.0.0.0", 443,
                    "www.bing.com:443", "www.bing.com",
                    "private", "public", "0011223344556677", "chrome",
                    "/tmp/config.json", "/bin/true", "xray",
                ),
            )
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "rc43-help",
                "PASSWORD_HASH": generate_password_hash("correct-password"),
            }
        )
        client = app.test_client()
        assert client.get("/help").status_code == 302
        response = client.post("/login", data={"password": "correct-password"})
        assert response.status_code == 302
        response = client.get("/help")
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert "Справка SG-Panel" in body
        assert "Пять профилей SG-Panel" in body
        assert "VLESS XHTTP-REALITY" in body
    os.environ.pop("XPANEL_DB", None)


def test_help_styles_and_navigation_are_present() -> None:
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    assert ".help-layout" in css
    assert ".context-help-link" in css
    assert "url_for('help_page')" in base
    assert "Профили и настройки" in base
    assert "Справка SG-Panel" in base
