from __future__ import annotations

import os
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", "scrypt:32768:8:1$test$test")

from xpanel.db import connect, init_db
from xpanel.service import get_instance_address, get_instance_identity, update_instance_name
from xpanel.web import create_app


@pytest.fixture()
def panel_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, instance_name, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, config_path,
                xray_bin, xray_service
            ) VALUES (1, 'SG-Panel', '63.179.105.193', '0.0.0.0', 443,
                'www.bing.com:443', 'www.bing.com', 'private', 'public',
                '0011223344556677', 'firefox', ?, '/bin/true', 'xray')
            """,
            (str(tmp_path / "config.json"),),
        )
    return tmp_path


def test_default_identity_contains_public_address(panel_db):
    assert get_instance_address() == "63.179.105.193"
    assert get_instance_identity() == "SG-Panel · 63.179.105.193"


def test_custom_name_keeps_address_visible(panel_db):
    update_instance_name("CC1 Frankfurt")
    assert get_instance_identity() == "CC1 Frankfurt · 63.179.105.193"


def test_address_is_not_duplicated_when_already_in_name(panel_db):
    update_instance_name("CC1-63.179.105.193")
    assert get_instance_identity() == "CC1-63.179.105.193"


def test_header_login_and_system_render_identity(panel_db):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "identity-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    login = client.get("/login")
    assert b"SG-Panel" in login.data
    assert b"63.179.105.193" in login.data
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    dashboard = client.get("/")
    assert b"SG-Panel \xc2\xb7 63.179.105.193" in dashboard.data
    system = client.get("/diagnostics?tab=status")
    assert b"instance-address-field" in system.data
    assert b"63.179.105.193" in system.data


def test_release_markers_are_rc68():
    root = Path(__file__).resolve().parents[1]
    assert '__version__ = "0.10.0-rc70"' in (root / 'xpanel/__init__.py').read_text(encoding='utf-8')
    assert 'sg070' in (root / 'xpanel/templates/base.html').read_text(encoding='utf-8')
    assert 'SG-Panel RC70 — Latte light theme preview' in (root / 'xpanel/static/app.css').read_text(encoding='utf-8')
