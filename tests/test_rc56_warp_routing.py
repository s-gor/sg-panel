import os
import json
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", "scrypt:32768:8:1$test$test")

from xpanel.db import connect, init_db
from xpanel.web import _friendly_geodata_error, create_app


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_rc56_version_and_ui_revision_are_consistent():
    assert '__version__ = "0.10.0-rc70"' in read("xpanel/__init__.py")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_UI_REVISION="sg070"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("deploy/ec2-first-install.sh")
    assert "sg070" in read("xpanel/templates/base.html")
    assert "sg070" in read("xpanel/templates/login.html")


def test_routing_page_has_separate_warp_condition_fields_and_preset():
    template = read("xpanel/templates/routing.html")
    assert "Российские сайты и IP" in template
    assert "Домены / Geosite" in template
    assert "IP / GeoIP / CIDR" in template
    assert 'name="selected_domains"' in template
    assert 'name="selected_ips"' in template
    assert "Фактически созданные правила" in template
    assert "логическое AND" in template
    assert "data-warp-preset" in template
    assert "geosite:category-ru" in read("xpanel/service.py")
    assert "geoip:ru" in read("xpanel/service.py")


def test_cluster_heading_is_neutral_and_compact():
    template = read("xpanel/templates/nodes.html")
    assert "<h2>Подключение SG-Node</h2>" in template
    assert "Подготовьте сервер, добавьте его в Cluster и выполните подключение." in template
    assert "без пропущенных шагов" not in template


def test_missing_geosite_category_is_reported_clearly():
    detail = (
        "failed to load geosite: category-ru > "
        "code not found in geosite.dat: category-ru"
    )
    message = _friendly_geodata_error(detail)
    assert "Категория Geosite «category-ru»" in message
    assert "Routing → GeoFiles" in message


def test_missing_geoip_category_is_reported_clearly():
    detail = "failed to load geoip.dat: list not found: ru"
    message = _friendly_geodata_error(detail)
    assert "Категория GeoIP «ru»" in message
    assert "geoip.dat" in message


def test_unrelated_xray_error_is_not_rewritten():
    detail = "failed to bind TCP port 443"
    assert _friendly_geodata_error(detail) == detail


def test_release_notes_explain_two_rules_and_safe_migration():
    notes = read("RELEASE-NOTES-RC56.md")
    assert "два управляемых правила" in notes
    assert "selected_ips" in notes
    assert "Существующие домены" in notes
    assert "SG Client" in notes



def test_configured_warp_form_validates_and_saves_domain_and_ip_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    outbound = {
        "protocol": "wireguard",
        "tag": "warp",
        "settings": {
            "secretKey": "secret",
            "address": ["172.16.0.2/32"],
            "peers": [{
                "publicKey": "public",
                "endpoint": "162.159.192.1:2408",
                "allowedIPs": ["0.0.0.0/0"],
            }],
        },
    }
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,config_path,xray_bin,xray_service
            ) VALUES (1,'vpn.example.com','0.0.0.0',443,'www.bing.com:443',
                'www.bing.com','private','public','0011223344556677','firefox',
                '/tmp/config.json','/bin/true','xray')
            """
        )
        con.execute(
            "UPDATE warp_settings SET enabled=1, outbound_json=? WHERE id=1",
            (json.dumps(outbound),),
        )

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "rc56-test-secret",
        "PASSWORD_HASH": generate_password_hash("correct-password"),
    })
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    with client.session_transaction() as session:
        csrf = session["csrf_token"]

    response = client.get("/routing")
    assert response.status_code == 200
    assert "Российские сайты и IP" in response.get_data(as_text=True)

    draft = {
        "csrf_token": csrf,
        "action": "validate",
        "route_mode": "selected",
        "selected_domains": "geosite:category-ru",
        "selected_ips": "geoip:ru",
    }
    ok_validation = {"ok": True, "detail": "xray run -test: OK", "users": 0, "json": "{}"}
    with patch("xpanel.web.validate_generated_config", return_value=ok_validation):
        validation = client.post("/warp/routing", data=draft)
    assert validation.status_code == 200
    body = validation.get_json()
    assert body["ok"] is True

    save = dict(draft)
    save.pop("action")
    save["validation_token"] = body["token"]
    with patch("xpanel.web.apply_config", return_value={
        "enabled_users": 0, "enabled_rules": 2, "service": "active", "profile": "raw_reality"
    }):
        saved = client.post("/warp/routing", data=save)
    assert saved.status_code == 302

    with connect() as con:
        rows = con.execute(
            "SELECT domains,ips,priority FROM routing_rules WHERE outbound_tag='warp' AND enabled=1 ORDER BY priority"
        ).fetchall()
    assert [(row["domains"], row["ips"], row["priority"]) for row in rows] == [
        ("geosite:category-ru", "", 40),
        ("", "geoip:ru", 41),
    ]
