from __future__ import annotations

import os
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "test-secret")
os.environ.setdefault("XPANEL_PASSWORD_HASH", "scrypt:32768:8:1$test$test")

from xpanel.db import connect, init_db
from xpanel.service import parse_vless_share_link
from xpanel.web import create_app


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def reality_link() -> str:
    return (
        "vless://11111111-1111-4111-8111-111111111111@54.10.20.30:443"
        "?type=tcp&security=reality&pbk=Public_Key-123&fp=firefox"
        "&sni=www.bing.com&sid=aabbccdd&flow=xtls-rprx-vision&spx=%2F"
        "#Cascade-CC1-to-CC2%2FPrimary"
    )


def test_reality_link_is_fully_parsed_for_cascade():
    parsed = parse_vless_share_link(reality_link())
    assert parsed["tag"] == "cascade-cc2"
    assert parsed["name"] == "Cascade-CC1-to-CC2/Primary"
    assert parsed["address"] == "54.10.20.30"
    assert parsed["port"] == 443
    assert parsed["uuid"] == "11111111-1111-4111-8111-111111111111"
    assert parsed["network"] == "raw"
    assert parsed["security"] == "reality"
    assert parsed["flow"] == "xtls-rprx-vision"
    assert parsed["server_name"] == "www.bing.com"
    assert parsed["public_key"] == "Public_Key-123"
    assert parsed["short_id"] == "aabbccdd"
    assert parsed["fingerprint"] == "firefox"
    assert parsed["spider_x"] == "/"
    assert parsed["vision"] is True


def test_xhttp_tls_link_is_parsed_without_inventing_vision():
    parsed = parse_vless_share_link(
        "vless://22222222-2222-4222-8222-222222222222@exit.example.com:8443"
        "?type=xhttp&security=tls&fp=firefox&sni=exit.example.com"
        "&host=cdn.example.com&path=%2Fsg-xhttp&mode=packet-up&alpn=h2%2Chttp%2F1.1"
        "#Virginia%20Exit"
    )
    assert parsed["tag"] == "virginia-exit"
    assert parsed["network"] == "xhttp"
    assert parsed["security"] == "tls"
    assert parsed["flow"] == ""
    assert parsed["xhttp_host"] == "cdn.example.com"
    assert parsed["xhttp_path"] == "/sg-xhttp"
    assert parsed["xhttp_mode"] == "packet-up"
    assert parsed["alpn"] == "h2,http/1.1"
    assert parsed["vision"] is False


@pytest.mark.parametrize(
    ("link", "message"),
    [
        ("https://example.com", "vless://"),
        (
            "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            "?type=grpc&security=reality&pbk=key&sni=www.bing.com",
            "RAW/TCP или XHTTP",
        ),
        (
            "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            "?type=tcp&security=reality&sni=www.bing.com&fp=firefox",
            "public key",
        ),
    ],
)
def test_invalid_or_unsupported_links_are_rejected_clearly(link: str, message: str):
    with pytest.raises(ValueError) as exc:
        parse_vless_share_link(link)
    assert message.lower() in str(exc.value).lower()


def test_outbounds_page_contains_link_import_ui_and_autofill_script():
    template = read("xpanel/templates/outbounds.html")
    assert "Импорт из VLESS-ссылки" in template
    assert "Разобрать и заполнить" in template
    assert "data-vless-link-input" in template
    assert "outbound_import_vless" in template
    assert "не сохраняется в панели" in template
    assert "cascade-cc2" not in template  # suggestion comes from the actual link
    assert "setField('public_key', outbound.public_key)" in template
    assert "setField('short_id', outbound.short_id)" in template


def test_import_endpoint_parses_but_does_not_create_outbound(tmp_path, monkeypatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id,address,listen,port,dest,server_name,private_key,public_key,
                short_id,fingerprint,config_path,xray_bin,xray_service
            ) VALUES (1,'panel.example.com','0.0.0.0',443,'www.bing.com:443',
                'www.bing.com','private','public','0011223344556677','firefox',
                '/tmp/config.json','/bin/true','xray')
            """
        )

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc59-test-secret",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    with client.session_transaction() as session:
        csrf = session["csrf_token"]

    response = client.post(
        "/outbounds/import-vless",
        data={"csrf_token": csrf, "vless_link": reality_link()},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["outbound"]["tag"] == "cascade-cc2"
    assert payload["outbound"]["address"] == "54.10.20.30"

    with connect() as con:
        assert con.execute("SELECT COUNT(*) FROM outbounds").fetchone()[0] == 0
