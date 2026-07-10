from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc53-managed-contract-test")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel.service import (
    add_user,
    build_config,
    get_transport_expert_settings,
    load_client_ca_pem,
    make_links,
    managed_client_export_v2,
    update_transport_expert_settings,
)
from xpanel.web import create_app


@pytest.fixture()
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("placeholder", encoding="utf-8")
    key.write_text("placeholder", encoding="utf-8")
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, flow,
                config_path, xray_bin, xray_service, inbound_profile,
                transport_listen, transport_port, xhttp_path, xhttp_mode,
                tls_cert_path, tls_key_path
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "vpn.example.com",
                "private", "public", "0011223344556677", "chrome",
                "xtls-rprx-vision", str(tmp_path / "config.json"),
                "/bin/true", "xray", "raw_reality", "127.0.0.1", 8443,
                "/sg-xhttp", "auto", str(cert), str(key),
            ),
        )
    user = add_user("RC53 Client")
    return tmp_path, user


def _create_certificate(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "ca.pem"
    key = tmp_path / "ca.key"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=RC53 Test CA", "-days", "1",
            "-keyout", str(key), "-out", str(cert),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("openssl certificate generation is unavailable")
    return cert, key


def test_rc53_database_has_client_contract_columns(panel):
    row = get_transport_expert_settings()
    assert row["tls_verify_name_mode"] == "auto"
    assert row["tls_verify_name"] == ""
    assert row["client_ca_pem"] == ""
    assert row["client_ca_sha256"] == ""


def test_reality_contract_contains_flow_and_omits_tls_material(panel):
    _root, user = panel
    with connect() as con:
        con.execute(
            """
            UPDATE transport_expert_settings SET
                ech_mode='existing', ech_public_name='outer.example.com',
                ech_server_keys='SERVER-SECRET-RC53', ech_config_list='CLIENT-ECH-RC53',
                certificate_pinning_enabled=1, certificate_pinning_sha256=?,
                certificate_pinning_source='administrator',
                client_ca_pem='PUBLIC-CA-RC53', client_ca_source='administrator',
                client_ca_sha256='ca-sha'
            WHERE id=1
            """,
            ("a" * 64,),
        )
    payload = managed_client_export_v2(user["id"])
    assert payload["schema"] == "sg-panel-managed-profile-v2"
    connection = payload["connections"][0]
    assert connection["security"] == "reality"
    assert connection["reality"]["flow"] == "xtls-rprx-vision"
    assert connection["credential"] == {
        "type": "uuid", "value": str(user["uuid"]), "source": "SG-Panel"
    }
    assert connection["tls"]["applicable"] is False
    assert "flow=xtls-rprx-vision" in connection["uri"]
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "SERVER-SECRET-RC53" not in encoded
    assert "CLIENT-ECH-RC53" not in encoded
    assert "PUBLIC-CA-RC53" not in encoded
    assert "a" * 64 not in encoded


def test_xhttp_tls_contract_exports_verified_client_values(panel):
    root, user = panel
    cert, _key = _create_certificate(root)
    imported = load_client_ca_pem(str(cert))
    with connect() as con:
        con.execute(
            "UPDATE server_settings SET inbound_profile='xhttp_tls', flow='' WHERE id=1"
        )
    update_transport_expert_settings(
        certificate_pinning_enabled=True,
        certificate_pinning_sha256="b" * 64,
        certificate_pinning_source="SG-Panel certificate file",
        tls_verify_name_mode="manual",
        tls_verify_name="certificate.example.com",
        client_ca_pem=imported["pem"],
        client_ca_source="private CA supplied by administrator",
    )
    payload = managed_client_export_v2(user["id"])
    connection = payload["connections"][0]
    verification = connection["tls"]["verification"]
    assert connection["security"] == "tls"
    assert connection["tls"]["ech"]["applicable"] is False
    assert verification["mode"] == "pinned_sha256_and_custom_ca"
    assert verification["systemCaEnabled"] is True
    assert verification["verifyPeerCertByName"] == "certificate.example.com"
    assert verification["pinnedPeerCertSha256"] == "b" * 64
    assert "BEGIN CERTIFICATE" in verification["customCaPem"]
    query = parse_qs(urlsplit(connection["uri"]).query)
    assert query["pcs"] == ["b" * 64]
    assert query["vcn"] == ["certificate.example.com"]
    assert "ech" not in query


def test_hysteria_ech_exports_only_client_config(panel):
    _root, user = panel
    with connect() as con:
        con.execute(
            "UPDATE server_settings SET inbound_profile='hysteria2_tls', flow='' WHERE id=1"
        )
    update_transport_expert_settings(
        ech_mode="existing",
        ech_public_name="outer.example.com",
        ech_server_keys="SERVER-ECH-SECRET",
        ech_config_list="CLIENT-ECH-CONFIG",
    )
    config, _server, _users = build_config()
    tls_settings = config["inbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls_settings["echServerKeys"] == "SERVER-ECH-SECRET"

    payload = managed_client_export_v2(user["id"])
    connection = payload["connections"][0]
    assert connection["tls"]["ech"]["applicable"] is True
    assert connection["tls"]["ech"]["configList"] == "CLIENT-ECH-CONFIG"
    assert connection["credential"]["type"] == "auth"
    assert connection["credential"]["value"]
    assert connection["endpoint"]["portSpec"]
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "SERVER-ECH-SECRET" not in encoded


def test_hysteria_ech_dns_mode_keeps_server_key_and_exports_resolver(panel):
    _root, user = panel
    with connect() as con:
        con.execute(
            "UPDATE server_settings SET inbound_profile='hysteria2_tls', flow='' WHERE id=1"
        )
    resolver = "outer.example.com+https://1.1.1.1/dns-query"
    update_transport_expert_settings(
        ech_mode="dns",
        ech_public_name="outer.example.com",
        ech_server_keys="SERVER-ECH-DNS-SECRET",
        ech_config_list=resolver,
    )
    config, _server, _users = build_config()
    assert config["inbounds"][0]["streamSettings"]["tlsSettings"]["echServerKeys"] == "SERVER-ECH-DNS-SECRET"
    payload = managed_client_export_v2(user["id"])
    ech = payload["connections"][0]["tls"]["ech"]
    assert ech["mode"] == "dns"
    assert ech["configList"] == resolver
    assert ech["source"] == "dns_https_record"
    assert "SERVER-ECH-DNS-SECRET" not in json.dumps(payload)


def test_subscription_json_advertises_managed_v2(panel):
    _root, user = panel
    with connect() as con:
        con.execute("UPDATE subscription_settings SET enabled=1 WHERE id=1")
    app = create_app({"TESTING": True, "SECRET_KEY": "rc53-sub-test"})
    client = app.test_client()
    response = client.get(f"/sub/{user['subscription_token']}?format=json")
    assert response.status_code == 200
    assert response.headers["X-SG-Managed-Profile"] == "v2"
    payload = response.get_json()
    assert payload["managedPreferred"] == "managedV2"
    assert payload["managed"]["schema"] == "sg-panel-managed-profile-v1"
    assert payload["managedV2"]["schema"] == "sg-panel-managed-profile-v2"


def test_advanced_page_is_contextual_for_reality_tls_and_ech(panel):
    _root, _user = panel
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc53-page-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302

    reality = client.get("/settings/advanced").get_data(as_text=True)
    assert "Vision настраивается в Inbound" in reality
    assert 'name="ech_mode"' not in reality
    assert 'name="certificate_pinning_sha256"' not in reality
    assert 'name="client_ca_pem"' not in reality
    assert "ECH, SHA-256 сертификата и CA PEM не экспортируются для REALITY" in reality

    with connect() as con:
        con.execute("UPDATE server_settings SET inbound_profile='xhttp_tls', flow='' WHERE id=1")
    xhttp_tls = client.get("/settings/advanced").get_data(as_text=True)
    assert 'name="certificate_pinning_sha256"' in xhttp_tls
    assert 'name="client_ca_pem"' in xhttp_tls
    assert 'name="ech_mode"' not in xhttp_tls
    assert "TLS завершается в Nginx" in xhttp_tls

    with connect() as con:
        con.execute("UPDATE server_settings SET inbound_profile='hysteria2_tls' WHERE id=1")
    hysteria = client.get("/settings/advanced").get_data(as_text=True)
    assert 'name="ech_mode"' in hysteria
    assert "echServerKeys · server secret" in hysteria


def test_client_access_page_exposes_managed_json_url(panel):
    _root, user = panel
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc53-link-page-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302
    body = client.get(f"/users/{user['id']}/link").get_data(as_text=True)
    assert "SG Client · управляемый JSON v2" in body
    assert "?format=json" in body
    assert "Скопировать для SG Client" in body


def test_ca_import_rejects_private_key(panel, tmp_path: Path):
    bad = tmp_path / "bad.pem"
    bad.write_text(
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="закрытый ключ"):
        load_client_ca_pem(str(bad))
