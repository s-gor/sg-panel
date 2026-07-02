from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "xpanel" / "templates"


def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def test_hysteria_profile_is_exposed_in_inbound_ui() -> None:
    html = _read("settings.html")
    assert 'value="hysteria2_tls"' in html
    assert "Hysteria 2 + TLS" in html
    assert "UDP / QUIC" in html
    assert 'name="hysteria_udp_idle_timeout"' in html
    assert 'name="hysteria_masquerade_type"' in html
    assert 'name="hysteria_masquerade_url"' in html
    assert 'name="hysteria_masquerade_content"' in html
    assert 'name="tls_cert_path"' in html
    assert "Security Group" in html


def test_client_and_subscription_pages_are_protocol_neutral() -> None:
    link = _read("link.html")
    users = _read("users.html")
    subscriptions = _read("subscriptions.html")
    assert "HYSTERIA 2 / UDP" in link
    assert "server.inbound_profile" in link
    assert "текущего Inbound" in users
    assert "текущего Inbound-профиля" in subscriptions


def test_diagnostics_exposes_udp_transport_and_combined_ports() -> None:
    html = _read("diagnostics.html")
    service = (ROOT / "xpanel" / "service.py").read_text(encoding="utf-8")
    assert "TCP и UDP-порты" in html
    assert "diagnostics.transport_protocol" in html
    assert '["ss", "-lnup"]' in service
    assert '"transport_protocol": "UDP"' in service


def test_hysteria_database_fields_have_migrations() -> None:
    db = (ROOT / "xpanel" / "db.py").read_text(encoding="utf-8")
    for field in (
        "hysteria_udp_idle_timeout",
        "hysteria_masquerade_type",
        "hysteria_masquerade_url",
        "hysteria_masquerade_content",
        "hysteria_masquerade_status",
    ):
        assert field in db
        assert f'_ensure_column(con, "server_settings", "{field}"' in db


def test_hysteria_documentation_covers_udp_and_ec2() -> None:
    docs = (ROOT / "docs" / "INBOUND-PROFILES.md").read_text(encoding="utf-8")
    assert "Hysteria 2 + TLS" in docs
    assert "Security Group" in docs
    assert "443/udp" in docs
    assert "ss -lnup" in docs
    assert "hysteria2://" in docs


def test_hysteria_runtime_tls_copy_is_private_and_rewrites_config(tmp_path, monkeypatch) -> None:
    import json
    import xpanel.service as service

    source_cert = tmp_path / "source-fullchain.pem"
    source_key = tmp_path / "source-privkey.pem"
    source_cert.write_text("certificate-data", encoding="utf-8")
    source_key.write_text("private-key-data", encoding="utf-8")
    runtime_dir = tmp_path / "runtime-tls"
    monkeypatch.setenv("XPANEL_HYSTERIA_TLS_DIR", str(runtime_dir))
    monkeypatch.setattr(service, "_xray_service_identity", lambda _name: (65534, 65534))
    monkeypatch.setattr(service.os, "chown", lambda *_args: None)

    server = {
        "tls_cert_path": str(source_cert),
        "tls_key_path": str(source_key),
        "xray_service": "xray",
    }
    cert_path, key_path = service._sync_hysteria_tls_material(server)
    assert cert_path.read_text(encoding="utf-8") == "certificate-data"
    assert key_path.read_text(encoding="utf-8") == "private-key-data"
    assert cert_path.stat().st_mode & 0o777 == 0o640
    assert key_path.stat().st_mode & 0o777 == 0o640

    config = {
        "inbounds": [{
            "tag": "vless-reality-in",
            "protocol": "hysteria",
            "streamSettings": {
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": str(source_cert),
                        "keyFile": str(source_key),
                    }]
                }
            },
        }]
    }
    rewritten = json.loads(service._runtime_hysteria_config_text(json.dumps(config), cert_path, key_path))
    certificate = rewritten["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]
    assert certificate["certificateFile"] == str(cert_path)
    assert certificate["keyFile"] == str(key_path)


def test_certificate_renewal_hook_syncs_hysteria_tls() -> None:
    installer = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
    uninstaller = (ROOT / "deploy" / "uninstall.sh").read_text(encoding="utf-8")
    assert "sync-sg-panel-hysteria-tls.sh" in installer
    assert "sync-hysteria-tls --restart" in installer
    assert "sync-sg-panel-hysteria-tls.sh" in uninstaller
