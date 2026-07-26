from pathlib import Path
from unittest.mock import patch

import pytest

from xpanel.db import connect, init_db
import xpanel.service as service

ROOT = Path(__file__).resolve().parents[1]


def test_installer_uses_shared_validated_xray_policy_and_has_rollback() -> None:
    script = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    policy = (ROOT / "deploy/xray-version.env").read_text(encoding="utf-8")
    assert 'XRAY_VERSION="v26.6.27"' in policy
    assert 'source "$XRAY_VERSION_FILE"' in script
    assert 'XRAY_VERSION="v26.5.9"' not in script
    assert "ensure_xray_version" in script
    assert "rollback_xray" in script
    assert "xray run -test -config" in script
    assert "Установка или проверка Xray" in script
    assert "Сохраняю установленный Xray" in script


def test_inbound_recommendations_prefer_detected_certificate() -> None:
    server = {
        "address": "18.184.17.146",
        "server_name": "www.bing.com",
        "dest": "www.bing.com:443",
        "xhttp_path": "/sg-xhttp",
        "xhttp_mode": "auto",
        "transport_port": 8443,
    }
    candidates = [{
        "domain": "infosec.opik.net",
        "cert": "/etc/letsencrypt/live/infosec.opik.net/fullchain.pem",
        "key": "/etc/letsencrypt/live/infosec.opik.net/privkey.pem",
    }]
    with (
        patch.object(service, "get_server", return_value=server),
        patch.object(service, "_read_simple_env", side_effect=[
            {"PANEL_DOMAIN": "infosec.opik.net"}, {}
        ]),
        patch.object(service, "_nginx_panel_domain", return_value="infosec.opik.net"),
        patch.object(service, "_certificate_candidates", return_value=candidates),
        patch.object(service, "_listener_status", side_effect=["занят", "свободен"]),
    ):
        result = service.get_inbound_recommendations()

    hysteria = result["profiles"]["hysteria2_tls"]
    assert result["domain"] == "infosec.opik.net"
    assert result["certificate_found"] is True
    assert result["xray_recommended_version"] == "v26.6.27"
    assert hysteria["address"] == "infosec.opik.net"
    assert hysteria["server_name"] == "infosec.opik.net"
    assert hysteria["listen"] == "0.0.0.0"
    assert hysteria["port"] == 443
    assert hysteria["hysteria_udp_idle_timeout"] == 60
    assert hysteria["hysteria_masquerade_status"] == 404


def test_inbound_page_exposes_auto_detection_and_safe_apply_button() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "Панель настроит профиль сама" not in html
    assert "Обнаружено автоматически" in html
    assert "Основное подключение" in html
    assert "Сохранить и применить" in html
    assert "READY PROFILES" not in html
    assert "server-profile-form" in html
    assert ".inbound-detection-card" in css



def test_reality_sni_is_not_detected_as_tls_domain() -> None:
    server = {
        "address": "18.184.17.146",
        "server_name": "www.bing.com",
        "dest": "www.bing.com:443",
        "xhttp_path": "/sg-xhttp",
        "xhttp_mode": "auto",
        "transport_port": 8443,
    }
    with (
        patch.object(service, "get_server", return_value=server),
        patch.object(service, "_read_simple_env", side_effect=[{}, {}]),
        patch.object(service, "_nginx_panel_domain", return_value=""),
        patch.object(service, "_certificate_candidates", return_value=[]),
        patch.object(service, "_listener_status", side_effect=["свободен", "свободен"]),
    ):
        result = service.get_inbound_recommendations()

    hysteria = result["profiles"]["hysteria2_tls"]
    assert result["domain"] == ""
    assert result["certificate_found"] is False
    assert hysteria["address"] == "18.184.17.146"
    assert hysteria["server_name"] == ""
    assert hysteria["tls_cert_path"] == ""
    assert hysteria["tls_key_path"] == ""


def test_switch_to_hysteria_does_not_reuse_reality_sni(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "panel.db"
    monkeypatch.setenv("XPANEL_DB", str(db_path))
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
                "18.184.17.146", "0.0.0.0", 443,
                "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "chrome",
                "xtls-rprx-vision", str(tmp_path / "config.json"), "/bin/true", "xray",
            ),
        )

    with pytest.raises(ValueError, match="Hysteria 2 требует ваш реальный домен"):
        service.update_server_settings(
            address="18.184.17.146",
            listen="0.0.0.0",
            port=443,
            dest="www.bing.com:443",
            server_name="www.bing.com",
            private_key="private",
            public_key="public",
            short_id="0011223344556677",
            fingerprint="chrome",
            flow="",
            loglevel="warning",
            api_listen="127.0.0.1:10085",
            stats_enabled=True,
            config_path=str(tmp_path / "config.json"),
            xray_bin="/bin/true",
            xray_service="xray",
            inbound_profile="hysteria2_tls",
            transport_listen="127.0.0.1",
            transport_port=8443,
            xhttp_path="/sg-xhttp",
            xhttp_mode="auto",
            grpc_service_name="sg-grpc",
            tls_cert_path="",
            tls_key_path="",
        )

    with connect() as con:
        row = con.execute("SELECT inbound_profile, server_name, tls_cert_path FROM server_settings WHERE id=1").fetchone()
    assert row["inbound_profile"] == "raw_reality"
    assert row["server_name"] == "www.bing.com"
    assert row["tls_cert_path"] == ""
