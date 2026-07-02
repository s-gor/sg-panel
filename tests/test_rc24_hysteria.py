from pathlib import Path
from unittest.mock import patch

import xpanel.service as service

ROOT = Path(__file__).resolve().parents[1]


def test_installer_pins_xray_2659_and_has_rollback() -> None:
    script = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    assert 'XRAY_VERSION="v26.5.9"' in script
    assert "ensure_xray_version" in script
    assert "rollback_xray" in script
    assert "xray run -test -config" in script
    assert "Обновление Xray до $XRAY_VERSION с автоматическим откатом" in script


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
    assert result["xray_recommended_version"] == "v26.5.9"
    assert hysteria["address"] == "infosec.opik.net"
    assert hysteria["server_name"] == "infosec.opik.net"
    assert hysteria["listen"] == "0.0.0.0"
    assert hysteria["port"] == 443
    assert hysteria["hysteria_udp_idle_timeout"] == 60
    assert hysteria["hysteria_masquerade_status"] == 404


def test_inbound_page_exposes_auto_detection_and_safe_apply_button() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "Обнаружено автоматически" in html
    assert "Подставить рекомендуемые значения" in html
    assert "inbound_recommendations|tojson" in html
    assert "field.dataset.userEdited" in html
    assert ".inbound-detection-card" in css
