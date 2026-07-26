from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from werkzeug.security import generate_password_hash

os.environ.setdefault("XPANEL_SECRET_KEY", "rc50-expert-test")
os.environ.setdefault("XPANEL_PASSWORD_HASH", generate_password_hash("correct-password"))

from xpanel.db import connect, init_db
from xpanel import service
from xpanel.service import (
    XPanelError,
    _source_values,
    add_user,
    apply_geofiles_source,
    build_config,
    calculate_certificate_pin,
    get_geofiles_overview,
    get_transport_expert_settings,
    make_links,
    managed_client_export,
    update_transport_expert_settings,
    validate_geofiles_source,
)
from xpanel.web import create_app

ROOT = Path(__file__).resolve().parents[1]


def _varint(value: int) -> bytes:
    result = bytearray()
    while True:
        current = value & 0x7F
        value >>= 7
        result.append(current | (0x80 if value else 0))
        if not value:
            return bytes(result)


def _geo_file(*categories: str) -> bytes:
    body = bytearray()
    for category in categories:
        encoded = category.encode("utf-8")
        message = b"\x0a" + _varint(len(encoded)) + encoded
        body += b"\x0a" + _varint(len(message)) + message
    padding = max(0, 8192 - len(body) - 4)
    body += b"\x12" + _varint(padding) + (b"\0" * padding)
    return bytes(body)


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
                "private", "public", "0011223344556677", "chrome", "",
                str(tmp_path / "config.json"), "/bin/true", "xray",
                "xhttp_tls", "127.0.0.1", 8443, "/sg-xhttp", "auto",
                str(cert), str(key),
            ),
        )
    user = add_user("RC50 Client")
    return tmp_path, user


def test_rc50_tables_are_initialized(panel):
    expert = get_transport_expert_settings()
    geofiles = get_geofiles_overview()
    assert expert["xhttp_extra_server_json"].strip() == "{}"
    assert expert["finalmask_enabled"] == 0
    assert geofiles["selected_source"] == "sgclient"
    with connect() as con:
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert {"transport_expert_settings", "geofiles_settings"} <= tables


def test_xhttp_mode_extra_and_finalmask_reach_config_and_links(panel):
    _root, user = panel
    update_transport_expert_settings(
        xhttp_mode="stream-one",
        xmux_mode="expert",
        xhttp_extra_server_json='{"xmux":{"maxConnections":4}}',
        xhttp_extra_client_json='{"xmux":{"maxConnections":2}}',
        finalmask_enabled=True,
        finalmask_server_json='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8"],"delays":["10-20"],"maxSplit":"3-6"}}]}',
        finalmask_client_json='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8"],"delays":["10-20"],"maxSplit":"3-6"}}]}',
        certificate_pinning_enabled=True,
        certificate_pinning_sha256="b" * 64,
        certificate_pinning_source="current TLS certificate",
    )
    config, server, _users = build_config()
    assert server["xhttp_mode"] == "stream-one"
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    assert stream["xhttpSettings"]["mode"] == "stream-one"
    assert stream["xhttpSettings"]["extra"]["xmux"]["maxConnections"] == 4
    assert stream["finalmask"]["tcp"][0]["type"] == "fragment"

    link = make_links(user["id"])[0]["link"]
    query = parse_qs(urlsplit(str(link)).query)
    assert query["mode"] == ["stream-one"]
    assert json.loads(unquote(query["extra"][0]))["xmux"]["maxConnections"] == 2
    assert json.loads(unquote(query["fm"][0]))["tcp"][0]["type"] == "fragment"
    assert query["pcs"] == ["b" * 64]


def test_expert_validation_rejects_invalid_values(panel):
    with pytest.raises(ValueError, match="XHTTP Mode"):
        update_transport_expert_settings(xhttp_mode="magic")
    with pytest.raises(ValueError, match="корень JSON"):
        update_transport_expert_settings(xhttp_extra_server_json="[]")
    with pytest.raises(ValueError, match="неизвестные поля верхнего уровня"):
        update_transport_expert_settings(
            finalmask_enabled=True,
            finalmask_server_json='{"tcpParams":{"type":"none"}}',
            finalmask_client_json='{"tcpParams":{"type":"none"}}',
        )
    with pytest.raises(ValueError, match="64 HEX"):
        update_transport_expert_settings(
            certificate_pinning_enabled=True,
            certificate_pinning_sha256="abcd",
        )
    with pytest.raises(ValueError, match="echServerKeys"):
        update_transport_expert_settings(
            ech_mode="dns",
            ech_public_name="public.example.com",
            ech_config_list="https://1.1.1.1/dns-query",
        )


def test_managed_export_never_contains_ech_server_secret(panel):
    _root, user = panel
    with connect() as con:
        con.execute(
            "UPDATE server_settings SET inbound_profile='hysteria2_tls' WHERE id=1"
        )
    update_transport_expert_settings(
        ech_mode="existing",
        ech_public_name="public.example.com",
        ech_server_keys="SERVER-SECRET-KEY",
        ech_config_list="CLIENT-ECH-CONFIG",
        certificate_pinning_enabled=True,
        certificate_pinning_sha256="a" * 64,
        certificate_pinning_source="current TLS certificate",
    )
    payload = managed_client_export(user["id"])
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "SERVER-SECRET-KEY" not in encoded
    assert payload["ech"]["configList"] == "CLIENT-ECH-CONFIG"
    assert payload["certificatePinning"]["pinnedPeerCertSha256"] == "a" * 64


def test_certificate_pin_is_sha256_of_der_certificate(panel, tmp_path: Path):
    cert = tmp_path / "test-cert.pem"
    key = tmp_path / "test-key.pem"
    proc = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=example.com", "-days", "1",
            "-keyout", str(key), "-out", str(cert),
        ],
        text=True, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        pytest.skip("openssl certificate generation is unavailable")
    result = calculate_certificate_pin(str(cert))
    assert len(result["sha256"]) == 64
    assert set(result["sha256"]) <= set("0123456789abcdef")
    assert result["source"] == str(cert)


def test_supported_geofiles_sources_and_url_rules(panel):
    for source in ("loyalsoldier", "runetfreedom", "roscomvpn"):
        values = _source_values(source)
        assert values["geoip_url"].startswith("https://")
        assert values["geosite_url"].startswith("https://")
    with pytest.raises(ValueError, match="HTTPS"):
        _source_values(
            "custom",
            "http://example.com/geoip.dat",
            "https://example.com/geosite.dat",
        )
    with pytest.raises(ValueError, match="логином"):
        _source_values(
            "custom",
            "https://user:pass@example.com/geoip.dat",
            "https://example.com/geosite.dat",
        )


def test_local_geofiles_check_and_apply_is_atomic(
    panel, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source_geoip = tmp_path / "source-geoip.dat"
    source_geosite = tmp_path / "source-geosite.dat"
    source_geoip.write_bytes(_geo_file("private", "ru"))
    source_geosite.write_bytes(_geo_file("private", "category-ru"))

    active_dir = tmp_path / "active"
    active_dir.mkdir()
    active_geoip = active_dir / "geoip.dat"
    active_geosite = active_dir / "geosite.dat"
    active_geoip.write_bytes(b"old-ip" * 1024)
    active_geosite.write_bytes(b"old-site" * 1024)

    state_dir = tmp_path / "state"
    monkeypatch.setattr(service, "GEOFILES_STATE_DIR", state_dir)
    monkeypatch.setattr(
        service, "_current_asset_paths", lambda: (active_geoip, active_geosite)
    )
    monkeypatch.setattr(service, "render_text", lambda: ("{}\n", None, None))
    monkeypatch.setattr(
        service.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(service, "require_root", lambda: None)
    monkeypatch.setattr(
        service, "validate_generated_config", lambda: {"ok": True, "detail": "OK"}
    )
    monkeypatch.setattr(service, "restart_xray", lambda: "active")

    manifest = validate_geofiles_source(
        source="local",
        geoip_local_path=str(source_geoip),
        geosite_local_path=str(source_geosite),
    )
    assert manifest["source"] == "local"
    result = apply_geofiles_source()
    assert result["source"] == "local"
    assert active_geoip.read_bytes() == source_geoip.read_bytes()
    assert active_geosite.read_bytes() == source_geosite.read_bytes()
    assert (state_dir / "original-xray" / "geoip.dat").is_file()
    assert (state_dir / "original-xray" / "geosite.dat").is_file()


def test_failed_geofiles_check_is_visible(panel, tmp_path: Path, monkeypatch):
    geoip = tmp_path / "geoip.dat"
    geosite = tmp_path / "geosite.dat"
    geoip.write_bytes(_geo_file("private"))
    geosite.write_bytes(_geo_file("private"))
    monkeypatch.setattr(service, "GEOFILES_STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(service, "render_text", lambda: ("{}\n", None, None))
    monkeypatch.setattr(
        service.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="failed category: geosite:missing"
        ),
    )
    with pytest.raises(XPanelError, match="missing"):
        validate_geofiles_source(
            source="local",
            geoip_local_path=str(geoip),
            geosite_local_path=str(geosite),
        )
    overview = get_geofiles_overview()
    assert overview["settings"]["last_check_state"] == "error"
    assert "missing" in overview["settings"]["last_check_message"]


def test_advanced_and_geofiles_pages_contain_explanations_and_examples(panel):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "rc50-expert-test",
            "PASSWORD_HASH": generate_password_hash("correct-password"),
        }
    )
    client = app.test_client()
    assert client.post("/login", data={"password": "correct-password"}).status_code == 302

    legacy = client.get("/settings/expert")
    assert legacy.status_code == 302
    assert legacy.headers["Location"].endswith("/settings/advanced")

    response = client.get("/settings/advanced")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for text in (
        "Фактическое состояние",
        "Подключения текущей схемы",
        "XHTTP mode",
        "Server Extra",
        "Client Extra",
        "FinalMask",
        "Ручной JSON XHTTP и XMUX",
        "Итоговые конфигурации",
        "Проверка текущей схемы",
        "Проверить и применить параметры",
    ):
        assert text in body
    assert 'name="ech_mode"' not in body

    response = client.get("/routing/geofiles")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for text in (
        "Комплект SG Client", "Loyalsoldier", "RunetFreedom", "RoscomVPN",
        "Пользовательские URL", "Локальные файлы",
    ):
        assert text in body

def test_subscription_json_contains_managed_export(panel):
    _root, user = panel
    with connect() as con:
        con.execute(
            "UPDATE subscription_settings SET enabled=1 WHERE id=1"
        )
    token = str(user["subscription_token"])
    app = create_app({"TESTING": True, "SECRET_KEY": "rc50-sub-test"})
    client = app.test_client()
    response = client.get(f"/sub/{token}?format=json")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["managed"]["schema"] == "sg-panel-managed-profile-v1"
    assert payload["managed"]["user"]["name"] == "RC50 Client"
    assert payload["managedV2"]["schema"] == "sg-panel-managed-profile-v2"
    assert payload["managedPreferred"] == "managedV2"


def test_release_contains_rc52_contextual_documentation():
    advanced = (ROOT / "xpanel/templates/advanced.html").read_text(encoding="utf-8")
    geofiles = (ROOT / "xpanel/templates/geofiles.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "РАСШИРЕННЫЕ ПАРАМЕТРЫ" in advanced
    assert "Исправность файлов и совместимость Routing проверяются отдельно" in geofiles
    assert "SG-Panel 054 — guided Cluster onboarding and Firefox REALITY defaults" in css
    assert "Включить редактирование" not in advanced

