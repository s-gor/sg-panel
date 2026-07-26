from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from xpanel.db import connect, init_db
from xpanel.service import (
    _hysteria_masquerade,
    _hysteria_quic_params,
    _validate_hysteria_hop_interval,
    _validate_hysteria_hop_ports,
    add_user,
    build_config,
    config_json_document,
    make_link,
    update_config_json_document,
    update_server_settings,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "xpanel" / "templates"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_hysteria_studio_ui_contains_three_levels_and_presets() -> None:
    html = _read(TEMPLATES / "settings.html")
    for marker in (
        "HYSTERIA STUDIO",
        "ОСНОВНЫЕ",
        "ПРОИЗВОДИТЕЛЬНОСТЬ",
        "Экспертные параметры Hysteria 2",
        "Автоматически",
        "Мобильная сеть",
        "Высокая скорость",
        "Ограниченный сервер",
        "Пользовательский",
        'name="hysteria_congestion"',
        'name="hysteria_udp_hop_ports"',
        'name="hysteria_masquerade_dir"',
        'name="hysteria_masquerade_headers"',
    ):
        assert marker in html


def test_success_flash_is_inline_and_auto_dismisses() -> None:
    html = _read(TEMPLATES / "base.html")
    css = _read(ROOT / "xpanel" / "static" / "app.css")
    assert "document.querySelectorAll('.flash-toast.success')" in html
    assert "7000" in html
    assert ".flash-toast.is-leaving" in css
    flash_block = css[css.index(".flash-stack"):css.index(".flash-toast", css.index(".flash-stack"))]
    assert "position: relative" in flash_block
    assert "position: fixed" not in flash_block


def test_hysteria_schema_and_migrations_include_studio_fields() -> None:
    with tempfile.TemporaryDirectory() as temp:
        os.environ["XPANEL_DB"] = str(Path(temp) / "panel.db")
        try:
            init_db()
            with connect() as con:
                columns = {row["name"] for row in con.execute("PRAGMA table_info(server_settings)")}
            for name in (
                "hysteria_performance_profile",
                "hysteria_congestion",
                "hysteria_bbr_profile",
                "hysteria_brutal_up",
                "hysteria_brutal_down",
                "hysteria_masquerade_dir",
                "hysteria_masquerade_headers",
                "hysteria_udp_hop_ports",
                "hysteria_udp_hop_interval",
                "hysteria_max_incoming_streams",
                "hysteria_init_stream_receive_window",
                "hysteria_max_connection_receive_window",
            ):
                assert name in columns
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_quic_params_and_masquerade_helpers_generate_official_shape() -> None:
    values = {
        "hysteria_congestion": "force-brutal",
        "hysteria_bbr_profile": "standard",
        "hysteria_quic_debug": 1,
        "hysteria_brutal_up": "60 mbps",
        "hysteria_brutal_down": "0",
        "hysteria_init_stream_receive_window": 8388608,
        "hysteria_max_stream_receive_window": 8388608,
        "hysteria_init_connection_receive_window": 20971520,
        "hysteria_max_connection_receive_window": 20971520,
        "hysteria_max_idle_timeout": 30,
        "hysteria_keepalive_period": 10,
        "hysteria_disable_pmtud": 0,
        "hysteria_max_incoming_streams": 1024,
        "hysteria_udp_hop_ports": "20000-20100",
        "hysteria_udp_hop_interval": "5-10",
        "hysteria_masquerade_type": "proxy",
        "hysteria_masquerade_url": "https://example.com/",
        "hysteria_masquerade_rewrite_host": 1,
        "hysteria_masquerade_insecure": 0,
        "hysteria_masquerade_dir": "",
        "hysteria_masquerade_headers": "{}",
        "hysteria_masquerade_content": "",
        "hysteria_masquerade_status": 404,
    }
    params = _hysteria_quic_params(values)  # type: ignore[arg-type]
    assert params["congestion"] == "force-brutal"
    assert params["brutalUp"] == "60 mbps"
    assert params["brutalDown"] == "0"
    assert isinstance(params["brutalUp"], str)
    assert isinstance(params["brutalDown"], str)
    assert params["udpHop"] == {"ports": "20000-20100", "interval": "5-10"}
    assert params["keepAlivePeriod"] == 10
    assert _hysteria_masquerade(values) == {  # type: ignore[arg-type]
        "type": "proxy",
        "url": "https://example.com/",
        "rewriteHost": True,
        "insecure": False,
    }


def test_hopping_validation_rejects_unsafe_values() -> None:
    assert _validate_hysteria_hop_ports("443,20000-20100") == "443,20000-20100"
    assert _validate_hysteria_hop_interval("5-10") == "5-10"
    with pytest.raises(ValueError):
        _validate_hysteria_hop_ports("50000-20000")
    with pytest.raises(ValueError):
        _validate_hysteria_hop_interval("4")


def test_hysteria_studio_values_round_trip_and_link_uses_hopping_ports() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        cert = root / "fullchain.pem"
        key = root / "privkey.pem"
        cert.write_text("certificate", encoding="utf-8")
        key.write_text("private key", encoding="utf-8")
        try:
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
                        "vpn.example.com", "0.0.0.0", 443,
                        "www.bing.com:443", "vpn.example.com",
                        "private", "public", "0011223344556677", "chrome",
                        str(root / "config.json"), "/bin/true", "xray",
                    ),
                )
            user = add_user("Studio")
            update_server_settings(
                address="vpn.example.com", listen="0.0.0.0", port=443,
                dest="www.bing.com:443", server_name="vpn.example.com",
                private_key="private", public_key="public", short_id="0011223344556677",
                fingerprint="chrome", flow="", loglevel="warning",
                api_listen="127.0.0.1:10085", stats_enabled=False,
                config_path=str(root / "config.json"), xray_bin="/bin/true", xray_service="xray",
                inbound_profile="hysteria2_tls", transport_listen="127.0.0.1", transport_port=8443,
                xhttp_path="/sg", xhttp_mode="auto", grpc_service_name="sg-grpc",
                tls_cert_path=str(cert), tls_key_path=str(key),
                hysteria_udp_idle_timeout=90,
                hysteria_masquerade_type="string",
                hysteria_masquerade_content="<h1>OK</h1>",
                hysteria_masquerade_status=200,
                hysteria_masquerade_headers='{"content-type":"text/html"}',
                hysteria_performance_profile="speed",
                hysteria_congestion="force-brutal",
                hysteria_bbr_profile="aggressive",
                hysteria_brutal_up="60 mbps",
                hysteria_brutal_down="120 mbps",
                hysteria_quic_debug=True,
                hysteria_max_idle_timeout=45,
                hysteria_keepalive_period=10,
                hysteria_disable_pmtud=True,
                hysteria_max_incoming_streams=2048,
                hysteria_udp_hop_ports="443,20000-20100",
                hysteria_udp_hop_interval="5-10",
            )
            config, server, _users = build_config()
            stream = config["inbounds"][0]["streamSettings"]
            assert stream["hysteriaSettings"]["masquerade"]["statusCode"] == 200
            params = stream["finalmask"]["quicParams"]
            assert params["congestion"] == "force-brutal"
            assert params["udpHop"]["ports"] == "443,20000-20100"
            assert params["maxIncomingStreams"] == 2048
            link = make_link(user["id"])
            assert f"@vpn.example.com:443,20000-20100/" in link

            document = json.loads(config_json_document())
            metadata = document["inbounds"][0]["_sgPanel"]
            assert metadata["hysteriaPerformanceProfile"] == "speed"
            assert metadata["hysteriaUdpHopPorts"] == "443,20000-20100"
            update_config_json_document(json.dumps(document))
            with connect() as con:
                saved = con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
            assert saved["hysteria_congestion"] == "force-brutal"
            assert saved["hysteria_udp_hop_ports"] == "443,20000-20100"
            assert server["hysteria_performance_profile"] == "speed"
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_hysteria_full_diagnostics_page_is_available() -> None:
    settings = _read(TEMPLATES / "settings.html")
    diagnostics = _read(TEMPLATES / "hysteria_diagnostics.html")
    web = _read(ROOT / "xpanel" / "web.py")
    service = _read(ROOT / "xpanel" / "service.py")
    assert "Полная проверка" in settings
    assert "settings_hysteria_diagnostics" in settings
    assert "FULL HYSTERIA CHECK" in diagnostics
    assert "Внешняя доступность UDP" in service
    assert 'def settings_hysteria_diagnostics()' in web
    assert '"hysteria_diagnostics.html"' in web


def test_hysteria_diagnostics_returns_structured_local_checks(monkeypatch) -> None:
    import subprocess
    import xpanel.service as service

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        os.environ["XPANEL_DB"] = str(root / "panel.db")
        cert = root / "fullchain.pem"
        key = root / "privkey.pem"
        cert.write_text("certificate", encoding="utf-8")
        key.write_text("private key", encoding="utf-8")
        try:
            init_db()
            with connect() as con:
                con.execute(
                    """
                    INSERT INTO server_settings (
                        id, address, listen, port, dest, server_name,
                        private_key, public_key, short_id, fingerprint,
                        config_path, xray_bin, xray_service, inbound_profile,
                        tls_cert_path, tls_key_path
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "vpn.example.com", "0.0.0.0", 443,
                        "www.bing.com:443", "vpn.example.com",
                        "private", "public", "0011223344556677", "chrome",
                        str(root / "config.json"), "/bin/true", "xray",
                        "hysteria2_tls", str(cert), str(key),
                    ),
                )
            add_user("Diagnostic")

            def fake_run(args, **_kwargs):
                if args[0] == "openssl":
                    return subprocess.CompletedProcess(args, 0, "notAfter=Jul 01 00:00:00 2027 GMT\n", "")
                if args[:2] == ["systemctl", "is-active"]:
                    return subprocess.CompletedProcess(args, 0, "active\n", "")
                if args[0] == "journalctl":
                    return subprocess.CompletedProcess(args, 0, "Xray started\n", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            monkeypatch.setattr(service, "_run", fake_run)
            monkeypatch.setattr(service, "_listener_status", lambda *_args: "занят")
            monkeypatch.setattr(service, "validate_generated_config", lambda: {"ok": True, "detail": "xray run -test: OK"})
            monkeypatch.setattr(
                service.socket,
                "getaddrinfo",
                lambda *_args, **_kwargs: [(2, 2, 17, "", ("203.0.113.10", 443))],
            )
            report = service.get_hysteria_diagnostics()
            assert report["overall_ok"] is True
            assert report["endpoint"] == "vpn.example.com:443/UDP"
            assert any(item["key"] == "external" and item["level"] == "neutral" for item in report["checks"])
            assert any(item["key"] == "udp" and item["level"] == "ok" for item in report["checks"])
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_hysteria_bandwidth_zero_is_always_serialized_as_string() -> None:
    from xpanel.service import _hysteria_rate_value

    for value in (0, "0", " 0 ", None, ""):
        result = _hysteria_rate_value(value)
        assert result == "0"
        assert isinstance(result, str)

    for value, expected in (("100 mbps", "100 mbps"), ("20MB", "20mb"), ("1g", "1g")):
        result = _hysteria_rate_value(value)
        assert result == expected
        assert isinstance(result, str)


def test_all_hysteria_presets_keep_bandwidth_values_as_strings() -> None:
    html = _read(TEMPLATES / "settings.html")
    for preset in ("auto", "mobile", "speed", "limited"):
        marker = f"{preset}: {{"
        start = html.index(marker)
        end = html.index("}", start)
        block = html[start:end]
        assert "hysteria_brutal_up: '0'" in block
        assert "hysteria_brutal_down: '0'" in block


def test_generated_hysteria_json_uses_string_bandwidth_for_unlimited() -> None:
    values = {
        "hysteria_congestion": "brutal",
        "hysteria_bbr_profile": "standard",
        "hysteria_quic_debug": 0,
        "hysteria_brutal_up": "0",
        "hysteria_brutal_down": "0",
        "hysteria_init_stream_receive_window": 8388608,
        "hysteria_max_stream_receive_window": 8388608,
        "hysteria_init_connection_receive_window": 20971520,
        "hysteria_max_connection_receive_window": 20971520,
        "hysteria_max_idle_timeout": 30,
        "hysteria_keepalive_period": 0,
        "hysteria_disable_pmtud": 0,
        "hysteria_max_incoming_streams": 1024,
        "hysteria_udp_hop_ports": "",
        "hysteria_udp_hop_interval": "30",
    }
    params = _hysteria_quic_params(values)  # type: ignore[arg-type]
    encoded = json.dumps({"quicParams": params})
    decoded = json.loads(encoded)["quicParams"]
    assert decoded["brutalUp"] == "0"
    assert decoded["brutalDown"] == "0"
    assert '\"brutalUp\": \"0\"' in encoded
    assert '\"brutalDown\": \"0\"' in encoded
