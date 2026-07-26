from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

import xpanel.service as service
from xpanel.db import connect, init_db
from xpanel.service import (
    XPanelError,
    add_routing_rule,
    apply_geofiles_source,
    validate_geofiles_source,
    validate_uploaded_geofiles,
)


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
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("placeholder", encoding="utf-8")
    key.write_text("placeholder", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text('{"old": true}\n', encoding="utf-8")
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
                "private", "public", "0011223344556677", "firefox", "",
                str(config_path), "/bin/true", "xray.service",
                "xhttp_tls", "127.0.0.1", 8443, "/sg-xhttp", "auto",
                str(cert), str(key),
            ),
        )
    state = tmp_path / "state"
    active = tmp_path / "active"
    active.mkdir()
    active_geoip = active / "geoip.dat"
    active_geosite = active / "geosite.dat"
    active_geoip.write_bytes(b"old-geoip" * 1024)
    active_geosite.write_bytes(b"old-geosite" * 1024)
    monkeypatch.setattr(service, "GEOFILES_STATE_DIR", state)
    monkeypatch.setattr(service, "_current_asset_paths", lambda: (active_geoip, active_geosite))
    monkeypatch.setattr(service, "require_root", lambda: None)

    events: list[tuple[str, str]] = []

    def fake_run(args, **kwargs):
        if args[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(args, 0, stdout="active\n", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    def fake_systemctl(action: str, unit: str, **kwargs):
        events.append(("systemctl", action))

    def fake_confirm(unit: str):
        events.append(("confirm", unit))

    monkeypatch.setattr(service, "_run", fake_run)
    monkeypatch.setattr(service, "_systemctl_checked", fake_systemctl)
    monkeypatch.setattr(service, "_confirm_xray_active", fake_confirm)
    return {
        "root": tmp_path,
        "state": state,
        "active_geoip": active_geoip,
        "active_geosite": active_geosite,
        "config": config_path,
        "events": events,
    }


def _write_pair(tmp_path: Path, *, ip: tuple[str, ...] = ("private",), site: tuple[str, ...] = ("private",)):
    geoip = tmp_path / "candidate-geoip.dat"
    geosite = tmp_path / "candidate-geosite.dat"
    geoip.write_bytes(_geo_file(*ip))
    geosite.write_bytes(_geo_file(*site))
    return geoip, geosite


def test_bundled_sg_client_pair_has_expected_hashes_and_categories(panel):
    manifest = validate_geofiles_source(source="sgclient")
    assert manifest["source_label"] == "Комплект SG Client"
    assert manifest["geoip"]["sha256"] == "c0f37cacaca04fcf273d6fc740e236748b2a7a082056b162bf7ce95db8af6efa"
    assert manifest["geosite"]["sha256"] == "8bc708286ac3160003d9eba7290841f931e3ef41a05d92555a07b513a7a08163"
    assert len(manifest["geoip_categories"]) == 266
    assert len(manifest["geosite_categories"]) == 1506
    assert manifest["compatible"] is True
    assert manifest["candidate_xray_test"] == "ok"


def test_bundled_pair_rejects_hash_mismatch(panel, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "geoip.dat").write_bytes(_geo_file("private"))
    (bundle / "geosite.dat").write_bytes(_geo_file("private"))
    monkeypatch.setattr(service, "GEOFILES_BUNDLED_DIR", bundle)
    with pytest.raises(XPanelError, match="SHA-256 не совпадает"):
        validate_geofiles_source(source="sgclient")


def test_missing_category_hard_blocks_and_preserves_user_rule(panel):
    root = panel["root"]
    add_routing_rule(
        name="Google through Cascade",
        priority=70,
        outbound_tag="blocked",
        domains="geosite:google",
    )
    geoip, geosite = _write_pair(root)
    manifest = validate_geofiles_source(
        source="local", geoip_local_path=str(geoip), geosite_local_path=str(geosite)
    )
    assert manifest["compatible"] is False
    assert manifest["missing_categories"] == ["geosite:google"]
    with connect() as con:
        state = con.execute("SELECT last_check_state FROM geofiles_settings WHERE id=1").fetchone()[0]
        rule = con.execute("SELECT enabled, domains FROM routing_rules WHERE name=?", ("Google through Cascade",)).fetchone()
    assert state == "blocked"
    assert rule["enabled"] == 1
    assert rule["domains"] == "geosite:google"
    with pytest.raises(XPanelError, match="отсутствуют категории"):
        apply_geofiles_source()
    with connect() as con:
        rule_after = con.execute("SELECT enabled, domains FROM routing_rules WHERE name=?", ("Google through Cascade",)).fetchone()
    assert dict(rule_after) == dict(rule)


def test_full_candidate_is_tested_before_live_assets_are_touched(panel, monkeypatch: pytest.MonkeyPatch):
    root = panel["root"]
    geoip, geosite = _write_pair(root, ip=("private", "ru"), site=("private", "category-ru"))
    validate_geofiles_source(source="local", geoip_local_path=str(geoip), geosite_local_path=str(geosite))
    panel["events"].clear()
    real_test = service._run_xray_test_with_assets

    def tracked_test(binary, config, assets):
        panel["events"].append(("xray-test", str(Path(assets))))
        return real_test(binary, config, assets)

    monkeypatch.setattr(service, "_run_xray_test_with_assets", tracked_test)
    result = apply_geofiles_source()
    assert result["service"] == "active"
    assert panel["events"][0] == ("xray-test", str(panel["state"] / "staging"))
    stop_index = panel["events"].index(("systemctl", "stop"))
    assert stop_index > 0
    assert (panel["state"] / "sets" / result["generation"] / "manifest.json").is_file()
    assert (panel["state"] / "sets" / result["generation"] / "config.json").is_file()


def test_failed_restart_rolls_back_files_config_db_and_confirms_service(panel, monkeypatch: pytest.MonkeyPatch):
    root = panel["root"]
    old_geoip = panel["active_geoip"].read_bytes()
    old_geosite = panel["active_geosite"].read_bytes()
    old_config = panel["config"].read_bytes()
    geoip, geosite = _write_pair(root, ip=("private", "ru"), site=("private", "category-ru"))
    validate_geofiles_source(source="local", geoip_local_path=str(geoip), geosite_local_path=str(geosite))
    calls = 0

    def fail_first_confirm(unit: str):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise XPanelError("forced active failure")

    monkeypatch.setattr(service, "_confirm_xray_active", fail_first_confirm)
    with pytest.raises(XPanelError, match="forced active failure"):
        apply_geofiles_source()
    assert calls == 2
    assert panel["active_geoip"].read_bytes() == old_geoip
    assert panel["active_geosite"].read_bytes() == old_geosite
    assert panel["config"].read_bytes() == old_config
    with connect() as con:
        settings = con.execute("SELECT active_generation, active_source FROM geofiles_settings WHERE id=1").fetchone()
    assert settings["active_generation"] == ""
    assert settings["active_source"] == "xray"


def test_roscomvpn_preset_adds_only_existing_categories_and_keeps_user_rules(panel):
    root = panel["root"]
    add_routing_rule(
        name="User domain",
        priority=50,
        outbound_tag="direct",
        domains="domain:example.com",
    )
    geoip, geosite = _write_pair(
        root,
        ip=("private", "direct"),
        site=("private", "category-ru", "category-ads", "torrent"),
    )
    validate_geofiles_source(
        source="local", geoip_local_path=str(geoip), geosite_local_path=str(geosite)
    )
    # The preset is source-gated; set the selected source to RoscomVPN while retaining the checked pair.
    with connect() as con:
        con.execute("UPDATE geofiles_settings SET source='roscomvpn' WHERE id=1")
    result = apply_geofiles_source(server_preset="roscomvpn", enable_block=True)
    assert result["preset"]["final_outbound"] == "direct"
    with connect() as con:
        user = con.execute("SELECT enabled, domains, outbound_tag FROM routing_rules WHERE name='User domain'").fetchone()
        direct = con.execute("SELECT domains, ips, outbound_tag FROM routing_rules WHERE name=?", (service.ROSCOMVPN_DIRECT_RULE,)).fetchone()
        blocked = con.execute("SELECT enabled, domains, outbound_tag FROM routing_rules WHERE name=?", (service.ROSCOMVPN_BLOCK_RULE,)).fetchone()
        final = con.execute("SELECT default_outbound_tag FROM routing_settings WHERE id=1").fetchone()[0]
    assert dict(user) == {"enabled": 1, "domains": "domain:example.com", "outbound_tag": "direct"}
    assert direct["domains"].splitlines() == ["geosite:private", "geosite:category-ru"]
    assert direct["ips"].splitlines() == ["geoip:private", "geoip:direct"]
    assert blocked["enabled"] == 1
    assert blocked["domains"].splitlines() == ["geosite:category-ads", "geosite:torrent"]
    assert final == "direct"


def test_browser_upload_stores_and_checks_the_pair(panel):
    result = validate_uploaded_geofiles(io.BytesIO(_geo_file("private")), io.BytesIO(_geo_file("private")))
    assert result["source"] == "local"
    assert result["compatible"] is True
    upload_root = service.GEOFILES_STATE_DIR / "uploads" / "current"
    assert (upload_root / "geoip.dat").is_file()
    assert (upload_root / "geosite.dat").is_file()
