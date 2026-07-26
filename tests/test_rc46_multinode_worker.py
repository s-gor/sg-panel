from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


WORKER_PATH = Path(__file__).resolve().parents[1] / "node_agent" / "sg_node_worker.py"


def pilot_config():
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "sg-node-reality-in",
                "listen": "0.0.0.0",
                "port": 8443,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": "11111111-1111-4111-8111-111111111111",
                            "email": "Test User",
                            "flow": "xtls-rprx-vision",
                            "level": 0,
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": "www.microsoft.com:443",
                        "xver": 0,
                        "serverNames": ["www.microsoft.com"],
                        "privateKey": "abcdefghijklmnopqrstuvwxyzABCDE_1234567890",
                        "shortIds": ["0011223344556677"],
                    },
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
    }


def load_worker():
    spec = importlib.util.spec_from_file_location("sg_node_worker_test", WORKER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_worker_validates_and_applies_xray_config(tmp_path, monkeypatch):
    worker = load_worker()
    worker.XRAY_CONFIG = tmp_path / "xray" / "config.json"
    worker.BACKUP_DIR = tmp_path / "backups"
    worker.XRAY_BIN = tmp_path / "xray-bin"
    worker.XRAY_BIN.write_text("fake", encoding="utf-8")
    worker.XRAY_CONFIG.parent.mkdir(parents=True)
    worker.XRAY_CONFIG.write_text('{"old": true}\n', encoding="utf-8")

    calls = []

    def fake_command(args, *, timeout=45):
        calls.append(list(args))
        if args[:3] == ["systemctl", "is-active", "xray.service"]:
            return subprocess.CompletedProcess(args, 0, stdout="active\n", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(worker, "command", fake_command)
    config = pilot_config()
    payload = {
        "profile": "VLESS REALITY",
        "config": config,
        "client_count": 1,
    }
    result = worker.apply_xray_config(7, payload)
    assert result["profile"] == "VLESS REALITY"
    assert result["client_count"] == 1
    assert json.loads(worker.XRAY_CONFIG.read_text(encoding="utf-8")) == config
    assert any("-test" in call for call in calls)
    assert any(call[:2] == ["systemctl", "restart"] for call in calls)
    assert list(worker.BACKUP_DIR.glob("config-before-job-7-*.json"))


def test_worker_does_not_replace_config_when_xray_test_fails(tmp_path, monkeypatch):
    worker = load_worker()
    worker.XRAY_CONFIG = tmp_path / "xray" / "config.json"
    worker.BACKUP_DIR = tmp_path / "backups"
    worker.XRAY_BIN = tmp_path / "xray-bin"
    worker.XRAY_BIN.write_text("fake", encoding="utf-8")
    worker.XRAY_CONFIG.parent.mkdir(parents=True)
    worker.XRAY_CONFIG.write_text('{"old": true}\n', encoding="utf-8")

    def fake_command(args, *, timeout=45):
        if "-test" in args:
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="invalid config")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(worker, "command", fake_command)
    with pytest.raises(RuntimeError, match="invalid config"):
        worker.apply_xray_config(8, {"config": pilot_config()})
    assert json.loads(worker.XRAY_CONFIG.read_text(encoding="utf-8")) == {"old": True}


def test_worker_rejects_non_pilot_config_before_xray(tmp_path, monkeypatch):
    worker = load_worker()
    worker.XRAY_CONFIG = tmp_path / "xray" / "config.json"
    worker.BACKUP_DIR = tmp_path / "backups"
    worker.XRAY_BIN = tmp_path / "xray-bin"
    worker.XRAY_BIN.write_text("fake", encoding="utf-8")
    worker.XRAY_CONFIG.parent.mkdir(parents=True)
    worker.XRAY_CONFIG.write_text('{"old": true}\n', encoding="utf-8")
    called = False

    def fake_command(args, *, timeout=45):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(worker, "command", fake_command)
    with pytest.raises(RuntimeError, match="unsupported top-level"):
        worker.apply_xray_config(
            9,
            {"config": {"inbounds": [], "outbounds": [], "api": {"services": ["HandlerService"]}}},
        )
    assert called is False
    assert json.loads(worker.XRAY_CONFIG.read_text(encoding="utf-8")) == {"old": True}


def test_worker_accepts_zero_clients_for_safe_user_cleanup(tmp_path, monkeypatch):
    worker = load_worker()
    worker.XRAY_CONFIG = tmp_path / "xray" / "config.json"
    worker.BACKUP_DIR = tmp_path / "backups"
    worker.XRAY_BIN = tmp_path / "xray-bin"
    worker.XRAY_BIN.write_text("fake", encoding="utf-8")
    worker.XRAY_CONFIG.parent.mkdir(parents=True)
    worker.XRAY_CONFIG.write_text('{"old": true}\n', encoding="utf-8")
    tested_paths = []

    def fake_command(args, *, timeout=45):
        if "-test" in args:
            tested_paths.append(Path(args[-1]).name)
        if args[:3] == ["systemctl", "is-active", "xray.service"]:
            return subprocess.CompletedProcess(args, 0, stdout="active\n", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(worker, "command", fake_command)
    config = pilot_config()
    config["inbounds"][0]["settings"]["clients"] = []
    result = worker.apply_xray_config(11, {"config": config, "profile": "VLESS REALITY", "client_count": 0})
    assert result["client_count"] == 0
    assert tested_paths == [".sg-node-11.tmp.json"]


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


def _prepare_geofiles_worker(worker, tmp_path, monkeypatch):
    worker.GEOFILES_ROOT = tmp_path / "geofiles"
    worker.GEOFILES_STAGING = worker.GEOFILES_ROOT / "staging"
    worker.GEOFILES_SETS = worker.GEOFILES_ROOT / "sets"
    worker.GEOFILES_BACKUPS = worker.GEOFILES_ROOT / "backups"
    worker.GEOFILES_TRANSACTION = worker.GEOFILES_ROOT / "transaction.json"
    worker.XRAY_ASSET_DIR = tmp_path / "assets"
    worker.XRAY_CONFIG = tmp_path / "xray" / "config.json"
    worker.XRAY_BIN = tmp_path / "xray-bin"
    worker.XRAY_BIN.write_text("fake", encoding="utf-8")
    worker.XRAY_ASSET_DIR.mkdir(parents=True)
    worker.XRAY_CONFIG.parent.mkdir(parents=True)
    (worker.XRAY_ASSET_DIR / "geoip.dat").write_bytes(b"old-ip" * 1024)
    (worker.XRAY_ASSET_DIR / "geosite.dat").write_bytes(b"old-site" * 1024)
    worker.XRAY_CONFIG.write_text('{"old": true}\n', encoding="utf-8")

    def fake_command(args, *, timeout=45):
        if args[:3] == ["systemctl", "is-active", "xray.service"]:
            return subprocess.CompletedProcess(args, 0, stdout="active\n", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(worker, "command", fake_command)
    monkeypatch.setattr(
        worker,
        "xray_test_with_assets",
        lambda config, assets: subprocess.CompletedProcess([], 0, stdout="", stderr=""),
    )


def test_worker_stages_parses_validates_and_applies_controller_generation(tmp_path, monkeypatch):
    worker = load_worker()
    _prepare_geofiles_worker(worker, tmp_path, monkeypatch)
    source_geoip = tmp_path / "source-geoip.dat"
    source_geosite = tmp_path / "source-geosite.dat"
    source_geoip.write_bytes(_geo_file("private", "direct"))
    source_geosite.write_bytes(_geo_file("private", "category-ru"))

    def fake_download(generation, name, destination):
        source = source_geoip if name == "geoip.dat" else source_geosite
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())

    monkeypatch.setattr(worker, "download_controller_geofile", fake_download)
    config = pilot_config()
    config["routing"] = {
        "domainStrategy": "AsIs",
        "rules": [{"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"}],
    }
    payload = {
        "transfer": "controller",
        "controller_generation": "controller-generation-1",
        "source": "roscomvpn",
        "geoip_sha256": worker.file_sha256(source_geoip),
        "geosite_sha256": worker.file_sha256(source_geosite),
        "manifest": {
            "geoip_categories": ["direct", "private"],
            "geosite_categories": ["category-ru", "private"],
        },
        "config": config,
        "config_sha256": __import__("hashlib").sha256(
            json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }
    result = worker.apply_geofiles(41, payload)
    assert result["service"] == "active"
    assert result["manifest"]["geoip_categories"] == ["direct", "private"]
    assert result["manifest"]["required_categories"] == ["geosite:category-ru"]
    assert (worker.GEOFILES_ROOT / "active-manifest.json").is_file()
    assert (worker.XRAY_ASSET_DIR / "geoip.dat").read_bytes() == source_geoip.read_bytes()
    assert json.loads(worker.XRAY_CONFIG.read_text(encoding="utf-8")) == config


def test_worker_blocks_missing_category_before_live_change(tmp_path, monkeypatch):
    worker = load_worker()
    _prepare_geofiles_worker(worker, tmp_path, monkeypatch)
    old_ip = (worker.XRAY_ASSET_DIR / "geoip.dat").read_bytes()
    old_site = (worker.XRAY_ASSET_DIR / "geosite.dat").read_bytes()
    source_geoip = tmp_path / "source-geoip.dat"
    source_geosite = tmp_path / "source-geosite.dat"
    source_geoip.write_bytes(_geo_file("private"))
    source_geosite.write_bytes(_geo_file("private"))

    monkeypatch.setattr(
        worker,
        "download_controller_geofile",
        lambda generation, name, destination: destination.write_bytes(
            (source_geoip if name == "geoip.dat" else source_geosite).read_bytes()
        ),
    )
    config = pilot_config()
    config["routing"] = {
        "rules": [{"type": "field", "domain": ["geosite:google"], "outboundTag": "direct"}]
    }
    payload = {
        "transfer": "controller",
        "controller_generation": "controller-generation-2",
        "geoip_sha256": worker.file_sha256(source_geoip),
        "geosite_sha256": worker.file_sha256(source_geosite),
        "config": config,
    }
    with pytest.raises(RuntimeError, match="missing: geosite:google"):
        worker.apply_geofiles(42, payload)
    assert (worker.XRAY_ASSET_DIR / "geoip.dat").read_bytes() == old_ip
    assert (worker.XRAY_ASSET_DIR / "geosite.dat").read_bytes() == old_site
