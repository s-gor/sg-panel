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
