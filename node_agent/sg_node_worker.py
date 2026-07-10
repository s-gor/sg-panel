#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

WORKER_VERSION = "0.5.0"
JOBS_DIR = Path("/var/lib/sg-node/jobs")
BACKUP_DIR = Path("/var/lib/sg-node/backups")
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
XRAY_BIN = Path("/usr/local/bin/xray")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def command(args: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def safe_read_json(path: Path) -> dict[str, Any]:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise RuntimeError("job file is not a regular file")
    if st.st_size > 1_100_000:
        raise RuntimeError("job file is too large")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        raw = os.read(fd, 1_100_001)
    finally:
        os.close(fd)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("job must be a JSON object")
    return data


def write_result(job_id: int, result: dict[str, Any]) -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    target = JOBS_DIR / f"{job_id}.result.json"
    temporary = JOBS_DIR / f".{job_id}.result.tmp"
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o640)
    try:
        shutil.chown(temporary, user="root", group="sg-node")
    except (LookupError, OSError):
        pass
    temporary.replace(target)


def validate_pilot_reality_config(config: dict[str, Any]) -> None:
    if set(config) - {"log", "inbounds", "outbounds"}:
        raise RuntimeError("pilot config contains unsupported top-level sections")
    inbounds = config.get("inbounds")
    outbounds = config.get("outbounds")
    if not isinstance(inbounds, list) or len(inbounds) != 1:
        raise RuntimeError("pilot config must contain exactly one inbound")
    if not isinstance(outbounds, list) or len(outbounds) != 1:
        raise RuntimeError("pilot config must contain exactly one outbound")
    inbound = inbounds[0]
    if not isinstance(inbound, dict):
        raise RuntimeError("pilot inbound must be an object")
    if set(inbound) - {"tag", "listen", "port", "protocol", "settings", "streamSettings"}:
        raise RuntimeError("pilot inbound contains unsupported fields")
    if inbound.get("tag") != "sg-node-reality-in":
        raise RuntimeError("unexpected pilot inbound tag")
    if inbound.get("listen") != "0.0.0.0" or inbound.get("protocol") != "vless":
        raise RuntimeError("pilot inbound must be VLESS on 0.0.0.0")
    port = inbound.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535 or port in {22, 80, 443, 61443}:
        raise RuntimeError("unsupported pilot port")

    settings = inbound.get("settings")
    if not isinstance(settings, dict) or set(settings) - {"clients", "decryption"}:
        raise RuntimeError("unsupported VLESS settings")
    if settings.get("decryption") != "none":
        raise RuntimeError("VLESS decryption must be none")
    clients = settings.get("clients")
    if not isinstance(clients, list) or not 0 <= len(clients) <= 100:
        raise RuntimeError("pilot config must contain 0-100 clients")
    for client in clients:
        if not isinstance(client, dict) or set(client) - {"id", "email", "flow", "level"}:
            raise RuntimeError("unsupported VLESS client fields")
        try:
            uuid.UUID(str(client.get("id") or ""))
        except ValueError as exc:
            raise RuntimeError("invalid VLESS client UUID") from exc
        if client.get("flow") != "xtls-rprx-vision" or int(client.get("level") or 0) != 0:
            raise RuntimeError("pilot clients must use Vision at level 0")
        email = str(client.get("email") or "")
        if not email or len(email) > 80:
            raise RuntimeError("invalid VLESS client name")

    stream = inbound.get("streamSettings")
    if not isinstance(stream, dict) or set(stream) - {"network", "security", "realitySettings"}:
        raise RuntimeError("unsupported stream settings")
    if stream.get("network") != "tcp" or stream.get("security") != "reality":
        raise RuntimeError("pilot stream must be TCP REALITY")
    reality = stream.get("realitySettings")
    if not isinstance(reality, dict) or set(reality) - {"show", "dest", "xver", "serverNames", "privateKey", "shortIds"}:
        raise RuntimeError("unsupported REALITY settings")
    if reality.get("show") is not False or int(reality.get("xver") or 0) != 0:
        raise RuntimeError("unsupported REALITY flags")
    dest = str(reality.get("dest") or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]+:[0-9]{1,5}", dest):
        raise RuntimeError("invalid REALITY target")
    server_names = reality.get("serverNames")
    if not isinstance(server_names, list) or len(server_names) != 1 or not re.fullmatch(r"[A-Za-z0-9._-]+", str(server_names[0])):
        raise RuntimeError("invalid REALITY serverName")
    private_key = str(reality.get("privateKey") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{30,80}", private_key):
        raise RuntimeError("invalid REALITY private key")
    short_ids = reality.get("shortIds")
    if not isinstance(short_ids, list) or len(short_ids) != 1 or not re.fullmatch(r"[0-9a-f]{2,32}", str(short_ids[0])):
        raise RuntimeError("invalid REALITY shortId")

    outbound = outbounds[0]
    if not isinstance(outbound, dict) or outbound.get("tag") != "direct" or outbound.get("protocol") != "freedom":
        raise RuntimeError("pilot config allows only the direct freedom outbound")
    if set(outbound) - {"tag", "protocol", "settings"}:
        raise RuntimeError("unsupported outbound fields")
    if outbound.get("settings") not in ({}, None):
        raise RuntimeError("unsupported freedom settings")


def apply_xray_config(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    expected = str(payload.get("config_sha256") or "").lower()
    if not isinstance(config, dict):
        raise RuntimeError("payload.config must be an object")
    validate_pilot_reality_config(config)
    encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
    actual = hashlib.sha256(encoded).hexdigest()
    if expected and expected != actual:
        raise RuntimeError("config SHA-256 mismatch")
    if not XRAY_BIN.is_file():
        raise RuntimeError(f"Xray not found: {XRAY_BIN}")

    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    temp_config = XRAY_CONFIG.parent / f".sg-node-{job_id}.tmp.json"
    temp_config.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp_config, 0o600)

    tested = command([str(XRAY_BIN), "run", "-test", "-config", str(temp_config)])
    if tested.returncode != 0:
        detail = (tested.stderr or tested.stdout or "xray run -test failed").strip()
        temp_config.unlink(missing_ok=True)
        raise RuntimeError(detail[-4000:])

    backup = BACKUP_DIR / f"config-before-job-{job_id}-{utc_stamp()}.json"
    had_previous = XRAY_CONFIG.exists()
    if had_previous:
        shutil.copy2(XRAY_CONFIG, backup)
        os.chmod(backup, 0o600)

    try:
        os.chmod(temp_config, 0o644)
        temp_config.replace(XRAY_CONFIG)
        command(["systemctl", "daemon-reload"], timeout=20)
        enabled = command(["systemctl", "enable", "xray.service"], timeout=20)
        if enabled.returncode != 0:
            raise RuntimeError((enabled.stderr or enabled.stdout or "xray enable failed").strip())
        restarted = command(["systemctl", "restart", "xray.service"], timeout=40)
        if restarted.returncode != 0:
            raise RuntimeError((restarted.stderr or restarted.stdout or "xray restart failed").strip())
        active = command(["systemctl", "is-active", "xray.service"], timeout=10)
        if active.returncode != 0 or active.stdout.strip() != "active":
            raise RuntimeError("xray.service did not become active")
    except Exception:
        if had_previous and backup.exists():
            shutil.copy2(backup, XRAY_CONFIG)
            os.chmod(XRAY_CONFIG, 0o644)
            command(["systemctl", "restart", "xray.service"], timeout=40)
        elif not had_previous:
            XRAY_CONFIG.unlink(missing_ok=True)
            command(["systemctl", "disable", "--now", "xray.service"], timeout=20)
            command(["systemctl", "reset-failed", "xray.service"], timeout=10)
        raise

    return {
        "message": "Конфигурация проверена и применена на ноде",
        "profile": str(payload.get("profile") or ""),
        "client_count": int(payload.get("client_count") or 0),
        "config_sha256": actual,
        "backup_path": str(backup) if had_previous else "",
        "worker_version": WORKER_VERSION,
    }


def process_file(path: Path) -> None:
    job_id = int(path.name.split(".", 1)[0])
    working = JOBS_DIR / f"{job_id}.working.json"
    try:
        path.replace(working)
    except FileNotFoundError:
        return
    ok = False
    result: dict[str, Any]
    try:
        job = safe_read_json(working)
        if int(job.get("id") or 0) != job_id:
            raise RuntimeError("job id mismatch")
        if str(job.get("job_type") or "") != "apply_xray_config":
            raise RuntimeError("unsupported job type")
        payload = job.get("payload")
        if not isinstance(payload, dict):
            raise RuntimeError("job payload must be an object")
        result = apply_xray_config(job_id, payload)
        ok = True
    except Exception as exc:
        result = {
            "message": str(exc)[:4000] or "Неизвестная ошибка worker",
            "worker_version": WORKER_VERSION,
        }
    finally:
        write_result(job_id, {"ok": ok, "result": result})
        working.unlink(missing_ok=True)


def main() -> int:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    while True:
        for path in sorted(JOBS_DIR.glob("*.pending.json")):
            try:
                process_file(path)
            except Exception:
                # A malformed filename or transient filesystem problem must not stop the worker.
                continue
        time.sleep(0.5)


if __name__ == "__main__":
    raise SystemExit(main())
