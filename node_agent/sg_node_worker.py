#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import re
import secrets
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import urllib.error
import urllib.request

WORKER_VERSION = "0.7.0"
JOBS_DIR = Path("/var/lib/sg-node/jobs")
BACKUP_DIR = Path("/var/lib/sg-node/backups")
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
AGENT_CONFIG = Path(os.environ.get("SG_NODE_CONFIG", "/etc/sg-node/agent.json"))
XRAY_BIN = Path("/usr/local/bin/xray")
GEOFILES_ROOT = Path("/var/lib/sg-node/geofiles")
GEOFILES_STAGING = GEOFILES_ROOT / "staging"
GEOFILES_SETS = GEOFILES_ROOT / "sets"
GEOFILES_BACKUPS = GEOFILES_ROOT / "backups"
GEOFILES_TRANSACTION = GEOFILES_ROOT / "transaction.json"
XRAY_ASSET_DIR = Path("/usr/local/share/xray")
GEOFILES_MINIMUM_SIZE = 4096


MINIMUM_XRAY_VERSION = (26, 6, 27)
MINIMUM_XRAY_LABEL = "v26.6.27"
VLESS_SECRET = Path("/etc/sg-node/xray-secrets.env")
_MLKEM_PREFIX = "mlkem768x25519plus"
_MLKEM_PADDING = "100-111-1111.75-0-111.50-0-3333"
_BASE64_ANY_RE = re.compile(r"^[A-Za-z0-9_+/=-]+$")


class XrayEncryptionRuntimeError(RuntimeError):
    pass


def _normalise_key_material(value: object) -> tuple[str, bytes]:
    text = str(value or "").strip()
    if not text or not _BASE64_ANY_RE.fullmatch(text):
        raise XrayEncryptionRuntimeError("Некорректный ML-KEM-768 key material")
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise XrayEncryptionRuntimeError("Некорректный ML-KEM-768 key material") from exc
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="), raw


def _value_role(value: object) -> str:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) != 7 or parts[0].lower() != _MLKEM_PREFIX:
        return "invalid"
    session = parts[2].lower()
    role = "client" if session in {"0rtt", "1rtt"} else "server" if re.fullmatch(r"(?:\d+|\d+-\d+)s", session) else "invalid"
    if role == "invalid":
        return role
    try:
        _text, raw = _normalise_key_material(parts[-1])
    except XrayEncryptionRuntimeError:
        return "invalid"
    if role == "server" and 32 <= len(raw) <= 128:
        return "server"
    if role == "client" and len(raw) >= 128:
        return "client"
    return "invalid"


def server_value_ready(value: object) -> bool:
    return "PLACEHOLDER" not in str(value or "").upper() and _value_role(value) == "server"


def client_value_ready(value: object) -> bool:
    return "PLACEHOLDER" not in str(value or "").upper() and _value_role(value) == "client"


def _build_mlkem_pair(seed: object, client: object) -> tuple[str, str]:
    seed_text, seed_raw = _normalise_key_material(seed)
    client_text, client_raw = _normalise_key_material(client)
    if not 32 <= len(seed_raw) <= 128:
        raise XrayEncryptionRuntimeError("xray mlkem768 вернул некорректный Seed")
    if len(client_raw) < 128:
        raise XrayEncryptionRuntimeError("xray mlkem768 вернул некорректный Client key")
    encryption = f"{_MLKEM_PREFIX}.native.0rtt.{_MLKEM_PADDING}.{client_text}"
    decryption = f"{_MLKEM_PREFIX}.native.600s.{_MLKEM_PADDING}.{seed_text}"
    if not client_value_ready(encryption) or not server_value_ready(decryption):
        raise XrayEncryptionRuntimeError("Не удалось собрать корректную ML-KEM-768 пару")
    return encryption, decryption


def _normalise_pair(encryption: object, decryption: object) -> tuple[str, str, bool]:
    client = str(encryption or "").strip()
    server = str(decryption or "").strip()
    if _value_role(client) == "client" and _value_role(server) == "server":
        return client, server, False
    if _value_role(client) == "server" and _value_role(server) == "client":
        return server, client, True
    raise XrayEncryptionRuntimeError("Некорректная ML-KEM-768 пара VLESS Encryption")


def _xray_version(binary: Path) -> tuple[int, int, int]:
    result = command([str(binary), "version"], timeout=15)
    text = (result.stdout or result.stderr or "").strip()
    match = re.search(r"(?im)^Xray\s+v?(\d+)\.(\d+)\.(\d+)\b", text)
    if result.returncode != 0 or not match:
        raise XrayEncryptionRuntimeError("Не удалось определить версию Xray")
    return tuple(int(item) for item in match.groups())


def require_supported_xray(binary: Path) -> tuple[int, int, int]:
    version = _xray_version(binary)
    if version < MINIMUM_XRAY_VERSION:
        raise XrayEncryptionRuntimeError(
            f"VLESS Encryption требует Xray не ниже {MINIMUM_XRAY_LABEL}"
        )
    return version


def _read_secret() -> dict[str, str]:
    values: dict[str, str] = {}
    if VLESS_SECRET.is_file():
        for raw in VLESS_SECRET.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in raw and not raw.lstrip().startswith("#"):
                key, value = raw.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    encryption, decryption, swapped = _normalise_pair(
        values.get("SG_NODE_VLESS_ENCRYPTION", ""),
        values.get("SG_NODE_VLESS_DECRYPTION", ""),
    )
    return {
        "encryption": encryption,
        "decryption": decryption,
        "generation": values.get("SG_NODE_VLESS_ENCRYPTION_GENERATION", "").strip(),
        "checked_at": values.get("SG_NODE_VLESS_ENCRYPTION_CHECKED_AT", "").strip(),
        "swapped": "1" if swapped else "0",
    }


def _write_secret(pair: dict[str, str]) -> None:
    VLESS_SECRET.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(VLESS_SECRET.parent, 0o700)
    temporary = VLESS_SECRET.with_name(VLESS_SECRET.name + ".tmp")
    temporary.write_text(
        "\n".join(
            [
                "# SG-Node Xray VLESS Encryption. Server decryption never leaves this node.",
                f"SG_NODE_VLESS_ENCRYPTION={pair['encryption']}",
                f"SG_NODE_VLESS_DECRYPTION={pair['decryption']}",
                f"SG_NODE_VLESS_ENCRYPTION_GENERATION={pair['generation']}",
                f"SG_NODE_VLESS_ENCRYPTION_CHECKED_AT={pair['checked_at']}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.chown(temporary, 0, 0)
    os.replace(temporary, VLESS_SECRET)
    os.chmod(VLESS_SECRET, 0o600)


def _find_mlkem_value(output: str, names: tuple[str, ...]) -> str:
    for name in names:
        match = re.search(
            rf"(?im)^\s*[\"']?{re.escape(name)}[\"']?\s*:\s*[\"']?([^\"'\s,}}]+)",
            output,
        )
        if match:
            return match.group(1).strip().rstrip("=")
    return ""


def _generate_pair(binary: Path) -> tuple[str, str]:
    result = command([str(binary), "mlkem768"], timeout=45)
    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    if result.returncode != 0:
        raise XrayEncryptionRuntimeError(output.strip()[-4000:] or "xray mlkem768 failed")
    seed = _find_mlkem_value(output, ("Seed", "seed", "PrivateKey"))
    client = _find_mlkem_value(output, ("Client", "client", "PublicKey", "Password (PublicKey)"))
    if not seed or not client:
        raise XrayEncryptionRuntimeError("xray mlkem768 не вернул отдельные Seed и Client")
    return _build_mlkem_pair(seed, client)


def _validate_pair(binary: Path, encryption: str, decryption: str) -> None:
    user_id = str(uuid.uuid4())
    payload = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "sg-node-vlessenc-selftest-in", "listen": "127.0.0.1", "port": 39991,
            "protocol": "vless",
            "settings": {"clients": [{"id": user_id, "flow": "xtls-rprx-vision"}], "decryption": decryption},
            "streamSettings": {"network": "xhttp", "security": "none", "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "auto"}},
        }],
        "outbounds": [{
            "tag": "sg-node-vlessenc-selftest-out", "protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": 39991, "id": user_id, "encryption": encryption, "flow": "xtls-rprx-vision"},
            "streamSettings": {"network": "xhttp", "security": "none", "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "stream-one"}},
        }],
    }
    with tempfile.TemporaryDirectory(prefix="sg-node-vlessenc-") as temporary:
        path = Path(temporary) / "config.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result = command([str(binary), "run", "-test", "-config", str(path)], timeout=45)
        if result.returncode != 0:
            raise XrayEncryptionRuntimeError(
                (result.stderr or result.stdout or "xray run -test failed").strip()[-4000:]
            )


def ensure_node_encryption_pair(binary: Path) -> dict[str, str]:
    require_supported_xray(binary)
    try:
        pair = _read_secret()
        _validate_pair(binary, pair["encryption"], pair["decryption"])
        if pair.get("swapped") == "1":
            pair["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            pair["generation"] = pair.get("generation") or uuid.uuid4().hex
            _write_secret(pair)
        return pair
    except (XrayEncryptionRuntimeError, OSError):
        encryption, decryption = _generate_pair(binary)
        _validate_pair(binary, encryption, decryption)
        pair = {
            "encryption": encryption,
            "decryption": decryption,
            "generation": uuid.uuid4().hex,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "swapped": "0",
        }
        _write_secret(pair)
        return pair

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
    if inbound.get("tag") not in {"sg-node-reality-in", "sg-node-xhttp-reality-in"}:
        raise RuntimeError("unexpected pilot inbound tag")
    if inbound.get("listen") != "0.0.0.0" or inbound.get("protocol") != "vless":
        raise RuntimeError("pilot inbound must be VLESS on 0.0.0.0")
    port = inbound.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535 or port in {22, 80, 443, 61443}:
        raise RuntimeError("unsupported pilot port")

    settings = inbound.get("settings")
    if not isinstance(settings, dict) or set(settings) - {"clients", "decryption"}:
        raise RuntimeError("unsupported VLESS settings")
    clients = settings.get("clients")
    if not isinstance(clients, list) or not 0 <= len(clients) <= 1000:
        raise RuntimeError("pilot config must contain 0-1000 clients")
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
    if not isinstance(stream, dict) or set(stream) - {"network", "security", "realitySettings", "xhttpSettings"}:
        raise RuntimeError("unsupported stream settings")
    network = str(stream.get("network") or "tcp")
    if network not in {"tcp", "raw", "xhttp"} or stream.get("security") != "reality":
        raise RuntimeError("pilot stream must be TCP/XHTTP REALITY")
    decryption = str(settings.get("decryption") or "")
    if network == "xhttp":
        if not server_value_ready(decryption):
            raise RuntimeError("XHTTP REALITY requires a complete local ML-KEM-768 decryption")
        xhttp = stream.get("xhttpSettings")
        if not isinstance(xhttp, dict) or set(xhttp) - {"path", "mode"}:
            raise RuntimeError("unsupported XHTTP settings")
        path = str(xhttp.get("path") or "")
        if not path.startswith("/") or len(path) > 200:
            raise RuntimeError("invalid XHTTP path")
        if str(xhttp.get("mode") or "auto") != "auto":
            raise RuntimeError("SG-Node XHTTP server mode must be auto")
    elif decryption != "none":
        raise RuntimeError("TCP REALITY decryption must be none")

    reality = stream.get("realitySettings")
    if not isinstance(reality, dict) or set(reality) - {"show", "dest", "target", "xver", "serverNames", "privateKey", "shortIds"}:
        raise RuntimeError("unsupported REALITY settings")
    if reality.get("show") is not False or int(reality.get("xver") or 0) != 0:
        raise RuntimeError("unsupported REALITY flags")
    target = str(reality.get("target") or reality.get("dest") or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]+:[0-9]{1,5}", target):
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


def _replace_decryption_placeholder(value: Any, decryption: str) -> Any:
    if isinstance(value, dict):
        return {key: _replace_decryption_placeholder(item, decryption) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_decryption_placeholder(item, decryption) for item in value]
    if value == "__SG_NODE_VLESS_DECRYPTION__":
        return decryption
    return value


CASCADE_INBOUND_TAG = "sg-cascade-reality-in"
CASCADE_STATE = Path(os.environ.get("SG_NODE_CASCADE_STATE", "/var/lib/sg-node/cascade-access.json"))
CASCADE_PORTS = (64441, 64442, 64443, 64444, 64445)


def _read_live_xray_config() -> dict[str, Any]:
    if not XRAY_CONFIG.is_file():
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        }
    try:
        document = json.loads(XRAY_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"не удалось прочитать действующую конфигурацию Xray: {exc}") from exc
    if not isinstance(document, dict):
        raise RuntimeError("действующая конфигурация Xray должна быть JSON-объектом")
    return document


def _xray_reality_keypair() -> dict[str, str]:
    if not XRAY_BIN.is_file():
        raise RuntimeError(f"Xray not found: {XRAY_BIN}")
    generated = command([str(XRAY_BIN), "x25519"], timeout=30)
    output = (generated.stdout or "") + ("\n" + generated.stderr if generated.stderr else "")
    if generated.returncode != 0:
        raise RuntimeError(output.strip()[-4000:] or "xray x25519 failed")
    private_match = re.search(r"(?m)^PrivateKey:\s*(\S+)\s*$", output)
    public_match = re.search(r"(?m)^(?:Password\s*\(PublicKey\)|PublicKey):\s*(\S+)\s*$", output)
    if not private_match or not public_match:
        raise RuntimeError("xray x25519 не вернул private/public key")
    return {
        "private_key": private_match.group(1).strip(),
        "public_key": public_match.group(1).strip(),
        "short_id": secrets.token_hex(8),
    }



def _xray_public_from_private(private_key: str) -> str:
    generated = command([str(XRAY_BIN), "x25519", "-i", private_key], timeout=30)
    output = (generated.stdout or "") + ("\n" + generated.stderr if generated.stderr else "")
    if generated.returncode != 0:
        raise RuntimeError(output.strip()[-4000:] or "xray x25519 -i failed")
    public_match = re.search(r"(?m)^(?:Password\s*\(PublicKey\)|PublicKey):\s*(\S+)\s*$", output)
    if not public_match:
        raise RuntimeError("xray x25519 -i не вернул public key")
    return public_match.group(1).strip()


def _cascade_port_available(port: int, used_ports: set[int]) -> bool:
    if port in used_ports:
        return False
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _apply_merged_xray_config(job_id: int, config: dict[str, Any], *, backup_label: str) -> dict[str, Any]:
    if not XRAY_BIN.is_file():
        raise RuntimeError(f"Xray not found: {XRAY_BIN}")
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    temp_config = XRAY_CONFIG.parent / f".sg-node-{job_id}.tmp.json"
    encoded_text = json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temp_config.write_text(encoded_text, encoding="utf-8")
    os.chmod(temp_config, 0o600)

    tested = command([str(XRAY_BIN), "run", "-test", "-config", str(temp_config)], timeout=60)
    if tested.returncode != 0:
        detail = (tested.stderr or tested.stdout or "xray run -test failed").strip()
        temp_config.unlink(missing_ok=True)
        raise RuntimeError(detail[-4000:])

    backup = BACKUP_DIR / f"{backup_label}-{job_id}-{utc_stamp()}.json"
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
        restarted = command(["systemctl", "restart", "xray.service"], timeout=45)
        if restarted.returncode != 0:
            raise RuntimeError((restarted.stderr or restarted.stdout or "xray restart failed").strip())
        active = command(["systemctl", "is-active", "xray.service"], timeout=10)
        if active.returncode != 0 or active.stdout.strip() != "active":
            raise RuntimeError("xray.service did not become active")
    except Exception:
        if had_previous and backup.exists():
            shutil.copy2(backup, XRAY_CONFIG)
            os.chmod(XRAY_CONFIG, 0o644)
            command(["systemctl", "restart", "xray.service"], timeout=45)
        elif not had_previous:
            XRAY_CONFIG.unlink(missing_ok=True)
            command(["systemctl", "disable", "--now", "xray.service"], timeout=20)
            command(["systemctl", "reset-failed", "xray.service"], timeout=10)
        raise

    return {
        "config_sha256": hashlib.sha256(encoded_text.encode("utf-8")).hexdigest(),
        "backup_path": str(backup) if had_previous else "",
    }



def _cascade_state_snapshot() -> bytes | None:
    return CASCADE_STATE.read_bytes() if CASCADE_STATE.is_file() else None


def _restore_cascade_state(snapshot: bytes | None) -> None:
    if snapshot is None:
        CASCADE_STATE.unlink(missing_ok=True)
        return
    CASCADE_STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CASCADE_STATE.with_name(CASCADE_STATE.name + ".rollback")
    temporary.write_bytes(snapshot)
    os.chmod(temporary, 0o600)
    temporary.replace(CASCADE_STATE)


def _write_cascade_state(document: dict[str, Any]) -> None:
    CASCADE_STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CASCADE_STATE.with_name(CASCADE_STATE.name + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(CASCADE_STATE)
    os.chmod(CASCADE_STATE, 0o600)


def upsert_cascade_access(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    """Safely add/remove one Cascade service identity in the live config.

    Existing RAW/TCP Reality is reused when possible, so no new public port is
    required. Only when no suitable inbound exists is a dedicated one created.
    Controller never receives or replaces the complete node configuration.
    """
    action = str(payload.get("action") or "upsert").strip().lower()
    if action not in {"upsert", "remove"}:
        raise RuntimeError("неизвестное действие Cascade")
    service_uuid = str(payload.get("service_uuid") or "").strip()
    try:
        service_uuid = str(uuid.UUID(service_uuid))
    except (ValueError, AttributeError) as exc:
        raise RuntimeError("некорректный UUID служебного доступа Cascade") from exc
    controller = re.sub(r"[^A-Za-z0-9А-Яа-яЁё._ -]+", "", str(payload.get("controller") or "Controller"))[:64].strip() or "Controller"
    service_email = f"Cascade · {controller}"

    previous_state_document: dict[str, Any] = {}
    if CASCADE_STATE.is_file():
        try:
            loaded_state = json.loads(CASCADE_STATE.read_text(encoding="utf-8"))
            if isinstance(loaded_state, dict) and str(loaded_state.get("format") or "") == "sg-cascade-access-v1":
                previous_state_document = loaded_state
        except (OSError, json.JSONDecodeError):
            previous_state_document = {}
    managed_uuids = {service_uuid}
    previous_uuid = str(previous_state_document.get("service_uuid") or "").strip()
    if previous_uuid:
        managed_uuids.add(previous_uuid)
    managed_emails = {service_email}
    previous_email = str(previous_state_document.get("service_email") or "").strip()
    if previous_email:
        managed_emails.add(previous_email)

    current = _read_live_xray_config()
    candidate = json.loads(json.dumps(current))
    inbounds = candidate.get("inbounds")
    if not isinstance(inbounds, list):
        raise RuntimeError("действующая конфигурация Xray содержит некорректный список inbounds")

    # Remove only our old service identity and dedicated fallback inbound.
    cleaned_inbounds: list[Any] = []
    for inbound in inbounds:
        if isinstance(inbound, dict) and str(inbound.get("tag") or "") == CASCADE_INBOUND_TAG:
            continue
        if isinstance(inbound, dict):
            settings = inbound.get("settings")
            if isinstance(settings, dict) and isinstance(settings.get("clients"), list):
                settings["clients"] = [
                    client for client in settings["clients"]
                    if not (
                        isinstance(client, dict)
                        and (
                            str(client.get("id") or "") in managed_uuids
                            or str(client.get("email") or "") in managed_emails
                        )
                    )
                ]
        cleaned_inbounds.append(inbound)
    inbounds[:] = cleaned_inbounds

    routing = candidate.get("routing")
    if routing is None:
        routing = {"domainStrategy": "AsIs", "rules": []}
        candidate["routing"] = routing
    if not isinstance(routing, dict):
        raise RuntimeError("действующая конфигурация Xray содержит некорректный routing")
    rules = routing.get("rules")
    if rules is None:
        rules = []
        routing["rules"] = rules
    if not isinstance(rules, list):
        raise RuntimeError("действующая конфигурация Xray содержит некорректный routing.rules")
    rules[:] = [
        rule for rule in rules
        if not (
            isinstance(rule, dict)
            and (
                (
                    isinstance(rule.get("inboundTag"), list)
                    and CASCADE_INBOUND_TAG in [str(value) for value in rule.get("inboundTag", [])]
                )
                or (
                    isinstance(rule.get("user"), list)
                    and any(str(value) in managed_emails for value in rule.get("user", []))
                )
            )
        )
    ]

    if action == "remove":
        previous_state = _cascade_state_snapshot()
        CASCADE_STATE.unlink(missing_ok=True)
        try:
            applied = _apply_merged_xray_config(job_id, candidate, backup_label="config-before-cascade-remove")
        except Exception:
            _restore_cascade_state(previous_state)
            raise
        return {
            "message": "Служебный доступ Cascade удалён; остальные профили Xray сохранены",
            "action": "remove",
            "service_uuid": service_uuid,
            "worker_version": WORKER_VERSION,
            **applied,
        }

    target = str(payload.get("target") or "www.bing.com:443").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+:[0-9]{1,5}", target):
        raise RuntimeError("Reality target должен иметь вид host:port")
    target_host, target_port_text = target.rsplit(":", 1)
    if not 1 <= int(target_port_text) <= 65535:
        raise RuntimeError("некорректный порт Reality target")
    requested_server_name = str(payload.get("server_name") or target_host).strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", requested_server_name):
        raise RuntimeError("некорректный Reality serverName")

    outbounds = candidate.get("outbounds")
    if outbounds is None:
        outbounds = []
        candidate["outbounds"] = outbounds
    if not isinstance(outbounds, list):
        raise RuntimeError("действующая конфигурация Xray содержит некорректный список outbounds")
    direct = next((item for item in outbounds if isinstance(item, dict) and str(item.get("tag") or "") == "direct"), None)
    if direct is None:
        outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    elif str(direct.get("protocol") or "") != "freedom":
        raise RuntimeError("outbound с тегом direct уже существует и не является freedom")

    chosen: dict[str, Any] | None = None
    for inbound in inbounds:
        if not isinstance(inbound, dict) or str(inbound.get("protocol") or "") != "vless":
            continue
        stream = inbound.get("streamSettings")
        settings = inbound.get("settings")
        if not isinstance(stream, dict) or not isinstance(settings, dict):
            continue
        if str(stream.get("network") or "tcp") not in {"tcp", "raw"} or str(stream.get("security") or "") != "reality":
            continue
        clients = settings.get("clients")
        reality = stream.get("realitySettings")
        if not isinstance(clients, list) or not isinstance(reality, dict):
            continue
        private_key = str(reality.get("privateKey") or "").strip()
        names = reality.get("serverNames") if isinstance(reality.get("serverNames"), list) else []
        short_ids = reality.get("shortIds") if isinstance(reality.get("shortIds"), list) else []
        valid_short_id = next(
            (str(value) for value in short_ids if re.fullmatch(r"[0-9a-f]{2,32}", str(value))),
            "",
        )
        if not valid_short_id:
            valid_short_id = secrets.token_hex(8)
            short_ids.append(valid_short_id)
            reality["shortIds"] = short_ids
        valid_server_name = next(
            (str(value) for value in names if re.fullmatch(r"[A-Za-z0-9._-]+", str(value))),
            "",
        )
        port = int(inbound.get("port") or 0)
        if not private_key or not valid_server_name or not 1 <= port <= 65535:
            continue
        try:
            public_key = _xray_public_from_private(private_key)
        except RuntimeError:
            continue
        chosen = {
            "mode": "reuse",
            "inbound": inbound,
            "inbound_tag": str(inbound.get("tag") or ""),
            "port": port,
            "target": str(reality.get("target") or reality.get("dest") or target),
            "server_name": valid_server_name,
            "private_key": private_key,
            "public_key": public_key,
            "short_id": valid_short_id,
        }
        break

    if chosen is None:
        used_ports = {
            int(item.get("port") or 0)
            for item in inbounds
            if isinstance(item, dict) and str(item.get("port") or "").isdigit()
        }
        requested_ports = payload.get("preferred_ports")
        candidates: list[int] = []
        if isinstance(requested_ports, list):
            for value in requested_ports:
                try:
                    port = int(value)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535 and port not in candidates:
                    candidates.append(port)
        for port in CASCADE_PORTS:
            if port not in candidates:
                candidates.append(port)
        port = next((value for value in candidates if _cascade_port_available(value, used_ports)), 0)
        if not port:
            raise RuntimeError("не найден свободный порт для служебного профиля Cascade")
        keys = _xray_reality_keypair()
        inbound = {
            "tag": CASCADE_INBOUND_TAG,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": target,
                    "xver": 0,
                    "serverNames": [requested_server_name],
                    "privateKey": keys["private_key"],
                    "shortIds": [keys["short_id"]],
                },
            },
        }
        inbounds.append(inbound)
        chosen = {
            "mode": "dedicated",
            "inbound": inbound,
            "inbound_tag": CASCADE_INBOUND_TAG,
            "port": port,
            "target": target,
            "server_name": requested_server_name,
            "private_key": keys["private_key"],
            "public_key": keys["public_key"],
            "short_id": keys["short_id"],
        }

    selected_settings = chosen["inbound"].get("settings")
    if not isinstance(selected_settings, dict) or not isinstance(selected_settings.get("clients"), list):
        raise RuntimeError("выбранный Reality Inbound не содержит clients")
    selected_settings["clients"].append({
        "id": service_uuid,
        "email": service_email,
        "flow": "xtls-rprx-vision",
        "level": 0,
    })
    rules.insert(0, {
        "type": "field",
        "user": [service_email],
        "outboundTag": "direct",
    })

    state_document = {
        "format": "sg-cascade-access-v1",
        "mode": chosen["mode"],
        "tag": CASCADE_INBOUND_TAG,
        "inbound_tag": chosen["inbound_tag"],
        "port": chosen["port"],
        "service_uuid": service_uuid,
        "controller": controller,
        "service_email": service_email,
        "target": chosen["target"],
        "server_name": chosen["server_name"],
        "private_key": chosen["private_key"] if chosen["mode"] == "dedicated" else "",
        "public_key": chosen["public_key"],
        "short_id": chosen["short_id"],
        "flow": "xtls-rprx-vision",
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    previous_state = _cascade_state_snapshot()
    _write_cascade_state(state_document)
    try:
        applied = _apply_merged_xray_config(job_id, candidate, backup_label="config-before-cascade-upsert")
    except Exception:
        _restore_cascade_state(previous_state)
        raise
    return {
        "message": (
            "Cascade использует существующий Reality TCP; остальные профили Xray сохранены"
            if chosen["mode"] == "reuse"
            else "Служебный профиль Cascade создан; остальные профили Xray сохранены"
        ),
        "action": "upsert",
        "access_mode": chosen["mode"],
        "service_uuid": service_uuid,
        "public_port": chosen["port"],
        "public_key": chosen["public_key"],
        "short_id": chosen["short_id"],
        "server_name": chosen["server_name"],
        "network": "tcp",
        "security": "reality",
        "flow": "xtls-rprx-vision",
        "fingerprint": "firefox",
        "spider_x": "/",
        "worker_version": WORKER_VERSION,
        **applied,
    }


def apply_xray_config(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    expected = str(payload.get("config_sha256") or "").lower()
    if not isinstance(config, dict):
        raise RuntimeError("payload.config must be an object")
    pair: dict[str, str] = {}
    encoded_candidate = json.dumps(config, ensure_ascii=False)
    needs_encryption = bool(payload.get("ensure_xhttp_encryption")) or "__SG_NODE_VLESS_DECRYPTION__" in encoded_candidate
    if needs_encryption:
        require_supported_xray(XRAY_BIN)
        try:
            pair = ensure_node_encryption_pair(XRAY_BIN)
        except XrayEncryptionRuntimeError as exc:
            raise RuntimeError(str(exc)) from exc
        config = _replace_decryption_placeholder(config, pair["decryption"])
    validate_pilot_reality_config(config)
    encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
    actual = hashlib.sha256(encoded).hexdigest()
    if expected and not needs_encryption and expected != actual:
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
        "xray_minimum_supported": MINIMUM_XRAY_LABEL,
        "client_encryption": str(pair.get("encryption") or ""),
        "encryption_generation": str(pair.get("generation") or ""),
        "encryption_checked_at": str(pair.get("checked_at") or ""),
        "xhttp_server_mode": "auto" if pair else "",
        "xhttp_client_mode": str(payload.get("xhttp_client_mode") or "stream-one") if pair else "",
    }



def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_protobuf_varint(data: memoryview, offset: int, limit: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    while offset < limit and shift <= 63:
        current = int(data[offset])
        offset += 1
        value |= (current & 0x7F) << shift
        if current & 0x80 == 0:
            return value, offset
        shift += 7
    return None, offset


def skip_protobuf_field(data: memoryview, offset: int, limit: int, wire: int) -> int | None:
    if wire == 0:
        value, offset = read_protobuf_varint(data, offset, limit)
        return offset if value is not None else None
    if wire == 1:
        offset += 8
    elif wire == 2:
        length, offset = read_protobuf_varint(data, offset, limit)
        if length is None:
            return None
        offset += int(length)
    elif wire == 5:
        offset += 4
    else:
        return None
    return offset if offset <= limit else None


def read_protobuf_string_field(data: memoryview, start: int, length: int) -> str:
    end = start + length
    offset = start
    while offset < end:
        key, offset = read_protobuf_varint(data, offset, end)
        if key is None:
            break
        field = int(key >> 3)
        wire = int(key & 7)
        if field == 1 and wire == 2:
            value_length, value_start = read_protobuf_varint(data, offset, end)
            if value_length is None or value_start + int(value_length) > end:
                break
            return bytes(data[value_start:value_start + int(value_length)]).decode("utf-8", "replace")
        next_offset = skip_protobuf_field(data, offset, end, wire)
        if next_offset is None:
            break
        offset = next_offset
    return ""


def read_geofile_categories(path: Path) -> list[str]:
    data = memoryview(path.read_bytes())
    result: set[str] = set()
    offset = 0
    limit = len(data)
    while offset < limit:
        key, offset = read_protobuf_varint(data, offset, limit)
        if key is None:
            break
        field = int(key >> 3)
        wire = int(key & 7)
        if field == 1 and wire == 2:
            length, start = read_protobuf_varint(data, offset, limit)
            if length is None or start + int(length) > limit:
                break
            code = read_protobuf_string_field(data, start, int(length)).strip().lower()
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", code):
                result.add(code)
            offset = start + int(length)
            continue
        next_offset = skip_protobuf_field(data, offset, limit, wire)
        if next_offset is None:
            break
        offset = next_offset
    return sorted(result)


def canonical_geo_reference(value: object) -> str:
    text = str(value or "").strip().lower()
    for prefix in ("geoip:", "geosite:"):
        if text.startswith(prefix):
            category = text[len(prefix):].split("@", 1)[0].strip()
            if category:
                return prefix + category
    return ""


def collect_geo_references(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for nested in value.values():
            result.update(collect_geo_references(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(collect_geo_references(nested))
    elif isinstance(value, str):
        reference = canonical_geo_reference(value)
        if reference:
            result.add(reference)
    return result


def analyze_geofile_pair(geoip: Path, geosite: Path) -> dict[str, Any]:
    for label, path in (("geoip.dat", geoip), ("geosite.dat", geosite)):
        if not path.is_file() or path.stat().st_size < GEOFILES_MINIMUM_SIZE:
            raise RuntimeError(f"{label} is too small")
    geoip_categories = read_geofile_categories(geoip)
    geosite_categories = read_geofile_categories(geosite)
    if not geoip_categories:
        raise RuntimeError("geoip.dat contains no categories")
    if not geosite_categories:
        raise RuntimeError("geosite.dat contains no categories")
    return {
        "geoip_categories": geoip_categories,
        "geosite_categories": geosite_categories,
    }


def geofiles_compatibility(config: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    available = {f"geoip:{item}" for item in analysis["geoip_categories"]}
    available.update(f"geosite:{item}" for item in analysis["geosite_categories"])
    required = collect_geo_references(config)
    missing = sorted(required - available)
    return {
        "compatible": not missing,
        "required_categories": sorted(required),
        "missing_categories": missing,
    }


def require_https_url(value: object, label: str) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError(f"{label} must be a public HTTPS URL")
    return text


def controller_connection() -> tuple[str, str]:
    try:
        config = json.loads(AGENT_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read SG-Node agent config: {exc}") from exc
    panel_url = str(config.get("panel_url") or "").strip().rstrip("/")
    token = str(config.get("agent_token") or "").strip()
    if not panel_url.startswith(("https://", "http://")) or not token:
        raise RuntimeError("SG-Node agent config has no Controller URL/token")
    return panel_url, token


def download_controller_geofile(generation: str, name: str, destination: Path) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", generation):
        raise RuntimeError("invalid Controller GeoFiles generation")
    if name not in {"geoip.dat", "geosite.dat"}:
        raise RuntimeError("invalid GeoFiles asset name")
    panel_url, token = controller_connection()
    url = f"{panel_url}/api/node/v1/geofiles/{generation}/{name}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": f"SG-Node-Worker/{WORKER_VERSION}",
            "Accept": "application/octet-stream",
        },
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=195) as response, destination.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"Controller GeoFiles download failed: {exc}") from exc


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = command([
        "curl", "--fail", "--location", "--silent", "--show-error",
        "--proto", "=https", "--tlsv1.2", "--max-time", "180",
        "--output", str(destination), url,
    ], timeout=195)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or f"download failed: {url}").strip())


def staged_manifest() -> dict[str, Any]:
    path = GEOFILES_STAGING / "manifest.json"
    if not path.is_file():
        raise RuntimeError("GeoFiles staging manifest not found")
    return safe_read_json(path)


def node_config_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    if config is None:
        if not XRAY_CONFIG.is_file():
            raise RuntimeError("payload.config is required because current Xray config is missing")
        config = json.loads(XRAY_CONFIG.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError("payload.config must be an object")
    return config


def xray_test_with_assets(config_path: Path, asset_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(asset_dir)
    return subprocess.run(
        [str(XRAY_BIN), "run", "-test", "-config", str(config_path)],
        capture_output=True, text=True, timeout=45, check=False, env=env,
    )


def ensure_xray_active() -> None:
    state = command(["systemctl", "is-active", "xray.service"], timeout=10)
    if state.returncode != 0 or state.stdout.strip() != "active":
        raise RuntimeError("xray.service did not become active")


def stage_geofiles(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    transfer = str(payload.get("transfer") or "source").strip().lower()
    geoip_url = ""
    geosite_url = ""
    generation = str(payload.get("controller_generation") or "").strip()
    if transfer != "controller":
        geoip_url = require_https_url(payload.get("geoip_url"), "geoip_url")
        geosite_url = require_https_url(payload.get("geosite_url"), "geosite_url")
    expected_geoip = str(payload.get("geoip_sha256") or "").strip().lower()
    expected_geosite = str(payload.get("geosite_sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_geoip) or not re.fullmatch(r"[0-9a-f]{64}", expected_geosite):
        raise RuntimeError("Controller must provide both verified GeoFiles SHA-256 values")
    temporary = GEOFILES_ROOT / f".staging-{job_id}"
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True, exist_ok=False)
    try:
        geoip = temporary / "geoip.dat"
        geosite = temporary / "geosite.dat"
        if transfer == "controller":
            download_controller_geofile(generation, "geoip.dat", geoip)
            download_controller_geofile(generation, "geosite.dat", geosite)
        else:
            download_file(geoip_url, geoip)
            download_file(geosite_url, geosite)
        for label, path, expected in (
            ("geoip.dat", geoip, expected_geoip),
            ("geosite.dat", geosite, expected_geosite),
        ):
            if path.stat().st_size < GEOFILES_MINIMUM_SIZE:
                raise RuntimeError(f"{label} is too small")
            actual = file_sha256(path)
            if actual != expected:
                raise RuntimeError(f"{label} SHA-256 mismatch")
        analysis = analyze_geofile_pair(geoip, geosite)
        controller_manifest = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}
        for key in ("geoip_categories", "geosite_categories"):
            expected_categories = controller_manifest.get(key)
            if isinstance(expected_categories, list) and sorted(str(item).lower() for item in expected_categories) != analysis[key]:
                raise RuntimeError(f"local {key} do not match Controller manifest")
        manifest = {
            "source": str(payload.get("source") or "custom"),
            "source_label": str(payload.get("source_label") or "Controller"),
            "transfer": transfer,
            "controller_generation": generation if transfer == "controller" else "",
            "geoip_url": geoip_url,
            "geosite_url": geosite_url,
            "geoip": {"sha256": expected_geoip, "size": geoip.stat().st_size},
            "geosite": {"sha256": expected_geosite, "size": geosite.stat().st_size},
            **analysis,
            "staged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "controller_manifest": controller_manifest,
        }
        write_json_atomic(temporary / "manifest.json", manifest)
        shutil.rmtree(GEOFILES_STAGING, ignore_errors=True)
        temporary.replace(GEOFILES_STAGING)
        return {"message": "GeoFiles staged on SG-Node", "manifest": manifest, "worker_version": WORKER_VERSION}
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def validate_geofiles(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    manifest = staged_manifest()
    geoip = GEOFILES_STAGING / "geoip.dat"
    geosite = GEOFILES_STAGING / "geosite.dat"
    if file_sha256(geoip) != manifest["geoip"]["sha256"] or file_sha256(geosite) != manifest["geosite"]["sha256"]:
        raise RuntimeError("staged GeoFiles changed after staging")
    analysis = analyze_geofile_pair(geoip, geosite)
    config = node_config_from_payload(payload)
    config_sha = hashlib.sha256(json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    expected_config_sha = str(payload.get("config_sha256") or "").strip().lower()
    if expected_config_sha and expected_config_sha != config_sha:
        raise RuntimeError("SG-Node candidate config SHA-256 mismatch")
    compatibility = geofiles_compatibility(config, analysis)
    if not compatibility["compatible"]:
        raise RuntimeError(
            "SG-Node candidate is incompatible with staged GeoFiles; missing: "
            + ", ".join(compatibility["missing_categories"])
        )
    config_path = GEOFILES_STAGING / f"candidate-{job_id}.json"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = xray_test_with_assets(config_path, GEOFILES_STAGING)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "Xray rejected full SG-Node candidate").strip()[-4000:])
    manifest.update({
        **analysis,
        **compatibility,
        "candidate_config_sha256": config_sha,
        "validated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "xray_test": "ok",
    })
    write_json_atomic(GEOFILES_STAGING / "manifest.json", manifest)
    return {"message": "Full SG-Node candidate validated with staging GeoFiles", "manifest": manifest, "worker_version": WORKER_VERSION}


def restore_node_backup(backup: Path) -> None:
    metadata = safe_read_json(backup / "transaction.json")
    stopped = command(["systemctl", "stop", "xray.service"], timeout=40)
    if stopped.returncode != 0:
        raise RuntimeError((stopped.stderr or stopped.stdout or "rollback xray stop failed").strip())
    for name in ("geoip.dat", "geosite.dat"):
        previous = backup / name
        target = XRAY_ASSET_DIR / name
        if previous.is_file():
            shutil.copy2(previous, target)
        elif not bool(metadata.get(f"{name}_existed")):
            target.unlink(missing_ok=True)
    previous_config = backup / "config.json"
    if previous_config.is_file():
        shutil.copy2(previous_config, XRAY_CONFIG)
        os.chmod(XRAY_CONFIG, 0o644)
    elif not bool(metadata.get("config_existed")):
        XRAY_CONFIG.unlink(missing_ok=True)
    active_manifest = GEOFILES_ROOT / "active-manifest.json"
    previous_manifest = backup / "active-manifest.json"
    if previous_manifest.is_file():
        shutil.copy2(previous_manifest, active_manifest)
    elif not bool(metadata.get("active_manifest_existed")):
        active_manifest.unlink(missing_ok=True)
    if XRAY_CONFIG.is_file():
        tested = xray_test_with_assets(XRAY_CONFIG, XRAY_ASSET_DIR)
        if tested.returncode != 0:
            raise RuntimeError((tested.stderr or tested.stdout or "rollback xray test failed").strip()[-4000:])
    restarted = command(["systemctl", "restart", "xray.service"], timeout=40)
    if restarted.returncode != 0:
        raise RuntimeError((restarted.stderr or restarted.stdout or "rollback restart failed").strip())
    ensure_xray_active()


def apply_geofiles(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    has_transfer = str(payload.get("transfer") or "").strip() == "controller"
    has_source_urls = bool(payload.get("geoip_url") or payload.get("geosite_url"))
    if has_transfer or has_source_urls:
        stage_geofiles(job_id, payload)
    elif not (GEOFILES_STAGING / "manifest.json").is_file():
        raise RuntimeError("GeoFiles are not staged and no source was supplied")
    validated = validate_geofiles(job_id, payload)
    manifest = dict(validated["manifest"])
    config = node_config_from_payload(payload)
    config_text = json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    generation = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + str(manifest["candidate_config_sha256"])[:12]
    generation_dir = GEOFILES_SETS / generation
    generation_dir.mkdir(parents=True, exist_ok=False)
    for name in ("geoip.dat", "geosite.dat"):
        shutil.copy2(GEOFILES_STAGING / name, generation_dir / name)
    (generation_dir / "config.json").write_text(config_text, encoding="utf-8")
    manifest["generation"] = generation
    write_json_atomic(generation_dir / "manifest.json", manifest)

    XRAY_ASSET_DIR.mkdir(parents=True, exist_ok=True)
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    backup = GEOFILES_BACKUPS / f"before-{job_id}-{utc_stamp()}"
    backup.mkdir(parents=True, exist_ok=False)
    metadata = {
        "generation": generation,
        "geoip.dat_existed": (XRAY_ASSET_DIR / "geoip.dat").is_file(),
        "geosite.dat_existed": (XRAY_ASSET_DIR / "geosite.dat").is_file(),
        "config_existed": XRAY_CONFIG.is_file(),
        "active_manifest_existed": (GEOFILES_ROOT / "active-manifest.json").is_file(),
        "xray_state_before": (
            command(["systemctl", "is-active", "xray.service"], timeout=10).stdout or "unknown"
        ).strip(),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    for name in ("geoip.dat", "geosite.dat"):
        current = XRAY_ASSET_DIR / name
        if current.is_file():
            shutil.copy2(current, backup / name)
    if XRAY_CONFIG.is_file():
        shutil.copy2(XRAY_CONFIG, backup / "config.json")
    active_manifest = GEOFILES_ROOT / "active-manifest.json"
    if active_manifest.is_file():
        shutil.copy2(active_manifest, backup / "active-manifest.json")
    write_json_atomic(backup / "transaction.json", metadata)
    write_json_atomic(GEOFILES_TRANSACTION, {**metadata, "backup": str(backup), "state": "committing"})
    try:
        stopped = command(["systemctl", "stop", "xray.service"], timeout=40)
        if stopped.returncode != 0:
            raise RuntimeError((stopped.stderr or stopped.stdout or "xray stop failed").strip())
        for name in ("geoip.dat", "geosite.dat"):
            temp = XRAY_ASSET_DIR / f".{name}.sg-node-{job_id}"
            shutil.copy2(generation_dir / name, temp)
            temp.replace(XRAY_ASSET_DIR / name)
        temp_config = XRAY_CONFIG.parent / f".config.sg-node-{job_id}.json"
        temp_config.write_text(config_text, encoding="utf-8")
        os.chmod(temp_config, 0o644)
        temp_config.replace(XRAY_CONFIG)
        tested = xray_test_with_assets(XRAY_CONFIG, XRAY_ASSET_DIR)
        if tested.returncode != 0:
            raise RuntimeError((tested.stderr or tested.stdout or "final xray test failed").strip()[-4000:])
        restarted = command(["systemctl", "restart", "xray.service"], timeout=40)
        if restarted.returncode != 0:
            raise RuntimeError((restarted.stderr or restarted.stdout or "xray restart failed").strip())
        ensure_xray_active()
        manifest["applied_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_json_atomic(GEOFILES_ROOT / "active-manifest.json", manifest)
        GEOFILES_TRANSACTION.unlink(missing_ok=True)
        shutil.rmtree(GEOFILES_STAGING, ignore_errors=True)
        return {
            "message": "GeoFiles generation applied atomically on SG-Node",
            "generation": generation,
            "manifest": manifest,
            "backup_path": str(backup),
            "service": "active",
            "worker_version": WORKER_VERSION,
        }
    except Exception as exc:
        try:
            restore_node_backup(backup)
            write_json_atomic(backup / "rollback.json", {"ok": True, "error": str(exc), "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            GEOFILES_TRANSACTION.unlink(missing_ok=True)
        except Exception as rollback_exc:
            write_json_atomic(GEOFILES_TRANSACTION, {**metadata, "backup": str(backup), "state": "rollback_failed", "error": str(exc), "rollback_error": str(rollback_exc)})
            raise RuntimeError(f"critical SG-Node rollback failure: {rollback_exc}; original: {exc}") from rollback_exc
        raise


def rollback_geofiles(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    requested = str(payload.get("backup_path") or "").strip()
    if requested:
        backup = Path(requested).resolve()
        if GEOFILES_BACKUPS.resolve() not in backup.parents:
            raise RuntimeError("backup_path is outside SG-Node GeoFiles backup directory")
    else:
        candidates = sorted(GEOFILES_BACKUPS.glob("before-*"), reverse=True)
        if not candidates:
            raise RuntimeError("no SG-Node GeoFiles backup found")
        backup = candidates[0]
    restore_node_backup(backup)
    return {"message": "SG-Node GeoFiles rollback confirmed", "backup_path": str(backup), "service": "active", "worker_version": WORKER_VERSION}


def get_geofiles_manifest(job_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    path = GEOFILES_ROOT / "active-manifest.json"
    manifest = safe_read_json(path) if path.is_file() else {}
    return {"message": "SG-Node GeoFiles manifest", "manifest": manifest, "worker_version": WORKER_VERSION}


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
        job_type = str(job.get("job_type") or "")
        payload = job.get("payload")
        if not isinstance(payload, dict):
            raise RuntimeError("job payload must be an object")
        handlers = {
            "apply_xray_config": apply_xray_config,
            "stage_geofiles": stage_geofiles,
            "validate_geofiles": validate_geofiles,
            "apply_geofiles": apply_geofiles,
            "rollback_geofiles": rollback_geofiles,
            "get_geofiles_manifest": get_geofiles_manifest,
            "upsert_cascade_access": upsert_cascade_access,
        }
        worker_operation = str(payload.get("worker_operation") or "").strip()
        if job_type == "apply_xray_config" and worker_operation in handlers:
            handler = handlers[worker_operation]
        else:
            handler = handlers.get(job_type)
        if handler is None:
            raise RuntimeError("unsupported job type")
        result = handler(job_id, payload)
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
