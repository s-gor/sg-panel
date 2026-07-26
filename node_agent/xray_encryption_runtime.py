from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from xray_encryption import (
    VlessEncryptionError,
    build_mlkem_pair,
    client_value_ready,
    normalize_pair,
    server_value_ready,
)

MINIMUM_XRAY_VERSION = (26, 6, 27)
MINIMUM_XRAY_LABEL = "v26.6.27"
DEFAULT_SECRET_PATH = Path("/etc/sg-node/xray-secrets.env")


class XrayEncryptionRuntimeError(RuntimeError):
    pass


def command(args: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def xray_version(binary: str | Path) -> tuple[int, int, int]:
    result = command([str(binary), "version"], timeout=15)
    text = (result.stdout or result.stderr or "").strip()
    match = re.search(r"(?im)^Xray\s+v?(\d+)\.(\d+)\.(\d+)\b", text)
    if result.returncode != 0 or not match:
        raise XrayEncryptionRuntimeError(
            f"Не удалось определить версию Xray: {text[-1000:] or 'пустой вывод'}"
        )
    return tuple(int(item) for item in match.groups())


def require_supported_xray(binary: str | Path) -> tuple[int, int, int]:
    version = xray_version(binary)
    if version < MINIMUM_XRAY_VERSION:
        raise XrayEncryptionRuntimeError(
            f"VLESS Encryption требует Xray не ниже {MINIMUM_XRAY_LABEL}; "
            f"обнаружена v{version[0]}.{version[1]}.{version[2]}"
        )
    return version


def parse_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def read_pair(path: Path = DEFAULT_SECRET_PATH) -> dict[str, str]:
    values = parse_env(path)
    try:
        encryption, decryption, swapped = normalize_pair(
            values.get("SG_NODE_VLESS_ENCRYPTION", ""),
            values.get("SG_NODE_VLESS_DECRYPTION", ""),
        )
    except VlessEncryptionError as exc:
        raise XrayEncryptionRuntimeError(str(exc)) from exc
    return {
        "encryption": encryption,
        "decryption": decryption,
        "generation": values.get("SG_NODE_VLESS_ENCRYPTION_GENERATION", "").strip(),
        "checked_at": values.get("SG_NODE_VLESS_ENCRYPTION_CHECKED_AT", "").strip(),
        "swapped": "1" if swapped else "0",
    }


def find_output_value(output: str, names: tuple[str, ...]) -> str:
    for name in names:
        match = re.search(
            rf"(?im)^\s*[\"']?{re.escape(name)}[\"']?\s*:\s*[\"']?([^\"'\s,}}]+)",
            output,
        )
        if match:
            return match.group(1).strip().rstrip("=")
    return ""


def generate_pair(binary: str | Path) -> tuple[str, str]:
    require_supported_xray(binary)
    result = command([str(binary), "mlkem768"], timeout=45)
    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    if result.returncode != 0:
        raise XrayEncryptionRuntimeError(
            "xray mlkem768 завершился с ошибкой:\n" + output.strip()[-4000:]
        )
    seed = find_output_value(output, ("Seed", "seed", "PrivateKey"))
    client = find_output_value(
        output,
        ("Client", "client", "PublicKey", "Password (PublicKey)"),
    )
    if not seed or not client:
        raise XrayEncryptionRuntimeError(
            "Не удалось разобрать xray mlkem768: ожидались отдельные Seed и Client"
        )
    try:
        return build_mlkem_pair(seed, client)
    except VlessEncryptionError as exc:
        raise XrayEncryptionRuntimeError(str(exc)) from exc


def validate_pair(binary: str | Path, encryption: str, decryption: str) -> None:
    require_supported_xray(binary)
    if not client_value_ready(encryption) or not server_value_ready(decryption):
        raise XrayEncryptionRuntimeError("ML-KEM-768 пара неполная или имеет перепутанные роли")
    user_id = str(uuid.uuid4())
    payload = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "sg-node-vlessenc-selftest-in",
                "listen": "127.0.0.1",
                "port": 39991,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": user_id, "flow": "xtls-rprx-vision"}],
                    "decryption": decryption,
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "auto"},
                },
            }
        ],
        "outbounds": [
            {
                "tag": "sg-node-vlessenc-selftest-out",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 39991,
                    "id": user_id,
                    "encryption": encryption,
                    "flow": "xtls-rprx-vision",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "stream-one"},
                },
            }
        ],
    }
    with tempfile.TemporaryDirectory(prefix="sg-node-vlessenc-") as temporary:
        config = Path(temporary) / "config.json"
        config.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result = command([str(binary), "run", "-test", "-config", str(config)], timeout=45)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "xray run -test failed").strip()
            raise XrayEncryptionRuntimeError(
                "Xray отклонил ML-KEM-768 пару:\n" + detail[-4000:]
            )


def write_pair(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        "\n".join(
            [
                "# SG-Node Xray VLESS Encryption. Server decryption never leaves this node.",
                f"SG_NODE_VLESS_ENCRYPTION={values['encryption']}",
                f"SG_NODE_VLESS_DECRYPTION={values['decryption']}",
                f"SG_NODE_VLESS_ENCRYPTION_GENERATION={values['generation']}",
                f"SG_NODE_VLESS_ENCRYPTION_CHECKED_AT={values['checked_at']}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.chown(temporary, 0, 0)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    os.chown(path, 0, 0)


def ensure_pair(binary: str | Path, *, force: bool = False) -> dict[str, str]:
    if not force:
        try:
            pair = read_pair(DEFAULT_SECRET_PATH)
            validate_pair(binary, pair["encryption"], pair["decryption"])
            if pair.get("swapped") == "1":
                pair["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                pair["generation"] = pair.get("generation") or uuid.uuid4().hex
                write_pair(DEFAULT_SECRET_PATH, pair)
            return pair
        except (XrayEncryptionRuntimeError, OSError):
            pass
    encryption, decryption = generate_pair(binary)
    validate_pair(binary, encryption, decryption)
    pair = {
        "encryption": encryption,
        "decryption": decryption,
        "generation": uuid.uuid4().hex,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "swapped": "0",
    }
    write_pair(DEFAULT_SECRET_PATH, pair)
    return pair
