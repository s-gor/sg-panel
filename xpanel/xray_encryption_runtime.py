from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .xray_encryption import (
    VlessEncryptionError,
    build_mlkem_pair,
    client_value_ready,
    normalize_pair,
    server_value_ready,
)

MINIMUM_XRAY_VERSION = (26, 6, 27)
MINIMUM_XRAY_LABEL = "v26.6.27"
DEFAULT_SECRET_PATH = Path(
    os.environ.get("XPANEL_XRAY_ENCRYPTION_SECRET", "/etc/xpanel-mvp/xray-secrets.env")
)


class XrayEncryptionRuntimeError(RuntimeError):
    pass


def _command(args: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def xray_version(binary: str | Path) -> tuple[int, int, int]:
    result = _command([str(binary), "version"], timeout=15)
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


def _parse_env(path: Path) -> dict[str, str]:
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


def read_pair(path: str | Path = DEFAULT_SECRET_PATH) -> dict[str, str]:
    target = Path(path)
    values = _parse_env(target)
    encryption = values.get("XPANEL_VLESS_ENCRYPTION", "").strip()
    decryption = values.get("XPANEL_VLESS_DECRYPTION", "").strip()
    try:
        encryption, decryption, swapped = normalize_pair(encryption, decryption)
    except VlessEncryptionError as exc:
        raise XrayEncryptionRuntimeError(str(exc)) from exc
    return {
        "encryption": encryption,
        "decryption": decryption,
        "generation": values.get("XPANEL_VLESS_ENCRYPTION_GENERATION", "").strip(),
        "checked_at": values.get("XPANEL_VLESS_ENCRYPTION_CHECKED_AT", "").strip(),
        "swapped": "1" if swapped else "0",
        "path": str(target),
    }


def _find_output_value(output: str, names: tuple[str, ...]) -> str:
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
    result = _command([str(binary), "mlkem768"], timeout=45)
    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    if result.returncode != 0:
        raise XrayEncryptionRuntimeError(
            "xray mlkem768 завершился с ошибкой:\n" + output.strip()[-4000:]
        )
    seed = _find_output_value(output, ("Seed", "seed", "PrivateKey"))
    client = _find_output_value(
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


def validate_pair_with_xray(
    binary: str | Path,
    encryption: str,
    decryption: str,
    *,
    reality_settings: dict[str, Any] | None = None,
) -> None:
    require_supported_xray(binary)
    if not client_value_ready(encryption) or not server_value_ready(decryption):
        raise XrayEncryptionRuntimeError("ML-KEM-768 пара неполная или имеет перепутанные роли")
    inbound_stream: dict[str, Any] = {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "auto"},
    }
    outbound_stream: dict[str, Any] = {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "stream-one"},
    }
    if reality_settings:
        inbound_reality = dict(reality_settings)
        public_key = str(inbound_reality.pop("publicKey", "") or "")
        inbound_stream["security"] = "reality"
        inbound_stream["realitySettings"] = inbound_reality
        server_names = inbound_reality.get("serverNames") or []
        if not server_names:
            raise XrayEncryptionRuntimeError("REALITY self-test требует serverNames")
        short_ids = inbound_reality.get("shortIds") or []
        # Server config normally has privateKey only. A full outbound REALITY
        # self-test cannot derive pbk without an explicit public key, so the
        # cryptographic VLESS/XHTTP validation remains local-security=none.
        # The production candidate is subsequently tested with REALITY by the
        # normal SG-Panel render/apply path.
        if public_key and short_ids:
            outbound_stream.update(
                {
                    "security": "reality",
                    "realitySettings": {
                        "serverName": str(server_names[0]),
                        "fingerprint": "firefox",
                        "publicKey": public_key,
                        "shortId": str(short_ids[0]),
                    },
                }
            )
        else:
            inbound_stream = {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {"path": "/sg-vlessenc-selftest", "mode": "auto"},
            }
    user_id = str(uuid.uuid4())
    payload = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "sg-vlessenc-selftest-in",
                "listen": "127.0.0.1",
                "port": 39991,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": user_id, "flow": "xtls-rprx-vision"}],
                    "decryption": decryption,
                },
                "streamSettings": inbound_stream,
            }
        ],
        "outbounds": [
            {
                "tag": "sg-vlessenc-selftest-out",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 39991,
                    "id": user_id,
                    "encryption": encryption,
                    "flow": "xtls-rprx-vision",
                },
                "streamSettings": outbound_stream,
            }
        ],
    }
    with tempfile.TemporaryDirectory(prefix="sg-panel-vlessenc-") as temporary:
        config = Path(temporary) / "config.json"
        config.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result = _command([str(binary), "run", "-test", "-config", str(config)], timeout=45)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "xray run -test failed").strip()
            raise XrayEncryptionRuntimeError(
                "Xray отклонил ML-KEM-768 пару:\n" + detail[-4000:]
            )


def _write_secret(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    lines = [
        "# SG-Panel Xray VLESS Encryption. Server decryption is root-only.",
        f"XPANEL_VLESS_ENCRYPTION={values['encryption']}",
        f"XPANEL_VLESS_DECRYPTION={values['decryption']}",
        f"XPANEL_VLESS_ENCRYPTION_GENERATION={values['generation']}",
        f"XPANEL_VLESS_ENCRYPTION_CHECKED_AT={values['checked_at']}",
        "",
    ]
    temporary.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(temporary, 0o600)
    try:
        os.chown(temporary, 0, 0)
    except PermissionError:
        pass
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    try:
        os.chown(path, 0, 0)
    except PermissionError:
        pass


def ensure_pair(
    binary: str | Path,
    *,
    secret_path: str | Path = DEFAULT_SECRET_PATH,
    force: bool = False,
    reality_settings: dict[str, Any] | None = None,
) -> dict[str, str]:
    target = Path(secret_path)
    if not force:
        try:
            pair = read_pair(target)
            validate_pair_with_xray(
                binary,
                pair["encryption"],
                pair["decryption"],
                reality_settings=reality_settings,
            )
            if pair.get("swapped") == "1":
                pair["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                pair["generation"] = pair.get("generation") or uuid.uuid4().hex
                _write_secret(target, pair)
            return pair
        except (XrayEncryptionRuntimeError, OSError):
            pass
    encryption, decryption = generate_pair(binary)
    validate_pair_with_xray(
        binary,
        encryption,
        decryption,
        reality_settings=reality_settings,
    )
    values = {
        "encryption": encryption,
        "decryption": decryption,
        "generation": uuid.uuid4().hex,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "swapped": "0",
        "path": str(target),
    }
    _write_secret(target, values)
    return values
