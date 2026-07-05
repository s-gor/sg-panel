from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .service import XPanelError

XRAY_REPOSITORY = "XTLS/Xray-core"
XRAY_UPDATE_UNIT = "sg-panel-xray-update.service"
XRAY_CHANNELS = {"stable", "prerelease"}
_XRAY_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$", re.IGNORECASE)
_SAFE_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _state_dir() -> Path:
    return Path(os.environ.get("XPANEL_UPDATE_STATE_DIR", "/var/lib/sg-panel-update"))


def _check_path(channel: str) -> Path:
    return _state_dir() / f"xray-check-{channel}.json"


def _status_path() -> Path:
    return Path(
        os.environ.get(
            "XPANEL_XRAY_UPDATE_STATUS", str(_state_dir() / "xray-status.json")
        )
    )


def _log_path() -> Path:
    return Path(
        os.environ.get(
            "XPANEL_XRAY_UPDATE_LOG", str(_state_dir() / "xray-update.log")
        )
    )


def _project_dir() -> Path:
    return Path(os.environ.get("XPANEL_PROJECT_DIR", "/opt/xpanel-mvp"))


def _atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(temporary, mode)
    temporary.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def normalize_xray_version(value: str) -> str:
    match = _XRAY_VERSION_RE.fullmatch(str(value or "").strip())
    if not match:
        return ""
    return f"v{int(match.group(1))}.{int(match.group(2))}.{int(match.group(3))}"


def xray_version_key(value: str) -> tuple[int, int, int]:
    normalized = normalize_xray_version(value)
    if not normalized:
        return (-1, -1, -1)
    match = _XRAY_VERSION_RE.fullmatch(normalized)
    assert match is not None
    return tuple(int(match.group(index)) for index in range(1, 4))


def _validate_channel(channel: str) -> str:
    clean = str(channel or "").strip().lower()
    if clean not in XRAY_CHANNELS:
        raise ValueError("Неизвестный канал обновления Xray")
    return clean


def _machine_asset() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "64",
        "amd64": "64",
        "aarch64": "arm64-v8a",
        "arm64": "arm64-v8a",
    }
    asset = mapping.get(machine)
    if not asset:
        raise XPanelError(f"Архитектура сервера пока не поддерживается: {machine}")
    return f"Xray-linux-{asset}.zip"


def installed_xray_version(xray_bin: str = "/usr/local/bin/xray") -> str:
    path = Path(str(xray_bin or ""))
    if not path.is_absolute() or not path.is_file():
        return ""
    try:
        result = subprocess.run(
            [str(path), "version"],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    first = (result.stdout or result.stderr or "").splitlines()
    if result.returncode != 0 or not first:
        return ""
    parts = first[0].split()
    if len(parts) < 2 or parts[0].lower() != "xray":
        return ""
    return normalize_xray_version(parts[1])


def _cached_check(
    channel: str, current: str, max_age: timedelta = timedelta(minutes=15)
) -> dict[str, Any] | None:
    cached = _read_json(_check_path(channel))
    if str(cached.get("current") or "") != current:
        return None
    checked_at = str(cached.get("checked_at") or "")
    if not checked_at:
        return None
    try:
        moment = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - moment > max_age:
        return None
    return cached


def _release_has_assets(release: dict[str, Any], asset_name: str) -> bool:
    names = {
        str(item.get("name") or "")
        for item in release.get("assets", [])
        if isinstance(item, dict)
    }
    return asset_name in names and f"{asset_name}.dgst" in names


def _select_release(payload: Any, channel: str, asset_name: str) -> dict[str, Any]:
    if channel == "stable":
        candidates = [payload] if isinstance(payload, dict) else []
    else:
        candidates = payload if isinstance(payload, list) else []
        candidates = [
            item
            for item in candidates
            if isinstance(item, dict)
            and bool(item.get("prerelease"))
            and not bool(item.get("draft"))
        ]
    valid = [
        item
        for item in candidates
        if normalize_xray_version(str(item.get("tag_name") or ""))
        and _release_has_assets(item, asset_name)
    ]
    if not valid:
        raise XPanelError(
            "GitHub не вернул подходящий официальный релиз Xray для архитектуры сервера"
        )
    return max(valid, key=lambda item: xray_version_key(str(item.get("tag_name") or "")))


def check_xray_updates(
    *,
    channel: str = "stable",
    force: bool = False,
    allow_network: bool = True,
    xray_bin: str = "/usr/local/bin/xray",
) -> dict[str, Any]:
    clean_channel = _validate_channel(channel)
    current = installed_xray_version(xray_bin)
    if not current:
        current = "не определена"
    if not force:
        cached = _cached_check(clean_channel, current)
        if cached is not None:
            return cached

    previous = _read_json(_check_path(clean_channel))
    stamp = _utc_now()
    asset_name = _machine_asset()
    if not allow_network:
        latest = str(previous.get("latest") or "")
        result = {
            "channel": clean_channel,
            "current": current,
            "latest": latest,
            "available": bool(
                latest
                and xray_version_key(latest) > xray_version_key(current)
            ),
            "installed_newer": bool(
                latest
                and xray_version_key(current) > xray_version_key(latest)
            ),
            "prerelease": clean_channel == "prerelease",
            "asset": asset_name,
            "checked_at": str(previous.get("checked_at") or stamp),
            "error": str(previous.get("error") or ""),
        }
        return result

    if clean_channel == "stable":
        url = f"https://api.github.com/repos/{XRAY_REPOSITORY}/releases/latest"
    else:
        url = f"https://api.github.com/repos/{XRAY_REPOSITORY}/releases?per_page=50"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SG-Panel-Xray-Updater",
        },
    )
    error = ""
    latest = ""
    release_url = ""
    published_at = ""
    try:
        with urllib.request.urlopen(request, timeout=12) as response:  # nosec B310
            raw = response.read(8_000_001)
        if len(raw) > 8_000_000:
            raise XPanelError(
                "Ответ GitHub для проверки Xray слишком большой; повторите проверку позже"
            )
        payload = json.loads(raw.decode("utf-8"))
        release = _select_release(payload, clean_channel, asset_name)
        latest = normalize_xray_version(str(release.get("tag_name") or ""))
        release_url = str(release.get("html_url") or "")
        published_at = str(release.get("published_at") or "")
    except (
        OSError,
        urllib.error.URLError,
        json.JSONDecodeError,
        ValueError,
        XPanelError,
    ) as exc:
        error = str(exc)
        if str(previous.get("current") or "") == current:
            latest = str(previous.get("latest") or "")
            release_url = str(previous.get("release_url") or "")
            published_at = str(previous.get("published_at") or "")

    result = {
        "channel": clean_channel,
        "current": current,
        "latest": latest,
        "available": bool(
            not error and latest and xray_version_key(latest) > xray_version_key(current)
        ),
        "installed_newer": bool(
            latest and xray_version_key(current) > xray_version_key(latest)
        ),
        "prerelease": clean_channel == "prerelease",
        "asset": asset_name,
        "release_url": release_url,
        "published_at": published_at,
        "checked_at": stamp,
        "error": error,
    }
    _atomic_json(_check_path(clean_channel), result)
    return result


def get_xray_update_status() -> dict[str, Any]:
    data: dict[str, Any] = {
        "state": "idle",
        "version": "",
        "channel": "",
        "message": "Обновление Xray ещё не запускалось",
        "updatedAt": "",
    }
    data.update(_read_json(_status_path()))
    try:
        data["log"] = _log_path().read_text(
            encoding="utf-8", errors="replace"
        )[-64_000:]
    except OSError:
        data["log"] = ""

    if shutil.which("systemctl"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", XRAY_UPDATE_UNIT],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            data["unit_state"] = result.stdout.strip() or "inactive"
        except (OSError, subprocess.TimeoutExpired):
            data["unit_state"] = "unknown"
    else:
        data["unit_state"] = "unavailable"

    running_states = {
        "starting",
        "downloading",
        "verifying",
        "backing_up",
        "installing",
        "validating",
        "rollback",
    }
    if (
        str(data.get("state")) in running_states
        and str(data.get("unit_state")) not in {"active", "activating", "unknown"}
    ):
        updated_at = str(data.get("updatedAt") or data.get("startedAt") or "")
        try:
            moment = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
        except ValueError:
            moment = datetime.now(timezone.utc) - timedelta(minutes=10)
        if datetime.now(timezone.utc) - moment > timedelta(minutes=2):
            data["state"] = "error"
            data["message"] = (
                "Операция обновления Xray была прервана. Проверьте журнал и службу Xray"
            )
            data["updatedAt"] = _utc_now()
            persisted = {
                key: value
                for key, value in data.items()
                if key not in {"log", "unit_state"}
            }
            _atomic_json(_status_path(), persisted)
    return data


def xray_update_in_progress() -> bool:
    status = get_xray_update_status()
    if str(status.get("state")) in {
        "starting",
        "downloading",
        "verifying",
        "backing_up",
        "installing",
        "validating",
        "rollback",
    }:
        return True
    return str(status.get("unit_state")) in {"active", "activating"}


def _safe_absolute_file(value: str, label: str) -> str:
    path = Path(str(value or ""))
    if not path.is_absolute() or "\x00" in str(path):
        raise ValueError(f"Некорректный путь: {label}")
    return str(path)


def start_xray_update(
    version: str,
    channel: str,
    *,
    xray_bin: str = "/usr/local/bin/xray",
    config_path: str = "/usr/local/etc/xray/config.json",
    xray_service: str = "xray",
) -> dict[str, str]:
    expected_version = normalize_xray_version(version)
    clean_channel = _validate_channel(channel)
    if not expected_version or expected_version != str(version).strip():
        raise ValueError("Некорректная версия Xray")
    clean_bin = _safe_absolute_file(xray_bin, "Xray")
    clean_config = _safe_absolute_file(config_path, "config.json")
    clean_service = str(xray_service or "").strip()
    if not _SAFE_SERVICE_RE.fullmatch(clean_service):
        raise ValueError("Некорректное имя службы Xray")
    current = installed_xray_version(clean_bin)
    if not current:
        raise XPanelError("Не удалось определить установленную версию Xray")
    if xray_version_key(expected_version) <= xray_version_key(current):
        raise ValueError("Выбранная версия Xray не новее установленной")
    if os.geteuid() != 0 and os.environ.get("XPANEL_UPDATE_TEST_MODE") != "1":
        raise PermissionError("Для обновления Xray нужны права root")
    if xray_update_in_progress():
        raise XPanelError("Обновление Xray уже выполняется")
    from .update_manager import update_in_progress

    if update_in_progress():
        raise XPanelError("Сначала дождитесь завершения обновления SG-Panel")

    script = _project_dir() / "deploy" / "update-xray.sh"
    if not script.is_file():
        raise FileNotFoundError(script)
    systemd_run = shutil.which("systemd-run")
    if not systemd_run:
        raise XPanelError("Не найдена команда systemd-run")

    state_dir = _state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    _log_path().write_text("", encoding="utf-8")
    os.chmod(_log_path(), 0o600)
    started = _utc_now()
    _atomic_json(
        _status_path(),
        {
            "state": "starting",
            "version": expected_version,
            "channel": clean_channel,
            "message": "Обновление Xray поставлено в очередь",
            "startedAt": started,
            "updatedAt": started,
        },
    )

    systemctl = shutil.which("systemctl")
    if systemctl:
        subprocess.run(
            [systemctl, "reset-failed", XRAY_UPDATE_UNIT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    command = [
        systemd_run,
        "--unit=sg-panel-xray-update",
        "--collect",
        "--property=Type=oneshot",
        f"--working-directory={_project_dir()}",
        f"--setenv=XPANEL_XRAY_UPDATE_VERSION={expected_version}",
        f"--setenv=XPANEL_XRAY_UPDATE_CHANNEL={clean_channel}",
        f"--setenv=XPANEL_XRAY_UPDATE_STATUS={_status_path()}",
        f"--setenv=XPANEL_XRAY_UPDATE_LOG={_log_path()}",
        f"--setenv=XPANEL_XRAY_BIN={clean_bin}",
        f"--setenv=XPANEL_XRAY_CONFIG={clean_config}",
        f"--setenv=XPANEL_XRAY_SERVICE={clean_service}",
        "/bin/bash",
        str(script),
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"Не удалось запустить системное обновление Xray: {exc}"
        _atomic_json(
            _status_path(),
            {
                "state": "error",
                "version": expected_version,
                "channel": clean_channel,
                "message": message,
                "startedAt": started,
                "updatedAt": _utc_now(),
            },
        )
        raise XPanelError(message) from exc
    if result.returncode != 0:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or "Не удалось запустить обновление Xray"
        )
        _atomic_json(
            _status_path(),
            {
                "state": "error",
                "version": expected_version,
                "channel": clean_channel,
                "message": detail,
                "startedAt": started,
                "updatedAt": _utc_now(),
            },
        )
        raise XPanelError(detail)
    return {
        "unit": XRAY_UPDATE_UNIT,
        "version": expected_version,
        "channel": clean_channel,
    }
