from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .service import XPanelError

UPDATE_REPOSITORY = "s-gor/sg-panel"
UPDATE_UNIT = "sg-panel-update.service"
_VERSION_TAG_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:"
    r"[-.]?(alpha|beta|rc)(\d+)(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?"
    r"|-(?!(?:alpha|beta|rc)\d)[A-Za-z0-9][A-Za-z0-9.-]*"
    r")?$",
    re.IGNORECASE,
)
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _state_dir() -> Path:
    return Path(os.environ.get("XPANEL_UPDATE_STATE_DIR", "/var/lib/sg-panel-update"))


def _check_path() -> Path:
    return _state_dir() / "check.json"


def _status_path() -> Path:
    return Path(os.environ.get("XPANEL_UPDATE_STATUS", str(_state_dir() / "status.json")))


def _log_path() -> Path:
    return Path(os.environ.get("XPANEL_UPDATE_LOG", str(_state_dir() / "update.log")))


def _project_dir() -> Path:
    return Path(os.environ.get("XPANEL_PROJECT_DIR", "/opt/xpanel-mvp"))


def _atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, mode)
    temporary.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def version_key(value: str) -> tuple[int, int, int, int, int]:
    """Return a sortable application-version key.

    Release tags may contain publication suffixes such as ``-final-docs1``.
    The installed application version is determined only by the semantic prefix.
    """
    match = _VERSION_TAG_RE.fullmatch(str(value or "").strip())
    if not match:
        return (-1, -1, -1, -1, -1)
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    label = (match.group(4) or "stable").lower()
    rank = {"alpha": 0, "beta": 1, "rc": 2, "stable": 3}[label]
    number = int(match.group(5) or 0)
    return (major, minor, patch, rank, number)


def normalized_version(value: str) -> str:
    match = _VERSION_TAG_RE.fullmatch(str(value or "").strip())
    if not match:
        return ""
    major, minor, patch = match.group(1), match.group(2), match.group(3)
    label, number = match.group(4), match.group(5)
    suffix = f"-{label.lower()}{number}" if label else ""
    return f"v{major}.{minor}.{patch}{suffix}"


def _tag_preference(tag: str) -> tuple[int, int, str]:
    app_version = normalized_version(tag)
    exact = 2 if tag == app_version else 0
    final = 1 if "-final" in tag.lower() else 0
    return (exact, final, tag)


def _cached_check(
    current: str, max_age: timedelta = timedelta(minutes=15)
) -> dict[str, Any] | None:
    cached = _read_json(_check_path())
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


def check_for_updates(*, force: bool = False, allow_network: bool = True) -> dict[str, Any]:
    current = f"v{__version__}"
    if not force:
        cached = _cached_check(current)
        if cached is not None:
            return cached

    previous = _read_json(_check_path())
    stamp = _utc_now()
    if not allow_network:
        latest = str(previous.get("latest") or current)
        latest_ref = str(previous.get("latest_ref") or latest)
        result = {
            "current": current,
            "latest": latest,
            "latest_ref": latest_ref,
            "available": version_key(latest) > version_key(current),
            "checked_at": str(previous.get("checked_at") or stamp),
            "error": str(previous.get("error") or ""),
        }
        return result

    request = urllib.request.Request(
        f"https://api.github.com/repos/{UPDATE_REPOSITORY}/tags?per_page=100",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "SG-Panel-Updater",
        },
    )
    error = ""
    latest = current
    latest_ref = current
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
            raw = response.read(256_000).decode("utf-8")
        payload = json.loads(raw)
        tags = [
            str(item.get("name") or "")
            for item in payload
            if isinstance(item, dict)
        ]
        valid = [tag for tag in tags if version_key(tag)[0] >= 0 and _SAFE_REF_RE.fullmatch(tag)]
        if valid:
            best_key = max(version_key(tag) for tag in valid)
            candidates = [tag for tag in valid if version_key(tag) == best_key]
            remote_ref = max(candidates, key=_tag_preference)
            remote_latest = normalized_version(remote_ref)
            if version_key(remote_latest) >= version_key(current):
                latest_ref = remote_ref
                latest = remote_latest
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        error = str(exc)
        cached_latest = str(previous.get("latest") or current)
        cached_ref = str(previous.get("latest_ref") or cached_latest)
        if version_key(cached_latest) >= version_key(current):
            latest, latest_ref = cached_latest, cached_ref

    result = {
        "current": current,
        "latest": latest,
        "latest_ref": latest_ref,
        "available": not error and version_key(latest) > version_key(current),
        "checked_at": stamp,
        "error": error,
    }
    _atomic_json(_check_path(), result)
    return result


def get_update_status() -> dict[str, Any]:
    data: dict[str, Any] = {
        "state": "idle",
        "version": "",
        "ref": "",
        "message": "Обновление ещё не запускалось",
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
                ["systemctl", "is-active", UPDATE_UNIT],
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
        "starting", "downloading", "verifying", "backing_up", "installing",
        "validating", "rollback",
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
                "Операция обновления была прервана. Проверьте журнал и состояние служб"
            )
            data["updatedAt"] = _utc_now()
            persisted = {key: value for key, value in data.items() if key not in {"log", "unit_state"}}
            _atomic_json(_status_path(), persisted)
    return data


def update_in_progress() -> bool:
    status = get_update_status()
    if str(status.get("state")) in {
        "starting", "downloading", "verifying", "backing_up", "installing",
        "validating", "rollback",
    }:
        return True
    return str(status.get("unit_state")) in {"active", "activating"}


def start_panel_update(version: str, ref: str) -> dict[str, str]:
    expected_version = normalized_version(version)
    clean_ref = str(ref or "").strip()
    if not expected_version or expected_version != str(version).strip():
        raise ValueError("Некорректная версия обновления")
    if not _SAFE_REF_RE.fullmatch(clean_ref) or clean_ref.startswith("/") or ".." in clean_ref:
        raise ValueError("Некорректная ссылка на версию обновления")
    if version_key(expected_version) <= version_key(f"v{__version__}"):
        raise ValueError("Выбранная версия не новее установленной")
    if os.geteuid() != 0 and os.environ.get("XPANEL_UPDATE_TEST_MODE") != "1":
        raise PermissionError("Для обновления панели нужны права root")
    if update_in_progress():
        raise XPanelError("Обновление уже выполняется")
    from .xray_update_manager import xray_update_in_progress

    if xray_update_in_progress():
        raise XPanelError("Сначала дождитесь завершения обновления Xray")

    script = _project_dir() / "deploy" / "update-from-github.sh"
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
            "ref": clean_ref,
            "message": "Обновление поставлено в очередь",
            "startedAt": started,
            "updatedAt": started,
        },
    )

    systemctl = shutil.which("systemctl")
    if systemctl:
        subprocess.run(
            [systemctl, "reset-failed", UPDATE_UNIT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    command = [
        systemd_run,
        "--unit=sg-panel-update",
        "--collect",
        "--property=Type=oneshot",
        f"--working-directory={_project_dir()}",
        f"--setenv=XPANEL_UPDATE_VERSION={expected_version}",
        f"--setenv=XPANEL_UPDATE_REF={clean_ref}",
        f"--setenv=XPANEL_UPDATE_STATUS={_status_path()}",
        f"--setenv=XPANEL_UPDATE_LOG={_log_path()}",
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
        message = f"Не удалось запустить системную операцию обновления: {exc}"
        _atomic_json(
            _status_path(),
            {
                "state": "error",
                "version": expected_version,
                "ref": clean_ref,
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
            or "Не удалось запустить обновление"
        )
        _atomic_json(
            _status_path(),
            {
                "state": "error",
                "version": expected_version,
                "ref": clean_ref,
                "message": detail,
                "startedAt": started,
                "updatedAt": _utc_now(),
            },
        )
        raise XPanelError(detail)
    return {"unit": UPDATE_UNIT, "version": expected_version, "ref": clean_ref}
