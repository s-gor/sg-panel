#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

AGENT_VERSION = "0.5.0"
WORKER_VERSION = "0.5.0"
CONFIG_PATH = Path(os.environ.get("SG_NODE_CONFIG", "/etc/sg-node/agent.json"))
DEFAULT_INTERVAL = 30
JOBS_DIR = Path("/var/lib/sg-node/jobs")
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")


def load_config() -> dict[str, Any]:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"не удалось прочитать {CONFIG_PATH}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("конфигурация агента должна быть JSON-объектом")
    panel_url = str(data.get("panel_url") or "").strip().rstrip("/")
    if not panel_url.startswith(("https://", "http://")):
        raise RuntimeError("panel_url должен начинаться с https:// или http://")
    data["panel_url"] = panel_url
    return data


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(CONFIG_PATH)


def request_json(
    url: str,
    payload: dict[str, Any],
    *,
    token: str = "",
    timeout: int = 20,
) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"SG-Node/{AGENT_VERSION}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(body).get("error") or body
        except json.JSONDecodeError:
            detail = body
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"панель недоступна: {exc.reason}") from exc
    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("панель вернула некорректный JSON") from exc
    if not isinstance(result, dict):
        raise RuntimeError("панель вернула неожиданный ответ")
    if result.get("ok") is False:
        raise RuntimeError(str(result.get("error") or "операция отклонена"))
    return result


def command_version(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    output = (result.stdout or result.stderr or "").strip().splitlines()
    return output[0][:120] if output else ""


def service_state(unit: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    state = (result.stdout or result.stderr or "").strip().splitlines()
    return state[0][:32] if state else "unknown"


def read_os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values.get("NAME") or platform.system(), values.get("VERSION") or platform.release()


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def aws_public_ipv4() -> str:
    """Return the EC2 public IPv4 through IMDSv2 without using proxies."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token_request = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        data=b"",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        method="PUT",
    )
    try:
        with opener.open(token_request, timeout=1.5) as response:
            token = response.read().decode("ascii", "ignore").strip()
        if not token:
            return ""
        address_request = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with opener.open(address_request, timeout=1.5) as response:
            address = response.read().decode("ascii", "ignore").strip()
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        return ""
    return address if _is_public_ip(address) else ""


def public_address() -> str:
    configured = os.environ.get("SG_NODE_PUBLIC_ADDRESS", "").strip()
    if configured:
        return configured[:255]

    address = aws_public_ipv4()
    if address:
        return address

    hostname = socket.getfqdn() or socket.gethostname()
    try:
        resolved = socket.gethostbyname(hostname)
    except OSError:
        resolved = ""
    if resolved and _is_public_ip(resolved):
        return resolved
    return ""


def cpu_percent() -> float | None:
    def snapshot() -> tuple[int, int] | None:
        try:
            fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
            values = [int(value) for value in fields]
        except (OSError, ValueError, IndexError):
            return None
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return sum(values), idle

    first = snapshot()
    if first is None:
        return None
    time.sleep(0.15)
    second = snapshot()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 1)


def memory_percent() -> float | None:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    if total <= 0:
        return None
    return round(max(0.0, min(100.0, (total - available) * 100 / total)), 1)


def disk_percent() -> float | None:
    try:
        usage = shutil.disk_usage("/")
    except OSError:
        return None
    if usage.total <= 0:
        return None
    return round(usage.used * 100 / usage.total, 1)


def agent_id() -> str:
    machine_id = ""
    try:
        machine_id = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    base = machine_id or f"{socket.gethostname()}-{uuid.getnode()}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"sg-node:{base}"))


def inspect_xray_config() -> tuple[str, int | None]:
    try:
        document = json.loads(XRAY_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "", None
    inbounds = document.get("inbounds") if isinstance(document, dict) else None
    if not isinstance(inbounds, list) or not inbounds:
        return "", 0
    profiles: set[str] = set()
    clients: set[str] = set()
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol") or "").lower()
        stream = inbound.get("streamSettings")
        network = str(stream.get("network") or "").lower() if isinstance(stream, dict) else ""
        security = str(stream.get("security") or "").lower() if isinstance(stream, dict) else ""
        if protocol == "vless" and security == "reality":
            profiles.add("VLESS REALITY")
        elif protocol == "vless" and network == "xhttp":
            profiles.add("VLESS XHTTP")
        elif protocol == "hysteria":
            profiles.add("Hysteria 2")
        settings = inbound.get("settings")
        if isinstance(settings, dict):
            values = settings.get("clients") if isinstance(settings.get("clients"), list) else settings.get("users")
            if isinstance(values, list):
                for value in values:
                    if isinstance(value, dict):
                        identity = str(value.get("email") or value.get("id") or value.get("auth") or "").strip()
                        if identity:
                            clients.add(identity)
    return " + ".join(sorted(profiles)), len(clients)


def collect_metadata(last_error: str = "") -> dict[str, Any]:
    os_name, os_version = read_os_release()
    try:
        load1 = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        load1 = 0.0
    inbound_profile, client_count = inspect_xray_config()
    return {
        "public_address": public_address(),
        "platform": os_name,
        "platform_version": os_version,
        "architecture": platform.machine(),
        "agent_version": AGENT_VERSION,
        "agent_state": service_state("sg-node-agent.service"),
        "worker_version": WORKER_VERSION,
        "worker_state": service_state("sg-node-worker.service"),
        "xray_version": command_version(["/usr/local/bin/xray", "version"])
        or command_version(["xray", "version"]),
        "xray_state": service_state("xray.service"),
        "nginx_version": command_version(["nginx", "-v"]),
        "nginx_state": service_state("nginx.service"),
        "inbound_profile": inbound_profile,
        "client_count": client_count,
        "cpu_percent": cpu_percent(),
        "memory_percent": memory_percent(),
        "disk_percent": disk_percent(),
        "load1": load1,
        "last_error": last_error[:500],
    }


def ensure_registered(config: dict[str, Any]) -> dict[str, Any]:
    if config.get("agent_token"):
        return config
    enrollment_token = str(config.get("enrollment_token") or "").strip()
    if not enrollment_token:
        raise RuntimeError("нет enrollment_token для первой регистрации")
    response = request_json(
        config["panel_url"] + "/api/node/v1/register",
        {
            "enrollment_token": enrollment_token,
            "agent_id": agent_id(),
            "metadata": collect_metadata(),
        },
    )
    permanent = str(response.get("agent_token") or "").strip()
    if not permanent:
        raise RuntimeError("панель не вернула постоянный токен агента")
    config["agent_token"] = permanent
    config.pop("enrollment_token", None)
    config["node_id"] = response.get("node", {}).get("id")
    config["heartbeat_interval"] = int(response.get("heartbeat_interval") or DEFAULT_INTERVAL)
    save_config(config)
    print(f"SG-Node зарегистрирован: node_id={config.get('node_id')}", flush=True)
    return config


def execute_job(config: dict[str, Any], job: dict[str, Any]) -> None:
    job_id = int(job.get("id") or 0)
    if job_id <= 0:
        raise RuntimeError("панель вернула некорректный job id")
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    pending = JOBS_DIR / f"{job_id}.pending.json"
    result_path = JOBS_DIR / f"{job_id}.result.json"
    result_path.unlink(missing_ok=True)
    temporary = JOBS_DIR / f".{job_id}.pending.tmp"
    temporary.write_text(json.dumps(job, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(pending)

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if result_path.exists():
            try:
                response = json.loads(result_path.read_text(encoding="utf-8"))
            finally:
                result_path.unlink(missing_ok=True)
            if not isinstance(response, dict):
                raise RuntimeError("worker вернул некорректный результат")
            request_json(
                config["panel_url"] + f"/api/node/v1/jobs/{job_id}/complete",
                {
                    "ok": bool(response.get("ok")),
                    "result": response.get("result") if isinstance(response.get("result"), dict) else {},
                },
                token=str(config["agent_token"]),
            )
            return
        time.sleep(0.5)
    raise RuntimeError("worker не завершил задание за 120 секунд")


def run_forever() -> None:
    config = ensure_registered(load_config())
    interval = max(15, min(300, int(config.get("heartbeat_interval") or DEFAULT_INTERVAL)))
    next_heartbeat = 0.0
    last_error = ""
    while True:
        now = time.monotonic()
        if now >= next_heartbeat:
            try:
                response = request_json(
                    config["panel_url"] + "/api/node/v1/heartbeat",
                    collect_metadata(last_error),
                    token=str(config["agent_token"]),
                )
                interval = max(15, min(300, int(response.get("heartbeat_interval") or interval)))
                last_error = ""
            except Exception as exc:
                last_error = str(exc)
                print(f"heartbeat failed: {last_error}", file=sys.stderr, flush=True)
            next_heartbeat = time.monotonic() + interval

        try:
            response = request_json(
                config["panel_url"] + "/api/node/v1/jobs/next",
                {},
                token=str(config["agent_token"]),
            )
            job = response.get("job")
            if isinstance(job, dict):
                execute_job(config, job)
                next_heartbeat = 0.0
        except Exception as exc:
            last_error = str(exc)
            print(f"job poll failed: {last_error}", file=sys.stderr, flush=True)
        time.sleep(3)


def main() -> int:
    try:
        run_forever()
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"SG-Node startup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
