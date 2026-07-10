from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlencode

from flask import (
    Flask,
    Response,
    jsonify,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from . import __version__
from .db import connect, db_path, init_db, use_db_path
from .update_manager import (
    check_for_updates,
    get_update_status,
    start_panel_update,
    update_in_progress,
)
from .xray_update_manager import (
    check_xray_updates,
    get_xray_update_status,
    start_xray_update,
    xray_update_in_progress,
)
from .node_manager import (
    ROLE_LABELS as NODE_ROLE_LABELS,
    create_enrollment_token,
    create_node,
    create_node_job,
    delete_node,
    find_node,
    heartbeat_node,
    has_active_enrollment,
    list_node_events,
    list_node_jobs,
    list_node_deployments,
    list_user_deployments,
    latest_node_config,
    create_user_deletion_request,
    user_deletion_request,
    finish_user_deletion_request,
    list_nodes,
    claim_node_job,
    complete_node_job,
    network_summary,
    register_node,
    restore_node,
    revoke_node,
    update_node,
)
from .security import (
    create_admin_session,
    get_security_settings,
    ip_is_allowed,
    list_admin_sessions,
    list_audit_log,
    login_block_status,
    purge_security_history,
    recent_login_attempts,
    record_login_attempt,
    revoke_admin_session,
    revoke_all_admin_sessions,
    security_overview,
    update_security_settings,
    update_panel_exposure_settings,
    validate_admin_session,
    write_audit,
)
from .service import (
    XPanelError,
    add_routing_rule,
    add_routing_rule_json,
    add_geo_policy,
    add_dns_host,
    add_dns_server,
    add_vless_outbound,
    add_vless_outbound_json,
    add_user,
    apply_config,
    apply_geofiles_source,
    config_json_document,
    dns_json_document,
    inbound_json_document,
    backup_file,
    calculate_certificate_pin,
    create_backup,
    create_warp,
    configure_warp_routing,
    delete_backup,
    delete_warp,
    delete_dns_host,
    delete_dns_server,
    delete_routing_rule,
    delete_outbound,
    delete_user,
    diagnostic_report,
    find_routing_rule,
    find_dns_host,
    find_dns_server,
    find_outbound,
    find_user,
    find_subscription_user,
    format_bytes,
    generate_reality_keys,
    generate_ech_pair,
    get_diagnostics,
    get_geodata_status,
    get_geofiles_overview,
    get_dns_settings,
    get_routing_settings,
    get_server,
    get_inbound_recommendations,
    get_hysteria_studio_overview,
    get_hysteria_diagnostics,
    get_transport_expert_overview,
    get_status,
    get_subscription_settings,
    get_user_stats,
    get_user_traffic_history,
    get_warp_overview,
    get_cascade_overview,
    get_instance_name,
    get_instance_address,
    get_instance_identity,
    update_instance_name,
    ensure_cascade_service_access,
    remove_cascade,
    import_cascade_link,
    select_cascade_outbound,
    set_cascade_enabled,
    test_cascade,
    list_backups,
    list_dns_hosts,
    list_dns_servers,
    list_outbounds,
    list_outbound_tags,
    list_balancer_tags,
    list_routing_rules,
    list_users,
    list_hysteria_inbounds,
    list_xhttp_inbounds,
    list_reality_inbounds,
    load_client_ca_pem,
    make_link,
    managed_client_export,
    managed_client_export_v2,
    make_links,
    make_saved_links,
    outbound_json_document,
    parse_vless_share_link,
    make_subscription_url,
    preview_dns_json,
    warp_json_document,
    routing_json_document,
    rule_json_document,
    regenerate_user_uuid,
    regenerate_subscription_token,
    reset_stats,
    record_subscription_access,
    restart_xray,
    restore_backup,
    verify_backup,
    set_routing_rule_enabled,
    set_dns_host_enabled,
    set_dns_server_enabled,
    set_outbound_enabled,
    set_user_enabled,
    set_user_subscription_enabled,
    set_warp_enabled,
    update_routing_rule,
    update_routing_rule_json,
    update_config_json_document,
    update_dns_json_document,
    update_inbound_json_document,
    update_routing_json_document,
    update_dns_host,
    update_dns_server,
    update_dns_settings,
    update_vless_outbound,
    update_vless_outbound_json,
    update_warp_json_document,
    update_routing_settings,
    update_server_settings,
    update_transport_expert_settings,
    update_user,
    update_users_json_document,
    update_subscription_settings,
    user_is_expired,
    user_expiring_soon,
    users_json_document,
    subscription_is_available,
    validate_generated_config,
    validate_geofiles_source,
    test_dns_resolution,
    test_outbound_tcp,
    test_warp,
)


PANEL_ACCESS_STATE_FILE = Path(os.environ.get(
    "XPANEL_ACCESS_STATE_FILE", "/etc/xpanel-mvp/panel-access.env"
))
PANEL_ACCESS_NGINX_CONF = Path(os.environ.get(
    "XPANEL_ACCESS_NGINX_CONF", "/etc/nginx/sites-available/sg-panel"
))
PANEL_ACCESS_JOB_DIR = Path(os.environ.get(
    "XPANEL_ACCESS_JOB_DIR", "/opt/xpanel-mvp/data/panel-access-jobs"
))
PANEL_ACCESS_SCRIPT = Path(os.environ.get(
    "XPANEL_ACCESS_SCRIPT", "/opt/xpanel-mvp/deploy/configure-panel-access.sh"
))
NODE_FULL_INSTALLER = Path(__file__).resolve().parent.parent / "deploy" / "install-sg-node.sh"
NODE_CONNECT_INSTALLER = Path(__file__).resolve().parent.parent / "deploy" / "connect-node.sh"
NODE_AGENT_INSTALLER = Path(__file__).resolve().parent.parent / "deploy" / "install-node-agent.sh"
NODE_RUNTIME_INSTALLER = Path(__file__).resolve().parent.parent / "deploy" / "install-node-runtime.sh"
NODE_AGENT_SOURCE = Path(__file__).resolve().parent.parent / "node_agent" / "sg_node_agent.py"
NODE_WORKER_SOURCE = Path(__file__).resolve().parent.parent / "node_agent" / "sg_node_worker.py"
NODE_AGENT_UNINSTALLER = Path(__file__).resolve().parent.parent / "deploy" / "uninstall-node-agent.sh"

CLOUDFLARE_HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
PANEL_CLOUDFLARE_PORTS = CLOUDFLARE_HTTPS_PORTS - {443}



def _friendly_geodata_error(detail: str) -> str:
    lowered = detail.lower()
    if not any(marker in lowered for marker in ("not found", "failed to load", "code not found")):
        return detail
    for kind, label in (("geosite", "Geosite"), ("geoip", "GeoIP")):
        if kind not in lowered:
            continue
        category = "указанная категория"
        patterns = (
            rf"(?i)code not found in {kind}\.dat[: ]+([a-z0-9._@-]+)",
            rf"(?i){kind}(?:\.dat)?[^\n]*?list not found:\s*([a-z0-9._@-]+)",
            rf"(?i)failed to load {kind}:\s*([a-z0-9._@-]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, detail)
            if match:
                category = match.group(1)
                break
        return (
            f"Категория {label} «{category}» отсутствует в текущем {kind}.dat. "
            "Выберите совместимый источник в Routing → GeoFiles или измените условие."
        )
    return detail

def _service_is_active(name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "active"


def _panel_exposure_state(settings: sqlite3.Row, panel_access: dict[str, object]) -> dict[str, object]:
    mode = str(settings["panel_exposure_mode"] or "direct")
    hostname = str(settings["cloudflare_hostname"] or "")
    port = int(panel_access.get("port") or 0)
    https_ready = panel_access.get("mode") == "https"
    port_supported = port in CLOUDFLARE_HTTPS_PORTS
    edge_observed = bool(
        request.headers.get("CF-Ray") and request.headers.get("CF-Connecting-IP")
    )
    tunnel_active = _service_is_active("cloudflared")
    origin_lockdown = bool(settings["cloudflare_origin_lockdown"])
    access_enabled = bool(settings["cloudflare_access_enabled"])

    labels = {
        "direct": "Direct through Nginx",
        "cloudflare_proxy": "Cloudflare Proxy",
        "cloudflare_tunnel": "Cloudflare Tunnel + Access",
    }
    if mode == "cloudflare_proxy":
        ready = https_ready and port_supported and origin_lockdown and edge_observed
        configured = https_ready and port_supported and bool(hostname)
        status = "ready" if ready else ("configured" if configured else "attention")
        message = (
            "Cloudflare edge обнаружен, origin lockdown подтверждён."
            if ready else
            "Origin подготовлен; проверьте proxied DNS, Security Group/firewall и реальный запрос через Cloudflare."
            if configured else
            "Для Proxy нужен HTTPS hostname и поддерживаемый Cloudflare HTTPS-порт."
        )
    elif mode == "cloudflare_tunnel":
        ready = tunnel_active and access_enabled and bool(hostname)
        status = "ready" if ready else ("configured" if hostname else "attention")
        message = (
            "cloudflared работает, Cloudflare Access отмечен как включённый."
            if ready else
            "Укажите hostname, установите cloudflared и защитите приложение политикой Cloudflare Access."
        )
    else:
        status = "ready"
        message = "Браузер подключается напрямую к Nginx на сервере."

    return {
        "mode": mode,
        "label": labels.get(mode, labels["direct"]),
        "status": status,
        "message": message,
        "hostname": hostname,
        "origin_lockdown": origin_lockdown,
        "access_enabled": access_enabled,
        "tunnel_name": str(settings["cloudflare_tunnel_name"] or ""),
        "https_ready": https_ready,
        "port": port,
        "port_supported": port_supported,
        "supported_ports": ", ".join(str(item) for item in sorted(CLOUDFLARE_HTTPS_PORTS)),
        "edge_observed": edge_observed,
        "cloudflared_active": tunnel_active,
        "client_ip_header": "CF-Connecting-IP" if mode != "direct" else "X-Forwarded-For / remote_addr",
    }


def _read_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _panel_access_state(fallback_host: str = "") -> dict[str, object]:
    values = _read_key_value_file(PANEL_ACCESS_STATE_FILE)
    mode = values.get("PANEL_ACCESS_MODE", "").lower()
    host = values.get("PANEL_PUBLIC_HOST", "") or values.get("PANEL_DOMAIN", "")
    port_text = values.get("PANEL_PUBLIC_PORT", "")

    nginx_text = ""
    if PANEL_ACCESS_NGINX_CONF.exists():
        try:
            nginx_text = PANEL_ACCESS_NGINX_CONF.read_text(encoding="utf-8")
        except OSError:
            nginx_text = ""

    listeners = re.findall(
        r"(?m)^\s*listen\s+(?:\[::\]:)?(\d+)([^;]*);",
        nginx_text,
    )
    ssl_ports = [port for port, options in listeners if re.search(r"\bssl\b", options)]
    public_ports = [port for port, _ in listeners if port != "80"]
    nginx_hosts = re.findall(r"(?m)^\s*server_name\s+([^;\s]+)", nginx_text)
    nginx_host = next((item for item in nginx_hosts if item != "_"), "")

    # The live Nginx listener is authoritative. A stale state file must never
    # make an HTTPS installation advertise the previous http://IP address.
    if ssl_ports:
        mode = "https"
        port_text = ssl_ports[0]
        if nginx_host:
            host = nginx_host
    elif public_ports:
        mode = "http"
        port_text = public_ports[0]
        host = nginx_host or fallback_host or host
    elif mode not in {"http", "https"}:
        mode = "http"

    try:
        port = int(port_text)
    except (TypeError, ValueError):
        port = 61443
    host = host or fallback_host or "SERVER_IP"
    scheme = "https" if mode == "https" else "http"
    return {
        "mode": mode,
        "host": host,
        "port": port,
        "url": f"{scheme}://{host}:{port}",
        "updated_at": values.get("UPDATED_AT", ""),
    }


def _validate_panel_access_values(mode: str, host: str, port_text: str) -> tuple[str, str, int]:
    mode = (mode or "").strip().lower()
    host = (host or "").strip()
    if mode not in {"http", "https"}:
        raise ValueError("Выберите HTTP или HTTPS + Let's Encrypt")
    if not host or not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise ValueError("Укажите корректный IP, hostname или домен")
    if mode == "https" and not re.fullmatch(
        r"([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
        host,
    ):
        raise ValueError("Для HTTPS требуется полное доменное имя")
    try:
        port = int(port_text)
    except (TypeError, ValueError) as exc:
        raise ValueError("Порт панели должен быть числом") from exc
    if not (49152 <= port <= 65535 or port in PANEL_CLOUDFLARE_PORTS):
        raise ValueError(
            "Порт панели должен быть 49152–65535 либо одним из HTTPS-портов Cloudflare: "
            + ", ".join(str(item) for item in sorted(PANEL_CLOUDFLARE_PORTS))
        )
    if port in {22, 80, 443, 8080}:
        raise ValueError(f"Порт {port} зарезервирован для другого назначения")
    return mode, host, port


def _panel_access_job_paths(job_id: str) -> dict[str, Path]:
    return {
        "wrapper": PANEL_ACCESS_JOB_DIR / f"{job_id}.sh",
        "log": PANEL_ACCESS_JOB_DIR / f"{job_id}.log",
        "status": PANEL_ACCESS_JOB_DIR / f"{job_id}.status",
        "meta": PANEL_ACCESS_JOB_DIR / f"{job_id}.json",
    }


def _read_panel_access_job(job_id: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9]{14}-[0-9a-f]{12}", job_id):
        raise FileNotFoundError(job_id)
    paths = _panel_access_job_paths(job_id)
    if not paths["meta"].exists():
        raise FileNotFoundError(job_id)
    meta = json.loads(paths["meta"].read_text(encoding="utf-8"))
    status = paths["status"].read_text(encoding="utf-8").strip() if paths["status"].exists() else "queued"
    log = paths["log"].read_text(encoding="utf-8", errors="replace") if paths["log"].exists() else ""
    return {**meta, "job_id": job_id, "status": status, "log": log[-200000:]}


def _expiry_for_form(value: str | None) -> str:
    if not value:
        return ""
    return str(value)[:16]


def _user_expiry_from_form() -> str:
    mode = request.form.get("expiration_mode", "unlimited").strip().lower()
    if mode == "unlimited":
        return ""
    if mode == "date":
        value = request.form.get("expiry_at", "").strip()
        if not value:
            raise ValueError("Укажите дату и время окончания доступа")
        return value
    if mode == "period":
        try:
            days = int(request.form.get("duration_days", "30"))
        except ValueError as exc:
            raise ValueError("Некорректный срок действия") from exc
        if days not in {1, 7, 30, 90, 365}:
            raise ValueError("Период должен быть 1, 7, 30, 90 или 365 дней")
        return (datetime.now(timezone.utc) + timedelta(days=days)).replace(
            second=0, microsecond=0
        ).isoformat()
    raise ValueError("Неизвестный режим срока действия")


def _activity_text(value: str | None, *, online: bool | None = None) -> str:
    if online is True:
        return "Сейчас онлайн"
    if not value:
        return "Ещё не подключался"
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    seconds = max(0, int((datetime.now(timezone.utc) - moment.astimezone(timezone.utc)).total_seconds()))
    if seconds < 60:
        return "Меньше минуты назад"
    if seconds < 3600:
        return f"{seconds // 60} мин. назад"
    if seconds < 86400:
        return f"{seconds // 3600} ч. назад"
    if seconds < 7 * 86400:
        return f"{seconds // 86400} дн. назад"
    return moment.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")


INBOUND_PROFILE_LABELS = {
    "raw_reality": "VLESS REALITY",
    "xhttp_tls": "VLESS XHTTP-TLS",
    "xhttp_reality": "VLESS XHTTP-REALITY",
    "grpc_tls": "VLESS gRPC + TLS",
    "hysteria2_tls": "Hysteria 2",
    "xhttp_hysteria_tls": "XHTTP-TLS + Hysteria 2",
}


def _write_env_values(env_file: Path, updates: dict[str, str]) -> None:
    env_file.parent.mkdir(parents=True, exist_ok=True)
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    output: list[str] = []
    pending = dict(updates)
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in pending:
            output.append(f"{key}={pending.pop(key)}")
        else:
            output.append(line)
    for key, value in pending.items():
        output.append(f"{key}={value}")
    env_file.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(env_file, 0o600)


def _read_env_values(env_file: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_file.exists():
        return values
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _write_password_hash(env_file: Path, password_hash: str, *, rotate_secret: bool = False) -> str | None:
    updates = {"XPANEL_PASSWORD_HASH": password_hash}
    new_secret = None
    if rotate_secret:
        new_secret = secrets.token_urlsafe(48)
        updates["XPANEL_SECRET_KEY"] = new_secret
    _write_env_values(env_file, updates)
    return new_secret


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("XPANEL_SECRET_KEY", ""),
        PASSWORD_HASH=os.environ.get("XPANEL_PASSWORD_HASH", ""),
        ENV_FILE=os.environ.get("XPANEL_ENV_FILE", "/etc/xpanel-mvp/web.env"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("XPANEL_SECURE_COOKIES", "0") == "1",
        SESSION_COOKIE_NAME="ser_g_panel_session",
        MAX_CONTENT_LENGTH=512 * 1024,
        PANEL_BIND_ADDRESS=os.environ.get("XPANEL_BIND_ADDRESS", "0.0.0.0"),
        PANEL_PORT=int(os.environ.get("XPANEL_PORT", "8080")),
        TRUST_PROXY_HEADERS_ENV=os.environ.get("XPANEL_TRUST_PROXY_HEADERS", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("XPANEL_SECRET_KEY не задан")
    if not app.config["PASSWORD_HASH"]:
        raise RuntimeError("XPANEL_PASSWORD_HASH не задан")

    @app.context_processor
    def inject_globals() -> dict:
        fallback_host = request.host.split(":", 1)[0] if request else ""
        system_ok = False
        try:
            server = get_server()
            state = subprocess.run(
                ["systemctl", "is-active", str(server["xray_service"])],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            system_ok = state.returncode == 0 and state.stdout.strip() == "active"
        except Exception:
            system_ok = False
        try:
            panel_instance_name = get_instance_name()
            panel_instance_address = get_instance_address()
            panel_instance_identity = get_instance_identity()
        except Exception:
            panel_instance_name = "SG-Panel"
            panel_instance_address = ""
            panel_instance_identity = panel_instance_name
        return {
            "xpanel_version": __version__,
            "format_bytes": format_bytes,
            "user_is_expired": user_is_expired,
            "expiry_for_form": _expiry_for_form,
            "panel_access_global": _panel_access_state(fallback_host),
            "global_system_ok": system_ok,
            "instance_name": panel_instance_name,
            "instance_address": panel_instance_address,
            "instance_identity": panel_instance_identity,
        }

    def client_ip() -> str:
        remote = (request.remote_addr or "unknown").strip()
        try:
            settings = get_security_settings()
        except Exception:
            return remote
        exposure_mode = str(settings["panel_exposure_mode"] or "direct")
        cf_connecting_ip = request.headers.get("CF-Connecting-IP", "").strip()
        trust_cloudflare = (
            exposure_mode == "cloudflare_proxy" and bool(settings["cloudflare_origin_lockdown"])
        ) or (
            exposure_mode == "cloudflare_tunnel" and bool(settings["cloudflare_access_enabled"])
        )
        if (
            trust_cloudflare
            and remote in {"127.0.0.1", "::1"}
            and cf_connecting_ip
            and request.headers.get("CF-Ray", "").strip()
        ):
            return cf_connecting_ip

        forwarded = request.headers.get("X-Forwarded-For", "")
        if (
            (settings["trust_proxy_headers"] or app.config["TRUST_PROXY_HEADERS_ENV"])
            and remote in {"127.0.0.1", "::1"}
            and forwarded
        ):
            candidate = forwarded.split(",", 1)[0].strip()
            if candidate:
                return candidate
        return remote

    def logged_in() -> bool:
        if not session.get("authenticated"):
            return False
        record = validate_admin_session(session.get("admin_session_id"))
        if record is None:
            session.clear()
            return False
        g.admin_session = record
        return True

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not logged_in():
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    def apply_saved_change(message: str) -> dict[str, object]:
        """Apply a saved GUI change immediately and keep the user on the same page."""
        label = message.rstrip(" .")
        try:
            result = apply_config()
        except (XPanelError, ValueError, PermissionError, FileNotFoundError, OSError) as exc:
            raise XPanelError(
                f"{label} сохранено в панели, но не применено к Xray. "
                f"Предыдущий рабочий config.json восстановлен. Причина: {exc}"
            ) from exc
        flash(f"{label}. Настройки сохранены и применены. Xray работает.", "success")
        return result

    validation_serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"], salt="sg-panel-config-validation-v1"
    )

    def _draft_payload() -> dict[str, object]:
        excluded = {"csrf_token", "validation_token", "action"}
        payload: dict[str, object] = {}
        for key, values in request.form.lists():
            if key in excluded:
                continue
            payload[key] = values if len(values) != 1 else values[0]
        return payload

    def _payload_digest(payload: dict[str, object]) -> str:
        encoded = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _config_revision() -> str:
        init_db()
        queries = {
            "server_settings": "SELECT * FROM server_settings ORDER BY id",
            "hysteria_inbounds": "SELECT * FROM hysteria_inbounds ORDER BY id",
            "hysteria_user_auth": (
                "SELECT inbound_id,user_id,auth,updated_at "
                "FROM hysteria_user_auth ORDER BY inbound_id,user_id"
            ),
            "users": (
                "SELECT id,name,uuid,enabled,comment,expiry_at,subscription_enabled "
                "FROM users ORDER BY id"
            ),
            "config_settings": "SELECT * FROM config_settings ORDER BY id",
            "routing_settings": "SELECT * FROM routing_settings ORDER BY id",
            "routing_rules": "SELECT * FROM routing_rules ORDER BY id",
            "dns_settings": "SELECT * FROM dns_settings ORDER BY id",
            "dns_servers": "SELECT * FROM dns_servers ORDER BY id",
            "dns_hosts": "SELECT * FROM dns_hosts ORDER BY id",
            "outbounds": "SELECT * FROM outbounds ORDER BY id",
            "warp_settings": (
                "SELECT id,enabled,outbound_json,route_mode,selected_domains,selected_ips "
                "FROM warp_settings ORDER BY id"
            ),
            "transport_expert_settings": (
                "SELECT * FROM transport_expert_settings ORDER BY id"
            ),
            "geofiles_settings": (
                "SELECT id,source,geoip_url,geosite_url,geoip_local_path,"
                "geosite_local_path,active_source,active_geoip_sha256,"
                "active_geosite_sha256,last_check_state,last_checked_at,"
                "last_applied_at FROM geofiles_settings ORDER BY id"
            ),
        }
        snapshot: dict[str, object] = {}
        with connect() as con:
            for name, query in queries.items():
                snapshot[name] = [dict(row) for row in con.execute(query).fetchall()]
        encoded = json.dumps(
            snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _clone_database(target: Path) -> None:
        init_db()
        source = sqlite3.connect(db_path())
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

    def _validate_candidate_change(mutator) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="sg-panel-validate-") as tmpdir:
            candidate = Path(tmpdir) / "panel.db"
            _clone_database(candidate)
            with use_db_path(candidate):
                result = mutator()
                validation = validate_generated_config()
                if not validation["ok"]:
                    detail = str(validation.get("detail") or "неизвестная ошибка")
                    raise XPanelError("xray run -test завершился с ошибкой:\n" + _friendly_geodata_error(detail))
                return {
                    "result": result,
                    "detail": str(validation.get("detail") or "xray run -test: OK"),
                    "users": int(validation.get("users", 0)),
                }

    def _issue_validation_token(
        scope: str, payload: dict[str, object], *, claims: dict[str, object] | None = None
    ) -> str:
        nonce = secrets.token_urlsafe(18)
        grants = list(session.get("config_validation_grants", []))
        grants.append(nonce)
        session["config_validation_grants"] = grants[-10:]
        session.modified = True
        return validation_serializer.dumps(
            {
                "scope": scope,
                "payload": _payload_digest(payload),
                "revision": _config_revision(),
                "nonce": nonce,
                "claims": claims or {},
            }
        )

    def _require_validation_token(
        scope: str, payload: dict[str, object]
    ) -> dict[str, object]:
        token = request.form.get("validation_token", "")
        if not token:
            raise ValueError("Сначала нажмите «Проверить конфигурацию»")
        try:
            data = validation_serializer.loads(token, max_age=15 * 60)
        except SignatureExpired as exc:
            raise ValueError("Проверка устарела. Проверьте конфигурацию ещё раз") from exc
        except BadSignature as exc:
            raise ValueError("Результат проверки недействителен. Выполните проверку снова") from exc
        if not isinstance(data, dict) or data.get("scope") != scope:
            raise ValueError("Результат проверки относится к другому разделу")
        if data.get("payload") != _payload_digest(payload):
            raise ValueError("Данные изменились после проверки. Выполните проверку снова")
        if data.get("revision") != _config_revision():
            raise ValueError(
                "Конфигурация панели изменилась после проверки. Выполните проверку снова"
            )
        nonce = str(data.get("nonce", ""))
        grants = list(session.get("config_validation_grants", []))
        if not nonce or nonce not in grants:
            raise ValueError(
                "Результат проверки уже использован или больше не действует"
            )
        grants.remove(nonce)
        session["config_validation_grants"] = grants
        session.modified = True
        return data

    def _validation_response(
        scope: str, mutator, *, message: str, claims_builder=None
    ) -> Response:
        payload = _draft_payload()
        try:
            validation = _validate_candidate_change(mutator)
            claims = (
                claims_builder(validation["result"]) if claims_builder is not None else {}
            )
            token = _issue_validation_token(scope, payload, claims=claims)
            body = {
                "ok": True,
                "token": token,
                "message": message,
                "detail": validation["detail"],
                "users": validation["users"],
            }
            status = 200
        except (
            ValueError, XPanelError, PermissionError, FileNotFoundError, OSError,
            sqlite3.Error,
        ) as exc:
            body = {"ok": False, "message": str(exc)}
            status = 400
        return Response(
            json.dumps(body, ensure_ascii=False),
            status=status,
            content_type="application/json; charset=utf-8",
        )

    def _preflight_change(mutator) -> None:
        try:
            _validate_candidate_change(mutator)
        except (
            ValueError, XPanelError, PermissionError, FileNotFoundError, OSError,
            sqlite3.Error,
        ) as exc:
            if isinstance(exc, XPanelError):
                raise
            raise XPanelError(
                f"Предварительная проверка не пройдена: {exc}"
            ) from exc

    def _is_validation_action() -> bool:
        return request.form.get("action", "") == "validate"

    @app.before_request
    def protect_requests():
        g.client_ip = client_ip()
        endpoint = request.endpoint or ""
        public_node_endpoints = {
            "health",
            "node_agent_installer",
            "node_agent_source",
            "node_worker_source",
            "node_agent_uninstaller",
            "node_api_register",
            "node_api_heartbeat",
            "node_api_job_next",
            "node_api_job_complete",
        }
        if endpoint == "static" or endpoint in public_node_endpoints:
            return None
        settings = get_security_settings()

        if endpoint == "subscription_public":
            if (
                settings["subscription_allowlist_enabled"]
                and not ip_is_allowed(
                    g.client_ip, settings["subscription_allowed_networks"]
                )
            ):
                return Response(
                    "Not found\n", status=404,
                    content_type="text/plain; charset=utf-8",
                )
            return None

        if (
            settings["allowlist_enabled"]
            and not ip_is_allowed(g.client_ip, settings["allowed_networks"])
        ):
            write_audit(
                "access_denied", detail=request.path, ip_address=g.client_ip,
                user_agent=request.headers.get("User-Agent", ""), success=False,
            )
            abort(403, description="Адрес не входит в IP allowlist панели")

        if request.method == "POST" and endpoint != "login_post":
            expected = session.get("csrf_token", "")
            received = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, received):
                abort(400, description="Неверный CSRF-токен")
        return None

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'self'",
        )
        if request.endpoint != "static":
            response.headers.setdefault("Cache-Control", "no-store, max-age=0")

        excluded = {"login_post", "logout", "subscription_public"}
        if (
            request.method == "POST"
            and request.endpoint
            and request.endpoint not in excluded
        ):
            try:
                write_audit(
                    "admin_action", detail=request.endpoint,
                    ip_address=getattr(g, "client_ip", request.remote_addr or ""),
                    user_agent=request.headers.get("User-Agent", ""),
                    success=response.status_code < 400,
                )
            except Exception:
                pass
        return response

    @app.get("/health")
    def health():
        if getattr(g, "client_ip", client_ip()) not in {"127.0.0.1", "::1"}:
            abort(404)
        return Response(
            json.dumps({"ok": True}, ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )

    @app.get("/login")
    def login():
        if logged_in():
            return redirect(url_for("dashboard"))
        block = login_block_status(getattr(g, "client_ip", client_ip()))
        return render_template("login.html", login_block=block)

    @app.post("/login")
    def login_post():
        ip = getattr(g, "client_ip", client_ip())
        user_agent = request.headers.get("User-Agent", "")
        block = login_block_status(ip)
        if block["blocked"]:
            minutes = max(1, (int(block["retry_after"]) + 59) // 60)
            write_audit(
                "login_blocked", detail=f"retry_after={block['retry_after']}",
                ip_address=ip, user_agent=user_agent, success=False,
            )
            response = render_template(
                "login.html", login_block=block,
                login_error=f"Слишком много попыток. Повторите через {minutes} мин.",
            ), 429
            return response

        password = request.form.get("password", "")
        if check_password_hash(app.config["PASSWORD_HASH"], password):
            record_login_attempt(ip, True, user_agent)
            admin_session_id = create_admin_session(ip, user_agent)
            session.clear()
            session.permanent = True
            session["authenticated"] = True
            session["admin_session_id"] = admin_session_id
            csrf_token()
            write_audit(
                "login_success", ip_address=ip, user_agent=user_agent, success=True
            )
            flash("Вход выполнен", "success")
            return redirect(url_for("dashboard"))

        record_login_attempt(ip, False, user_agent)
        block = login_block_status(ip)
        write_audit(
            "login_failed", detail=f"attempts={block['attempts']}",
            ip_address=ip, user_agent=user_agent, success=False,
        )
        if block["blocked"]:
            minutes = max(1, (int(block["retry_after"]) + 59) // 60)
            error = f"Слишком много попыток. Вход заблокирован на {minutes} мин."
            status = 429
        else:
            settings = get_security_settings()
            remaining = max(0, int(settings["max_login_attempts"]) - int(block["attempts"]))
            error = f"Неверный пароль. Осталось попыток: {remaining}."
            status = 401
        return render_template(
            "login.html", login_block=block, login_error=error
        ), status

    @app.post("/logout")
    @login_required
    def logout():
        session_id = session.get("admin_session_id")
        write_audit(
            "logout", ip_address=getattr(g, "client_ip", ""),
            user_agent=request.headers.get("User-Agent", ""), success=True,
        )
        if session_id:
            revoke_admin_session(session_id)
        session.clear()
        return redirect(url_for("login"))

    @app.post("/system/instance-name")
    @login_required
    def system_instance_name():
        try:
            value = request.form.get("instance_name", "")
            _preflight_change(lambda: update_instance_name(value))
            update_instance_name(value)
            apply_saved_change("Имя сервера обновлено")
            flash("Имя сервера сохранено и показывается во всей панели.", "success")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(request.form.get("next") or url_for("diagnostics_page", tab="status"))

    @app.get("/")
    @login_required
    def dashboard():
        try:
            users = list_users()
            stats = get_user_stats(include_online=False)
            return render_template(
                "dashboard.html",
                status=get_status(),
                server=get_server(),
                users=users[:5],
                stats=stats,
            )
        except Exception as exc:
            return render_template(
                "dashboard.html", error=str(exc), status=None, users=[], stats={}
            )

    @app.get("/users")
    @login_required
    def users_page():
        all_users = list_users()
        stats = get_user_stats(include_online=False)
        server = get_server()
        query = request.args.get("q", "").strip().casefold()
        status_filter = request.args.get("status", "all").strip().lower()
        sort_mode = request.args.get("sort", "created").strip().lower()

        enriched: list[dict[str, object]] = []
        for user in all_users:
            row = dict(user)
            item_stats = stats.get(int(user["id"]), {})
            expired = user_is_expired(user)
            expiring = user_expiring_soon(user)
            online = item_stats.get("online") is True
            row.update(
                {
                    "stats": item_stats,
                    "expired": expired,
                    "expiring_soon": expiring,
                    "effective_enabled": bool(user["enabled"]) and not expired,
                    "online": online,
                    "activity_text": _activity_text(
                        str(item_stats.get("last_seen_at") or ""),
                        online=item_stats.get("online") if isinstance(item_stats, dict) else None,
                    ),
                }
            )
            enriched.append(row)

        rows = enriched
        if query:
            rows = [
                row for row in rows
                if query in str(row.get("name", "")).casefold()
                or query in str(row.get("uuid", "")).casefold()
                or query in str(row.get("comment", "")).casefold()
            ]
        if status_filter == "active":
            rows = [row for row in rows if bool(row["effective_enabled"])]
        elif status_filter == "online":
            rows = [row for row in rows if bool(row["online"])]
        elif status_filter == "expiring":
            rows = [row for row in rows if bool(row["expiring_soon"])]
        elif status_filter == "expired":
            rows = [row for row in rows if bool(row["expired"])]
        elif status_filter == "disabled":
            rows = [row for row in rows if not bool(row["enabled"])]
        elif status_filter == "unlimited":
            rows = [row for row in rows if not row.get("expiry_at")]

        if sort_mode == "name":
            rows.sort(key=lambda row: str(row.get("name", "")).casefold())
        elif sort_mode == "activity":
            rows.sort(
                key=lambda row: str(row["stats"].get("last_seen_at") or ""),
                reverse=True,
            )
        elif sort_mode == "traffic":
            rows.sort(
                key=lambda row: int(row["stats"].get("lifetime_total") or 0),
                reverse=True,
            )
        elif sort_mode == "expiry":
            rows.sort(
                key=lambda row: (
                    not bool(row.get("expiry_at")),
                    str(row.get("expiry_at") or "9999"),
                    int(row.get("id", 0)),
                )
            )
        else:
            rows.sort(key=lambda row: int(row.get("id", 0)), reverse=True)

        selected = None
        selected_value = request.args.get("client", "").strip()
        if selected_value.isdigit():
            selected = next(
                (row for row in enriched if int(row["id"]) == int(selected_value)),
                None,
            )
        if selected is None and rows:
            selected = rows[0]

        summary = {
            "total": len(enriched),
            "active": sum(1 for row in enriched if bool(row["effective_enabled"])),
            "online": sum(1 for row in enriched if bool(row["online"])),
            "expiring": sum(1 for row in enriched if bool(row["expiring_soon"])),
            "expired": sum(1 for row in enriched if bool(row["expired"])),
            "disabled": sum(1 for row in enriched if not bool(row["enabled"])),
            "lifetime_uplink": sum(int(row["stats"].get("lifetime_uplink") or 0) for row in enriched),
            "lifetime_downlink": sum(int(row["stats"].get("lifetime_downlink") or 0) for row in enriched),
            "speed": sum(int(row["stats"].get("total_bps") or 0) for row in enriched),
        }
        summary["lifetime_total"] = int(summary["lifetime_uplink"]) + int(summary["lifetime_downlink"])
        errors = sorted(
            {
                str(row["stats"].get("error") or "")
                for row in enriched
                if str(row["stats"].get("error") or "")
            }
        )
        selected_history = (
            get_user_traffic_history(int(selected["id"]), days=14)
            if selected is not None
            else []
        )
        selected_deployments = (
            list_user_deployments(int(selected["id"]))
            if selected is not None
            else []
        )
        selected_deletion_request = (
            user_deletion_request(int(selected["id"]))
            if selected is not None
            else None
        )
        return render_template(
            "users.html",
            users=rows,
            all_users=enriched,
            selected_user=selected,
            selected_history=selected_history,
            selected_deployments=selected_deployments,
            selected_deletion_request=selected_deletion_request,
            client_stats=summary,
            query=request.args.get("q", "").strip(),
            status_filter=status_filter,
            sort_mode=sort_mode,
            server=server,
            profile_label=INBOUND_PROFILE_LABELS.get(
                str(server["inbound_profile"]), str(server["inbound_profile"])
            ),
            stats_errors=errors,
            open_create=request.args.get("create", "").strip() == "1",
        )

    @app.get("/users/json")
    @login_required
    def users_json_page():
        return render_template(
            "section_json.html",
            page_title="Пользователи JSON",
            page_section="USERS / JSON",
            page_heading="JSON пользователей",
            page_subtitle="Полный список пользователей, их состояние, сроки и подписки",
            kicker="CONTEXT JSON",
            card_title="Пользователи SG-Panel",
            description=(
                "Отредактируйте массив users. Сначала выполните обязательную "
                "проверку; сохранение станет доступно только после успешного xray run -test."
            ),
            json_label="Объект с массивом users",
            json_config=users_json_document(),
            form_action=url_for("users_json_save"),
            back_url=url_for("users_page"),
        )

    @app.post("/users/json")
    @login_required
    def users_json_save():
        scope = "users:json"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: update_users_json_document(source),
                message="Users JSON и итоговый config.json успешно проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            update_users_json_document(source)
            apply_saved_change("Users JSON сохранён")
            return redirect(url_for("users_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "section_json.html",
                page_title="Пользователи JSON",
                page_section="USERS / JSON",
                page_heading="JSON пользователей",
                page_subtitle="Полный список пользователей, их состояние, сроки и подписки",
                kicker="CONTEXT JSON",
                card_title="Пользователи SG-Panel",
                description="Исправьте JSON и выполните проверку заново.",
                json_label="Объект с массивом users",
                json_config=source,
                form_action=url_for("users_json_save"),
                back_url=url_for("users_page"),
            ), 400

    @app.post("/users/add")
    @login_required
    def users_add():
        scope = "user:add"
        try:
            expiry_at = _user_expiry_from_form()
            values = {
                "name": request.form.get("name", ""),
                "comment": request.form.get("comment", ""),
                "expiry_at": expiry_at,
            }
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: add_user(**values),
                    message="Пользователь и итоговый config.json проверены.",
                    claims_builder=lambda row: {
                        "user_uuid": str(row["uuid"]),
                        "expiry_at": str(row["expiry_at"] or ""),
                    },
                )
            grant = _require_validation_token(scope, _draft_payload())
            claims = grant.get("claims")
            claims = claims if isinstance(claims, dict) else {}
            validated_uuid = str(claims.get("user_uuid", ""))
            if not validated_uuid:
                raise ValueError("Проверка не содержит UUID нового пользователя")
            user = add_user(
                user_uuid=validated_uuid,
                name=values["name"],
                comment=values["comment"],
                expiry_at=str(claims.get("expiry_at", "")),
            )
            apply_saved_change(f"Пользователь {user['name']} добавлен")
            return redirect(url_for("user_link", user_id=user["id"]))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("users_page"))

    @app.get("/users/<int:user_id>/edit")
    @login_required
    def user_edit_page(user_id: int):
        user = find_user(user_id)
        return render_template(
            "user_edit.html",
            user=user,
            node_deployments=list_user_deployments(user_id),
            deletion_request=user_deletion_request(user_id),
        )

    @app.post("/users/<int:user_id>/edit")
    @login_required
    def user_edit(user_id: int):
        scope = f"user:{user_id}"
        values = {
            "name": request.form.get("name", ""),
            "user_uuid": request.form.get("uuid", ""),
            "comment": request.form.get("comment", ""),
            "expiry_at": request.form.get("expiry_at", ""),
        }
        try:
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: update_user(user_id, **values),
                    message="Пользователь и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            user = update_user(user_id, **values)
            apply_saved_change(f"Пользователь {user['name']} обновлён")
            return redirect(url_for("users_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("user_edit_page", user_id=user_id))

    @app.post("/users/<int:user_id>/regenerate-uuid")
    @login_required
    def user_regenerate_uuid(user_id: int):
        try:
            new_uuid = str(uuidlib.uuid4())
            _preflight_change(lambda: regenerate_user_uuid(user_id, new_uuid))
            user = regenerate_user_uuid(user_id, new_uuid)
            apply_saved_change(
                f"Для {user['name']} создан новый UUID; старая ссылка больше не работает"
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("user_edit_page", user_id=user_id))

    @app.post("/users/<int:user_id>/toggle")
    @login_required
    def users_toggle(user_id: int):
        try:
            current = find_user(user_id)
            target_enabled = not bool(current["enabled"])
            _preflight_change(lambda: set_user_enabled(user_id, target_enabled))
            updated = set_user_enabled(user_id, target_enabled)
            apply_saved_change(
                f"{updated['name']}: {'включён' if updated['enabled'] else 'отключён'}"
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("users_page"))

    @app.post("/users/<int:user_id>/delete")
    @login_required
    def users_delete(user_id: int):
        try:
            user = find_user(user_id)
            deployments = [
                item for item in list_user_deployments(user_id)
                if str(item.get("state") or "") in {"pending", "active", "error", "removing"}
            ]
            offline = [
                str(item.get("node_name") or "") for item in deployments
                if str(item.get("node_effective_state") or "") != "online"
            ]
            if offline:
                raise ValueError(
                    "Сначала верните в сеть ноды: " + ", ".join(offline)
                )

            # Verify the future local config before any remote operation starts.
            _preflight_change(lambda: delete_user(user_id))

            job_specs: list[tuple[dict[str, object], dict[str, object], int]] = []
            for deployment in deployments:
                node_id = int(deployment["node_id"])
                current_config = latest_node_config(node_id)
                if not isinstance(current_config, dict):
                    raise ValueError(
                        f"Для {deployment['node_name']} не найдена последняя применённая конфигурация"
                    )
                config, removed = _config_without_user(current_config, str(user["uuid"]))
                if removed <= 0:
                    raise ValueError(
                        f"На {deployment['node_name']} UUID пользователя не найден в последней конфигурации"
                    )
                count = 0
                for inbound in config.get("inbounds", []):
                    if not isinstance(inbound, dict):
                        continue
                    settings = inbound.get("settings")
                    if not isinstance(settings, dict):
                        continue
                    values = settings.get("clients") if isinstance(settings.get("clients"), list) else settings.get("users")
                    if isinstance(values, list):
                        count += len(values)
                job_specs.append((deployment, config, count))

            if not job_specs:
                deleted = delete_user(user_id)
                apply_saved_change(f"Пользователь {deleted['name']} удалён")
                return redirect(url_for("users_page"))

            if bool(user["enabled"]):
                set_user_enabled(user_id, False)
                apply_saved_change(
                    f"Пользователь {user['name']} отключён на центральном сервере перед удалением"
                )

            jobs: list[dict[str, object]] = []
            for deployment, config, count in job_specs:
                encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
                jobs.append(
                    create_node_job(
                        int(deployment["node_id"]),
                        job_type="apply_xray_config",
                        title=f"Удаление {user['name']} из конфигурации",
                        payload={
                            "profile": str(deployment.get("profile") or ""),
                            "config": config,
                            "config_sha256": hashlib.sha256(encoded).hexdigest(),
                            "client_count": count,
                            "deployment": {
                                "action": "remove",
                                "user_id": int(user["id"]),
                                "user_uuid": str(user["uuid"]),
                                "user_name": str(user["name"]),
                                "profile": str(deployment.get("profile") or ""),
                            },
                        },
                    )
                )
            deletion = create_user_deletion_request(
                user_id,
                user_name=str(user["name"]),
                user_uuid=str(user["uuid"]),
                jobs=jobs,
            )
            flash(
                f"Удаление запущено на {len(jobs)} нодах. Пользователь будет удалён из базы после успешной проверки всех серверов.",
                "success",
            )
            return redirect(url_for("user_edit_page", user_id=user_id))
        except (ValueError, XPanelError, sqlite3.Error) as exc:
            flash(str(exc), "error")
            return redirect(url_for("user_edit_page", user_id=user_id))

    @app.get("/users/<int:user_id>/link")
    @login_required
    def user_link(user_id: int):
        import qrcode

        user = find_user(user_id)
        links = make_saved_links(user_id, allow_disabled=True)
        direct_links: list[dict[str, object]] = []
        for item in links:
            image = qrcode.make(str(item["link"]))
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            direct_links.append({
                **item,
                "qr_data": base64.b64encode(buffer.getvalue()).decode("ascii"),
            })
        link = str(direct_links[0]["link"])
        qr_data = str(direct_links[0]["qr_data"])

        subscription_url = make_subscription_url(
            user_id, request.url_root.rstrip("/")
        )
        managed_subscription_url = subscription_url + "?format=json"
        subscription_image = qrcode.make(subscription_url)
        subscription_buffer = io.BytesIO()
        subscription_image.save(subscription_buffer, format="PNG")
        subscription_qr_data = base64.b64encode(
            subscription_buffer.getvalue()
        ).decode("ascii")
        return render_template(
            "link.html",
            user=user,
            direct_links=direct_links,
            active_links=[item for item in direct_links if bool(item.get("active"))],
            inactive_links=[item for item in direct_links if not bool(item.get("active"))],
            link=link,
            qr_data=qr_data,
            subscription_url=subscription_url,
            managed_subscription_url=managed_subscription_url,
            subscription_qr_data=subscription_qr_data,
            subscription_settings=get_subscription_settings(),
            subscription_json_enabled=bool(get_security_settings()["subscription_json_enabled"]),
            server=get_server(),
        )

    @app.get("/subscriptions")
    @login_required
    def subscriptions_page():
        users = list_users()
        fallback = request.url_root.rstrip("/")
        urls = {
            int(user["id"]): make_subscription_url(user["id"], fallback)
            for user in users
        }
        return render_template(
            "subscriptions.html",
            settings=get_subscription_settings(),
            users=users,
            subscription_urls=urls,
            fallback_base_url=fallback,
        )

    @app.post("/subscriptions/settings")
    @login_required
    def subscriptions_settings_save():
        try:
            update_subscription_settings(
                enabled="enabled" in request.form,
                base_url=request.form.get("base_url", ""),
                profile_title=request.form.get("profile_title", "SG-Panel"),
            )
            flash(
                "Настройки подписок сохранены. Apply config не требуется.",
                "success",
            )
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("subscriptions_page"))

    @app.post("/users/<int:user_id>/subscription/toggle")
    @login_required
    def user_subscription_toggle(user_id: int):
        try:
            current = find_user(user_id)
            updated = set_user_subscription_enabled(
                user_id, not bool(current["subscription_enabled"])
            )
            flash(
                f"Подписка {updated['name']}: "
                f"{'enabled' if updated['subscription_enabled'] else 'disabled'}",
                "success",
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("subscriptions_page"))

    @app.post("/users/<int:user_id>/subscription/regenerate")
    @login_required
    def user_subscription_regenerate(user_id: int):
        try:
            user = regenerate_subscription_token(user_id)
            flash(
                f"Для {user['name']} создан новый token. Старая подписка больше не работает.",
                "success",
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("subscriptions_page"))

    @app.get("/sub/<token>")
    def subscription_public(token: str):
        try:
            user = find_subscription_user(token)
            if not subscription_is_available(user):
                return Response(
                    "Not found\n", status=404, content_type="text/plain; charset=utf-8"
                )
            links = make_links(user["id"])
            link = str(links[0]["link"])
            link_lines = [str(item["link"]) for item in links]
            settings = get_subscription_settings()
        except XPanelError:
            return Response(
                "Not found\n", status=404, content_type="text/plain; charset=utf-8"
            )

        output_format = request.args.get("format", "base64").strip().lower()
        security = get_security_settings()
        if output_format == "plain" and not security["subscription_plain_enabled"]:
            return Response("Not found\n", status=404, content_type="text/plain; charset=utf-8")
        if output_format == "json" and not security["subscription_json_enabled"]:
            return Response("Not found\n", status=404, content_type="text/plain; charset=utf-8")
        if output_format == "base64":
            body = base64.b64encode(("\n".join(link_lines) + "\n").encode("utf-8")).decode("ascii")
            response = Response(body + "\n", content_type="text/plain; charset=utf-8")
        elif output_format == "plain":
            response = Response("\n".join(link_lines) + "\n", content_type="text/plain; charset=utf-8")
        elif output_format == "json":
            body = {
                "profile": settings["profile_title"],
                "user": user["name"],
                "link": link,
                "links": links,
                "managed": managed_client_export(user["id"]),
                "managedV2": managed_client_export_v2(user["id"]),
                "managedPreferred": "managedV2",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            response = Response(
                json.dumps(body, ensure_ascii=False, indent=2) + "\n",
                content_type="application/json; charset=utf-8",
            )
        else:
            abort(400, description="format должен быть base64, plain или json")

        record_subscription_access(user["id"])
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if output_format == "json":
            response.headers["X-SG-Managed-Profile"] = "v2"
        return response

    @app.post("/stats/reset")
    @login_required
    def stats_reset():
        try:
            reset_stats()
            flash("Трафик всех клиентов сброшен. Пользователи и конфигурации не изменены", "success")
        except (XPanelError, FileNotFoundError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("users_page"))

    @app.post("/users/<int:user_id>/traffic/reset")
    @login_required
    def user_traffic_reset(user_id: int):
        try:
            user = find_user(user_id)
            reset_stats(user_id)
            flash(f"Трафик клиента {user['name']} сброшен. Доступ и конфигурация не изменены", "success")
        except (XPanelError, FileNotFoundError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("users_page", client=user_id))

    @app.get("/settings/advanced")
    @login_required
    def settings_advanced_page():
        return render_template(
            "advanced.html",
            expert=get_transport_expert_overview(),
            server=get_server(),
        )

    @app.get("/settings/expert")
    @login_required
    def settings_expert_page():
        """Compatibility redirect from RC50/RC51 bookmarks."""
        return redirect(url_for("settings_advanced_page"), code=302)

    def expert_form_values() -> dict[str, object]:
        current = get_transport_expert_overview()["settings"]
        finalmask_present = request.form.get("finalmask_present") == "1"
        tls_present = request.form.get("tls_present") == "1"
        ech_present = request.form.get("ech_present") == "1"
        return {
            "xhttp_mode": request.form.get("xhttp_mode", str(get_server()["xhttp_mode"] or "auto")),
            "xhttp_extra_server_json": request.form.get("xhttp_extra_server_json", current["xhttp_extra_server_json"]),
            "xhttp_extra_client_json": request.form.get("xhttp_extra_client_json", current["xhttp_extra_client_json"]),
            "finalmask_enabled": (
                request.form.get("finalmask_enabled") == "1"
                if finalmask_present else bool(current["finalmask_enabled"])
            ),
            "finalmask_server_json": request.form.get("finalmask_server_json", current["finalmask_server_json"]),
            "finalmask_client_json": request.form.get("finalmask_client_json", current["finalmask_client_json"]),
            "ech_mode": request.form.get("ech_mode", current["ech_mode"]) if ech_present else current["ech_mode"],
            "ech_public_name": request.form.get("ech_public_name", current["ech_public_name"]) if ech_present else current["ech_public_name"],
            "ech_server_keys": request.form.get("ech_server_keys", current["ech_server_keys"]) if ech_present else current["ech_server_keys"],
            "ech_config_list": request.form.get("ech_config_list", current["ech_config_list"]) if ech_present else current["ech_config_list"],
            "certificate_pinning_enabled": (
                request.form.get("certificate_pinning_enabled") == "1"
                if tls_present else bool(current["certificate_pinning_enabled"])
            ),
            "certificate_pinning_sha256": request.form.get("certificate_pinning_sha256", current["certificate_pinning_sha256"]) if tls_present else current["certificate_pinning_sha256"],
            "certificate_pinning_source": request.form.get("certificate_pinning_source", current["certificate_pinning_source"]) if tls_present else current["certificate_pinning_source"],
            "tls_verify_name_mode": request.form.get("tls_verify_name_mode", current["tls_verify_name_mode"]) if tls_present else current["tls_verify_name_mode"],
            "tls_verify_name": request.form.get("tls_verify_name", current["tls_verify_name"]) if tls_present else current["tls_verify_name"],
            "client_ca_pem": request.form.get("client_ca_pem", current["client_ca_pem"]) if tls_present else current["client_ca_pem"],
            "client_ca_source": request.form.get("client_ca_source", current["client_ca_source"]) if tls_present else current["client_ca_source"],
        }

    @app.post("/settings/expert")
    @app.post("/settings/advanced")
    @login_required
    def settings_advanced_save():
        scope = "settings:advanced"
        try:
            values = expert_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope,
                    lambda: update_transport_expert_settings(**values),
                    message="Дополнительные параметры транспорта и итоговый config.json корректны.",
                )
            _require_validation_token(scope, _draft_payload())
            update_transport_expert_settings(**values)
            apply_saved_change("Дополнительные параметры транспорта сохранены и применены")
        except (ValueError, XPanelError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("settings_advanced_page"))

    @app.post("/settings/expert/generate-ech")
    @app.post("/settings/advanced/generate-ech")
    @login_required
    def settings_advanced_generate_ech():
        try:
            result = generate_ech_pair(request.form.get("public_name", ""))
            return jsonify({"ok": True, **result})
        except (ValueError, XPanelError, OSError) as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

    @app.post("/settings/expert/certificate-pin")
    @app.post("/settings/advanced/certificate-pin")
    @login_required
    def settings_advanced_certificate_pin():
        try:
            result = calculate_certificate_pin(request.form.get("cert_path", ""))
            return jsonify({"ok": True, **result})
        except (ValueError, XPanelError, OSError) as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400


    @app.post("/settings/expert/import-ca")
    @app.post("/settings/advanced/import-ca")
    @login_required
    def settings_advanced_import_ca():
        try:
            result = load_client_ca_pem(request.form.get("ca_path", ""))
            return jsonify({"ok": True, **result})
        except (ValueError, XPanelError, OSError) as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

    def geofiles_form_values() -> dict[str, object]:
        return {
            "source": request.form.get("source", "xray"),
            "geoip_url": request.form.get("geoip_url", ""),
            "geosite_url": request.form.get("geosite_url", ""),
            "geoip_local_path": request.form.get("geoip_local_path", ""),
            "geosite_local_path": request.form.get("geosite_local_path", ""),
        }

    @app.get("/routing/geofiles")
    @login_required
    def geofiles_page():
        return render_template(
            "geofiles.html",
            geofiles=get_geofiles_overview(),
            format_bytes=format_bytes,
        )

    @app.post("/settings/geofiles/check")
    @app.post("/routing/geofiles/check")
    @login_required
    def settings_geofiles_check():
        try:
            result = validate_geofiles_source(**geofiles_form_values())
            flash(
                "GeoFiles проверены: текущие Routing Rules совместимы; применение разблокировано",
                "success",
            )
            write_audit(
                "geofiles_checked", detail=str(result.get("source", "")),
                ip_address=getattr(g, "client_ip", ""),
                user_agent=request.headers.get("User-Agent", ""), success=True,
            )
        except (ValueError, XPanelError, OSError, subprocess.TimeoutExpired) as exc:
            flash(str(exc), "error")
        return redirect(url_for("geofiles_page"))

    @app.post("/settings/geofiles/apply")
    @app.post("/routing/geofiles/apply")
    @login_required
    def settings_geofiles_apply():
        try:
            result = apply_geofiles_source()
            flash(f"GeoFiles применены: {result['source']}", "success")
            write_audit(
                "geofiles_applied", detail=str(result.get("source", "")),
                ip_address=getattr(g, "client_ip", ""),
                user_agent=request.headers.get("User-Agent", ""), success=True,
            )
        except (ValueError, XPanelError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("geofiles_page"))

    @app.get("/settings")
    @login_required
    def settings_page():
        return render_template(
            "settings.html",
            server=get_server(),
            hysteria_inbounds=list_hysteria_inbounds(),
            xhttp_inbounds=list_xhttp_inbounds(),
            reality_inbounds=list_reality_inbounds(),
            inbound_recommendations=get_inbound_recommendations(),
            hysteria_studio=get_hysteria_studio_overview(),
        )

    def server_form_values() -> dict[str, object]:
        current = get_server()
        current_instances = {int(row["id"]): row for row in list_hysteria_inbounds()}
        current_xhttp = {int(row["id"]): row for row in list_xhttp_inbounds()}
        current_reality = {int(row["id"]): row for row in list_reality_inbounds()}
        public_listen = request.form.get("listen", current["listen"])
        public_port = int(request.form.get("port", current["port"]))
        hysteria_instances = [
            {
                "id": 1,
                "name": request.form.get(
                    "hysteria_instance_1_name", current_instances[1]["name"]
                ),
                "enabled": True,
                "listen": public_listen,
                "port": public_port,
            },
            {
                "id": 2,
                "name": request.form.get(
                    "hysteria_instance_2_name", current_instances[2]["name"]
                ),
                "enabled": request.form.get("hysteria_instance_2_enabled") == "1",
                "listen": request.form.get(
                    "hysteria_instance_2_listen", current_instances[2]["listen"]
                ),
                "port": int(request.form.get(
                    "hysteria_instance_2_port", current_instances[2]["port"]
                )),
            },
            {
                "id": 3,
                "name": request.form.get(
                    "hysteria_instance_3_name", current_instances[3]["name"]
                ),
                "enabled": request.form.get("hysteria_instance_3_enabled") == "1",
                "listen": request.form.get(
                    "hysteria_instance_3_listen", current_instances[3]["listen"]
                ),
                "port": int(request.form.get(
                    "hysteria_instance_3_port", current_instances[3]["port"]
                )),
            },
        ]
        reality_instances = [
            {
                "id": 1,
                "name": request.form.get(
                    "reality_instance_1_name", current_reality[1]["name"]
                ),
                "enabled": True,
                "listen": public_listen,
                "port": public_port,
                "short_id": request.form.get("short_id", current_reality[1]["short_id"]),
            },
            {
                "id": 2,
                "name": request.form.get(
                    "reality_instance_2_name", current_reality[2]["name"]
                ),
                "enabled": request.form.get("reality_instance_2_enabled") == "1",
                "listen": request.form.get(
                    "reality_instance_2_listen", current_reality[2]["listen"]
                ),
                "port": int(request.form.get(
                    "reality_instance_2_port", current_reality[2]["port"]
                )),
                "short_id": request.form.get(
                    "reality_instance_2_short_id", current_reality[2]["short_id"]
                ),
            },
            {
                "id": 3,
                "name": request.form.get(
                    "reality_instance_3_name", current_reality[3]["name"]
                ),
                "enabled": request.form.get("reality_instance_3_enabled") == "1",
                "listen": request.form.get(
                    "reality_instance_3_listen", current_reality[3]["listen"]
                ),
                "port": int(request.form.get(
                    "reality_instance_3_port", current_reality[3]["port"]
                )),
                "short_id": request.form.get(
                    "reality_instance_3_short_id", current_reality[3]["short_id"]
                ),
            },
        ]
        xhttp_instances = [
            {
                "id": 1,
                "name": request.form.get(
                    "xhttp_instance_1_name", current_xhttp[1]["name"]
                ),
                "enabled": True,
                "listen": request.form.get(
                    "transport_listen", current_xhttp[1]["listen"]
                ),
                "port": int(request.form.get(
                    "transport_port", current_xhttp[1]["port"]
                )),
                "path": request.form.get(
                    "xhttp_path", current_xhttp[1]["path"]
                ),
            },
            {
                "id": 2,
                "name": request.form.get(
                    "xhttp_instance_2_name", current_xhttp[2]["name"]
                ),
                "enabled": request.form.get("xhttp_instance_2_enabled") == "1",
                "listen": request.form.get(
                    "xhttp_instance_2_listen", current_xhttp[2]["listen"]
                ),
                "port": int(request.form.get(
                    "xhttp_instance_2_port", current_xhttp[2]["port"]
                )),
                "path": request.form.get(
                    "xhttp_instance_2_path", current_xhttp[2]["path"]
                ),
            },
            {
                "id": 3,
                "name": request.form.get(
                    "xhttp_instance_3_name", current_xhttp[3]["name"]
                ),
                "enabled": request.form.get("xhttp_instance_3_enabled") == "1",
                "listen": request.form.get(
                    "xhttp_instance_3_listen", current_xhttp[3]["listen"]
                ),
                "port": int(request.form.get(
                    "xhttp_instance_3_port", current_xhttp[3]["port"]
                )),
                "path": request.form.get(
                    "xhttp_instance_3_path", current_xhttp[3]["path"]
                ),
            },
        ]
        return {
            "address": request.form.get("address", ""),
            "listen": public_listen,
            "port": public_port,
            "dest": request.form.get("dest", ""),
            "server_name": request.form.get("server_name", ""),
            "private_key": request.form.get("private_key", ""),
            "public_key": request.form.get("public_key", ""),
            "short_id": request.form.get("short_id", ""),
            "fingerprint": request.form.get("fingerprint", "firefox"),
            "flow": request.form.get("flow", "xtls-rprx-vision"),
            "loglevel": current["loglevel"],
            "api_listen": current["api_listen"],
            "stats_enabled": bool(current["stats_enabled"]),
            "config_path": current["config_path"],
            "xray_bin": current["xray_bin"],
            "xray_service": current["xray_service"],
            "inbound_profile": request.form.get("inbound_profile", "raw_reality"),
            "transport_listen": request.form.get(
                "transport_listen", current["transport_listen"]
            ),
            "transport_port": int(
                request.form.get("transport_port", current["transport_port"])
            ),
            "xhttp_path": request.form.get("xhttp_path", current["xhttp_path"]),
            "xhttp_mode": request.form.get("xhttp_mode", current["xhttp_mode"]),
            "grpc_service_name": current["grpc_service_name"],
            "tls_cert_path": request.form.get(
                "tls_cert_path", current["tls_cert_path"]
            ),
            "tls_key_path": request.form.get(
                "tls_key_path", current["tls_key_path"]
            ),
            "hysteria_udp_idle_timeout": int(
                request.form.get("hysteria_udp_idle_timeout", current["hysteria_udp_idle_timeout"])
            ),
            "hysteria_masquerade_type": request.form.get(
                "hysteria_masquerade_type", current["hysteria_masquerade_type"]
            ),
            "hysteria_masquerade_url": request.form.get(
                "hysteria_masquerade_url", current["hysteria_masquerade_url"]
            ),
            "hysteria_masquerade_content": request.form.get(
                "hysteria_masquerade_content", current["hysteria_masquerade_content"]
            ),
            "hysteria_masquerade_status": int(
                request.form.get("hysteria_masquerade_status", current["hysteria_masquerade_status"])
            ),
            "hysteria_masquerade_dir": request.form.get(
                "hysteria_masquerade_dir", current["hysteria_masquerade_dir"]
            ),
            "hysteria_masquerade_rewrite_host": request.form.get("hysteria_masquerade_rewrite_host") == "1",
            "hysteria_masquerade_insecure": request.form.get("hysteria_masquerade_insecure") == "1",
            "hysteria_masquerade_headers": request.form.get(
                "hysteria_masquerade_headers", current["hysteria_masquerade_headers"]
            ),
            "hysteria_performance_profile": request.form.get(
                "hysteria_performance_profile", current["hysteria_performance_profile"]
            ),
            "hysteria_congestion": request.form.get(
                "hysteria_congestion", current["hysteria_congestion"]
            ),
            "hysteria_bbr_profile": request.form.get(
                "hysteria_bbr_profile", current["hysteria_bbr_profile"]
            ),
            "hysteria_brutal_up": request.form.get(
                "hysteria_brutal_up", current["hysteria_brutal_up"]
            ),
            "hysteria_brutal_down": request.form.get(
                "hysteria_brutal_down", current["hysteria_brutal_down"]
            ),
            "hysteria_quic_debug": request.form.get("hysteria_quic_debug") == "1",
            "hysteria_max_idle_timeout": int(
                request.form.get("hysteria_max_idle_timeout", current["hysteria_max_idle_timeout"])
            ),
            "hysteria_keepalive_period": int(
                request.form.get("hysteria_keepalive_period", current["hysteria_keepalive_period"])
            ),
            "hysteria_disable_pmtud": request.form.get("hysteria_disable_pmtud") == "1",
            "hysteria_max_incoming_streams": int(
                request.form.get("hysteria_max_incoming_streams", current["hysteria_max_incoming_streams"])
            ),
            "hysteria_udp_hop_ports": request.form.get(
                "hysteria_udp_hop_ports", current["hysteria_udp_hop_ports"]
            ),
            "hysteria_udp_hop_interval": request.form.get(
                "hysteria_udp_hop_interval", current["hysteria_udp_hop_interval"]
            ),
            "hysteria_init_stream_receive_window": int(
                request.form.get("hysteria_init_stream_receive_window", current["hysteria_init_stream_receive_window"])
            ),
            "hysteria_max_stream_receive_window": int(
                request.form.get("hysteria_max_stream_receive_window", current["hysteria_max_stream_receive_window"])
            ),
            "hysteria_init_connection_receive_window": int(
                request.form.get("hysteria_init_connection_receive_window", current["hysteria_init_connection_receive_window"])
            ),
            "hysteria_max_connection_receive_window": int(
                request.form.get("hysteria_max_connection_receive_window", current["hysteria_max_connection_receive_window"])
            ),
            "hysteria_instances": hysteria_instances,
            "xhttp_instances": xhttp_instances,
            "reality_instances": reality_instances,
        }

    @app.get("/settings/hysteria/diagnostics")
    @login_required
    def settings_hysteria_diagnostics():
        return render_template(
            "hysteria_diagnostics.html",
            report=get_hysteria_diagnostics(),
        )

    @app.post("/settings/server")
    @login_required
    def settings_save():
        scope = "settings:server"
        try:
            values = server_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope,
                    lambda: update_server_settings(**values),
                    message=(
                        "Inbound и итоговый config.json корректны. "
                        "Теперь можно сохранить и применить."
                    ),
                )
            _require_validation_token(scope, _draft_payload())
            server = update_server_settings(**values)
            label = "XHTTP и Hysteria 2 применены" if server["inbound_profile"] == "xhttp_hysteria_tls" else ("Hysteria 2 применена" if server["inbound_profile"] == "hysteria2_tls" else "Inbound применён")
            apply_saved_change(label)
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("settings_page"))

    @app.get("/settings/json")
    @login_required
    def inbound_json_page():
        return render_template(
            "section_json.html",
            page_title="Inbound JSON",
            page_section="INBOUND / JSON",
            page_heading="JSON основного Inbound",
            page_subtitle="Редактируемый фрагмент основного Inbound",
            kicker="CONTEXT JSON",
            card_title="Основной Inbound Xray",
            description=(
                "Изменения сначала проверяются на временной копии SQLite и проходят "
                "xray run -test. В рабочую базу ничего не записывается до отдельного сохранения."
            ),
            json_label="Объект inbound",
            json_config=inbound_json_document(),
            form_action=url_for("inbound_json_save"),
            back_url=url_for("settings_page"),
        )

    @app.post("/settings/json")
    @login_required
    def inbound_json_save():
        scope = "settings:inbound-json"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope,
                lambda: update_inbound_json_document(source),
                message=(
                    "Inbound JSON, модель SG-Panel и итоговый config.json проверены. "
                    "Можно сохранить и применить."
                ),
            )
        try:
            _require_validation_token(scope, _draft_payload())
            result = update_inbound_json_document(source)
            apply_saved_change(
                f"Inbound JSON сохранён; синхронизировано {result['users']} пользователей"
            )
            return redirect(url_for("settings_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "section_json.html",
                page_title="Inbound JSON",
                page_section="INBOUND / JSON",
                page_heading="JSON основного Inbound",
                page_subtitle="Редактируемый фрагмент основного Inbound",
                kicker="CONTEXT JSON",
                card_title="Основной Inbound Xray",
                description="Сначала исправьте JSON и выполните проверку заново.",
                json_label="Объект inbound",
                json_config=source,
                form_action=url_for("inbound_json_save"),
                back_url=url_for("settings_page"),
            ), 400

    @app.post("/settings/generate-reality")
    @login_required
    def settings_generate_reality():
        try:
            server = get_server()
            keys = generate_reality_keys(server["xray_bin"])
            values = {
                "address": server["address"],
                "listen": server["listen"],
                "port": server["port"],
                "dest": server["dest"],
                "server_name": server["server_name"],
                "private_key": keys["private_key"],
                "public_key": keys["public_key"],
                "short_id": keys["short_id"],
                "fingerprint": server["fingerprint"],
                "flow": server["flow"],
                "loglevel": server["loglevel"],
                "api_listen": server["api_listen"],
                "stats_enabled": bool(server["stats_enabled"]),
                "config_path": server["config_path"],
                "xray_bin": server["xray_bin"],
                "xray_service": server["xray_service"],
                "inbound_profile": server["inbound_profile"],
                "transport_listen": server["transport_listen"],
                "transport_port": server["transport_port"],
                "xhttp_path": server["xhttp_path"],
                "xhttp_mode": server["xhttp_mode"],
                "grpc_service_name": server["grpc_service_name"],
                "tls_cert_path": server["tls_cert_path"],
                "tls_key_path": server["tls_key_path"],
            }
            _preflight_change(lambda: update_server_settings(**values))
            create_backup()
            update_server_settings(**values)
            apply_saved_change(
                "Созданы новые Reality-ключи; старые клиентские ссылки больше не работают"
            )
        except (ValueError, XPanelError, FileNotFoundError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("settings_page"))

    @app.post("/settings/password")
    @login_required
    def settings_password():
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        repeat = request.form.get("repeat_password", "")
        if not check_password_hash(app.config["PASSWORD_HASH"], current):
            flash("Текущий пароль указан неверно", "error")
            return redirect(url_for("security_page"))
        if len(new) < 8:
            flash("Новый пароль должен содержать не менее 8 символов", "error")
            return redirect(url_for("security_page"))
        if new != repeat:
            flash("Новые пароли не совпадают", "error")
            return redirect(url_for("security_page"))
        new_hash = generate_password_hash(new)
        write_audit(
            "password_changed", ip_address=getattr(g, "client_ip", ""),
            user_agent=request.headers.get("User-Agent", ""), success=True,
        )
        new_secret = _write_password_hash(
            Path(app.config["ENV_FILE"]), new_hash, rotate_secret=True
        )
        revoke_all_admin_sessions()
        app.config["PASSWORD_HASH"] = new_hash
        if new_secret and app.config.get("TESTING"):
            app.config["SECRET_KEY"] = new_secret
        session.clear()
        if not app.config.get("TESTING"):
            subprocess.Popen(
                [
                    "systemd-run",
                    f"--unit=sg-panel-password-restart-{secrets.token_hex(4)}",
                    "--on-active=2s",
                    "/bin/systemctl",
                    "restart",
                    "xpanel-web",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return redirect(url_for("login"))

    @app.get("/security")
    @login_required
    def security_page():
        env_values = _read_env_values(Path(app.config["ENV_FILE"]))
        settings = get_security_settings()
        panel_access = _panel_access_state(request.host.split(":", 1)[0])
        return render_template(
            "security.html",
            settings=settings,
            overview=security_overview(),
            sessions=list_admin_sessions(),
            login_attempts=recent_login_attempts(50),
            audit_log=list_audit_log(100),
            current_session_id=session.get("admin_session_id", ""),
            current_ip=getattr(g, "client_ip", request.remote_addr or ""),
            panel_bind=env_values.get(
                "XPANEL_BIND_ADDRESS", app.config["PANEL_BIND_ADDRESS"]
            ),
            panel_port=env_values.get("XPANEL_PORT", str(app.config["PANEL_PORT"])),
            secure_cookies=app.config["SESSION_COOKIE_SECURE"],
            request_is_secure=request.is_secure,
            panel_access=panel_access,
            panel_exposure=_panel_exposure_state(settings, panel_access),
            xray_address=str(get_server()["address"]),
        )

    @app.post("/security/exposure")
    @login_required
    def security_exposure_save():
        try:
            mode = request.form.get("panel_exposure_mode", "direct")
            update_panel_exposure_settings(
                mode=mode,
                cloudflare_hostname=request.form.get("cloudflare_hostname", ""),
                cloudflare_origin_lockdown="cloudflare_origin_lockdown" in request.form,
                cloudflare_access_enabled="cloudflare_access_enabled" in request.form,
                cloudflare_tunnel_name=request.form.get("cloudflare_tunnel_name", ""),
            )
            settings = get_security_settings()
            state = _panel_exposure_state(
                settings, _panel_access_state(request.host.split(":", 1)[0])
            )
            write_audit(
                "panel_exposure_updated",
                detail=f"{state['mode']} {state['hostname']}",
                ip_address=getattr(g, "client_ip", ""),
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )
            if state["status"] == "ready":
                flash(f"Panel exposure: {state['label']} настроен", "success")
            else:
                flash(f"Panel exposure сохранён. {state['message']}", "warning")
        except (ValueError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("security_page") + "#panel-exposure")

    @app.post("/security/panel-access")
    @login_required
    def panel_access_start():
        try:
            mode, host, port = _validate_panel_access_values(
                request.form.get("panel_access_mode", ""),
                request.form.get("panel_access_host", ""),
                request.form.get("panel_access_port", ""),
            )
            if not PANEL_ACCESS_SCRIPT.is_file():
                raise RuntimeError(f"Не найден {PANEL_ACCESS_SCRIPT}")
            PANEL_ACCESS_JOB_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(PANEL_ACCESS_JOB_DIR, 0o700)
            job_id = (
                datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                + "-"
                + secrets.token_hex(6)
            )
            paths = _panel_access_job_paths(job_id)
            target_url = f"{mode}://{host}:{port}"
            paths["meta"].write_text(
                json.dumps(
                    {
                        "mode": mode,
                        "host": host,
                        "port": port,
                        "target_url": target_url,
                        "created_at": datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            command = [
                "/bin/bash",
                str(PANEL_ACCESS_SCRIPT),
                "--mode",
                mode,
                "--host",
                host,
                "--port",
                str(port),
            ]
            quoted = " ".join(shlex.quote(item) for item in command)
            wrapper_lines = [
                "#!/usr/bin/env bash",
                "set +e",
                f"printf 'running\\n' > {shlex.quote(str(paths['status']))}",
                "{",
                "  printf '[SG-Panel] Начинаю настройку доступа\\n'",
                f"  {quoted}",
                f"}} > {shlex.quote(str(paths['log']))} 2>&1",
                "rc=$?",
                "if [[ $rc -eq 0 ]]; then",
                f"  printf 'success\\n' > {shlex.quote(str(paths['status']))}",
                "else",
                f"  printf 'failed\\n' > {shlex.quote(str(paths['status']))}",
                "fi",
                "exit 0",
                "",
            ]
            paths["wrapper"].write_text("\n".join(wrapper_lines), encoding="utf-8")
            os.chmod(paths["wrapper"], 0o700)
            paths["status"].write_text("queued\n", encoding="utf-8")
            unit = f"sg-panel-access-{job_id}"
            started = subprocess.run(
                [
                    "systemd-run",
                    "--unit",
                    unit,
                    "--collect",
                    "/bin/bash",
                    str(paths["wrapper"]),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if started.returncode != 0:
                raise RuntimeError(
                    (started.stderr or started.stdout).strip()
                    or "не удалось запустить задачу настройки доступа"
                )
            write_audit(
                "panel_access_started",
                detail=f"{mode} {host}:{port}",
                ip_address=getattr(g, "client_ip", ""),
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )
            return redirect(url_for("panel_access_job", job_id=job_id))
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            flash(str(exc), "error")
            return redirect(url_for("security_page"))

    @app.get("/security/panel-access/jobs/<job_id>")
    @login_required
    def panel_access_job(job_id: str):
        try:
            job = _read_panel_access_job(job_id)
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            abort(404)
        return render_template("panel_access_job.html", job=job)

    @app.get("/security/panel-access/jobs/<job_id>/status")
    @login_required
    def panel_access_job_status(job_id: str):
        try:
            job = _read_panel_access_job(job_id)
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            abort(404)
        return Response(
            json.dumps(job, ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )

    @app.post("/security/settings")
    @login_required
    def security_settings_save():
        try:
            update_security_settings(
                session_timeout_minutes=int(request.form.get("session_timeout_minutes", "60")),
                max_login_attempts=int(request.form.get("max_login_attempts", "5")),
                lockout_minutes=int(request.form.get("lockout_minutes", "15")),
                allowlist_enabled="allowlist_enabled" in request.form,
                allowed_networks=request.form.get("allowed_networks", ""),
                trust_proxy_headers="trust_proxy_headers" in request.form,
                subscription_plain_enabled="subscription_plain_enabled" in request.form,
                subscription_json_enabled="subscription_json_enabled" in request.form,
                subscription_allowlist_enabled="subscription_allowlist_enabled" in request.form,
                subscription_allowed_networks=request.form.get(
                    "subscription_allowed_networks", ""
                ),
                audit_retention_days=int(request.form.get("audit_retention_days", "90")),
                current_ip=getattr(g, "client_ip", request.remote_addr or ""),
            )
            flash("Настройки безопасности сохранены", "success")
        except (ValueError, RuntimeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("security_page"))

    @app.post("/security/sessions/<session_id>/revoke")
    @login_required
    def security_session_revoke(session_id: str):
        current = session.get("admin_session_id")
        if revoke_admin_session(session_id):
            flash("Сессия завершена", "success")
        else:
            flash("Сессия не найдена", "error")
        if session_id == current:
            session.clear()
            return redirect(url_for("login"))
        return redirect(url_for("security_page"))

    @app.post("/security/sessions/revoke-all")
    @login_required
    def security_sessions_revoke_all():
        current = session.get("admin_session_id")
        include_current = request.form.get("include_current") == "1"
        count = revoke_all_admin_sessions(
            except_session_id=None if include_current else current
        )
        flash(f"Завершено сессий: {count}", "success")
        if include_current:
            session.clear()
            return redirect(url_for("login"))
        return redirect(url_for("security_page"))

    @app.post("/security/history/purge")
    @login_required
    def security_history_purge():
        purge_security_history()
        flash("Старые записи журнала удалены согласно сроку хранения", "success")
        return redirect(url_for("security_page"))

    @app.get("/config")
    @login_required
    def config_page():
        validation = validate_generated_config()
        return render_template("config.html", validation=validation, server=get_server())

    def runtime_form_values() -> dict[str, object]:
        current = get_server()
        return {
            "address": current["address"],
            "listen": current["listen"],
            "port": current["port"],
            "dest": current["dest"],
            "server_name": current["server_name"],
            "private_key": current["private_key"],
            "public_key": current["public_key"],
            "short_id": current["short_id"],
            "fingerprint": current["fingerprint"],
            "flow": current["flow"],
            "loglevel": request.form.get("loglevel", current["loglevel"]),
            "api_listen": request.form.get("api_listen", current["api_listen"]),
            "stats_enabled": "stats_enabled" in request.form,
            "config_path": request.form.get("config_path", current["config_path"]),
            "xray_bin": request.form.get("xray_bin", current["xray_bin"]),
            "xray_service": request.form.get("xray_service", current["xray_service"]),
            "inbound_profile": current["inbound_profile"],
            "transport_listen": current["transport_listen"],
            "transport_port": current["transport_port"],
            "xhttp_path": current["xhttp_path"],
            "xhttp_mode": current["xhttp_mode"],
            "grpc_service_name": current["grpc_service_name"],
            "tls_cert_path": current["tls_cert_path"],
            "tls_key_path": current["tls_key_path"],
        }

    @app.post("/config/runtime")
    @login_required
    def config_runtime_save():
        scope = "config:runtime"
        try:
            values = runtime_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope,
                    lambda: update_server_settings(**values),
                    message="Служебные параметры и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            update_server_settings(**values)
            apply_saved_change("Служебные параметры Xray сохранены")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("config_page"))

    @app.post("/config/validate")
    @login_required
    def config_validate():
        validation = validate_generated_config()
        flash(
            "Сгенерированный config.json прошёл xray run -test"
            if validation["ok"]
            else validation["detail"],
            "success" if validation["ok"] else "error",
        )
        return redirect(url_for("config_page"))

    @app.get("/config/json")
    @login_required
    def config_json_page():
        return render_template("config_json.html", config_json=config_json_document())

    @app.post("/config/json")
    @login_required
    def config_json_save():
        scope = "config:full-json"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope,
                lambda: update_config_json_document(source),
                message=(
                    "Полный JSON, модель SG-Panel и xray run -test успешно проверены. "
                    "Можно сохранить и применить."
                ),
            )
        try:
            _require_validation_token(scope, _draft_payload())
            result = update_config_json_document(source)
            apply_saved_change(
                "Полный JSON синхронизирован: "
                f"{result['users']} пользователей, {result['outbounds']} выходов, "
                f"{result['rules']} правил"
            )
            return redirect(url_for("config_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template("config_json.html", config_json=source), 400

    @app.get("/backups")
    @login_required
    def backups_page():
        return render_template("backups.html", backups=list_backups())

    @app.post("/backups/create")
    @login_required
    def backups_create():
        try:
            backup = create_backup()
            flash(f"Создана резервная копия {backup['name']}", "success")
        except (OSError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.get("/backups/<name>/download/<kind>")
    @login_required
    def backups_download(name: str, kind: str):
        if kind not in {"db", "config"}:
            abort(404)
        try:
            path = backup_file(name, kind)
        except (ValueError, FileNotFoundError):
            abort(404)
        return send_file(path, as_attachment=True, download_name=path.name)

    @app.post("/backups/<name>/verify")
    @login_required
    def backups_verify(name: str):
        try:
            result = verify_backup(name)
            if result["ok"]:
                flash(
                    f"Копия {result['name']} проверена: SQLite и итоговый Xray config корректны.",
                    "success",
                )
            else:
                flash(
                    f"Копия {result['name']} не прошла проверку: {result['detail']}",
                    "error",
                )
        except (ValueError, FileNotFoundError, OSError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.post("/backups/<name>/restore")
    @login_required
    def backups_restore(name: str):
        try:
            result = restore_backup(name)
            flash(
                f"Полное восстановление из {result['name']} завершено. "
                f"База и рабочий config.json применены, Xray перезапущен. "
                f"Страховочная копия прежнего состояния: {result['safety']}",
                "success",
            )
        except (ValueError, FileNotFoundError, OSError, PermissionError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.post("/backups/<name>/delete")
    @login_required
    def backups_delete(name: str):
        try:
            delete_backup(name)
            flash(f"Резервная копия {name} удалена", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("backups_page"))

    @app.get("/updates")
    @login_required
    def updates_page():
        allow_network = not bool(app.config.get("TESTING"))
        update_info = check_for_updates(force=False, allow_network=allow_network)
        update_status = get_update_status()
        server = get_server()
        xray_stable_info = check_xray_updates(
            channel="stable",
            force=False,
            allow_network=allow_network,
            xray_bin=str(server["xray_bin"]),
        )
        xray_prerelease_info = check_xray_updates(
            channel="prerelease",
            force=False,
            allow_network=allow_network,
            xray_bin=str(server["xray_bin"]),
        )
        xray_update_status = get_xray_update_status()
        labels = {
            "idle": "НЕ ЗАПУСКАЛОСЬ",
            "starting": "ПОДГОТОВКА",
            "downloading": "ЗАГРУЗКА",
            "verifying": "ПРОВЕРКА",
            "backing_up": "РЕЗЕРВНАЯ КОПИЯ",
            "installing": "УСТАНОВКА",
            "validating": "КОНТРОЛЬ",
            "success": "ГОТОВО",
            "rollback": "ОТКАТ",
            "rolled_back": "ВОССТАНОВЛЕНО",
            "error": "ОШИБКА",
            "unknown": "НЕИЗВЕСТНО",
        }
        running_states = {
            "starting", "downloading", "verifying", "backing_up",
            "installing", "validating", "rollback",
        }
        state = str(update_status.get("state") or "idle")
        state_class = (
            "success" if state == "success"
            else "danger" if state in {"error", "rolled_back"}
            else "warning" if state in running_states
            else ""
        )
        xray_state = str(xray_update_status.get("state") or "idle")
        xray_state_class = (
            "success" if xray_state == "success"
            else "danger" if xray_state in {"error", "rolled_back"}
            else "warning" if xray_state in running_states
            else ""
        )
        panel_running = update_in_progress()
        xray_running = xray_update_in_progress()
        return render_template(
            "updates.html",
            update_info=update_info,
            update_status=update_status,
            update_running=panel_running,
            update_state_label=labels.get(state, state.upper()),
            update_state_class=state_class,
            xray_stable_info=xray_stable_info,
            xray_prerelease_info=xray_prerelease_info,
            xray_update_status=xray_update_status,
            xray_update_running=xray_running,
            xray_update_state_label=labels.get(xray_state, xray_state.upper()),
            xray_update_state_class=xray_state_class,
            any_update_running=panel_running or xray_running,
        )

    @app.post("/updates/check")
    @login_required
    def updates_check():
        try:
            if xray_update_in_progress():
                raise XPanelError("Сначала дождитесь завершения обновления Xray")
            info = check_for_updates(force=True, allow_network=True)
            if info.get("error"):
                raise XPanelError(str(info["error"]))
            if info.get("available"):
                flash(f"Доступна версия {info['latest']}", "success")
            else:
                flash("Установлена актуальная версия SG-Panel", "success")
        except (OSError, ValueError, XPanelError) as exc:
            flash(f"Не удалось проверить обновления: {exc}", "error")
        return redirect(url_for("updates_page"))

    @app.post("/updates/start")
    @login_required
    def updates_start():
        try:
            if xray_update_in_progress():
                raise XPanelError("Сначала дождитесь завершения обновления Xray")
            info = check_for_updates(force=True, allow_network=True)
            if info.get("error"):
                raise XPanelError(str(info["error"]))
            version = request.form.get("version", "").strip()
            ref = request.form.get("ref", "").strip()
            if (
                not info.get("available")
                or version != str(info.get("latest") or "")
                or ref != str(info.get("latest_ref") or "")
            ):
                raise ValueError(
                    "Данные о версии изменились. Нажмите «Проверить сейчас» и повторите обновление"
                )
            result = start_panel_update(version, ref)
            flash(
                f"Обновление до {result['version']} запущено. Следите за живым журналом.",
                "success",
            )
        except (OSError, ValueError, PermissionError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("updates_page", watch="panel"))

    @app.get("/updates/status")
    @login_required
    def updates_status():
        return Response(
            json.dumps(get_update_status(), ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )

    @app.post("/updates/xray/check")
    @login_required
    def xray_updates_check():
        channel = request.form.get("channel", "stable").strip().lower()
        try:
            if update_in_progress() or xray_update_in_progress():
                raise XPanelError("Сначала дождитесь завершения текущей операции обновления")
            server = get_server()
            info = check_xray_updates(
                channel=channel,
                force=True,
                allow_network=True,
                xray_bin=str(server["xray_bin"]),
            )
            if info.get("error"):
                raise XPanelError(str(info["error"]))
            channel_name = "предварительная" if channel == "prerelease" else "стабильная"
            if info.get("available"):
                flash(
                    f"Доступна {channel_name} версия Xray {info['latest']}",
                    "success",
                )
            elif info.get("installed_newer"):
                flash(
                    f"Установленный Xray {info['current']} новее найденной версии {info['latest']}",
                    "success",
                )
            else:
                flash(
                    f"Для канала «{channel_name}» обновление Xray не требуется",
                    "success",
                )
        except (OSError, ValueError, XPanelError) as exc:
            flash(f"Не удалось проверить Xray: {exc}", "error")
        return redirect(url_for("updates_page", xray_channel=channel))

    @app.post("/updates/xray/start")
    @login_required
    def xray_updates_start():
        channel = request.form.get("channel", "stable").strip().lower()
        try:
            if update_in_progress() or xray_update_in_progress():
                raise XPanelError("Сначала дождитесь завершения текущей операции обновления")
            server = get_server()
            info = check_xray_updates(
                channel=channel,
                force=True,
                allow_network=True,
                xray_bin=str(server["xray_bin"]),
            )
            if info.get("error"):
                raise XPanelError(str(info["error"]))
            version = request.form.get("version", "").strip()
            if not info.get("available") or version != str(info.get("latest") or ""):
                raise ValueError(
                    "Данные о версии Xray изменились. Сначала повторите проверку"
                )
            result = start_xray_update(
                version,
                channel,
                xray_bin=str(server["xray_bin"]),
                config_path=str(server["config_path"]),
                xray_service=str(server["xray_service"]),
            )
            flash(
                f"Обновление Xray до {result['version']} запущено. Следите за журналом Xray.",
                "success",
            )
        except (OSError, ValueError, PermissionError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("updates_page", watch="xray", xray_channel=channel))

    @app.get("/updates/xray/status")
    @login_required
    def xray_updates_status():
        return Response(
            json.dumps(get_xray_update_status(), ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )

    @app.get("/help")
    @login_required
    def help_page():
        return render_template("help.html")

    @app.get("/diagnostics")
    @login_required
    def diagnostics_page():
        return render_template("diagnostics.html", diagnostics=get_diagnostics())

    @app.get("/diagnostics/report")
    @login_required
    def diagnostics_download():
        report = diagnostic_report()
        return Response(
            report,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=sg-panel-diagnostic.txt"},
        )

    @app.get("/dns")
    @login_required
    def dns_page():
        return render_template(
            "dns.html", settings=get_dns_settings(), servers=list_dns_servers(),
            hosts=list_dns_hosts(), preview=preview_dns_json(), routing=get_routing_settings(),
        )

    @app.get("/dns/json")
    @login_required
    def dns_json_page():
        return render_template(
            "section_json.html",
            page_title="DNS JSON",
            page_section="DNS / JSON",
            page_heading="JSON DNS",
            page_subtitle="Серверы, hosts и глобальные параметры DNS",
            kicker="CONTEXT JSON",
            card_title="DNS fragment",
            description=(
                "Редактор работает с фактическим DNS-фрагментом Xray. Блок _sgPanel "
                "хранит состояние раздела и удаляется из итогового config.json."
            ),
            json_label="Объект dns",
            json_config=dns_json_document(),
            form_action=url_for("dns_json_save"),
            back_url=url_for("dns_page"),
        )

    @app.post("/dns/json")
    @login_required
    def dns_json_save():
        scope = "dns:json"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope,
                lambda: update_dns_json_document(source),
                message="DNS JSON и итоговый config.json успешно проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            result = update_dns_json_document(source)
            apply_saved_change(
                f"DNS JSON сохранён: {result['servers']} серверов, "
                f"{result['hosts']} hosts-записей"
            )
            return redirect(url_for("dns_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "section_json.html",
                page_title="DNS JSON",
                page_section="DNS / JSON",
                page_heading="JSON DNS",
                page_subtitle="Серверы, hosts и глобальные параметры DNS",
                kicker="CONTEXT JSON",
                card_title="DNS fragment",
                description="Исправьте JSON и выполните проверку заново.",
                json_label="Объект dns",
                json_config=source,
                form_action=url_for("dns_json_save"),
                back_url=url_for("dns_page"),
            ), 400

    def dns_settings_form_values() -> dict[str, object]:
        return {
            "enabled": "enabled" in request.form,
            "query_strategy": request.form.get("query_strategy", "UseIPv4"),
            "disable_cache": "disable_cache" in request.form,
            "disable_fallback": "disable_fallback" in request.form,
            "disable_fallback_if_match": "disable_fallback_if_match" in request.form,
            "enable_parallel_query": "enable_parallel_query" in request.form,
            "use_system_hosts": "use_system_hosts" in request.form,
        }

    @app.post("/dns/settings")
    @login_required
    def dns_settings_save():
        scope = "dns:settings"
        try:
            values = dns_settings_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope,
                    lambda: update_dns_settings(**values),
                    message="Настройки DNS и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            update_dns_settings(**values)
            apply_saved_change("Настройки DNS сохранены")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    def dns_server_form_values() -> dict:
        return {
            "name": request.form.get("name", ""), "address": request.form.get("address", ""),
            "priority": int(request.form.get("priority", "100")),
            "domains": request.form.get("domains", ""),
            "expected_ips": request.form.get("expected_ips", ""),
            "unexpected_ips": request.form.get("unexpected_ips", ""),
            "query_strategy": request.form.get("query_strategy", ""),
            "skip_fallback": "skip_fallback" in request.form,
            "final_query": "final_query" in request.form,
            "timeout_ms": int(request.form.get("timeout_ms", "4000")),
        }

    @app.post("/dns/servers/add")
    @login_required
    def dns_server_add():
        scope = "dns:server:add"
        try:
            values = dns_server_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: add_dns_server(**values),
                    message="DNS-сервер и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            row = add_dns_server(**values)
            apply_saved_change(f"DNS-сервер {row['name']} добавлен")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.get("/dns/servers/<int:server_id>/edit")
    @login_required
    def dns_server_edit_page(server_id: int):
        return render_template("dns_server_edit.html", server=find_dns_server(server_id))

    @app.post("/dns/servers/<int:server_id>/edit")
    @login_required
    def dns_server_edit(server_id: int):
        scope = f"dns:server:{server_id}"
        try:
            values = dns_server_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: update_dns_server(server_id, **values),
                    message="DNS-сервер и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            row = update_dns_server(server_id, **values)
            apply_saved_change(f"DNS-сервер {row['name']} обновлён")
            return redirect(url_for("dns_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dns_server_edit_page", server_id=server_id))

    @app.post("/dns/servers/<int:server_id>/toggle")
    @login_required
    def dns_server_toggle(server_id: int):
        try:
            current = find_dns_server(server_id)
            target_enabled = not bool(current["enabled"])
            _preflight_change(lambda: set_dns_server_enabled(server_id, target_enabled))
            row = set_dns_server_enabled(server_id, target_enabled)
            apply_saved_change(
                f"DNS-сервер {row['name']}: "
                f"{'включён' if row['enabled'] else 'отключён'}"
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.post("/dns/servers/<int:server_id>/delete")
    @login_required
    def dns_server_delete(server_id: int):
        try:
            _preflight_change(lambda: delete_dns_server(server_id))
            row = delete_dns_server(server_id)
            apply_saved_change(f"DNS-сервер {row['name']} удалён")
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.post("/dns/hosts/add")
    @login_required
    def dns_host_add():
        scope = "dns:host:add"
        values = {
            "domain": request.form.get("domain", ""),
            "addresses": request.form.get("addresses", ""),
        }
        try:
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: add_dns_host(**values),
                    message="Hosts-запись и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            row = add_dns_host(**values)
            apply_saved_change(f"Hosts-запись {row['domain']} добавлена")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.post("/dns/hosts/<int:host_id>/edit")
    @login_required
    def dns_host_edit(host_id: int):
        scope = f"dns:host:{host_id}"
        values = {
            "domain": request.form.get("domain", ""),
            "addresses": request.form.get("addresses", ""),
        }
        try:
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: update_dns_host(host_id, **values),
                    message="Hosts-запись и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            row = update_dns_host(host_id, **values)
            apply_saved_change(f"Hosts-запись {row['domain']} обновлена")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.post("/dns/hosts/<int:host_id>/toggle")
    @login_required
    def dns_host_toggle(host_id: int):
        try:
            current = find_dns_host(host_id)
            target_enabled = not bool(current["enabled"])
            _preflight_change(lambda: set_dns_host_enabled(host_id, target_enabled))
            row = set_dns_host_enabled(host_id, target_enabled)
            apply_saved_change(
                f"Hosts-запись {row['domain']}: "
                f"{'включена' if row['enabled'] else 'отключена'}"
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.post("/dns/hosts/<int:host_id>/delete")
    @login_required
    def dns_host_delete(host_id: int):
        try:
            _preflight_change(lambda: delete_dns_host(host_id))
            row = delete_dns_host(host_id)
            apply_saved_change(f"Hosts-запись {row['domain']} удалена")
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.post("/dns/test")
    @login_required
    def dns_test():
        try:
            result = test_dns_resolution(request.form.get("domain", "example.com"))
            if result["ok"]:
                flash(f"Системный DNS: {result['domain']} → {', '.join(result['addresses'])} ({result['latency_ms']} ms)", "success")
            else:
                flash(f"Системный DNS: {result['detail']}", "error")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("dns_page"))

    @app.get("/routing")
    @login_required
    def routing_page():
        return render_template(
            "routing.html",
            settings=get_routing_settings(),
            rules=list_routing_rules(),
            outbound_tags=list_outbound_tags(enabled_only=True),
            balancer_tags=list_balancer_tags(),
            geodata=get_geodata_status(),
            format_bytes=format_bytes,
            users=list_users(),
            warp=get_warp_overview(),
        )

    def routing_settings_form_values() -> dict[str, object]:
        return {
            "domain_strategy": request.form.get("domain_strategy", "AsIs"),
            "sniffing_enabled": "sniffing_enabled" in request.form,
            "sniffing_route_only": "sniffing_route_only" in request.form,
            "sniff_http": "sniff_http" in request.form,
            "sniff_tls": "sniff_tls" in request.form,
            "sniff_quic": "sniff_quic" in request.form,
            "default_outbound_tag": request.form.get("default_outbound_tag", "direct"),
        }

    @app.post("/routing/settings")
    @login_required
    def routing_settings_save():
        scope = "routing:settings"
        try:
            values = routing_settings_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: update_routing_settings(**values),
                    message="Настройки Routing и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            update_routing_settings(**values)
            apply_saved_change("Настройки Routing сохранены")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("routing_page"))

    def rule_form_values() -> dict:
        return {
            "name": request.form.get("name", ""),
            "priority": int(request.form.get("priority", "100")),
            "outbound_tag": request.form.get("outbound_tag", "blocked"),
            "target_type": request.form.get("target_type", "outbound"),
            "domains": request.form.get("domains", ""),
            "ips": request.form.get("ips", ""),
            "ports": request.form.get("ports", ""),
            "network": request.form.get("network", ""),
            "protocols": request.form.get("protocols", ""),
            "inbound_tags": request.form.get("inbound_tags", ""),
            "users": "\n".join(request.form.getlist("users")),
        }

    @app.get("/routing/json")
    @login_required
    def routing_json_page():
        return render_template("routing_json.html", routing_json=routing_json_document())

    @app.post("/routing/json")
    @login_required
    def routing_json_save():
        scope = "routing:json"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: update_routing_json_document(source),
                message="Routing JSON и итоговый config.json успешно проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            result = update_routing_json_document(source)
            apply_saved_change(
                f"JSON Routing сохранён: {result['rules']} правил, "
                f"{result['balancers']} балансировщиков"
            )
            return redirect(url_for("routing_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template("routing_json.html", routing_json=source), 400

    @app.post("/routing/presets/add")
    @login_required
    def routing_geo_preset_add():
        scope = "routing:geo-preset"
        values = {
            "kind": request.form.get("kind", ""),
            "value": request.form.get("value", ""),
            "outbound_tag": request.form.get("outbound_tag", "direct"),
            "priority": int(request.form.get("priority", "100")),
            "name": request.form.get("name", ""),
        }
        try:
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: add_geo_policy(**values),
                    message="Гео-правила и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            rows = add_geo_policy(**values)
            apply_saved_change(
                "Добавлены гео-правила: "
                + ", ".join(str(row["name"]) for row in rows)
            )
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("routing_page"))

    @app.get("/routing/rules/json/new")
    @login_required
    def routing_rule_json_new_page():
        return render_template(
            "rule_json.html", rule=None, rule_json=rule_json_document(None)
        )

    @app.post("/routing/rules/json/new")
    @login_required
    def routing_rule_json_add():
        scope = "routing:rule-json:add"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: add_routing_rule_json(source),
                message="JSON правила и итоговый config.json проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            row = add_routing_rule_json(source)
            apply_saved_change(f"Правило {row['name']} создано из JSON")
            return redirect(url_for("routing_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "rule_json.html", rule=None, rule_json=source
            ), 400

    @app.get("/routing/rules/<int:rule_id>/json")
    @login_required
    def routing_rule_json_edit_page(rule_id: int):
        row = find_routing_rule(rule_id)
        return render_template(
            "rule_json.html", rule=row, rule_json=rule_json_document(row)
        )

    @app.post("/routing/rules/<int:rule_id>/json")
    @login_required
    def routing_rule_json_edit(rule_id: int):
        scope = f"routing:rule-json:{rule_id}"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: update_routing_rule_json(rule_id, source),
                message="JSON правила и итоговый config.json проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            row = update_routing_rule_json(rule_id, source)
            apply_saved_change(f"JSON правила {row['name']} сохранён")
            return redirect(url_for("routing_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "rule_json.html",
                rule=find_routing_rule(rule_id),
                rule_json=source,
            ), 400

    @app.post("/routing/rules/add")
    @login_required
    def routing_rule_add():
        scope = "routing:rule:add"
        try:
            values = rule_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: add_routing_rule(**values),
                    message="Правило и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            rule = add_routing_rule(**values)
            apply_saved_change(f"Правило {rule['name']} добавлено")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("routing_page"))

    @app.get("/routing/rules/<int:rule_id>/edit")
    @login_required
    def routing_rule_edit_page(rule_id: int):
        return render_template(
            "rule_edit.html",
            rule=find_routing_rule(rule_id),
            outbound_tags=list_outbound_tags(enabled_only=True),
            balancer_tags=list_balancer_tags(),
            users=list_users(),
        )

    @app.post("/routing/rules/<int:rule_id>/edit")
    @login_required
    def routing_rule_edit(rule_id: int):
        scope = f"routing:rule:{rule_id}"
        try:
            values = rule_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: update_routing_rule(rule_id, **values),
                    message="Правило и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            rule = update_routing_rule(rule_id, **values)
            apply_saved_change(f"Правило {rule['name']} обновлено")
            return redirect(url_for("routing_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("routing_rule_edit_page", rule_id=rule_id))

    @app.post("/routing/rules/<int:rule_id>/toggle")
    @login_required
    def routing_rule_toggle(rule_id: int):
        try:
            current = find_routing_rule(rule_id)
            target_enabled = not bool(current["enabled"])
            _preflight_change(lambda: set_routing_rule_enabled(rule_id, target_enabled))
            updated = set_routing_rule_enabled(rule_id, target_enabled)
            apply_saved_change(
                f"Правило {updated['name']}: "
                f"{'включено' if updated['enabled'] else 'отключено'}"
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("routing_page"))

    @app.post("/routing/rules/<int:rule_id>/delete")
    @login_required
    def routing_rule_delete(rule_id: int):
        try:
            _preflight_change(lambda: delete_routing_rule(rule_id))
            rule = delete_routing_rule(rule_id)
            apply_saved_change(f"Правило {rule['name']} удалено")
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("routing_page"))

    @app.get("/cascade")
    @login_required
    def cascade_page():
        return render_template("cascade.html", cascade=get_cascade_overview())

    @app.post("/cascade/access/create")
    @login_required
    def cascade_access_create():
        try:
            _preflight_change(ensure_cascade_service_access)
            ensure_cascade_service_access()
            apply_saved_change("Служебный доступ Cascade создан")
            flash("Ссылка для выходного сервера готова.", "success")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.post("/cascade/import")
    @login_required
    def cascade_import():
        link = request.form.get("vless_link", "")
        try:
            _preflight_change(lambda: import_cascade_link(link))
            import_cascade_link(link)
            apply_saved_change("Выходной сервер Cascade подключён")
            result = test_cascade()
            flash(f"Выходной сервер проверен. Выходной IP: {result['ip']}", "success")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.post("/cascade/reset")
    @login_required
    def cascade_reset():
        try:
            _preflight_change(remove_cascade)
            remove_cascade()
            apply_saved_change("Cascade удалён; основной выход direct")
            flash("Cascade удалён с этого сервера.", "success")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.post("/cascade/select")
    @login_required
    def cascade_select():
        try:
            outbound_id = int(request.form.get("outbound_id", "0"))
            select_cascade_outbound(outbound_id)
            flash("Выход выбран. Теперь выполните полную проверку каскада.", "success")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.post("/cascade/test")
    @login_required
    def cascade_test():
        try:
            result = test_cascade()
            extra = []
            if result.get("country"):
                extra.append(str(result["country"]))
            if result.get("colo"):
                extra.append(f"colo {result['colo']}")
            if result.get("warp") in {"on", "plus"}:
                extra.append(f"WARP {result['warp']}")
            suffix = f" ({', '.join(extra)})" if extra else ""
            flash(f"Каскад проверен. Выходной IP: {result['ip']}{suffix}", "success")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.post("/cascade/enable")
    @login_required
    def cascade_enable():
        try:
            _preflight_change(lambda: set_cascade_enabled(True))
            set_cascade_enabled(True)
            apply_saved_change("Каскад включён")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.post("/cascade/disable")
    @login_required
    def cascade_disable():
        try:
            _preflight_change(lambda: set_cascade_enabled(False))
            set_cascade_enabled(False)
            apply_saved_change("Каскад отключён; основной выход возвращён на direct")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("cascade_page"))

    @app.get("/outbounds")
    @login_required
    def outbounds_page():
        settings = get_routing_settings()
        return render_template(
            "outbounds.html",
            outbounds=list_outbounds(),
            default_outbound_tag=settings["default_outbound_tag"],
            warp=get_warp_overview(),
        )

    @app.get("/warp/json")
    @login_required
    def warp_json_page():
        try:
            source = warp_json_document()
        except XPanelError as exc:
            flash(str(exc), "error")
            return redirect(url_for("outbounds_page"))
        return render_template(
            "section_json.html",
            page_title="WARP JSON",
            page_section="OUTBOUNDS / WARP / JSON",
            page_heading="JSON WARP Outbound",
            page_subtitle="WireGuard outbound и политика его использования",
            kicker="CONTEXT JSON",
            card_title="Cloudflare WARP",
            description=(
                "Secret key остаётся в локальной панели. Перед сохранением JSON "
                "нормализуется и весь config.json проходит xray run -test."
            ),
            json_label="Объект WARP outbound",
            json_config=source,
            form_action=url_for("warp_json_save"),
            back_url=url_for("outbounds_page"),
        )

    @app.post("/warp/json")
    @login_required
    def warp_json_save():
        scope = "warp:json"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: update_warp_json_document(source),
                message="WARP JSON и итоговый config.json успешно проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            update_warp_json_document(source)
            apply_saved_change("WARP JSON сохранён")
            return redirect(url_for("outbounds_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "section_json.html",
                page_title="WARP JSON",
                page_section="OUTBOUNDS / WARP / JSON",
                page_heading="JSON WARP Outbound",
                page_subtitle="WireGuard outbound и политика его использования",
                kicker="CONTEXT JSON",
                card_title="Cloudflare WARP",
                description="Исправьте JSON и выполните проверку заново.",
                json_label="Объект WARP outbound",
                json_config=source,
                form_action=url_for("warp_json_save"),
                back_url=url_for("outbounds_page"),
            ), 400

    @app.post("/warp/create")
    @login_required
    def warp_create():
        try:
            create_warp()
            apply_saved_change("WARP Outbound создан и включён")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/warp/regenerate")
    @login_required
    def warp_regenerate():
        try:
            create_warp(regenerate=True)
            apply_saved_change("Учётные данные WARP пересозданы")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/warp/toggle")
    @login_required
    def warp_toggle():
        try:
            current = get_warp_overview()
            target_enabled = not bool(current["enabled"])
            _preflight_change(lambda: set_warp_enabled(target_enabled))
            updated = set_warp_enabled(target_enabled)
            state = "включён" if updated["enabled"] else "отключён"
            apply_saved_change(f"WARP {state}")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/warp/delete")
    @login_required
    def warp_delete():
        try:
            delete_warp()
            apply_saved_change("WARP удалён")
        except (XPanelError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/warp/routing")
    @login_required
    def warp_routing():
        scope = "warp:routing"
        mode = request.form.get("route_mode", "off")
        selected_domains = request.form.get("selected_domains", "")
        selected_ips = request.form.get("selected_ips", "")
        try:
            if _is_validation_action():
                return _validation_response(
                    scope,
                    lambda: configure_warp_routing(mode, selected_domains, selected_ips),
                    message="Маршрут WARP и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            configure_warp_routing(mode, selected_domains, selected_ips)
            apply_saved_change("Маршрут WARP сохранён")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("routing_page"))

    @app.post("/warp/test")
    @login_required
    def warp_test():
        try:
            result = test_warp()
            flash(result["detail"], "success")
        except (ValueError, XPanelError, FileNotFoundError, OSError, PermissionError) as exc:
            flash(str(exc), "error")
        target = "diagnostics_page" if request.form.get("next") == "diagnostics" else "outbounds_page"
        return redirect(url_for(target))

    def outbound_form_values() -> dict:
        return {
            "tag": request.form.get("tag", ""),
            "name": request.form.get("name", ""),
            "address": request.form.get("address", ""),
            "port": int(request.form.get("port", "443")),
            "user_uuid": request.form.get("uuid", ""),
            "flow": request.form.get("flow", ""),
            "network": request.form.get("network", "raw"),
            "security": request.form.get("security", "reality"),
            "server_name": request.form.get("server_name", ""),
            "public_key": request.form.get("public_key", ""),
            "short_id": request.form.get("short_id", ""),
            "fingerprint": request.form.get("fingerprint", "firefox"),
            "spider_x": request.form.get("spider_x", ""),
            "xhttp_host": request.form.get("xhttp_host", ""),
            "xhttp_path": request.form.get("xhttp_path", "/"),
            "xhttp_mode": request.form.get("xhttp_mode", "auto"),
            "allow_insecure": request.form.get("allow_insecure") == "on",
            "alpn": request.form.get("alpn", ""),
        }

    @app.post("/outbounds/import-vless")
    @login_required
    def outbound_import_vless():
        try:
            values = parse_vless_share_link(request.form.get("vless_link", ""))
            return jsonify({"ok": True, "outbound": values})
        except (ValueError, XPanelError) as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

    @app.get("/outbounds/json/new")
    @login_required
    def outbound_json_new_page():
        return render_template(
            "outbound_json.html", outbound=None, outbound_json=outbound_json_document(None)
        )

    @app.post("/outbounds/json/new")
    @login_required
    def outbound_json_add():
        scope = "outbound:json:add"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: add_vless_outbound_json(source),
                message="Outbound JSON и итоговый config.json проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            row = add_vless_outbound_json(source)
            apply_saved_change(f"JSON Outbound {row['tag']} создан")
            return redirect(url_for("outbounds_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "outbound_json.html", outbound=None, outbound_json=source
            ), 400

    @app.get("/outbounds/<int:outbound_id>/json")
    @login_required
    def outbound_json_edit_page(outbound_id: int):
        row = find_outbound(outbound_id)
        return render_template(
            "outbound_json.html", outbound=row, outbound_json=outbound_json_document(row)
        )

    @app.post("/outbounds/<int:outbound_id>/json")
    @login_required
    def outbound_json_edit(outbound_id: int):
        scope = f"outbound:json:{outbound_id}"
        source = request.form.get("json_config", "")
        if _is_validation_action():
            return _validation_response(
                scope, lambda: update_vless_outbound_json(outbound_id, source),
                message="Outbound JSON и итоговый config.json проверены.",
            )
        try:
            _require_validation_token(scope, _draft_payload())
            row = update_vless_outbound_json(outbound_id, source)
            apply_saved_change(f"JSON Outbound {row['tag']} сохранён")
            return redirect(url_for("outbounds_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return render_template(
                "outbound_json.html",
                outbound=find_outbound(outbound_id),
                outbound_json=source,
            ), 400

    @app.post("/outbounds/add")
    @login_required
    def outbound_add():
        scope = "outbound:add"
        try:
            values = outbound_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: add_vless_outbound(**values),
                    message="Outbound и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            outbound = add_vless_outbound(**values)
            apply_saved_change(f"Outbound {outbound['tag']} добавлен")
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.get("/outbounds/<int:outbound_id>/edit")
    @login_required
    def outbound_edit_page(outbound_id: int):
        return render_template("outbound_edit.html", outbound=find_outbound(outbound_id))

    @app.post("/outbounds/<int:outbound_id>/edit")
    @login_required
    def outbound_edit(outbound_id: int):
        scope = f"outbound:{outbound_id}"
        try:
            values = outbound_form_values()
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: update_vless_outbound(outbound_id, **values),
                    message="Outbound и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            outbound = update_vless_outbound(outbound_id, **values)
            apply_saved_change(f"Outbound {outbound['tag']} обновлён")
            return redirect(url_for("outbounds_page"))
        except (ValueError, XPanelError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("outbound_edit_page", outbound_id=outbound_id))

    @app.post("/outbounds/<int:outbound_id>/toggle")
    @login_required
    def outbound_toggle(outbound_id: int):
        try:
            current = find_outbound(outbound_id)
            target_enabled = not bool(current["enabled"])
            _preflight_change(lambda: set_outbound_enabled(outbound_id, target_enabled))
            updated = set_outbound_enabled(outbound_id, target_enabled)
            apply_saved_change(
                f"Outbound {updated['tag']}: "
                f"{'включён' if updated['enabled'] else 'отключён'}"
            )
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/outbounds/<int:outbound_id>/delete")
    @login_required
    def outbound_delete(outbound_id: int):
        try:
            _preflight_change(lambda: delete_outbound(outbound_id))
            outbound = delete_outbound(outbound_id)
            apply_saved_change(f"Outbound {outbound['tag']} удалён")
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("outbounds_page"))

    @app.post("/outbounds/<int:outbound_id>/test")
    @login_required
    def outbound_test(outbound_id: int):
        result = test_outbound_tcp(outbound_id)
        outbound = find_outbound(outbound_id)
        if result["ok"]:
            flash(f"{outbound['tag']}: TCP-порт доступен, {result['latency_ms']} ms. Это не проверка UUID/Reality.", "success")
        else:
            flash(f"{outbound['tag']}: TCP-порт недоступен: {result['detail']}", "error")
        return redirect(url_for("outbounds_page"))


    def _panel_node_base_url() -> str:
        state = _panel_access_state(request.host.split(":", 1)[0])
        url = str(state.get("url") or request.url_root.rstrip("/"))
        return url.rstrip("/")

    def _single_line_script_command(script_url: str, arguments: str, filename: str) -> str:
        quoted_url = shlex.quote(script_url)
        quoted_name = shlex.quote(filename)
        # This remains one copy/paste command. On a minimal clean Ubuntu it
        # installs curl itself before downloading the signed release script.
        bootstrap = (
            "set -Eeuo pipefail; export DEBIAN_FRONTEND=noninteractive; "
            "if ! command -v curl >/dev/null 2>&1; then "
            "apt-get update -qq && apt-get install -y -qq ca-certificates curl; fi; "
            f"tmp=$(mktemp /tmp/{quoted_name}.XXXXXX); "
            "trap 'rm -f \"$tmp\"' EXIT; "
            f"curl -fsSL --retry 5 --retry-delay 2 {quoted_url} -o \"$tmp\"; "
            "bash -n \"$tmp\"; chmod 700 \"$tmp\"; "
            f"bash \"$tmp\" {arguments}"
        )
        return "sudo bash -c " + shlex.quote(bootstrap)

    def _node_prepare_command() -> str:
        base = _panel_node_base_url()
        return _single_line_script_command(
            base + "/node/install-sg-node.sh",
            "--panel " + shlex.quote(base),
            "install-sg-node",
        )

    def _node_install_command(token: str) -> str:
        base = _panel_node_base_url()
        arguments = "--panel " + shlex.quote(base) + " --token " + shlex.quote(token)
        return _single_line_script_command(
            base + "/node/connect.sh",
            arguments,
            "connect-sg-node",
        )

    def _node_request_public_address() -> str:
        remote = (request.remote_addr or "").strip()
        candidates: list[str] = []
        if remote in {"127.0.0.1", "::1"}:
            if request.headers.get("CF-Ray", "").strip():
                candidates.append(request.headers.get("CF-Connecting-IP", "").strip())
            candidates.append(request.headers.get("X-Real-IP", "").strip())
            candidates.append(request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip())
        candidates.append(remote)
        for candidate in candidates:
            if not candidate:
                continue
            try:
                if ipaddress.ip_address(candidate).is_global:
                    return candidate
            except ValueError:
                continue
        return ""

    def _node_metadata_with_request_address(metadata: object) -> dict[str, object]:
        cleaned = dict(metadata) if isinstance(metadata, dict) else {}
        if not str(cleaned.get("public_address") or "").strip():
            detected = _node_request_public_address()
            if detected:
                cleaned["public_address"] = detected
        return cleaned

    def _node_runtime_command() -> str:
        # Kept only for compatibility with older installed nodes.
        base = _panel_node_base_url()
        installer_url = shlex.quote(base + "/node/runtime.sh")
        return (
            f"curl -fsSL {installer_url} -o /tmp/02-install-node-runtime.sh && "
            f"bash -n /tmp/02-install-node-runtime.sh && chmod 700 /tmp/02-install-node-runtime.sh && "
            f"sudo bash /tmp/02-install-node-runtime.sh"
        )

    def _node_update_command() -> str:
        return _node_prepare_command()

    def _node_uninstall_command() -> str:
        base = _panel_node_base_url()
        uninstaller_url = shlex.quote(base + "/node/uninstall.sh")
        return (
            f"curl -fsSL {uninstaller_url} -o /tmp/uninstall-sg-node.sh && "
            f"bash -n /tmp/uninstall-sg-node.sh && chmod 700 /tmp/uninstall-sg-node.sh && "
            f"sudo bash /tmp/uninstall-sg-node.sh --yes"
        )

    def _local_node_overlay(nodes: list[dict[str, object]]) -> list[dict[str, object]]:
        try:
            status = get_status()
        except Exception:
            status = {}
        for node in nodes:
            if not node.get("is_local"):
                continue
            system = status.get("system") if isinstance(status, dict) else {}
            if not isinstance(system, dict):
                system = {}
            node["effective_state"] = "online" if status.get("overall_ok") else "offline"
            node["state_label"] = "В сети" if status.get("overall_ok") else "Требуется проверка"
            node["agent_state"] = "active"
            node["worker_version"] = "локальный режим"
            node["worker_state"] = "active"
            node["xray_version"] = str(system.get("xray_version") or "")
            node["xray_state"] = str(status.get("service") or "unknown")
            node["nginx_state"] = "unknown"
            node["inbound_profile"] = str(status.get("inbound_profile_label") or "")
            node["client_count"] = int(status.get("enabled_users") or 0)
            node["cpu_percent"] = system.get("cpu_percent")
            node["memory_percent"] = system.get("memory_percent")
            node["disk_percent"] = system.get("disk_percent")
            node["last_seen_age"] = "Сейчас"
            node["last_error"] = str(status.get("config_detail") or "") if not status.get("overall_ok") else ""
        return nodes

    def _node_detail_template_context(
        node: dict[str, object],
        *,
        enrollment: dict[str, object] | None = None,
        install_command: str = "",
    ) -> dict[str, object]:
        defaults = get_server()
        reality_target = str(defaults["dest"] or "www.microsoft.com:443").strip()
        reality_sni = reality_target.rsplit(":", 1)[0] if ":" in reality_target else reality_target
        deployments = list_node_deployments(int(node["id"]))
        node_connected = bool(not node.get("is_local") and node.get("effective_state") == "online")
        xray_state = str(node.get("xray_state") or "").strip()
        node_ready_for_profile = bool(
            node_connected
            and (str(node.get("xray_version") or "").strip() or xray_state in {"active", "inactive", "failed"})
        )
        first_profile_pending = bool(node_connected and not deployments and not str(node.get("inbound_profile") or "").strip())
        return {
            "node": node,
            "node_connected": node_connected,
            "node_ready_for_profile": node_ready_for_profile,
            "first_profile_pending": first_profile_pending,
            "events": list_node_events(int(node["id"])),
            "jobs": list_node_jobs(int(node["id"])),
            "deployments": deployments,
            "users": [row for row in list_users() if bool(row["enabled"])],
            "server_defaults": defaults,
            "reality_default_server_name": reality_sni,
            "roles": NODE_ROLE_LABELS,
            "enrollment": enrollment,
            "install_command": install_command,
            "panel_url": _panel_node_base_url(),
            "prepare_command": _node_prepare_command(),
            "runtime_command": _node_runtime_command(),
            "update_command": _node_update_command(),
            "uninstall_command": _node_uninstall_command(),
        }

    def _config_without_user(config: dict[str, object], user_uuid: str) -> tuple[dict[str, object], int]:
        candidate = json.loads(json.dumps(config))
        removed = 0
        inbounds = candidate.get("inbounds") if isinstance(candidate, dict) else None
        if not isinstance(inbounds, list):
            raise ValueError("На ноде не найден список Inbound")
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            settings = inbound.get("settings")
            if not isinstance(settings, dict):
                continue
            for key in ("clients", "users"):
                values = settings.get(key)
                if not isinstance(values, list):
                    continue
                kept = []
                for value in values:
                    if not isinstance(value, dict):
                        kept.append(value)
                        continue
                    identity = str(value.get("id") or value.get("uuid") or "")
                    if identity == user_uuid:
                        removed += 1
                    else:
                        kept.append(value)
                settings[key] = kept
        return candidate, removed

    def _finish_ready_user_deletion(request_info: dict[str, object]) -> None:
        if str(request_info.get("status") or "") != "pending":
            return
        user_id = request_info.get("user_id")
        if user_id in (None, ""):
            finish_user_deletion_request(int(request_info["id"]), ok=True)
            return
        try:
            user = find_user(int(user_id))
            # The user was already disabled and removed from the live local Xray
            # configuration before remote cleanup started. Finalization therefore
            # only removes the database identity and subscription metadata.
            delete_user(int(user_id))
            finish_user_deletion_request(int(request_info["id"]), ok=True)
            write_audit(
                "user_deleted_cluster",
                detail=f"user={user['name']} request={request_info['id']}",
                ip_address=request.remote_addr or "node-agent",
                user_agent=request.headers.get("User-Agent", "SG-Node"),
                success=True,
            )
        except Exception as exc:
            finish_user_deletion_request(int(request_info["id"]), ok=False, error=str(exc))


    @app.get("/network/nodes")
    @login_required
    def nodes_page():
        nodes = _local_node_overlay(list_nodes())
        return render_template(
            "nodes.html",
            nodes=nodes,
            summary=network_summary(nodes),
            roles=NODE_ROLE_LABELS,
            panel_url=_panel_node_base_url(),
            prepare_command=_node_prepare_command(),
            uninstall_command=_node_uninstall_command(),
        )

    @app.post("/network/nodes/add")
    @login_required
    def node_add():
        try:
            node = create_node(
                request.form.get("name", ""),
                role=request.form.get("role", "regional"),
                location=request.form.get("location", ""),
                description=request.form.get("description", ""),
                public_address=request.form.get("public_address"),
            )
            enrollment = create_enrollment_token(int(node["id"]))
            return render_template(
                "node_detail.html",
                **_node_detail_template_context(
                    node,
                    enrollment=enrollment,
                    install_command=_node_install_command(str(enrollment["token"])),
                ),
            )
        except (ValueError, sqlite3.Error) as exc:
            flash(str(exc), "error")
            return redirect(url_for("nodes_page"))

    @app.get("/network/nodes/<int:node_id>")
    @login_required
    def node_detail_page(node_id: int):
        try:
            node = find_node(node_id)
        except ValueError:
            abort(404)
        if node.get("is_local"):
            node = next(
                item for item in _local_node_overlay([node]) if int(item["id"]) == node_id
            )
        return render_template(
            "node_detail.html",
            **_node_detail_template_context(node),
        )

    @app.get("/network/nodes/<int:node_id>/live")
    @login_required
    def node_live_status(node_id: int):
        try:
            node = find_node(node_id)
        except ValueError:
            abort(404)
        if node.get("is_local"):
            node = next(
                item for item in _local_node_overlay([node]) if int(item["id"]) == node_id
            )
        jobs = list_node_jobs(node_id)
        return jsonify(
            {
                "ok": True,
                "enrollment_pending": has_active_enrollment(node_id) if not node.get("is_local") else False,
                "node": {
                    "effective_state": node.get("effective_state"),
                    "state_label": node.get("state_label"),
                    "last_seen_age": node.get("last_seen_age"),
                    "public_address": node.get("public_address") or ("Не определён автоматически" if node.get("registered_at") else "Будет определён при подключении"),
                    "platform": (str(node.get("platform") or "") + " " + str(node.get("platform_version") or "")).strip() or "Ещё не получена",
                    "architecture": node.get("architecture") or "—",
                    "agent_version": node.get("agent_version") or ("локальный режим" if node.get("is_local") else "не установлен"),
                    "agent_state": node.get("agent_state") or ("active" if node.get("effective_state") == "online" else "unknown"),
                    "worker_version": node.get("worker_version") or "не определён",
                    "worker_state": node.get("worker_state") or "unknown",
                    "xray_version": node.get("xray_version") or "не определён",
                    "xray_state": node.get("xray_state") or "unknown",
                    "nginx_version": node.get("nginx_version") or "не определён",
                    "nginx_state": node.get("nginx_state") or "unknown",
                    "inbound_profile": node.get("inbound_profile") or "Первый профиль ещё не развёрнут",
                    "first_profile_pending": bool(
                        node.get("effective_state") == "online"
                        and not str(node.get("inbound_profile") or "").strip()
                        and not list_node_deployments(node_id)
                    ),
                    "client_count": node.get("client_count") if node.get("client_count") is not None else "—",
                    "cpu_percent": node.get("cpu_percent"),
                    "memory_percent": node.get("memory_percent"),
                    "disk_percent": node.get("disk_percent"),
                    "load1": node.get("load1"),
                },
                "jobs_html": render_template("_node_jobs.html", jobs=jobs),
                "polling": bool(jobs and jobs[0].get("status") in {"queued", "running"}),
            }
        )

    @app.post("/network/nodes/<int:node_id>/deploy/reality")
    @login_required
    def node_deploy_reality(node_id: int):
        try:
            node = find_node(node_id)
            if node.get("is_local"):
                raise ValueError("Для локального сервера используйте обычный раздел Xray Server")
            if node.get("effective_state") != "online":
                raise ValueError("Нода должна быть в сети")
            xray_version = str(node.get("xray_version") or "").strip()
            xray_state = str(node.get("xray_state") or "").strip()
            if not xray_version and xray_state not in {"active", "inactive", "failed"}:
                raise ValueError("Сначала установите Xray Runtime на ноде")

            user_id = int(request.form.get("user_id", "0") or 0)
            user = find_user(user_id)
            if not bool(user["enabled"]):
                raise ValueError("Выбранный клиент отключён")

            public_host = request.form.get("public_host", "").strip()
            if not public_host or len(public_host) > 255:
                raise ValueError("Укажите публичный IP или домен ноды")
            if any(value in public_host for value in ("/", "?", "#", " ")):
                raise ValueError("Публичный адрес должен быть доменом или IP без протокола")

            port = int(request.form.get("port", "64441") or 64441)
            if not 1 <= port <= 65535:
                raise ValueError("Порт должен быть от 1 до 65535")
            if port in {22, 80, 443, 61443}:
                raise ValueError("Для первой ноды используйте отдельный порт, например 64441")

            defaults = get_server()
            dest = request.form.get("dest", str(defaults["dest"])).strip()
            default_sni = str(defaults["dest"] or "www.microsoft.com:443").rsplit(":", 1)[0]
            server_name = request.form.get("server_name", default_sni).strip()
            if not dest or not server_name:
                raise ValueError("Укажите Reality target и Server Name")

            keys = generate_reality_keys(str(defaults["xray_bin"]))
            short_id = str(keys["short_id"])
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "tag": "sg-node-reality-in",
                        "listen": "0.0.0.0",
                        "port": port,
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": str(user["uuid"]),
                                    "email": str(user["name"]),
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
                                "dest": dest,
                                "xver": 0,
                                "serverNames": [server_name],
                                "privateKey": str(keys["private_key"]),
                                "shortIds": [short_id],
                            },
                        },
                    }
                ],
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom", "settings": {}}
                ],
            }
            encoded = json.dumps(config, ensure_ascii=False, sort_keys=True).encode("utf-8")
            query = urlencode(
                {
                    "encryption": "none",
                    "flow": "xtls-rprx-vision",
                    "security": "reality",
                    "sni": server_name,
                    "fp": "firefox",
                    "pbk": str(keys["public_key"]),
                    "sid": short_id,
                    "type": "tcp",
                }
            )
            label = quote(f"{user['name']}/{node['name']}/Primary", safe="")
            client_link = f"vless://{user['uuid']}@{public_host}:{port}?{query}#{label}"
            create_node_job(
                node_id,
                job_type="apply_xray_config",
                title=f"VLESS REALITY · {user['name']} · TCP {port}",
                payload={
                    "profile": "VLESS REALITY",
                    "config": config,
                    "config_sha256": hashlib.sha256(encoded).hexdigest(),
                    "client_count": 1,
                    "deployment": {
                        "action": "upsert",
                        "user_id": int(user["id"]),
                        "user_uuid": str(user["uuid"]),
                        "user_name": str(user["name"]),
                        "profile": "VLESS REALITY",
                        "public_host": public_host,
                        "public_port": port,
                    },
                },
                client_link=client_link,
            )
            flash(
                "Задание отправлено ноде. Она проверит конфигурацию, применит её и выполнит rollback при ошибке.",
                "success",
            )
        except (ValueError, XPanelError, OSError, sqlite3.Error) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/network/nodes/<int:node_id>/edit")
    @login_required
    def node_edit(node_id: int):
        try:
            update_node(
                node_id,
                name=request.form.get("name", ""),
                role=request.form.get("role", "regional"),
                location=request.form.get("location", ""),
                description=request.form.get("description", ""),
                public_address=request.form.get("public_address"),
            )
            flash("Карточка сервера обновлена", "success")
        except (ValueError, sqlite3.Error) as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/network/nodes/<int:node_id>/enrollment")
    @login_required
    def node_enrollment_create(node_id: int):
        try:
            node = find_node(node_id)
            if node.get("effective_state") == "revoked":
                restore_node(node_id)
                node = find_node(node_id)
            enrollment = create_enrollment_token(node_id)
            return render_template(
                "node_detail.html",
                **_node_detail_template_context(
                    node,
                    enrollment=enrollment,
                    install_command=_node_install_command(str(enrollment["token"])),
                ),
            )
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/network/nodes/<int:node_id>/revoke")
    @login_required
    def node_revoke(node_id: int):
        try:
            revoke_node(node_id)
            flash("Доступ сервера отозван", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/network/nodes/<int:node_id>/restore")
    @login_required
    def node_restore(node_id: int):
        try:
            restore_node(node_id)
            flash("Сервер снова ожидает подключения", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("node_detail_page", node_id=node_id))

    @app.post("/network/nodes/<int:node_id>/delete")
    @login_required
    def node_delete(node_id: int):
        try:
            node = find_node(node_id)
            active_jobs = [
                item for item in list_node_jobs(node_id)
                if str(item.get("status") or "") in {"queued", "running"}
            ]
            if active_jobs:
                raise ValueError("Дождитесь завершения текущего задания ноды")
            revoke_node(node_id) if node.get("registered_at") else None
            delete_node(node_id)
            flash("Сервер удалён из Cluster. Xray на удалённой машине не изменён.", "success")
            return redirect(url_for("nodes_page"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("node_detail_page", node_id=node_id))

    @app.get("/node/install-sg-node.sh")
    def node_full_installer():
        if not NODE_FULL_INSTALLER.exists():
            abort(404)
        return Response(
            NODE_FULL_INSTALLER.read_text(encoding="utf-8"),
            content_type="text/x-shellscript; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/node/connect.sh")
    def node_connect_installer():
        if not NODE_CONNECT_INSTALLER.exists():
            abort(404)
        return Response(
            NODE_CONNECT_INSTALLER.read_text(encoding="utf-8"),
            content_type="text/x-shellscript; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/node/install.sh")
    def node_agent_installer():
        if not NODE_AGENT_INSTALLER.exists():
            abort(404)
        return Response(
            NODE_AGENT_INSTALLER.read_text(encoding="utf-8"),
            content_type="text/x-shellscript; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/node/runtime.sh")
    def node_runtime_installer():
        if not NODE_RUNTIME_INSTALLER.exists():
            abort(404)
        return Response(
            NODE_RUNTIME_INSTALLER.read_text(encoding="utf-8"),
            content_type="text/x-shellscript; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/node/agent.py")
    def node_agent_source():
        if not NODE_AGENT_SOURCE.exists():
            abort(404)
        return Response(
            NODE_AGENT_SOURCE.read_text(encoding="utf-8"),
            content_type="text/x-python; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/node/worker.py")
    def node_worker_source():
        if not NODE_WORKER_SOURCE.exists():
            abort(404)
        return Response(
            NODE_WORKER_SOURCE.read_text(encoding="utf-8"),
            content_type="text/x-python; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/node/uninstall.sh")
    def node_agent_uninstaller():
        if not NODE_AGENT_UNINSTALLER.exists():
            abort(404)
        return Response(
            NODE_AGENT_UNINSTALLER.read_text(encoding="utf-8"),
            content_type="text/x-shellscript; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/node/v1/register")
    def node_api_register():
        payload = request.get_json(silent=True) or {}
        try:
            result = register_node(
                str(payload.get("enrollment_token") or ""),
                agent_id=str(payload.get("agent_id") or ""),
                metadata=_node_metadata_with_request_address(payload.get("metadata")),
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, **result})

    @app.post("/api/node/v1/heartbeat")
    def node_api_heartbeat():
        authorization = request.headers.get("Authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        payload = request.get_json(silent=True) or {}
        try:
            result = heartbeat_node(token, _node_metadata_with_request_address(payload))
        except PermissionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 401
        return jsonify(result)

    @app.post("/api/node/v1/jobs/next")
    def node_api_job_next():
        authorization = request.headers.get("Authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        try:
            job = claim_node_job(token)
        except PermissionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 401
        return jsonify({"ok": True, "job": job})

    @app.post("/api/node/v1/jobs/<int:job_id>/complete")
    def node_api_job_complete(job_id: int):
        authorization = request.headers.get("Authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        payload = request.get_json(silent=True) or {}
        try:
            job = complete_node_job(
                token,
                job_id,
                ok=bool(payload.get("ok")),
                result=payload.get("result") if isinstance(payload.get("result"), dict) else {},
            )
            deletion = job.get("deletion_request") if isinstance(job, dict) else None
            if isinstance(deletion, dict):
                _finish_ready_user_deletion(deletion)
        except PermissionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 401
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "job": job})

    @app.post("/apply")
    @login_required
    def apply_route():
        try:
            result = apply_config()
            flash(
                f"Конфигурация применена: {result['enabled_users']} пользователей, "
                f"{result['enabled_rules']} routing rules.",
                "success",
            )
        except (XPanelError, ValueError, PermissionError, FileNotFoundError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(request.referrer or url_for("dashboard"))

    @app.post("/restart")
    @login_required
    def restart_route():
        try:
            restart_xray()
            flash("Xray перезапущен", "success")
        except (XPanelError, PermissionError, FileNotFoundError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("diagnostics_page"))

    @app.post("/diagnostics/restart/<service_name>")
    @login_required
    def diagnostics_restart_service(service_name: str):
        if service_name == "xray":
            return restart_route()
        allowed = {"nginx": "nginx", "panel": "xpanel-web"}
        unit = allowed.get(service_name)
        if unit is None:
            abort(404)
        try:
            if service_name == "panel":
                subprocess.Popen(
                    [
                        "systemd-run",
                        f"--unit=sg-panel-web-restart-{secrets.token_hex(4)}",
                        "--on-active=2s",
                        "/bin/systemctl",
                        "restart",
                        unit,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                flash("Перезапуск SG-Panel запланирован через 2 секунды", "success")
            else:
                proc = subprocess.run(
                    ["systemctl", "restart", unit],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                if proc.returncode != 0:
                    raise XPanelError(
                        (proc.stderr or proc.stdout).strip()
                        or f"не удалось перезапустить {unit}"
                    )
                flash(f"Служба {unit} перезапущена", "success")
        except (XPanelError, OSError, subprocess.TimeoutExpired) as exc:
            flash(str(exc), "error")
        return redirect(url_for("diagnostics_page"))

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=str(error)), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("error.html", code=403, message=str(error)), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="Страница не найдена"), 404

    @app.errorhandler(429)
    def too_many_requests(error):
        return render_template("error.html", code=429, message=str(error)), 429

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
