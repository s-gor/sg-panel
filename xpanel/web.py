from __future__ import annotations

import base64
import hashlib
import io
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

from flask import (
    Flask,
    Response,
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
    config_json_document,
    dns_json_document,
    inbound_json_document,
    backup_file,
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
    get_diagnostics,
    get_geodata_status,
    get_dns_settings,
    get_routing_settings,
    get_server,
    get_inbound_recommendations,
    get_hysteria_studio_overview,
    get_hysteria_diagnostics,
    get_status,
    get_subscription_settings,
    get_user_stats,
    get_user_traffic_history,
    get_warp_overview,
    list_backups,
    list_dns_hosts,
    list_dns_servers,
    list_outbounds,
    list_outbound_tags,
    list_balancer_tags,
    list_routing_rules,
    list_users,
    make_link,
    outbound_json_document,
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
    update_user,
    update_users_json_document,
    update_subscription_settings,
    user_is_expired,
    user_expiring_soon,
    users_json_document,
    subscription_is_available,
    validate_generated_config,
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
    if not 49152 <= port <= 65535:
        raise ValueError("Публичный порт панели должен быть от 49152 до 65535")
    if port in {22, 80, 443, 8080, 8443}:
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
    "raw_reality": "VLESS RAW + REALITY",
    "xhttp_tls": "VLESS XHTTP + TLS",
    "xhttp_reality": "VLESS XHTTP + REALITY",
    "grpc_tls": "VLESS gRPC + TLS",
    "hysteria2_tls": "Hysteria 2 + TLS",
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
        return {
            "xpanel_version": __version__,
            "format_bytes": format_bytes,
            "user_is_expired": user_is_expired,
            "expiry_for_form": _expiry_for_form,
            "panel_access_global": _panel_access_state(fallback_host),
            "global_system_ok": system_ok,
        }

    def client_ip() -> str:
        remote = (request.remote_addr or "unknown").strip()
        try:
            settings = get_security_settings()
        except Exception:
            return remote
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
                "SELECT id,enabled,outbound_json,route_mode,selected_domains "
                "FROM warp_settings ORDER BY id"
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
                    raise XPanelError("xray run -test завершился с ошибкой:\n" + detail)
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
        if endpoint in {"static", "health"}:
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
        return render_template(
            "users.html",
            users=rows,
            all_users=enriched,
            selected_user=selected,
            selected_history=selected_history,
            client_stats=summary,
            query=request.args.get("q", "").strip(),
            status_filter=status_filter,
            sort_mode=sort_mode,
            server=server,
            profile_label=INBOUND_PROFILE_LABELS.get(
                str(server["inbound_profile"]), str(server["inbound_profile"])
            ),
            stats_errors=errors,
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
        return render_template("user_edit.html", user=find_user(user_id))

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
            _preflight_change(lambda: delete_user(user_id))
            user = delete_user(user_id)
            apply_saved_change(f"Пользователь {user['name']} удалён")
        except XPanelError as exc:
            flash(str(exc), "error")
        return redirect(url_for("users_page"))

    @app.get("/users/<int:user_id>/link")
    @login_required
    def user_link(user_id: int):
        import qrcode

        user = find_user(user_id)
        link = make_link(user_id, allow_disabled=True)
        image = qrcode.make(link)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        qr_data = base64.b64encode(buffer.getvalue()).decode("ascii")

        subscription_url = make_subscription_url(
            user_id, request.url_root.rstrip("/")
        )
        subscription_image = qrcode.make(subscription_url)
        subscription_buffer = io.BytesIO()
        subscription_image.save(subscription_buffer, format="PNG")
        subscription_qr_data = base64.b64encode(
            subscription_buffer.getvalue()
        ).decode("ascii")
        return render_template(
            "link.html",
            user=user,
            link=link,
            qr_data=qr_data,
            subscription_url=subscription_url,
            subscription_qr_data=subscription_qr_data,
            subscription_settings=get_subscription_settings(),
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
            link = make_link(user["id"])
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
            body = base64.b64encode((link + "\n").encode("utf-8")).decode("ascii")
            response = Response(body + "\n", content_type="text/plain; charset=utf-8")
        elif output_format == "plain":
            response = Response(link + "\n", content_type="text/plain; charset=utf-8")
        elif output_format == "json":
            body = {
                "profile": settings["profile_title"],
                "user": user["name"],
                "link": link,
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

    @app.get("/settings")
    @login_required
    def settings_page():
        return render_template(
            "settings.html",
            server=get_server(),
            inbound_recommendations=get_inbound_recommendations(),
            hysteria_studio=get_hysteria_studio_overview(),
        )

    def server_form_values() -> dict[str, object]:
        current = get_server()
        return {
            "address": request.form.get("address", ""),
            "listen": request.form.get("listen", current["listen"]),
            "port": int(request.form.get("port", "443")),
            "dest": request.form.get("dest", ""),
            "server_name": request.form.get("server_name", ""),
            "private_key": request.form.get("private_key", ""),
            "public_key": request.form.get("public_key", ""),
            "short_id": request.form.get("short_id", ""),
            "fingerprint": request.form.get("fingerprint", "chrome"),
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
            label = "Hysteria 2 применена" if server["inbound_profile"] == "hysteria2_tls" else "Inbound применён"
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
        return render_template(
            "security.html",
            settings=get_security_settings(),
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
            panel_access=_panel_access_state(request.host.split(":", 1)[0]),
            xray_address=str(get_server()["address"]),
        )

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
        update_info = check_for_updates(
            force=False, allow_network=not bool(app.config.get("TESTING"))
        )
        update_status = get_update_status()
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
        state = str(update_status.get("state") or "idle")
        state_class = (
            "success" if state == "success"
            else "danger" if state in {"error", "rolled_back"}
            else "warning" if state in {
                "starting", "downloading", "verifying", "backing_up",
                "installing", "validating", "rollback",
            }
            else ""
        )
        return render_template(
            "updates.html",
            update_info=update_info,
            update_status=update_status,
            update_running=update_in_progress(),
            update_state_label=labels.get(state, state.upper()),
            update_state_class=state_class,
        )

    @app.post("/updates/check")
    @login_required
    def updates_check():
        try:
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
        return redirect(url_for("updates_page", watch="1"))

    @app.get("/updates/status")
    @login_required
    def updates_status():
        return Response(
            json.dumps(get_update_status(), ensure_ascii=False),
            content_type="application/json; charset=utf-8",
        )

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
        selected = request.form.get("selected_domains", "")
        try:
            if _is_validation_action():
                return _validation_response(
                    scope, lambda: configure_warp_routing(mode, selected),
                    message="Маршрут WARP и итоговый config.json проверены.",
                )
            _require_validation_token(scope, _draft_payload())
            configure_warp_routing(mode, selected)
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
            "fingerprint": request.form.get("fingerprint", "chrome"),
            "spider_x": request.form.get("spider_x", ""),
            "xhttp_host": request.form.get("xhttp_host", ""),
            "xhttp_path": request.form.get("xhttp_path", "/"),
            "xhttp_mode": request.form.get("xhttp_mode", "auto"),
            "allow_insecure": request.form.get("allow_insecure") == "on",
            "alpn": request.form.get("alpn", ""),
        }

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
