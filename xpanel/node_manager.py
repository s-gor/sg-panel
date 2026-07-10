from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import connect

AGENT_API_VERSION = 1
AGENT_VERSION = "0.5.0"
ENROLLMENT_TTL_MINUTES = 30
OFFLINE_AFTER_SECONDS = 150

ROLE_LABELS = {
    "primary": "Основной",
    "backup": "Резервный",
    "regional": "Региональный",
    "entry": "Входной",
    "exit": "Выходной",
    "test": "Тестовый",
}

STATE_LABELS = {
    "local": "Локальный",
    "pending": "Ожидает подключения",
    "online": "В сети",
    "offline": "Нет связи",
    "revoked": "Отозван",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime | None = None) -> str:
    return (moment or _now()).replace(microsecond=0).isoformat()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _clean_text(value: Any, *, max_length: int, default: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return default
    return text[:max_length]


def _safe_number(value: Any, *, minimum: float = 0, maximum: float = 100) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return max(minimum, min(maximum, number))


def _safe_service_state(value: Any) -> str:
    state = str(value or "").strip().lower()
    allowed = {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
    return state if state in allowed else "unknown"


def _safe_optional_int(value: Any, *, minimum: int = 0, maximum: int = 1_000_000) -> int | None:
    if value in (None, ""):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return max(minimum, min(maximum, number))


def _slugify(name: str) -> str:
    base = name.strip().lower()
    base = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
    if not base:
        base = f"node-{secrets.token_hex(3)}"
    return base[:48]


def _node_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    last_seen = _parse_time(item.get("last_seen_at"))
    stored_state = str(item.get("state") or "pending")
    if item.get("is_local"):
        effective_state = "local"
    elif stored_state == "revoked":
        effective_state = "revoked"
    elif last_seen and (_now() - last_seen).total_seconds() <= OFFLINE_AFTER_SECONDS:
        effective_state = "online"
    elif item.get("registered_at"):
        effective_state = "offline"
    else:
        effective_state = "pending"
    item["effective_state"] = effective_state
    item["state_label"] = STATE_LABELS.get(effective_state, effective_state)
    item["role_label"] = ROLE_LABELS.get(str(item.get("role") or ""), str(item.get("role") or ""))
    item["last_seen_age"] = _last_seen_text(last_seen, effective_state)
    return item


def _last_seen_text(last_seen: datetime | None, state: str) -> str:
    if state == "local":
        return "На этом сервере"
    if state == "pending":
        return "Ещё не подключалась"
    if not last_seen:
        return "Нет данных"
    seconds = max(0, int((_now() - last_seen).total_seconds()))
    if seconds < 60:
        return "Только что"
    if seconds < 3600:
        return f"{seconds // 60} мин. назад"
    if seconds < 86400:
        return f"{seconds // 3600} ч. назад"
    return f"{seconds // 86400} дн. назад"


def record_node_event(
    node_id: int,
    event_type: str,
    message: str,
    *,
    level: str = "info",
    details: dict[str, Any] | None = None,
) -> None:
    if level not in {"info", "success", "warning", "error"}:
        level = "info"
    with connect() as con:
        con.execute(
            """
            INSERT INTO node_events (node_id, level, event_type, message, details_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(node_id),
                level,
                _clean_text(event_type, max_length=64, default="event"),
                _clean_text(message, max_length=500),
                json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
            ),
        )


def list_nodes() -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute(
            """
            SELECT * FROM nodes
            ORDER BY is_local DESC,
                     CASE role WHEN 'primary' THEN 0 WHEN 'backup' THEN 1 ELSE 2 END,
                     name COLLATE NOCASE
            """
        ).fetchall()
    return [_node_dict(row) for row in rows]


def find_node(node_id: int) -> dict[str, Any]:
    with connect() as con:
        row = con.execute("SELECT * FROM nodes WHERE id = ?", (int(node_id),)).fetchone()
    if row is None:
        raise ValueError("Сервер не найден")
    return _node_dict(row)


def list_node_events(node_id: int, *, limit: int = 30) -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute(
            """
            SELECT id, node_id, level, event_type, message, details_json, created_at
            FROM node_events
            WHERE node_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(node_id), max(1, min(int(limit), 200))),
        ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
        result.append(item)
    return result


def create_node(
    name: str,
    *,
    role: str = "regional",
    location: str = "",
    description: str = "",
    public_address: str | None = None,
) -> dict[str, Any]:
    name = _clean_text(name, max_length=80)
    if len(name) < 2:
        raise ValueError("Укажите понятное имя сервера")
    role = _clean_text(role, max_length=20, default="regional")
    if role not in ROLE_LABELS:
        raise ValueError("Неизвестная роль сервера")
    location = _clean_text(location, max_length=80)
    description = _clean_text(description, max_length=300)
    public_address = _clean_text(public_address, max_length=255)
    if any(value in public_address for value in ("/", "?", "#", " ")):
        raise ValueError("Публичный адрес должен быть доменом или IP без протокола")
    base_slug = _slugify(name)
    with connect() as con:
        slug = base_slug
        counter = 2
        while con.execute("SELECT 1 FROM nodes WHERE slug = ?", (slug,)).fetchone():
            slug = f"{base_slug[:42]}-{counter}"
            counter += 1
        try:
            cursor = con.execute(
                """
                INSERT INTO nodes (name, slug, role, location, description, public_address, state)
                VALUES (?, ?, ?, ?, ?, ?, 'pending')
                """,
                (name, slug, role, location, description, public_address),
            )
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                raise ValueError("Сервер с таким именем уже существует") from exc
            raise
        node_id = int(cursor.lastrowid)
    record_node_event(node_id, "node_created", "Сервер добавлен в сеть и ожидает подключения")
    return find_node(node_id)


def update_node(
    node_id: int,
    *,
    name: str,
    role: str,
    location: str = "",
    description: str = "",
    public_address: str | None = None,
) -> dict[str, Any]:
    current = find_node(node_id)
    name = _clean_text(name, max_length=80)
    if len(name) < 2:
        raise ValueError("Укажите понятное имя сервера")
    if role not in ROLE_LABELS:
        raise ValueError("Неизвестная роль сервера")
    if current["is_local"]:
        role = "primary"
        public_address = str(current.get("public_address") or "")
    elif public_address is None:
        public_address = str(current.get("public_address") or "")
    public_address = _clean_text(public_address, max_length=255)
    if any(value in public_address for value in ("/", "?", "#", " ")):
        raise ValueError("Публичный адрес должен быть доменом или IP без протокола")
    with connect() as con:
        try:
            con.execute(
                """
                UPDATE nodes
                SET name = ?, role = ?, location = ?, description = ?,
                    public_address = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    name,
                    role,
                    _clean_text(location, max_length=80),
                    _clean_text(description, max_length=300),
                    public_address,
                    int(node_id),
                ),
            )
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                raise ValueError("Сервер с таким именем уже существует") from exc
            raise
    record_node_event(node_id, "node_updated", "Карточка сервера обновлена")
    return find_node(node_id)


def has_active_enrollment(node_id: int) -> bool:
    """Return True while a usable one-time connection token still exists."""
    now = _iso()
    with connect() as con:
        row = con.execute(
            """
            SELECT 1
            FROM node_enrollment_tokens
            WHERE node_id = ?
              AND used_at IS NULL
              AND revoked_at IS NULL
              AND expires_at > ?
            LIMIT 1
            """,
            (int(node_id), now),
        ).fetchone()
    return row is not None


def create_enrollment_token(node_id: int) -> dict[str, Any]:
    node = find_node(node_id)
    if node["is_local"]:
        raise ValueError("Локальный сервер не требует подключения агента")
    if node["effective_state"] == "revoked":
        raise ValueError("Сначала восстановите отозванный сервер")
    raw_token = secrets.token_urlsafe(36)
    token_hash = _hash_token(raw_token)
    expires_at = _now() + timedelta(minutes=ENROLLMENT_TTL_MINUTES)
    with connect() as con:
        con.execute(
            """
            UPDATE node_enrollment_tokens
            SET revoked_at = ?
            WHERE node_id = ? AND used_at IS NULL AND revoked_at IS NULL
            """,
            (_iso(), int(node_id)),
        )
        con.execute(
            """
            INSERT INTO node_enrollment_tokens
                (node_id, token_hash, token_hint, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (int(node_id), token_hash, raw_token[-8:], _iso(expires_at)),
        )
    record_node_event(
        node_id,
        "enrollment_created",
        "Создан одноразовый код подключения",
        details={"expires_at": _iso(expires_at), "token_hint": raw_token[-8:]},
    )
    return {
        "token": raw_token,
        "expires_at": _iso(expires_at),
        "expires_minutes": ENROLLMENT_TTL_MINUTES,
    }


def _metadata_fields(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "public_address": _clean_text(payload.get("public_address"), max_length=255),
        "platform": _clean_text(payload.get("platform"), max_length=80),
        "platform_version": _clean_text(payload.get("platform_version"), max_length=120),
        "architecture": _clean_text(payload.get("architecture"), max_length=40),
        "agent_version": _clean_text(payload.get("agent_version"), max_length=40),
        "agent_state": _safe_service_state(payload.get("agent_state")),
        "worker_version": _clean_text(payload.get("worker_version"), max_length=40),
        "worker_state": _safe_service_state(payload.get("worker_state")),
        "xray_version": _clean_text(payload.get("xray_version"), max_length=120),
        "xray_state": _safe_service_state(payload.get("xray_state")),
        "nginx_version": _clean_text(payload.get("nginx_version"), max_length=120),
        "nginx_state": _safe_service_state(payload.get("nginx_state")),
        "inbound_profile": _clean_text(payload.get("inbound_profile"), max_length=60),
        "cpu_percent": _safe_number(payload.get("cpu_percent")),
        "memory_percent": _safe_number(payload.get("memory_percent")),
        "disk_percent": _safe_number(payload.get("disk_percent")),
        "load1": _safe_number(payload.get("load1"), minimum=0, maximum=10_000),
        "client_count": _safe_optional_int(payload.get("client_count")),
        "last_error": _clean_text(payload.get("last_error"), max_length=500),
    }


def register_node(
    enrollment_token: str,
    *,
    agent_id: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    enrollment_token = str(enrollment_token or "").strip()
    agent_id = _clean_text(agent_id, max_length=128)
    if not enrollment_token or not agent_id:
        raise ValueError("Не передан код подключения или идентификатор агента")
    now = _now()
    permanent_token = secrets.token_urlsafe(48)
    fields = _metadata_fields(metadata or {})
    with connect() as con:
        token_row = con.execute(
            """
            SELECT t.*, n.state, n.is_local
            FROM node_enrollment_tokens t
            JOIN nodes n ON n.id = t.node_id
            WHERE t.token_hash = ?
            """,
            (_hash_token(enrollment_token),),
        ).fetchone()
        if token_row is None:
            raise ValueError("Одноразовый код подключения не найден")
        if token_row["used_at"]:
            raise ValueError("Одноразовый код уже использован")
        if token_row["revoked_at"]:
            raise ValueError("Одноразовый код отозван")
        expires_at = _parse_time(token_row["expires_at"])
        if expires_at is None or expires_at < now:
            raise ValueError("Срок действия одноразового кода истёк")
        if token_row["state"] == "revoked" or token_row["is_local"]:
            raise ValueError("Этот сервер нельзя зарегистрировать")
        duplicate = con.execute(
            "SELECT id FROM nodes WHERE agent_id = ? AND id != ?",
            (agent_id, int(token_row["node_id"])),
        ).fetchone()
        if duplicate is not None:
            raise ValueError("Этот агент уже зарегистрирован на другом сервере")
        con.execute(
            "UPDATE node_enrollment_tokens SET used_at = ? WHERE id = ?",
            (_iso(now), int(token_row["id"])),
        )
        con.execute(
            """
            UPDATE nodes
            SET state = 'online', agent_id = ?, agent_token_hash = ?,
                public_address = ?, platform = ?, platform_version = ?,
                architecture = ?, agent_version = ?, agent_state = ?,
                worker_version = ?, worker_state = ?, xray_version = ?,
                xray_state = ?, nginx_version = ?, nginx_state = ?,
                inbound_profile = ?, cpu_percent = ?,
                memory_percent = ?, disk_percent = ?, load1 = ?, client_count = ?,
                last_error = ?, last_seen_at = ?, registered_at = COALESCE(registered_at, ?),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                agent_id,
                _hash_token(permanent_token),
                fields["public_address"],
                fields["platform"],
                fields["platform_version"],
                fields["architecture"],
                fields["agent_version"],
                fields["agent_state"],
                fields["worker_version"],
                fields["worker_state"],
                fields["xray_version"],
                fields["xray_state"],
                fields["nginx_version"],
                fields["nginx_state"],
                fields["inbound_profile"],
                fields["cpu_percent"],
                fields["memory_percent"],
                fields["disk_percent"],
                fields["load1"],
                fields["client_count"],
                fields["last_error"],
                _iso(now),
                _iso(now),
                int(token_row["node_id"]),
            ),
        )
        node_id = int(token_row["node_id"])
    record_node_event(
        node_id,
        "node_registered",
        "SG-Node Agent подключён и зарегистрирован",
        level="success",
        details={"agent_id": agent_id, "api_version": AGENT_API_VERSION},
    )
    return {
        "node": find_node(node_id),
        "agent_token": permanent_token,
        "heartbeat_interval": 30,
        "api_version": AGENT_API_VERSION,
    }


def _node_by_agent_token(agent_token: str) -> dict[str, Any]:
    agent_token = str(agent_token or "").strip()
    if not agent_token:
        raise PermissionError("Не передан токен агента")
    token_hash = _hash_token(agent_token)
    with connect() as con:
        row = con.execute(
            "SELECT * FROM nodes WHERE agent_token_hash = ?",
            (token_hash,),
        ).fetchone()
    if row is None:
        raise PermissionError("Неизвестный токен агента")
    node = _node_dict(row)
    if node["effective_state"] == "revoked":
        raise PermissionError("Доступ этого сервера отозван")
    return node


def heartbeat_node(agent_token: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    node = _node_by_agent_token(agent_token)
    fields = _metadata_fields(payload or {})
    fields["public_address"] = fields["public_address"] or str(node.get("public_address") or "")
    with connect() as con:
        con.execute(
            """
            UPDATE nodes
            SET state = 'online', public_address = ?, platform = ?,
                platform_version = ?, architecture = ?, agent_version = ?,
                agent_state = ?, worker_version = ?, worker_state = ?,
                xray_version = ?, xray_state = ?, nginx_version = ?,
                nginx_state = ?, inbound_profile = ?, cpu_percent = ?,
                memory_percent = ?, disk_percent = ?, load1 = ?,
                client_count = ?, last_error = ?, last_seen_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                fields["public_address"],
                fields["platform"],
                fields["platform_version"],
                fields["architecture"],
                fields["agent_version"],
                fields["agent_state"],
                fields["worker_version"],
                fields["worker_state"],
                fields["xray_version"],
                fields["xray_state"],
                fields["nginx_version"],
                fields["nginx_state"],
                fields["inbound_profile"],
                fields["cpu_percent"],
                fields["memory_percent"],
                fields["disk_percent"],
                fields["load1"],
                fields["client_count"],
                fields["last_error"],
                _iso(),
                int(node["id"]),
            ),
        )
    return {
        "ok": True,
        "node_id": int(node["id"]),
        "server_time": _iso(),
        "heartbeat_interval": 30,
    }


def revoke_node(node_id: int) -> dict[str, Any]:
    node = find_node(node_id)
    if node["is_local"]:
        raise ValueError("Локальный сервер нельзя отозвать")
    with connect() as con:
        con.execute(
            """
            UPDATE nodes
            SET state = 'revoked', agent_token_hash = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (int(node_id),),
        )
        con.execute(
            """
            UPDATE node_enrollment_tokens
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE node_id = ? AND used_at IS NULL
            """,
            (_iso(), int(node_id)),
        )
    record_node_event(node_id, "node_revoked", "Доступ SG-Node Agent отозван", level="warning")
    return find_node(node_id)


def restore_node(node_id: int) -> dict[str, Any]:
    node = find_node(node_id)
    if node["is_local"]:
        return node
    with connect() as con:
        con.execute(
            """
            UPDATE nodes
            SET state = 'pending', agent_id = NULL, agent_token_hash = NULL,
                last_seen_at = NULL, last_error = '', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (int(node_id),),
        )
    record_node_event(node_id, "node_restored", "Сервер возвращён в режим ожидания подключения")
    return find_node(node_id)


def delete_node(node_id: int) -> None:
    node = find_node(node_id)
    if node["is_local"]:
        raise ValueError("Локальный сервер нельзя удалить")
    with connect() as con:
        con.execute("DELETE FROM nodes WHERE id = ?", (int(node_id),))


def network_summary(nodes: list[dict[str, Any]] | None = None) -> dict[str, int]:
    nodes = nodes if nodes is not None else list_nodes()
    return {
        "total": len(nodes),
        "online": sum(1 for item in nodes if item["effective_state"] in {"local", "online"}),
        "offline": sum(1 for item in nodes if item["effective_state"] == "offline"),
        "pending": sum(1 for item in nodes if item["effective_state"] == "pending"),
        "revoked": sum(1 for item in nodes if item["effective_state"] == "revoked"),
    }

JOB_STATUS_LABELS = {
    "queued": "Ожидает ноду",
    "running": "Выполняется",
    "succeeded": "Применено",
    "failed": "Ошибка",
    "cancelled": "Отменено",
}


def _job_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    for source, target in (("payload_json", "payload"), ("result_json", "result")):
        try:
            parsed = json.loads(item.pop(source) or "{}")
        except json.JSONDecodeError:
            parsed = {}
        item[target] = parsed if isinstance(parsed, dict) else {}
    status = str(item.get("status") or "queued")
    item["status_label"] = JOB_STATUS_LABELS.get(status, status)
    return item


def list_node_jobs(node_id: int, *, limit: int = 10) -> list[dict[str, Any]]:
    find_node(node_id)
    with connect() as con:
        rows = con.execute(
            """
            SELECT * FROM node_jobs
            WHERE node_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(node_id), max(1, min(int(limit), 100))),
        ).fetchall()
    return [_job_dict(row) for row in rows]


def find_node_job(job_id: int) -> dict[str, Any]:
    with connect() as con:
        row = con.execute("SELECT * FROM node_jobs WHERE id = ?", (int(job_id),)).fetchone()
    if row is None:
        raise ValueError("Задание ноды не найдено")
    return _job_dict(row)


def _backfill_node_deployments() -> None:
    """Reconstruct deployment state from the newest successful config per node.

    Preview 2 did not persist deployments separately, so an upgraded installation
    needs a one-time best-effort reconstruction before safe user/node deletion can
    reason about existing links.
    """
    with connect() as con:
        nodes = con.execute("SELECT id FROM nodes WHERE is_local = 0").fetchall()
        for node_row in nodes:
            node_id = int(node_row["id"])
            jobs = con.execute(
                """
                SELECT * FROM node_jobs
                WHERE node_id = ? AND status = 'succeeded'
                ORDER BY id DESC LIMIT 30
                """,
                (node_id,),
            ).fetchall()
            latest: dict[str, Any] | None = None
            for row in jobs:
                parsed = _job_dict(row)
                payload = parsed.get("payload") if isinstance(parsed.get("payload"), dict) else {}
                if isinstance(payload.get("config"), dict):
                    latest = parsed
                    break
            if latest is None:
                continue
            payload = latest.get("payload") if isinstance(latest.get("payload"), dict) else {}
            config = payload.get("config") if isinstance(payload, dict) else None
            if not isinstance(config, dict):
                continue
            found: dict[str, str] = {}
            public_port: int | None = None
            for inbound in config.get("inbounds", []):
                if not isinstance(inbound, dict):
                    continue
                if public_port is None:
                    public_port = _safe_optional_int(inbound.get("port"), minimum=1, maximum=65535)
                settings = inbound.get("settings")
                if not isinstance(settings, dict):
                    continue
                values = settings.get("clients") if isinstance(settings.get("clients"), list) else settings.get("users")
                if not isinstance(values, list):
                    continue
                for value in values:
                    if not isinstance(value, dict):
                        continue
                    user_uuid = str(value.get("id") or value.get("uuid") or "").strip()
                    if user_uuid:
                        found[user_uuid] = str(value.get("email") or value.get("name") or user_uuid)
            existing = con.execute(
                "SELECT id, user_uuid, state FROM node_deployments WHERE node_id = ?",
                (node_id,),
            ).fetchall()
            for row in existing:
                if str(row["user_uuid"]) not in found and str(row["state"]) == "active":
                    con.execute(
                        "UPDATE node_deployments SET state='removed', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (int(row["id"]),),
                    )
            for user_uuid, fallback_name in found.items():
                user = con.execute(
                    "SELECT id, name FROM users WHERE uuid = ?", (user_uuid,)
                ).fetchone()
                user_id = int(user["id"]) if user is not None else None
                user_name = str(user["name"]) if user is not None else fallback_name
                con.execute(
                    """
                    INSERT INTO node_deployments
                        (node_id, user_id, user_uuid, user_name, profile, public_port,
                         client_link, state, last_job_id, last_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, 'Восстановлено из последней конфигурации')
                    ON CONFLICT(node_id, user_uuid) DO UPDATE SET
                        user_id=excluded.user_id,
                        user_name=excluded.user_name,
                        profile=excluded.profile,
                        public_port=excluded.public_port,
                        client_link=CASE WHEN excluded.client_link != '' THEN excluded.client_link ELSE node_deployments.client_link END,
                        state='active',
                        last_job_id=excluded.last_job_id,
                        last_message='Восстановлено из последней конфигурации',
                        updated_at=CURRENT_TIMESTAMP
                    """,
                    (
                        node_id,
                        user_id,
                        user_uuid,
                        user_name[:80],
                        str(payload.get("profile") or "")[:80],
                        public_port,
                        str(latest.get("client_link") or "")[:4096],
                        int(latest["id"]),
                    ),
                )


def list_node_deployments(node_id: int, *, include_removed: bool = False) -> list[dict[str, Any]]:
    find_node(node_id)
    _backfill_node_deployments()
    query = "SELECT * FROM node_deployments WHERE node_id = ?"
    params: list[Any] = [int(node_id)]
    if not include_removed:
        query += " AND state != 'removed'"
    query += " ORDER BY user_name COLLATE NOCASE, id"
    with connect() as con:
        rows = con.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def list_user_deployments(user_id: int, *, include_removed: bool = False) -> list[dict[str, Any]]:
    _backfill_node_deployments()
    query = """
        SELECT d.*, n.name AS node_name, n.location AS node_location,
               n.state AS node_state, n.is_local AS node_is_local,
               n.last_seen_at AS node_last_seen_at, n.registered_at AS node_registered_at
        FROM node_deployments d
        JOIN nodes n ON n.id = d.node_id
        WHERE d.user_id = ?
    """
    params: list[Any] = [int(user_id)]
    if not include_removed:
        query += " AND d.state != 'removed'"
    query += " ORDER BY n.name COLLATE NOCASE, d.id"
    with connect() as con:
        rows = con.execute(query, params).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if item.get("node_is_local"):
            item["node_effective_state"] = "local"
        else:
            last_seen = _parse_time(item.get("node_last_seen_at"))
            if last_seen and (_now() - last_seen).total_seconds() <= OFFLINE_AFTER_SECONDS:
                item["node_effective_state"] = "online"
            elif item.get("node_registered_at"):
                item["node_effective_state"] = "offline"
            else:
                item["node_effective_state"] = str(item.get("node_state") or "pending")
        items.append(item)
    return items


def _deployment_metadata(job: dict[str, Any]) -> dict[str, Any]:
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    metadata = payload.get("deployment") if isinstance(payload, dict) else {}
    return metadata if isinstance(metadata, dict) else {}


def _record_deployment_job(job: dict[str, Any]) -> None:
    metadata = _deployment_metadata(job)
    action = str(metadata.get("action") or "").strip()
    if action not in {"upsert", "remove"}:
        return
    node_id = int(job["node_id"])
    user_id = metadata.get("user_id")
    user_id = int(user_id) if user_id not in (None, "") else None
    user_uuid = _clean_text(metadata.get("user_uuid"), max_length=80)
    if not user_uuid:
        return
    state = "pending" if action == "upsert" else "removing"
    with connect() as con:
        con.execute(
            """
            INSERT INTO node_deployments
                (node_id, user_id, user_uuid, user_name, profile, public_host,
                 public_port, client_link, state, last_job_id, last_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
            ON CONFLICT(node_id, user_uuid) DO UPDATE SET
                user_id = excluded.user_id,
                user_name = excluded.user_name,
                profile = CASE WHEN excluded.profile != '' THEN excluded.profile ELSE node_deployments.profile END,
                public_host = CASE WHEN excluded.public_host != '' THEN excluded.public_host ELSE node_deployments.public_host END,
                public_port = COALESCE(excluded.public_port, node_deployments.public_port),
                client_link = CASE WHEN excluded.client_link != '' THEN excluded.client_link ELSE node_deployments.client_link END,
                state = excluded.state,
                last_job_id = excluded.last_job_id,
                last_message = '',
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                node_id,
                user_id,
                user_uuid,
                _clean_text(metadata.get("user_name"), max_length=80),
                _clean_text(metadata.get("profile"), max_length=80),
                _clean_text(metadata.get("public_host"), max_length=255),
                _safe_optional_int(metadata.get("public_port"), minimum=1, maximum=65535),
                _clean_text(job.get("client_link"), max_length=4096),
                state,
                int(job["id"]),
            ),
        )


def _complete_deployment_job(job: dict[str, Any], *, ok: bool, message: str) -> None:
    metadata = _deployment_metadata(job)
    action = str(metadata.get("action") or "").strip()
    user_uuid = _clean_text(metadata.get("user_uuid"), max_length=80)
    if action not in {"upsert", "remove"} or not user_uuid:
        return
    state = ("active" if action == "upsert" else "removed") if ok else "error"
    with connect() as con:
        con.execute(
            """
            UPDATE node_deployments
            SET state = ?, last_message = ?, last_job_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ? AND user_uuid = ?
            """,
            (state, message, int(job["id"]), int(job["node_id"]), user_uuid),
        )


def latest_node_config(node_id: int) -> dict[str, Any] | None:
    for job in list_node_jobs(node_id, limit=100):
        if job.get("status") != "succeeded":
            continue
        payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        config = payload.get("config") if isinstance(payload, dict) else None
        if isinstance(config, dict):
            return json.loads(json.dumps(config))
    return None


def create_user_deletion_request(
    user_id: int,
    *,
    user_name: str,
    user_uuid: str,
    jobs: list[dict[str, Any]],
) -> dict[str, Any]:
    with connect() as con:
        active = con.execute(
            """
            SELECT id FROM user_deletion_requests
            WHERE user_id = ? AND status IN ('pending', 'running')
            ORDER BY id DESC LIMIT 1
            """,
            (int(user_id),),
        ).fetchone()
        if active is not None:
            raise ValueError("Удаление этого пользователя уже выполняется")
        cursor = con.execute(
            """
            INSERT INTO user_deletion_requests
                (user_id, user_name, user_uuid, status)
            VALUES (?, ?, ?, ?)
            """,
            (
                int(user_id),
                _clean_text(user_name, max_length=80),
                _clean_text(user_uuid, max_length=80),
                "running" if jobs else "pending",
            ),
        )
        request_id = int(cursor.lastrowid)
        for job in jobs:
            con.execute(
                """
                INSERT INTO user_deletion_targets
                    (request_id, node_id, job_id, status)
                VALUES (?, ?, ?, ?)
                """,
                (request_id, int(job["node_id"]), int(job["id"]), str(job["status"])),
            )
    return get_user_deletion_request(request_id)


def get_user_deletion_request(request_id: int) -> dict[str, Any]:
    with connect() as con:
        row = con.execute(
            "SELECT * FROM user_deletion_requests WHERE id = ?", (int(request_id),)
        ).fetchone()
        if row is None:
            raise ValueError("Запрос удаления пользователя не найден")
        targets = con.execute(
            """
            SELECT t.*, n.name AS node_name
            FROM user_deletion_targets t
            JOIN nodes n ON n.id = t.node_id
            WHERE t.request_id = ? ORDER BY n.name COLLATE NOCASE
            """,
            (int(request_id),),
        ).fetchall()
    item = dict(row)
    item["targets"] = [dict(target) for target in targets]
    return item


def user_deletion_request(user_id: int) -> dict[str, Any] | None:
    with connect() as con:
        row = con.execute(
            """
            SELECT id FROM user_deletion_requests
            WHERE user_id = ? ORDER BY id DESC LIMIT 1
            """,
            (int(user_id),),
        ).fetchone()
    return get_user_deletion_request(int(row["id"])) if row is not None else None


def update_deletion_target(job: dict[str, Any], *, ok: bool, message: str) -> dict[str, Any] | None:
    with connect() as con:
        target = con.execute(
            "SELECT * FROM user_deletion_targets WHERE job_id = ?", (int(job["id"]),)
        ).fetchone()
        if target is None:
            return None
        status = "succeeded" if ok else "failed"
        con.execute(
            """
            UPDATE user_deletion_targets
            SET status = ?, message = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, _clean_text(message, max_length=500), int(target["id"])),
        )
        rows = con.execute(
            "SELECT status, message FROM user_deletion_targets WHERE request_id = ?",
            (int(target["request_id"]),),
        ).fetchall()
        statuses = [str(row["status"]) for row in rows]
        if any(value == "failed" for value in statuses):
            request_status = "failed"
            error = next((str(row["message"]) for row in rows if row["status"] == "failed"), "")
        elif statuses and all(value == "succeeded" for value in statuses):
            request_status = "pending"
            error = ""
        else:
            request_status = "running"
            error = ""
        con.execute(
            """
            UPDATE user_deletion_requests
            SET status = ?, error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (request_status, error, int(target["request_id"])),
        )
    return get_user_deletion_request(int(target["request_id"]))


def finish_user_deletion_request(request_id: int, *, ok: bool, error: str = "") -> None:
    with connect() as con:
        con.execute(
            """
            UPDATE user_deletion_requests
            SET status = ?, error = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                "succeeded" if ok else "failed",
                _clean_text(error, max_length=1000),
                1 if ok else 0,
                _iso() if ok else None,
                int(request_id),
            ),
        )


def create_node_job(
    node_id: int,
    *,
    job_type: str,
    title: str,
    payload: dict[str, Any],
    client_link: str = "",
) -> dict[str, Any]:
    node = find_node(node_id)
    if node.get("is_local"):
        raise ValueError("Локальный сервер не использует задания SG-Node")
    if node.get("effective_state") != "online":
        raise ValueError("Сервер должен быть в сети")
    if job_type != "apply_xray_config":
        raise ValueError("Неизвестный тип задания")
    if not isinstance(payload, dict):
        raise ValueError("Задание должно содержать JSON-объект")
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if len(encoded.encode("utf-8")) > 1_000_000:
        raise ValueError("Задание слишком большое")
    with connect() as con:
        active = con.execute(
            """
            SELECT id FROM node_jobs
            WHERE node_id = ? AND status IN ('queued', 'running')
            LIMIT 1
            """,
            (int(node_id),),
        ).fetchone()
        if active is not None:
            raise ValueError("На сервере уже выполняется другое задание")
        cursor = con.execute(
            """
            INSERT INTO node_jobs
                (node_id, job_type, status, title, payload_json, client_link)
            VALUES (?, ?, 'queued', ?, ?, ?)
            """,
            (
                int(node_id),
                job_type,
                _clean_text(title, max_length=160, default="Задание SG-Node"),
                encoded,
                _clean_text(client_link, max_length=4096),
            ),
        )
        job_id = int(cursor.lastrowid)
    record_node_event(
        node_id,
        "job_queued",
        f"Подготовлено задание: {title}",
        details={"job_id": job_id, "job_type": job_type},
    )
    job = find_node_job(job_id)
    _record_deployment_job(job)
    return job


def claim_node_job(agent_token: str) -> dict[str, Any] | None:
    node = _node_by_agent_token(agent_token)
    with connect() as con:
        con.execute(
            """
            UPDATE node_jobs
            SET status = 'queued', claimed_at = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE node_id = ? AND status = 'running'
              AND claimed_at IS NOT NULL AND claimed_at < ?
            """,
            (int(node["id"]), _iso(_now() - timedelta(minutes=5))),
        )
        row = con.execute(
            """
            SELECT * FROM node_jobs
            WHERE node_id = ? AND status = 'queued'
            ORDER BY id
            LIMIT 1
            """,
            (int(node["id"]),),
        ).fetchone()
        if row is None:
            return None
        changed = con.execute(
            """
            UPDATE node_jobs
            SET status = 'running', claimed_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'queued'
            """,
            (_iso(), int(row["id"])),
        ).rowcount
        if changed != 1:
            return None
    job = find_node_job(int(row["id"]))
    with connect() as con:
        con.execute(
            """
            UPDATE user_deletion_targets
            SET status = 'running', updated_at = CURRENT_TIMESTAMP
            WHERE job_id = ?
            """,
            (int(job["id"]),),
        )
    record_node_event(
        int(node["id"]),
        "job_started",
        f"Нода начала задание: {job['title']}",
        details={"job_id": int(job["id"])},
    )
    return job


def complete_node_job(
    agent_token: str,
    job_id: int,
    *,
    ok: bool,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    node = _node_by_agent_token(agent_token)
    job = find_node_job(job_id)
    if int(job["node_id"]) != int(node["id"]):
        raise PermissionError("Задание принадлежит другой ноде")
    if job["status"] not in {"running", "queued"}:
        return job
    result = result if isinstance(result, dict) else {}
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True)
    if len(encoded.encode("utf-8")) > 200_000:
        encoded = json.dumps(
            {"message": "Ответ ноды был слишком большим", "truncated": True},
            ensure_ascii=False,
        )
    status = "succeeded" if ok else "failed"
    with connect() as con:
        con.execute(
            """
            UPDATE node_jobs
            SET status = ?, result_json = ?, completed_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, encoded, _iso(), int(job_id)),
        )
    message = _clean_text(result.get("message"), max_length=400)
    completed_job = find_node_job(job_id)
    _complete_deployment_job(completed_job, ok=ok, message=message)
    deletion_request = update_deletion_target(completed_job, ok=ok, message=message)
    if deletion_request is not None:
        completed_job["deletion_request"] = deletion_request
    record_node_event(
        int(node["id"]),
        "job_succeeded" if ok else "job_failed",
        message or ("Задание успешно применено" if ok else "Задание завершилось ошибкой"),
        level="success" if ok else "error",
        details={"job_id": int(job_id), "job_type": job["job_type"]},
    )
    return completed_job
