from __future__ import annotations

import ipaddress
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .db import connect, init_db


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def get_security_settings() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM security_settings WHERE id = 1").fetchone()
    if row is None:
        raise RuntimeError("security settings are not initialized")
    return row


def normalize_networks(value: str | None) -> str:
    result: list[str] = []
    seen: set[str] = set()
    for raw in (value or "").replace(",", "\n").splitlines():
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"Некорректная сеть или IP: {item}") from exc
        canonical = str(network)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return "\n".join(result)


def _network_objects(value: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    normalized = normalize_networks(value)
    return [ipaddress.ip_network(item, strict=False) for item in normalized.splitlines()]


def ip_is_allowed(
    ip_value: str | None,
    networks: str | None,
    *,
    allow_loopback: bool = True,
) -> bool:
    try:
        address = ipaddress.ip_address((ip_value or "").strip())
    except ValueError:
        return False
    if allow_loopback and address.is_loopback:
        return True
    return any(address in network for network in _network_objects(networks))


def update_security_settings(
    *,
    session_timeout_minutes: int,
    max_login_attempts: int,
    lockout_minutes: int,
    allowlist_enabled: bool,
    allowed_networks: str,
    trust_proxy_headers: bool,
    subscription_plain_enabled: bool,
    subscription_json_enabled: bool,
    subscription_allowlist_enabled: bool,
    subscription_allowed_networks: str,
    audit_retention_days: int,
    current_ip: str | None = None,
) -> sqlite3.Row:
    if not 5 <= int(session_timeout_minutes) <= 1440:
        raise ValueError("Тайм-аут сессии должен быть от 5 до 1440 минут")
    if not 3 <= int(max_login_attempts) <= 20:
        raise ValueError("Число попыток входа должно быть от 3 до 20")
    if not 1 <= int(lockout_minutes) <= 1440:
        raise ValueError("Блокировка должна быть от 1 до 1440 минут")
    if not 7 <= int(audit_retention_days) <= 3650:
        raise ValueError("Хранение журнала должно быть от 7 до 3650 дней")

    admin_networks = normalize_networks(allowed_networks)
    subscription_networks = normalize_networks(subscription_allowed_networks)
    if allowlist_enabled:
        if not admin_networks:
            raise ValueError("Для IP allowlist укажите хотя бы одну сеть")
        if current_ip and not ip_is_allowed(current_ip, admin_networks):
            raise ValueError(
                f"Текущий адрес {current_ip} не входит в новый allowlist. "
                "Настройки не сохранены, чтобы не потерять доступ."
            )
    if subscription_allowlist_enabled and not subscription_networks:
        raise ValueError("Для allowlist подписок укажите хотя бы одну сеть")

    with connect() as con:
        con.execute(
            """
            UPDATE security_settings SET
                session_timeout_minutes = ?, max_login_attempts = ?,
                lockout_minutes = ?, allowlist_enabled = ?, allowed_networks = ?,
                trust_proxy_headers = ?, subscription_plain_enabled = ?,
                subscription_json_enabled = ?, subscription_allowlist_enabled = ?,
                subscription_allowed_networks = ?, audit_retention_days = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (
                int(session_timeout_minutes), int(max_login_attempts),
                int(lockout_minutes), 1 if allowlist_enabled else 0,
                admin_networks, 1 if trust_proxy_headers else 0,
                1 if subscription_plain_enabled else 0,
                1 if subscription_json_enabled else 0,
                1 if subscription_allowlist_enabled else 0,
                subscription_networks, int(audit_retention_days), _iso(),
            ),
        )
    purge_security_history()
    return get_security_settings()


def record_login_attempt(ip_address: str, success: bool, user_agent: str = "") -> None:
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO login_attempts (ip_address, success, user_agent, attempted_at)
            VALUES (?, ?, ?, ?)
            """,
            (ip_address[:80], 1 if success else 0, user_agent[:500], _iso()),
        )


def login_block_status(ip_address: str) -> dict[str, int | bool]:
    settings = get_security_settings()
    now = _now()
    window_start = now - timedelta(minutes=int(settings["lockout_minutes"]))
    with connect() as con:
        last_success_row = con.execute(
            """
            SELECT attempted_at FROM login_attempts
            WHERE ip_address = ? AND success = 1
            ORDER BY id DESC LIMIT 1
            """,
            (ip_address,),
        ).fetchone()
        last_success = _parse(last_success_row["attempted_at"]) if last_success_row else None
        since = max(filter(None, [window_start, last_success])) if last_success else window_start
        rows = con.execute(
            """
            SELECT attempted_at FROM login_attempts
            WHERE ip_address = ? AND success = 0 AND attempted_at >= ?
            ORDER BY attempted_at ASC
            """,
            (ip_address, _iso(since)),
        ).fetchall()
    count = len(rows)
    max_attempts = int(settings["max_login_attempts"])
    if count < max_attempts:
        return {"blocked": False, "attempts": count, "retry_after": 0}
    first = _parse(rows[0]["attempted_at"]) or now
    unlock_at = first + timedelta(minutes=int(settings["lockout_minutes"]))
    retry_after = max(0, int((unlock_at - now).total_seconds()))
    return {
        "blocked": retry_after > 0,
        "attempts": count,
        "retry_after": retry_after,
    }


def create_admin_session(ip_address: str, user_agent: str = "") -> str:
    init_db()
    session_id = secrets.token_urlsafe(36)
    now = _iso()
    with connect() as con:
        con.execute(
            """
            INSERT INTO admin_sessions
                (id, ip_address, user_agent, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, ip_address[:80], user_agent[:500], now, now),
        )
    return session_id


def validate_admin_session(session_id: str | None) -> sqlite3.Row | None:
    if not session_id:
        return None
    settings = get_security_settings()
    now = _now()
    with connect() as con:
        row = con.execute(
            "SELECT * FROM admin_sessions WHERE id = ? AND revoked_at IS NULL",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        last_seen = _parse(row["last_seen_at"]) or now
        if now - last_seen > timedelta(minutes=int(settings["session_timeout_minutes"])):
            con.execute(
                "UPDATE admin_sessions SET revoked_at = ? WHERE id = ?",
                (_iso(now), session_id),
            )
            return None
        if now - last_seen > timedelta(seconds=30):
            con.execute(
                "UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?",
                (_iso(now), session_id),
            )
            row = con.execute(
                "SELECT * FROM admin_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return row


def list_admin_sessions(limit: int = 100) -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute(
            """
            SELECT * FROM admin_sessions
            ORDER BY (revoked_at IS NULL) DESC, last_seen_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 500)),),
        ).fetchall()


def revoke_admin_session(session_id: str) -> bool:
    with connect() as con:
        cur = con.execute(
            """
            UPDATE admin_sessions SET revoked_at = COALESCE(revoked_at, ?)
            WHERE id = ?
            """,
            (_iso(), session_id),
        )
        return cur.rowcount > 0


def revoke_all_admin_sessions(*, except_session_id: str | None = None) -> int:
    with connect() as con:
        if except_session_id:
            cur = con.execute(
                """
                UPDATE admin_sessions SET revoked_at = ?
                WHERE revoked_at IS NULL AND id != ?
                """,
                (_iso(), except_session_id),
            )
        else:
            cur = con.execute(
                "UPDATE admin_sessions SET revoked_at = ? WHERE revoked_at IS NULL",
                (_iso(),),
            )
        return int(cur.rowcount)


def write_audit(
    event: str,
    *,
    detail: str = "",
    ip_address: str = "",
    user_agent: str = "",
    success: bool = True,
) -> None:
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO audit_log
                (event, detail, ip_address, user_agent, success, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event[:100], detail[:1000], ip_address[:80], user_agent[:500],
                1 if success else 0, _iso(),
            ),
        )


def list_audit_log(limit: int = 200) -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit), 1000)),),
        ).fetchall()


def recent_login_attempts(limit: int = 100) -> list[sqlite3.Row]:
    init_db()
    with connect() as con:
        return con.execute(
            "SELECT * FROM login_attempts ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        ).fetchall()


def purge_security_history() -> None:
    settings = get_security_settings()
    cutoff = _now() - timedelta(days=int(settings["audit_retention_days"]))
    old_sessions = _now() - timedelta(days=max(7, int(settings["audit_retention_days"])))
    with connect() as con:
        con.execute("DELETE FROM audit_log WHERE created_at < ?", (_iso(cutoff),))
        con.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (_iso(cutoff),))
        con.execute(
            """
            DELETE FROM admin_sessions
            WHERE revoked_at IS NOT NULL AND last_seen_at < ?
            """,
            (_iso(old_sessions),),
        )


def security_overview() -> dict[str, int]:
    init_db()
    with connect() as con:
        active_sessions = int(
            con.execute(
                "SELECT COUNT(*) FROM admin_sessions WHERE revoked_at IS NULL"
            ).fetchone()[0]
        )
        failed_24h = int(
            con.execute(
                """
                SELECT COUNT(*) FROM login_attempts
                WHERE success = 0 AND attempted_at >= ?
                """,
                (_iso(_now() - timedelta(hours=24)),),
            ).fetchone()[0]
        )
        audit_events = int(con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
    return {
        "active_sessions": active_sessions,
        "failed_logins_24h": failed_24h,
        "audit_events": audit_events,
    }
