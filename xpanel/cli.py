from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid as uuidlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .db import connect, db_path, init_db


def fail(message: str, code: int = 1) -> int:
    print(f"Ошибка: {message}", file=sys.stderr)
    return code


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("для этой команды нужны права root")


def get_server() -> sqlite3.Row:
    init_db()
    with connect() as con:
        row = con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
    if row is None:
        raise RuntimeError("настройки сервера ещё не заданы; выполните set-server")
    return row


def find_user(identifier: str) -> sqlite3.Row:
    init_db()
    with connect() as con:
        if identifier.isdigit():
            row = con.execute(
                "SELECT * FROM users WHERE id = ?", (int(identifier),)
            ).fetchone()
        else:
            row = con.execute(
                "SELECT * FROM users WHERE name = ? COLLATE NOCASE", (identifier,)
            ).fetchone()
    if row is None:
        raise RuntimeError(f"пользователь не найден: {identifier}")
    return row


def validate_server_values(
    address: str,
    port: int,
    dest: str,
    server_name: str,
    private_key: str,
    public_key: str,
    short_id: str,
) -> None:
    fields = {
        "address": address,
        "dest": dest,
        "server_name": server_name,
        "private_key": private_key,
        "public_key": public_key,
        "short_id": short_id,
    }
    empty = [name for name, value in fields.items() if not value or not value.strip()]
    if empty:
        raise ValueError("пустые обязательные поля: " + ", ".join(empty))
    if not 1 <= port <= 65535:
        raise ValueError("port должен быть от 1 до 65535")
    if not re.fullmatch(r"[0-9a-fA-F]{2,32}", short_id):
        raise ValueError("short_id должен быть HEX-строкой чётной длины от 2 до 32 символов")
    if ":" not in dest:
        raise ValueError("dest должен иметь вид host:port")


def cmd_init_db(_args: argparse.Namespace) -> int:
    path = init_db()
    print(f"База данных готова: {path}")
    return 0


def cmd_gen_keys(args: argparse.Namespace) -> int:
    xray_bin = args.xray_bin
    if not Path(xray_bin).is_file() and shutil.which(xray_bin) is None:
        return fail(f"Xray не найден: {xray_bin}")

    proc = subprocess.run(
        [xray_bin, "x25519"],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        return fail(f"xray x25519 завершился с ошибкой: {detail}")

    output = proc.stdout + "\n" + proc.stderr
    private_match = re.search(r"(?m)^PrivateKey:\s*(\S+)\s*$", output)
    public_match = re.search(
        r"(?m)^(?:Password\s*\(PublicKey\)|PublicKey):\s*(\S+)\s*$",
        output,
    )

    if not private_match or not public_match:
        return fail(
            "не удалось разобрать вывод xray x25519; ожидались "
            "'PrivateKey:' и 'Password (PublicKey):'"
        )

    private_key = private_match.group(1).strip()
    public_key = public_match.group(1).strip()
    short_id = secrets.token_hex(8)

    if not private_key or not public_key:
        return fail("Xray вернул пустой private/public key")

    print(f"PrivateKey: {private_key}")
    print(f"PublicKey: {public_key}")
    print(f"ShortID: {short_id}")

    if args.save:
        path = Path(args.save).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f'PRIVATE_KEY="{private_key}"\n'
            f'PUBLIC_KEY="{public_key}"\n'
            f'SHORT_ID="{short_id}"\n',
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        print(f"Сохранено: {path}")

    if args.print_set_server:
        values = {
            "address": "192.168.1.200",
            "port": "443",
            "dest": "www.microsoft.com:443",
            "server_name": "www.microsoft.com",
            "private_key": private_key,
            "public_key": public_key,
            "short_id": short_id,
        }
        command = [
            "python3", "-m", "xpanel", "set-server",
            "--address", values["address"],
            "--port", values["port"],
            "--dest", values["dest"],
            "--server-name", values["server_name"],
            "--private-key", values["private_key"],
            "--public-key", values["public_key"],
            "--short-id", values["short_id"],
        ]
        print("\nКоманда set-server:")
        print(" ".join(shlex.quote(part) for part in command))

    return 0


def cmd_set_server(args: argparse.Namespace) -> int:
    validate_server_values(
        args.address,
        args.port,
        args.dest,
        args.server_name,
        args.private_key,
        args.public_key,
        args.short_id,
    )
    init_db()
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint,
                config_path, xray_bin, xray_service
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                address = excluded.address,
                listen = excluded.listen,
                port = excluded.port,
                dest = excluded.dest,
                server_name = excluded.server_name,
                private_key = excluded.private_key,
                public_key = excluded.public_key,
                short_id = excluded.short_id,
                fingerprint = excluded.fingerprint,
                config_path = excluded.config_path,
                xray_bin = excluded.xray_bin,
                xray_service = excluded.xray_service
            """,
            (
                args.address,
                args.listen,
                args.port,
                args.dest,
                args.server_name,
                args.private_key,
                args.public_key,
                args.short_id,
                args.fingerprint,
                args.config_path,
                args.xray_bin,
                args.xray_service,
            ),
        )
    print("Настройки сервера сохранены.")
    return 0


def cmd_show_server(_args: argparse.Namespace) -> int:
    server = get_server()
    print(f"Address:      {server['address']}")
    print(f"Listen:       {server['listen']}")
    print(f"Port:         {server['port']}")
    print(f"Dest:         {server['dest']}")
    print(f"Server name:  {server['server_name']}")
    print(f"Private key:  {'установлен' if server['private_key'] else 'ПУСТО'}")
    print(f"Public key:   {server['public_key']}")
    print(f"Short ID:     {server['short_id']}")
    print(f"Fingerprint:  {server['fingerprint']}")
    print(f"Flow:         {server['flow']}")
    print(f"Log level:    {server['loglevel']}")
    print(f"Stats API:    {server['api_listen'] if server['stats_enabled'] else 'disabled'}")
    print(f"Config:       {server['config_path']}")
    print(f"Xray binary:  {server['xray_bin']}")
    print(f"Service:      {server['xray_service']}")
    return 0


def cmd_add_user(args: argparse.Namespace) -> int:
    init_db()
    user_uuid = args.uuid or str(uuidlib.uuid4())
    try:
        uuidlib.UUID(user_uuid)
    except ValueError:
        return fail("некорректный UUID")

    try:
        with connect() as con:
            cur = con.execute(
                """
                INSERT INTO users (name, uuid, enabled, subscription_token)
                VALUES (?, ?, ?, ?)
                """,
                (
                    args.name.strip(), user_uuid, 0 if args.disabled else 1,
                    secrets.token_urlsafe(32),
                ),
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError as exc:
        return fail(f"пользователь с таким именем или UUID уже существует: {exc}")

    print(f"Пользователь добавлен: id={user_id}, name={args.name}, uuid={user_uuid}")
    return 0


def cmd_list_users(_args: argparse.Namespace) -> int:
    init_db()
    with connect() as con:
        rows = con.execute(
            "SELECT id, name, uuid, enabled, created_at FROM users ORDER BY id"
        ).fetchall()

    if not rows:
        print("Пользователей нет.")
        return 0

    print(f"{'ID':<5} {'STATE':<9} {'NAME':<24} UUID")
    for row in rows:
        state = "enabled" if row["enabled"] else "disabled"
        print(f"{row['id']:<5} {state:<9} {row['name']:<24} {row['uuid']}")
    return 0


def set_user_enabled(identifier: str, enabled: bool) -> int:
    user = find_user(identifier)
    with connect() as con:
        con.execute(
            "UPDATE users SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, user["id"]),
        )
    print(f"{user['name']}: {'enabled' if enabled else 'disabled'}")
    return 0


def cmd_enable_user(args: argparse.Namespace) -> int:
    return set_user_enabled(args.user, True)


def cmd_disable_user(args: argparse.Namespace) -> int:
    return set_user_enabled(args.user, False)


def cmd_delete_user(args: argparse.Namespace) -> int:
    user = find_user(args.user)
    with connect() as con:
        con.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    print(f"Пользователь удалён: {user['name']}")
    return 0


def build_config():
    from .service import build_config as service_build_config
    return service_build_config()


def render_text():
    from .service import render_text as service_render_text
    return service_render_text()

def cmd_render(args: argparse.Namespace) -> int:
    text, server, users = render_text()
    output = Path(args.output) if args.output else (db_path().parent / "rendered-config.json")
    if args.stdout:
        print(text, end="")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    os.chmod(output, 0o644)
    print(f"Конфигурация создана: {output}")
    print(f"Активных пользователей: {len(users)}")
    return 0


def run_xray_test(xray_bin: str, config_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [xray_bin, "run", "-test", "-config", str(config_path)],
        text=True,
        capture_output=True,
    )


def cmd_apply(_args: argparse.Namespace) -> int:
    from .service import apply_config
    result = apply_config()
    print(f"Конфигурация применена: {result['config_path']}")
    if result.get("backup_path"):
        print(f"Резервная копия: {result['backup_path']}")
    print(f"Активных пользователей: {result['enabled_users']}")
    print(f"Активных routing rules: {result['enabled_rules']}")
    print("Xray: active")
    return 0

def cmd_show_link(args: argparse.Namespace) -> int:
    from .service import make_link
    print(make_link(args.user, allow_disabled=args.allow_disabled))
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    from .service import get_status
    status = get_status()
    print(f"Database:       {status['db_path']}")
    print(f"Users:          {status['enabled_users']} enabled / {status['total_users']} total")
    print(f"Expired:        {status['expired_users']}")
    print(f"Traffic:        {status['traffic_total_human']}")
    print(f"Routing rules:  {status['rules_enabled']} enabled / {status['rules_total']} total")
    print(f"Xray service:   {status['service']}")
    print(f"Xray config:    {status['config_state']} ({status['config_path']})")
    print(f"Stats API:      {status['api_listen'] if status['stats_enabled'] else 'disabled'}")
    return 0


def cmd_expire_users(args: argparse.Namespace) -> int:
    from .service import expire_users
    users = expire_users(apply=args.apply)
    if not users:
        print("Просроченных активных пользователей нет.")
        return 0
    print("Отключены просроченные пользователи:")
    for user in users:
        print(f"- {user['name']} (id={user['id']})")
    if args.apply:
        print("Конфигурация применена.")
    return 0


def cmd_backup(_args: argparse.Namespace) -> int:
    from .service import create_backup
    result = create_backup()
    print(f"Backup создан: {result['name']}")
    return 0


def cmd_diagnostics(_args: argparse.Namespace) -> int:
    from .service import diagnostic_report
    print(diagnostic_report())
    return 0



def cmd_list_outbounds(_args: argparse.Namespace) -> int:
    from .service import get_routing_settings, list_outbounds
    default_tag = get_routing_settings()["default_outbound_tag"]
    print(f"{'TAG':20} {'TYPE':16} {'STATE':10} {'DEFAULT':8} TARGET")
    for item in list_outbounds():
        target = "system"
        if not item.get("system"):
            target = f"{item['address']}:{item['port']}"
        print(
            f"{str(item['tag']):20} {str(item['protocol']):16} "
            f"{('enabled' if item['enabled'] else 'disabled'):10} "
            f"{('*' if item['tag'] == default_tag else ''):8} {target}"
        )
    return 0


def cmd_add_vless_outbound(args: argparse.Namespace) -> int:
    from .service import add_vless_outbound
    row = add_vless_outbound(
        tag=args.tag,
        name=args.name,
        address=args.address,
        port=args.port,
        user_uuid=args.uuid,
        flow=args.flow,
        server_name=args.server_name,
        public_key=args.public_key,
        short_id=args.short_id,
        fingerprint=args.fingerprint,
        spider_x=args.spider_x,
        network=args.network,
        security=args.security,
        xhttp_host=args.xhttp_host,
        xhttp_path=args.xhttp_path,
        xhttp_mode=args.xhttp_mode,
        allow_insecure=args.allow_insecure,
        alpn=args.alpn,
    )
    print(f"Outbound добавлен: {row['tag']} -> {row['address']}:{row['port']}")
    return 0


def cmd_delete_outbound(args: argparse.Namespace) -> int:
    from .service import delete_outbound
    row = delete_outbound(args.id)
    print(f"Outbound удалён: {row['tag']}")
    return 0


def cmd_test_outbound(args: argparse.Namespace) -> int:
    from .service import test_outbound_tcp
    result = test_outbound_tcp(args.id)
    if result['ok']:
        print(f"TCP доступен: {result['latency_ms']} ms")
        return 0
    return fail(f"TCP недоступен: {result['detail']}")



def cmd_list_dns(_args: argparse.Namespace) -> int:
    from .service import get_dns_settings, list_dns_hosts, list_dns_servers
    settings = get_dns_settings()
    print(f"DNS: {'enabled' if settings['enabled'] else 'disabled'}; strategy={settings['query_strategy']}")
    for row in list_dns_servers():
        state = 'enabled' if row['enabled'] else 'disabled'
        print(f"SERVER {row['id']}: {row['name']} | {row['address']} | priority={row['priority']} | {state}")
    for row in list_dns_hosts():
        state = 'enabled' if row['enabled'] else 'disabled'
        values = str(row['addresses']).replace(chr(10), ', ')
        print(f"HOST {row['id']}: {row['domain']} -> {values} | {state}")
    return 0


def cmd_dns_preview(_args: argparse.Namespace) -> int:
    from .service import preview_dns_json
    print(preview_dns_json(), end='')
    return 0

def cmd_list_subscriptions(args: argparse.Namespace) -> int:
    from .service import get_subscription_settings, list_users, make_subscription_url
    settings = get_subscription_settings()
    print(
        f"Subscriptions: {'enabled' if settings['enabled'] else 'disabled'}; "
        f"base_url={settings['base_url'] or args.base_url or '(auto unavailable in CLI)'}"
    )
    print(f"{'ID':<5} {'STATE':<10} {'USER':<24} URL")
    for user in list_users():
        state = 'enabled' if user['subscription_enabled'] else 'disabled'
        try:
            url = make_subscription_url(user['id'], args.base_url)
        except RuntimeError:
            url = '(set --base-url or configure it in GUI)'
        print(f"{user['id']:<5} {state:<10} {user['name']:<24} {url}")
    return 0


def cmd_show_subscription(args: argparse.Namespace) -> int:
    from .service import make_subscription_url
    print(make_subscription_url(args.user, args.base_url))
    return 0


def cmd_regenerate_subscription(args: argparse.Namespace) -> int:
    from .service import regenerate_subscription_token, make_subscription_url
    user = regenerate_subscription_token(args.user)
    print(f"Новый token создан для {user['name']}")
    if args.base_url:
        print(make_subscription_url(user['id'], args.base_url))
    return 0


def cmd_set_subscription(args: argparse.Namespace) -> int:
    from .service import set_user_subscription_enabled
    user = set_user_subscription_enabled(args.user, args.enabled)
    print(
        f"Подписка {user['name']}: "
        f"{'enabled' if user['subscription_enabled'] else 'disabled'}"
    )
    return 0


def cmd_security_status(_args: argparse.Namespace) -> int:
    from .security import get_security_settings, security_overview
    settings = get_security_settings()
    overview = security_overview()
    print(f"session_timeout_minutes={settings['session_timeout_minutes']}")
    print(f"max_login_attempts={settings['max_login_attempts']}")
    print(f"lockout_minutes={settings['lockout_minutes']}")
    print(f"allowlist_enabled={bool(settings['allowlist_enabled'])}")
    print(f"allowed_networks={settings['allowed_networks'] or '(all)'}")
    print(f"active_sessions={overview['active_sessions']}")
    print(f"failed_logins_24h={overview['failed_logins_24h']}")
    return 0


def cmd_revoke_sessions(args: argparse.Namespace) -> int:
    from .security import revoke_all_admin_sessions
    count = revoke_all_admin_sessions()
    print(f"Завершено сессий: {count}")
    return 0


def cmd_unlock_admin(args: argparse.Namespace) -> int:
    require_root()
    from .security import clear_failed_login_attempts

    count = clear_failed_login_attempts(args.ip)
    if args.ip:
        print(f"Блокировка входа снята для IP {args.ip}. Удалено неудачных попыток: {count}")
    else:
        print(f"Блокировка входа снята для всех IP. Удалено неудачных попыток: {count}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xpanel",
        description="CLI-ядро SG-Panel для управления Xray Reality",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-db", help="создать SQLite-базу")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("gen-keys", help="сгенерировать Reality-ключи и ShortID")
    p.add_argument("--xray-bin", default="/usr/local/bin/xray")
    p.add_argument("--save", help="сохранить ключи в env-файл")
    p.add_argument("--print-set-server", action="store_true")
    p.set_defaults(func=cmd_gen_keys)

    p = sub.add_parser("set-server", help="сохранить настройки Reality-сервера")
    p.add_argument("--address", required=True, help="IP или домен для клиентской ссылки")
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--dest", required=True, help="например www.microsoft.com:443")
    p.add_argument("--server-name", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--short-id", required=True)
    p.add_argument("--fingerprint", default="chrome")
    p.add_argument("--config-path", default="/usr/local/etc/xray/config.json")
    p.add_argument("--xray-bin", default="/usr/local/bin/xray")
    p.add_argument("--xray-service", default="xray")
    p.set_defaults(func=cmd_set_server)

    p = sub.add_parser("show-server", help="показать настройки сервера")
    p.set_defaults(func=cmd_show_server)

    p = sub.add_parser("add-user", help="добавить пользователя")
    p.add_argument("name")
    p.add_argument("--uuid")
    p.add_argument("--disabled", action="store_true")
    p.set_defaults(func=cmd_add_user)

    p = sub.add_parser("list-users", help="показать пользователей")
    p.set_defaults(func=cmd_list_users)

    for command, help_text, func in (
        ("enable-user", "включить пользователя", cmd_enable_user),
        ("disable-user", "отключить пользователя", cmd_disable_user),
        ("delete-user", "удалить пользователя", cmd_delete_user),
    ):
        p = sub.add_parser(command, help=help_text)
        p.add_argument("user", help="ID или имя пользователя")
        p.set_defaults(func=func)

    p = sub.add_parser("render", help="сгенерировать config.json без перезапуска")
    p.add_argument("--output")
    p.add_argument("--stdout", action="store_true")
    p.set_defaults(func=cmd_render)

    p = sub.add_parser(
        "apply",
        help="backup, xray run -test, атомарная установка и restart",
    )
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("show-link", help="показать VLESS Reality-ссылку")
    p.add_argument("user", help="ID или имя пользователя")
    p.add_argument("--allow-disabled", action="store_true")
    p.set_defaults(func=cmd_show_link)

    p = sub.add_parser("status", help="показать состояние базы, конфига и Xray")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("expire-users", help="отключить пользователей с истёкшим сроком")
    p.add_argument("--apply", action="store_true", help="сразу применить config.json")
    p.set_defaults(func=cmd_expire_users)

    p = sub.add_parser("backup", help="создать backup panel.db и config.json")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("diagnostics", help="показать диагностический отчёт")
    p.set_defaults(func=cmd_diagnostics)


    p = sub.add_parser("security-status", help="показать настройки безопасности и сессии")
    p.set_defaults(func=cmd_security_status)

    p = sub.add_parser("revoke-sessions", help="завершить все административные сессии")
    p.set_defaults(func=cmd_revoke_sessions)

    p = sub.add_parser("unlock-admin", help="снять блокировку входа в панель")
    p.add_argument("--ip", help="снять блокировку только для указанного IP")
    p.set_defaults(func=cmd_unlock_admin)

    p = sub.add_parser("list-outbounds", help="показать системные и пользовательские outbounds")
    p.set_defaults(func=cmd_list_outbounds)

    p = sub.add_parser("add-vless-outbound", help="добавить VLESS outbound для каскада")
    p.add_argument("--tag", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--address", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--uuid", required=True)
    p.add_argument("--flow", default="xtls-rprx-vision")
    p.add_argument("--network", choices=("raw", "xhttp"), default="raw")
    p.add_argument("--security", choices=("reality", "tls"), default="reality")
    p.add_argument("--server-name", required=True)
    p.add_argument("--public-key", default="", help="Reality password/public key второго сервера")
    p.add_argument("--short-id", default="")
    p.add_argument("--fingerprint", default="chrome")
    p.add_argument("--spider-x", default="")
    p.add_argument("--xhttp-host", default="")
    p.add_argument("--xhttp-path", default="/")
    p.add_argument("--xhttp-mode", choices=("auto", "packet-up", "stream-up", "stream-one"), default="auto")
    p.add_argument("--allow-insecure", action="store_true")
    p.add_argument("--alpn", default="", help="значения ALPN через запятую")
    p.set_defaults(func=cmd_add_vless_outbound)

    p = sub.add_parser("delete-outbound", help="удалить пользовательский outbound")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_delete_outbound)

    p = sub.add_parser("test-outbound", help="проверить доступность TCP-порта outbound")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_test_outbound)

    p = sub.add_parser("list-dns", help="показать настройки DNS, серверы и hosts")
    p.set_defaults(func=cmd_list_dns)

    p = sub.add_parser("dns-preview", help="показать генерируемый раздел DNS в JSON")
    p.set_defaults(func=cmd_dns_preview)

    p = sub.add_parser("list-subscriptions", help="показать подписки пользователей")
    p.add_argument("--base-url", default="", help="базовый URL, если он не задан в GUI")
    p.set_defaults(func=cmd_list_subscriptions)

    p = sub.add_parser("show-subscription", help="показать постоянный URL подписки")
    p.add_argument("user", help="ID или имя пользователя")
    p.add_argument("--base-url", default="", help="базовый URL, если он не задан в GUI")
    p.set_defaults(func=cmd_show_subscription)

    p = sub.add_parser("regenerate-subscription", help="создать новый token подписки")
    p.add_argument("user", help="ID или имя пользователя")
    p.add_argument("--base-url", default="")
    p.set_defaults(func=cmd_regenerate_subscription)

    for command, enabled, help_text in (
        ("enable-subscription", True, "включить подписку пользователя"),
        ("disable-subscription", False, "отключить подписку пользователя"),
    ):
        p = sub.add_parser(command, help=help_text)
        p.add_argument("user", help="ID или имя пользователя")
        p.set_defaults(func=cmd_set_subscription, enabled=enabled)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except (RuntimeError, ValueError, PermissionError, FileNotFoundError) as exc:
        return fail(str(exc))
    except KeyboardInterrupt:
        print("\nОтменено.", file=sys.stderr)
        return 130
