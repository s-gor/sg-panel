from __future__ import annotations

import getpass
import os
import re
import sqlite3
import subprocess
import tempfile
import urllib.request
import zipfile
import sys
import time
from pathlib import Path
from typing import Callable

from werkzeug.security import generate_password_hash

from . import __version__
from .db import connect, init_db
from .security import revoke_all_admin_sessions
from .service import XPanelError, create_backup, list_backups, restore_backup, verify_backup
from .update_manager import version_key

PROJECT_DIR = Path("/opt/xpanel-mvp")
ENV_FILE = Path("/etc/xpanel-mvp/web.env")
SERVICE_UNITS = [
    "xpanel-web.service",
    "xray.service",
    "nginx.service",
    "sg-node-agent.service",
    "sg-node-worker.service",
]
MENU_WIDTH = 70


class _Colors:
    def __init__(self) -> None:
        enabled = bool(sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.green = "\033[1;32m" if enabled else ""
        self.cyan = "\033[1;36m" if enabled else ""
        self.yellow = "\033[1;33m" if enabled else ""
        self.red = "\033[1;31m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""


C = _Colors()


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Запустите меню через sudo sg-panel")


def _read_server_row() -> sqlite3.Row | None:
    try:
        init_db()
        with connect() as con:
            return con.execute("SELECT * FROM server_settings WHERE id = 1").fetchone()
    except Exception:
        return None


def _read_instance_meta() -> tuple[str, str]:
    name = "SG-Panel"
    address = "Адрес не определён"
    server = _read_server_row()
    if server is not None:
        name = str(server["instance_name"] or "").strip() or name
        address = str(server["address"] or address)
    env = Path("/etc/xpanel-mvp/panel-access.env")
    if env.exists():
        values: dict[str, str] = {}
        for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        name = values.get("PANEL_SERVER_NAME") or values.get("SERVER_NAME") or name
        host = values.get("PANEL_PUBLIC_HOST") or values.get("PANEL_DOMAIN") or ""
        port = values.get("PANEL_PUBLIC_PORT") or ""
        scheme = "https" if (values.get("PANEL_ACCESS_MODE") or "").lower() == "https" else "http"
        if host:
            default_port = "443" if scheme == "https" else "80"
            address = f"{scheme}://{host}" + (f":{port}" if port and port != default_port else "")
    return name, address


def _service_state(unit: str) -> str:
    result = subprocess.run(
        ["systemctl", "is-active", unit],
        capture_output=True,
        text=True,
        check=False,
    )
    state = (result.stdout or result.stderr).strip()
    return state or "unknown"


def _unit_exists(unit: str) -> bool:
    result = subprocess.run(
        ["systemctl", "status", unit],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode != 4


def _pause() -> None:
    input("\nНажмите Enter для возврата в меню...")


def _header(title: str) -> None:
    print(f"\n{C.cyan}{'─' * MENU_WIDTH}{C.reset}")
    print(f"{C.bold}{title}{C.reset}")
    print(f"{C.cyan}{'─' * MENU_WIDTH}{C.reset}")


def _clip(value: object, width: int) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


def _state_mark(state: str) -> str:
    normalized = str(state or "unknown").strip().lower()
    if normalized in {"active", "online"}:
        return f"{C.green}●{C.reset} {normalized}"
    if normalized in {"inactive", "offline", "disabled", "not-installed"}:
        return f"{C.yellow}●{C.reset} {normalized}"
    return f"{C.red}●{C.reset} {normalized}"


def _visible_len(text: str) -> int:
    return len(text)


def _box_row(text: str = "") -> str:
    content = _clip(text, MENU_WIDTH - 4)
    return f"│ {content}{' ' * (MENU_WIDTH - 4 - _visible_len(content))} │"


def _menu_header() -> list[str]:
    name, address = _read_instance_meta()
    service_parts: list[str] = []
    labels = {
        "xpanel-web.service": "Panel",
        "xray.service": "Xray",
        "nginx.service": "Nginx",
        "sg-node-agent.service": "Agent",
        "sg-node-worker.service": "Worker",
    }
    for unit in SERVICE_UNITS:
        if _unit_exists(unit):
            service_parts.append(f"{labels[unit]} {_service_state(unit)}")
    services = " · ".join(service_parts) or "службы не определены"
    return [
        "╭" + "─" * (MENU_WIDTH - 2) + "╮",
        _box_row(f"SG-PANEL v{__version__} · УПРАВЛЕНИЕ СЕРВЕРОМ"),
        "├" + "─" * (MENU_WIDTH - 2) + "┤",
        _box_row(name),
        _box_row(address),
        _box_row(services),
        "├" + "─" * (MENU_WIDTH - 2) + "┤",
    ]


def _menu_items() -> list[tuple[str, str, Callable[[], None], str]]:
    return [
        ("1", "Состояние панели и адрес", show_status, "normal"),
        ("2", "Перезапустить все службы", restart_all, "normal"),
        ("3", "Сменить пароль администратора", change_password, "accent"),
        ("4", "Создать резервную копию", create_backup_interactive, "normal"),
        ("5", "Проверить резервную копию", verify_backup_interactive, "normal"),
        ("6", "Восстановить резервную копию", restore_backup_interactive, "warning"),
        ("7", "Обновить SG-Panel", update_panel_interactive, "warning"),
    ]


def show_status() -> None:
    _header("SG-Panel · Состояние панели и адрес")
    name, address = _read_instance_meta()
    print(f"Версия панели: v{__version__}")
    print(f"Сервер:        {name}")
    print(f"Адрес панели:  {address}")
    print("")
    try:
        from .service import get_status

        status = get_status()
        print(f"База данных:   {status['db_path']}")
        print(f"Пользователи:  {status['enabled_users']} enabled / {status['total_users']} total")
        print(f"Истёкшие:      {status['expired_users']}")
        print(f"Трафик:        {status['traffic_total_human']}")
        print(f"Routing:       {status['rules_enabled']} enabled / {status['rules_total']} total")
        print(f"Xray config:   {status['config_state']} ({status['config_path']})")
    except Exception as exc:
        print(f"Не удалось прочитать сводку панели: {exc}")
    print("\nСлужбы:")
    for unit in SERVICE_UNITS:
        if _unit_exists(unit):
            print(f"- {unit:<22} {_state_mark(_service_state(unit))}")
    _pause()


def restart_all() -> None:
    _header("SG-Panel · Перезапуск всех служб")
    targets = [unit for unit in SERVICE_UNITS if _unit_exists(unit)]
    if not targets:
        print("Не найдено ни одной управляемой службы.")
        _pause()
        return
    print("Будут перезапущены:")
    for unit in targets:
        print(f"- {unit}")
    confirm = input("\nПродолжить? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes", "д", "да"}:
        print("Отменено.")
        _pause()
        return
    for unit in targets:
        print(f"Перезапуск {unit}...")
        subprocess.run(["systemctl", "restart", unit], check=False)
    time.sleep(2)
    print("\nИтоговый статус:")
    for unit in targets:
        print(f"- {unit:<22} {_state_mark(_service_state(unit))}")
    _pause()


def change_password() -> None:
    _header("SG-Panel · Смена пароля администратора")
    if not ENV_FILE.exists():
        print(f"Не найден файл окружения: {ENV_FILE}")
        _pause()
        return
    new_password = getpass.getpass("Новый пароль (не менее 8 символов): ")
    repeat = getpass.getpass("Повторите новый пароль: ")
    if len(new_password) < 8:
        print("Пароль слишком короткий.")
        _pause()
        return
    if new_password != repeat:
        print("Пароли не совпадают.")
        _pause()
        return
    password_hash = generate_password_hash(new_password)
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    updates = {
        "XPANEL_PASSWORD_HASH": password_hash,
        "XPANEL_SECRET_KEY": __import__("secrets").token_urlsafe(48),
    }
    output: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in updates:
            output.append(f"{key}={updates.pop(key)}")
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in updates.items())
    ENV_FILE.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(ENV_FILE, 0o600)
    revoke_all_admin_sessions()
    subprocess.run(["systemctl", "restart", "xpanel-web"], check=False)
    print(f"{C.green}OK{C.reset} Пароль изменён. Все сессии браузера сброшены, веб-панель перезапущена.")
    _pause()


def create_backup_interactive() -> None:
    _header("SG-Panel · Создать резервную копию")
    result = create_backup()
    print(f"{C.green}OK{C.reset} Резервная копия создана: {result['name']}")
    print(f"Проверка: {'OK' if result.get('verified') else 'Ошибка'}")
    if result.get("verification_detail"):
        print(f"Детали:   {result['verification_detail']}")
    _pause()


def _select_backup(action: str) -> str | None:
    backups = list_backups()
    if not backups:
        print("Резервных копий нет.")
        return None
    print(f"\nДоступные резервные копии ({action}):")
    for index, item in enumerate(backups, start=1):
        status = "OK" if item.get("verified") else "ERR"
        print(
            f"{index}. {item['name']}  |  {item['created_at']}  |  {item['size_human']}  |  {status}"
        )
    raw = input("\nВведите номер копии (или Enter для отмены): ").strip()
    if not raw:
        return None
    if not raw.isdigit() or not (1 <= int(raw) <= len(backups)):
        print("Неверный выбор.")
        return None
    return str(backups[int(raw) - 1]["name"])


def verify_backup_interactive() -> None:
    _header("SG-Panel · Проверить резервную копию")
    name = _select_backup("проверка")
    if not name:
        _pause()
        return
    result = verify_backup(name)
    print(f"\nКопия:   {result['name']}")
    print(f"Статус:  {'OK' if result['ok'] else 'Ошибка'}")
    print(f"Детали:  {result['detail']}")
    print(f"Клиенты: {result['users']}")
    _pause()


def restore_backup_interactive() -> None:
    _header("SG-Panel · Восстановить резервную копию")
    name = _select_backup("восстановление")
    if not name:
        _pause()
        return
    confirm = input(f"\nВосстановить {name}? Будет создана страховочная копия. [y/N]: ").strip().lower()
    if confirm not in {"y", "yes", "д", "да"}:
        print("Отменено.")
        _pause()
        return
    try:
        result = restore_backup(name)
    except Exception as exc:
        print(f"Ошибка восстановления: {exc}")
        _pause()
        return
    print(f"{C.green}OK{C.reset} Восстановление завершено: {result['name']}")
    print(f"Страховочная копия:       {result['safety']}")
    print(f"Клиенты в копии:          {result['users']}")
    print(f"Конфиг:                   {result['config_path']}")
    print(f"Служба Xray:              {result['service']}")
    _pause()


def update_panel_interactive() -> None:
    _header("SG-Panel · Обновить SG-Panel")
    print(f"Текущая версия: v{__version__}")
    print("Источник:        GitHub main · s-gor/sg-panel")
    print("Проверяю версию в GitHub main...")

    url = "https://github.com/s-gor/sg-panel/archive/refs/heads/main.zip"
    try:
        with tempfile.TemporaryDirectory(prefix="sg-panel-ssh-update-") as temp_dir:
            archive = Path(temp_dir) / "sg-panel-main.zip"
            source_dir = Path(temp_dir) / "source"
            request = urllib.request.Request(url, headers={"User-Agent": "SG-Panel-SSH-Menu"})
            with urllib.request.urlopen(request, timeout=45) as response:  # nosec B310
                archive.write_bytes(response.read())
            if archive.stat().st_size < 100_000:
                raise XPanelError("загруженный архив слишком мал")
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(source_dir)
            candidates = list(source_dir.glob("*/install-or-upgrade.sh"))
            if len(candidates) != 1:
                raise XPanelError("не удалось определить корень исходников GitHub main")
            installer = candidates[0]
            root = installer.parent
            version_file = root / "xpanel" / "__init__.py"
            if not version_file.is_file():
                raise XPanelError("архив GitHub main не содержит SG-Panel")
            match = re.search(
                r"__version__\s*=\s*['\"]([^'\"]+)['\"]",
                version_file.read_text(encoding="utf-8", errors="replace"),
            )
            if not match:
                raise XPanelError("не удалось определить версию SG-Panel в GitHub main")
            remote_version = match.group(1).strip()
            current_label = f"v{__version__}"
            remote_label = f"v{remote_version}"
            current_key = version_key(current_label)
            remote_key = version_key(remote_label)
            if remote_key[0] < 0:
                raise XPanelError(f"некорректная версия в GitHub main: {remote_label}")

            print(f"Версия в GitHub: {remote_label}")
            if remote_key <= current_key:
                if remote_key == current_key:
                    print(f"\n{C.green}OK{C.reset} Установлена та же версия. Обновление не требуется.")
                else:
                    print(f"\n{C.yellow}Внимание:{C.reset} версия в GitHub не новее установленной. Обновление отменено.")
                _pause()
                return

            print("Перед изменением сервера будет создана полная страховочная копия.")
            confirm = input(
                f"\nОбновить {current_label} → {remote_label}? [y/N]: "
            ).strip().lower()
            if confirm not in {"y", "yes", "д", "да"}:
                print("Отменено.")
                _pause()
                return

            print("Запускаю обновление с backup и автоматическим rollback.\n")
            result = subprocess.run(["bash", str(installer)], cwd=root, check=False)
            if result.returncode != 0:
                raise XPanelError(f"обновление завершилось с кодом {result.returncode}")
    except Exception as exc:
        print(f"Не удалось обновить SG-Panel: {exc}")
        _pause()
        return
    print(f"\n{C.green}OK{C.reset} SG-Panel успешно обновлена из GitHub main.")
    _pause()


def menu_loop() -> int:
    _require_root()
    actions = {key: handler for key, _label, handler, _kind in _menu_items()}
    while True:
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")
        for line in _menu_header():
            print(f"{C.cyan}{line}{C.reset}")
        for key, label, _handler, kind in _menu_items():
            number_color = C.yellow if kind in {"warning", "accent"} else C.cyan
            plain = f"{key:>2}. {label}"
            padding = " " * max(0, MENU_WIDTH - 4 - len(plain))
            print(
                f"{C.cyan}│{C.reset} {number_color}{key:>2}{C.reset}. "
                f"{label}{padding} {C.cyan}│{C.reset}"
            )
        exit_plain = " 0. Выход"
        print(
            f"{C.cyan}│{C.reset} {C.dim}{exit_plain}{C.reset}"
            f"{' ' * (MENU_WIDTH - 4 - len(exit_plain))} {C.cyan}│{C.reset}"
        )
        print(f"{C.cyan}╰{'─' * (MENU_WIDTH - 2)}╯{C.reset}")
        choice = input("\nВыберите действие: ").strip()
        if choice == "0":
            return 0
        action = actions.get(choice)
        if action is None:
            print(f"{C.red}Неизвестный пункт.{C.reset}")
            time.sleep(1)
            continue
        try:
            action()
        except (KeyboardInterrupt, EOFError):
            print("\nОтменено.")
            _pause()
        except Exception as exc:
            print(f"{C.red}Ошибка: {exc}{C.reset}", file=sys.stderr)
            _pause()


def main(argv: list[str] | None = None) -> int:
    try:
        return menu_loop()
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nПрервано.")
        return 130
    except (XPanelError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
