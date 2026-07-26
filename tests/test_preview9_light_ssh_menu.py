from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ssh_menu_contains_only_approved_items():
    text = (ROOT / "xpanel" / "admin_cli.py").read_text(encoding="utf-8")
    approved = [
        '("1", "Состояние панели и адрес", show_status, "normal")',
        '("2", "Перезапустить все службы", restart_all, "normal")',
        '("3", "Сменить пароль администратора", change_password, "accent")',
        '("4", "Создать резервную копию", create_backup_interactive, "normal")',
        '("5", "Проверить резервную копию", verify_backup_interactive, "normal")',
        '("6", "Восстановить резервную копию", restore_backup_interactive, "warning")',
        '("7", "Обновить SG-Panel", update_panel_interactive, "warning")',
        'exit_plain = " 0. Выход"',
    ]
    for item in approved:
        assert item in text
    for forbidden in (
        "Проверить клиентов и подключения",
        "Проверить Cluster и SG-Node",
        "Проверить Cascade",
        "Сбросить браузерные сессии и CSRF",
        "Переименовать сервер",
        "Полностью удалить SG-Panel",
    ):
        assert forbidden not in text


def test_ssh_menu_uses_awg_style_colored_console_card():
    text = (ROOT / "xpanel" / "admin_cli.py").read_text(encoding="utf-8")
    assert "MENU_WIDTH = 70" in text
    assert "class _Colors:" in text
    assert '"╭" + "─" * (MENU_WIDTH - 2) + "╮"' in text
    assert '"├" + "─" * (MENU_WIDTH - 2) + "┤"' in text
    assert "SG-PANEL v{__version__} · УПРАВЛЕНИЕ СЕРВЕРОМ" in text
    assert 'print("\\033[2J\\033[H", end="")' in text
    assert 'number_color = C.yellow if kind in {"warning", "accent"} else C.cyan' in text
    assert "Panel" in text and "Xray" in text and "Nginx" in text


def test_ssh_launcher_is_installed():
    text = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
    assert "cat > /usr/local/bin/sg-panel" in text
    assert "python -m xpanel.admin_cli" in text
    assert "chmod 0755 /usr/local/bin/sg-panel" in text


def test_ssh_update_uses_main_and_safe_upgrade_script():
    text = (ROOT / "xpanel" / "admin_cli.py").read_text(encoding="utf-8")
    assert "archive/refs/heads/main.zip" in text
    assert 'glob("*/install-or-upgrade.sh")' in text
    assert "backup и автоматическим rollback" in text


def test_light_theme_has_strong_text_and_blue_actions():
    app_css = (ROOT / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
    typography = (ROOT / "xpanel" / "static" / "rc6-typography.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "--text: #192530" in app_css
    assert "--accent: #80b7fc" in app_css
    assert "background: linear-gradient(180deg, #5da2f7, #3d8cf1)" in app_css
    assert "--rc6-text-secondary: #4d6172" in typography
    assert "sg070-preview9-fix35-full-recovery" in base
