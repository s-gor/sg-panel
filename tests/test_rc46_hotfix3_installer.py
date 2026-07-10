from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
EC2 = ROOT / "deploy" / "ec2-first-install.sh"


def test_unified_clean_installer_bootstraps_before_collecting_inputs() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    main = text[text.index("main(){"):]
    password = text.index('prompt_secret "Пароль администратора панели')
    port = text.index('prompt_default "Публичный HTTP-порт панели')
    address = text.index('prompt_default "Адрес панели и Xray')
    collect_call = main.index("collect_inputs")
    assert main.index('run_step "Этап 1/7 · Подготовка чистой Ubuntu"') < collect_call
    assert main.index('run_step "Этап 4/7 · Определение публичного адреса"') < collect_call
    assert password < port < address
    assert collect_call < main.index('run_step "Этап 5/7 · Проверка и распаковка SG-Panel RC70"')
    assert "Все параметры приняты. Установка продолжается без дополнительного ввода" in text


def test_unified_installer_supports_github_pipe_and_local_exact_zip() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    assert "</dev/tty" in text
    assert "SG_PANEL_ARCHIVE_URL" in text
    assert "SG_PANEL_SOURCE_ZIP" in text
    assert "LOCAL_ARCHIVE_NAME" in text
    assert "curl -fL --retry 3" in text
    assert "unzip -tq" in text


def test_unified_installer_updates_upgrades_and_installs_dependencies() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    assert "update -qq" in text
    assert "dist-upgrade -y" in text
    for package in (
        "nginx",
        "python3-venv",
        "unzip",
        "sqlite3",
        "certbot",
        "libnginx-mod-stream",
    ):
        assert package in text


def test_unified_installer_uses_live_spinner_and_logs() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    for token in (
        "spinner_loop(){",
        "step_begin(){",
        "step_ok(){",
        "wait_for_apt(){",
        "run_step(){",
        "Последние полезные строки журнала",
        "Полный журнал:",
    ):
        assert token in text
    assert "C_GREEN" in text
    assert "local frames='|/-\\'" in text


def test_unified_installer_passes_inputs_without_later_prompts() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    for variable in (
        "XPANEL_ADMIN_PASSWORD",
        "PANEL_PUBLIC_PORT",
        "XRAY_ADDRESS",
        "FIRST_USER",
        "REALITY_DEST",
        "REALITY_SNI",
        "SG_PANEL_INPUTS_PRECOLLECTED=1",
        "SG_PANEL_SYSTEM_READY=1",
    ):
        assert variable in text
    assert "Адрес:           $url" in text


def test_inner_installer_accepts_precollected_inputs_and_ready_system() -> None:
    text = EC2.read_text(encoding="utf-8")
    assert "SG_PANEL_INPUTS_PRECOLLECTED" in text
    assert "SG_PANEL_SYSTEM_READY" in text
    assert "dist-upgrade -y" in text
