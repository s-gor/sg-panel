from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_clean_installer_starts_spinner_and_bootstraps_before_questions():
    script = read("install.sh")
    main = script[script.index("main(){"):]
    assert 'startup_begin "Запуск мастера установки RC70"' in main
    assert main.index('startup_begin "Запуск мастера установки RC70"') < main.index('run_step "Этап 1/7 · Подготовка чистой Ubuntu"')
    assert main.index('run_step "Этап 4/7 · Определение публичного адреса"') < main.index("collect_inputs")
    assert 'PREDETECTED_PUBLIC_IPV4="$(cat "$WORK_DIR/public-ipv4" 2>/dev/null || true)"' in main
    assert 'startup_ok "Мастер установки RC70 запущен"' in main


def test_zip_installer_and_upgrade_start_with_classic_spinner():
    direct = read("deploy/ec2-first-install.sh")
    upgrade = read("install-or-upgrade.sh")
    assert 'step_begin "Запуск мастера SG-Panel RC70"' in direct
    assert 'step_begin "Запуск обновления SG-Panel RC70"' in upgrade
    assert "local frames='|/-\\'" in read("install.sh")
    assert "local frames='|/-\\'" in direct
    assert "local frames='|/-\\'" in upgrade


def test_rc63_release_notes_describe_installer_startup():
    notes = read("RELEASE-NOTES-RC69.md")
    assert "с первой секунды запуска" in notes
    assert "до ввода параметров" in notes
    assert "системных компонентов" in notes
    assert "070-INSTALL-SG-PANEL-RC70.run" in read("README.md")
    assert "sudo bash ./070-INSTALL-SG-PANEL-RC70.run" in read("README.md")
