from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_rc58_version_and_ui_revision_are_consistent():
    assert '__version__ = "0.10.0-rc70"' in read("xpanel/__init__.py")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install.sh")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_UI_REVISION="sg070"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("deploy/ec2-first-install.sh")
    assert "sg070" in read("xpanel/templates/base.html")
    assert "sg070" in read("xpanel/templates/login.html")
    assert "SG-Panel RC70 — Latte light theme preview" in read("xpanel/static/app.css")


def test_clean_installer_uses_exact_local_rc58_archive():
    script = read("install.sh")
    assert 'LOCAL_ARCHIVE_NAME="070-SG-Panel-RC70.zip"' in script
    assert "--source-zip ./070-SG-Panel-RC70.zip" in script
    assert "SG-Panel-v0.10.0-RC46" not in script
    assert 'grep -q "__version__ = \\"$EXPECTED_VERSION\\""' in script


def test_bootstrap_components_are_installed_before_questions():
    script = read("install.sh")
    collect = script.index("collect_inputs", script.index("main(){"))
    bootstrap_labels = (
        "Этап 1/7 · Подготовка чистой Ubuntu",
        "Этап 2/7 · Обновление индексов APT",
        "Этап 3/7 · Установка системных компонентов",
        "Этап 4/7 · Определение публичного адреса",
    )
    for label in bootstrap_labels:
        assert label in script
        assert script.index(label, script.index("main(){")) < collect
    assert collect < script.index("Этап 5/7 · Проверка и распаковка SG-Panel RC70", script.index("main(){"))
    for prompt in (
        "Пароль администратора панели",
        "Повторите пароль",
        "Публичный HTTP-порт панели",
        "Адрес панели и Xray",
        "Имя первого пользователя",
        "Reality target",
        "Reality SNI",
    ):
        assert prompt in script
    assert "Ubuntu и необходимые системные компоненты уже подготовлены" in script
    assert "Установка продолжается без дополнительного ввода" in script


def test_clean_installer_has_seven_quiet_spinner_stages():
    script = read("install.sh")
    for label in (
        "Этап 1/7 · Подготовка чистой Ubuntu",
        "Этап 2/7 · Обновление индексов APT",
        "Этап 3/7 · Установка системных компонентов",
        "Этап 4/7 · Определение публичного адреса",
        "Этап 5/7 · Проверка и распаковка SG-Panel RC70",
        "Этап 6/7 · Установка SG-Panel, Xray и Nginx",
        "Этап 7/7 · Финальная проверка панели и служб",
    ):
        assert label in script
    assert "local frames='|/-\\'" in script
    assert "${frames:frame_index%4:1}" in script
    assert '>>"$LOG_FILE" 2>&1' in script
    assert "Dpkg::Use-Pty=0" in script
    assert "APT_LISTCHANGES_FRONTEND=none" in script


def test_bootstrap_uses_the_same_unified_installer():
    script = read("install-from-github.sh")
    assert "/install.sh}" in script
    assert 'bash -n "$TMP_INSTALLER"' in script
    assert 'bash "$TMP_INSTALLER" "$@"' in script
    assert "deploy/ec2-first-install.sh" not in script
    assert "Bootstrap 1/2 · Подготовка загрузчика" in script
    assert "Bootstrap 2/2 · Загрузка мастера SG-Panel" in script


def test_direct_ec2_installer_also_has_numbered_quiet_stages():
    script = read("deploy/ec2-first-install.sh")
    assert "Этап 1/9 · Проверка памяти и свободного места" in script
    assert "Этап 9/9 · Проверка служб, конфигурации и адреса панели" in script
    assert "Этап 1/4 · Проверка установленного Xray" in script
    assert "Этап 4/4 · Финальная проверка служб и версии" in script
    log_body = script[script.index("log(){"):script.index("stage(){")]
    assert '>>"$LOG_FILE"' in log_body
    assert "printf '[SG-Panel] %s\\n' \"$*\"\n" not in log_body


def test_clean_installer_never_creates_or_enables_swap():
    script = read("deploy/ec2-first-install.sh")
    assert "check_memory_and_disk(){" in script
    assert "Swap автоматически не создаётся" in script
    assert "fallocate -l 2G /swapfile" not in script
    assert "mkswap /swapfile" not in script
    assert "swapon /swapfile" not in script
    assert "echo '/swapfile none swap sw 0 0'" not in script


def test_upgrade_rollback_has_its_own_spinner_and_restores_state():
    script = read("install-or-upgrade.sh")
    assert "Rollback · восстановление предыдущего рабочего состояния" in script
    assert 'spinner_loop "$CURRENT_STEP" "$STEP_STARTED" &' in script
    assert "Rollback завершён успешно" in script
    for item in (
        "xpanel-mvp",
        "web.env",
        "panel-access.env",
        "install-complete.env",
        "xray-config.json",
        "/etc/xpanel-mvp/warp",
    ):
        assert item in script


def test_docs_show_no_manual_apt_or_unzip_for_exact_rc58_test():
    readme = read("README.md")
    installation = read("docs/INSTALLATION.md")
    command = "sudo bash ./070-INSTALL-SG-PANEL-RC70.run"
    assert command in readme
    assert command in installation
    exact_section = installation[installation.index("## Проверка точного RC70"):installation.index("## Установка после публикации")]
    assert "apt-get update" not in exact_section
    assert "unzip -o" not in exact_section
    assert "sha256sum" not in exact_section


def test_rc58_keeps_warp_cluster_and_firefox_fixes():
    assert "Российские сайты и IP" in read("xpanel/templates/routing.html")
    assert "geosite:category-ru" in read("xpanel/service.py")
    assert "geoip:ru" in read("xpanel/service.py")
    assert "Подключение SG-Node" in read("xpanel/templates/nodes.html")
    assert '"fp": "firefox"' in read("xpanel/web.py")
    assert "--fingerprint firefox" in read("deploy/ec2-first-install.sh")
