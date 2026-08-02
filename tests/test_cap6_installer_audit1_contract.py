from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_clean_installer_can_resume_a_known_partial_attempt():
    text = read("install.sh")
    assert 'BOOTSTRAP_MARKER="$BOOTSTRAP_STATE_DIR/active.env"' in text
    assert "known_partial_attempt_exists()" in text
    assert "complete_install_artifacts_exist()" in text
    assert "mark_bootstrap_attempt" in text
    assert "Обнаружена предыдущая незавершённая установка" in text


def test_source_and_xray_downloads_are_retry_safe():
    outer = read("install.sh")
    inner = read("deploy/ec2-first-install.sh")
    assert "--retry-all-errors" in outer
    assert "--max-time 300" in outer
    assert 'xray_install_script="$(mktemp ' in inner
    assert "--retry-all-errors" in inner
    assert 'bash -n "$xray_install_script"' in inner
    assert '[[ ! -x /usr/local/bin/xray ]]' in inner
    assert 'bash -c "$(curl -fsSL' not in inner


def test_systemd_checks_retry_instead_of_one_shot_sleep():
    inner = read("deploy/ec2-first-install.sh")
    upgrade = read("install-or-upgrade.sh")
    assert "wait_for_service_active()" in inner
    assert 'wait_for_service_active xray "Xray' in inner
    assert 'wait_for_service_active xpanel-web "xpanel-web"' in inner
    assert "wait_for_service_active()" in upgrade
    assert 'wait_for_service_active "$SERVICE"' in upgrade


def test_acl_dependency_is_installed_before_https_runtime():
    outer = read("install.sh")
    inner = read("deploy/ec2-first-install.sh")
    upgrade = read("install-or-upgrade.sh")
    assert "certbot openssl acl" in outer
    assert "certbot openssl acl" in inner
    assert "ensure_acl_dependency()" in upgrade
    assert "Подготовка безопасного доступа Xray к сертификатам" in upgrade
