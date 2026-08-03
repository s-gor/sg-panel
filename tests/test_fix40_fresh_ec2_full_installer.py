from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_full_installer_is_fresh_ec2_or_safe_resume_only() -> None:
    body = read("install.sh")
    assert 'LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"' in body
    assert 'BOOTSTRAP_MARKER="$BOOTSTRAP_STATE_DIR/active.env"' in body
    assert "complete_install_artifacts_exist()" in body
    assert "known_partial_attempt_exists()" in body
    assert "runtime_artifacts_exist()" in body
    assert "Обнаружена завершённая SG-Panel" in body
    assert "Обнаружена предыдущая незавершённая установка" in body
    assert "Обнаружены сторонние или неподтверждённые" in body


def test_full_installer_uses_current_release_identity() -> None:
    body = read("install.sh")
    assert 'EXPECTED_VERSION="0.10.0-rc80"' in body
    assert 'EXPECTED_BUILD="FIX40"' in body
    assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
    assert "Мастер полной установки SG-Panel" in body
    assert "Проверка и распаковка SG-Panel FIX40" in body


def test_full_installer_does_not_delete_existing_panel() -> None:
    body = read("install.sh")
    forbidden = (
        "rm -rf /opt/xpanel-mvp",
        "rm -rf /etc/xpanel-mvp",
        "FULL-UNINSTALL-SG-PANEL.sh",
    )
    for marker in forbidden:
        assert marker not in body
