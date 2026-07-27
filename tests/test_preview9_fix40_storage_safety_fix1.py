from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "install-or-upgrade.sh"


def body() -> str:
    return UPDATER.read_text(encoding="utf-8")


def test_failed_stage_escapes_log_redirection() -> None:
    text = body()
    assert "trap - ERR" in text
    assert 'FAILED_STEP="$label"' in text
    assert 'show_failure "$rc" "$failed_step"' in text


def test_nested_install_is_removed_before_backup_and_copy() -> None:
    text = body()
    assert "cleanup_nested_install_artifacts" in text
    assert 'rm -rf --one-file-system "$TARGET/xpanel-mvp"' in text
    assert "--exclude='xpanel-mvp/'" in text


def test_backup_does_not_duplicate_venv_or_nested_panel() -> None:
    text = body()
    start = text.index("backup_stage(){")
    end = text.index("\n}\n\ncopy_stage", start)
    backup = text[start:end]
    assert "rsync -a --delete" in backup
    assert "--exclude='.venv/'" in backup
    assert "--exclude='xpanel-mvp/'" in backup
    assert 'cp -a "$TARGET"' not in backup


def test_disk_space_is_checked_before_backup() -> None:
    text = body()
    assert "check_upgrade_disk_space" in text
    assert text.index('run_stage "Проверка свободного места"') < text.index(
        'run_stage "Создание резервной копии"'
    )


def test_rollback_preserves_venv_and_cleans_failed_backup_after_service_restart() -> None:
    text = body()
    start = text.index("rollback(){")
    end = text.index("\ntrap rollback", start)
    rollback = text[start:end]
    assert 'rm -rf "$TARGET"' not in rollback
    assert "--exclude='.venv/'" in rollback
    assert 'systemctl is-active --quiet "$SERVICE"' in rollback
    assert 'rm -rf --one-file-system "$BACKUP_ROOT"' in rollback
