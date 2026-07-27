from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "install-or-upgrade.sh"


def body() -> str:
    return UPDATER.read_text(encoding="utf-8")


def test_rollback_is_restricted_to_original_installer_shell() -> None:
    text = body()
    assert 'MAIN_BASHPID="$BASHPID"' in text
    assert 'if [[ "$BASHPID" != "$MAIN_BASHPID" ]]; then' in text
    assert 'trap - ERR INT TERM' in text


def test_spinner_cannot_trigger_live_rollback() -> None:
    text = body()
    start = text.index("spinner_loop(){")
    end = text.index("\n}\n\nstop_spinner", start)
    spinner = text[start:end]
    assert "trap - ERR" in spinner
    assert "trap 'exit 0' INT TERM" in spinner
    assert "set +e" in spinner


def test_rollback_restores_project_contents_without_nested_directory() -> None:
    text = body()
    assert 'rsync -a --delete' in text
    assert '"$BACKUP_ROOT/xpanel-mvp/" "$TARGET/"' in text
    assert "--exclude='xpanel-mvp/'" in text
    assert 'cp -a "$BACKUP_ROOT/xpanel-mvp" "$TARGET"' not in text
