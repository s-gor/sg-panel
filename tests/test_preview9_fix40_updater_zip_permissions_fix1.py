from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "install-or-upgrade.sh"


def test_updater_does_not_require_executable_bit_after_python_zip_extraction():
    text = UPDATER.read_text(encoding="utf-8")
    migration = '$SOURCE_DIR/deploy/migrate-placeholder-404.sh'

    assert f'[[ -f "{migration}" ]]' in text
    assert f'[[ -x "{migration}" ]]' not in text
    assert f'bash -n "{migration}"' in text


def test_updater_invokes_404_migration_explicitly_with_bash():
    text = UPDATER.read_text(encoding="utf-8")
    assert 'bash "$TARGET/deploy/migrate-placeholder-404.sh"' in text
