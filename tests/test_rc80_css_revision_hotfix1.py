from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_rc80_uses_the_real_existing_css_revision() -> None:
    updater = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    base = (ROOT / "xpanel" / "templates" / "base.html").read_text(encoding="utf-8")

    assert 'EXPECTED_UI_REVISION="sg070"' in updater
    assert 'EXPECTED_UI_REVISION="sg080"' not in updater
    assert "sg070" in base


def test_css_revision_error_is_not_hardcoded_to_release_name() -> None:
    updater = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "в шаблоне отсутствует ожидаемая ревизия CSS $EXPECTED_UI_REVISION" in updater
