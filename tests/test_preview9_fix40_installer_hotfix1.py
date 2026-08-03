from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_core_build_and_release_are_separate_identities() -> None:
    init = read("xpanel/__init__.py")
    assert '__version__ = "0.10.0-rc80"' in init
    assert '__build__ = "FIX40"' in init
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init


def test_upgrade_validator_checks_live_build_not_hidden_core_version() -> None:
    script = read("install-or-upgrade.sh")
    assert 'EXPECTED_VERSION="0.10.0-rc80"' in script
    assert 'EXPECTED_BUILD="FIX40"' in script
    assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in script
    assert 'grep -Fq "$EXPECTED_BUILD" <<<"$http_body"' in script
    assert 'GUI не отдаёт маркер сборки $EXPECTED_BUILD' in script
    assert 'grep -q "v$EXPECTED_VERSION" <<<"$http_body"' not in script
    assert 'static/fix40-ui-repair.css' in script


def test_clean_install_validates_same_live_build_marker() -> None:
    master = read("install.sh")
    core = read("deploy/ec2-first-install.sh")
    for script in (master, core):
        assert 'EXPECTED_BUILD="FIX40"' in script
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in script
        assert 'grep -Fq "$EXPECTED_BUILD" <<<"$login_body"' in script
        assert 'GUI не отдаёт маркер сборки $EXPECTED_BUILD' in script


def test_source_preflight_validates_all_identity_layers() -> None:
    for relative in ("install.sh", "install-or-upgrade.sh", "deploy/ec2-first-install.sh"):
        script = read(relative)
        assert '__version__ = \\"$EXPECTED_VERSION\\"' in script
        assert '__build__ = \\"$EXPECTED_BUILD\\"' in script
        assert '__release_label__ = \\"$EXPECTED_RELEASE_LABEL\\"' in script


def test_hotfix_does_not_rename_visible_fix40_build() -> None:
    assert 'FIX40-HF1' not in read("xpanel/__init__.py")
    assert 'Preview 9 · FIX40' in read("xpanel/__init__.py")
