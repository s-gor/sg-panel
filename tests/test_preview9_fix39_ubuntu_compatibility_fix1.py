from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _dpkg_ge(version: str, minimum: str = "22.04") -> bool:
    return subprocess.run(
        ["dpkg", "--compare-versions", version, "ge", minimum],
        check=False,
    ).returncode == 0


def test_version_comparison_accepts_interim_and_future_ubuntu():
    for version in ("22.04", "22.10", "23.04", "23.10", "24.04", "24.10", "25.04", "25.10", "26.04", "30.04"):
        assert _dpkg_ge(version), version
    for version in ("18.04", "20.04", "21.10"):
        assert not _dpkg_ge(version), version


def test_clean_installer_uses_minimum_version_not_allowlist():
    text = _text("install.sh")
    assert 'dpkg --compare-versions "$version" ge "22.04"' in text
    assert "check_supported_platform" in text
    assert "22.04|24.04" not in text
    assert "24.04|24.10|25.04|25.10|26.04" not in text


def test_upgrade_and_node_installers_use_same_contract():
    paths = (
        "install-or-upgrade.sh",
        "01-install-sg-node.sh",
        "deploy/install-sg-node.sh",
    )
    for path in paths:
        text = _text(path)
        assert "dpkg --compare-versions" in text, path
        assert 'ge "22.04"' in text, path
        assert "24.04|24.10|25.04|25.10|26.04" not in text, path


def test_active_installation_docs_do_not_require_a_release_channel():
    for path in (
        "README.md",
        "docs/INSTALLATION.md",
        "docs/MULTI-NODE.md",
        "xpanel/templates/help.html",
        "install.sh",
        "install-or-upgrade.sh",
        "01-install-sg-node.sh",
        "deploy/install-sg-node.sh",
    ):
        assert ("LT" + "S") not in _text(path), path
