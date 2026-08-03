from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_rc80_version_is_consistent() -> None:
    assert '__version__ = "0.10.0-rc80"' in (ROOT / "xpanel" / "__init__.py").read_text(encoding="utf-8")
    for relative in ("install.sh", "install-or-upgrade.sh", "deploy/ec2-first-install.sh"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert 'EXPECTED_VERSION="0.10.0-rc80"' in text


def test_installer_has_no_ports_confirmation() -> None:
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    for forbidden in (
        "required_ports_confirmation",
        "Все три порта уже открыты",
        "Порты подтверждены",
        "SG-PANEL CAP2 REQUIRED PORTS NOTICE",
        "[да/нет]",
    ):
        assert forbidden not in text


def test_rc80_publication_uses_approved_cascade_wording() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Что изменилось в RC80" in text
    assert "### Cascade теперь настраивается ещё проще" in text
    assert "Cascade и раньше настраивался через интерфейс SG-Panel" in text
    assert "Cascade настраивается без ручного редактирования Xray" not in text
