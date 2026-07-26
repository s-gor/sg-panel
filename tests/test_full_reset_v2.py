from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "full-uninstall.sh"
ROOT_COPY = ROOT / "FULL-UNINSTALL-SG-PANEL.sh"


def test_full_reset_copies_match() -> None:
    assert SCRIPT.read_bytes() == ROOT_COPY.read_bytes()


def test_full_reset_removes_controller_node_and_runtime_state() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    for marker in (
        "/opt/xpanel-mvp",
        "/opt/sg-panel",
        "/opt/sg-node",
        "/etc/sg-node",
        "/var/lib/sg-node",
        "/var/lib/sg-panel-update",
        "/usr/local/sbin/sg-node-connect",
        "sg-node-agent.service",
        "sg-node-worker.service",
        "sg-panel-xray-update.service",
    ):
        assert marker in text


def test_full_reset_preserves_ssh_and_cloud_configuration() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "SSH, сеть Ubuntu, /home и настройки AWS/EC2" in text
    assert "/etc/ssh" not in text
    assert "iptables -F" not in text
    assert "nft flush ruleset" not in text


def test_full_reset_requires_explicit_yes_and_has_verification() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "ASSUME_YES=0" in text
    assert "--yes" in text
    assert "verify_removal" in text
    assert "reserved-port:" in text
