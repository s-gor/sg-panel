from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_https_switch_does_not_run_apt():
    text = read("deploy/configure-https.sh")
    assert "apt-get" not in text
    assert "libnginx-mod-stream" in text
    assert "setfacl" in text


def test_xray_certificate_access_is_applied_before_xray_config():
    text = read("deploy/configure-https.sh")
    helper = 'bash /opt/xpanel-mvp/deploy/install-xray-cert-access.sh "$CERT" "$KEY"'
    apply = ".venv/bin/python -m xpanel apply"
    assert helper in text
    assert text.index(helper) < text.index(apply)
    assert "wait_for_xray()" in text


def test_https_rollback_covers_runtime_helpers_and_port_state():
    text = read("deploy/configure-panel-access.sh")
    assert "cert-access-helper" in text
    assert "cert-access-hook" in text
    assert "nginx-renewal-hook" in text
    assert "reserved-port-conf" in text
    assert "sysctl --system" in text


def test_private_key_is_not_made_world_readable():
    text = read("deploy/install-xray-cert-access.sh")
    assert "setfacl" in text
    assert "systemctl show -p User" in text
    assert "chmod o+r" not in text
    assert "chmod o+x" not in text
    assert "systemctl restart xray.service" in text
