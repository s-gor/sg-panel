from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def script() -> str:
    return (ROOT / "deploy/install-xray-cert-access.sh").read_text(
        encoding="utf-8"
    )


def test_xray_certificate_access_uses_preinstalled_acl_without_runtime_apt():
    text = script()
    assert "apt-get" not in text
    assert "setfacl" in text
    assert "systemctl show -p User" in text
    assert "readlink -f" in text
    assert "chmod o+r" not in text
    assert "chmod o+x" not in text


def test_certificate_access_is_reapplied_after_certbot_renewal():
    text = script()
    assert "/usr/local/sbin/sg-panel-fix-xray-cert-access" in text
    assert "/etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access" in text
    assert "systemctl restart xray.service" in text
    assert "systemctl is-active xray.service" in text
