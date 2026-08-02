from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def script() -> str:
    return (ROOT / "deploy/install-xray-cert-access.sh").read_text(
        encoding="utf-8"
    )


def test_xray_certificate_access_has_no_package_install_or_acl_dependency():
    text = script()

    assert "apt-get" not in text
    assert "setfacl" not in text
    assert "command -v setfacl" not in text
    assert "chmod o+x" in text
    assert "chmod o+r" in text
    assert "readlink -f" in text


def test_certificate_access_is_reapplied_after_certbot_renewal():
    text = script()

    assert "/usr/local/sbin/sg-panel-fix-xray-cert-access" in text
    assert "/etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access" in text
    assert "systemctl restart xray.service" in text
