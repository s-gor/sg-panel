from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_certificate_acl_installer_is_persistent_and_scoped_to_xray_user():
    script = read("deploy/install-xray-cert-access.sh")
    assert "systemctl show xray.service --property=User --value" in script
    assert "setfacl -m" in script
    assert "readlink -f" in script
    assert "certificateFile" in script
    assert "keyFile" in script
    assert "/usr/local/sbin/sg-panel-fix-xray-cert-access" in script
    assert "/etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access" in script
    assert "systemctl restart xray.service" in script
    assert "chmod 777" not in script
    assert "chmod 666" not in script


def test_https_configuration_grants_access_before_applying_xray():
    script = read("deploy/configure-https.sh")
    grant = 'install-xray-cert-access.sh "$CERT" "$KEY"'
    apply = ".venv/bin/python -m xpanel apply >/dev/null"
    assert grant in script
    assert script.index(grant) < script.index(apply)


def test_panel_update_restores_certificate_access_before_xray_apply():
    script = read("deploy/update-from-github.sh")
    grant = "bash deploy/install-xray-cert-access.sh"
    apply = ".venv/bin/python -m xpanel apply"
    assert grant in script
    assert script.index(grant) < script.index(apply)
    assert "/usr/local/sbin/sg-panel-fix-xray-cert-access" in script
    assert "/etc/letsencrypt/renewal-hooks/deploy/sg-panel-xray-cert-access" in script


def test_full_uninstall_removes_runtime_certificate_helper():
    script = read("FULL-UNINSTALL-SG-PANEL.sh")
    assert "/usr/local/sbin/sg-panel-fix-xray-cert-access" in script
