from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hotfix20_runtime_installer_is_numbered_and_waits_for_real_config():
    script = (ROOT / "deploy" / "install-node-runtime.sh").read_text(encoding="utf-8")
    assert 'SCRIPT_VERSION="1.0"' in script
    assert 'XRAY_VERSION="v26.5.9"' in script
    assert "сначала подключите ноду к Cluster Controller" in script
    assert "systemctl disable --now xray.service" in script
    assert "Обновление SG-Node Agent и Worker" in script
    assert "/node/worker.py" in script
    assert "waiting_config" in script
    assert "Nginx: не устанавливался" in script


def test_hotfix20_controller_exposes_runtime_command_and_allows_first_deploy():
    web = (ROOT / "xpanel" / "web.py").read_text(encoding="utf-8")
    template = (ROOT / "xpanel" / "templates" / "node_detail.html").read_text(encoding="utf-8")
    assert 'NODE_RUNTIME_INSTALLER' in web
    assert '@app.get("/node/runtime.sh")' in web
    assert '/tmp/02-install-node-runtime.sh' in web
    assert 'Сначала установите Xray Runtime на ноде' in web
    assert '02 · Установить Xray Runtime' not in template
    assert 'data-copy-node-runtime' not in template
    assert 'Переподключить ноду' in template
    assert "node.xray_state in ['active', 'inactive', 'failed']" in template


def test_hotfix20_worker_enables_xray_only_after_real_config():
    worker = (ROOT / "node_agent" / "sg_node_worker.py").read_text(encoding="utf-8")
    assert 'WORKER_VERSION = "0.5.0"' in worker
    assert '["systemctl", "enable", "xray.service"]' in worker
    assert '["systemctl", "disable", "--now", "xray.service"]' in worker


def test_hotfix20_cache_revision_and_installer_guard():
    base = (ROOT / "xpanel" / "templates" / "base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel" / "templates" / "login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    css = (ROOT / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert "SG-Panel 054" in css
