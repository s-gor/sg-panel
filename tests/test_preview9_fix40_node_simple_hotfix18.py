from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_hotfix18_release_identity_and_css_are_cumulative():
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in text("xpanel/__init__.py")
    base = text("xpanel/templates/base.html")
    assert "fix40-node-simple-hotfix18.css" in base
    assert "fix40-node-simple-hotfix18.css" in base
    assert base.count("fix40-node-simple-hotfix18.css") == 1
    css = text("xpanel/static/fix40-node-simple-hotfix18.css")
    assert "safe card geometry" in css
    assert ".node-simple-shell" in css
    assert ".cluster-node-connect-form" in css


def test_cluster_uses_one_user_choice_and_one_universal_command():
    nodes = text("xpanel/templates/nodes.html")
    assert 'cluster-node-connect-form' in nodes
    assert ">Создать и получить команду</button>" in nodes
    assert 'class="cluster-stage4-step"' not in nodes
    assert "Одна команда сама определит" in nodes
    web = text("xpanel/web.py")
    helper = web.split("def _node_install_command", 1)[1].split("def _node_request_public_address", 1)[0]
    assert 'base + "/node/install-sg-node.sh"' in helper
    assert 'base + "/node/connect.sh"' not in helper
    assert '" --token "' in helper


def test_existing_panel_mode_never_changes_panel_nginx_or_xray():
    script = text("deploy/install-sg-node.sh")
    assert 'SCRIPT_VERSION="1.2"' in script
    assert '--token) ENROLLMENT_TOKEN=' in script
    assert '[[ -d /opt/xpanel-mvp && -f /etc/systemd/system/xpanel-web.service ]]' in script
    assert 'FULL_PANEL_PRESENT=1' in script
    assert "Xray действующей SG-Panel проверен и оставлен без изменений" in script
    assert "Nginx и веб-доступ действующей SG-Panel оставлены без изменений" in script
    assert "Системные пакеты SG-Panel не изменялись" in script
    assert '/usr/local/sbin/sg-node-connect --panel "$PANEL_URL" --token "$ENROLLMENT_TOKEN"' in script
    assert 'systemctl is-active --quiet xpanel-web.service' in script
    assert text("01-install-sg-node.sh") == script


def test_node_page_is_compact_and_reload_uses_get_detail_url():
    template = text("xpanel/templates/node_detail.html")
    assert "node-stage-rail" not in template
    assert "node-restore-status" in template
    assert "node-simple-next" in template
    assert "node-simple-advanced" in template
    assert "Развернуть профиль и клиентов" in template
    assert "canonicalNodeUrl" in template
    assert "window.location.replace(canonicalNodeUrl)" in template
    assert "window.location.replace(window.location.href)" not in template
    web = text("xpanel/web.py")
    assert '@app.get("/network/nodes/add")' in web
    assert 'return redirect(url_for("nodes_page"))' in web


def test_obsolete_expert_overview_is_removed():
    advanced = text("xpanel/templates/advanced.html")
    assert "Фактическое состояние" not in advanced
    assert "advanced-overview-card" not in advanced
    assert "Расширенные параметры и диагностика текущей схемы" in advanced
