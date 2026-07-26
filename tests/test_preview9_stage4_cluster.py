from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"


def test_cluster_uses_compact_controller_and_server_rows_without_duplicate_summary():
    template = (TEMPLATES / "nodes.html").read_text(encoding="utf-8")
    css = (STATIC / "fix40-cluster-restore-ui21.css").read_text(encoding="utf-8")

    assert "cluster-restore-ui21" in template
    assert "cluster-controller-card" in template
    assert "compact-node-list" in template
    assert "compact-node-row" in template
    assert "cluster-stage4-server-grid" not in template
    assert "cluster-stage4-server-card" not in template
    assert "node.last_error" in template
    assert ".cluster-restore-controller" in css
    assert ".compact-node-row" in css


def test_cluster_onboarding_is_closed_by_default_and_opened_from_page_action():
    template = (TEMPLATES / "nodes.html").read_text(encoding="utf-8")

    assert "data-open-node-onboarding" in template
    assert 'id="cluster-add-node"' in template
    assert '<details class="ui-card cluster-onboarding cluster-restore-onboarding"' in template
    assert '+ Добавить SG-Node' in template
    assert 'onboarding.open = true' in template
    assert '<details class="ui-card cluster-onboarding cluster-restore-onboarding" id="cluster-add-node" open>' not in template


def test_cluster_keeps_single_node_add_form():
    template = (TEMPLATES / "nodes.html").read_text(encoding="utf-8")

    assert 'action="{{ url_for(\'node_add\') }}"' in template
    assert 'method="post"' in template
    assert 'name="csrf_token"' in template
    assert 'name="role" value="regional"' in template
    assert 'name="location" value=""' in template
    assert 'name="public_address" value=""' in template
    assert 'name="description" value=""' in template
    assert 'name="name" required maxlength="80"' in template
    assert '>Создать и получить команду</button>' in template
    assert 'nodePrepareCommand' not in template


def test_cluster_restore_stylesheet_is_loaded_once():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert base.count("fix40-cluster-restore-ui21.css") == 1
