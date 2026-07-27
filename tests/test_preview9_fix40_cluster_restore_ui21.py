from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_ui21_identity_and_stylesheet_are_cumulative():
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in text("xpanel/__init__.py")
    base = text("xpanel/templates/base.html")
    assert "fix40-cluster-restore-ui21.css" in base
    assert base.count("fix40-cluster-restore-ui21.css") == 1
    css = text("xpanel/static/fix40-cluster-restore-ui21.css")
    assert "Restore the compact Cluster and SG-Node card" in css
    assert ".node-restore-status" in css
    assert ".cluster-restore-onboarding" in css


def test_cluster_returns_to_compact_rows_and_always_open_onboarding():
    template = text("xpanel/templates/nodes.html")
    assert "compact-node-row" in template
    assert "cluster-controller-card" in template
    assert '<section class="ui-card cluster-onboarding cluster-restore-onboarding"' in template
    assert "+ Добавить SG-Node" in template
    assert "cluster-stage4-server-grid" not in template
    assert "cluster-stage4-server-card" not in template


def test_node_card_has_no_duplicate_nav_or_gray_metric_towers():
    template = text("xpanel/templates/node_detail.html")
    assert 'class="node-simple-nav"' not in template
    assert "node-restore-status" in template
    assert 'class="wide"><dt>Адрес</dt>' in template
    assert "node-restore-command-box" in template
    assert "Показать команду полностью" in template
    assert "node-simple-facts" not in template


def test_empty_jobs_render_nothing():
    jobs = text("xpanel/templates/_node_jobs.html")
    assert "Заданий пока нет" not in jobs
    assert "{% if jobs %}" in jobs


def test_ui20_cascade_and_worker_fix_are_preserved():
    assert "guided three-step Cascade" in text("xpanel/static/fix40-cascade-steps-ui20.css")
    assert 'WORKER_VERSION = "0.7.0"' in text("node_agent/sg_node_worker.py")
    assert 'WORKER_VERSION = "0.7.0"' in text("node_agent/sg_node_agent.py")
