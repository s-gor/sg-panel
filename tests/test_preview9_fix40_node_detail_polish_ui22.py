from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_ui22_identity_and_node_detail_polish_are_cumulative():
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in text("xpanel/__init__.py")
    base = text("xpanel/templates/base.html")
    assert "fix40-cluster-restore-ui21.css" in base
    assert "fix40-node-detail-polish-ui22.css" in base
    assert base.index("fix40-node-detail-polish-ui22.css") > base.index("fix40-cluster-restore-ui21.css")
    css = text("xpanel/static/fix40-node-detail-polish-ui22.css")
    assert 'remove the inherited gray slabs' in css
    assert 'background: #162231 !important' in css
    assert '.node-simple-danger' in css


def test_ui22_does_not_touch_node_or_cascade_runtime():
    template = text("xpanel/templates/node_detail.html")
    assert "node-restore-status" in template
    assert "node-simple-advanced" in template
    assert "node-simple-tech-grid" in template
    assert 'WORKER_VERSION = "0.7.0"' in text("node_agent/sg_node_worker.py")
    assert 'WORKER_VERSION = "0.7.0"' in text("node_agent/sg_node_agent.py")
    assert "guided three-step Cascade" in text("xpanel/static/fix40-cascade-steps-ui20.css")
