from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cluster_empty_state_is_compact_and_has_no_duplicate_button():
    template = (ROOT / "xpanel/templates/nodes.html").read_text(encoding="utf-8")
    assert 'class="cluster-restore-empty-note"' in template
    assert '<strong>SG-Node пока нет</strong>' in template
    assert template.count('<button class="button primary" type="button" data-open-node-onboarding>') == 1
    assert 'class="ui-card cluster-restore-empty"' not in template


def test_cluster_empty_fix_css_is_page_scoped_and_loaded_after_cluster_base():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/fix40-cluster-empty-fix1.css").read_text(encoding="utf-8")
    old_ref = "fix40-cluster-restore-ui21.css"
    new_ref = "fix40-cluster-empty-fix1.css"
    assert old_ref in base and new_ref in base
    assert base.index(old_ref) < base.index(new_ref)
    assert "cluster-empty-fix1" in base
    assert "body.cluster-restore-ui21 .cluster-restore-empty-note" in css
    assert ".topbar-heading h1" not in css
