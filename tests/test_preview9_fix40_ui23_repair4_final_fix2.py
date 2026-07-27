from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_final_fix2_uses_new_cache_keys_for_all_modified_css():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    assert "clients-layout-hotfix3-final-fix2" in base
    assert "cluster-restore-ui21-final-fix2" in base
    assert "ui23-repair4-final-fix2" in base

def test_final_fix2_keeps_previous_four_groups():
    settings = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    nodes = (ROOT / "xpanel/templates/nodes.html").read_text(encoding="utf-8")
    users = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    routing_css = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
    assert "sg-hy-secret-actions" in settings
    assert "cluster-restore-onboarding-head" in nodes
    assert ">Открыть</em>" not in nodes
    assert "clients-list-heading" in users
    assert "Final Fix 1 · Routing local visual alignment only" in routing_css

def test_final_fix2_does_not_restore_global_heading_rule():
    css = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
    assert "Final Polish 2 · Unified page heading size" not in css
