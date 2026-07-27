from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")

def test_salamander_actions_are_equal_without_global_typography():
    settings = read("xpanel/templates/settings.html")
    assert '<div class="sg-hy-secret-actions">' in settings
    assert "grid-template-columns:repeat(3,minmax(0,1fr))" in settings
    assert "sg-hy-secret-row{display:grid;grid-template-columns:minmax(0,1fr)" in settings

def test_cluster_is_always_open_and_internal_lines_are_removed():
    nodes = read("xpanel/templates/nodes.html")
    cluster_css = read("xpanel/static/fix40-cluster-restore-ui21.css")
    final_css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    assert '<section class="ui-card cluster-onboarding cluster-restore-onboarding" id="cluster-add-node">' in nodes
    assert '>Открыть</em>' not in nodes
    assert "onboarding.open = true" not in nodes
    assert "border-bottom: 0 !important" in final_css
    assert ".cluster-list-section .compact-section-heading { border-bottom: 0 !important; }" in cluster_css

def test_routing_changes_are_local_and_do_not_force_page_title_size():
    css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    assert "Final Fix 1 · Routing local visual alignment only" in css
    local = css.split("Final Fix 1 · Routing local visual alignment only", 1)[1]
    assert "topbar-heading h1" in local
    assert "display: block !important" in local
    assert "topbar-heading h1 { font-size" not in local
    assert "background: var(--panel) !important" in local

def test_clients_have_local_heading_and_readable_type():
    users = read("xpanel/templates/users.html")
    css = read("xpanel/static/fix40-clients-layout-hotfix3.css")
    assert "clients-list-heading" in users
    assert "Имя, сервер подключения, доступы" in users
    assert "Final Fix 1 · Clients local visual alignment only" in css
    assert "font-size: 14px !important" in css
