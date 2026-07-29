from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")

def test_release_and_final_stylesheet_contract() -> None:
    init = read("xpanel/__init__.py")
    base = read("xpanel/templates/base.html")
    # Phase 6 consolidated stylesheet contract: Hotfix 5→9 is one active layer.
    assert "fix40-light-buttons-theme-icon-hotfix9.css" in base
    assert "fix40-interface-cleanup-hotfix5.css" not in base
    assert "fix40-ui-compact-hotfix6.css" not in base
    assert "fix40-global-tabs-dark-buttons-hotfix7.css" not in base
    assert "fix40-interface-verification-hotfix8.css" not in base
    css = read("xpanel/static/fix40-ui-compact-hotfix6.css")
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init
    assert "UI Compact Hotfix 6" in css

def test_system_tabs_and_cluster_cleanup_are_preserved() -> None:
    css = read("xpanel/static/fix40-interface-cleanup-hotfix5.css")
    nodes = read("xpanel/templates/nodes.html")
    assert "grid-template-columns: repeat(3, minmax(0, 180px))" in css
    assert "background: #41586f" in css
    assert '<section class="ui-card cluster-onboarding cluster-restore-onboarding" id="cluster-add-node">' in nodes
    assert 'cluster-stage4-onboarding' not in nodes

def test_outbounds_is_compact_and_has_one_help_control() -> None:
    template = read("xpanel/templates/outbounds.html")
    assert (
        '{% block page_actions %}<a class="button secondary" '
        'href="{{ url_for(\'help_page\') }}#routing-warp">Справка</a>{% endblock %}'
        in template
    )
    assert (
        '<a class="button secondary" href="{{ url_for(\'help_page\') }}#routing-warp">'
        "Полная инструкция</a>"
        in template
    )
    assert "outbounds-gateway-style2" in template
def test_routing_cleanup_is_preserved() -> None:
    routing = read("xpanel/templates/routing.html")
    assert '<nav class="r096-tabs routing-simple-tabs"' not in routing
    assert '<section class="routing-status-strip"' not in routing
    assert '<footer class="routing-simple-footer"' not in routing
    assert "Выбранная конфигурация" in routing
    assert "Пользовательские правила" in routing
    assert "Базовая схема" in routing

def test_installer_checks_final_hotfix6_css() -> None:
    for rel in ("install.sh", "install-or-upgrade.sh", "deploy/ec2-first-install.sh"):
        body = read(rel)
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
        assert "fix40-ui-compact-hotfix6.css" in body
        assert "UI Compact Hotfix 6" in body


def test_geofiles_is_a_real_standalone_page() -> None:
    base = read("xpanel/templates/base.html")
    page = read("xpanel/templates/geofiles.html")
    web = read("xpanel/web.py")
    assert "request.endpoint in ['routing_page', 'geofiles_page']" in base
    assert "{% include '_geofiles_panel_fix39.html' %}" in page
    assert 'render_template(\n            "geofiles.html"' in web
    assert 'return redirect(url_for("routing_page") + "#geofiles")' not in web
    assert web.count('return redirect(url_for("geofiles_page"))') >= 3
