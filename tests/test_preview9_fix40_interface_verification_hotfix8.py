from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_release_identity_and_stylesheet_order():
    init = text("xpanel/__init__.py")
    base = text("xpanel/templates/base.html")
    # Phase 6 consolidated stylesheet contract: Hotfix 5→9 is one active layer.
    assert "fix40-light-buttons-theme-icon-hotfix9.css" in base
    assert "fix40-interface-cleanup-hotfix5.css" not in base
    assert "fix40-ui-compact-hotfix6.css" not in base
    assert "fix40-global-tabs-dark-buttons-hotfix7.css" not in base
    assert "fix40-interface-verification-hotfix8.css" not in base
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init


def test_tab_labels_are_explicit_and_routing_has_no_duplicate_tabs():
    base = text("xpanel/templates/base.html")
    assert 'class="section-tab-label">Resources</span>' in base
    assert 'class="section-tab-label">Subscriptions</span>' in base
    assert 'not is_routing' in base
    tabs = base[base.index('{% if not is_xray'):base.index('{% with messages')]
    assert 'Traffic Rules' not in tabs


def test_ui8_css_forces_visible_white_labels():
    css = text("xpanel/static/fix40-interface-verification-hotfix8.css")
    for marker in (
        "-webkit-text-fill-color: #ffffff !important",
        "opacity: 1 !important",
        "visibility: visible !important",
        "background: #41586f !important",
        ".network-controller-state",
    ):
        assert marker in css


def test_routing_title_and_clients_controller_status():
    routing = text("xpanel/templates/routing.html")
    users = text("xpanel/templates/users.html")
    assert "{% block heading %}Routing{% endblock %}" in routing
    assert "Единая схема правил" in routing
    assert "network-controller-state" in users
    assert '<strong class="{{ \'text-success\'' not in users


def test_installers_expect_hotfix8_and_ui8_asset():
    for rel in ("install-or-upgrade.sh", "install.sh", "deploy/ec2-first-install.sh"):
        body = text(rel)
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
        assert "Interface Verification Hotfix 8" in body
    assert 'LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"' in text("install.sh")
