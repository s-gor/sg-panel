from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_routing_title_and_dedicated_cache_key():
    routing = (ROOT / "xpanel/templates/routing.html").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    assert "{% block heading %}Routing{% endblock %}" in routing
    assert "Маршрутизация{% endblock %}" not in routing
    assert "fix40-routing-ui-fix1.css" in base
    assert "routing-ui-fix1" in base


def test_routing_status_cards_are_not_outlined():
    css = (ROOT / "xpanel/static/fix40-routing-ui-fix1.css").read_text(encoding="utf-8")
    assert "border: 0 !important" in css
    assert "border-left: 0 !important" in css
    assert "border-radius: var(--radius, 16px) !important" in css
    assert ".routing-status-card.is-selected.is-pending" in css


def test_routing_font_changes_are_local_only():
    css = (ROOT / "xpanel/static/fix40-routing-ui-fix1.css").read_text(encoding="utf-8")
    assert "body.routing-final-system1" in css
    assert ".routing-apply-copy span" in css
    assert ".r096-warning-card span" in css
    assert ".r096-rule-list small" in css
    assert ".topbar-heading h1" not in css
    assert "body.preview-9-rc6-typography" not in css
