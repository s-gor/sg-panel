from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_preview3_css_is_loaded_after_preview2_buttons() -> None:
    base = read("xpanel/templates/base.html")
    assert "routing-unified-preview2-buttons.css" in base
    assert "routing-unified-preview3-polish.css" in base
    assert base.index("routing-unified-preview3-polish.css") > base.index("routing-unified-preview2-buttons.css")


def test_preview3_softens_selected_buttons_in_both_themes() -> None:
    css = read("xpanel/static/routing-unified-preview3-polish.css")
    assert 'html[data-resolved-theme="dark"] body.routing-unified-preview1' in css
    assert 'html[data-resolved-theme="light"] body.routing-unified-preview1' in css
    assert "#36536f" in css
    assert "#718f82" in css
    assert "#4f8fc8" not in css
    assert "#6ca48b" not in css


def test_preview3_makes_geofiles_navigation_secondary() -> None:
    template = read("xpanel/templates/routing.html")
    assert '<a class="r096-secondary-button" href="{{ url_for(\'geofiles_page\') }}">Открыть GeoFiles</a>' in template
    assert '<a class="r096-primary-button" href="{{ url_for(\'geofiles_page\') }}">Открыть GeoFiles</a>' not in template


def test_preview3_uses_compact_validation_only_for_routing_form() -> None:
    routing = read("xpanel/templates/routing.html")
    base = read("xpanel/templates/base.html")
    assert "data-validated-form data-validation-compact" in routing
    assert "form.hasAttribute('data-validation-compact')" in base
    assert "status.hidden = true" in base
    assert "Есть непроверенные изменения" in base
    assert "Проверяю конфигурацию…" in base
    assert "window.setTimeout(() => { status.hidden = true; }, 2600)" in base


def test_preview3_keeps_errors_visible_and_does_not_change_routing_backend() -> None:
    base = read("xpanel/templates/base.html")
    notes = read("ROUTING-GATEWAY-PREVIEW3-POLISH-NOTES.md")
    assert "showStatus('is-error'" in base
    assert "errors remain visible" in notes
    assert "Routing model, candidate generation, GeoFiles, Outbounds and rollback are unchanged" in notes
