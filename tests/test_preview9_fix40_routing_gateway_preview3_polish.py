from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_preview3_polish_is_replaced_by_one_final_layer() -> None:
    base = read("xpanel/templates/base.html")
    assert "routing-unified-preview3-polish.css" not in base
    assert "fix40-ui23-repair4-final-system1.css" in base


def test_final_system_softens_selected_buttons_in_both_themes() -> None:
    css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    assert "#607f9c" in css
    assert "#638d78" in css
    assert "--sg-control-shadow" in css


def test_geofiles_navigation_stays_secondary() -> None:
    template = read("xpanel/templates/routing.html")
    assert '<a class="r096-secondary-button" href="{{ url_for(\'geofiles_page\') }}">Открыть GeoFiles</a>' in template


def test_routing_uses_full_visible_validation_state() -> None:
    routing = read("xpanel/templates/routing.html")
    base = read("xpanel/templates/base.html")
    assert "data-validated-form data-validation-current-title" in routing
    assert "data-validation-compact" not in routing
    assert "Схема не применена" in base
    assert "Продолжает работать" in base


def test_errors_remain_visible_and_backend_change_is_explicitly_tested_elsewhere() -> None:
    base = read("xpanel/templates/base.html")
    assert "showStatus('is-error'" in base
    assert "body.warnings" in base
