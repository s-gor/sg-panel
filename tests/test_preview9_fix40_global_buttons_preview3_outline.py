from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "xpanel/static/fix40-global-buttons-preview3-outline.css").read_text(encoding="utf-8")
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
NOTES = (ROOT / "GLOBAL-BUTTONS-PREVIEW3-OUTLINE-NOTES.md").read_text(encoding="utf-8")


def test_preview3_outline_stylesheet_is_loaded_after_preview2():
    old = BASE.index("fix40-global-buttons-preview2.css")
    new = BASE.index("fix40-global-buttons-preview3-outline.css")
    assert new > old


def test_ordinary_buttons_are_transparent_in_both_themes():
    assert CSS.count("background: transparent !important") >= 4
    assert 'html[data-resolved-theme="dark"]' in CSS
    assert 'html[data-resolved-theme="light"]' in CSS
    assert "border: 1px solid #58738d !important" in CSS
    assert "border: 1px solid #789184 !important" in CSS


def test_selected_and_pressed_controls_receive_accent_fill():
    assert ".section-tabs a.active" in CSS
    assert ".nested-tabs a.active" in CSS
    assert ".r096-choice-card > input:checked + span" in CSS
    assert ".r096-segments label > input:checked + span" in CSS
    assert "background: #58738d !important" in CSS
    assert "background: #4f7764 !important" in CSS


def test_routing_unselected_choices_are_forced_transparent():
    assert ".r096-choice-card > input:not(:checked) + span" in CSS
    assert ".r096-segments label > input:not(:checked) + span" in CSS
    assert "Routing option groups must never be filled unless checked" in CSS


def test_notes_record_cumulative_scope_and_no_backend_change():
    assert "Routing Gateway Preview 3" in NOTES
    assert "Backend" in NOTES
    assert "невыбранные варианты" in NOTES
