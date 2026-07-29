from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
CSS = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
NOTES = (ROOT / "docs/history/build-notes/GLOBAL-BUTTONS-PREVIEW3-OUTLINE-NOTES.md").read_text(encoding="utf-8")


def test_preview_layers_are_not_loaded_after_final_replacement():
    assert "fix40-global-buttons-preview1.css" not in BASE
    assert "fix40-global-buttons-preview2.css" not in BASE
    assert "fix40-global-buttons-preview3-outline.css" not in BASE
    assert "fix40-ui23-repair4-final-system1.css" in BASE


def test_ordinary_buttons_are_outlined_in_both_themes():
    assert 'html[data-resolved-theme="dark"]' in CSS
    assert 'html[data-resolved-theme="light"]' in CSS
    assert "background: transparent !important" in CSS
    assert "border: 1px solid var(--sg-control-line) !important" in CSS


def test_primary_and_selected_controls_receive_one_accent_material():
    assert ".button.primary" in CSS
    assert ".r096-primary-button" in CSS
    assert ".r096-choice-card > input:checked + span" in CSS
    assert ".r096-segments label > input:checked + span" in CSS
    assert "background:var(--sg-control-fill) !important" in CSS


def test_routing_is_a_dedicated_component_not_a_global_button_side_effect():
    assert "Routing final composition" in CSS
    assert ".routing-unified-segments" in CSS
    assert ".routing-unified-footer" in CSS


def test_notes_remain_as_historical_record_only():
    assert "Routing Gateway Preview 3" in NOTES
    assert "Backend" in NOTES
