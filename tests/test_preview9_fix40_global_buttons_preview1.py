from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")


def test_final_control_system_is_loaded_after_page_specific_layers():
    assert BASE.index("fix40-ui23-repair4-final-system1.css") > BASE.index("fix40-cascade-steps-ui20.css")
    assert "fix40-global-buttons-preview1.css" not in BASE


def test_dark_buttons_use_final_control_material():
    assert "--sg-control-fill: linear-gradient(180deg,#607f9c" in CSS
    assert "--sg-control-fill-line: #7e9bb5" in CSS
    assert "font-weight: var(--sg-control-weight) !important" in CSS


def test_light_buttons_use_final_control_material():
    assert "--sg-control-fill: linear-gradient(180deg,#638d78" in CSS
    assert "--sg-control-fill-line: #496e5b" in CSS


def test_shared_component_covers_global_and_routing_buttons():
    for selector in ("button.button", "a.button", ".client-action:not(.more)", ".r096-primary-button", ".r096-secondary-button", ".routing-unified-footer .validation-button", ".r096-choice-card > span", ".r096-segments label > span"):
        assert selector in CSS


def test_semantic_variants_are_deliberate_not_one_fill_for_everything():
    assert ".button.primary" in CSS
    assert ".button.danger" in CSS
    assert "background: transparent !important" in CSS


def test_preview1_notes_remain_historical_record():
    notes = (ROOT / "docs/history/build-notes/GLOBAL-BUTTONS-PREVIEW1-NOTES.md").read_text(encoding="utf-8")
    assert "No backend" in notes
