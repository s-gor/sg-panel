from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "xpanel/static/fix40-global-buttons-preview1.css").read_text(encoding="utf-8")
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")


def test_global_button_stylesheet_is_loaded_last_after_routing_polish():
    routing = BASE.index("routing-unified-preview3-polish.css")
    buttons = BASE.index("fix40-global-buttons-preview1.css")
    assert buttons > routing


def test_dark_buttons_match_active_resources_material():
    assert "--sg-button-dark-bg: #58738d" in CSS
    assert "--sg-button-dark-border: #7892aa" in CSS
    assert "background: var(--sg-button-dark-bg) !important" in CSS
    assert "font-weight: var(--sg-button-font-weight) !important" in CSS


def test_light_buttons_match_active_resources_material():
    assert "--sg-button-light-bg: linear-gradient(180deg, #4f7764 0%, #3e6050 100%)" in CSS
    assert "--sg-button-light-border: #b88a45" in CSS
    assert "background: var(--sg-button-light-bg) !important" in CSS


def test_shared_component_covers_global_and_routing_buttons():
    for selector in (
        ".button",
        ".section-tabs a",
        ".nested-tabs a",
        ".client-action:not(.more)",
        ".r096-primary-button",
        ".r096-secondary-button",
        ".routing-unified-footer .validation-button",
        ".r096-choice-card > span",
        ".r096-segments label > span",
    ):
        assert selector in CSS


def test_semantic_variants_do_not_create_separate_colour_families():
    # Danger/warning/toggle controls are all instances of .button and therefore
    # use the same shared material. The preview CSS does not add red/green fills.
    assert ".button.danger" not in CSS
    assert ".button.warning" not in CSS
    assert ".button.toggle-enable" not in CSS
    assert ".button.toggle-disable" not in CSS


def test_notes_confirm_visual_only_scope():
    notes = (ROOT / "GLOBAL-BUTTONS-PREVIEW1-NOTES.md").read_text(encoding="utf-8")
    assert "No backend" in notes
    assert "Routing" in notes
    assert "Xray" in notes
