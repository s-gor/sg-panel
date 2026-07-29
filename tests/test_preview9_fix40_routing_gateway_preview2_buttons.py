from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_preview2_button_layer_is_replaced_by_final_system() -> None:
    base = read("xpanel/templates/base.html")
    assert "routing-unified-preview2-buttons.css" not in base
    assert "fix40-ui23-repair4-final-system1.css" in base


def test_final_system_supports_both_resolved_themes() -> None:
    css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    assert 'html[data-resolved-theme="dark"]' in css
    assert 'html[data-resolved-theme="light"]' in css


def test_final_system_gives_choices_real_surfaces() -> None:
    css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    for marker in (".r096-choice-card > span", ".r096-segments label > span", "border:1px solid var(--sg-control-line)", "background:var(--sg-control-fill)"):
        assert marker in css


def test_missing_standard_slots_do_not_stretch_neighbours() -> None:
    css = read("xpanel/static/fix40-ui23-repair4-final-system1.css")
    assert ".route-slot.is-empty" in css
    assert "visibility:hidden" in css


def test_preview2_notes_remain_historical() -> None:
    notes = read("docs/history/build-notes/ROUTING-GATEWAY-PREVIEW2-BUTTONS-NOTES.md")
    assert "Не изменялось" in notes
