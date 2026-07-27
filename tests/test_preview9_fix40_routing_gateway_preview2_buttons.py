from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_preview2_button_css_is_loaded_after_global_hotfixes() -> None:
    base = read("xpanel/templates/base.html")
    assert "routing-unified-preview2-buttons.css" in base
    assert base.index("routing-unified-preview2-buttons.css") > base.index("fix40-cascade-steps-ui20.css")


def test_preview2_supports_graphite_and_resolved_dark_theme() -> None:
    css = read("xpanel/static/routing-unified-preview2-buttons.css")
    assert 'html[data-theme="graphite"] body.routing-unified-preview1' in css
    assert 'html[data-resolved-theme="dark"] body.routing-unified-preview1' in css
    assert 'html[data-resolved-theme="light"] body.routing-unified-preview1' in css


def test_preview2_gives_all_choices_real_button_surfaces() -> None:
    css = read("xpanel/static/routing-unified-preview2-buttons.css")
    for marker in (
        ".r096-choice-card > span",
        ".r096-segments label > span",
        "background: var(--rup2-option-bg) !important",
        "border: 1px solid var(--rup2-option-border) !important",
        "background: var(--rup2-selected-bg) !important",
        "color: var(--rup2-selected-text) !important",
    ):
        assert marker in css


def test_preview2_keeps_disabled_choices_visible() -> None:
    css = read("xpanel/static/routing-unified-preview2-buttons.css")
    assert ".r096-choice-card > input:disabled + span" in css
    assert "background: var(--rup2-disabled-bg) !important" in css
    assert "opacity: 1 !important" in css


def test_preview2_is_visual_only() -> None:
    notes = read("ROUTING-GATEWAY-PREVIEW2-BUTTONS-NOTES.md")
    assert "Не изменялось" in notes
    assert "построение Xray candidate" in notes
    assert "backup / rollback" in notes
