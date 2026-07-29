from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
OUTBOUNDS = (ROOT / "xpanel/templates/outbounds.html").read_text(encoding="utf-8")


def test_preview2_is_replaced_not_layered():
    assert "fix40-global-buttons-preview2.css" not in BASE
    assert "fix40-ui23-repair4-final-system1.css" in BASE


def test_final_system_intentionally_outranks_historical_rules():
    assert "body.preview-9-rc6-typography" in CSS
    assert "!important" in CSS
    assert "--sg-control-transition" in CSS


def test_primary_and_secondary_are_visually_distinct():
    assert "background: transparent !important" in CSS
    assert "background: var(--sg-control-fill) !important" in CSS


def test_both_themes_have_dedicated_variables():
    assert 'html[data-resolved-theme="dark"]' in CSS
    assert 'html[data-resolved-theme="light"]' in CSS


def test_outbounds_problem_buttons_remain_ordinary_actions():
    for marker in ('class="button secondary"', 'class="button primary"'):
        assert marker in OUTBOUNDS


def test_preview2_notes_remain_historical_record():
    notes = (ROOT / "docs/history/build-notes/GLOBAL-BUTTONS-PREVIEW2-NOTES.md").read_text(encoding="utf-8")
    assert "No backend" in notes
