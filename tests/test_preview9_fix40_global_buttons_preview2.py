from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "xpanel/static/fix40-global-buttons-preview2.css").read_text(encoding="utf-8")
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
OUTBOUNDS = (ROOT / "xpanel/templates/outbounds.html").read_text(encoding="utf-8")


def test_preview2_stylesheet_is_loaded_after_preview1():
    assert BASE.index("fix40-global-buttons-preview2.css") > BASE.index("fix40-global-buttons-preview1.css")


def test_preview2_intentionally_outranks_historical_primary_rules():
    assert "body.preview-9-rc6-typography.preview-9-rc6-typography" in CSS
    assert "button.button" in CSS
    assert "a.button" in CSS
    assert "background-image: none !important" in CSS


def test_dark_primary_and_secondary_share_exact_reference_material():
    assert "background: #58738d !important" in CSS
    assert "border-color: #7892aa !important" in CSS
    assert "font-weight: 800 !important" in CSS
    assert "color: #fff !important" in CSS


def test_light_primary_and_secondary_share_exact_reference_material():
    assert "background: linear-gradient(180deg, #4f7764 0%, #3e6050 100%) !important" in CSS
    assert "border-color: #b88a45 !important" in CSS
    assert "color: #fffdf7 !important" in CSS


def test_outbounds_problem_buttons_are_ordinary_primary_and_secondary_buttons():
    for markup in (
        'class="button secondary" href="{{ url_for(\'help_page\') }}#routing-warp">Инструкция',
        'class="button primary" type="submit"',
        'class="button secondary" href="{{ url_for(\'outbound_json_new_page\') }}">{ } Создать из JSON',
        'class="button primary ob-output-toggle"',
    ):
        assert markup in OUTBOUNDS


def test_preview2_notes_confirm_visual_only_scope():
    notes = (ROOT / "GLOBAL-BUTTONS-PREVIEW2-NOTES.md").read_text(encoding="utf-8")
    assert "No backend" in notes
    assert "#41586f" in notes
    assert "Создать WARP" in notes
