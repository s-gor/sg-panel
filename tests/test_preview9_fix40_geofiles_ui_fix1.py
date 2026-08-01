from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_geofiles_active_pair_has_balanced_structure():
    template = (ROOT / "xpanel/templates/_geofiles_panel_fix39.html").read_text(encoding="utf-8")
    assert 'class="geofiles-active-grid"' in template
    assert 'class="geofiles-active-stack"' not in template
    assert 'class="geofiles-active-card is-source"' in template
    assert 'class="geofiles-active-card is-check"' in template
    assert template.count('class="geofiles-active-card is-file"') == 2
    assert template.index('class="geofiles-active-card is-source"') < template.index('class="geofiles-active-card is-check"') < template.index('class="geofiles-active-card is-file"')
    assert 'class="expert-example geofiles-categories-details"' in template


def test_geofiles_css_is_local_and_loaded_last():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/fix40-geofiles-ui-fix1.css").read_text(encoding="utf-8")
    assert "request.endpoint == 'geofiles_page'" in base
    assert "fix40-geofiles-ui-fix1.css" in base
    assert "geofiles-ui-fix1" in base
    assert base.index("fix40-ui23-repair4-final-system1.css") < base.index("fix40-geofiles-ui-fix1.css")
    assert "body.geofiles-standalone-page" in css
    assert ".geofiles-categories-details" in css
    assert "grid-template-columns: repeat(4, minmax(0, 1fr))" in css
    assert ".geofiles-safety-line" in css
    assert "border-radius: 17px" in css
    assert ".topbar-heading h1" not in css


def test_geofiles_fix_does_not_touch_runtime_logic():
    css = (ROOT / "xpanel/static/fix40-geofiles-ui-fix1.css").read_text(encoding="utf-8")
    assert "display: grid" in css
    assert "routing" not in css.lower()
    assert "xray" not in css.lower()
