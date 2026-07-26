from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"


def test_stage5_separates_global_shell_from_page_header():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    assert '<div class="workspace">' in base
    assert '<header class="global-topbar">' in base
    assert '<main class="content">' in base
    assert '<header class="topbar page-header awg-style-topbar">' in base
    assert base.index('class="global-topbar"') < base.index('class="content"')
    assert base.index('class="content"') < base.index('class="topbar page-header')


def test_stage5_keeps_server_identity_flags_and_readable_theme_control():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    assert 'country_flag(instance_country_code, "country-flag country-flag-topbar")' in base
    assert '<small>v{{ xpanel_version }}</small>' in base
    assert 'data-theme-label>Графит</b>' in base
    assert "if (label) label.textContent = choices[safe][1]" in base
    assert 'class="theme-chip theme-button"' in base


def test_stage5_uses_existing_typography_layer_and_larger_menu_geometry():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    css = (STATIC / "rc6-typography.css").read_text(encoding="utf-8")

    assert "rc6-typography.css" in base
    assert "stage-5" not in base.lower()
    assert ".global-topbar" in css
    assert ".topbar.page-header" in css
    assert "min-height:60px" in css
    assert "font-size: 15px" in css
    assert "font-size: 11.25px" in css
    assert "grid-template-columns: 250px minmax(0,1fr)" in css


def test_stage5_does_not_add_page_specific_markup_to_global_base():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    assert "cluster-stage4" not in base
    assert "clients-stage3" not in base
    assert "cascade-stage2" not in base
