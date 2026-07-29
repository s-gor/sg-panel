from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_hotfix7_css_is_loaded_last() -> None:
    base = read("xpanel/templates/base.html")
    # Phase 6 consolidated stylesheet contract: Hotfix 5→9 is one active layer.
    assert "fix40-light-buttons-theme-icon-hotfix9.css" in base
    assert "fix40-interface-cleanup-hotfix5.css" not in base
    assert "fix40-ui-compact-hotfix6.css" not in base
    assert "fix40-global-tabs-dark-buttons-hotfix7.css" not in base
    assert "fix40-interface-verification-hotfix8.css" not in base


def test_all_section_tabs_are_equal_buttons_without_underline() -> None:
    css = read("xpanel/static/fix40-global-tabs-dark-buttons-hotfix7.css")
    assert "body.preview-9-rc6-typography .section-tabs" in css
    assert "grid-auto-columns: 180px !important" in css
    assert "width: 180px !important" in css
    assert "border-bottom: 0 !important" in css
    assert "color: #fff !important" in css


def test_dark_theme_uses_sg_blue_gray_for_tabs_and_primary_actions() -> None:
    css = read("xpanel/static/fix40-global-tabs-dark-buttons-hotfix7.css")
    assert 'html[data-resolved-theme="dark"] body.preview-9-rc6-typography .section-tabs a' in css
    assert "background: #41586f !important" in css
    assert "background: #58738d !important" in css
    assert 'html[data-resolved-theme="dark"] body.preview-9-rc6-typography .button.primary' in css
    assert "color: #fff !important" in css


def test_release_identity_is_hotfix7() -> None:
    init = read("xpanel/__init__.py")
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init
    for entry in ("install.sh", "install-or-upgrade.sh"):
        body = read(entry)
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
