from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_release_identity_and_asset_order():
    init = text("xpanel/__init__.py")
    base = text("xpanel/templates/base.html")
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init
    assert "fix40-light-buttons-theme-icon-hotfix9.css" in base
    assert base.rfind("fix40-light-buttons-theme-icon-hotfix9.css") > base.rfind("fix40-interface-verification-hotfix8.css")


def test_light_section_buttons_use_jade_primary_material():
    css = text("xpanel/static/fix40-light-buttons-theme-icon-hotfix9.css")
    for marker in (
        'html[data-resolved-theme="light"] body.preview-9-rc6-typography .section-tabs a',
        "var(--jade-action-top, #709A84)",
        "var(--jade-action-bottom, #4D7864)",
        "var(--jade-champagne, #B88A45)",
        "var(--jade-top-light",
        "#FFFDF7 !important",
    ):
        assert marker in css


def test_theme_control_is_direct_icon_only():
    base = text("xpanel/templates/base.html")
    button_start = base.index('<button class="theme-chip theme-button theme-icon-only"')
    button_end = base.index("</button>", button_start)
    button = base[button_start:button_end]
    assert "theme-mode-icon-moon" in button
    assert "theme-mode-icon-sun" in button
    assert "data-theme-label" not in button
    assert "⌄" not in button
    assert "Графит" not in button
    assert 'data-theme-choice="graphite"' not in base
    assert 'data-theme-choice="light"' not in base


def test_all_install_paths_expect_hotfix9_and_validate_asset():
    for rel in ("install-or-upgrade.sh", "install.sh", "deploy/ec2-first-install.sh"):
        body = text(rel)
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
        assert "Light Button Gradient and Theme Icon Hotfix 9" in body
    assert 'LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"' in text("install.sh")
