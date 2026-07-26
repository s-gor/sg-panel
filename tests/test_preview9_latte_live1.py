from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "xpanel/static/rc6-typography.css").read_text(encoding="utf-8")
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
UPGRADE = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")


def test_exact_latte_tokens_are_present():
    for token in (
        "--page-bg: #D6DEE3",
        "--sidebar-bg: #C8D2D9",
        "--topbar-bg: #DFE6EA",
        "--card-bg: #E9EEF1",
        "--nested-bg: #DCE5E9",
        "--row-bg: #E4EAED",
        "--field-bg: #F7F9FA",
        "--border: #9EAFB9",
        "--border-soft: #BAC6CD",
        "--text-primary: #172531",
        "--text-secondary: #4E6371",
        "--text-muted: #687A85",
        "--blue: #315D82",
        "--success: #19785B",
        "--warning: #95681C",
        "--error: #A3464F",
    ):
        assert token in CSS


def test_geodata_badges_use_status_palette_not_dark_button_fill():
    assert ".geodata-file" in CSS
    assert "background: var(--warning-bg) !important" in CSS
    assert ".geodata-file.is-ready" in CSS
    assert "background: var(--success-bg) !important" in CSS


def test_live_cache_revision_is_consistent():
    # FIX35 gives every active stylesheet one cumulative cache revision.
    assert BASE.count("sg070-preview9-fix35-full-recovery") == 8
    assert "sg070-preview9-routing-server-fix34" not in BASE
    assert 'EXPECTED_UI_REVISION="sg070"' in UPGRADE
