from __future__ import annotations

from pathlib import Path, PureWindowsPath
import re

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "xpanel/static/fix40-global-jade-routing-vision-hotfix4.css"
BASE = ROOT / "xpanel/templates/base.html"
DASHBOARD = ROOT / "xpanel/templates/dashboard.html"
FAILED_CSS = ROOT / "xpanel/static/fix40-system-security-reality-ui-fix1.css"
FAILED_JS = ROOT / "xpanel/static/fix40-system-security-reality-ui-fix1.js"
FAILED_MARKER = "fix40-system-security-reality-ui-fix1"


def _blocks(css: str):
    return re.findall(r"(?s)([^{}]+)\{([^{}]*)\}", css)


def test_dashboard_success_text_is_not_a_filled_badge() -> None:
    css = CSS.read_text(encoding="utf-8")
    filled = [
        (selector, body)
        for selector, body in _blocks(css)
        if "border-color: var(--sg-jade-border)" in body
        and "background: var(--sg-jade-soft)" in body
        and ".status.ok" in selector
    ]
    assert len(filled) == 1
    assert ".text-success" not in filled[0][0]


def test_dashboard_keeps_three_success_values_without_inline_patch() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")
    assert dashboard.count("text-success") == 3
    assert "data-sg-dashboard-no-green-fill" not in dashboard
    assert "background: transparent !important" not in dashboard


def test_failed_overlay_is_absent() -> None:
    base = BASE.read_text(encoding="utf-8")
    assert FAILED_MARKER not in base
    assert not FAILED_CSS.exists()
    assert not FAILED_JS.exists()
