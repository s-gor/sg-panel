from pathlib import Path

from xpanel.service import fingerprint_for_xray, normalise_fingerprint_profile

ROOT = Path(__file__).resolve().parents[1]


def test_browser_aliases_are_preserved_in_ui_and_mapped_for_xray() -> None:
    assert normalise_fingerprint_profile("brave") == "brave"
    assert normalise_fingerprint_profile("opera") == "opera"
    assert normalise_fingerprint_profile("vivaldi") == "vivaldi"
    assert fingerprint_for_xray("brave") == "chrome"
    assert fingerprint_for_xray("opera") == "chrome"
    assert fingerprint_for_xray("vivaldi") == "chrome"
    assert fingerprint_for_xray("edge") == "edge"


def test_fingerprint_dropdown_contains_requested_browsers() -> None:
    html = (ROOT / "xpanel/templates/_fingerprint_select.html").read_text(encoding="utf-8")
    for value, label in (
        ("chrome", "Google Chrome"),
        ("brave", "Brave"),
        ("edge", "Microsoft Edge"),
        ("firefox", "Mozilla Firefox"),
        ("safari", "Apple Safari"),
        ("opera", "Opera"),
        ("vivaldi", "Vivaldi"),
        ("360", "360 Browser"),
        ("qq", "QQ Browser"),
        ("random", "Random"),
        ("randomized", "Randomized"),
    ):
        assert f'value="{value}"' in html
        assert label in html


def test_all_fingerprint_forms_use_shared_dropdown() -> None:
    for name in ("settings.html", "outbounds.html", "outbound_edit.html"):
        html = (ROOT / "xpanel/templates" / name).read_text(encoding="utf-8")
        assert "fingerprint_select" in html
        assert 'input name="fingerprint"' not in html


def test_dark_theme_uses_awg_blue_palette_and_bright_text() -> None:
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    for token in ("--bg: #0d131b", "--panel: #17212e", "--panel-3: #111923", "--text: #edf3fb"):
        assert token in css
    assert "exact SG-AWG-Panel dark palette" in css
    assert "#f4f8fc" in css


def test_installer_uses_green_awg_single_line_spinner() -> None:
    script = (ROOT / "deploy/ec2-first-install.sh").read_text(encoding="utf-8")
    assert "local frames='|/-\\'" in script
    assert "[SG-Panel] [%s%s%s] %s (%s сек)" in script
    assert '"$COLOR_GREEN" "${frames:frame_index%4:1}" "$COLOR_RESET"' in script
    assert "sleep 0.25" in script
    assert "[SG-Panel] [%sOK%s] %s (%s сек)" in script
    assert r"COLOR_GREEN=$'\033[1;32m'" in script
    assert "local -a frames" not in script


def test_rc20_shell_matches_awg_navigation_and_scale() -> None:
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    html = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    assert "rc20-awg-shell" in html
    assert "linear-gradient(135deg, #25518b, #284870)" in css
    assert "color: #76b7ff" in css
    assert "width: min(1540px, 100%)" in css
    assert "background: transparent !important" in css
