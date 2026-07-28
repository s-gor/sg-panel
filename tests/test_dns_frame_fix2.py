from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "xpanel" / "static" / "fix40-dns-frame-fix1.css"


def test_dns_frame_fix2_is_visual_only_and_scoped():
    css = CSS.read_text(encoding="utf-8")
    assert "DNS Frame Fix 2" in css
    assert "body.dns-simple-page" in css
    assert ".dns-current-card" in css
    assert ".dns-basic-add-card" in css
    assert ".dns-simple-servers" in css
    assert ".table-wrap" in css
    assert "border: 0 !important" in css
    assert "box-shadow: none !important" in css


def test_dns_frame_fix2_keeps_form_controls_out_of_blanket_selector():
    css = CSS.read_text(encoding="utf-8")
    selector = ":where(header,footer,form,section,article,div)"
    assert selector in css
    assert ":where(input" not in css
    assert ":where(button" not in css
    assert ":where(select" not in css
    assert ":where(textarea" not in css
