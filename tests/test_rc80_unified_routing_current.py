from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_rc80_unified_routing_is_the_active_entry() -> None:
    web = (ROOT / "xpanel" / "web.py").read_text(encoding="utf-8")
    base = (ROOT / "xpanel" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "def routing_unified_planner_preview4_page" in web
    assert '"routing_unified_planner_preview4.html"' in web
    assert "routing_unified_planner_preview4_page" in base


def test_rc80_transaction_and_user_rules_are_present() -> None:
    module = (ROOT / "xpanel" / "unified_planner_preview4.py").read_text(encoding="utf-8")
    template = (
        ROOT / "xpanel" / "templates" / "routing_unified_planner_preview4.html"
    ).read_text(encoding="utf-8")
    assert "def validate_plan" in module
    assert "def apply_checked_plan" in module
    assert '"kind": "unified-routing-geofiles-xray"' in module
    assert "xray run -test" in module
    assert "Пользовательские правила" in template
    assert 'name="custom_direct_domains"' in template
    assert 'name="custom_warp_domains"' in template
    assert 'name="custom_block_domains"' in template


def test_rc80_final_ui_layers_are_present() -> None:
    template = (
        ROOT / "xpanel" / "templates" / "routing_unified_planner_preview4.html"
    ).read_text(encoding="utf-8")
    for marker in (
        "SG-Panel RC80 Two Column Routing Preview 21",
        "SG-Panel RC80 Two Column Bottom Align Preview 22",
        "SG-Panel RC80 User Rules Preview 23 Fixed",
        "SG-Panel RC80 Neutral Buttons Fix 2",
        "SG-Panel RC80 Dark Graphite Restore Fix 3",
    ):
        assert marker in template
