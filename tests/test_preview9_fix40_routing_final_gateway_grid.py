from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_failed_grid_layer_is_replaced_by_final_system():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    assert "routing-unified-final-gateway-grid.css" not in base
    assert "fix40-ui23-repair4-final-system1.css" in base


def test_standard_actions_use_explicit_direct_warp_block_slots():
    routing = (ROOT / "xpanel/templates/routing.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
    assert "route_slot(name, 'direct'" in routing
    assert "route_slot(name, 'warp'" in routing
    assert "route_slot(name, 'blocked'" in routing
    assert "grid-template-columns:repeat(3,minmax(0,1fr))" in css
    assert ".route-slot.is-empty" in css


def test_final_layer_uses_one_selected_material_and_nonsticky_apply_card():
    css = (ROOT / "xpanel/static/fix40-ui23-repair4-final-system1.css").read_text(encoding="utf-8")
    assert "background:var(--sg-control-fill) !important" in css
    assert "box-shadow:var(--sg-control-shadow) !important" in css
    assert "position:static !important" in css
