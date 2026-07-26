import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"
WEB = ROOT / "xpanel" / "web.py"


def test_stage1_topbar_and_route_diagram_contract():
    css = (STATIC / "cascade-rc6.css").read_text(encoding="utf-8")
    template = (TEMPLATES / "cascade.html").read_text(encoding="utf-8")

    assert "grid-template-rows: 58px minmax(76px,auto)" in css
    assert "body.sg-awg-cascade-rc6 .topbar::before" in css
    assert "cascade-route-server" in template
    assert 'country_flag(instance_country_code, "country-flag country-flag-route"' in template
    assert 'country_flag(cascade.exit_country_code, "country-flag country-flag-route"' in template
    assert "Сервер ещё не выбран" in template
    assert "grid-template-columns: repeat(2,minmax(0,1fr))" in css


def test_stage1_uses_existing_css_layers_only():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "cascade-rc6.css" in base
    assert "rc6-typography.css" in base
    assert "stage-1" not in base.lower()


def test_stage1_sidebar_readability_is_not_reduced():
    app_css = (STATIC / "app.css").read_text(encoding="utf-8")
    type_css = (STATIC / "rc6-typography.css").read_text(encoding="utf-8")
    assert "gap:5px" in app_css
    assert "padding:14px 10px 10px" in app_css
    assert "min-height:58px" in app_css
    assert "font-size: 14.5px" in type_css
    assert "font-size: 11px" in type_css


def test_country_cache_guard_does_not_treat_missing_entry_as_fresh():
    tree = ast.parse(WEB.read_text(encoding="utf-8"))
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_instance_country")
    source = ast.get_source_segment(WEB.read_text(encoding="utf-8"), fn) or ""
    assert "cached = _COUNTRY_CACHE.get(value)" in source
    assert "cached is not None" in source
    assert "_COUNTRY_CACHE.get(value) or {}" not in source
