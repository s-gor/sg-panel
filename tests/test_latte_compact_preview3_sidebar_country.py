import ast
import ipaddress
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"
WEB = ROOT / "xpanel" / "web.py"


def _load_geoip_functions():
    tree = ast.parse(WEB.read_text(encoding="utf-8"))
    names = {
        "_geoip_read_varint",
        "_geoip_skip_field",
        "_geoip_cidr_matches",
        "_geoip_entry_country",
        "_bundled_geoip_country",
    }
    module = ast.Module(
        body=[node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names],
        type_ignores=[],
    )
    namespace = {
        "ipaddress": ipaddress,
        "Path": Path,
        "_GEOIP_ASSET_CACHE": {},
        "memoryview": memoryview,
        "__file__": str(WEB),
    }
    exec(compile(module, str(WEB), "exec"), namespace)
    return namespace["_bundled_geoip_country"]


def test_preview3_resolves_country_from_bundled_geoip_without_network():
    resolve = _load_geoip_functions()
    assert resolve("3.121.217.202") == "DE"
    assert resolve("54.196.170.197") == "US"
    assert resolve("1.1.1.1") == "AU"


def test_preview3_sidebar_matches_compact_awg_geometry():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "Latte Compact UI Preview 3" in css
    assert ".preview-3-sidebar-polish.rc20-awg-shell .sidebar" in css
    assert "padding:14px 10px 10px" in css
    assert "min-height:58px" in css
    assert "background:linear-gradient(180deg,#182B31,#16272D)" in css
    assert "country-flag-sidebar{width:22px;height:15px}" in css


def test_preview3_server_card_and_flag_fallback_contract():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    macro = (TEMPLATES / "_country_flag.html").read_text(encoding="utf-8")
    assert "sg070-preview7" in base
    assert "preview-3-sidebar-polish" in base
    assert "system-server-line" in base
    assert "system-server-subline" in base
    assert "this.onerror=null" in macro
    assert "flags/globe.svg" in macro
