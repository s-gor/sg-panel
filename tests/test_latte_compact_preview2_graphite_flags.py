from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"


def test_preview2_contains_complete_country_flag_asset_set():
    flags = sorted((STATIC / "flags").glob("*.png"))
    assert len(flags) == 250
    assert {"DE.png", "FR.png", "US.png", "CH.png", "GB.png", "UA.png"}.issubset(
        {item.name for item in flags}
    )
    assert (STATIC / "flags" / "globe.svg").is_file()


def test_preview2_uses_flag_assets_in_shared_server_identity():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    dashboard = (TEMPLATES / "dashboard.html").read_text(encoding="utf-8")
    nodes = (TEMPLATES / "nodes.html").read_text(encoding="utf-8")
    cascade = (TEMPLATES / "cascade.html").read_text(encoding="utf-8")
    users = (TEMPLATES / "users.html").read_text(encoding="utf-8")
    macro = (TEMPLATES / "_country_flag.html").read_text(encoding="utf-8")

    assert "flags/' ~ normalized ~ '.png'" in macro
    assert "country-flag-topbar" in base
    assert "country-flag-sidebar" in base
    assert "country-flag-identity" in dashboard
    assert "node.country_code" in nodes
    assert "country-flag country-flag-inline" in nodes
    assert "cascade.exit_country_code" in cascade
    assert "country-flag-inline" in users


def test_preview2_graphite_reserves_green_for_status_and_blue_for_actions():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "Latte Compact UI Preview 2" in css
    assert "--accent: #5FA7FF" in css
    assert "--success: #55D99E" in css
    assert "background:linear-gradient(180deg,#315F99,#274E81)" in css
    assert "country-flag-identity" in css


def test_preview2_cache_buster_is_present():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "sg070-preview7" in base
    assert "preview-2-awg-graphite" in base
