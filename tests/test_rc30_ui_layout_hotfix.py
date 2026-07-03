from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_clients_layout_gives_more_width_to_table_without_clipping_detail_card():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    assert ".clients-studio-layout{display:grid;grid-template-columns:minmax(0,1fr)minmax(264px,286px);" in packed
    assert ".clients-studio-layout{grid-template-columns:minmax(0,1fr)270px;}" in packed
    assert "@media(max-width:1280px){.clients-studio-layout{grid-template-columns:1fr;}" in packed
    assert ".clients-studio-table{width:100%;min-width:0;table-layout:fixed;" in packed
    assert ".clients-table-card.table-wrap{margin:0;overflow-x:hidden;}" in packed
    assert ".clients-studio-tableth:nth-child(6),.clients-studio-tabletd:nth-child(6){width:15%;}" in packed
    assert ".clients-studio-tableth{" in packed and "white-space:normal" in packed
    assert ".clients-row-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));" in packed
    assert ".client-action{min-width:0;" in packed and "white-space:normal" in packed
    assert "@media(max-width:900px){.clients-table-card.table-wrap{overflow-x:auto;}.clients-studio-table{min-width:820px;}" in packed
    assert ".client-detail-nameh2{" in packed and "overflow-wrap:anywhere" in packed
    assert ".client-detail-actions.button{width:100%;min-width:0;height:auto;" in packed


def test_hysteria_heading_uses_full_width_and_keeps_actions_on_left():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    assert ".hysteria-studio-heading{display:grid!important;grid-template-columns:autominmax(0,1fr);" in packed
    assert ".hysteria-studio-heading>span{grid-row:1/span2;}" in packed
    assert ".hysteria-studio-actions{grid-column:2;display:flex;width:100%;min-width:0;" in packed
    assert "justify-content:flex-start" in packed
    assert ".hysteria-studio-overviewstrong{" in packed and "overflow-wrap:anywhere" in packed
    assert ".hysteria-readinessstrong{min-width:0;overflow-wrap:anywhere" in packed
    assert "font-size:10px" in packed  # existing readable badge text is preserved


def test_stylesheet_cache_key_is_updated_everywhere():
    for name in ("base.html", "login.html"):
        template = (ROOT / "xpanel/templates" / name).read_text(encoding="utf-8")
        assert "?v={{ xpanel_version }}-rc30hf7-ui" in template


def test_network_status_cards_use_one_desktop_row_with_existing_responsive_fallbacks():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    assert ".routing-context-metrics{grid-template-columns:repeat(4,minmax(0,1fr));}" in packed
    assert "@media(max-width:1150px){.routing-context-metrics{grid-template-columns:repeat(2,minmax(0,1fr));}}" in packed
    assert "@media(max-width:760px){.routing-context-metrics{grid-template-columns:1fr;}}" in packed


def test_remaining_ui_polish_is_compact_and_responsive():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    link = (ROOT / "xpanel/templates/link.html").read_text(encoding="utf-8")
    settings = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    dashboard = (ROOT / "xpanel/templates/dashboard.html").read_text(encoding="utf-8")

    assert ".link-grid.qr-frame{width:min(210px,100%);" in packed
    assert ".link-grid.link-box{min-height:150px;" in packed
    assert "@media(max-width:1280px){.link-grid{grid-template-columns:minmax(230px,.58fr)minmax(420px,1.42fr);}}" in packed
    assert "@media(max-width:900px){.link-grid{grid-template-columns:1fr;}" in packed
    assert "DIRECT QR" in link and "SUBSCRIPTION QR" in link

    assert 'class="inbound-detection-header"' in settings
    assert 'class="inbound-detection-domain"' in settings
    assert ".inbound-detection-grid{grid-template-columns:minmax(220px,1.55fr)repeat(4,minmax(110px,1fr));" in packed
    assert ".inbound-detection-gridstrong{" in packed and "overflow-wrap:anywhere" in packed

    assert 'class="memory-dial-product">SG-Panel' in dashboard
    assert "sys.panel_memory_human" in dashboard
    assert "sys.memory_available_human" in dashboard
    assert ".memory-dial-centerstrong{" in packed and "color:#66d99a!important" in packed

    assert ".clients-studio-tabletd{padding-top:13px;padding-bottom:13px;}" in packed
    assert ".client-action{min-height:32px;" in packed and "font-size:10px" in packed
