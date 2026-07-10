from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_selected_client_is_outside_old_two_column_layout():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    layout_start = html.index('<div class="clients-studio-layout">')
    layout_end = html.index('<section class="client-detail-card client-detail-standard clients-selected-card', layout_start)
    before_card = html[layout_start:layout_end]
    assert before_card.rstrip().endswith("</div>")
    assert 'data-client-wide-card' in html
    assert '<aside class="client-detail-card' not in html
    assert html.count("user_traffic_reset") == 1


def test_reset_action_is_in_main_action_row_not_extra_details_row():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    actions = html.split('<div class="client-detail-actions">', 1)[1].split('</div>', 1)[0]
    details = html.split('<details class="client-technical-details">', 1)[1].split('</details>', 1)[0]
    assert 'class="client-reset-action"' in actions
    assert 'Сбросить трафик' in actions
    assert 'client-extra-actions' not in details
    assert 'Сбросить трафик' not in details


def test_hotfix8_has_readable_extra_fields_and_cache_revision():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    packed = compact(css)
    assert "КЛИЕНТ №" in html
    assert "sg070" in base
    assert "sg070" in login
    assert ".clients-selected-card{position:static;grid-column:1/-1;width:100%;" in packed
    assert ".clients-selected-card.client-extra-item>span" in packed
    assert ".clients-selected-card.client-extra-item>strong" in packed
    assert ".clients-selected-card.client-copy-rowcode" in packed
    assert ".clients-selected-card .client-extra-item > span" in css
    assert ".clients-selected-card .client-extra-item > strong" in css
    assert ".clients-selected-card .client-copy-row code" in css
    assert "font-size: 17px" in css
    assert "font-size: 15px" in css


def test_upgrade_script_verifies_served_hotfix8_css():
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert 'EXPECTED_UI_REVISION="sg070"' in script
    assert 'GUI не подключает CSS SG-Panel RC70' in script
    assert 'веб-служба отдаёт прежний app.css' in script
    assert 'SG-Panel RC70' in script
