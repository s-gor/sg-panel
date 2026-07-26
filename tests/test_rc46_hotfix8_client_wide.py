from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_selected_client_uses_awg_side_inspector():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    assert '<div class="clients-awg-master-detail' in html
    assert '<aside class="clients-awg-inspector client-detail-standard"' in html
    assert 'clients-awg-table-card' in html
    assert 'data-confirm="Удалить клиента' in html
    assert html.count("user_traffic_reset") == 1


def test_reset_action_is_kept_in_collapsed_access_management():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    danger = html.split('<details class="client-danger-zone">', 1)[1].split('</details>', 1)[0]
    assert 'Сбросить трафик' in danger
    assert 'user_traffic_reset' in danger
    assert 'client-technical-details' not in html
    expert = (ROOT / "xpanel/templates/advanced.html").read_text(encoding="utf-8")
    assert 'JSON клиентов' not in expert
    assert 'Управление подключениями клиентов' in expert


def test_preview5_has_readable_inspector_and_cache_revision():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    packed = compact(css)
    assert "clients-awg-inspector" in html
    assert "sg070" in base
    assert "sg070" in login
    assert ".clients-awg-inspector{position:sticky;top:18px;" in packed
    assert ".clients-awg-inspector .client-detail-name h2" in css
    assert ".clients-awg-server-card" in css
    assert ".clients-awg-facts" in css
    assert "font-size:25px" in packed
    assert "font-size:12px" in packed


def test_upgrade_script_verifies_served_hotfix8_css():
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert 'EXPECTED_UI_REVISION="sg070"' in script
    assert 'GUI не подключает CSS SG-Panel RC70' in script
    assert 'веб-служба не отдаёт светлую тему SG-Panel RC70' in script
    assert 'веб-служба не отдаёт Cluster hotfix SG-Panel RC70' in script
    assert 'SG-Panel RC70' in script
