from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_clients_table_restores_original_primary_action() -> None:
    html = read("xpanel/templates/users.html")
    assert '>Основной доступ</a><a class="client-action more"' in html
    assert "Устройства и ссылки · {{ user.device_count }}" not in html
    assert ">+ Устройство</a>" not in html
    assert "clients-device-row-actions" not in html
    assert "clients-layout-hotfix3" in html


def test_device_management_remains_in_inspector() -> None:
    html = read("xpanel/templates/users.html")
    web = read("xpanel/web.py")
    assert 'data-open-dialog="add-device-dialog"' in html
    assert "+ Добавить устройство" in html
    assert 'return redirect(url_for("device_link", user_id=user_id, device_id=device["id"]))' in web


def test_primary_device_card_has_no_coloured_inset_accent() -> None:
    css = read("xpanel/static/fix40-clients-layout-hotfix3.css")
    assert ".client-device-card.is-primary" in css
    assert "box-shadow: none !important" in css
    assert "border-color: var(--line-soft) !important" in css


def test_client_management_is_balanced_and_delete_is_full_width() -> None:
    html = read("xpanel/templates/users.html")
    css = read("xpanel/static/fix40-clients-layout-hotfix3.css")
    assert '<section class="client-management-panel"' in html
    assert '<form class="client-management-delete"' in html
    assert 'grid-template-columns: repeat(2, minmax(0, 1fr)) !important' in css
    assert 'grid-column: 1 / -1 !important' in css
    assert 'width: 100% !important' in css
    assert '.client-management-delete .danger-outline' in css
    assert '<details class="client-danger-zone">' not in html


def test_reality_tcp_still_explicitly_names_xtls_vision() -> None:
    service = read("xpanel/service.py")
    assert service.count('"raw_reality": "VLESS REALITY TCP · XTLS VISION"') >= 2
    assert "flow=xtls-rprx-vision" in service


def test_hotfix_stylesheet_is_loaded_and_validated() -> None:
    base = read("xpanel/templates/base.html")
    assert "fix40-clients-layout-hotfix3.css" in base
    assert "fix40-clients-ux-hotfix2.css" not in base
    for script in ("install.sh", "install-or-upgrade.sh", "deploy/ec2-first-install.sh"):
        text = read(script)
        assert "fix40-clients-layout-hotfix3.css" in text
        assert "Clients Layout Hotfix 3" in text


def test_scope_keeps_internal_modal_contract() -> None:
    html = read("xpanel/templates/users.html")
    assert "window.confirm(" not in html
    assert "window.alert(" not in html
    assert "window.prompt(" not in html
