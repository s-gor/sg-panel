from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"


def test_stage3_clients_uses_wide_stable_master_detail_contract():
    template = (TEMPLATES / "users.html").read_text(encoding="utf-8")
    css = (STATIC / "app.css").read_text(encoding="utf-8")

    assert "clients-stage3-wide" in template
    assert "grid-template-columns:minmax(0,1fr) 330px" in css
    assert "table-layout:fixed" in css
    assert ".clients-awg-table th:nth-child(1){width:25%}" in css
    assert ".clients-awg-table th:nth-child(6){width:14%}" in css
    assert "text-overflow:ellipsis" in css
    assert "word-break:normal" in css
    assert "overflow-wrap:normal" in css


def test_stage3_clients_compacts_inspector_without_losing_core_information():
    template = (TEMPLATES / "users.html").read_text(encoding="utf-8")
    css = (STATIC / "app.css").read_text(encoding="utf-8")

    assert "clients-awg-facts-compact" in template
    assert "Доступы и устройства" in template
    assert "client-device-uuid" in template
    assert "data-copy-value" in template
    assert "Последняя активность" in template
    assert "Подписка:" in template
    assert "device_link" in template
    assert "device_regenerate_uuid_route" in template
    assert "Источник клиента" not in template
    assert ".clients-awg-facts-compact>div.fact-wide{grid-column:1/-1}" in css


def test_stage3_clients_keeps_existing_forms_and_backend_routes():
    template = (TEMPLATES / "users.html").read_text(encoding="utf-8")

    assert "url_for('user_link', user_id=user.id)" in template
    assert "url_for('device_link', user_id=selected_user.id, device_id=device.id)" in template
    assert "url_for('user_edit_page', user_id=selected_user.id)" in template
    assert "url_for('device_add', user_id=selected_user.id)" in template
    assert "url_for('users_json_page')" not in template
    expert = (TEMPLATES / "advanced.html").read_text(encoding="utf-8")
    assert "url_for('users_json_page')" not in expert
    assert "Подключения клиента" in expert
    assert "url_for('user_traffic_reset', user_id=selected_user.id)" in template
    assert "url_for('users_toggle', user_id=selected_user.id)" in template
    assert "url_for('users_delete', user_id=selected_user.id)" in template
    assert template.count('name="csrf_token"') >= 3


def test_stage3_adds_no_new_global_css_layer():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    assert "stage-3" not in base.lower()
    assert "clients-stage3" not in base.lower()
