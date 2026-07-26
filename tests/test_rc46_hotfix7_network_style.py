from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_clients_use_awg_master_detail_and_inline_delete():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    assert "client-detail-standard" in html
    assert "clients-awg-master-detail" in html
    assert "clients-awg-inspector" in html
    assert "Серверы подключения" in html
    assert "<span>Ноды</span>" not in html
    assert 'data-confirm="Удалить клиента' in html
    assert "client-device-uuid" in html
    assert "data-copy-value" in html
    assert ".clients-awg-master-detail{display:grid;grid-template-columns:minmax(0,1fr)360px;" in packed or ".clients-awg-master-detail{display:grid;grid-template-columns:minmax(0,1fr)330px;" in packed
    assert ".inline-confirm[hidden]{display:none!important;}" in packed


def test_cluster_uses_compact_rows_and_inline_node_delete():
    nodes = (ROOT / "xpanel/templates/nodes.html").read_text(encoding="utf-8")
    detail = (ROOT / "xpanel/templates/node_detail.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/fix40-cluster-restore-ui21.css").read_text(encoding="utf-8")
    assert "cluster-controller-card" in nodes
    assert "cluster-restore-onboarding" in nodes
    assert "compact-node-list" in nodes
    assert "compact-node-row" in nodes
    assert "data-node-delete-open" in detail
    assert "data-node-delete-confirm" in detail
    assert "Удалить ноду «" in detail
    assert ".node-restore-status" in css


def test_edit_page_does_not_use_browser_confirm_for_user_delete():
    html = (ROOT / "xpanel/templates/user_edit.html").read_text(encoding="utf-8")
    assert "data-edit-user-delete-open" in html
    assert "data-edit-user-delete-confirm" in html
    delete_section = html.split("data-edit-user-delete-open", 1)[1].split("user-identity-rotation", 1)[0]
    assert "return confirm(" not in delete_section
