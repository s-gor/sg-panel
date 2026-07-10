from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_clients_use_network_scale_and_inline_delete():
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    assert "client-detail-standard" in html
    assert "КЛИЕНТ №" in html
    assert "Развёрнут на серверах" in html
    assert "<span>Ноды</span>" not in html
    assert "data-client-delete-open" in html
    assert "data-client-delete-confirm" in html
    assert "selectedClientUuid" in html
    assert "data-copy-client-uuid" in html
    assert ".client-detail-standard.client-quick-grid{grid-template-columns:repeat(3,minmax(0,1fr));" in packed
    assert ".client-extra-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));" in packed
    assert ".inline-confirm[hidden]{display:none!important;}" in packed


def test_cluster_uses_network_cards_and_inline_node_delete():
    nodes = (ROOT / "xpanel/templates/nodes.html").read_text(encoding="utf-8")
    detail = (ROOT / "xpanel/templates/node_detail.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)
    assert "ui-card cluster-overview-card" in nodes
    assert "ui-dashboard-metrics page-context-metrics cluster-context-metrics" in nodes
    assert "data-node-delete-open" in detail
    assert "data-node-delete-confirm" in detail
    assert "Удалить ноду «" in detail
    assert ".cluster-context-metrics{grid-template-columns:repeat(4,minmax(0,1fr));}" in packed
    assert ".node-card-grid{grid-template-columns:repeat(2,minmax(0,1fr));}" in packed


def test_edit_page_does_not_use_browser_confirm_for_user_delete():
    html = (ROOT / "xpanel/templates/user_edit.html").read_text(encoding="utf-8")
    assert "data-edit-user-delete-open" in html
    assert "data-edit-user-delete-confirm" in html
    delete_section = html.split("data-edit-user-delete-open", 1)[1].split("user-identity-rotation", 1)[0]
    assert "return confirm(" not in delete_section
