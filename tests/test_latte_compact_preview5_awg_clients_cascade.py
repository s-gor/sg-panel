from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_clients_uses_awg_master_detail_composition() -> None:
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    for marker in (
        "clients-awg-metrics",
        "Серверы подключения",
        "Network Controller",
        "clients-awg-filter-panel",
        "clients-awg-master-detail",
        "clients-awg-inspector",
        "Выдача конфигураций",
    ):
        assert marker in html
    assert ".clients-awg-metrics" in css
    assert "grid-template-columns:repeat(4,minmax(0,1fr))" in css.replace(" ", "")
    assert ".clients-awg-master-detail" in css


def test_cascade_uses_awg_two_variant_flow() -> None:
    html = (ROOT / "xpanel/templates/cascade.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    for marker in (
        "Подключайтесь к одному серверу, а выходите в интернет через другой",
        "Вариант 1 · Из Cluster",
        "Вариант 2 · Другой сервер",
        'data-cascade-mode-panel="cluster"',
        'data-cascade-mode-panel="external"',
        "Активные подключения Cascade",
        "Клиенты остаются в разделе Clients",
    ):
        assert marker in html
    assert ".cascade-awg-options" in css
    assert ".cascade-awg-route" in css
    assert ".cascade-awg-external-grid" in css


def test_clients_and_cascade_use_full_awg_workspace() -> None:
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    compact = "".join(css.split())
    assert '{% block page_actions %}' in base
    assert ".clients-awg-page,.cascade-awg-page{width:100%!important;max-width:none!important" in compact
    assert "body.awg-clients-page .topbar" in css
    assert "grid-template-rows:64pxauto" in compact
    assert "body.awg-clients-page .section-tabs" in css
    assert "body.awg-cascade-page .section-tabs" in css
