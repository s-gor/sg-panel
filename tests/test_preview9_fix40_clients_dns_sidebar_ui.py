from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_build_label_is_separate_from_legacy_core_version() -> None:
    init = read("xpanel/__init__.py")
    web = read("xpanel/web.py")
    base = read("xpanel/templates/base.html")
    assert '__version__ = "0.10.0-rc70"' in init
    assert '__build__ = "FIX40"' in init
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init
    assert '"xpanel_build": __build__' in web
    assert '"xpanel_release_label": __release_label__' in web
    assert '<small>{{ xpanel_release_label }}</small>' in base
    assert '<strong class="system-server-version">{{ xpanel_build }}</strong>' in base
    assert '<span class="topbar-version">{{ xpanel_build }}</span>' in base
    assert 'СИСТЕМА ГОТОВА <b>{{ xpanel_build }}</b>' in read("xpanel/templates/login.html")


def test_fix40_stylesheet_is_loaded_last() -> None:
    base = read("xpanel/templates/base.html")
    fix35 = base.index("fix35-full-recovery.css")
    fix40 = base.index("fix40-ui-repair.css")
    assert fix40 > fix35
    assert "clients-dns-sidebar" in base


def test_collapsed_sidebar_contract() -> None:
    css = read("xpanel/static/fix40-ui-repair.css")
    assert "grid-template-columns: 72px minmax(0, 1fr)" in css
    assert "width: 72px !important" in css
    assert "flex: 0 0 48px !important" in css
    assert "height: 48px !important" in css
    assert "overflow: hidden !important" in css
    assert "scrollbar-width: none !important" in css
    assert ".sidebar-spacer" in css and "display: none !important" in css


def test_clients_inspector_contract() -> None:
    users = read("xpanel/templates/users.html")
    css = read("xpanel/static/fix40-ui-repair.css")
    assert "'clients-fix40'" in users
    assert "minmax(320px, 390px)" in css
    assert "body.clients-fix40 .client-device-uuid" in css
    assert "grid-template-columns: minmax(0, 1fr) auto" in css
    assert "body.clients-fix40 .client-device-actions" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in css
    assert "@media (max-width: 1080px)" in css


def test_dns_page_has_no_summary_cards_or_detached_priority_column() -> None:
    dns = read("xpanel/templates/dns.html")
    assert "{% block section %}DNS{% endblock %}" in dns
    assert "{% block heading %}DNS{% endblock %}" in dns
    assert "dns-context-metrics" not in dns
    assert "<th>Приоритет</th>" not in dns
    assert '<table class="dns-server-table">' in dns
    assert "dns-priority-note" in dns
    assert "Приоритет {{ server.priority }}" in dns
    assert '<p class="panel-kicker">UPSTREAM</p><h2>DNS-серверы</h2>' not in dns
    assert "Контекстный JSON DNS" in dns
    assert dns.index("Контекстный JSON DNS") < dns.index("Общие настройки DNS")
