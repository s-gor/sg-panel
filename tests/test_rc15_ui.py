from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "xpanel" / "templates"


def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def test_grouped_navigation_matches_awg_workflow_order() -> None:
    html = _read("base.html")
    labels = [
        "<b>System</b>",
        "<b>Clients</b>",
        "<b>Xray Server</b>",
        "<b>Network</b>",
        "<b>Security</b>",
        "<b>Maintenance</b>",
    ]
    positions = [html.index(label) for label in labels]
    assert positions == sorted(positions)


def test_sidebar_footer_and_topbar_follow_awg_panel_pattern() -> None:
    html = _read("base.html")
    assert "СОБСТВЕННЫЙ СЕРВЕР" in html
    assert "SG-Panel Core" in html
    assert "СИСТЕМА В НОРМЕ" in html
    assert "ТРЕБУЕТСЯ ПРОВЕРКА" in html
    assert "data-account-button" in html


def test_theme_switch_has_system_light_and_dark_modes() -> None:
    html = _read("base.html")
    assert 'data-theme-choice="system"' in html
    assert 'data-theme-choice="light"' in html
    assert 'data-theme-choice="dark"' in html
    assert "sg-panel-theme" in html
    assert "prefers-color-scheme: dark" in html


def test_json_workbenches_have_format_validate_and_sync_flow() -> None:
    for name in (
        "section_json.html",
        "config_json.html",
        "routing_json.html",
        "outbound_json.html",
        "rule_json.html",
    ):
        html = _read(name)
        assert "Current JSON" in html, name
        assert "Форматировать" in html, name
        assert "data-validation-toolbar" in html, name
        assert "Синхронизировать" in html, name
        assert "data-validated-form" in html, name


def test_system_and_network_tabs_match_grouped_navigation() -> None:
    html = _read("base.html")
    for label in (
        "Resources",
        "Status &amp; Services",
        "Logs &amp; Diagnostics",
        "Traffic Rules",
        "Outbounds",
        "DNS",
    ):
        assert f">{label}<" in html


def test_diagnostics_uses_collapsed_service_log_panels() -> None:
    html = _read("diagnostics.html")
    css = (ROOT / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
    assert "Служебные сообщения" in html
    assert "Один журнал за раз" not in html
    assert "diagnosticLogSelect" not in html
    assert html.count('class="diagnostic-log-panel"') >= 5
    assert 'id="diagnostic-log-xray"' in html
    assert 'id="diagnostic-log-nginx"' in html
    assert 'id="diagnostic-log-panel"' in html
    assert 'id="diagnostic-log-ports"' in html
    assert ".diagnostic-log-panel" in css
    assert "height:330px" in css.replace(" ", "")


def test_base_and_login_templates_include_sg_favicon() -> None:
    for name in ("base.html", "login.html"):
        html = _read(name)
        assert "favicon.svg" in html
        assert 'rel="icon"' in html


def test_dashboard_uses_awg_quality_memory_composition() -> None:
    html = _read("dashboard.html")
    css = (ROOT / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
    assert "Оперативная память" in html
    assert "memory-dial" in html
    assert "memory-legend" in html
    assert "memory-legend-swatch {{ segment.tone }}" in html
    assert "memory-facts" in html
    assert "Пиковая память панели" in html
    assert "resource-secondary-strip" in html
    assert ".memory-dial" in css
    assert ".memory-legend-item" in css
