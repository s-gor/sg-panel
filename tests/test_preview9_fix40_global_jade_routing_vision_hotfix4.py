from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_global_jade_contract_is_loaded_last_and_covers_positive_states() -> None:
    base = read("xpanel/templates/base.html")
    css = read("xpanel/static/fix40-global-jade-routing-vision-hotfix4.css")
    assert "fix40-global-jade-routing-vision-hotfix4.css" in base
    assert base.rfind("fix40-global-jade-routing-vision-hotfix4.css") > base.rfind("fix40-clients-layout-hotfix3.css")
    for marker in (
        "Global Jade / Routing / Vision Hotfix 4",
        "--sg-jade: #456f5c",
        ".client-status-badge.online",
        ".outbound-status.enabled",
        ".system-pill:not(.attention)",
        ".validation-gate.is-success",
        ".cascade-state-pill.enabled",
        ".inbound-selection-state.is-active",
    ):
        assert marker in css


def test_clients_layout_has_stable_actions_and_complete_two_by_three_facts() -> None:
    users = read("xpanel/templates/users.html")
    css = read("xpanel/static/fix40-global-jade-routing-vision-hotfix4.css")
    assert '<div class="clients-row-actions"><a class="client-action primary"' in users
    assert "Основной доступ" in users and "•••" in users
    assert 'class="clients-awg-facts clients-awg-facts-compact"' in users
    for label in (
        "Маршрут", "Доступы", "Последняя активность", "Трафик за всё время", "Срок клиента", "Комментарий"
    ):
        assert label in users
    assert "grid-template-columns: minmax(128px, 1fr) 44px" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in css
    assert ".clients-awg-facts-compact > div.fact-wide" in css


def test_routing_is_one_readable_workspace_and_geofiles_is_separate() -> None:
    routing = read("xpanel/templates/routing.html")
    geofiles_page = read("xpanel/templates/geofiles.html")
    css = read("xpanel/static/fix40-global-jade-routing-vision-hotfix4.css")
    assert 'data-r096-tab="' not in routing
    assert "Выбранная конфигурация" in routing
    assert "Пользовательские правила" in routing
    assert "Основные правила" in routing
    assert "Серверная маршрутизация SG-Panel" in routing
    assert '_geofiles_panel_fix39.html' not in routing
    assert "{% include '_geofiles_panel_fix39.html' %}" in geofiles_page
    assert "body.routing-fix40-simple .section-tabs { display: none" in css
    for obsolete in (
        "Базовые сценарии SG Client",
        "Основные правила и выходы",
        "Создать готовое правило",
        "RoscomVPN · совместимость в GeoFiles",
    ):
        assert obsolete not in routing
    assert "Direct / VPN / Block" not in routing
    assert '"vpn"' not in routing.lower()


def test_geofiles_and_roscomvpn_contract_remains_on_geofiles_tab() -> None:
    panel = read("xpanel/templates/_geofiles_panel_fix39.html")
    service = read("xpanel/service.py")
    for marker in (
        "RoscomVPN · отдельная совместимость",
        "Совместимая серверная основа обязательна",
        "category-ads-all",
        "Оба файла всегда загружаются, проверяются и применяются вместе",
        "Применить проверенный план",
    ):
        assert marker in panel
    assert "GEOFILES_OPERATION_LOCK" in service
    assert "candidate_config_sha256" in service
    assert "remove_missing" not in service


def test_vision_and_mlkem_have_full_help_and_short_xray_explanation() -> None:
    help_html = read("xpanel/templates/help.html")
    settings = read("xpanel/templates/settings.html")
    for marker in (
        'id="vision-mlkem"',
        "Vision — не отдельный пакет",
        "vision=true",
        "flow=xtls-rprx-vision",
        "xray mlkem768",
        "Server Decryption",
        "Client Encryption",
        "mode=stream-one",
        "xray run -test",
        "Безопасное обновление существующей панели",
    ):
        assert marker in help_html
    assert "Vision не устанавливается отдельным модулем" in settings
    assert "flow=xtls-rprx-vision" in settings
    assert "Полная инструкция" in settings


def test_installer_hides_optional_warp_helper_warning_but_keeps_log_record() -> None:
    upgrade = read("install-or-upgrade.sh")
    visible_warning = "[SG-Panel] [%sПРЕДУПРЕЖДЕНИЕ%s] WARP-helper не обновлён"
    assert visible_warning not in upgrade
    assert 'log "WARP-helper не обновлён; необязательный компонент оставлен без изменений."' in upgrade
    for script in ("install.sh", "install-or-upgrade.sh", "deploy/ec2-first-install.sh"):
        text = read(script)
        assert "fix40-ui-compact-hotfix6.css" in text
        assert "UI Compact Hotfix 6" in text
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in text
