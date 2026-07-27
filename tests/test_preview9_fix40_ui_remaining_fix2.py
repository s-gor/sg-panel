from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def test_remaining_fix2_is_loaded_after_fix1_and_scoped() -> None:
    base = read("xpanel/templates/base.html")
    css = read("xpanel/static/fix40-ui-remaining-fix2.css")
    assert base.index("fix40-ui-remaining-fix1.css") < base.index("fix40-ui-remaining-fix2.css")
    assert "ui-remaining-fix2" in base
    assert ".topbar-heading h1" not in css

def test_outbounds_system_names_are_plain_and_technical_values_are_additional() -> None:
    page = read("xpanel/templates/outbounds.html")
    assert "Direct — прямой доступ" in page
    assert "Block — блокировка" in page
    assert "tag: {{ outbound.tag }} · protocol: {{ outbound.protocol }}" in page
    system_block = page[page.index('id="ob-system-title"'):page.index('id="warp-title"')]
    assert "<strong>{{ outbound.tag }}</strong>" not in system_block

def test_dns_main_hides_low_level_strategy_and_addresses() -> None:
    page = read("xpanel/templates/dns.html")
    advanced = read("xpanel/templates/advanced.html")
    assert "Базовая стратегия" not in page
    assert "+local://" not in page
    assert "{{ server.address }}" not in page
    assert 'type="hidden" name="query_strategy"' in page
    assert "Защищённый DNS (DoH)" in page
    assert "Статические Hosts" in advanced
    assert "Предпросмотр DNS JSON" in advanced

def test_security_never_displays_raw_endpoint_fallback() -> None:
    page = read("xpanel/templates/security.html")
    assert "Действие выполнено через интерфейс SG-Panel" in page
    assert "Подробности доступны в системном журнале" in page
    assert "item.detail|replace('_', ' ')" not in page
    assert "item.event|replace('_', ' ')" not in page
    assert "'node_deploy_clients':'Развёртывание клиентов на SG-Node'" in page
    assert "{{ 'Успешно' if item.success else 'Ошибка' }}" in page

def test_xmux_frames_are_removed_and_presets_stay_before_manual() -> None:
    css = read("xpanel/static/fix40-ui-remaining-fix2.css")
    settings = read("xpanel/templates/settings.html")
    advanced = read("xpanel/templates/advanced.html")
    assert "body.server-settings-page .sg-xmux-preset" in css
    assert "border:0!important" in css
    assert ".expert-xmux-manual-block" in css
    assert settings.index("sg-xmux-ready-presets") < settings.index("sg-xmux-manual-zone")
    assert advanced.index("Стандартный пресет") < advanced.index("Ручной XHTTP / XMUX JSON")
    assert advanced.index("Пресет «Для РФ — уменьшенный»") < advanced.index("Ручной XHTTP / XMUX JSON")
