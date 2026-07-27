from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


def test_remaining_fix_css_is_scoped_and_loaded_with_new_cache_key() -> None:
    base = read('xpanel/templates/base.html')
    css = read('xpanel/static/fix40-ui-remaining-fix1.css')
    assert 'fix40-ui-remaining-fix1.css' in base
    assert 'ui-remaining-fix1' in base
    assert '.topbar-heading h1' not in css
    assert 'body.outbounds-page' in css
    assert 'body.dns-simple-page' in css
    assert 'body.security-page' in css
    assert 'body.updates-page' in css


def test_outbounds_is_plain_language_and_warp_json_is_additional() -> None:
    page = read('xpanel/templates/outbounds.html')
    assert 'Системные выходы' in page
    assert '<h2 id="warp-title">WARP</h2>' in page
    assert 'Пользовательские выходы' in page
    assert 'warp-more-actions' in page
    assert 'Технические параметры' in page
    assert 'WARP Outbound' not in page
    assert 'Custom outbounds' not in page


def test_dns_main_is_simple_and_technical_sections_are_in_expert() -> None:
    dns = read('xpanel/templates/dns.html')
    advanced = read('xpanel/templates/advanced.html')
    web = read('xpanel/web.py')
    assert 'dns-simple-page' in dns
    assert 'Expert DNS' in dns
    assert 'Статические записи' not in dns
    assert 'json-preview dns-preview' not in dns
    assert 'id="dns-expert"' in advanced
    assert 'Статические Hosts' in advanced
    assert 'Предпросмотр DNS JSON' in advanced
    assert 'dns_settings=get_dns_settings()' in web
    assert 'def _dns_redirect()' in web
    assert 'return redirect(url_for("dns_page"))' in web


def test_security_history_is_readable_and_localized() -> None:
    page = read('xpanel/templates/security.html')
    css = read('xpanel/static/fix40-ui-remaining-fix1.css')
    assert 'js-local-datetime' in page
    assert "routing_unified_save':'Сохранение Routing'" in page
    assert "new Intl.DateTimeFormat('ru-RU'" in page
    assert 'grid-template-columns:repeat(2,minmax(0,1fr))!important' in css
    assert 'max-height:none!important' in css


def test_updates_fonts_are_local_and_xmux_presets_precede_manual_json() -> None:
    css = read('xpanel/static/fix40-ui-remaining-fix1.css')
    advanced = read('xpanel/templates/advanced.html')
    settings = read('xpanel/templates/settings.html')
    assert '.xray-update-guards span' in css
    assert '.update-safety-flow strong' in css
    assert '.update-log' in css
    assert advanced.index('Стандартный пресет') < advanced.index('Ручной XHTTP / XMUX JSON')
    assert advanced.index('Пресет «Для РФ — уменьшенный»') < advanced.index('Ручной XHTTP / XMUX JSON')
    assert settings.index('sg-xmux-ready-presets') < settings.index('sg-xmux-manual-zone')
