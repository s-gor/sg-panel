from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_profiles_are_grouped_by_certificate_requirement_and_ordered_by_family():
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    assert "REALITY · без сертификата" in html
    assert "TLS · нужен сертификат" in html
    positions = [
        html.index('value="raw_reality"'),
        html.index('value="xhttp_reality"'),
        html.index('value="xhttp_tls"'),
        html.index('value="hysteria2_tls"'),
        html.index('value="xhttp_hysteria_tls"'),
    ]
    assert positions == sorted(positions)
    assert "Работает сейчас" in html
    assert "Выбрано, ещё не применено" in html
    assert "Выбор карточки ещё не переключает сервер" in html


def test_selected_profile_explains_connection_path_before_settings():
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    assert "Серверная схема подключения" in html
    assert "Параметры подключения клиента" in html
    assert "Сначала идут значения из клиентской ссылки" in html
    assert "Выбрано, ещё не применено" in html
    assert 'id="inbound-route-client"' not in html
    assert 'id="inbound-active-banner"' not in html


def test_light_theme_overrides_hard_dark_surfaces_and_has_clear_states():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    for marker in (
        'html[data-resolved-theme="light"] .ui-card-heading',
        'html[data-resolved-theme="light"] .ui-info-note',
        'html[data-resolved-theme="light"] .inbound-profile-family',
        'html[data-resolved-theme="light"] .inbound-profile-card.is-active',
        'html[data-resolved-theme="light"] .inbound-profile-card.is-draft-selected',
        'html[data-resolved-theme="light"] .inbound-mode-route',
        'html[data-resolved-theme="light"] .inbound-field-group',
        'html[data-resolved-theme="light"] .rc20-awg-shell .topbar h1',
        'html[data-resolved-theme="light"] .rc20-awg-shell .section-tabs a.active',
    ):
        assert marker in css
    assert "--bg: #edf1f2" in css
    assert "--panel: #ffffff" in css
    assert "#fff6e5" in css


def test_rc44_release_notes_remain_available():
    release = (ROOT / "RELEASE-NOTES-RC44.md").read_text(encoding="utf-8")
    assert "REALITY · без сертификата" in release
    assert "TLS · нужен сертификат" in release
    assert "Светлая тема" in release
