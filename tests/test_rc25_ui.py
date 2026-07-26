from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "xpanel" / "templates" / "settings.html"
CSS = ROOT / "xpanel" / "static" / "app.css"


def test_active_and_draft_inbound_states_are_distinct() -> None:
    html = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    assert "Работает сейчас" in html
    assert "Выбрано, ещё не применено" in html
    assert "const activeProfile" in html
    assert "is-draft-selected" in html
    assert ".profile-card-active-state" in css
    assert ".profile-card-draft-state" in css


def test_hysteria_settings_appear_immediately_after_common_settings() -> None:
    html = TEMPLATE.read_text(encoding="utf-8")
    core = html.index('class="ui-form-section inbound-core-settings"')
    hysteria = html.index('class="ui-form-section profile-section hysteria-immediate-settings"')
    reality = html.index('data-profile-section="raw_reality xhttp_reality"')
    assert core < hysteria < reality
    assert "Все параметры выбранного UDP/QUIC-профиля находятся здесь" in html
    assert 'name="tls_cert_path"' in html
    assert 'name="hysteria_udp_idle_timeout"' in html
    assert 'name="hysteria_masquerade_type"' in html


def test_hidden_profile_fields_are_disabled_before_submit() -> None:
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "data-exclusive-profile-field" in html
    assert "field.disabled = !visible" in html
    assert "fields.find((item) => !item.disabled)" in html
