from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_outbounds_is_plain_language_and_warp_json_is_additional() -> None:
    html = read("xpanel/templates/outbounds.html")

    assert "{% block heading %}Outbounds{% endblock %}" in html
    assert "System outbounds" in html
    assert "WARP Outbound" in html
    assert "Custom outbounds" in html
    assert "Прямой выход в интернет." in html
    assert "Отбрасывает трафик, совпавший с блокирующим правилом." in html
    assert "WARP JSON" in html
    assert "Открыть Routing" in html


def test_dns_main_is_simple_and_technical_sections_are_in_expert() -> None:
    html = read("xpanel/templates/dns.html")

    assert "dns-rebuild-page" in html
    assert "dnsr-top" in html
    assert "dnsr-current" in html
    assert "dnsr-add" in html
    assert "dnsr-list-card" in html
    assert "Expert DNS" in html
    assert "Открыть Expert DNS" in html

    # Old layered DNS geometry must not return.
    assert "dns-simple-page" not in html
    assert "dns-current-card" not in html
    assert "dns-basic-add-card" not in html
    assert "dns-simple-servers" not in html

    # Expert-only editors are not exposed as normal main-page fields.
    assert 'name="domains"' not in html
    assert 'name="expected_ips"' not in html
    assert 'name="skipFallback"' not in html


def test_dns_rebuild_keeps_real_backend_forms_and_validation() -> None:
    html = read("xpanel/templates/dns.html")

    for marker in (
        "dns_settings_save",
        "dns_server_add",
        "dns_server_edit_page",
        "dns_server_toggle",
        "dns_server_delete",
        'name="csrf_token"',
        'name="enabled"',
        'name="name"',
        'name="priority"',
        'name="address"',
        "data-validated-form",
        "data-validation-compact",
        'class="ui-toggle-row dnsr-toggle-row"',
    ):
        assert marker in html

    assert ">Применить</button>" in html
    assert "Проверить конфигурацию" not in html  # injected by shared validated-form JS


def test_dns_rebuild_has_dedicated_scoped_styles() -> None:
    css = read("xpanel/static/dns-rebuild-001.css")

    assert "SG-Panel DNS Rebuild 001" in css
    assert "body.dns-rebuild-page" in css
    assert ".dnsr-card" in css
    assert ".dnsr-list-card" in css
    assert 'input[type="checkbox"]:checked + .switch' in css
    assert ".validation-gate" in css
    assert "background: transparent !important;" in css
