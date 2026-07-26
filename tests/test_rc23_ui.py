from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_inbound_page_omits_redundant_summary_and_active_profile_banner() -> None:
    for template_name in ("settings.html", "expert_inbound.html"):
        html = (ROOT / "xpanel/templates" / template_name).read_text(encoding="utf-8")
        assert 'class="inbound-summary-grid"' not in html
        assert 'class="inbound-active-banner"' not in html
        assert "inbound-selected-profile-name" not in html
        assert "inbound-route-client" not in html
        assert "inbound-profile-families" in html
        assert "inbound-core-settings" in html


def test_inbound_profile_cards_are_grouped_by_protection_family_on_wide_screen() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "inbound-profile-families" in html
    assert "profile-card-status-row" in html
    assert "Работает сейчас" in html
    assert "profile-family-grid-2" in html
    assert "profile-family-grid-4" in html
    assert ".profile-family-grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }" in css
    assert "REALITY · без сертификата" in html
    assert "TLS · нужен сертификат" in html
    assert "Выбор карточки ещё не переключает сервер" in html
