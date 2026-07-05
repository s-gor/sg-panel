from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_inbound_page_uses_balanced_summary_and_active_profile_banner() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "inbound-summary-grid" in html
    assert "Пользователи и ID" in html
    assert "inbound-active-banner" in html
    assert "inbound-selected-profile-name" in html
    assert "Ниже показаны только относящиеся к ней параметры" in html
    assert ".inbound-summary-grid" in css
    assert ".inbound-active-banner" in css


def test_inbound_profile_cards_are_grouped_by_protection_family_on_wide_screen() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "inbound-profile-families" in html
    assert "profile-card-status-row" in html
    assert "Активный профиль" in html
    assert "profile-family-grid-2" in html
    assert "profile-family-grid-3" in html
    assert "REALITY · без сертификата" in html
    assert "TLS · нужен сертификат" in html
    assert "UUID и Hysteria auth не удаляются" in html
