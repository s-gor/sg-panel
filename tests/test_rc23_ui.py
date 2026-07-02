from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_inbound_page_uses_balanced_summary_and_active_profile_banner() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "inbound-summary-grid" in html
    assert "Пользователи и ID" in html
    assert "inbound-active-banner" in html
    assert "inbound-selected-profile-name" in html
    assert "Ниже будут показаны только те параметры" in html
    assert ".inbound-summary-grid" in css
    assert ".inbound-active-banner" in css


def test_inbound_profile_cards_are_compact_and_four_column_on_wide_screen() -> None:
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert "inbound-profile-grid-4" in html
    assert "profile-card-status-row" in html
    assert "Активный профиль" in html
    assert "repeat(4, minmax(0, 1fr))" in css
    assert "UUID и Hysteria auth не удаляются" in html
