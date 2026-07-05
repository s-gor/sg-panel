from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_soft_light_theme_and_cache_bust_are_present() -> None:
    css = (ROOT / "xpanel" / "static" / "app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel" / "templates" / "base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel" / "templates" / "login.html").read_text(encoding="utf-8")
    assert "--bg: #edf1f2" in css
    assert "--panel: #ffffff" in css
    assert "--accent: #157c5d" in css
    assert "?v={{ xpanel_version }}" in base
    assert "?v={{ xpanel_version }}" in login
    assert 'data-theme-choice="light"' in base
    assert 'data-login-theme="light"' in login


def test_profile_cards_show_one_short_useful_description() -> None:
    html = (ROOT / "xpanel" / "templates" / "settings.html").read_text(encoding="utf-8")
    assert "Прямое подключение к Xray. До трёх точек; XTLS Vision выбирается внутри профиля." in html
    assert "Nginx принимает TLS. До трёх XHTTP Path на одном публичном TCP-порту." in html
    assert "XHTTP напрямую в Xray с защитой REALITY. Один публичный Path." in html
    assert "Прямой QUIC/UDP в Xray. До трёх независимых UDP-портов." in html
    assert "Обе семьи работают одновременно и используют общий TLS-сертификат." in html
    for removed in ("Рекомендуется</b>", "Основной TLS</b>", "Расширенный</b>", "UDP / QUIC</b>", "<b>TCP + UDP</b>"):
        assert removed not in html
