from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_reality_key_regeneration_uses_in_page_confirmation():
    settings = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    assert "data-reality-key-confirm" in settings
    assert "reality-key-inline-confirm-body" in settings
    assert "data-reality-key-cancel" in settings
    assert "Да, сгенерировать" in settings
    assert "settings_generate_reality" in settings
    assert "Сгенерировать новые Reality-ключи?" not in settings
    assert 'onsubmit="return confirm(' not in settings


def test_client_copy_buttons_reset_and_can_be_used_repeatedly():
    link = (ROOT / "xpanel/templates/link.html").read_text(encoding="utf-8")
    subscriptions = (ROOT / "xpanel/templates/subscriptions.html").read_text(encoding="utf-8")
    for template in (link, subscriptions):
        assert "dataset.copyLabel" in template
        assert "_copyResetTimer" in template
        assert "window.clearTimeout" in template
        assert "window.setTimeout" in template
        assert "1800" in template
    assert "showCopyFeedback(button, 'Скопировано')" in link
    assert "showSubscriptionCopyFeedback(button, 'Скопировано')" in subscriptions


def test_hotfix2_styles_and_cache_key_are_present():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    assert ".reality-key-inline-confirm-body" in css
    assert ".reality-key-inline-confirm > summary::-webkit-details-marker" in css
    for name in ("base.html", "login.html"):
        template = (ROOT / "xpanel/templates" / name).read_text(encoding="utf-8")
        assert "?v={{ xpanel_version }}" in template
