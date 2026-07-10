from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(text: str) -> str:
    return "".join(text.split())


def test_hotfix15_reality_labels_and_action_inset():
    html = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    css = compact((ROOT / "xpanel/static/app.css").read_text(encoding="utf-8"))

    assert "Адрес прослушивания" in html
    assert "Публичный порт" in html
    assert "<span>Тег</span>" in html
    assert "Показать закрытый ключ" in html
    assert "Скрыть закрытый ключ" in html
    assert "Закрытый ключ REALITY" in html
    assert "Открытый ключ REALITY / пароль" in html
    assert "Заменяет закрытый ключ, открытый ключ и Short ID" in html
    assert 'class="reality-key-action-row"' in html
    assert "is-last-visible-profile-section" in html

    assert ".inbound-settings-form>.ui-form-section.is-last-visible-profile-section{padding-bottom:4px;border-bottom:0;}" in css
    assert ".inbound-settings-form>.validation-gate{margin-top:10px;}" in css
    assert ".inbound-reality-actions.reality-key-action-row{min-width:0;padding:020px18px;}" in css
    assert ".reality-instance-fieldslabel>span:first-child{min-height:34px;display:flex;align-items:flex-end;}" in css


def test_hotfix15_cache_revision_and_installer_guard():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "RC46 Preview 3 Hotfix 15" in css
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert 'grep -q "SG-Panel RC70 — Latte light theme preview"' in installer
    assert "GUI не подключает CSS SG-Panel RC70" in installer
