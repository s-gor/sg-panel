from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hotfix18_password_fields_are_one_desktop_row():
    template = (ROOT / "xpanel/templates/security.html").read_text()
    css = (ROOT / "xpanel/static/app.css").read_text()

    assert 'class="ui-field-grid password-grid"' in template
    assert css.count('.security-page .security-password-card .password-grid') >= 2
    assert 'grid-template-columns: repeat(3, minmax(0, 1fr));' in css
    assert '@media (max-width: 1080px)' in css
    assert 'grid-template-columns: 1fr;' in css


def test_hotfix18_button_stays_outside_password_grid():
    template = (ROOT / "xpanel/templates/security.html").read_text()
    grid_start = template.index('<div class="ui-field-grid password-grid">')
    grid_end = template.index('</div>', grid_start)
    button_pos = template.index('>Сменить пароль</button>', grid_end)
    assert button_pos > grid_end


def test_hotfix18_cache_revision_and_installer_guard():
    base = (ROOT / "xpanel/templates/base.html").read_text()
    login = (ROOT / "xpanel/templates/login.html").read_text()
    installer = (ROOT / "install-or-upgrade.sh").read_text()
    css = (ROOT / "xpanel/static/app.css").read_text()

    assert 'sg070' in base
    assert 'sg070' in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
    assert 'SG-Panel RC70' in installer
    assert 'SG-Panel 054' in css
