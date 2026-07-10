from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(text: str) -> str:
    return "".join(text.split())


def test_hotfix12_adds_explicit_client_navigation_and_create_again_flow():
    link = (ROOT / "xpanel/templates/link.html").read_text(encoding="utf-8")
    users = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    web = (ROOT / "xpanel/web.py").read_text(encoding="utf-8")

    assert "К списку клиентов" in link
    assert "Создать ещё клиента" in link
    assert "url_for('users_page', client=user.id)" in link
    assert "url_for('users_page', create=1)" in link
    assert 'open_create=request.args.get("create", "").strip() == "1"' in web
    assert "if (dialog && !dialog.open) dialog.showModal()" in users


def test_hotfix12_saved_inactive_links_use_amber_brown_state_not_green():
    template = (ROOT / "xpanel/templates/link.html").read_text(encoding="utf-8")
    css = compact((ROOT / "xpanel/static/app.css").read_text(encoding="utf-8"))

    assert "else 'saved'" in template
    assert "secondary saved-link-copy" in template
    assert 'class="pill saved"' in template
    assert ".pill.saved{color:#E9C46A;" in css
    assert ".saved-link-inactive.panel-card{border-color:rgba(233,196,106,.34);" in css
    assert ".saved-link-inactive.saved-link-warning{border-color:rgba(233,196,106,.46);background:#3A321A;" in css
    assert 'html[data-resolved-theme="light"].saved-link-inactive.panel-card{' in css


def test_hotfix12_keeps_prior_clients_and_routing_fixes_and_bumps_assets():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "clients-network-scale" in css
    assert "routing-rule-actions-cell" in css
    assert "RC46 Preview 3 Hotfix 12" in css
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
