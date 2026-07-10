from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(text: str) -> str:
    return "".join(text.split())


def test_hotfix11_targets_real_routing_table_action_column():
    template = (ROOT / "xpanel/templates/routing.html").read_text(encoding="utf-8")
    css = compact((ROOT / "xpanel/static/app.css").read_text(encoding="utf-8"))
    assert 'class="routing-rule-actions-heading"' in template
    assert 'class="routing-rule-actions-cell"' in template
    assert 'row-actions routing-rule-actions' in template
    assert '.routing-rules-card.routing-rule-actions-heading,.routing-rules-card.routing-rule-actions-cell{padding-right:32px;}' in css
    assert '.routing-rules-card.routing-rule-actions{justify-content:flex-end;}' in css


def test_hotfix11_cache_and_installer_revision():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    installer = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in installer
