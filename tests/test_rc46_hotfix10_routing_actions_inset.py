from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compact(value: str) -> str:
    return "".join(value.split())


def test_routing_action_group_moves_inward_without_changing_card_geometry():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = compact(css)

    assert ".routing-rules-card>.ui-card-heading.ui-heading-actions{margin-inline-end:10px;gap:7px;}" in packed
    assert ".routing-rules-card{width:" not in css
    assert ".routing-rules-card{max-width:" not in css


def test_hotfix10_cache_and_installer_revision():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    script = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")

    assert "sg070" in base
    assert "sg070" in login
    assert 'EXPECTED_UI_REVISION="sg070"' in script
    assert "SG-Panel RC70" in script
