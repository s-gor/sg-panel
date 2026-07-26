from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_rc57_version_and_ui_revision_are_consistent():
    assert '__version__ = "0.10.0-rc70"' in read("xpanel/__init__.py")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_UI_REVISION="sg070"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("deploy/ec2-first-install.sh")
    assert "sg070" in read("xpanel/templates/base.html")
    assert "sg070" in read("xpanel/templates/login.html")


def test_help_has_complete_warp_setup_and_verification_guide():
    help_page = read("xpanel/templates/help.html")
    required = [
        'id="routing-warp"',
        "Создать и проверить WARP Outbound",
        "Российские сайты и IP",
        "geosite:category-ru",
        "geoip:ru",
        "WARP test — ifconfig.me",
        "domain:ifconfig.me",
        "2ip.ru",
        "публичного IP EC2",
        "логическим AND",
    ]
    for text in required:
        assert text in help_page


def test_routing_page_has_compact_expandable_warp_guide():
    routing = read("xpanel/templates/routing.html")
    assert 'class="warp-guide"' in routing
    assert "Как настроить и проверить WARP" in routing
    assert "domain:ifconfig.me" in routing
    assert "Открыть полную инструкцию" in routing
    assert "#routing-warp" in routing


def test_outbounds_links_to_full_warp_guide():
    outbounds = read("xpanel/templates/outbounds.html")
    assert "Полная инструкция" in outbounds
    assert "#routing-warp" in outbounds


def test_markdown_warp_guide_contains_control_and_real_checks():
    guide = read("docs/WARP.md")
    assert "Подробная проверка выборочной маршрутизации" in guide
    assert "WARP test — ifconfig.me" in guide
    assert "domain:ifconfig.me" in guide
    assert "2ip.ru" in guide
    assert "обычный IP-checker показывает EC2" in guide


def test_release_notes_limit_scope_to_documentation():
    notes = read("RELEASE-NOTES-RC57.md")
    assert "Логика WARP Routing из RC56 не изменена" in notes
    assert "SG Client не изменяется" in notes
    assert "Cluster не изменяются" in notes
