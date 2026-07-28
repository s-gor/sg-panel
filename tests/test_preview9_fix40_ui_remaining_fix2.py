from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_outbounds_system_names_are_plain_and_technical_values_are_additional() -> None:
    html = read("xpanel/templates/outbounds.html")

    assert "'direct': {'title': 'direct', 'description': 'Прямой выход в интернет.'}" in html
    assert "'blocked': {'title': 'blocked', 'description': 'Отбрасывает трафик, совпавший с блокирующим правилом.'}" in html
    assert "<strong>{{ system_label['title'] }}</strong>" in html
    assert "<code>{{ outbound.protocol }}</code>" in html
    assert "Системный выход" in html
    assert "По умолчанию" in html

    # Rejected/old wording must not become the primary system name again.
    assert "Direct — прямой доступ" not in html
    assert "Block — блокировка" not in html


def test_outbounds_warp_title_is_compact() -> None:
    css = read("xpanel/static/fix40-outbounds-gateway-style2.css")
    html = read("xpanel/templates/outbounds.html")

    assert "WARP Outbound" in html
    assert "body.outbounds-gateway-style2 .ob-gw-warp-head h2" in css
    assert "font-size: 24px !important;" in css
    assert "font-size: 22px !important;" in css


def test_new_ui_styles_are_loaded_from_base() -> None:
    base = read("xpanel/templates/base.html")

    assert "dns-rebuild-001.css" in base
    assert "fix40-outbounds-gateway-style2.css" in base
    assert base.count("dns-rebuild-001.css") == 1
    assert base.count("fix40-outbounds-gateway-style2.css") == 1
