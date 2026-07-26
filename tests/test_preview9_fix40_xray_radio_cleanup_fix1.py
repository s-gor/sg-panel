from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SETTINGS = (ROOT / "xpanel" / "templates" / "settings.html").read_text(encoding="utf-8")


def test_xray_server_resets_all_radio_controls_to_compact_circles():
    selector = '.sg-ao-page input[type="radio"]'
    assert selector in SETTINGS
    assert 'appearance:none!important' in SETTINGS
    assert 'width:16px!important' in SETTINGS
    assert 'height:16px!important' in SETTINGS
    assert 'min-height:16px!important' in SETTINGS
    assert 'max-height:16px!important' in SETTINGS
    assert 'padding:0!important' in SETTINGS
    assert 'border-radius:50%!important' in SETTINGS
    assert 'box-shadow:none!important' in SETTINGS


def test_xray_server_radio_controls_keep_checked_and_keyboard_focus_states():
    assert '.sg-ao-page input[type="radio"]::after' in SETTINGS
    assert '.sg-ao-page input[type="radio"]:checked::after{transform:scale(1)}' in SETTINGS
    assert '.sg-ao-page input[type="radio"]:focus-visible' in SETTINGS
    assert 'outline-offset:3px' in SETTINGS


def test_xray_server_radio_fix_is_page_scoped_and_keeps_both_feature_groups():
    assert 'name="xmux_mode"' in SETTINGS
    assert 'name="hysteria_instance_1_obfs_mode"' in SETTINGS
    assert 'data-xmux-card' in SETTINGS
    assert 'data-hysteria-salamander-card' in SETTINGS
