from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_geofiles_custom_url_fix1_contract() -> None:
    service = (ROOT / "xpanel/service.py").read_text(encoding="utf-8")
    template = (ROOT / "xpanel/templates/_geofiles_panel_fix39.html").read_text(encoding="utf-8")
    assert "# SG-PANEL GEOFILES CUSTOM URL FIX1" in service
    assert '_SG_GCUF1_ROSCOM_OWNER = "roscomvpn-server-preset"' in service
    assert 'if source != "custom":' in service
    assert 'DELETE FROM routing_rules WHERE managed_by=?' in service
    assert '_sg_gcuf1_restore_roscom_rules(snapshot)' in service
    assert "Только чтение" not in template
