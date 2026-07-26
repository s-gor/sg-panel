from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "xpanel" / "templates" / "base.html"


def test_final_css_assets_have_new_cache_revision():
    source = BASE.read_text(encoding="utf-8")
    assert "app.css') }}?v={{ xpanel_version }}-sg070-preview9-fix35-full-recovery" in source
    assert "cascade-rc6.css') }}?v={{ xpanel_version }}-sg070-preview9-fix35-full-recovery" in source
    assert "rc6-typography.css') }}?v={{ xpanel_version }}-sg070-preview9-fix35-full-recovery" in source


def test_intermediate_cache_revisions_are_not_active():
    source = BASE.read_text(encoding="utf-8")
    assert "sg070-preview9-type1" not in source
    assert 'sg070-preview9">' not in source
