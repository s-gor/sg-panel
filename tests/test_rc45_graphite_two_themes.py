from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_theme_switch_exposes_only_graphite_and_light():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    for html in (base, login):
        assert "graphite" in html
        assert "light" in html
        assert 'data-theme-choice="system"' not in html
        assert 'data-theme-choice="dark"' not in html
        assert 'data-login-theme="system"' not in html
        assert 'data-login-theme="dark"' not in html
        assert "prefers-color-scheme" not in html
    assert 'data-theme-choice="graphite"' in base
    assert 'data-theme-choice="light"' in base
    assert 'data-login-theme="graphite"' in login
    assert 'data-login-theme="light"' in login


def test_old_theme_values_migrate_to_graphite_and_light_is_preserved():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    login = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
    for html in (base, login):
        assert "stored === 'light' ? 'light' : 'graphite'" in html
        assert "saved === 'light' ? 'light' : 'dark'" in html
        assert "localStorage.setItem('sg-panel-theme', saved)" in html


def test_graphite_palette_matches_sg_client_values():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    for marker in (
        '--sg-background: #0B121C',
        '--sg-header: #0E1723',
        '--sg-sidebar: #101B29',
        '--sg-surface: #111D2B',
        '--sg-surface-soft: #0F1A27',
        '--sg-surface-raised: #162438',
        '--sg-input: #0E1926',
        '--sg-border: #24364B',
        '--sg-border-strong: #34506B',
        '--sg-text: #F4F7FA',
        '--sg-text-muted: #8A9AAF',
        '--sg-accent: #35D69A',
        '--sg-accent-soft: #14372D',
        '--sg-accent-border: #2A7A5C',
        '--sg-hover: #17263A',
        '--sg-pressed: #20324A',
        '--sg-selected: #182A3E',
    ):
        assert marker in css
    assert 'html[data-theme="graphite"]' in css
    assert 'background: #101B29' in css
    assert 'background: #0E1926' in css


def test_rc45_version_installers_and_release_notes_are_consistent():
    assert '__version__ = "0.10.0-rc70"' in (ROOT / "xpanel/__init__.py").read_text(encoding="utf-8")
    for relative in ("deploy/ec2-first-install.sh", "install-or-upgrade.sh"):
        assert 'EXPECTED_VERSION="0.10.0-rc70"' in (ROOT / relative).read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC45.md").read_text(encoding="utf-8")
    assert "Графит" in release
    assert "Светлая" in release
    assert "Системная тема удалена" in release
