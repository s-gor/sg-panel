from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
LOGIN = (ROOT / "xpanel/templates/login.html").read_text(encoding="utf-8")
JADE = (ROOT / "xpanel/static/luxury-jade-depth.css").read_text(encoding="utf-8")


def test_luxury_jade_theme_is_exposed_as_the_only_light_choice():
    assert "SG Luxury Jade Depth" in BASE
    assert "Luxury Jade" in BASE
    assert "Тема SG Luxury Jade Depth" in LOGIN
    assert 'data-theme-choice="light"' in BASE
    assert 'data-login-theme="light"' in LOGIN


def test_luxury_jade_reference_palette_and_depth_are_present():
    for token in (
        "--jade-page: #E5ECE7",
        "--jade-ivory-top: #FEFCF7",
        "--jade-stone-top: #F1EADE",
        "--jade-accent: #456F5C",
        "--jade-champagne: #B88A45",
        "--jade-text: #29312C",
        "--jade-button-shadow: 0 2px 12px rgba(43, 52, 46, .20)",
        "--jade-card-shadow: 0 4px 18px rgba(43, 52, 46, .17)",
        "radial-gradient(circle at 78% -8%",
        "var(--jade-top-light), var(--jade-button-shadow)",
        "var(--jade-top-light), var(--jade-card-shadow)",
    ):
        assert token in JADE


def test_luxury_jade_stylesheet_is_light_only():
    # No dark-theme selector or unscoped body/component rule is allowed here.
    assert 'data-theme="dark"' not in JADE
    assert 'data-resolved-theme="dark"' not in JADE
    assert "Preview 9 graphite remains controlled by the original stylesheets" in JADE


def test_luxury_jade_stylesheet_is_loaded_last_on_main_and_login():
    assert "luxury-jade-depth.css" in BASE
    assert BASE.index("luxury-jade-depth.css") > BASE.index("rc6-typography.css")
    assert "luxury-jade-depth.css" in LOGIN
    assert LOGIN.index("luxury-jade-depth.css") > LOGIN.index("app.css")


def test_compact_system_page_has_complete_light_overrides():
    dashboard = (ROOT / "xpanel/templates/dashboard.html").read_text(encoding="utf-8")
    for selector in (
        ".compact-health-strip",
        ".compact-memory-dial",
        ".compact-memory-dial::before",
        ".compact-memory-legend > div",
        ".compact-fact-row > div",
        ".compact-resource-card",
        ".disk-ring",
        ".service-facts a",
    ):
        assert selector in JADE
    for token in (
        "--memory-ring-light: conic-gradient",
        'class="memory-segment-{{ segment.key }}"',
        "var(--lux-memory-panel)",
        "var(--lux-memory-cache)",
        "var(--lux-memory-free)",
    ):
        assert token in dashboard or token in JADE


def test_late_preview_graphite_islands_are_overridden_only_in_light_css():
    for selector in (
        ".compact-summary-bar",
        ".compact-clients-table-card",
        ".diagnostic-log-panel",
        ".ob-system-panel",
        ".profile-card-body",
        ".clients-awg-inspector",
        ".client-deployment-panel",
        ".cluster-stage4-server-card",
        ".hysteria-studio-panel",
        ".cascade-simple-hero",
        ".update-progress-card",
    ):
        assert selector in JADE
    assert "complete light-surface correction (FIX 1)" in JADE


def test_global_preview_stylesheets_are_byte_identical_to_fix33_base():
    import hashlib

    expected = {
        "app.css": "5aedcf1f0fcbd8db4e47b146cb6801eb4cf00f9503c703ce4b903d8af2b89fb8",
        "rc6-typography.css": "d3fbef64f8b0b58143f7aaf366f04fb7340943206ce8fe344aa646f14d0380c9",
        "cascade-rc6.css": "ee307cba4b8e4000d926a9863b89f608bd9e6a6559dbe1252f307e0b795ae536",
    }
    for name, digest in expected.items():
        payload = (ROOT / "xpanel/static" / name).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == digest


def test_current_cache_revisions_are_used():
    assert BASE.count("sg070-preview9-fix35-full-recovery") == 8
    assert "sg070-preview9-routing-server-fix34" not in BASE
    assert "sg070-preview9-luxury-jade-depth-fix1" in LOGIN


def test_fix1_final_material_pass_covers_late_component_families():
    for selector in (
        ".backup-technical-grid",
        ".cascade-awg-cluster-form > article",
        ".cascade-awg-disabled-pair > article",
        ".cascade-awg-external-grid > article",
        ".cascade-awg-active-route > section",
        ".clients-filter-field :is(input,select)",
        ".dashboard-health.is-error",
        ".hysteria-diagnostic-hero.is-error",
    ):
        assert selector in JADE
    assert "background-color: var(--jade-ivory-top) !important" in JADE
    assert "background-image: linear-gradient(180deg, var(--jade-ivory-top) 0%, var(--jade-ivory-bottom) 100%) !important" in JADE
    assert "background-color: var(--jade-stone-top) !important" in JADE
    assert "background-image: linear-gradient(180deg, var(--jade-stone-top) 0%, var(--jade-stone-bottom) 100%) !important" in JADE
