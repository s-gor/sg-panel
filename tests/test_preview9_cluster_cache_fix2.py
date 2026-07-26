from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cluster_css_cache_revision_changed():
    base = (ROOT / 'xpanel/templates/base.html').read_text(encoding='utf-8')
    assert 'sg070-preview9-fix35-full-recovery' in base
    assert 'sg070-preview9-cluster404-fix2' not in base


def test_cluster_left_status_stripe_is_disabled():
    css = (ROOT / 'xpanel/static/app.css').read_text(encoding='utf-8')
    assert 'SG-PANEL CLUSTER CACHE FIX 2' in css
    assert 'border-left:1px solid var(--line-soft) !important' in css
    assert '.cluster-stage4-server-card::before' in css
    assert 'content:none !important' in css
    assert 'width:100%' in css
