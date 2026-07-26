from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def test_release_label_and_status_summary_removed():
    init = text("xpanel/__init__.py")
    diagnostics = text("xpanel/templates/diagnostics.html")
    base = text("xpanel/templates/base.html")
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in init
    assert 'ui-diagnostics-summary diagnostics-core-grid' not in diagnostics
    assert '<article class="ui-status-card"><span>Xray</span>' not in diagnostics
    assert '<article class="ui-status-card"><span>Nginx</span>' not in diagnostics
    assert '<article class="ui-status-card"><span>SG-Panel</span>' not in diagnostics
    assert '<article class="ui-status-card"><span>config.json</span>' not in diagnostics
    assert 'instance-settings-card' in diagnostics
    assert 'diagnostics-controls-card' in diagnostics
    assert 'diagnostics-facts-card' not in diagnostics
    assert 'fix40-node-simple-hotfix18.css' in base

def test_installers_expect_hotfix10():
    for path in ("install-or-upgrade.sh", "install.sh", "deploy/ec2-first-install.sh"):
        body = text(path)
        assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in body
    assert 'LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"' in text("install.sh")
