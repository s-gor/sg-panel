from pathlib import Path
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]

def text(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def test_ui17_release_and_css_contract():
    assert '__release_label__ = "Preview 9 · FIX40 · UI23"' in text('xpanel/__init__.py')
    base = text('xpanel/templates/base.html')
    Environment().parse(base)
    assert base.count('fix40-diagnostics-log-polish-hotfix17.css') == 1
    css = text('xpanel/static/fix40-diagnostics-log-polish-hotfix17.css')
    assert 'margin-bottom: 0 !important' in css
    assert 'padding: 10px 12px 12px !important' in css
    assert 'padding: 13px 18px !important' in css

def test_ui17_keeps_raw_service_states():
    template = text('xpanel/templates/diagnostics.html')
    Environment().parse(template)
    assert "{{ diagnostics.xray_service }}" in template
    assert "{{ diagnostics.nginx_service }}" in template
    assert "{{ diagnostics.panel_service }}" in template
    assert "'Активен' if diagnostics." not in template

def test_fresh_install_identity_is_ui17():
    assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in text('install.sh')
    assert 'LOCAL_ARCHIVE_NAME="SG-PANEL-FIX40-FULL-UI23-SOURCE.zip"' in text('install.sh')
    assert 'EXPECTED_RELEASE_LABEL="Preview 9 · FIX40 · UI23"' in text('deploy/ec2-first-install.sh')
