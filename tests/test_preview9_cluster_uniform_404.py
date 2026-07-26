from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_cluster_uses_uniform_wide_server_cards():
    template = read("xpanel/templates/nodes.html")
    css = read("xpanel/static/app.css")
    assert "compact-node-row state-{{ node.effective_state }}" in template
    assert "compact-node-row state-{{ node.effective_state }} {{ 'controller'" not in template
    assert ".compact-node-list" in css
    assert "grid-template-columns:1fr" in css
    assert "border-left:1px solid var(--line-soft)" in css
    assert "border-left:3px solid #43d99a" not in css


def test_placeholder_returns_404_for_unknown_paths():
    files = [
        read("deploy/configure-http.sh"),
        read("deploy/configure-https.sh"),
        read("xpanel/service.py"),
    ]
    for text in files:
        assert "location = /index.html" in text
        assert "try_files /index.html =404" in text
        assert "location / {\n        return 404;" in text
        assert "try_files $uri $uri/ /index.html" not in text


def test_upgrade_applies_404_migration_to_existing_installations():
    upgrade = read("install-or-upgrade.sh")
    migration = read("deploy/migrate-placeholder-404.sh")
    assert 'migrate-placeholder-404.sh' in upgrade
    assert 'Исправление публичной заглушки: неизвестные пути → 404' in upgrade
    assert '/etc/nginx/sites-available/sg-panel' in migration
    assert '/etc/nginx/sites-available/sg-panel-reality-placeholder' in migration
    assert "nginx -t" in migration
    assert "systemctl reload nginx" in migration
    assert "restore_all" in migration
