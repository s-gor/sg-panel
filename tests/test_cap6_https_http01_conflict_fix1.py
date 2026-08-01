from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_https_http01_temporarily_disables_conflicting_http_site():
    script = (ROOT / "deploy/configure-panel-access.sh").read_text(encoding="utf-8")

    backup = 'backup_path /etc/nginx/sites-enabled/sg-panel nginx-link'
    disable = 'rm -f /etc/nginx/sites-enabled/sg-panel /etc/nginx/sites-enabled/default'
    acme_link = 'ln -sfn /etc/nginx/sites-available/sg-panel-acme /etc/nginx/sites-enabled/sg-panel-acme'
    restore = 'restore_path "$BACKUP_DIR/nginx-link" /etc/nginx/sites-enabled/sg-panel'

    assert backup in script
    assert disable in script
    assert acme_link in script
    assert restore in script
    assert script.index(backup) < script.index(disable) < script.index(acme_link)
    assert script.index(restore) < script.index('log "Готовлю HTTP-01 на TCP 80"')


def test_local_http01_probe_never_uses_environment_proxy():
    script = (ROOT / "deploy/configure-panel-access.sh").read_text(encoding="utf-8")
    assert "curl --noproxy '*' -fsS --max-time 5" in script
    assert '--resolve "$HOST:80:127.0.0.1"' in script


def test_https_success_recreates_final_panel_site():
    script = (ROOT / "deploy/configure-panel-access.sh").read_text(encoding="utf-8")
    assert 'rm -f /etc/nginx/sites-enabled/sg-panel-acme' in script
    assert 'bash /opt/xpanel-mvp/deploy/configure-https.sh' in script
    assert script.index('rm -f /etc/nginx/sites-enabled/sg-panel-acme') < script.index(
        'bash /opt/xpanel-mvp/deploy/configure-https.sh'
    )
