from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_proven_https_webroot_flow_is_restored():
    script = (ROOT / "deploy/configure-panel-access.sh").read_text(encoding="utf-8")

    assert 'certbot certonly' in script
    assert '--webroot -w "$ACME_ROOT"' in script
    assert '--domain "$HOST"' in script
    assert 'Проверяю локальный HTTP-01 Nginx/webroot' not in script
    assert 'sg-panel-local-' not in script
    assert '--resolve "$HOST:80:127.0.0.1"' not in script
    assert 'Временно отключаю прежний HTTP-сайт панели на TCP 80' not in script


def test_transactional_https_rollback_remains_present():
    script = (ROOT / "deploy/configure-panel-access.sh").read_text(encoding="utf-8")

    assert 'log "HTTPS не настроен, восстанавливаю предыдущий доступ"' in script
    assert 'trap rollback ERR INT TERM' in script
    assert 'bash /opt/xpanel-mvp/deploy/configure-https.sh' in script
