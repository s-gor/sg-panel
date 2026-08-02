from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def page() -> str:
    return (ROOT / "xpanel/templates/panel_access_job.html").read_text(
        encoding="utf-8"
    )


def test_completion_stays_visible_and_has_direct_button():
    text = page()
    assert "Соединение защищено, панель переведена на HTTPS." in text
    assert "Открыть панель по HTTPS" in text
    assert "targetLink.href = targetUrl" in text
    assert "targetLink.hidden = false" in text


def test_page_never_forces_navigation():
    text = page()
    assert "window.location.replace" not in text
    assert "window.location.assign" not in text
    assert "panel_access_switched" not in text
    assert "targetLoginUrl" not in text
    assert "redirectScheduled" not in text


def test_lost_http_connection_probes_real_https_before_ready():
    text = page()
    assert "[SG-Panel Access] Переключаю панель на HTTPS" in text
    assert "const httpsProbeUrl" in text
    assert "async function probeHttpsReady()" in text
    assert "await probeHttpsReady()" in text
    assert "switchingStarted && consecutiveFailures >= 2" in text
    assert "Проверяю новый HTTPS-адрес" in text
    assert "targetLink.hidden = true" in text


def test_no_server_hotfix_is_published():
    assert not (ROOT / "SG-PANEL-UI23-CAP6-HTTPS-TRANSITION-UX1.run").exists()
    assert not (
        ROOT / "SG-PANEL-UI23-CAP6-HTTPS-TRANSITION-UX1.run.sha256"
    ).exists()
