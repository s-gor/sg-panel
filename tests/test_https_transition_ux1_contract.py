from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_page() -> str:
    return (ROOT / "xpanel/templates/panel_access_job.html").read_text(
        encoding="utf-8"
    )


def test_https_transition_shows_completion_after_success_status():
    page = read_page()

    success_block = page.split("if (data.status === 'success')", 1)[1].split(
        "if (data.status === 'failed')", 1
    )[0]
    assert "showHttpsReady();" in success_block
    assert "Соединение защищено, панель переведена на HTTPS." in page
    assert "Открыть панель по HTTPS" in page


def test_connection_loss_uses_real_https_probe_before_showing_button():
    page = read_page()

    assert "const httpsProbeUrl" in page
    assert "async function probeHttpsReady()" in page
    assert "mode: 'no-cors'" in page
    assert "credentials: 'omit'" in page
    assert (
        "switchingStarted && consecutiveFailures >= 2 && await probeHttpsReady()"
        in page
    )
    assert "Проверяю новый HTTPS-адрес" in page
    assert "Кнопка появится" in page


def test_https_transition_never_forces_browser_navigation():
    page = read_page()

    assert "window.location.replace" not in page
    assert "window.location.assign" not in page
    assert "panel_access_switched" not in page
    assert "targetLoginUrl" not in page
    assert "redirectScheduled" not in page


def test_https_failure_still_hides_the_https_button():
    page = read_page()

    failed = page.split("if (data.status === 'failed')", 1)[1].split(
        "} catch (error)", 1
    )[0]
    assert "targetLink.hidden = true" in failed
    assert "HTTPS не включён. Предыдущий доступ восстановлен." in page
