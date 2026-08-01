from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_page() -> str:
    return (ROOT / "xpanel/templates/panel_access_job.html").read_text(encoding="utf-8")


def test_https_transition_shows_completion_message_and_direct_button():
    page = read_page()
    assert "Соединение защищено, панель переведена на HTTPS." in page
    assert "Если страница не открылась автоматически, обновите её." in page
    assert "Открыть панель по HTTPS" in page
    assert "targetLink.href = targetUrl" in page
    assert "targetLink.hidden = false" in page


def test_https_transition_never_forces_browser_navigation():
    page = read_page()
    assert "window.location.replace" not in page
    assert "window.location.assign" not in page
    assert "panel_access_switched" not in page
    assert "targetLoginUrl" not in page
    assert "setTimeout(() => window.location" not in page


def test_https_transition_fallback_requires_real_switch_marker():
    page = read_page()
    marker = "[SG-Panel Access] Переключаю панель на HTTPS"
    assert marker in page
    assert "switchingStarted && consecutiveFailures >= 2" in page
    assert "showHttpsReady();" in page
    assert "hadSuccessfulPoll || consecutiveFailures >= 3" not in page


def test_https_failure_still_hides_the_https_button():
    page = read_page()
    failed = page.split("if (data.status === 'failed')", 1)[1].split("} catch (error)", 1)[0]
    assert "targetLink.hidden = true" in failed
    assert "HTTPS не включён. Предыдущий доступ восстановлен." in page
