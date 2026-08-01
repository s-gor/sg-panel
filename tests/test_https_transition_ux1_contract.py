from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_https_transition_shows_clear_completion_message_and_button():
    page = (ROOT / "xpanel/templates/panel_access_job.html").read_text(encoding="utf-8")

    assert "Соединение защищено, панель переведена на HTTPS." in page
    assert "Если страница не открылась автоматически, обновите её." in page
    assert "Открыть панель по HTTPS" in page
    assert "targetLink.href = targetLoginUrl()" in page
    assert "window.location.replace(targetLoginUrl())" in page


def test_https_transition_fallback_requires_real_switch_marker():
    page = (ROOT / "xpanel/templates/panel_access_job.html").read_text(encoding="utf-8")

    marker = "[SG-Panel Access] Переключаю панель на HTTPS"
    assert marker in page
    assert "switchingStarted && consecutiveFailures >= 2" in page
    assert "showHttpsReady('Соединение защищено')" in page
    assert "hadSuccessfulPoll || consecutiveFailures >= 3" not in page


def test_https_failure_still_hides_the_https_button():
    page = (ROOT / "xpanel/templates/panel_access_job.html").read_text(encoding="utf-8")

    failed = page.split("if (data.status === 'failed')", 1)[1].split("} catch (error)", 1)[0]
    assert "targetLink.hidden = true" in failed
    assert "HTTPS не включён. Предыдущий доступ восстановлен." in page
