from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def page() -> str:
    return (ROOT / "xpanel/templates/panel_access_job.html").read_text(
        encoding="utf-8"
    )


def test_https_transition_matches_sg_gateway_operation_terminal():
    text = page()

    assert "function continueTerminalOverHttps()" in text
    assert "Nginx включил HTTPS" in text
    assert "Продолжаю этот же терминал по защищённому адресу" in text
    assert "window.location.replace(secureJobUrl.toString())" in text
    assert "showHttpsReady();" in text


def test_finished_page_keeps_direct_button():
    text = page()

    assert "Соединение защищено, панель переведена на HTTPS." in text
    assert "Открыть панель по HTTPS" in text
    assert "targetLink.href = targetUrl" in text
    assert "targetLink.hidden = false" in text
