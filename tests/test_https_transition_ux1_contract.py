from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def page() -> str:
    return (ROOT / "xpanel/templates/panel_access_job.html").read_text(
        encoding="utf-8"
    )


def test_sg_gateway_same_terminal_https_handoff():
    text = page()

    required = (
        "let hadSuccessfulPoll = false",
        "let redirectScheduled = false",
        "function continueTerminalOverHttps()",
        "secureJobUrl.protocol = 'https:'",
        "secureJobUrl.hostname = resultUrl.hostname",
        "secureJobUrl.port = resultUrl.port",
        "window.location.replace(secureJobUrl.toString())",
        "switchingStarted && (hadSuccessfulPoll || consecutiveFailures >= 3)",
    )
    for value in required:
        assert value in text


def test_button_is_shown_only_after_job_success():
    text = page()

    success = text.split("if (data.status === 'success')", 1)[1].split(
        "if (data.status === 'failed')", 1
    )[0]
    assert "showHttpsReady();" in success
    assert "targetLink.hidden = false" in text
    assert "Открыть панель по HTTPS" in text


def test_no_login_redirect_or_https_probe_experiments_remain():
    text = page()

    assert "targetLoginUrl" not in text
    assert "panel_access_switched" not in text
    assert "httpsProbeUrl" not in text
    assert "probeHttpsReady" not in text
    assert "window.location.assign" not in text
