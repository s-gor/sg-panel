from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_https_job_redirect_requires_explicit_success() -> None:
    page = read("xpanel/templates/panel_access_job.html")
    assert "if (data.status === 'success')" in page
    assert "scheduleRedirect('Доступ успешно переключён')" in page
    assert "hadSuccessfulPoll || consecutiveFailures >= 3" not in page
    assert "scheduleRedirect('Nginx уже перешёл на новый адрес'" not in page
    catch = page.split("} catch (error) {", 1)[1].split("window.setTimeout(poll", 1)[0]
    assert "scheduleRedirect(" not in catch
    assert "На HTTPS не переходим, пока сервер не вернёт status=success" in page


def test_https_job_failure_keeps_previous_access_and_explains_tcp80() -> None:
    page = read("xpanel/templates/panel_access_job.html")
    assert 'id="target-link"' in page and "hidden>Перейти на подтверждённый HTTPS-адрес" in page
    assert "targetLink.hidden = false" in page
    assert "targetLink.hidden = true" in page
    assert "Let's Encrypt не смог подключиться к TCP 80 снаружи" in page
    assert "предыдущий доступ восстановлен" in page


def test_local_http01_probe_is_not_presented_as_external_wan_check() -> None:
    script = read("deploy/configure-panel-access.sh")
    assert 'log "Проверяю локальный HTTP-01 Nginx/webroot"' in script
    assert '--resolve "$HOST:80:127.0.0.1"' in script
    assert 'внешнюю доступность TCP 80 проверит Let\'s Encrypt' in script
    assert "if ! certbot certonly" in script
    assert "Проверьте внешний TCP 80; HTTPS не включён" in script
    assert 'log "HTTPS не настроен, восстанавливаю предыдущий доступ"' in script


if __name__ == "__main__":
    test_https_job_redirect_requires_explicit_success()
    test_https_job_failure_keeps_previous_access_and_explains_tcp80()
    test_local_http01_probe_is_not_presented_as_external_wan_check()
    print("HTTPS Access Safety Fix 1 contract: PASS")
