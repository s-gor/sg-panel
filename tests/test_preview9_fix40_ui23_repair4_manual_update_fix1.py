from pathlib import Path


def test_manual_update_block_has_concrete_github_main_zip_workflow():
    text = Path("xpanel/templates/updates.html").read_text(encoding="utf-8")
    assert "https://github.com/s-gor/sg-panel/archive/refs/heads/main.zip" in text
    assert "curl -fL" in text
    assert "python3 -m zipfile -e sg-panel-main.zip ." in text
    assert "cd sg-panel-main" in text
    assert "sudo bash deploy/update-from-local-source.sh" in text
    assert "текущую опубликованную версию из GitHub" in text
    assert "Локальная тестовая сборка в этот ZIP не входит" in text


def test_manual_update_block_drops_undefined_zip_wording():
    text = Path("xpanel/templates/updates.html").read_text(encoding="utf-8")
    assert "распакуйте новый проверенный ZIP" not in text
