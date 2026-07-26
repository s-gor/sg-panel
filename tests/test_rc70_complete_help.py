from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_version_and_ui_revision_are_rc70():
    assert '__version__ = "0.10.0-rc70"' in read("xpanel/__init__.py")
    assert "sg070" in read("xpanel/templates/base.html")
    assert "sg070" in read("xpanel/templates/login.html")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_UI_REVISION="sg070"' in read("install-or-upgrade.sh")


def test_builtin_cascade_help_is_complete():
    help_html = read("xpanel/templates/help.html")
    required = [
        'id="cascade"',
        "Сделать этот сервер выходом",
        "Скопировать ссылку",
        "Подключить и проверить",
        "Включить Cascade",
        "Открыть Clients",
        "Проверить ещё раз",
        "Заменить выходной сервер",
        "Отключить и вернуть Direct",
        "Удалить Cascade",
        "служебную ссылку выхода пользователю не выдавайте",
        "Типовые ошибки",
    ]
    for value in required:
        assert value in help_html


def test_builtin_node_help_is_complete():
    help_html = read("xpanel/templates/help.html")
    required = [
        'id="multinode"',
        "Скопировать команду полной установки SG-Node",
        "Добавить подготовленную SG-Node",
        "Создать карточку и новый токен",
        "Скопировать команду подключения",
        "STATUS=ready_to_connect",
        "Agent и Worker",
        "64441/tcp",
        "Проверить и развернуть",
        "ожидает первого профиля",
        "Создать новую команду",
        "Отключить ноду",
        "События и обслуживание",
        "/var/log/sg-node-full-install.log",
        "/var/log/sg-node-connect.log",
    ]
    for value in required:
        assert value in help_html


def test_contextual_links_point_to_exact_help_anchors():
    cascade = read("xpanel/templates/cascade.html")
    nodes = read("xpanel/templates/nodes.html")
    node_detail = read("xpanel/templates/node_detail.html")
    assert cascade.count("#cascade") >= 3
    assert "#multinode" in nodes
    assert node_detail.count("#multinode") >= 2
    assert "Полная инструкция" in node_detail


def test_user_documents_are_current_and_linked():
    docs = [
        "docs/README.md",
        "docs/START-HERE.md",
        "docs/USER-GUIDE.md",
        "docs/PANEL.md",
        "docs/CASCADE.md",
        "docs/MULTI-NODE.md",
    ]
    for relative in docs:
        content = read(relative)
        assert "v0.10.0-rc70" in content
        assert "v0.10.0-rc50" not in content
    assert "CASCADE.md" in read("docs/README.md")
    assert "MULTI-NODE.md" in read("docs/README.md")
    assert "| `Routing` |" in read("docs/PANEL.md")
    assert "| `Network` |" not in read("docs/PANEL.md")


def test_release_notes_describe_docs_only_scope():
    notes = read("RELEASE-NOTES-RC70.md")
    assert "полную пошаговую инструкцию по Cascade" in notes
    assert "Cluster и SG-Node" in notes
    assert "Сетевая логика" in notes
    assert "не изменялись" in notes
