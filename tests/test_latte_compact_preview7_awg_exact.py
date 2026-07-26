from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_page_classes_are_server_side_and_not_late_script_only():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    assert "preview-7-awg-exact" in base
    assert "request.endpoint == 'cascade_page'" in base
    assert "request.endpoint == 'nodes_page'" in base
    assert "request.endpoint == 'users_page'" in base
    assert "sg070-preview7" in base


def test_cascade_uses_unbounded_awg_workspace():
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    packed = "".join(css.split())
    assert "body.preview-7-awg-exact.awg-cascade-page .content" in css
    assert "width:100%!important" in packed
    assert "max-width:none!important" in packed
    assert ".cascade-awg-scheme{padding:31px30px29px" in packed


def test_cluster_matches_compact_ui21_hierarchy():
    html = (ROOT / "xpanel/templates/nodes.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/fix40-cluster-restore-ui21.css").read_text(encoding="utf-8")
    for marker in (
        "CONTROLLER · ТЕКУЩИЙ СЕРВЕР",
        "+ Добавить SG-Node",
        "Дополнительные серверы",
        "Имя сервера → одна команда → автоматический статус «В сети»",
        "Создать и получить команду",
        "compact-node-list",
        "compact-node-row",
    ):
        assert marker in html
    assert ".cluster-restore-controller" in css
    assert ".cluster-restore-onboarding" in css
    assert "cluster-stage4-summary" not in html
