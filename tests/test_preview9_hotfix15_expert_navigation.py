from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hotfix15_expert_navigation_is_not_duplicated():
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")
    advanced = (ROOT / "xpanel/templates/advanced.html").read_text(encoding="utf-8")

    assert '<span class="section-tab-label">Подключения</span>' in base
    assert '<span class="section-tab-label">Резервные Inbound</span>' in base
    assert '<span class="section-tab-label">Xray Config</span>' in base
    assert '<span class="section-tab-label">Транспорты</span>' not in base
    assert '<span class="section-tab-label">Ядро Xray</span>' not in base
    assert 'Подключения, резервные Inbound и JSON' in base
    assert 'Подключения текущей схемы' in advanced
    assert 'id="xray-core"' not in advanced
    assert '<h2>Ядро Xray</h2>' not in advanced
