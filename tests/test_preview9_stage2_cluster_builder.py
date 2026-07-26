from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "xpanel" / "static"
TEMPLATES = ROOT / "xpanel" / "templates"


def test_stage2_cluster_builder_visual_contract():
    template = (TEMPLATES / "cascade.html").read_text(encoding="utf-8")
    css = (STATIC / "cascade-rc6.css").read_text(encoding="utf-8")

    assert "cascade-cluster-builder" in template
    assert "Выберите SG-Node для выхода в интернет" in template
    assert "Автоматическая настройка" in template
    assert "INBOUND · ЭТОТ СЕРВЕР" in template
    assert "OUTBOUND · SG-NODE" in template
    assert "Служебный маршрут<br>создаст Agent" in template
    assert "Клиентские профили менять или перевыпускать не нужно" in template
    assert "Что произойдёт" in template
    assert "grid-template-columns: minmax(0,1fr) 108px minmax(0,1fr)" in css
    assert "min-height: 250px" in css
    assert ".cascade-cluster-submit" in css


def test_stage2_cluster_builder_uses_real_country_flag_assets():
    template = (TEMPLATES / "cascade.html").read_text(encoding="utf-8")

    assert 'id="cascade-exit-flag"' in template
    assert "flags/globe.svg" in template
    assert 'data-country="{{ node.country_code }}"' in template
    assert "data-flag-src" in template
    assert "selected?.dataset.flagSrc || exitFlag.dataset.fallbackSrc" in template
    assert "Страна не выбрана" in template


def test_stage2_keeps_existing_cluster_form_contract():
    template = (TEMPLATES / "cascade.html").read_text(encoding="utf-8")

    assert 'action="{{ url_for(\'cascade_cluster_connect\') }}"' in template
    assert 'method="post"' in template
    assert 'name="csrf_token"' in template
    assert 'name="exit_node_id"' in template
    assert 'id="cascade-cluster-form"' in template
    assert 'data-cascade-mode-panel="external"' in template


def test_stage2_adds_no_new_global_css_layer():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    assert "cascade-rc6.css" in base
    assert "rc6-typography.css" in base
    assert "stage-2" not in base.lower()
