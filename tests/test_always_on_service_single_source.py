from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "xpanel/service.py"
SINGLE_SOURCE_FUNCTIONS = (
    "make_links",
    "make_saved_links",
    "validate_generated_config",
    "apply_config",
)


def _source() -> str:
    return SERVICE.read_text(encoding="utf-8")


def _top_level_functions(source: str) -> dict[str, list[ast.FunctionDef]]:
    tree = ast.parse(source)
    result: dict[str, list[ast.FunctionDef]] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            result.setdefault(node.name, []).append(node)
    return result


def _segment(source: str, node: ast.FunctionDef) -> str:
    value = ast.get_source_segment(source, node)
    assert value is not None
    return value


def test_always_on_service_functions_have_one_top_level_definition() -> None:
    source = _source()
    functions = _top_level_functions(source)
    for name in SINGLE_SOURCE_FUNCTIONS:
        assert len(functions.get(name, [])) == 1, name


def test_active_link_generation_uses_the_always_on_channel_model() -> None:
    source = _source()
    functions = _top_level_functions(source)
    make_links = _segment(source, functions["make_links"][0])
    make_saved_links = _segment(source, functions["make_saved_links"][0])

    for marker in (
        "get_xray_channels_settings",
        '"raw_reality"',
        '"xhttp_reality"',
        '"xhttp_tls"',
        '"hysteria2_tls"',
    ):
        assert marker in make_links

    assert "RUSSIA_KIT_PROFILE" not in make_links
    assert "return make_links(" in make_saved_links


def test_active_validation_and_apply_keep_always_on_tls_and_transaction_logic() -> None:
    source = _source()
    functions = _top_level_functions(source)
    validate = _segment(source, functions["validate_generated_config"][0])
    apply = _segment(source, functions["apply_config"][0])

    assert "_sg_sync_always_on_tls_material" in validate
    assert "_sg_runtime_all_tls_config_text" in validate
    assert "_sg_sync_always_on_tls_material" in apply
    assert "_sg_runtime_all_tls_config_text" in apply
    assert '"all_available_channels"' in apply
    assert "SG_ALWAYS_ON_CHANNELS_MARKER" in apply
    assert "run_xray_test" in apply
    assert "_restore_nginx_frontends" in apply


def test_legacy_russia_kit_helper_is_not_silently_reactivated() -> None:
    source = _source()
    functions = _top_level_functions(source)
    make_links = _segment(source, functions["make_links"][0])

    # Russia Kit remains available for a later explicit migration; this cleanup
    # only prevents the shadowed legacy link generator from becoming active.
    assert "def _make_russia_kit_links(" in source
    assert "_make_russia_kit_links(" not in make_links
    assert "# SG_GATEWAY_ALWAYS_ON_CHANNELS_V1_START" in source
    assert "# SG_GATEWAY_ALWAYS_ON_CHANNELS_V1_END" in source
