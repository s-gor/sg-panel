from pathlib import Path

from jinja2 import Environment, meta

ROOT = Path(__file__).resolve().parents[1]


def test_cascade_template_has_no_undefined_node_outside_loop() -> None:
    source = (ROOT / "xpanel/templates/cascade.html").read_text(encoding="utf-8")
    ast = Environment().parse(source)
    undeclared = meta.find_undeclared_variables(ast)
    assert "node" not in undeclared
    assert 'data-country="{{ node.country_code }}"' not in source
