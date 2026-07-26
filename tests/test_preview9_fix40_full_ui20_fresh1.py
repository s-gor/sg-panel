from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_full_ui20_release_identity_is_consistent() -> None:
    expected = 'Preview 9 · FIX40 · UI23'
    assert f'__release_label__ = "{expected}"' in read('xpanel/__init__.py')
    for relative in ('install.sh', 'install-or-upgrade.sh', 'deploy/ec2-first-install.sh'):
        assert f'EXPECTED_RELEASE_LABEL="{expected}"' in read(relative)


def test_agent_reports_the_installed_worker_version() -> None:
    agent = read('node_agent/sg_node_agent.py')
    worker = read('node_agent/sg_node_worker.py')
    assert 'WORKER_VERSION = "0.7.0"' in agent
    assert 'WORKER_VERSION = "0.7.0"' in worker
    assert '"worker_version": WORKER_VERSION' in agent


def test_cascade_template_has_no_node_reference_outside_loop_marker() -> None:
    page = read('xpanel/templates/cascade.html')
    assert 'data-country="{{ node.country_code }}"' not in page
    assert '{% for node in cluster_nodes %}' in page
    assert 'country_flag(node.country_code' in page



def test_cascade_template_parses_after_the_fix() -> None:
    from jinja2 import Environment

    Environment().parse(read('xpanel/templates/cascade.html'))
