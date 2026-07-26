from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from xpanel import service
from xpanel.db import init_db

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def panel_db(tmp_path: Path):
    previous = os.environ.get("XPANEL_DB")
    os.environ["XPANEL_DB"] = str(tmp_path / "panel.db")
    init_db()
    try:
        yield tmp_path
    finally:
        if previous is None:
            os.environ.pop("XPANEL_DB", None)
        else:
            os.environ["XPANEL_DB"] = previous


def test_repair4_xmux_is_visible_in_xray_server_with_both_presets() -> None:
    template = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    assert "XMUX для XHTTP" in template
    assert "Общие клиентские параметры XHTTP Reality и XHTTP TLS" in template
    assert "Стандартный" in template
    assert "Для РФ — уменьшенный" in template
    for value in (
        "maxConnections 2-4",
        "reuse 300-600",
        "requests 1000-2000",
        "lifetime 1200-2400",
        "keepalive 600",
        "maxConcurrency 0",
        "maxConnections 6",
        "requests 600-900",
        "lifetime 1800-3000",
        "keepalive 0",
    ):
        assert value in template


def test_repair4_standard_preset_is_exact_and_client_only(panel_db: Path) -> None:
    service.update_xmux_settings(
        xmux_mode="auto",
        xhttp_extra_client_json='{"headers":{"X-Test":"kept"}}',
    )
    client = service._effective_xhttp_extra("client")
    server = service._effective_xhttp_extra("server")
    assert client["headers"] == {"X-Test": "kept"}
    assert client["xmux"] == {
        "maxConnections": "2-4",
        "cMaxReuseTimes": "300-600",
        "hMaxRequestTimes": "1000-2000",
        "hMaxReusableSecs": "1200-2400",
        "hKeepAlivePeriod": 600,
    }
    assert "xmux" not in server


def test_repair4_russia_preset_accepts_zero_concurrency_with_six_connections(panel_db: Path) -> None:
    service.update_xmux_settings(xmux_mode="reduced")
    client = service._effective_xhttp_extra("client")
    assert client["xmux"] == {
        "maxConcurrency": 0,
        "maxConnections": "6",
        "cMaxReuseTimes": 0,
        "hMaxRequestTimes": "600-900",
        "hMaxReusableSecs": "1800-3000",
        "hKeepAlivePeriod": 0,
    }
    service._validate_xmux_conflicts(client, label="Client Extra")


def test_repair4_blocks_only_two_positive_xmux_controllers() -> None:
    with pytest.raises(ValueError, match="положительные maxConnections и maxConcurrency"):
        service._validate_xmux_conflicts(
            {"xmux": {"maxConcurrency": "2-4", "maxConnections": 6}},
            label="Client Extra",
        )
    service._validate_xmux_conflicts(
        {"xmux": {"maxConcurrency": 0, "maxConnections": 6}},
        label="Client Extra",
    )
    service._validate_xmux_conflicts(
        {"xmux": {"maxConcurrency": "16-32", "maxConnections": 0}},
        label="Client Extra",
    )


def test_repair4_manual_mode_requires_and_preserves_xmux_json(panel_db: Path) -> None:
    with pytest.raises(ValueError, match="нужен объект xmux"):
        service.update_xmux_settings(xmux_mode="expert", xhttp_extra_client_json="{}")

    source = {
        "xmux": {
            "maxConcurrency": "8-16",
            "maxConnections": 0,
            "cMaxReuseTimes": "64-128",
            "hMaxRequestTimes": "600-900",
            "hMaxReusableSecs": "1800-3000",
            "hKeepAlivePeriod": 0,
        },
        "headers": {"X-Manual": "yes"},
    }
    service.update_xmux_settings(
        xmux_mode="expert",
        xhttp_extra_client_json=json.dumps(source),
    )
    assert service._effective_xhttp_extra("client") == source


def test_repair4_always_on_context_no_longer_hides_xmux() -> None:
    web = (ROOT / "xpanel/web.py").read_text(encoding="utf-8")
    service_source = (ROOT / "xpanel/service.py").read_text(encoding="utf-8")
    advanced = (ROOT / "xpanel/templates/advanced.html").read_text(encoding="utf-8")
    assert "xmux=get_transport_expert_overview()" in web
    assert "xhttp_applicable = True" in service_source
    assert "Стандартный пресет" in advanced
    assert "Пресет «Для РФ — уменьшенный»" in advanced
