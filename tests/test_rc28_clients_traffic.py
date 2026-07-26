from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from xpanel.db import connect, init_db
from xpanel.service import (
    _traffic_snapshot_from_db,
    add_user,
    collect_traffic_snapshot,
    get_user_traffic_history,
    reset_stats,
    update_users_json_document,
    users_json_document,
)

ROOT = Path(__file__).resolve().parents[1]


def _seed_server() -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint,
                stats_enabled, config_path, xray_bin, xray_service
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "www.bing.com",
                "private", "public", "0011223344556677", "chrome",
                "/tmp/config.json", "/bin/true", "xray",
            ),
        )


def test_rc28_schema_has_persistent_traffic_tables() -> None:
    with tempfile.TemporaryDirectory() as temp:
        os.environ["XPANEL_DB"] = str(Path(temp) / "panel.db")
        try:
            init_db()
            with connect() as con:
                tables = {
                    row["name"]
                    for row in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                columns = {
                    row["name"]
                    for row in con.execute("PRAGMA table_info(user_traffic_totals)")
                }
            assert "user_traffic_totals" in tables
            assert "user_traffic_daily" in tables
            assert {
                "uplink_total", "downlink_total", "last_raw_uplink",
                "session_downlink", "uplink_bps", "last_seen_at",
            } <= columns
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_collector_accumulates_deltas_across_xray_counter_reset() -> None:
    with tempfile.TemporaryDirectory() as temp:
        os.environ["XPANEL_DB"] = str(Path(temp) / "panel.db")
        try:
            init_db()
            _seed_server()
            user = add_user("Traffic User")
            prefix = "user>>>Traffic User>>>traffic>>>"
            first = {prefix + "uplink": 100, prefix + "downlink": 200}
            second = {prefix + "uplink": 160, prefix + "downlink": 260}
            after_restart = {prefix + "uplink": 10, prefix + "downlink": 20}
            t0 = datetime.now(timezone.utc).replace(microsecond=0)
            with patch("xpanel.service.query_stats", side_effect=[first, second, after_restart]), patch(
                "xpanel.service._query_online", return_value=True
            ):
                one = collect_traffic_snapshot(include_online=True, now=t0)[int(user["id"])]
                two = collect_traffic_snapshot(
                    include_online=True, now=t0 + timedelta(seconds=60)
                )[int(user["id"])]
                three = collect_traffic_snapshot(
                    include_online=True, now=t0 + timedelta(seconds=120)
                )[int(user["id"])]

            assert one["lifetime_total"] == 300
            assert two["lifetime_total"] == 420
            assert two["total_bps"] == 2
            # Lower raw counters mean a new Xray session; new bytes are added,
            # not subtracted and the persistent history remains monotonic.
            assert three["lifetime_total"] == 450
            assert three["session_total"] == 30
            assert three["online"] is True
            assert three["last_seen_at"]
            history = get_user_traffic_history(int(user["id"]), days=14)
            assert sum(int(item["total"]) for item in history) == 450
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_reset_single_client_keeps_other_history_and_sets_fresh_baseline() -> None:
    with tempfile.TemporaryDirectory() as temp:
        os.environ["XPANEL_DB"] = str(Path(temp) / "panel.db")
        try:
            init_db()
            _seed_server()
            first = add_user("One")
            second = add_user("Two")
            raw = {
                "user>>>One>>>traffic>>>uplink": 100,
                "user>>>One>>>traffic>>>downlink": 200,
                "user>>>Two>>>traffic>>>uplink": 300,
                "user>>>Two>>>traffic>>>downlink": 400,
            }
            with patch("xpanel.service.query_stats", return_value=raw):
                collect_traffic_snapshot()
                reset_stats(int(first["id"]))
            snapshot = _traffic_snapshot_from_db([first, second])
            assert snapshot[int(first["id"])]["lifetime_total"] == 0
            assert snapshot[int(first["id"])]["session_total"] == 300
            assert snapshot[int(second["id"])]["lifetime_total"] == 700
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_users_json_round_trip_preserves_traffic_for_matching_client() -> None:
    with tempfile.TemporaryDirectory() as temp:
        os.environ["XPANEL_DB"] = str(Path(temp) / "panel.db")
        try:
            init_db()
            _seed_server()
            user = add_user("Keep Me")
            raw = {
                "user>>>Keep Me>>>traffic>>>uplink": 123,
                "user>>>Keep Me>>>traffic>>>downlink": 456,
            }
            with patch("xpanel.service.query_stats", return_value=raw):
                collect_traffic_snapshot()
            update_users_json_document(users_json_document())
            snapshot = _traffic_snapshot_from_db([user])
            assert snapshot[int(user["id"])]["lifetime_total"] == 579
        finally:
            os.environ.pop("XPANEL_DB", None)


def test_clients_studio_ui_and_collector_timer_are_packaged() -> None:
    html = (ROOT / "xpanel/templates/users.html").read_text(encoding="utf-8")
    css = (ROOT / "xpanel/static/app.css").read_text(encoding="utf-8")
    timer = (ROOT / "deploy/install-maintenance.sh").read_text(encoding="utf-8")
    for marker in (
        "Доступы и устройства",
        "Последняя активность",
        "Трафик за всё время",
        "Срок",
        "Серверы подключения",
        "Добавить клиента",
        "Истекают в течение 7 дней",
    ):
        assert marker in html
    assert ".clients-awg-master-detail" in css
    assert "grid-template-columns:minmax(0,1fr) 330px" in css
    assert "client-detail-standard" in html
    assert "Последние 14 дней" not in html
    assert "xpanel-traffic.timer" in timer
    assert "OnUnitActiveSec=60s" in timer
    assert "collect-traffic --online" in timer
    assert "Сбросить трафик" in html
    assert "Сбросить весь трафик" in html
    assert "Доступы и конфигурации останутся без изменений" in html
    assert html.index("Сбросить трафик") < html.index("Удалить клиента")
