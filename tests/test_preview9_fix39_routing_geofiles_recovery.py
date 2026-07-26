from __future__ import annotations

import hashlib
import json
from io import BytesIO
from pathlib import Path

import pytest

from xpanel.db import connect, init_db
from xpanel import service

ROOT = Path(__file__).resolve().parents[1]


def _set_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    monkeypatch.setattr(service, "GEOFILES_STATE_DIR", tmp_path / "geofiles")
    monkeypatch.setattr(
        service, "GEOFILES_OPERATION_LOCK", tmp_path / "geofiles" / ".operation.lock"
    )
    init_db()


def _fake_download(_source: str, _value: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes((destination.name.encode("ascii") + b"\0") * 8192)


def _fake_analysis(*_args: object, **_kwargs: object) -> dict[str, object]:
    return {
        "family": "Пользовательский",
        "geoip_categories": ["private", "direct"],
        "geosite_categories": ["private", "category-ru"],
    }


def _candidate(config_text: str = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}') -> dict[str, object]:
    return {
        "config_text": config_text,
        "config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
        "config_path": "/tmp/candidate.json",
        "users": 0,
        "compatibility": {"compatible": True, "missing_categories": []},
        "preset": {"name": "none"},
        "xray_test": "ok",
    }


def test_check_does_not_mutate_persisted_source_before_apply(tmp_path, monkeypatch) -> None:
    _set_paths(tmp_path, monkeypatch)
    with connect() as con:
        before = dict(con.execute("SELECT * FROM geofiles_settings WHERE id=1").fetchone())

    monkeypatch.setattr(service, "_copy_or_download_geofile", _fake_download)
    monkeypatch.setattr(service, "_analyze_geofile_pair", _fake_analysis)
    monkeypatch.setattr(service, "_run_geofiles_structural_test", lambda *a, **k: None)
    monkeypatch.setattr(
        service,
        "render_text",
        lambda: ('{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}', {"xray_bin": "/bin/true"}, []),
    )
    monkeypatch.setattr(
        service,
        "_geofiles_compatibility",
        lambda *a, **k: {"compatible": True, "missing_categories": []},
    )
    monkeypatch.setattr(service, "_prepare_geofiles_candidate", lambda *a, **k: _candidate())

    manifest = service.validate_geofiles_source(
        source="custom",
        geoip_url="https://example.test/geoip.dat",
        geosite_url="https://example.test/geosite.dat",
    )

    with connect() as con:
        after = dict(con.execute("SELECT * FROM geofiles_settings WHERE id=1").fetchone())
    assert after["source"] == before["source"]
    assert after["geoip_url"] == before["geoip_url"]
    assert after["geosite_url"] == before["geosite_url"]
    assert manifest["source"] == "custom"
    overview = service.get_geofiles_overview()
    assert overview["selected_source"] == "custom"
    assert overview["selection"]["geoip_url"] == "https://example.test/geoip.dat"


def test_roscom_source_forces_compatible_plan(tmp_path, monkeypatch) -> None:
    _set_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_copy_or_download_geofile", _fake_download)
    monkeypatch.setattr(
        service,
        "_analyze_geofile_pair",
        lambda *a, **k: {
            "family": "RoscomVPN",
            "geoip_categories": ["direct", "private", "whitelist"],
            "geosite_categories": ["category-ru", "category-ads", "private", "whitelist"],
        },
    )
    monkeypatch.setattr(service, "_run_geofiles_structural_test", lambda *a, **k: None)
    captured: dict[str, object] = {}

    def prepare(*_args: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        value = _candidate()
        value["preset"] = {"name": "roscomvpn"}
        return value

    monkeypatch.setattr(service, "_prepare_geofiles_candidate", prepare)
    manifest = service.validate_geofiles_source(source="roscomvpn", final_outbound_tag="direct")
    assert captured["server_preset"] == "roscomvpn"
    assert manifest["server_preset"] == "roscomvpn"


def test_apply_blocks_changed_candidate_before_touching_live_state(tmp_path, monkeypatch) -> None:
    _set_paths(tmp_path, monkeypatch)
    stage = service.GEOFILES_STATE_DIR / "staging"
    stage.mkdir(parents=True)
    geoip = stage / "geoip.dat"
    geosite = stage / "geosite.dat"
    geoip.write_bytes(b"a" * 8192)
    geosite.write_bytes(b"b" * 8192)
    checked = _candidate("{\"checked\":true}")
    manifest = {
        "source": "custom",
        "source_label": "Custom",
        "geoip_url": "https://example.test/geoip.dat",
        "geosite_url": "https://example.test/geosite.dat",
        "geoip_local_path": "",
        "geosite_local_path": "",
        "geoip": {"sha256": service._sha256_file(geoip)},
        "geosite": {"sha256": service._sha256_file(geosite)},
        "family": "Пользовательский",
        "geoip_categories": ["private"],
        "geosite_categories": ["private"],
        "candidate_config_sha256": checked["config_sha256"],
        "server_preset": "none",
        "block_enabled": False,
        "final_outbound_tag": "direct",
    }
    with connect() as con:
        con.execute(
            "UPDATE geofiles_settings SET last_check_state='ok', staged_manifest_json=? WHERE id=1",
            (json.dumps(manifest),),
        )
    monkeypatch.setattr(service, "require_root", lambda: None)
    monkeypatch.setattr(service, "_prepare_geofiles_candidate", lambda *a, **k: _candidate('{"changed":true}'))
    monkeypatch.setattr(
        service,
        "_current_asset_paths",
        lambda: (_ for _ in ()).throw(AssertionError("live paths must not be touched")),
    )
    with pytest.raises(service.XPanelError, match="изменились после проверки"):
        service.apply_geofiles_source()


def test_controller_geofiles_operations_are_serialized(tmp_path, monkeypatch) -> None:
    _set_paths(tmp_path, monkeypatch)
    service.GEOFILES_STATE_DIR.mkdir(parents=True)
    import fcntl

    with service.GEOFILES_OPERATION_LOCK.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(service.XPanelError, match="другая операция"):
            service.validate_geofiles_source(source="sgclient")
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
