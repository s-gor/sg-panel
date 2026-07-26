from __future__ import annotations

import errno
from pathlib import Path
import subprocess

import pytest

import xpanel.service as service
from xpanel.db import connect, init_db
from xpanel.service import XPanelError, apply_geofiles_source, validate_geofiles_source


ROOT = Path(__file__).resolve().parents[1]


def _varint(value: int) -> bytes:
    result = bytearray()
    while True:
        current = value & 0x7F
        value >>= 7
        result.append(current | (0x80 if value else 0))
        if not value:
            return bytes(result)


def _geo_file(*categories: str) -> bytes:
    body = bytearray()
    for category in categories:
        encoded = category.encode("utf-8")
        message = b"\x0a" + _varint(len(encoded)) + encoded
        body += b"\x0a" + _varint(len(message)) + message
    padding = max(0, 8192 - len(body) - 4)
    body += b"\x12" + _varint(padding) + (b"\0" * padding)
    return bytes(body)


@pytest.fixture()
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XPANEL_DB", str(tmp_path / "panel.db"))
    init_db()
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("placeholder", encoding="utf-8")
    key.write_text("placeholder", encoding="utf-8")
    with connect() as con:
        con.execute(
            """
            INSERT INTO server_settings (
                id, address, listen, port, dest, server_name,
                private_key, public_key, short_id, fingerprint, flow,
                config_path, xray_bin, xray_service, inbound_profile,
                transport_listen, transport_port, xhttp_path, xhttp_mode,
                tls_cert_path, tls_key_path
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "vpn.example.com", "0.0.0.0", 443,
                "www.bing.com:443", "vpn.example.com",
                "private", "public", "0011223344556677", "chrome", "",
                str(tmp_path / "config.json"), "/bin/true", "xray",
                "xhttp_tls", "127.0.0.1", 8443, "/sg-xhttp", "auto",
                str(cert), str(key),
            ),
        )
    return tmp_path


def test_web_service_allows_only_xray_asset_directories_for_geofiles():
    script = (ROOT / "deploy/install-service.sh").read_text(encoding="utf-8")

    assert "mkdir -p" in script
    assert "/usr/local/share/xray" in script
    assert "/usr/share/xray" in script

    unit_line = next(
        line for line in script.splitlines() if line.startswith("ReadWritePaths=")
    )
    assert "/usr/local/share/xray" in unit_line
    assert "/usr/share/xray" in unit_line
    assert "/usr/local/share " not in unit_line
    assert "/usr/share " not in unit_line


def test_read_only_asset_directory_has_clear_error_and_preserves_old_files(
    panel, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source_geoip = tmp_path / "source-geoip.dat"
    source_geosite = tmp_path / "source-geosite.dat"
    source_geoip.write_bytes(_geo_file("private", "ru"))
    source_geosite.write_bytes(_geo_file("private", "category-ru"))

    active_dir = tmp_path / "active"
    active_dir.mkdir()
    active_geoip = active_dir / "geoip.dat"
    active_geosite = active_dir / "geosite.dat"
    old_geoip = b"old-ip" * 1024
    old_geosite = b"old-site" * 1024
    active_geoip.write_bytes(old_geoip)
    active_geosite.write_bytes(old_geosite)

    state_dir = tmp_path / "state"
    monkeypatch.setattr(service, "GEOFILES_STATE_DIR", state_dir)
    monkeypatch.setattr(
        service, "_current_asset_paths", lambda: (active_geoip, active_geosite)
    )
    monkeypatch.setattr(service, "require_root", lambda: None)
    monkeypatch.setattr(
        service,
        "_run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, stdout="active\n" if args[:2] == ["systemctl", "is-active"] else "", stderr=""
        ),
    )
    monkeypatch.setattr(service, "_systemctl_checked", lambda *args, **kwargs: None)
    monkeypatch.setattr(service, "_confirm_xray_active", lambda *args, **kwargs: None)

    validate_geofiles_source(
        source="local",
        geoip_local_path=str(source_geoip),
        geosite_local_path=str(source_geosite),
    )

    real_copy2 = service.shutil.copy2

    def read_only_copy(source, destination, *args, **kwargs):
        destination_path = Path(destination)
        if destination_path.name.endswith(".sg-transaction"):
            raise OSError(errno.EROFS, "Read-only file system", str(destination_path))
        return real_copy2(source, destination, *args, **kwargs)

    monkeypatch.setattr(service.shutil, "copy2", read_only_copy)

    with pytest.raises(XPanelError, match="каталог ресурсов Xray недоступен") as caught:
        apply_geofiles_source()

    assert "Xray" in str(caught.value)
    assert active_geoip.read_bytes() == old_geoip
    assert active_geosite.read_bytes() == old_geosite
