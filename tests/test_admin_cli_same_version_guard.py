from __future__ import annotations

import io
import os
import zipfile
from unittest.mock import Mock, patch

from xpanel import __version__
from xpanel import admin_cli


def _github_zip(version: str) -> bytes:
    stream = io.BytesIO()
    filler = os.urandom(120_000)
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr("sg-panel-main/install-or-upgrade.sh", "#!/usr/bin/env bash\nexit 0\n")
        bundle.writestr("sg-panel-main/xpanel/__init__.py", f'__version__ = "{version}"\n')
        bundle.writestr("sg-panel-main/filler.bin", filler)
    return stream.getvalue()


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self.payload


def test_ssh_update_does_not_reinstall_same_version(capsys):
    payload = _github_zip(__version__)
    run = Mock()
    with (
        patch.object(admin_cli.urllib.request, "urlopen", return_value=_Response(payload)),
        patch.object(admin_cli.subprocess, "run", run),
        patch("builtins.input", return_value=""),
    ):
        admin_cli.update_panel_interactive()

    output = capsys.readouterr().out
    assert "Установлена та же версия" in output
    assert "Обновление не требуется" in output
    run.assert_not_called()
