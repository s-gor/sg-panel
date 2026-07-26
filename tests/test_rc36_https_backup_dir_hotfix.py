from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTTPS = ROOT / "deploy" / "configure-https.sh"


def _fallback_function() -> str:
    text = HTTPS.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^wait_for_fallback\(\)\{.*?^\}\n", text)
    assert match, "wait_for_fallback function not found"
    return match.group(0)


def test_https_fallback_does_not_depend_on_backup_dir():
    function = _fallback_function()
    assert "BACKUP_DIR" not in function
    assert 'mktemp "${TMPDIR:-/tmp}/sg-panel-fallback-check.XXXXXX"' in function
    assert '"https://$DOMAIN/"' in function
    assert "grep -Fq 'SG Digital Systems' \"$body_file\"" in function


def test_https_fallback_runs_under_set_u_and_removes_temp_file():
    function = _fallback_function()
    with tempfile.TemporaryDirectory() as tmp:
        body = Path(tmp) / "fallback-check.html"
        script = "\n".join([
            "#!/usr/bin/env bash",
            "set -Eeuo pipefail",
            "DOMAIN=panel.example.com",
            f"TEST_BODY_FILE={str(body)!r}",
            "mktemp() { printf '%s\\n' \"$TEST_BODY_FILE\"; }",
            "curl() {",
            "  local output=\"\"",
            "  while (($#)); do",
            "    if [[ \"$1\" == \"--output\" ]]; then output=\"$2\"; shift 2; else shift; fi",
            "  done",
            "  printf '%s\\n' 'SG Digital Systems' > \"$output\"",
            "}",
            "sleep() { :; }",
            "nginx() { :; }",
            function,
            "wait_for_fallback",
            "[[ ! -e \"$TEST_BODY_FILE\" ]]",
        ])
        completed = subprocess.run(
            ["bash", "-c", script],
            text=True,
            capture_output=True,
            env={**os.environ, "BACKUP_DIR": ""},
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
