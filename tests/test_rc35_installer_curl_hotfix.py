from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTTP = ROOT / "deploy" / "configure-http.sh"
HTTPS = ROOT / "deploy" / "configure-https.sh"


def test_http_placeholder_check_does_not_pipe_curl_into_grep_q():
    text = HTTP.read_text(encoding="utf-8")
    assert 'curl -fsS --max-time 5 -H "Host: $HOST" "http://127.0.0.1/" | grep -q' not in text
    assert 'PLACEHOLDER_CHECK="$BACKUP_DIR/placeholder-check.html"' in text
    assert '--output "$PLACEHOLDER_CHECK"' in text
    assert 'grep -Fq "SG Digital Systems" "$PLACEHOLDER_CHECK"' in text


def test_https_fallback_check_does_not_pipe_curl_into_grep_q():
    text = HTTPS.read_text(encoding="utf-8")
    assert '"https://$DOMAIN/" | grep -q' not in text
    assert 'local body_file="$BACKUP_DIR/fallback-check.html"' in text
    assert '--output "$body_file"' in text
    assert "grep -Fq 'SG Digital Systems' \"$body_file\"" in text


def test_no_installer_uses_curl_pipe_grep_q_for_placeholder_validation():
    scripts = [HTTP, HTTPS]
    for path in scripts:
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            assert not ("curl " in line and "| grep -q" in line), f"unsafe pipeline in {path}: {line}"
