from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"


def _installer_without_main() -> str:
    text = INSTALL.read_text(encoding="utf-8")
    marker = '\nmain "$@"\n'
    assert marker in text
    return text.replace(marker, "\n", 1)


def test_installer_auto_detects_ec2_public_ipv4_after_bootstrap_and_before_prompt() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    detect = text.index("detect_public_ipv4(){")
    prompt = text.index('prompt_default "Адрес панели и Xray')
    main = text[text.index("main(){"):]
    assert detect < prompt
    assert main.index('run_step "Этап 4/7 · Определение публичного адреса"') < main.index("collect_inputs")
    assert "ds.meta_data.public_ipv4 ds.meta_data.public-ipv4" in text
    assert "AWS IMDSv2 first" in text
    assert text.index("AWS IMDSv2 first") < text.index("if command -v curl")
    assert "X-aws-ec2-metadata-token-ttl-seconds" in text
    assert "Публичный IPv4 EC2 определён автоматически" in text


def test_detect_public_ipv4_uses_cloud_init_default(tmp_path: Path) -> None:
    fake = tmp_path / "cloud-init"
    fake.write_text("#!/usr/bin/env bash\necho 18.184.108.124\n", encoding="utf-8")
    fake.chmod(0o755)
    shell = _installer_without_main() + '\nPATH="$FAKE_BIN:$PATH"\nvalue="$(detect_public_ipv4)"\ntrap - EXIT\nprintf %s "$value"\n'
    result = subprocess.run(
        ["bash", "-c", shell],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "TERM": "dumb", "FAKE_BIN": str(tmp_path)},
    )
    assert result.stdout == "18.184.108.124"


def test_public_host_validation_rejects_private_and_malformed_ipv4() -> None:
    shell = _installer_without_main() + r'''
for value in 18.184.108.124 panel.example.com; do
  is_valid_public_host "$value" || exit 10
done
for value in 10.0.0.1 192.168.1.1 999.999.999.999; do
  if is_valid_public_host "$value"; then exit 20; fi
done
trap - EXIT
'''
    subprocess.run(["bash", "-c", shell], check=True, text=True, capture_output=True)


def test_clean_installer_does_not_require_curl_for_ec2_metadata() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    block = text[text.index("detect_public_ipv4(){"):text.index("collect_inputs(){")]
    assert "python3" in block
    assert "urllib.request" in block
    assert "latest/api/token" in block
    assert "latest/meta-data/public-ipv4" in block
    assert "checkip.amazonaws.com" in block
    assert "api.ipify.org" in block
