from __future__ import annotations

from pathlib import Path
import hashlib
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OLD_PROCESS_MATCH = "pgrep -f '[u]nattended-upgrade' >/dev/null 2>&1"
REAL_WORKER_PATTERN = "(^|[[:space:]/])[u]nattended-upgrade([[:space:]]|$)"


def bash_executable() -> str:
    explicit = os.environ.get("SG_PANEL_TEST_BASH", "").strip()
    if explicit:
        candidate = Path(explicit)
        if not candidate.is_file():
            raise AssertionError(f"Explicit Git Bash not found: {candidate}")
        return str(candidate)
    detected = shutil.which("bash")
    if not detected:
        raise AssertionError("bash executable was not found")
    return detected


def run_bash(script: str) -> None:
    subprocess.run([bash_executable(), "-ceu", script], check=True)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_source_bootstrap_wait_contract() -> None:
    install = read("install.sh")
    core = read("deploy/ec2-first-install.sh")

    for body in (install, core):
        assert OLD_PROCESS_MATCH not in body
        assert REAL_WORKER_PATTERN in body
        assert "package_manager_busy_details" in body
        assert 'fuser "${locks[@]}"' not in body
        assert 'fuser "$lock"' in body
        assert "local waited=0 timeout=300" in body
        assert "APT/DPKG занят:" in body
        assert "APT/DPKG блокировка снята" in body
        assert "DPkg::Lock::Timeout=900" not in body
        assert "DPkg::Lock::Timeout=30" in body

    marker = install.index("/etc/cloud/cloud-init.disabled")
    wait = install.index("timeout 180 cloud-init status --wait")
    assert marker < wait
    assert "timeout 600 cloud-init status --wait" not in install
    assert "status:[[:space:]]*disabled" in install
    assert "cloud-init отключён marker-файлом; ожидание пропущено." in install
    assert "cloud-init сообщает status: disabled; ожидание пропущено." in install


def test_real_worker_regex_excludes_shutdown_waiter() -> None:
    script = r'''
pattern='(^|[[:space:]/])[u]nattended-upgrade([[:space:]]|$)'
printf '%s\n' '/usr/bin/python3 /usr/bin/unattended-upgrade' | grep -Eq "$pattern"
! printf '%s\n' '/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal' | grep -Eq "$pattern"
'''
    run_bash(script)


def _wait_functions(body: str) -> str:
    match = re.search(
        r"^wait_notice\(\)\{\n.*?^wait_for_apt\(\)\{\n.*?^\}\n",
        body,
        re.MULTILINE | re.DOTALL,
    )
    assert match
    return match.group(0)


def test_real_apt_lock_still_blocks() -> None:
    functions = _wait_functions(read("install.sh"))
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "installer.log"
        script = f'''set -Eeuo pipefail
LOG_FILE={str(log)!r}
fuser() {{ printf '4242\\n'; return 0; }}
ps() {{ printf 'apt-get install nginx\\n'; return 0; }}
{functions}
package_manager_busy
details="$(package_manager_busy_details)"
grep -Fq 'PID 4242' <<<"$details"
grep -Fq 'apt-get install nginx' <<<"$details"
'''
        run_bash(script)


def test_idle_shutdown_waiter_is_not_busy_fallback() -> None:
    functions = _wait_functions(read("install.sh"))
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "installer.log"
        script = f'''set -Eeuo pipefail
LOG_FILE={str(log)!r}
command() {{
  if [[ "$1" == "-v" && "$2" == "fuser" ]]; then return 1; fi
  builtin command "$@"
}}
pgrep() {{ return 1; }}
{functions}
! package_manager_busy
'''
        run_bash(script)


def test_full_wrapper_bootstrap_wait_contract() -> None:
    wrapper = read("SG-PANEL-UI23-CAP6-FULL-CLEAN.run")
    assert OLD_PROCESS_MATCH not in wrapper
    assert REAL_WORKER_PATTERN in wrapper
    assert "package_manager_busy_details" in wrapper
    assert "local waited=0 timeout=300" in wrapper
    assert "APT/DPKG занят:" in wrapper
    assert "DPkg::Lock::Timeout=900" not in wrapper
    assert "DPkg::Lock::Timeout=30" in wrapper
    assert re.search(r'^COMMIT="[0-9a-f]{40}"$', wrapper, re.MULTILINE)


def test_full_wrapper_sha_contract() -> None:
    installer = ROOT / "SG-PANEL-UI23-CAP6-FULL-CLEAN.run"
    expected = (ROOT / "SG-PANEL-UI23-CAP6-FULL-CLEAN.run.sha256").read_text(
        encoding="utf-8"
    ).split()[0]
    assert hashlib.sha256(installer.read_bytes()).hexdigest() == expected


def main() -> None:
    print(f"bash executable: {bash_executable()}")
    tests = [
        test_source_bootstrap_wait_contract,
        test_real_worker_regex_excludes_shutdown_waiter,
        test_real_apt_lock_still_blocks,
        test_idle_shutdown_waiter_is_not_busy_fallback,
    ]
    if os.environ.get("SOURCE_ONLY") != "1":
        tests.extend(
            [
                test_full_wrapper_bootstrap_wait_contract,
                test_full_wrapper_sha_contract,
            ]
        )
    for test in tests:
        test()
        print(f"{test.__name__}: OK")


if __name__ == "__main__":
    main()
