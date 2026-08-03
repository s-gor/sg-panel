from __future__ import annotations

from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1]
OLD_PROCESS_MATCH = "pgrep -f '[u]nattended-upgrade' >/dev/null 2>&1"
REAL_WORKER_PATTERN = "(^|[[:space:]/])[u]nattended-upgrade([[:space:]]|$)"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def shell_function(body: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\)\{{\n.*?^\}}\n",
        body,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"shell function not found: {name}"
    return match.group(0)


def worker_regex_for_python() -> re.Pattern[str]:
    # Production uses POSIX ERE. Python's equivalent is used only for
    # deterministic semantic samples; the exact production string is checked
    # separately in every installer source.
    translated = REAL_WORKER_PATTERN.replace("[[:space:]/]", r"[\s/]")
    translated = translated.replace("[[:space:]]", r"\s")
    return re.compile(translated)


def test_source_bootstrap_wait_contract() -> None:
    install = read("install.sh")
    core = read("deploy/ec2-first-install.sh")

    for body in (install, core):
        assert OLD_PROCESS_MATCH not in body
        assert REAL_WORKER_PATTERN in body
        assert "package_manager_busy_details" in body
        assert 'for lock in "${locks[@]}"; do' in body
        assert 'fuser "${locks[@]}"' not in body
        assert 'fuser "$lock"' in body
        assert "local waited=0 timeout=300" in body
        assert "APT/DPKG занят:" in body
        assert "APT/DPKG блокировка снята" in body
        assert "DPkg::Lock::Timeout=900" not in body
        assert "DPkg::Lock::Timeout=30" in body

        details = shell_function(body, "package_manager_busy_details")
        assert "unattended-upgrade-shutdown" not in details
        assert f"pgrep -a -f '{REAL_WORKER_PATTERN}'" in details
        assert "PID %s" in details
        assert "command_line" in details

    marker = install.index("/etc/cloud/cloud-init.disabled")
    wait = install.index("timeout 180 cloud-init status --wait")
    assert marker < wait
    assert "timeout 600 cloud-init status --wait" not in install
    assert "status:[[:space:]]*disabled" in install
    assert "cloud-init отключён marker-файлом; ожидание пропущено." in install
    assert "cloud-init сообщает status: disabled; ожидание пропущено." in install


def test_real_worker_regex_excludes_shutdown_waiter() -> None:
    pattern = worker_regex_for_python()
    real_worker = "/usr/bin/python3 /usr/bin/unattended-upgrade"
    shutdown_waiter = (
        "/usr/bin/python3 "
        "/usr/share/unattended-upgrades/unattended-upgrade-shutdown "
        "--wait-for-signal"
    )
    regex_command_itself = (
        "pgrep -a -f "
        "'(^|[[:space:]/])[u]nattended-upgrade([[:space:]]|$)'"
    )

    assert pattern.search(real_worker)
    assert not pattern.search(shutdown_waiter)
    assert not pattern.search(regex_command_itself)


def test_real_apt_lock_contract_is_preserved() -> None:
    for relative in ("install.sh", "deploy/ec2-first-install.sh"):
        details = shell_function(read(relative), "package_manager_busy_details")
        assert 'pids="$(fuser "$lock" 2>/dev/null || true)"' in details
        assert "[[ -n \"$pids\" ]] || continue" in details
        assert "found=1" in details
        assert 'ps -p "$pid" -o args=' in details
        assert "(( found == 1 )) && return 0" in details


def test_idle_shutdown_waiter_is_not_a_busy_fallback() -> None:
    for relative in ("install.sh", "deploy/ec2-first-install.sh"):
        details = shell_function(read(relative), "package_manager_busy_details")
        assert "pgrep -a -x apt" in details
        assert "pgrep -a -x apt-get" in details
        assert "pgrep -a -x dpkg" in details
        assert REAL_WORKER_PATTERN in details
        assert "unattended-upgrade-shutdown" not in details


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
    tests = [
        test_source_bootstrap_wait_contract,
        test_real_worker_regex_excludes_shutdown_waiter,
        test_real_apt_lock_contract_is_preserved,
        test_idle_shutdown_waiter_is_not_a_busy_fallback,
        test_full_wrapper_bootstrap_wait_contract,
        test_full_wrapper_sha_contract,
    ]
    for test in tests:
        test()
        print(f"{test.__name__}: OK")


if __name__ == "__main__":
    main()
