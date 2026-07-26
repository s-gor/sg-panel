from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(script: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}\(\)\{{(?P<body>.*?)\n\}}", script, re.S)
    assert match, f"function not found: {name}"
    return match.group("body")


def assert_three_active_lines(body: str) -> None:
    assert body.count("[SG-Panel] SG-Panel:") == 1
    assert body.count("[SG-Panel] Nginx:") == 1
    assert body.count("[SG-Panel] Xray:") == 1
    assert body.count("active%s") == 3
    assert "Полный журнал" not in body
    assert "Журнал внутренней установки" not in body
    assert "Резервная копия" not in body
    assert "ГОТОВО" not in body


def test_outer_full_installer_ends_with_only_three_service_lines() -> None:
    script = read("install.sh")
    assert_three_active_lines(function_body(script, "show_result"))
    assert script.rstrip().endswith('main "$@"')


def test_nested_updater_can_suppress_its_own_success_summary() -> None:
    script = read("install-or-upgrade.sh")
    final = script[script.index("  ROLLBACK_NEEDED=0") :]
    assert '${SG_PANEL_SUPPRESS_SUCCESS_SUMMARY:-0}' in final
    assert_three_active_lines(final)
    assert "Полный журнал" not in final
    assert "Резервная копия:" not in final


def test_ec2_master_owns_the_success_summary_and_suppresses_updater() -> None:
    script = read("deploy/ec2-first-install.sh")
    assert script.count("SG_PANEL_SUPPRESS_SUCCESS_SUMMARY=1") == 2
    assert_three_active_lines(function_body(script, "print_service_summary"))
    assert "EOF_UPDATE" not in script
    assert "EOF_RESULT" not in script
    assert script.rstrip().endswith("print_service_summary")


def test_error_paths_still_show_diagnostic_log_locations() -> None:
    full = read("install.sh")
    updater = read("install-or-upgrade.sh")
    assert "Полный журнал: %s" in function_body(full, "fail")
    assert "Журнал внутренней установки: %s" in function_body(full, "fail")
    assert "Полный журнал: %s" in function_body(updater, "show_failure")
