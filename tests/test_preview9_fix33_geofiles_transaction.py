from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_destructive_remove_missing_mode_is_absent() -> None:
    checked = [
        ROOT / "xpanel",
        ROOT / "node_agent",
        ROOT / "deploy",
        ROOT / "docs",
        ROOT / "README.md",
    ]
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for item in checked
        for path in ([item] if item.is_file() else item.rglob("*"))
        if path.is_file() and path.suffix in {".py", ".html", ".md", ".sh"}
    ).lower()
    assert "remove_missing" not in text
    assert "compatibility_action" not in text


def test_clean_installer_does_not_run_distribution_upgrade_or_use_old_space_gate() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    first_install = (ROOT / "deploy" / "ec2-first-install.sh").read_text(encoding="utf-8")
    combined = installer + "\n" + first_install
    assert "dist-upgrade" not in combined
    assert "614400" not in combined
    assert "не менее 600 MiB" not in combined
    assert "apt-get -o DPkg::Lock::Timeout=900 -o Dpkg::Use-Pty=0 update -qq" in installer


def test_country_database_is_dedicated_and_not_live_routing_fallback() -> None:
    country_db = ROOT / "assets" / "geoip" / "sg-country-geoip.dat"
    assert country_db.is_file()
    assert country_db.stat().st_size > 4096
    web = (ROOT / "xpanel" / "web.py").read_text(encoding="utf-8")
    assert "sg-country-geoip.dat" in web
    country_section = web[web.index("def _bundled_geoip_country"):web.index("def _instance_country", web.index("def _bundled_geoip_country"))]
    assert "/usr/local/share/xray/geoip.dat" not in country_section
    assert "/usr/share/xray/geoip.dat" not in country_section


def test_node_worker_exposes_transactional_geofiles_operations() -> None:
    worker = (ROOT / "node_agent" / "sg_node_worker.py").read_text(encoding="utf-8")
    for operation in (
        "stage_geofiles",
        "validate_geofiles",
        "apply_geofiles",
        "rollback_geofiles",
        "get_geofiles_manifest",
    ):
        assert f'def {operation}(' in worker
    assert 'env["XRAY_LOCATION_ASSET"]' in worker
    assert "ensure_xray_active()" in worker
