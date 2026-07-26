from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_release_markers_are_rc68() -> None:
    assert '__version__ = "0.10.0-rc70"' in read("xpanel/__init__.py")
    assert "sg070" in read("xpanel/templates/base.html")
    assert "sg070" in read("xpanel/templates/login.html")
    assert 'EXPECTED_VERSION="0.10.0-rc70"' in read("install-or-upgrade.sh")
    assert 'EXPECTED_UI_REVISION="sg070"' in read("install-or-upgrade.sh")
    assert "SG-Panel RC70 — Latte light theme preview" in read("xpanel/static/app.css")


def test_proxy_experiment_is_removed_from_user_interface_and_backend() -> None:
    routing = read("xpanel/templates/routing.html")
    outbounds = read("xpanel/templates/outbounds.html")
    help_html = read("xpanel/templates/help.html")
    web = read("xpanel/web.py")
    service = read("xpanel/service.py")
    db = read("xpanel/db.py")

    user_runtime = "\n".join((routing, outbounds, help_html, web, service))
    for marker in (
        "exact-proxy-routing",
        "Добавить HTTP/SOCKS",
        "proxy_outbound",
        "routing_proxy_exact",
        "usher.ttvnw.net",
    ):
        assert marker not in user_runtime
    assert "CREATE TABLE IF NOT EXISTS proxy_outbounds" not in db


def test_russian_warp_presets_remain_without_duplication() -> None:
    service = read("xpanel/service.py")
    routing = read("xpanel/templates/routing.html")
    help_html = read("xpanel/templates/help.html")

    assert 'WARP_RUSSIA_TLDS = "geosite:tld-ru"' in service
    assert 'WARP_RUSSIA_DOMAINS = "geosite:category-ru"' in service
    assert 'WARP_RUSSIA_IPS = "geoip:ru"' in service
    assert "+ Добавить правило" in routing
    assert "geosite:category-ru" in help_html and "geoip:ru" in help_html


def test_cascade_clarity_and_copy_fallback_are_preserved() -> None:
    cascade = read("xpanel/templates/cascade.html")
    help_html = read("xpanel/templates/help.html")

    assert "Сделать этот сервер выходом" in cascade
    assert "Для текущей цепочки не нажимайте эту кнопку" in cascade
    assert "document.execCommand('copy')" in cascade
    assert "обычную ссылку из Clients входного сервера" in help_html


def test_light_theme_is_luxury_jade_depth() -> None:
    base = read("xpanel/templates/base.html")
    login = read("xpanel/templates/login.html")
    jade = read("xpanel/static/luxury-jade-depth.css")

    assert '<b>SG Luxury Jade Depth</b>' in base
    assert "Тема SG Luxury Jade Depth" in login
    assert "--jade-page: #E5ECE7" in jade
    assert "--jade-ivory-top: #FEFCF7" in jade
    assert "--jade-border: #89968A" in jade
    assert "--jade-text: #29312C" in jade
    assert "--jade-accent: #456F5C" in jade


def test_rc66_proxy_rows_are_removed_during_upgrade(tmp_path, monkeypatch) -> None:
    import sqlite3

    from xpanel.db import connect, init_db

    db = tmp_path / "panel.db"
    monkeypatch.setenv("XPANEL_DB", str(db))
    init_db()
    with connect() as con:
        con.execute(
            """
            CREATE TABLE proxy_outbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT ''
            )
            """
        )
        con.execute(
            "INSERT INTO proxy_outbounds (tag,name,protocol,enabled,address,port) "
            "VALUES ('smartproxy','Smartproxy','http',1,'proxy.example',7000)"
        )
        con.execute(
            "UPDATE routing_settings SET default_outbound_tag='smartproxy' WHERE id=1"
        )
        con.execute(
            "INSERT INTO routing_rules (name,priority,outbound_tag,domains,target_type) "
            "VALUES ('Legacy proxy rule',30,'smartproxy','full:example.com','outbound')"
        )

    init_db()
    with connect() as con:
        assert con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='proxy_outbounds'"
        ).fetchone() is None
        assert con.execute(
            "SELECT default_outbound_tag FROM routing_settings WHERE id=1"
        ).fetchone()[0] == "direct"
        assert con.execute(
            "SELECT COUNT(*) FROM routing_rules WHERE outbound_tag='smartproxy'"
        ).fetchone()[0] == 0
        assert con.execute(
            "SELECT 1 FROM schema_migrations WHERE name='rc67-remove-experimental-proxy'"
        ).fetchone() is not None
