from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def markdown_files() -> list[Path]:
    return sorted([*ROOT.glob("*.md"), *(ROOT / "docs").glob("*.md")])


def test_rc34_documentation_describes_real_update_workflow():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    installation = (ROOT / "docs" / "INSTALLATION.md").read_text(encoding="utf-8")
    maintenance = (ROOT / "docs" / "MAINTENANCE.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC34.md").read_text(encoding="utf-8")

    assert "v0.10.0-rc70" in readme
    assert "Maintenance → Updates" in readme
    assert "Проверить сейчас" in readme
    assert "автоматический rollback" in readme
    assert "Порт панели [61443]:" in installation
    assert "просто нажмите **Enter**" in installation
    assert "первый переход с RC30 на RC34" in maintenance
    assert "/root/sg-panel-backups/YYYYMMDD-HHMMSS-update-rollback" in maintenance
    assert "локальный `/health`" in maintenance
    assert "RC31, RC32 и RC33 не используются" in release


def test_port_443_wording_includes_vless_and_https_placeholder():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flows = (ROOT / "docs" / "TRAFFIC-FLOWS.md").read_text(encoding="utf-8")
    assert "VLESS и обычный HTTPS/fallback на локальный Nginx с SG-заглушкой" in readme
    assert "VLESS и обычный HTTPS/fallback на локальную SG-заглушку" in flows
    assert "VLESS или HTTPS/fallback" not in readme
    assert "VLESS или HTTPS/fallback" not in flows


def test_all_relative_markdown_links_resolve_and_fences_are_balanced():
    link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        assert text.count("```") % 2 == 0, f"unbalanced code fence: {path}"
        for raw in link_pattern.findall(text):
            target = raw.split("#", 1)[0].strip()
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = (path.parent / target).resolve()
            assert resolved.exists(), f"broken link in {path}: {raw}"


def test_current_user_docs_do_not_reintroduce_old_profile_count_or_fixed_xhttp_mode():
    current = "\n".join(
        (ROOT / name).read_text(encoding="utf-8")
        for name in ("README.md", "RELEASE-NOTES-RC34.md", "RELEASE-NOTES-RC35.md", "RELEASE-NOTES-RC36.md", "RELEASE-NOTES-RC37.md", "RELEASE-NOTES-RC38.md", "RELEASE-NOTES-RC39.md", "RELEASE-NOTES-RC40.md", "RELEASE-NOTES-RC41.md", "RELEASE-NOTES-RC42.md", "RELEASE-NOTES-RC43.md", "RELEASE-NOTES-RC44.md", "RELEASE-NOTES-RC45.md")
    ) + "\n" + "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "docs").glob("*.md")
    )
    assert "пять доступных Inbound" not in current
    assert "все пять Inbound" not in current
    assert "сохраняет mode: auto" not in current
    assert "XHTTP/gRPC TLS" not in current
    assert "пять доступных входящих профилей" in current
    for mode in ("auto", "packet-up", "stream-up", "stream-one"):
        assert mode in current


def test_rc37_docs_describe_multi_hysteria_constraints():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    server = (ROOT / "docs" / "SERVER.md").read_text(encoding="utf-8")
    clients = (ROOT / "docs" / "CLIENTS.md").read_text(encoding="utf-8")
    diagnostics = (ROOT / "docs" / "DIAGNOSTICS.md").read_text(encoding="utf-8")
    json_editor = (ROOT / "docs" / "JSON-EDITOR.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC37.md").read_text(encoding="utf-8")

    for value in (readme, server, release):
        assert "до трёх hysteria 2" in value.lower()
        assert "8443" in value
        assert "9443" in value
    assert "все включённые Hysteria 2-ссылки" in clients
    assert "каждого UDP-listener" in diagnostics
    assert "Дополнительные Hysteria 2 Inbound управляются" in json_editor
    assert "port hopping" in release.lower()


def test_rc38_docs_describe_safe_xray_update():
    maintenance = (ROOT / "docs" / "MAINTENANCE.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC38.md").read_text(encoding="utf-8")
    for value in (maintenance, release):
        assert "Stable" in value
        assert "Pre-release" in value
        assert ".dgst" in value
        assert "SHA-256" in value
        assert "автомат" in value.lower() and "откат" in value.lower()
    assert "не понижают" in maintenance


def test_rc39_docs_describe_multi_xhttp_constraints():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    server = (ROOT / "docs" / "SERVER.md").read_text(encoding="utf-8")
    clients = (ROOT / "docs" / "CLIENTS.md").read_text(encoding="utf-8")
    diagnostics = (ROOT / "docs" / "DIAGNOSTICS.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC39.md").read_text(encoding="utf-8")

    for value in (readme, server, release):
        assert "до трёх" in value.lower()
        assert "8444" in value
        assert "8445" in value
        assert "Path" in value
    assert "все включённые XHTTP-ссылки" in clients
    assert "каждый включённый локальный XHTTP listener" in diagnostics
    assert "смешанный" in release.lower()


def test_rc40_docs_describe_mixed_xhttp_hysteria_and_layout_fix():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    server = (ROOT / "docs" / "SERVER.md").read_text(encoding="utf-8")
    clients = (ROOT / "docs" / "CLIENTS.md").read_text(encoding="utf-8")
    diagnostics = (ROOT / "docs" / "DIAGNOSTICS.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC40.md").read_text(encoding="utf-8")

    for value in (readme, server, release):
        assert "XHTTP-TLS + Hysteria 2" in value
        assert "TCP" in value and "UDP" in value
        assert "8443" in value
    assert "шесть" in clients
    assert "разным транспортам" in diagnostics
    assert "адаптив" in release.lower()


def test_rc41_docs_describe_multi_reality_and_vision():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    server = (ROOT / "docs" / "SERVER.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC41.md").read_text(encoding="utf-8")
    for value in (readme, server, release):
        assert "до трёх" in value.lower()
        assert "REALITY" in value
        assert "Vision" in value
        assert "Short ID" in value
    assert "не смешивается с Hysteria 2" in release


def test_rc42_docs_describe_saved_links_and_live_installer():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    clients = (ROOT / "docs" / "CLIENTS.md").read_text(encoding="utf-8")
    installation = (ROOT / "docs" / "INSTALLATION.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC42.md").read_text(encoding="utf-8")
    for value in (readme, clients, release):
        assert "Primary" in value and "Backup" in value and "Alt" in value
        assert "неактив" in value.lower()
        assert "подпис" in value.lower()
    assert "пароль администратора" in installation
    assert "вертуш" in installation
    assert "/var/log/sg-panel-install-" in installation


def test_rc43_docs_describe_builtin_help_and_profile_names():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC43.md").read_text(encoding="utf-8")
    help_template = (ROOT / "xpanel/templates/help.html").read_text(encoding="utf-8")
    for value in (readme, release, help_template):
        assert "VLESS REALITY" in value
        assert "VLESS XHTTP-TLS" in value
        assert "VLESS XHTTP-REALITY" in value
        assert "Hysteria 2" in value
        assert "XHTTP-TLS + Hysteria 2" in value
    assert "встроенн" in readme.lower() and "справ" in readme.lower()
    assert "XTLS Vision" in help_template
    assert "Сохранённые, но неактивные" in help_template


def test_rc44_docs_describe_clear_profile_choice_and_light_theme():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release = (ROOT / "RELEASE-NOTES-RC44.md").read_text(encoding="utf-8")
    settings = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")
    for value in (readme, release, settings):
        assert "REALITY · без сертификата" in value
        assert "TLS · нужен сертификат" in value
    assert "Работает сейчас" in settings
    assert "Выбрано, ещё не применено" in settings
    assert "светл" in release.lower()
