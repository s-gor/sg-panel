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

    assert "v0.10.0-rc34" in readme
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
        for name in ("README.md", "RELEASE-NOTES-RC34.md")
    ) + "\n" + "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "docs").glob("*.md")
    )
    assert "пять доступных Inbound" not in current
    assert "все пять Inbound" not in current
    assert "сохраняет mode: auto" not in current
    assert "XHTTP/gRPC TLS" not in current
    assert "четыре доступных входящих профиля" in current
    for mode in ("auto", "packet-up", "stream-up", "stream-one"):
        assert mode in current
