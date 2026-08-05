from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import service
from .db import connect, use_db_path


MANAGED_OWNERS = (
    service.UNIFIED_ROUTING_MANAGED_BY,
    "roscomvpn-server-preset",
)


def _source_values(values: dict[str, object]) -> dict[str, str]:
    source = str(values.get("source") or "sgclient").strip().lower()
    return service._source_values(
        source,
        str(values.get("geoip_url") or "") if source == "custom" else "",
        str(values.get("geosite_url") or "") if source == "custom" else "",
        str(values.get("geoip_local_path") or "") if source == "local" else "",
        str(values.get("geosite_local_path") or "") if source == "local" else "",
    )


def _stage_pair(stage: Path, cleaned: dict[str, str]) -> dict[str, object]:
    source = cleaned["source"]
    geoip = stage / "geoip.dat"
    geosite = stage / "geosite.dat"

    if source == "sgclient":
        bundled_geoip = service.GEOFILES_BUNDLED_DIR / "geoip.dat"
        bundled_geosite = service.GEOFILES_BUNDLED_DIR / "geosite.dat"
        for bundled in (bundled_geoip, bundled_geosite):
            if not bundled.is_file():
                raise service.XPanelError(
                    "в установке SG-Panel отсутствует штатный комплект SG-Client"
                )
            expected = service.GEOFILES_BUNDLED_SHA256[bundled.name]
            if service._sha256_file(bundled) != expected:
                raise service.XPanelError(
                    f"штатный {bundled.name} повреждён: SHA-256 не совпадает"
                )
        service._copy_or_download_geofile(source, str(bundled_geoip), geoip)
        service._copy_or_download_geofile(source, str(bundled_geosite), geosite)
    elif source == "local":
        service._copy_or_download_geofile(
            source, cleaned["geoip_local_path"], geoip
        )
        service._copy_or_download_geofile(
            source, cleaned["geosite_local_path"], geosite
        )
    else:
        service._copy_or_download_geofile(source, cleaned["geoip_url"], geoip)
        service._copy_or_download_geofile(
            source, cleaned["geosite_url"], geosite
        )

    analysis = service._analyze_geofile_pair(geoip, geosite)
    service._run_geofiles_structural_test(geoip, geosite, analysis)
    return analysis


def _add_rule(
    specs: list[dict[str, object]],
    role: str,
    tag: str,
    *,
    domains: list[str] | tuple[str, ...] = (),
    ips: list[str] | tuple[str, ...] = (),
) -> None:
    clean_domains = [str(item) for item in domains if str(item)]
    clean_ips = [str(item) for item in ips if str(item)]
    if not clean_domains and not clean_ips:
        return
    name, priority = service.UNIFIED_ROUTING_RULES[role]
    specs.append(
        {
            "role": role,
            "name": name,
            "priority": priority,
            "outbound_tag": tag,
            "domains": clean_domains,
            "ips": clean_ips,
        }
    )


def _first(categories: list[str], preferred: tuple[str, ...]) -> str:
    return service._select_unified_category(categories, preferred)


def _rule_plan(
    model: dict[str, object],
    analysis: dict[str, object],
) -> tuple[list[dict[str, object]], list[str], dict[str, list[str]]]:
    geoip_categories = [str(item) for item in analysis["geoip_categories"]]
    geosite_categories = [str(item) for item in analysis["geosite_categories"]]
    geoip = set(geoip_categories)
    geosite = set(geosite_categories)
    family = str(analysis.get("family") or "Пользовательский")

    specs: list[dict[str, object]] = []
    warnings: list[str] = []
    selected: dict[str, list[str]] = {
        "russia": [],
        "blocked": [],
        "ads": [],
    }

    _add_rule(
        specs,
        "custom-direct",
        "direct",
        domains=list(model.get("custom_direct_domains", [])),
        ips=list(model.get("custom_direct_ips", [])),
    )
    _add_rule(
        specs,
        "custom-warp",
        service.WARP_TAG,
        domains=list(model.get("custom_warp_domains", [])),
        ips=list(model.get("custom_warp_ips", [])),
    )
    _add_rule(
        specs,
        "custom-block",
        "blocked",
        domains=list(model.get("custom_block_domains", [])),
        ips=list(model.get("custom_block_ips", [])),
    )
    _add_rule(
        specs,
        "local",
        str(model["local_action"]),
        ips=service.UNIFIED_LOCAL_IPS,
    )

    scope = str(model["russia_scope"])
    if scope == "tld":
        if "tld-ru" not in geosite:
            raise service.XPanelError(
                "выбранная пара не содержит отдельную категорию geosite:tld-ru. "
                "Выберите «Сайты и IP» либо другой комплект GeoFiles"
            )
        selected["russia"] = ["geosite:tld-ru"]
        _add_rule(
            specs,
            "russia",
            str(model["russia_action"]),
            domains=["geosite:tld-ru"],
        )
    elif scope == "sites_ip":
        if family == "RoscomVPN":
            domains = [
                f"geosite:{item}"
                for item in ("category-ru", "whitelist")
                if item in geosite
            ]
            ips = [
                f"geoip:{item}"
                for item in ("direct", "whitelist")
                if item in geoip
            ]
            if not domains and not ips:
                raise service.XPanelError(
                    "RoscomVPN не содержит категорий для российского набора"
                )
        else:
            missing: list[str] = []
            domains = ["geosite:category-ru"] if "category-ru" in geosite else []
            ips = ["geoip:ru"] if "ru" in geoip else []
            if not domains:
                missing.append("geosite:category-ru")
            if not ips:
                missing.append("geoip:ru")
            if missing:
                raise service.XPanelError(
                    "для набора «Сайты и IP» отсутствуют категории: "
                    + ", ".join(missing)
                )
        selected["russia"] = [*domains, *ips]
        _add_rule(
            specs,
            "russia",
            str(model["russia_action"]),
            domains=domains,
            ips=ips,
        )

    default_action = str(model["default_action"])

    blocked_action = str(model["blocked_action"])
    if blocked_action != default_action:
        category = _first(
            geosite_categories,
            service.UNIFIED_BLOCKED_GEOSITE_CANDIDATES,
        )
        if category:
            value = f"geosite:{category}"
            selected["blocked"] = [value]
            _add_rule(
                specs,
                "blocked",
                blocked_action,
                domains=[value],
            )
        else:
            warnings.append(
                "В выбранной паре нет отдельной категории ресурсов, "
                "заблокированных в РФ. Правило не будет создано"
            )

    ads_action = str(model["ads_action"])
    if ads_action != default_action:
        category = _first(
            geosite_categories,
            service.UNIFIED_ADS_GEOSITE_CANDIDATES,
        )
        if category:
            value = f"geosite:{category}"
            selected["ads"] = [value]
            _add_rule(specs, "ads", ads_action, domains=[value])
        else:
            warnings.append(
                "В выбранной паре нет категории рекламы и трекеров. "
                "Правило не будет создано"
            )

    return specs, warnings, selected


def _write_candidate_routing(
    model: dict[str, object],
    specs: list[dict[str, object]],
    values: dict[str, object],
) -> None:
    settings = service.get_routing_settings()
    domain_strategy = str(
        values.get("domain_strategy") or settings["domain_strategy"]
    )
    if domain_strategy not in service.ALLOWED_DOMAIN_STRATEGIES:
        raise ValueError("некорректная domainStrategy")

    extra = service._routing_extra_with_metadata()
    meta = extra.get("_sgPanel")
    if not isinstance(meta, dict):
        meta = {}
    meta[service.UNIFIED_ROUTING_META_KEY] = model
    extra["_sgPanel"] = meta

    with connect() as con:
        manual_names = {
            str(row["name"]).casefold()
            for row in con.execute(
                "SELECT name,managed_by FROM routing_rules"
            )
            if str(row["managed_by"] or "") not in MANAGED_OWNERS
        }
        conflicts = [
            str(spec["name"])
            for spec in specs
            if str(spec["name"]).casefold() in manual_names
        ]
        if conflicts:
            raise service.XPanelError(
                "Переименуйте пользовательские правила, занявшие служебные имена: "
                + ", ".join(conflicts)
            )

        con.execute("BEGIN IMMEDIATE")
        try:
            con.execute(
                "DELETE FROM routing_rules WHERE managed_by IN (?,?)",
                MANAGED_OWNERS,
            )
            con.execute(
                """
                UPDATE routing_settings SET
                    domain_strategy=?,
                    default_outbound_tag=?,
                    extra_json=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=1
                """,
                (
                    domain_strategy,
                    str(model["default_action"]),
                    json.dumps(
                        extra,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                ),
            )
            for spec in specs:
                con.execute(
                    """
                    INSERT INTO routing_rules
                        (name,priority,enabled,outbound_tag,target_type,
                         domains,ips,ports,network,protocols,inbound_tags,
                         users,config_json,managed_by,managed_role)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        spec["name"],
                        spec["priority"],
                        1,
                        spec["outbound_tag"],
                        "outbound",
                        "\n".join(spec["domains"]),
                        "\n".join(spec["ips"]),
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        service.UNIFIED_ROUTING_MANAGED_BY,
                        spec["role"],
                    ),
                )
            con.commit()
        except Exception:
            con.rollback()
            raise


def _manual_rules() -> list[dict[str, object]]:
    with connect() as con:
        rows = con.execute(
            """
            SELECT name,priority,enabled,outbound_tag,domains,ips,protocols
            FROM routing_rules
            WHERE managed_by NOT IN (?,?)
            ORDER BY priority,id
            """,
            MANAGED_OWNERS,
        ).fetchall()
    return [dict(row) for row in rows]


STAGE_ROOT = service.GEOFILES_STATE_DIR / "unified-preview4-staging"
STAGE_MANIFEST = STAGE_ROOT / "manifest.json"


def _json_values(values: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values.items():
        if isinstance(value, bool):
            result[str(key)] = value
        elif isinstance(value, (str, int, float)) or value is None:
            result[str(key)] = value
        elif isinstance(value, (list, tuple)):
            result[str(key)] = [str(item) for item in value]
        else:
            result[str(key)] = str(value)
    return result


def _build_candidate_from_stage(
    stage: Path,
    values: dict[str, object],
    analysis: dict[str, object],
) -> dict[str, object]:
    cleaned = _source_values(values)
    source = cleaned["source"]
    source_info = service.GEOFILES_SOURCES[source]
    candidate_db = stage / "candidate.db"
    service._clone_current_database(candidate_db)

    try:
        with use_db_path(candidate_db):
            model = service._normalise_unified_routing_values(**values)
            specs, warnings, selected = _rule_plan(model, analysis)
            _write_candidate_routing(model, specs, values)

            config_text, server, users = service.render_text()
            try:
                document = json.loads(config_text)
            except json.JSONDecodeError as exc:
                raise service.XPanelError(
                    f"полный будущий config.json не удалось разобрать: {exc}"
                ) from exc

            compatibility = service._geofiles_compatibility(
                list(analysis["geoip_categories"]),
                list(analysis["geosite_categories"]),
                config_document=document,
            )
            manual_rules = _manual_rules()

            result: dict[str, object] = {
                "status": "blocked",
                "source": source,
                "source_label": str(source_info["label"]).replace(
                    "SG Client", "SG-Client"
                ),
                "family": str(analysis["family"]),
                "geoip_count": len(analysis["geoip_categories"]),
                "geosite_count": len(analysis["geosite_categories"]),
                "selected_categories": selected,
                "managed_rules": specs,
                "manual_rules": manual_rules,
                "warnings": warnings,
                "missing_categories": list(
                    compatibility["missing_categories"]
                ),
                "missing_details": list(
                    compatibility["missing_routing_details"]
                ),
                "missing_nonrouting": list(
                    compatibility["missing_nonrouting_categories"]
                ),
                "xray_test": "not-run",
                "checked_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
                "model": model,
                "cleaned_source": cleaned,
            }

            if not compatibility["compatible"]:
                result["message"] = (
                    "Полный candidate заблокирован отсутствующими категориями"
                )
                return result

            candidate_path = stage / "candidate-config.json"
            candidate_path.write_text(config_text, encoding="utf-8")
            xray = service._run_xray_test_with_assets(
                str(server["xray_bin"]),
                candidate_path,
                stage,
            )
            if xray.returncode != 0:
                detail = (xray.stderr or xray.stdout or "").strip()
                result["message"] = (
                    "Xray отклонил полный будущий config.json: "
                    + (detail or "неизвестная ошибка")
                )
                result["xray_test"] = "failed"
                return result

            result.update(
                {
                    "status": "ok",
                    "message": (
                        "Пара GeoFiles, будущий Routing и полный Xray config "
                        "совместимы"
                    ),
                    "xray_test": "ok",
                    "config_sha256": hashlib.sha256(
                        config_text.encode("utf-8")
                    ).hexdigest(),
                    "users": len(users),
                    "config_text": config_text,
                }
            )
            return result
    finally:
        candidate_db.unlink(missing_ok=True)


def _public_result(result: dict[str, object]) -> dict[str, object]:
    hidden = {"config_text", "model", "cleaned_source"}
    return {key: value for key, value in result.items() if key not in hidden}


def validate_plan(values: dict[str, object]) -> dict[str, object]:
    with service._geofiles_operation_lock("проверку единого плана"):
        if STAGE_ROOT.exists():
            shutil.rmtree(STAGE_ROOT)
        STAGE_ROOT.mkdir(parents=True, exist_ok=True)
        cleaned = _source_values(values)
        analysis = _stage_pair(STAGE_ROOT, cleaned)
        result = _build_candidate_from_stage(STAGE_ROOT, values, analysis)

        if result["status"] != "ok":
            STAGE_MANIFEST.unlink(missing_ok=True)
            return _public_result(result)

        token = secrets.token_urlsafe(32)
        manifest = {
            "version": 1,
            "token": token,
            "values": _json_values(values),
            "source": cleaned,
            "analysis": {
                "family": str(analysis["family"]),
                "geoip_categories": list(analysis["geoip_categories"]),
                "geosite_categories": list(analysis["geosite_categories"]),
            },
            "managed_rules": result["managed_rules"],
            "selected_categories": result["selected_categories"],
            "warnings": result["warnings"],
            "config_sha256": result["config_sha256"],
            "geoip_sha256": service._sha256_file(STAGE_ROOT / "geoip.dat"),
            "geosite_sha256": service._sha256_file(STAGE_ROOT / "geosite.dat"),
            "checked_at": result["checked_at"],
        }
        service._write_json_atomic(STAGE_MANIFEST, manifest)
        public = _public_result(result)
        public["candidate_token"] = token
        return public


def _read_checked_manifest(token: str) -> dict[str, object]:
    if not token or not STAGE_MANIFEST.is_file():
        raise service.XPanelError(
            "проверенный единый plan отсутствует; выполните проверку снова"
        )
    try:
        manifest = json.loads(STAGE_MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise service.XPanelError("manifest проверенного плана повреждён") from exc
    if not secrets.compare_digest(str(manifest.get("token") or ""), token):
        raise service.XPanelError(
            "результат проверки устарел; выполните проверку снова"
        )
    for name in ("geoip.dat", "geosite.dat"):
        if not (STAGE_ROOT / name).is_file():
            raise service.XPanelError(
                "проверенная пара GeoFiles отсутствует; выполните проверку снова"
            )
    if service._sha256_file(STAGE_ROOT / "geoip.dat") != str(
        manifest.get("geoip_sha256") or ""
    ):
        raise service.XPanelError(
            "geoip.dat изменился после проверки; выполните проверку снова"
        )
    if service._sha256_file(STAGE_ROOT / "geosite.dat") != str(
        manifest.get("geosite_sha256") or ""
    ):
        raise service.XPanelError(
            "geosite.dat изменился после проверки; выполните проверку снова"
        )
    return manifest


def checked_geofiles_update_status(token: str) -> dict[str, object]:
    """Compare a successfully checked staging pair with the active pair."""
    with service._geofiles_operation_lock("сравнение обновления GeoFiles"):
        manifest = _read_checked_manifest(token)
        active_geoip, active_geosite = service._current_asset_paths()
        if not active_geoip.is_file() or not active_geosite.is_file():
            raise service.XPanelError(
                "активная связанная пара GeoFiles отсутствует"
            )

        active_geoip_sha256 = service._sha256_file(active_geoip)
        active_geosite_sha256 = service._sha256_file(active_geosite)
        candidate_geoip_sha256 = str(manifest.get("geoip_sha256") or "")
        candidate_geosite_sha256 = str(
            manifest.get("geosite_sha256") or ""
        )
        geoip_changed = active_geoip_sha256 != candidate_geoip_sha256
        geosite_changed = (
            active_geosite_sha256 != candidate_geosite_sha256
        )
        changed = geoip_changed or geosite_changed

        result = {
            "status": (
                "geofiles_update_ready"
                if changed
                else "geofiles_current"
            ),
            "message": (
                "Найдена новая связанная пара GeoFiles"
                if changed
                else "Установленная связанная пара GeoFiles актуальна"
            ),
            "checked_at": str(manifest.get("checked_at") or ""),
            "geoip_changed": geoip_changed,
            "geosite_changed": geosite_changed,
            "active_geoip_sha256": active_geoip_sha256,
            "active_geosite_sha256": active_geosite_sha256,
            "candidate_geoip_sha256": candidate_geoip_sha256,
            "candidate_geosite_sha256": candidate_geosite_sha256,
        }

        if not changed:
            shutil.rmtree(STAGE_ROOT, ignore_errors=True)

        return result


def _update_geofiles_settings(
    manifest: dict[str, object],
    generation: str,
    active_geoip: Path,
    active_geosite: Path,
    applied_manifest: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    source_data = dict(manifest["source"])
    source = str(source_data["source"])
    geoip_info = service._geofile_info(active_geoip)
    geosite_info = service._geofile_info(active_geosite)
    with connect() as con:
        con.execute(
            """
            UPDATE geofiles_settings SET source=?, geoip_url=?, geosite_url=?,
                geoip_local_path=?, geosite_local_path=?, active_geoip_path=?,
                active_geosite_path=?, active_geoip_sha256=?,
                active_geosite_sha256=?, active_geoip_size=?,
                active_geosite_size=?, active_source=?, staged_manifest_json=?,
                active_generation=?, active_manifest_json=?,
                last_applied_at=CURRENT_TIMESTAMP, last_check_state='ok',
                last_check_message='Единый план Routing + GeoFiles + Xray применён',
                updated_at=CURRENT_TIMESTAMP WHERE id=1
            """,
            (
                source,
                str(source_data.get("geoip_url") or ""),
                str(source_data.get("geosite_url") or ""),
                str(source_data.get("geoip_local_path") or ""),
                str(source_data.get("geosite_local_path") or ""),
                str(active_geoip),
                str(active_geosite),
                geoip_info["sha256"],
                geosite_info["sha256"],
                geoip_info["size"],
                geosite_info["size"],
                source,
                json.dumps(applied_manifest, ensure_ascii=False),
                generation,
                json.dumps(applied_manifest, ensure_ascii=False),
            ),
        )
    return geoip_info, geosite_info


def apply_checked_plan(token: str) -> dict[str, object]:
    service.require_root()
    with service._geofiles_operation_lock("применение единого плана"):
        manifest = _read_checked_manifest(token)
        values = dict(manifest["values"])
        analysis = {
            "family": str(dict(manifest["analysis"])["family"]),
            "geoip_categories": list(
                dict(manifest["analysis"])["geoip_categories"]
            ),
            "geosite_categories": list(
                dict(manifest["analysis"])["geosite_categories"]
            ),
        }
        service._run_geofiles_structural_test(
            STAGE_ROOT / "geoip.dat",
            STAGE_ROOT / "geosite.dat",
            analysis,
        )
        candidate = _build_candidate_from_stage(STAGE_ROOT, values, analysis)
        if candidate["status"] != "ok":
            raise service.XPanelError(str(candidate["message"]))
        if str(candidate["config_sha256"]) != str(
            manifest.get("config_sha256") or ""
        ):
            raise service.XPanelError(
                "Routing, Outbounds или Xray-настройки изменились после проверки; "
                "рабочее состояние не изменено, выполните проверку снова"
            )
        if candidate["managed_rules"] != manifest.get("managed_rules"):
            raise service.XPanelError(
                "будущие служебные правила изменились после проверки; "
                "выполните проверку снова"
            )

        candidate_text = str(candidate["config_text"])
        candidate_sha256 = str(candidate["config_sha256"])
        model = dict(candidate["model"])
        specs = list(candidate["managed_rules"])
        source_data = dict(manifest["source"])
        source = str(source_data["source"])

        active_geoip, active_geosite = service._current_asset_paths()
        if active_geoip.parent.resolve() != active_geosite.parent.resolve():
            raise service.XPanelError(
                "активные geoip.dat и geosite.dat должны находиться в одном каталоге"
            )
        active_geoip.parent.mkdir(parents=True, exist_ok=True)
        service._preserve_original_xray_assets()
        server = service.get_server()
        config_path = Path(str(server["config_path"]))
        xray_service = str(server["xray_service"])
        config_path.parent.mkdir(parents=True, exist_ok=True)

        generation = (
            datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
            + "-unified-"
            + candidate_sha256[:12]
        )
        generation_dir = service.GEOFILES_STATE_DIR / "sets" / generation
        generation_dir.mkdir(parents=True, exist_ok=False)
        shutil.copy2(STAGE_ROOT / "geoip.dat", generation_dir / "geoip.dat")
        shutil.copy2(STAGE_ROOT / "geosite.dat", generation_dir / "geosite.dat")
        (generation_dir / "config.json").write_text(
            candidate_text, encoding="utf-8"
        )
        source_label = str(
            service.GEOFILES_SOURCES[source]["label"]
        ).replace("SG Client", "SG-Client")
        generation_manifest = {
            "source": source,
            "source_label": source_label,
            "geoip_url": str(source_data.get("geoip_url") or ""),
            "geosite_url": str(source_data.get("geosite_url") or ""),
            "geoip_local_path": str(
                source_data.get("geoip_local_path") or ""
            ),
            "geosite_local_path": str(
                source_data.get("geosite_local_path") or ""
            ),
            "geoip": service._geofile_info(STAGE_ROOT / "geoip.dat"),
            "geosite": service._geofile_info(STAGE_ROOT / "geosite.dat"),
            "family": str(analysis["family"]),
            "geoip_categories": list(analysis["geoip_categories"]),
            "geosite_categories": list(analysis["geosite_categories"]),
            "checked_at": str(manifest.get("checked_at") or ""),
            "generation": generation,
            "candidate_config_sha256": candidate_sha256,
            "candidate_xray_test": "ok",
            "unified_values": values,
            "managed_rules": specs,
            "selected_categories": candidate["selected_categories"],
            "warnings": candidate["warnings"],
            "prepared_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ),
        }
        service._write_json_atomic(
            generation_dir / "manifest.json", generation_manifest
        )

        backup = service.GEOFILES_STATE_DIR / "backups" / generation
        backup.mkdir(parents=True, exist_ok=False)
        asset_existed = {
            "geoip.dat": active_geoip.is_file(),
            "geosite.dat": active_geosite.is_file(),
        }
        for current in (active_geoip, active_geosite):
            if current.is_file():
                shutil.copy2(current, backup / current.name)
        config_existed = config_path.is_file()
        if config_existed:
            shutil.copy2(config_path, backup / "config.json")
        routing_snapshot = service._routing_state_snapshot()
        geofiles_snapshot = service._snapshot_geofiles_settings()
        service._write_json_atomic(
            backup / "routing-before.json", routing_snapshot
        )
        service._write_json_atomic(
            backup / "geofiles-settings-before.json", geofiles_snapshot
        )
        pre_state = (
            service._run(
                ["systemctl", "is-active", xray_service], timeout=10
            ).stdout
            or "unknown"
        ).strip()
        transaction = {
            "state": "prepared",
            "kind": "unified-routing-geofiles-xray",
            "generation": generation,
            "backup": str(backup),
            "active_geoip": str(active_geoip),
            "active_geosite": str(active_geosite),
            "config_path": str(config_path),
            "asset_existed": asset_existed,
            "config_existed": config_existed,
            "xray_state_before": pre_state,
            "created_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ),
        }
        service._write_json_atomic(
            service.GEOFILES_STATE_DIR / "transaction.json", transaction
        )

        live_tmp_geoip = active_geoip.with_name(
            active_geoip.name + ".sg-unified-transaction"
        )
        live_tmp_geosite = active_geosite.with_name(
            active_geosite.name + ".sg-unified-transaction"
        )
        config_tmp = config_path.with_name(
            config_path.name + ".sg-unified-transaction"
        )
        original_error: Exception | None = None
        try:
            transaction["state"] = "committing"
            service._write_json_atomic(
                service.GEOFILES_STATE_DIR / "transaction.json", transaction
            )
            service._systemctl_checked("stop", xray_service)
            shutil.copy2(generation_dir / "geoip.dat", live_tmp_geoip)
            shutil.copy2(generation_dir / "geosite.dat", live_tmp_geosite)
            shutil.copy2(generation_dir / "config.json", config_tmp)
            os.chmod(config_tmp, 0o644)
            os.replace(live_tmp_geoip, active_geoip)
            os.replace(live_tmp_geosite, active_geosite)
            os.replace(config_tmp, config_path)

            _write_candidate_routing(model, specs, values)
            committed_text, _, _ = service.render_text()
            committed_sha = hashlib.sha256(
                committed_text.encode("utf-8")
            ).hexdigest()
            if committed_sha != candidate_sha256:
                raise service.XPanelError(
                    "Routing или Xray-настройки изменились между candidate-test и commit"
                )

            applied_manifest = {
                **generation_manifest,
                "applied_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
            }
            geoip_info, geosite_info = _update_geofiles_settings(
                manifest,
                generation,
                active_geoip,
                active_geosite,
                applied_manifest,
            )
            final_test = service._run_xray_test_with_assets(
                str(server["xray_bin"]),
                config_path,
                active_geoip.parent,
            )
            if final_test.returncode != 0:
                raise service.XPanelError(
                    "применённый config.json не прошёл финальный xray run -test: "
                    + (
                        (final_test.stderr or final_test.stdout).strip()
                        or "неизвестная ошибка"
                    )
                )
            service._systemctl_checked("restart", xray_service)
            service._confirm_xray_active(xray_service)
            transaction["state"] = "committed"
            transaction["committed_at"] = datetime.now(
                timezone.utc
            ).isoformat(timespec="seconds")
            service._write_json_atomic(
                backup / "transaction.json", transaction
            )
            (service.GEOFILES_STATE_DIR / "transaction.json").unlink(
                missing_ok=True
            )
            shutil.rmtree(STAGE_ROOT, ignore_errors=True)
            service.prune_geofiles_storage(active_generation=generation)
            public = _public_result(candidate)
            public.update(
                {
                    "status": "applied",
                    "message": (
                        "GeoFiles, Routing и полный Xray config применены "
                        "одной транзакцией"
                    ),
                    "source": source,
                    "source_label": str(
                        service.GEOFILES_SOURCES[source]["label"]
                    ).replace("SG Client", "SG-Client"),
                    "generation": generation,
                    "backup": str(backup),
                    "geoip": geoip_info,
                    "geosite": geosite_info,
                    "service": "active",
                }
            )
            return public
        except Exception as exc:
            original_error = exc
            transaction["state"] = "rolling_back"
            transaction["error"] = str(exc)
            service._write_json_atomic(
                service.GEOFILES_STATE_DIR / "transaction.json", transaction
            )
            try:
                service._run(
                    ["systemctl", "stop", xray_service], timeout=40
                )
                for name, current in (
                    ("geoip.dat", active_geoip),
                    ("geosite.dat", active_geosite),
                ):
                    previous = backup / name
                    if previous.is_file():
                        shutil.copy2(previous, current)
                    elif not asset_existed[name]:
                        current.unlink(missing_ok=True)
                old_config = backup / "config.json"
                if old_config.is_file():
                    shutil.copy2(old_config, config_path)
                    os.chmod(config_path, 0o644)
                elif not config_existed:
                    config_path.unlink(missing_ok=True)
                service._restore_routing_state(routing_snapshot)
                service._restore_geofiles_settings(geofiles_snapshot)
                if config_path.is_file():
                    rollback_test = service._run_xray_test_with_assets(
                        str(server["xray_bin"]),
                        config_path,
                        active_geoip.parent,
                    )
                    if rollback_test.returncode != 0:
                        raise service.XPanelError(
                            "старый config.json не прошёл xray run -test после восстановления: "
                            + (
                                (
                                    rollback_test.stderr
                                    or rollback_test.stdout
                                ).strip()
                                or "неизвестная ошибка"
                            )
                        )
                service._systemctl_checked("restart", xray_service)
                service._confirm_xray_active(xray_service)
                transaction["state"] = "rolled_back"
                transaction["rolled_back_at"] = datetime.now(
                    timezone.utc
                ).isoformat(timespec="seconds")
                service._write_json_atomic(
                    backup / "transaction.json", transaction
                )
                (service.GEOFILES_STATE_DIR / "transaction.json").unlink(
                    missing_ok=True
                )
            except Exception as rollback_exc:
                transaction["state"] = "rollback_failed"
                transaction["rollback_error"] = str(rollback_exc)
                service._write_json_atomic(
                    service.GEOFILES_STATE_DIR / "transaction.json",
                    transaction,
                )
                raise service.XPanelError(
                    "Критическая ошибка отката: состояние могло быть восстановлено "
                    "не полностью. Исходная ошибка: "
                    f"{original_error}. Ошибка rollback: {rollback_exc}"
                ) from rollback_exc
            if isinstance(original_error, OSError) and original_error.errno in {
                errno.EACCES,
                errno.EPERM,
                errno.EROFS,
            }:
                failed_path = Path(
                    str(original_error.filename or active_geoip.parent)
                )
                raise service.XPanelError(
                    "каталог ресурсов Xray недоступен для записи: "
                    f"{failed_path}. Старое рабочее состояние восстановлено"
                ) from original_error
            raise
        finally:
            for temporary in (
                live_tmp_geoip,
                live_tmp_geosite,
                config_tmp,
            ):
                temporary.unlink(missing_ok=True)
