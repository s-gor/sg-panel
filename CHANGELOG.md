# Changelog

## UI23 Repair4 — финальная GitHub-публикация 2026-07-27

- объединены Inbound/Outbounds UX, Remaining UI Fix 2, Cluster Empty Fix 1, GeoFiles UI Fix 1 и Routing UI Fix 1;
- добавлен DNS Frame Fix 1 без изменения DNS-логики;
- исправлен updater: защита от вложенного `xpanel-mvp`, проверка места, облегчённый backup и безопасный rollback;
- сохранены Direct/Block/WARP runtime, Xray runtime, база данных и SG-Node runtime;
- версия приложения не менялась, Release и тег не создавались.

## UI23 Repair4 — Inbound / Outbounds UX Fix 1

- Renamed Xray Server page to «Входящие подключения» and clarified client → server direction.
- Unified Direct, Block and WARP as equal system outbounds.
- Moved WARP management into an expandable row instead of a separate large panel.
- No backend/runtime changes.

## Current baseline — v0.10.0-rc70 · Preview 9 · FIX40 · UI23

This repository starts from the cleaned cumulative UI23 baseline.

### Repair4 — visible XMUX presets

- XMUX moved into Xray Server as a visible setting shared by both XHTTP channels;
- added the Standard and Russia-reduced presets with explicit values;
- retained manual Client Extra JSON;
- zero-valued `maxConcurrency` is accepted beside positive `maxConnections`;
- positive `maxConcurrency` and positive `maxConnections` remain blocked;
- the full candidate still passes `xray run -test` before apply.

### UI23 — Hysteria2 Salamander FinalMask

- per-Hysteria2-Inbound state: `none` or `salamander`;
- cryptographically strong shared Salamander password per Inbound;
- additive and idempotent SQLite migration;
- minimum Xray version gate `v26.3.27`;
- safe merge into `streamSettings.finalmask.udp` while preserving `quicParams`, TCP layers and unrelated UDP layers;
- full candidate validation with `xray run -test`, runtime apply and rollback;
- one Hysteria2 URI builder for copy, QR, downloads and subscriptions;
- password-safe audit, diagnostics and backup/restore;
- internal confirmation dialogs for enable, disable and password rotation.

A real external Hysteria2 + Salamander client connection still requires a separate live acceptance pass.

### UI22 — SG-Node details

- restored compact dark server and service cards;
- removed inherited gray surfaces from the expanded SG-Node section;
- preserved Cluster, Cascade and Worker runtime behavior.

### UI21 — Cluster restoration

- compact Controller and SG-Node rows;
- onboarding hidden behind `+ Добавить SG-Node`;
- duplicate navigation removed from the server card;
- compact resource facts and a safe expandable enrollment command.

### UI20 — Guided Cascade

- explicit mode selection;
- visible selected SG-Node;
- guided three-step flow;
- one-button Cluster Cascade;
- normal full-width link fields for two independent SG-Panel servers.

### UI19 runtime fix retained

- SG-Node Worker `0.7.0`;
- Agent reports the actual Worker version `0.7.0`;
- Controller does not replace the full SG-Node Xray configuration when preparing Cascade.

Older experimental build notes, generated audits, manifests and package checksums were removed from the repository. Their history remains available in Git history.

## UI23 Repair4 — Routing UI Fix 1 (local package)
- Routing page heading is now `Routing`.
- Removed the heavy outline from the two top Routing status cards and aligned their rounding with the panel theme.
- Increased only the small explanatory text inside Routing.
- Added a dedicated cache key; no backend or Routing/WARP logic changes.

## UI23 Repair4 — Remaining UI Fix 2 (local package)
- Completed the four partially implemented UI items from Remaining UI Fix 1.
- Outbounds now shows user-facing Direct/Block names; technical tags stay in “Дополнительно”.
- DNS main page hides queryStrategy, +local schemes and raw technical addresses; Expert DNS retains them.
- Security audit never falls back to raw endpoint names.
- XMUX preset and manual blocks no longer use framed card borders.
- No runtime, backend, routing, WARP, Xray, Node or updater logic changes.
