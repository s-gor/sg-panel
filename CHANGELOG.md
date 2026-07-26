# Changelog

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
