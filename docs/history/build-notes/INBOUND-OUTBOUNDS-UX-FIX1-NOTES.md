# SG-Panel UI23 Repair4 — Inbound / Outbounds UX Fix 1

Local cumulative test package based on Remaining UI Fix 2.

## Xray Server
- Main page heading: «Входящие подключения».
- Explicit direction: «Клиент → SG-Panel».
- Four existing inbound channels are described as connection channels, not as all possible channels in general.

## Outbounds
- Direct, Block and WARP are equal rows inside one «Системные выходы» section.
- WARP no longer occupies a separate oversized section.
- WARP status is visible in the row; management expands inside the row.
- WARP JSON and low-level values remain under technical details.
- User-created outbounds remain a separate section below.

No backend/runtime changes. GitHub and SG-Node are not updated.
