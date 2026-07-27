# Текущая рабочая линия SG-Panel

## SG-Panel Preview 9 · FIX40 · UI23 Repair4 — финальная GitHub-база 2026-07-27

Текущая cumulative-база включает:

- UI23 Repair4 и Hysteria2 Salamander FinalMask;
- безопасный updater/rollback с проверкой свободного места;
- защиту от вложенного `/opt/xpanel-mvp/xpanel-mvp`;
- Routing UI Fix 1;
- GeoFiles UI Fix 1;
- компактный Cluster и постоянно открытую форму добавления SG-Node;
- понятные входящие подключения Xray Server;
- Direct, Block и WARP в одном разделе системных Outbounds;
- упрощённый DNS и отдельный Expert DNS;
- мягкие DNS-карточки без тяжёлых боковых рамок;
- UI-правки Clients, Security, Maintenance и XMUX.

## Публикация

- репозиторий: `s-gor/sg-panel`;
- ветка: `main`;
- без GitHub Release и без тега;
- версия приложения остаётся `v0.10.0-rc70`;
- SG-Node отдельно не обновляется.

## Автоматические проверки

- 246 pytest-тестов;
- разбор 38 Jinja-шаблонов;
- Python compileall;
- Bash syntax;
- проверка финального SOURCE ZIP и публикационного пакета.
