# Документация SG-Panel

Документация относится к версии `v0.10.0-rc80`.

## Начало работы

1. [С чего начать](START-HERE.md)
2. [Руководство пользователя](USER-GUIDE.md)
3. [Установка](INSTALLATION.md)
4. [Интерфейс, Help и раздел System](PANEL.md)
5. [Темы SG-Panel](THEMES.md)
6. [Cascade](CASCADE.md)
7. [Cluster и SG-Node](MULTI-NODE.md)

## Клиенты и подключения

- [Clients & Traffic Studio](CLIENTS.md)
- [Ссылки, QR-коды и подписки](PROTECTED-LINKS.md)
- [Xray Server и Inbound-профили](SERVER.md)
- [Hysteria2 Salamander FinalMask](HYSTERIA2-SALAMANDER.md)
- [Схемы движения трафика](TRAFFIC-FLOWS.md)

## Routing и каскад

- [Traffic Rules](TRAFFIC-RULES.md)
- [Cascade: входной и выходной сервер](CASCADE.md)
- [Outbounds](OUTBOUNDS.md)
- [DNS](DNS.md)
- [Cloudflare WARP](WARP.md)
- [Expert Transport и GeoFiles](EXPERT-TRANSPORT-GEOFILES.md)

## Конфигурация и безопасность

- [JSON и Generated Config](JSON-EDITOR.md)
- [HTTPS и fallback](HTTPS.md)
- [Security](SECURITY.md)

## Обслуживание

- [Maintenance, резервные копии и обновления](MAINTENANCE.md)
- [Диагностика](DIAGNOSTICS.md)
- [Полное удаление](UNINSTALL.md)

## Главное правило

Любое изменение Inbound, Clients, Routing или JSON сначала должно пройти **«Проверить конфигурацию»**. Кнопка **«Сохранить и применить»** становится доступной только после успешной проверки той же версии данных.
