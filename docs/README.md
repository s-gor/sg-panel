# Документация SG-Panel

Документация относится к версии `v0.10.0-rc30`.

## Начало работы

1. [Руководство пользователя](USER-GUIDE.md)
2. [Установка](INSTALLATION.md)
3. [Интерфейс и раздел System](PANEL.md)

## Клиенты и подключения

- [Clients & Traffic Studio](CLIENTS.md)
- [Ссылки, QR-коды и подписки](PROTECTED-LINKS.md)
- [Xray Server и Inbound-профили](SERVER.md)
- [Схемы движения трафика](TRAFFIC-FLOWS.md)

## Network

- [Traffic Rules](TRAFFIC-RULES.md)
- [Outbounds](OUTBOUNDS.md)
- [DNS](DNS.md)
- [Cloudflare WARP](WARP.md)

## Конфигурация и безопасность

- [JSON и Generated Config](JSON-EDITOR.md)
- [HTTPS и fallback](HTTPS.md)
- [Security](SECURITY.md)

## Обслуживание

- [Maintenance и резервные копии](MAINTENANCE.md)
- [Диагностика](DIAGNOSTICS.md)
- [Полное удаление](UNINSTALL.md)

## Главное правило

Любое изменение Inbound, Clients, Network или JSON сначала должно пройти **«Проверить конфигурацию»**. Кнопка **«Сохранить и применить»** становится доступной только после успешной проверки той же версии данных.
