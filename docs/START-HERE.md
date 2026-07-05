# С чего начать

Документ относится к версии `v0.10.0-rc45`.

## Новая установка

1. Выполните установку по документу [INSTALLATION.md](INSTALLATION.md).
2. Откройте адрес панели, показанный установщиком.
3. Войдите под созданным администратором.
4. Проверьте `System → Resources` и `System → Status & Services`.
5. Откройте `Clients`, выберите первого клиента и получите ссылку или подписку.
6. Проверьте реальное подключение до изменения Inbound или Network.

## Основной порядок работы

Любое изменение конфигурации выполняется так:

```text
Изменить параметры
→ Проверить конфигурацию
→ дождаться xray run -test
→ Сохранить и применить
→ проверить реального клиента
```

Простой выбор карточки Inbound не переключает работающий сервер.

## Куда перейти дальше

- [Полное руководство пользователя](USER-GUIDE.md)
- [Интерфейс, Help и System](PANEL.md)
- [Темы SG-Panel](THEMES.md)
- [Clients & Traffic Studio](CLIENTS.md)
- [Xray Server и профили](SERVER.md)
- [Traffic Rules](TRAFFIC-RULES.md)
- [Outbounds](OUTBOUNDS.md)
- [DNS](DNS.md)
- [Cloudflare WARP](WARP.md)
- [HTTPS и fallback](HTTPS.md)
- [Резервные копии и обновления](MAINTENANCE.md)
- [Диагностика](DIAGNOSTICS.md)
