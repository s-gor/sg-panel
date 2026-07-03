# Maintenance и резервные копии

## Когда создавать копию

Создавайте резервную копию перед:

- сменой Inbound-профиля;
- крупной правкой Traffic Rules или DNS;
- восстановлением другой копии;
- обновлением;
- ручной работой с полным JSON.

SG-Panel также создаёт автоматические точки отката перед опасными операциями.

## Что сохраняется

Копия содержит как минимум:

- SQLite `panel.db`;
- снимок итогового `config.json`;
- метаданные и контрольные суммы.

SQLite хранит клиентов, UUID/Auth, серверные настройки, правила, Outbounds, DNS, WARP, подписки, статистику и параметры безопасности панели.

Системные пакеты Ubuntu и внешние файлы провайдера не являются частью SQLite-копии.

## Создание

Откройте `Maintenance` и нажмите **«Создать резервную копию»**.

После создания используйте **«Проверить»**. Копия с ошибкой проверки не должна использоваться для восстановления.

## Скачивание

Скачайте SQLite и config snapshot на локальный компьютер. Не храните единственную копию на том же сервере.

Файлы могут содержать приватные ключи, UUID, токены и сетевую конфигурацию.

## Восстановление

1. выберите проверенную копию;
2. подтвердите восстановление;
3. панель вернёт SQLite;
4. заново сформирует рабочий `config.json`;
5. выполнит `xray run -test`;
6. перезапустит Xray;
7. проверит активное состояние.

После восстановления проверьте клиента и Network-маршруты.

## Обновление SG-Panel

Повторно запустите установочную команду или установщик из нового ZIP.

Обновление сохраняет:

- базу SQLite;
- клиентов и статистику;
- текущий HTTP/HTTPS режим;
- домен и порт панели;
- рабочую Xray-конфигурацию до подтверждения новой.

При ошибке installer возвращает прежние файлы, SQLite и конфигурацию Xray.

## Сертификаты

Let's Encrypt продлевается системным Certbot. После продления deploy-hook обновляет runtime-копии, необходимые Xray TLS/Hysteria.

Проверка:

```bash
sudo certbot certificates
systemctl list-timers | grep -i certbot
```

## Службы

```bash
systemctl status xpanel-web
systemctl status xray
systemctl status nginx
systemctl status xpanel-traffic.timer
```

## Основные пути

```text
/opt/xpanel-mvp
/opt/xpanel-mvp/data/panel.db
/usr/local/etc/xray/config.json
/etc/xpanel-mvp/web.env
/etc/xpanel-mvp/panel-access.env
/root/sg-panel-backups
```

## Небольшой сервер

На машине с 1 ГиБ RAM файловый кэш может занимать значительную часть памяти — это нормально. Оценивайте `MemAvailable`, swap activity и состояние процессов.

Не очищайте Linux cache по расписанию: это обычно ухудшает работу.

## Коллектор трафика

Timer раз в минуту сохраняет прирост Xray Stats API в SQLite.

Проверка:

```bash
systemctl is-active xpanel-traffic.timer
systemctl list-timers xpanel-traffic.timer
cd /opt/xpanel-mvp
sudo .venv/bin/python -m xpanel collect-traffic --online --strict
```
