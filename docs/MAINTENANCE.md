# Обслуживание сервера

## Обновление SG-Panel

Повторно запустите установочную команду из GitHub:

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Установщик обнаружит существующую панель и перейдёт в режим обновления.

Перед заменой файлов создаётся резервная копия.

## Изменение HTTP/HTTPS, домена или порта панели

Откройте:

```text
Безопасность → Доступ к панели
```

Здесь можно:

- оставить HTTP для локальной VM или SSH-туннеля;
- включить HTTPS + Let's Encrypt;
- изменить IP/hostname или домен;
- изменить публичный порт панели;
- вернуться с HTTPS на HTTP.

Параметр установщика `--reconfigure` используется только для адреса Xray и Reality target/SNI. Он больше не меняет доступ к панели.

## Сертификат Let's Encrypt

Этот раздел нужен только после включения HTTPS в «Безопасность → Доступ к панели».

Проверка автоматического продления:

```bash
sudo certbot renew --dry-run
```

Ожидается успешное завершение dry-run.

Для HTTP-01 порт `80/tcp` должен быть доступен из интернета.

## Страница-заглушка

Рабочий файл:

```text
/var/www/sg-panel-placeholder/index.html
```

Эталонная копия:

```text
/var/www/sg-panel-placeholder/index.default.html
```

Восстановление стандартной страницы:

```bash
sudo cp /var/www/sg-panel-placeholder/index.default.html /var/www/sg-panel-placeholder/index.html
sudo nginx -t && sudo systemctl reload nginx
```

Доступность после включения HTTPS панели:

```text
HTTP 80              HTTP-01 и страница-заглушка
выбранный порт        HTTPS-панель
HTTPS 443             только при XHTTP + TLS
```

В профилях REALITY порт `443` занимает Xray. Административная панель всегда остаётся на отдельном выбранном порту.

## Оптимизация небольшого EC2

Для сервера с `1 ГиБ` RAM установщик:

- создаёт swap `2 ГиБ`;
- запускает Waitress с ограниченным числом потоков;
- оставляет Stats API выключенным по умолчанию;
- выполняет периодическое обслуживание.

Для личного сервера и небольшого количества пользователей такой конфигурации обычно достаточно.

Проверка памяти:

```bash
free -h
```

Проверка диска:

```bash
df -h /
```

## Основные службы

```bash
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
systemctl is-active xpanel-maintenance.timer
systemctl is-active xpanel-traffic.timer
```

Перезапуск служб для диагностики доступен на странице **Diagnostics**.

## Основные пути

```text
/opt/xpanel-mvp
/opt/xpanel-mvp/data/panel.db
/usr/local/etc/xray/config.json
/etc/xpanel-mvp/web.env
/etc/xpanel-mvp/warp
/root/sg-panel-backups
/var/www/sg-panel-placeholder
```

## Полная очистка тестового EC2

Используется только на одноразовом сервере без других сайтов и сертификатов:

```bash
sudo bash deploy/purge-test-server.sh --destroy-test-server
```

Скрипт требует подтверждение:

```text
DELETE ALL
```


## Сбор долговременной статистики трафика

Таймер `xpanel-traffic.timer` запускает коллектор примерно раз в минуту.

Проверка:

```bash
systemctl status xpanel-traffic.timer --no-pager
systemctl status xpanel-traffic.service --no-pager
journalctl -u xpanel-traffic.service -n 50 --no-pager
```

Ручной запуск:

```bash
cd /opt/xpanel-mvp
sudo .venv/bin/python -m xpanel collect-traffic --online
```

Коллектор не изменяет конфигурацию Xray и не перезапускает службу. Он только читает локальный Stats API и сохраняет прирост в `panel.db`.
