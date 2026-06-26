# Обслуживание сервера

## Обновление SG-Panel

Повторно запустите установочную команду из GitHub:

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Установщик обнаружит существующую панель и перейдёт в режим обновления.

Перед заменой файлов создаётся резервная копия.

## Перенастройка домена или порта

```bash
sudo bash /tmp/install-sg-panel.sh --reconfigure
```

Пользователи, UUID, Reality-ключи и база сохраняются.

После смены домена:

- обновите A-запись;
- дождитесь правильного DNS;
- проверьте новый сертификат;
- обновите клиентские ссылки или подписки.

## Сертификат Let's Encrypt

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

Доступность:

```text
HTTP 80              во всех профилях
HTTPS 443            только при XHTTP + TLS
HTTPS-порт панели    во всех профилях
```

В профилях REALITY порт `443` занимает Xray, поэтому обычная HTTPS-заглушка на `443` недоступна.

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
