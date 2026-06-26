# Безопасное удаление SG-Panel

В SG-Panel `0.9.8` обычное удаление стало безопасным по умолчанию.

Команда без дополнительных параметров удаляет только панель и связанные с ней службы. Xray, его рабочая конфигурация и резервные копии сохраняются.

## Что сохраняется при обычном удалении

- Xray и его systemd-служба;
- `/usr/local/etc/xray/config.json`;
- резервные копии `/root/sg-panel-backups`;
- Nginx и Certbot;
- сертификаты Let's Encrypt;
- системные пакеты;
- `/swapfile`.

Перед удалением панель дополнительно сохраняет текущую SQLite-базу, конфигурацию Xray, `web.env` и ссылку первого пользователя в каталог:

```text
/root/sg-panel-backups/uninstall-ДАТА_UTC
```

Эта копия содержит чувствительные данные. Не публикуйте её и не меняйте права доступа.

## Удалить только SG-Panel

```bash
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/deploy/uninstall.sh -o /tmp/uninstall-sg-panel.sh && bash -n /tmp/uninstall-sg-panel.sh && chmod 700 /tmp/uninstall-sg-panel.sh && sudo bash /tmp/uninstall-sg-panel.sh
```

Скрипт покажет точный план и потребует ввести:

```text
УДАЛИТЬ ПАНЕЛЬ
```

Для автоматического запуска без вопроса:

```bash
sudo bash /tmp/uninstall-sg-panel.sh --yes
```

## Дополнительно удалить Xray

```bash
sudo bash /tmp/uninstall-sg-panel.sh --remove-xray
```

Удаляются бинарный файл Xray, systemd-служба, `/usr/local/etc/xray`, журналы Xray и файл первой VLESS-ссылки.

## Дополнительно удалить резервные копии

```bash
sudo bash /tmp/uninstall-sg-panel.sh --remove-backups
```

## Удалить панель, Xray и резервные копии

```bash
sudo bash /tmp/uninstall-sg-panel.sh --remove-xray --remove-backups
```

Nginx, Certbot, сертификаты и swap всё равно сохраняются.

## Полная очистка одноразового тестового сервера

Полная очистка вынесена из обычного деинсталлятора в отдельный файл:

```text
deploy/purge-test-server.sh
```

Она удаляет весь Nginx, все сертификаты Let's Encrypt, Xray, SG-Panel, swap и резервные копии. Такой режим подходит только для одноразового тестового EC2, на котором нет других сайтов и сертификатов.

Сначала прочитайте справку:

```bash
sudo bash deploy/purge-test-server.sh --help
```

Запуск требует явного параметра:

```bash
sudo bash deploy/purge-test-server.sh --destroy-test-server
```

Старый параметр `uninstall.sh --purge-all` больше не поддерживается и завершается отказом без удаления файлов.

## Проверка после обычного удаления

```bash
systemctl is-active xray
systemctl status xpanel-web --no-pager
ls -lh /usr/local/etc/xray/config.json
ls -ld /root/sg-panel-backups
```

Ожидается:

- Xray остаётся `active`;
- `xpanel-web` больше не существует;
- рабочий `config.json` сохранён;
- каталог резервных копий сохранён.
