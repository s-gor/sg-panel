# Установка SG-Panel

## Требования

- Ubuntu Server 24.04 LTS;
- архитектура `amd64`;
- отдельный сервер, VPS или EC2;
- root или sudo;
- минимум 1 ГиБ RAM;
- TCP `22` для SSH;
- TCP `443` для VLESS-профилей;
- отдельный TCP-порт панели, по умолчанию `61443`.

Для первой установки с `RAW/TCP + REALITY` домен и сертификат не нужны.

## Security Group или firewall

Минимальный набор для первого запуска:

| Порт | Источник |
|---:|---|
| `22/tcp` | ваш административный IP |
| `443/tcp` | адреса клиентов или необходимый диапазон |
| `61443/tcp` | ваш административный IP |

Дополнительно:

- `80/tcp` — для Let's Encrypt и публичной SG-заглушки;
- `443/udp` — для Hysteria 2;
- UDP-диапазон — только если включён Hysteria port hopping.

Не открывайте наружу `8080/tcp` и `8443/tcp`.

## Установка из GitHub

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Не используйте `curl | bash`: мастер читает ответы из терминала.

## Установка из ZIP

Скопируйте архив в `/home/ubuntu`, затем:

```bash
cd /home/ubuntu

sha256sum SG-Panel-...-GITHUB-SOURCE.zip

rm -rf sg-panel-main

unzip -o SG-Panel-...-GITHUB-SOURCE.zip

cd sg-panel-main

sudo bash deploy/ec2-first-install.sh
```

Сравните SHA-256 с суммой, опубликованной рядом с архивом.

## Вопросы установщика

### Адрес Xray для клиентов

Укажите публичный IPv4 или hostname. На EC2 мастер предложит найденный публичный IPv4.

### Порт панели

По умолчанию:

```text
61443
```

Порт не должен совпадать с `22`, `80`, `443`, `8080` или `8443`.

### Первый клиент

По умолчанию:

```text
sg-admin
```

Это клиент Xray, а не имя администратора веб-панели.

### Reality target и SNI

Значения по умолчанию:

```text
www.bing.com:443
www.bing.com
```

Не указывайте собственный домен сертификата как Reality SNI.

### Пароль администратора

Используйте отдельный пароль, который не применяется для SSH или других сервисов.

## Ожидаемый результат

После завершения мастер показывает:

- адрес панели;
- адрес Xray;
- состояние служб;
- открываемые порты;
- путь к первой клиентской ссылке.

Откройте:

```text
http://SERVER_IP:61443
```

## Быстрая проверка

```bash
cd /opt/xpanel-mvp

.venv/bin/python -m xpanel --version
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
systemctl is-active xpanel-traffic.timer
curl -fsS http://127.0.0.1:8080/login >/dev/null
```

Ожидается версия `0.10.0-rc30`, состояние `active` и успешное открытие локальной страницы входа.

Проверка Xray:

```bash
sudo /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

## Первый клиент

```bash
sudo cat /root/sg-panel-first-user.txt
```

Импортируйте ссылку в v2rayN, v2rayNG или другой совместимый клиент и проверьте соединение до дальнейших изменений.

## Включение HTTPS

HTTPS не включается автоматически при первой установке.

1. направьте DNS-запись `A` на сервер;
2. откройте TCP `80` и порт панели;
3. откройте `Security → Panel Access`;
4. выберите `HTTPS + Let's Encrypt`;
5. укажите домен и сохраните.

Подробнее: [HTTPS и fallback](HTTPS.md).

## Если установка прервалась

Повторно запустите тот же `deploy/ec2-first-install.sh`. Мастер определяет завершённую, частичную или повреждённую установку и старается продолжить безопасно.

Перед ручным удалением файлов сначала сохраните:

```text
/opt/xpanel-mvp/data/panel.db
/etc/xpanel-mvp/
/usr/local/etc/xray/config.json
/root/sg-panel-backups/
```

## Обновление

Повторный запуск установщика обновляет существующую установку с сохранением данных и текущего HTTP/HTTPS-доступа.

Параметр `--reconfigure` повторно спрашивает только адрес Xray, Reality target и Reality SNI:

```bash
sudo bash deploy/ec2-first-install.sh --reconfigure
```

Домен и публичный порт панели меняются в `Security → Panel Access`.
