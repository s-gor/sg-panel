# Установка SG-Panel

## Требования

- Ubuntu 22.04 или новее;
- `amd64` или `arm64`;
- отдельный VPS/EC2;
- root или sudo;
- минимум 1 ГиБ RAM;
- свободный TCP-порт панели, по умолчанию `61443`.

Для первой установки с VLESS REALITY домен и сертификат не нужны.

## Порты

Минимально:

| Порт | Назначение |
|---:|---|
| `22/tcp` | SSH |
| `443/tcp` | VLESS REALITY / XHTTP |
| `61443/tcp` | HTTP-интерфейс панели |

Дополнительно:

- `80/tcp` — Let's Encrypt и публичная заглушка;
- `443/udp` — основной Hysteria2;
- дополнительные UDP-порты — только для дополнительных Hysteria2 Inbound или port hopping.

Не открывайте наружу внутренний backend-порт `8080/tcp`.

## Установка из GitHub

```bash
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh
sudo bash /tmp/install-sg-panel.sh
```

Не используйте `curl | bash`: мастер должен читать ответы с клавиатуры.

Bootstrap загружает `install.sh`, проверяет его Bash-синтаксис и запускает единый мастер установки.

## Что происходит до вопросов

Мастер автоматически:

1. проверяет Ubuntu и архитектуру;
2. ждёт завершения cloud-init и освобождения apt/dpkg;
3. обновляет индексы APT;
4. устанавливает системные зависимости;
5. определяет публичный IPv4.

После этого он один раз спрашивает:

1. пароль администратора;
2. порт панели;
3. публичный IP или домен;
4. имя сервера;
5. имя первого клиента;
6. Reality target;
7. Reality SNI.

После строки:

```text
[SG-Panel] Все параметры приняты. Установка продолжается без дополнительного ввода.
```

дополнительный ввод не требуется.

## Что устанавливается

- SG-Panel `v0.10.0-rc70`;
- build `FIX40`, UI23;
- Xray `v26.6.27` или более новая уже установленная совместимая версия;
- Nginx;
- SQLite;
- первый VLESS REALITY-профиль;
- systemd-службы и таймеры;
- встроенные GeoFiles.

На чистой установке официальный временный Xray config может быть пустым `{}`. В таком случае старт Xray откладывается до создания рабочего config SG-Panel; после применения настоящего конфига служба проверяется строго.

## Результат

Панель открывается по адресу:

```text
http://SERVER_IP:61443
```

Первая клиентская ссылка:

```bash
sudo cat /root/sg-panel-first-user.txt
```

## Проверка

```bash
cd /opt/xpanel-mvp

.venv/bin/python -m xpanel --version
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
sudo /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

Ожидается версия `0.10.0-rc70`, службы `active` и успешная проверка Xray config.

## Журналы

```text
/var/log/sg-panel-bootstrap-*.log
/var/log/sg-panel-installer-*.log
/var/log/sg-panel-core-install-*.log
/var/log/sg-panel-upgrade-*.log
```

При ошибке мастер показывает этап, последние полезные строки и путь к полному журналу.

## Повтор после прерванной установки

Повторите ту же GitHub-команду. Мастер различает завершённую и частичную установку.

## Обновление

Из проверенного локального дерева:

```bash
sudo bash install-or-upgrade.sh
```

Updater делает backup и автоматически выполняет rollback при ошибке.

## HTTPS

HTTPS не включается автоматически. После успешной HTTP-установки настройте домен и сертификат в разделе доступа панели.

Подробнее: [HTTPS](HTTPS.md).
