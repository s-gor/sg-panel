# Основные Inbound-профили SG-Panel

Inbound определяет, как клиент подключается к Xray на сервере.

SG-Panel поддерживает три основных профиля:

1. `RAW/TCP + REALITY`;
2. `XHTTP + TLS`;
3. `XHTTP + REALITY`.

Пользователи, UUID, Routing, DNS, Outbounds и WARP при переключении сохраняются.

## Общий порядок переключения

1. откройте **Inbound**;
2. выберите профиль;
3. проверьте автоматически заполненные поля;
4. нажмите **«Сохранить и применить»**;
5. дождитесь сообщения, что Xray работает;
6. получите новую прямую ссылку или обновите подписку в клиенте.

Отдельный переход на **Xray Config** не требуется.

Старая прямая ссылка содержит параметры прежнего транспорта и может перестать работать.

## RAW/TCP + REALITY

Путь подключения:

```text
Клиент VLESS — TCP 443 — Xray REALITY — Routing — Outbound
```

Основные поля:

```text
Публичный адрес / домен: ваш домен
Публичный порт:          443
Server name / SNI:       имя REALITY target
Fingerprint:             chrome
Flow:                    xtls-rprx-vision
Reality target:          подходящий host:443
```

Проверенные значения:

```text
Reality target:     www.bing.com:443
Server name / SNI:  www.bing.com
```

Nginx не занимает `443`. Xray принимает соединение напрямую.

Проверка:

```bash
ss -ltnp | grep ':443'
```

Ожидается Xray на `443`.

## XHTTP + TLS

Путь подключения:

```text
Клиент VLESS XHTTP TLS — Nginx 443 — Xray 127.0.0.1:8443 — Routing — Outbound
```

Основные поля:

```text
Публичный адрес / домен: ваш домен
Публичный порт:          443
Server name / SNI:       тот же домен
Fingerprint:             chrome
XHTTP Path:              /sg-xhttp или ваш путь
Mode:                    auto
Локальный listen Xray:   127.0.0.1
Локальный порт Xray:     8443
TLS certificate:         /etc/letsencrypt/live/ДОМЕН/fullchain.pem
TLS private key:         /etc/letsencrypt/live/ДОМЕН/privkey.pem
Flow:                    отсутствует
```

Здесь `www.bing.com` не используется в поле SNI. SNI должен совпадать с доменом сертификата Let's Encrypt.

SG-Panel автоматически:

- меняет SNI на публичный домен;
- отключает Flow;
- подставляет пути сертификата;
- создаёт управляемую конфигурацию Nginx;
- переводит Xray на `127.0.0.1:8443`.

Проверка:

```bash
ss -ltnp | grep -E ':443|:8443'
```

Ожидается:

```text
Nginx на 443
Xray на 127.0.0.1:8443
```

Порт `8443` не открывается в AWS Security Group.

## XHTTP + REALITY

Путь подключения:

```text
Клиент VLESS XHTTP REALITY — Xray 443 — Routing — Outbound
```

Основные поля:

```text
Публичный адрес / домен: ваш домен
Публичный порт:          443
Server name / SNI:       имя REALITY target
Fingerprint:             chrome
XHTTP Path:              /sg-xhttp или ваш путь
Mode:                    auto
Reality target:          www.bing.com:443
Flow:                    отсутствует
```

Проверенные значения:

```text
Reality target:     www.bing.com:443
Server name / SNI:  www.bing.com
```

Сертификат Let's Encrypt для Xray не используется. Nginx освобождает `443`, а Xray слушает его напрямую.

Проверка:

```bash
ss -ltnp | grep ':443'
```

Ожидается Xray на `443`.

## Что сохраняется

```text
имя пользователя
UUID
срок действия
статус пользователя
Reality-ключи
Short ID
Routing
DNS
пользовательские Outbounds
WARP
подписки
```

## Что меняется

```text
transport
security
Flow
SNI
XHTTP Path
участие Nginx
локальный порт Xray для TLS-профиля
клиентская VLESS-ссылка
```

## Прямые ссылки и подписки после переключения

Прямая ссылка:

```text
Пользователи — Ссылка / QR — импортировать новый профиль
```

Подписка:

```text
обновить существующую группу подписок в клиенте
```

URL подписки и UUID пользователя сохраняются.

## Проверка config.json

При необходимости:

```bash
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

Ожидается:

```text
Configuration OK.
```

## Откат при ошибке

Перед применением SG-Panel сохраняет текущий `config.json` и управляемую конфигурацию Nginx.

Если новый Xray или Nginx не запускается, панель пытается вернуть:

```text
предыдущий config.json Xray
предыдущую конфигурацию Nginx
предыдущее состояние служб
```
