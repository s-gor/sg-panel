# Схемы движения трафика

Эта страница показывает, где начинается соединение, какие службы его принимают и через какой Outbound оно выходит.

## Общая схема

```text
Клиент — Inbound — Xray — Routing — Outbound — Интернет
```

Inbound и Outbound не являются взаимоисключающими настройками:

- Inbound отвечает за вход клиента на сервер;
- Outbound отвечает за дальнейший выход трафика;
- Routing связывает их.

## RAW/TCP + REALITY и direct

```text
Клиент VLESS
Публичный TCP 443
Xray RAW/TCP + REALITY
Default Outbound direct
Интернет через публичный IP EC2
```

На сервере:

```text
443/tcp       Xray
61443/tcp     Nginx HTTPS панели
8080/tcp      SG-Panel на 127.0.0.1
```

## RAW/TCP + REALITY и WARP

```text
Клиент VLESS
Публичный TCP 443
Xray RAW/TCP + REALITY
Default Outbound warp
Cloudflare WARP
Интернет через IP Cloudflare
```

WARP не создаёт системный интерфейс Ubuntu. WireGuard работает внутри Xray.

## XHTTP + TLS и direct

```text
Клиент VLESS XHTTP TLS
Публичный TCP 443
Nginx TLS
Xray XHTTP на 127.0.0.1:8443
Default Outbound direct
Интернет через публичный IP EC2
```

На сервере:

```text
443/tcp       Nginx
8443/tcp      Xray только на 127.0.0.1
61443/tcp     Nginx HTTPS панели
8080/tcp      SG-Panel только на 127.0.0.1
```

SNI клиента должен совпадать с доменом сертификата Let's Encrypt.

## XHTTP + REALITY и direct

```text
Клиент VLESS XHTTP REALITY
Публичный TCP 443
Xray XHTTP + REALITY
Default Outbound direct
Интернет через публичный IP EC2
```

Nginx не участвует в передаче XHTTP и не занимает `443`.

## Выборочный WARP

```text
Обычные сайты        direct
Выбранные домены     warp
Заблокированные      blocked
```

Routing проверяет правила по приоритету. Например:

```text
10  BitTorrent              blocked
20  Реклама                 blocked
40  Выбранные сайты         warp
остальной трафик            direct
```

## Весь трафик через WARP

```text
Явные правила блокировки    blocked
Остальной трафик            warp
```

В этом режиме отдельное правило `warp` может не отображаться в таблице: `warp` становится Default Outbound.

## Пользовательский Outbound

```text
Клиент
Первый SG-Panel/Xray
Routing
Пользовательский VLESS Outbound
Второй Xray-сервер
Интернет через IP второго сервера
```

В Outbound первого сервера указываются клиентские параметры Inbound второго сервера.

Пример соответствия:

```text
Inbound второго сервера     Outbound первого сервера
домен                        Address
порт                         Port
UUID пользователя            UUID
transport                    Network
security                     Security
SNI                          Server name
XHTTP Path                   Path
Reality public key           Public key
Short ID                     Short ID
```

## Подписка пользователя

Подписка не передаёт пользовательский трафик. Она только выдаёт клиентскую конфигурацию.

```text
v2rayN или v2rayNG
HTTPS-порт SG-Panel
/sub/персональный-токен
SG-Panel читает SQLite
Клиент получает актуальную VLESS-ссылку
```

После смены Inbound клиент обновляет подписку и получает новые transport-параметры с тем же UUID.
