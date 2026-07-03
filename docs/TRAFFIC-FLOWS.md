# Схемы движения трафика

## Общая схема

```text
Клиент → Inbound → Xray → Traffic Rules → Outbound → Интернет
```

- **Inbound** принимает соединение клиента;
- **Traffic Rules** выбирают маршрут;
- **Outbound** определяет дальнейший выход.

## RAW/TCP + REALITY

Без fallback:

```text
Клиент VLESS
    ↓ TCP 443
Xray RAW/TCP + REALITY
    ↓
direct / warp / пользовательский Outbound
```

После настройки домена и fallback:

```text
TCP 443 → Nginx stream SNI-router
          ├─ Reality SNI → Xray на локальном runtime-порту
          └─ собственный домен → локальная HTTPS-заглушка
```

## XHTTP + REALITY

```text
Клиент VLESS XHTTP REALITY, mode auto
    ↓ TCP 443
Nginx stream SNI-router при включённом fallback
    ├─ Reality SNI → Xray XHTTP + REALITY
    └─ собственный домен → локальная HTTPS-заглушка
```

Без настроенного домена Xray может принимать публичный TCP `443` напрямую.

## XHTTP + TLS

```text
Клиент VLESS XHTTP TLS
    ↓ TCP 443
Nginx TLS
    ├─ клиентский path → Xray 127.0.0.1:8443
    └─ другие запросы → локальная SG-заглушка
```

SNI клиента должен соответствовать сертификату.

## gRPC + TLS

```text
Клиент VLESS gRPC TLS
    ↓ TCP 443, HTTP/2
Nginx TLS
    ├─ gRPC service → Xray 127.0.0.1:8443
    └─ другие запросы → локальная SG-заглушка
```

## Hysteria 2 + TLS

```text
Клиент Hysteria 2
    ↓ UDP 443 или port hopping
Xray Hysteria 2
    ↓
direct / warp / пользовательский Outbound
```

Одновременно:

```text
Браузер → TCP 443 → Nginx → локальная SG-заглушка
```

TCP и UDP используют разные сокеты и не конфликтуют.

## Direct

```text
Клиент → Xray → direct → Интернет через публичный IP сервера
```

## Весь трафик через WARP

```text
Явные правила блокировки → block
Остальной трафик         → warp → Cloudflare → Интернет
```

WARP становится Default Outbound.

## Выборочный WARP

```text
Выбранные домены → warp
Остальные        → direct или другой Default Outbound
```

## Пользовательский Outbound

```text
Клиент
    ↓
Первый SG-Panel / Xray
    ↓ Traffic Rule
VLESS Outbound
    ↓
Второй Xray-сервер
    ↓
Интернет через IP второго сервера
```

Параметры Outbound первого сервера должны совпадать с Inbound второго сервера.

## Подписка

Подписка не передаёт пользовательский трафик:

```text
Клиентское приложение
    ↓ HTTP/HTTPS
/sub/персональный-token
    ↓
SG-Panel формирует актуальную ссылку текущего Inbound
```

После смены Inbound приложение обновляет подписку и получает новые transport-параметры.

## Служебные порты

```text
127.0.0.1:8080   backend SG-Panel
127.0.0.1:8443   Xray для XHTTP/gRPC TLS
PUBLIC:61443     публичный порт панели
PUBLIC:80        SG-заглушка и HTTP-01
PUBLIC:443/tcp   VLESS или HTTPS/fallback
PUBLIC:443/udp   Hysteria 2
```
