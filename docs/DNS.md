# DNS

Раздел `Routing → DNS` управляет встроенным DNS Xray.

## Когда он нужен

Встроенный DNS полезен для:

- разных upstream для разных доменов;
- UDP/TCP DNS, DoH и DoQ Local;
- статических hosts-записей;
- маршрутизации по `geoip` после разрешения домена;
- исключения системного DNS провайдера.

Если текущая схема работает и специальных правил нет, не усложняйте DNS без необходимости.

## Общие настройки

### Включить встроенный DNS

Добавляет раздел `dns` в итоговый `config.json`.

### Query strategy

- `UseIP` — использовать доступное IP-семейство;
- `UseIPv4` — только IPv4;
- `UseIPv6` — только IPv6;
- `UseSystem` — системная стратегия.

Для обычного IPv4 EC2 чаще всего подходит `UseIPv4`.

### System hosts

Использует записи `/etc/hosts`.

### Параллельные запросы

Опрос подходящих upstream выполняется параллельно.

### Отключить кэш

Не использовать внутренний DNS-кэш Xray. Обычно оставляйте кэш включённым.

### Fallback

DNS fallback не связан с HTTPS fallback на Nginx. Это два разных механизма.

- DNS fallback выбирает резервный DNS-upstream;
- HTTPS fallback показывает обычный сайт/заглушку на TCP `443`.

## Upstream-серверы

Поддерживаются адреса вида:

```text
1.1.1.1
tcp://1.1.1.1
tcp+local://1.1.1.1
https://1.1.1.1/dns-query
https+local://1.1.1.1/dns-query
quic+local://dns.example.com
```

Обычный IP-адрес без схемы используется как UDP DNS. `https://` и `https+local://` задают DoH; `quic+local://` — DoQ Local. Отдельный DNS-over-TLS (`tls://`, DoT) текущая форма SG-Panel не принимает.

Для каждого upstream можно задать:

- название;
- приоритет;
- query strategy;
- timeout;
- domains;
- expected IP;
- unexpected IP;
- fallback-поведение.

## Domains для upstream

Пример:

```text
domain:example.com
geosite:google
full:api.example.com
```

Если domains не заданы, сервер может участвовать как общий upstream или fallback в зависимости от остальных параметров.

## Статические hosts

Hosts переопределяют результат для указанного домена.

Пример:

```text
server.local -> 192.168.1.200
```

Не используйте hosts как замену полноценному публичному DNS для Let's Encrypt.

## Связь с Traffic Rules

`domainStrategy` в Traffic Rules определяет, когда Xray преобразует домен в IP для IP-правил.

При `AsIs` доменные правила работают напрямую. Для `geoip` может понадобиться `IPIfNonMatch` или `IPOnDemand`.

## Проверка DNS

На странице есть поле тестового домена и кнопка проверки.

После изменения также проверьте:

```bash
sudo /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

И выполните реальный запрос через клиент. Успешный локальный DNS-тест не доказывает, что Traffic Rule выбрал нужный Outbound.

## DNS JSON

Контекстный редактор содержит общие параметры, upstream и hosts в одном документе. Сохранение доступно только после успешной проверки.
