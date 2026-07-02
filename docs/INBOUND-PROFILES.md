# Основные Inbound-профили SG-Panel

Inbound определяет, как клиент подключается к Xray на сервере.

SG-Panel поддерживает четыре основных профиля:

1. `RAW/TCP + REALITY`;
2. `XHTTP + TLS`;
3. `XHTTP + REALITY`;
4. `Hysteria 2 + TLS` — экспериментальный прямой UDP/QUIC-профиль.

Пользователи, UUID, Routing, DNS, Outbounds и WARP при переключении сохраняются.

HTTPS самой административной панели на отдельном порту не определяет профиль Inbound. Начальный `RAW/TCP + REALITY` работает без домена панели и без сертификата. Сертификат для `XHTTP + TLS` и `Hysteria 2 + TLS` настраивается отдельно, когда выбран соответствующий профиль.

## Общий порядок переключения

1. откройте **Inbound**;
2. выберите профиль;
3. проверьте автоматически заполненные поля;
4. нажмите **«Проверить конфигурацию»**;
5. после успешной проверки нажмите **«Сохранить и применить»**;
6. дождитесь сообщения, что Xray работает;
7. получите новую прямую ссылку или обновите подписку в клиенте.

Отдельный переход на **Xray Config** не требуется.

Старая прямая ссылка содержит параметры прежнего транспорта и может перестать работать.

## RAW/TCP + REALITY

Путь подключения:

```text
Клиент VLESS — TCP 443 — Xray REALITY — Routing — Outbound
```

Основные поля:

```text
Публичный адрес / домен: IP сервера или домен
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
Публичный адрес / домен: IP сервера или домен
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
Публичный адрес / домен: IP сервера или домен
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

## Hysteria 2 + TLS

Начиная с RC24, SG-Panel автоматически обнаруживает домен и сертификат Let's Encrypt и предлагает готовые значения для Hysteria 2. Серверный Xray устанавливается как `v26.5.9`; обновление выполняется с резервной копией бинарника, проверкой конфигурации и автоматическим откатом при ошибке.

Этот профиль использует нативные Hysteria 2 inbound и transport Xray. Он работает поверх QUIC/UDP и слушает публичный UDP-порт напрямую. Nginx в транспорт не включается.

Путь подключения:

```text
Клиент Hysteria 2 — UDP 443 — Xray Hysteria 2 + TLS — Routing — Outbound
```

Основные поля:

```text
Публичный адрес / домен: домен сертификата
Публичный порт:          443/udp или другой открытый UDP-порт
Server name / SNI:       домен сертификата
Listen Xray:             0.0.0.0
TLS certificate:         /etc/letsencrypt/live/ДОМЕН/fullchain.pem
TLS private key:         /etc/letsencrypt/live/ДОМЕН/privkey.pem
UDP idle timeout:        60 секунд
HTTP/3 masquerade:       стандартная 404, собственный текст или proxy URL
```

Каждый существующий пользователь сохраняет UUID. Для Hysteria 2 этот UUID используется как индивидуальный `auth`, поэтому пользователи, сроки действия, подписки и статистические email не пересоздаются.

Для EC2 добавьте отдельное входящее правило Security Group:

```text
Protocol: UDP
Port:     выбранный публичный порт Hysteria 2
Source:   IP клиентов или 0.0.0.0/0, если доступ нужен из любых сетей
```

TCP-правило на том же номере порта не открывает UDP автоматически. Если используется UFW, откройте порт отдельно:

```bash
sudo ufw allow 443/udp
```

Проверка listener:

```bash
sudo ss -lnup | grep ':443'
```

Ожидается процесс Xray на выбранном UDP-порту. Проверка `xray run -test` подтверждает структуру конфигурации и сертификат, но не заменяет реальное внешнее подключение Hysteria-клиентом.

Прямая ссылка начинается с:

```text
hysteria2://
```

### Hysteria Studio

RC26 добавляет три уровня настройки.

**Основные параметры**:

```text
домен, UDP-порт и SNI
TLS certificate / private key
UDP idle timeout
QUIC max idle timeout
KeepAlive
```

**Профили производительности**:

```text
Автоматически
Мобильная сеть
Высокая скорость
Ограниченный сервер
Пользовательский
```

Пресет меняет только параметры Hysteria 2 и не обходит обязательную проверку. Доступны алгоритмы `brutal`, `bbr`, `reno` и `force-brutal`, профиль BBR и ограничения Upload/Download. Значение `0` для скорости означает отсутствие ограничения со стороны панели.

**HTTP/3 masquerade**:

```text
Стандартная 404
Собственный HTML
Статический каталог
Proxy URL
```

Для собственного HTML настраиваются статус и JSON-объект заголовков. Для proxy доступны Rewrite Host и режим игнорирования сертификата целевого сайта. Игнорирование сертификата следует включать только для осознанной диагностики.

**Экспертные параметры QUIC** находятся в закрытом разделе:

```text
Path MTU Discovery
Maximum incoming streams
Receive windows
Congestion debug
UDP port hopping
```

Пример port hopping:

```text
Порты:    443,20000-20100
Интервал: 30
```

В Security Group и локальном firewall должен быть открыт весь указанный UDP-диапазон. Минимальный интервал — 5 секунд. Клиентская `hysteria2://`-ссылка использует тот же список портов.

Панель проверяет типы, диапазоны и итоговый `config.json`, но локальная проверка не подтверждает внешнюю доступность UDP из конкретной сети клиента.

Кнопка **«Полная проверка»** открывает отдельный отчёт Hysteria 2. В нём проверяются DNS, TLS-файлы и срок сертификата, generated config, `xray run -test`, systemd, локальный UDP listener, пользователи, port hopping и журнал Xray. Пункт «Внешняя доступность UDP» специально остаётся нейтральным до реального подключения клиента из другой сети.

Профиль помечен как экспериментальный до реального теста на конкретном EC2, Security Group, маршруте провайдера и клиентском приложении. Сети, которые блокируют UDP/QUIC, не смогут использовать этот профиль.

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
клиентская ссылка выбранного профиля
```

## Прямые ссылки и подписки после переключения

Прямая ссылка:

```text
Clients → Clients — Ссылка / QR — импортировать новый профиль
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


SG-Panel хранит отдельную защищённую runtime-копию TLS в `/usr/local/etc/xray/sg-panel-tls`.
