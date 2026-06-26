# Основные inbound-профили SG-Panel

Установщик SG-Panel по умолчанию создаёт:

```text
VLESS + RAW/TCP + REALITY + Vision
Публичный порт: 443
```

На странице **Inbound** профиль можно заменить без редактирования JSON и без второго сервера.

SG-Panel RC5 показывает три актуальных профиля:

1. `RAW/TCP + REALITY`;
2. `XHTTP + TLS`;
3. `XHTTP + REALITY`.

Пользователи, UUID, сроки действия, маршрутизация, DNS и выходы сохраняются. Меняется основной inbound и создаваемая пользовательская ссылка.

`gRPC + TLS` удалён из основных карточек: Xray 26.3.27 помечает транспорт gRPC как устаревший и рекомендует XHTTP stream-up H2. Существующая gRPC-конфигурация может продолжать читаться через полный JSON для совместимости, но создавать новую через основной интерфейс не рекомендуется.

## Общий порядок переключения

1. Откройте **Inbound**.
2. Выберите профиль.
3. Проверьте автоматически заполненные поля.
4. Нажмите **«Сохранить профиль»**.
5. Откройте **Xray Config**.
6. Нажмите **«Проверить ещё раз»**.
7. Убедитесь, что вывод заканчивается строкой `Configuration OK.`.
8. Нажмите **«Применить конфигурацию»**.
9. Откройте пользователя и получите новую ссылку или QR-код.
10. Импортируйте новую конфигурацию в клиент.

Старая ссылка содержит параметры прежнего транспорта и после переключения может не работать.

## RAW/TCP + REALITY

```text
Клиент
  |
  | VLESS + RAW/TCP + REALITY + Vision
  v
Xray :443
```

Поля:

```text
Публичный адрес: ваш домен
Публичный порт: 443
Server name / SNI: имя REALITY target
Fingerprint: chrome
Flow: xtls-rprx-vision
Reality target: подходящий host:443
```

Для проверенной конфигурации используется:

```text
Reality target: www.bing.com:443
Server name / SNI: www.bing.com
```

`www.microsoft.com` не используется как значение по умолчанию: на Xray 26.3.27 этот target оказался несовместим с проверенной конфигурацией REALITY.

Nginx не занимает порт `443`. Xray принимает соединения напрямую.

## XHTTP + TLS

```text
Клиент
  |
  | VLESS + XHTTP + TLS :443
  v
Nginx
  |
  | локальный XHTTP
  v
Xray 127.0.0.1:8443
```

Поля:

```text
Публичный адрес: ваш домен
Публичный порт: 443
Server name / SNI: тот же домен
Fingerprint: chrome
XHTTP Path: /sg-xhttp
Mode: auto
Локальный listen Xray: 127.0.0.1
Локальный порт Xray: 8443
TLS certificate: /etc/letsencrypt/live/ДОМЕН/fullchain.pem
TLS private key: /etc/letsencrypt/live/ДОМЕН/privkey.pem
```

При выборе профиля RC5 автоматически:

- меняет SNI на публичный домен;
- отключает Flow;
- подставляет стандартные пути Let's Encrypt;
- создаёт управляемую конфигурацию Nginx;
- переводит Xray на loopback `127.0.0.1:8443`.

Nginx принимает TLS на `443`, передаёт XHTTP в локальный Xray и обслуживает страницу-заглушку для остальных запросов.

## XHTTP + REALITY

```text
Клиент
  |
  | VLESS + XHTTP + REALITY
  v
Xray :443
```

Поля:

```text
Публичный адрес: ваш домен
Публичный порт: 443
Server name / SNI: имя REALITY target
Fingerprint: chrome
XHTTP Path: /sg-xhttp
Mode: auto
Reality target: www.bing.com:443
Flow: отсутствует
```

Для проверенной конфигурации:

```text
Reality target: www.bing.com:443
Server name / SNI: www.bing.com
```

Сертификат Let's Encrypt для Xray не используется. Nginx освобождает `443`, а Xray снова слушает публичный порт напрямую.

## Что сохраняется при переключении

SG-Panel не создаёт нового пользователя. Сохраняются:

```text
имя пользователя
UUID
срок действия
статус пользователя
Reality-ключи
Short ID
маршрутизация
DNS
пользовательские outbounds
WARP
```

## Проверка серверных портов

Для `RAW/TCP + REALITY` и `XHTTP + REALITY`:

```bash
ss -ltnp | grep ':443'
```

Ожидается Xray на `443`.

Для `XHTTP + TLS`:

```bash
ss -ltnp | grep -E ':443|:8443'
```

Ожидается:

```text
Nginx на 443
Xray на 127.0.0.1:8443
```

Порт `8443` не нужно открывать в AWS Security Group.

## Проверка конфигурации

```bash
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

Ожидаемый результат:

```text
Configuration OK.
```

## Откат при ошибке

Перед применением SG-Panel сохраняет текущий `config.json` и состояние управляемой конфигурации Nginx.

Если Xray не запускается или `nginx -t` завершается ошибкой, панель пытается вернуть:

```text
предыдущий config.json Xray
предыдущий Nginx transport site
предыдущее состояние служб
```

RC5 также разрешает службе `xpanel-web` запись в `/etc/nginx`, что необходимо для графического переключения TLS-профиля.
