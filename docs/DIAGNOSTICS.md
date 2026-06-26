# Diagnostics и поиск неисправностей

## Обзор и Diagnostics выполняют разные задачи

### Обзор

Отвечает на вопрос:

```text
Всё ли сейчас работает?
```

Показывает краткое состояние и не содержит служебных операций.

### Diagnostics

Отвечает на вопрос:

```text
Почему не работает и где искать причину?
```

Содержит подробные проверки, журналы и перезапуск служб.

## Что проверять сначала

Откройте **Diagnostics** и проверьте:

```text
Xray service       active
Nginx service      active
SG-Panel service   active
config.json        OK
```

Если WARP используется:

```text
WARP               работает
Default Outbound   warp
```

## Проверка после изменения Inbound

### RAW/TCP + REALITY

```bash
ss -ltnp | grep ':443'
```

Ожидается Xray на `443`.

### XHTTP + TLS

```bash
ss -ltnp | grep -E ':443|:8443'
```

Ожидается:

```text
Nginx на 443
Xray на 127.0.0.1:8443
```

### XHTTP + REALITY

```bash
ss -ltnp | grep ':443'
```

Ожидается Xray на `443`.

## Проверка config.json

Через интерфейс:

```text
Xray Config — Проверить JSON
```

Через SSH:

```bash
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

Ожидается:

```text
Configuration OK.
```

## Проверка служб

```bash
systemctl --no-pager --full status xpanel-web xray nginx
```

Короткая проверка:

```bash
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
```

## Журналы

SG-Panel:

```bash
journalctl -u xpanel-web -n 100 --no-pager
```

Xray:

```bash
journalctl -u xray -n 100 --no-pager
```

Nginx:

```bash
journalctl -u nginx -n 100 --no-pager
```

Дополнительный журнал ошибок Nginx:

```bash
tail -n 100 /var/log/nginx/error.log
```

## Проверка панели

Backend:

```bash
curl -sS -o /dev/null -w 'Backend HTTP: %{http_code}\n' http://127.0.0.1:8080/login
```

Ожидается HTTP-код `200`.

HTTPS через Nginx:

```bash
curl -k -sS -o /dev/null -w 'HTTPS: %{http_code}\n' https://127.0.0.1:61443/login -H 'Host: ВАШ-ДОМЕН'
```

Код `502` означает, что Nginx работает, но backend `127.0.0.1:8080` не отвечает.

## Проверка WARP

Нажмите:

```text
Diagnostics — Проверить WARP
```

или:

```text
Outbounds — Проверить WARP
```

Ожидается:

```text
WARP on, IP ...
```

Если тест зависает и завершается timeout:

1. проверьте endpoint в Diagnostics;
2. рабочее значение для EC2 без IPv6-маршрута: `162.159.192.1:2408`;
3. проверьте исходящий UDP;
4. не включайте WARP в Routing, пока отдельный тест не проходит.

## Сайты не открываются после включения WARP

Верните рабочий маршрут через панель:

```text
Routing — Не использовать WARP — Сохранить и применить
```

После восстановления проверьте WARP отдельно.

Не удаляйте профиль WARP до получения результата теста.

## Клиент показывает IP AWS вместо WARP

Проверьте:

```text
Outbounds — WARP включён
Routing — Весь трафик через WARP
Обзор — Default Outbound WARP
```

Если используются выборочные домены, IP AWS для остальных сайтов является нормальным.

## Подписка не обновляется

Проверьте:

- URL начинается с `https://`, а не с `vless://`;
- глобальная выдача подписок включена;
- подписка конкретного пользователя включена;
- токен не был заменён кнопкой **«Новый токен»**;
- порт панели доступен клиенту;
- subscription allowlist разрешает IP клиента.

## Диагностический отчёт

На странице **Diagnostics** нажмите **«Скачать отчёт»**.

Перед публикацией отчёта проверьте его содержимое. Не добавляйте к нему:

- резервные копии;
- `panel.db`;
- private key REALITY;
- WARP private key;
- полные URL подписок.
