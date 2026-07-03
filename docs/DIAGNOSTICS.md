# Диагностика и поиск неисправностей

## Что проверять сначала

1. `System → Status & Services`;
2. `System → Logs & Diagnostics`;
3. результат `xray run -test`;
4. активный Inbound-профиль;
5. клиентскую ссылку после последнего изменения;
6. Security Group/firewall;
7. реальное соединение одного клиента.

## Команды базовой проверки

```bash
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
systemctl is-active xpanel-traffic.timer
curl -fsS http://127.0.0.1:8080/login >/dev/null
sudo /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
```

## Порты

```bash
sudo ss -lntup
```

Ожидайте:

- backend SG-Panel на `127.0.0.1:8080`;
- панель/Nginx на выбранном публичном порту;
- активную точку Xray или Nginx на TCP `443`;
- UDP `443` при активной Hysteria 2;
- локальный `127.0.0.1:8443` для XHTTP/gRPC TLS.

## RAW/TCP + REALITY не подключается

Проверьте:

- TCP `443` открыт;
- Reality private/public key соответствуют друг другу;
- short ID совпадает;
- SNI и fingerprint совпадают с клиентом;
- target доступен с сервера;
- после включения fallback клиент использует актуальный адрес и SNI.

## XHTTP + REALITY не подключается

Дополнительно проверьте:

- path совпадает;
- `mode: auto` сохранён;
- клиент поддерживает используемую реализацию XHTTP;
- fallback не направляет Reality SNI в обычную заглушку.

## XHTTP + TLS или gRPC + TLS не подключается

Проверьте:

- сертификат действителен;
- домен указывает на сервер;
- Nginx слушает TCP `443`;
- Xray слушает локальный `8443`;
- path или service name совпадает;
- HTTP/2 включён для gRPC;
- обычный `curl https://DOMAIN/` показывает заглушку.

## Hysteria 2 не подключается

Проверьте:

- UDP `443` или выбранный порт открыт;
- клиент поддерживает Hysteria 2;
- TLS domain/SNI совпадают;
- сертификат действителен;
- auth соответствует клиенту;
- port hopping диапазон одинаков на сервере, клиенте и firewall;
- ручная проверка Hysteria Studio прошла.

## Панель не открывается

На сервере:

```bash
systemctl status xpanel-web --no-pager
systemctl status nginx --no-pager
curl -I http://127.0.0.1:8080/login
sudo nginx -t
```

Проверьте правильный HTTP/HTTPS URL и порт в `/etc/xpanel-mvp/panel-access.env`.

## Ошибка после включения HTTPS

Проверьте:

```bash
dig +short panel.example.com
sudo certbot certificates
sudo nginx -t
sudo journalctl -u nginx -n 100 --no-pager
```

TCP `80` должен быть доступен для HTTP-01.

## WARP не работает

Проверьте:

1. WARP-профиль существует и включён;
2. тест WARP проходит;
3. режим выбран в Traffic Rules;
4. `warp` является целью правила или Default Outbound;
5. сервер имеет доступ к endpoint WARP.

Создание WARP без изменения маршрутизации не меняет внешний IP клиента.

## Traffic Rule не срабатывает

Проверьте:

- порядок правил;
- формат `domain:`, `full:`, `geosite:` или CIDR;
- Sniffing и Route only;
- `domainStrategy`;
- наличие geoip/geosite файлов;
- ожидаемый Outbound включён.

## Трафик клиента равен нулю

```bash
systemctl is-active xpanel-traffic.timer
cd /opt/xpanel-mvp
sudo .venv/bin/python -m xpanel collect-traffic --online --strict
```

Убедитесь, что клиент действительно передал данные после последнего измерения.

## Подписка не обновляется

- проверьте, что подписка включена;
- убедитесь, что используется текущий token;
- проверьте HTTPS и allowlist подписок;
- вручную откройте URL в браузере;
- обновите подписку в клиенте, а не только перезапустите соединение.

## Журналы

```bash
sudo journalctl -u xpanel-web -n 200 --no-pager
sudo journalctl -u xray -n 200 --no-pager
sudo journalctl -u nginx -n 200 --no-pager
```

Не публикуйте полный `config.json`, private keys, UUID, subscription tokens и резервные копии.

## Диагностический отчёт

Скачайте отчёт из `System → Logs & Diagnostics`. Перед отправкой проверьте его на наличие адресов и других данных, которые вы не хотите публиковать.
