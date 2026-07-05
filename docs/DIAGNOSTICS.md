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
- каждый включённый UDP-listener Hysteria 2 (`443`, `8443`, `9443` или выбранные порты);
- каждый включённый локальный XHTTP listener, обычно `127.0.0.1:8443`, `:8444` и `:8445`, при активном `VLESS XHTTP-TLS` или смешанном профиле;
- в смешанном профиле одновременно проверяются XHTTP TCP-listener и Hysteria 2 UDP-listener.

## VLESS REALITY не подключается

Проверьте:

- TCP `443` открыт;
- Reality private/public key соответствуют друг другу;
- short ID совпадает;
- SNI и fingerprint совпадают с клиентом;
- target доступен с сервера;
- после включения fallback клиент использует актуальный адрес и SNI.


## Диагностика смешанного профиля

Для `XHTTP-TLS + Hysteria 2` нормальна одновременная работа одинакового номера порта по разным транспортам, например `127.0.0.1:8443/tcp` для XHTTP и `0.0.0.0:8443/udp` для Hysteria 2. При проверке смотрите не только номер порта, но и протокол.

Если работают XHTTP-ссылки, но не Hysteria, проверьте UDP-правила Security Group. Если работает Hysteria, но не XHTTP, проверьте Nginx, TLS и соответствие Path.

## VLESS XHTTP-REALITY не подключается

Дополнительно проверьте:

- path совпадает;
- mode в ссылке клиента совпадает с выбранным на сервере (`auto`, `packet-up`, `stream-up` или `stream-one`);
- клиент поддерживает используемую реализацию XHTTP;
- fallback не направляет Reality SNI в обычную заглушку.

## VLESS XHTTP-TLS не подключается

Проверьте:

- сертификат действителен;
- домен указывает на сервер;
- Nginx слушает TCP `443`;
- Xray слушает локальный порт именно того экземпляра, ссылку которого вы проверяете (`8443`, `8444` или `8445` по умолчанию);
- Nginx содержит отдельный `location` для нужного Path;
- XHTTP Path и общий mode совпадают с клиентом;
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
## Диагностика нескольких Hysteria 2 Inbound

Hysteria Studio проверяет структуру всех включённых экземпляров и отдельно показывает локальное состояние каждого UDP-listener. Локальный статус подтверждает, что Xray слушает порт на сервере, но не подтверждает правила Security Group или доступность UDP из сети клиента.

Для окончательной проверки подключитесь по каждой выданной ссылке из внешней сети. Если основной порт работает, а резервный нет, сначала проверьте, что дополнительный порт открыт именно по UDP.

