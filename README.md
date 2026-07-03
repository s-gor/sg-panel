# SG-Panel

Система развёртывания и обслуживания собственного Xray-сервера с веб-панелью управления.

![Version](https://img.shields.io/badge/version-v0.10.0--rc30-3974c6)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Xray](https://img.shields.io/badge/Xray-v26.5.9-5b8def)

SG-Panel устанавливает Xray, создаёт рабочую конфигурацию, управляет клиентами, входящими профилями, маршрутами, выходами, DNS, WARP, безопасностью панели и резервными копиями.

Это не универсальная панель «на все случаи». Проект сосредоточен на одном собственном Xray-сервере и на режимах, которые SG-Panel умеет полностью сформировать, проверить и обслуживать.

```text
Клиент Xray
    |
    v
SG-Panel / Xray Server
    |
    +-- DIRECT --------> Интернет через IP сервера
    +-- WARP ----------> Интернет через Cloudflare WARP
    +-- Outbound ------> Интернет через другой Xray-сервер
```

> Текущая версия приложения: `v0.10.0-rc30`.

## Что делает SG-Panel

### Xray Server

Панель поддерживает пять основных входящих профилей:

- `RAW/TCP + REALITY`;
- `XHTTP + REALITY` с `mode: auto`;
- `XHTTP + TLS`;
- `gRPC + TLS`;
- `Hysteria 2 + TLS` поверх QUIC/UDP.

Для каждого профиля SG-Panel формирует серверную конфигурацию и клиентские ссылки. Переключение выполняется только после обязательной проверки.

### Clients & Traffic Studio

- отдельный UUID или Hysteria auth для каждого клиента;
- имя, комментарий, срок действия и включение/отключение;
- последняя активность и online-состояние;
- трафик текущей сессии, за день, месяц и всё время;
- текущая скорость и график за 14 дней;
- персональный и общий сброс накопленной статистики;
- прямая ссылка, QR-код и постоянная подписка.

### Network

- Default Outbound;
- Traffic Rules с приоритетами;
- пользовательские VLESS Outbounds;
- Cloudflare WARP для всего трафика или отдельных направлений;
- встроенный DNS Xray, DoH/DoQ/UDP upstream и статические hosts-записи;
- Sniffing и `Route only`.

### Проверяемая конфигурация

Все изменяющие Xray операции проходят одинаковый безопасный цикл:

```text
Изменить форму или JSON
        |
        v
Проверить конфигурацию
        |
        v
Временная копия SQLite
        |
        v
Проверка модели SG-Panel и xray run -test
        |
        v
Сохранить и применить
```

Во время проверки рабочая база и запущенный Xray не изменяются. Если после проверки изменить хотя бы одно поле, сохранение снова блокируется до новой проверки.

### Доступ и безопасность

- backend панели слушает только `127.0.0.1:8080`;
- публичный доступ обеспечивает Nginx на отдельном выбранном порту;
- начальная установка возможна по IP и HTTP;
- HTTPS с Let's Encrypt включается позже из интерфейса;
- пароль администратора, активные сессии и их завершение;
- IP allowlist для панели и отдельно для подписок;
- журнал входов и действий администратора;
- CSRF-защита форм.

### Резервные копии и восстановление

- создание и проверка резервной копии;
- скачивание SQLite и итогового `config.json`;
- полное восстановление с повторной генерацией конфигурации;
- автоматическая копия перед опасными операциями;
- rollback при ошибке применения или обновления.

## Входящие профили

| Профиль | Публичная точка | Что требуется | Обычный HTTPS на 443 |
|---|---|---|---|
| `RAW/TCP + REALITY` | `443/tcp` | IP или hostname, Reality target и SNI | после настройки домена уходит на локальную SG-заглушку |
| `XHTTP + REALITY` | `443/tcp` | Reality и XHTTP path, `mode: auto` | после настройки домена уходит на локальную SG-заглушку |
| `XHTTP + TLS` | `443/tcp` через Nginx | домен и сертификат Let's Encrypt | показывает локальную SG-заглушку вне клиентского path |
| `gRPC + TLS` | `443/tcp` через Nginx | домен, сертификат и service name | показывает локальную SG-заглушку вне gRPC service |
| `Hysteria 2 + TLS` | `443/udp` по умолчанию | домен и сертификат | `443/tcp` остаётся у локальной SG-заглушки |

Порт панели не должен совпадать с `22`, `80`, `443`, `8080` или `8443`.

## Требования

- отдельный сервер или EC2 с Ubuntu Server 24.04 LTS;
- архитектура `amd64`;
- права `root` или `sudo`;
- минимум 1 ГиБ RAM;
- публичный или локальный IPv4 либо hostname;
- открытый TCP `443` для VLESS-профилей;
- открытый UDP `443` для Hysteria 2, если используется стандартный порт;
- отдельный TCP-порт панели, по умолчанию `61443`.

Домен, DNS-запись и сертификат не нужны для первой установки с `RAW/TCP + REALITY`. Они понадобятся для HTTPS панели и TLS-профилей.

## Порты

| Порт | Назначение | Доступ извне |
|---:|---|---|
| `22/tcp` | SSH | только административный IP |
| `80/tcp` | SG-заглушка и HTTP-01 Let's Encrypt | нужен для выпуска/продления сертификата |
| `443/tcp` | VLESS или HTTPS/fallback | клиентские адреса |
| `443/udp` | Hysteria 2 | клиентские адреса |
| `61443/tcp` | HTTP или HTTPS панели | только административный IP или локальная сеть |
| `8080/tcp` | backend SG-Panel | не открывать |
| `8443/tcp` | локальный Xray для XHTTP/gRPC TLS | не открывать |

При port hopping откройте только тот UDP-диапазон, который указан в Hysteria Studio.

## Чистая установка

**Первоначальная установка больше не требует домена.** Панель сначала открывается по адресу `http://SERVER_IP:61443`, а HTTPS включается позже в разделе `Безопасность → Доступ к панели` (`Security → Panel Access`).

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Не используйте `curl | bash`: мастер установки должен читать ответы с клавиатуры.

Установщик запросит:

1. адрес Xray для клиентов;
2. публичный порт панели;
3. имя первого клиента;
4. Reality target;
5. Reality SNI;
6. пароль администратора.

После завершения откройте адрес, показанный установщиком, например:

```text
http://203.0.113.10:61443
```

Первая клиентская ссылка сохраняется в:

```bash
sudo cat /root/sg-panel-first-user.txt
```

Подробная последовательность: [Установка](docs/INSTALLATION.md).

## Первый вход

После авторизации открывается `System → Resources`.

Рекомендуемый первый порядок:

1. убедиться, что SG-Panel, Xray и Nginx активны;
2. открыть `Clients` и проверить первого клиента;
3. импортировать прямую ссылку или подписку в клиент;
4. проверить подключение;
5. только после этого менять Inbound, WARP, Traffic Rules или DNS.

Полное руководство: [Руководство пользователя](docs/USER-GUIDE.md).

## Включение HTTPS

1. Создайте DNS-запись `A`, направленную на публичный IPv4 сервера.
2. Разрешите TCP `80` и выбранный порт панели.
3. Откройте `Security → Panel Access`.
4. Выберите `HTTPS + Let's Encrypt`.
5. Укажите домен без `http://` и `https://`.
6. Нажмите **«Сохранить и применить»**.
7. Дождитесь завершения живого журнала операции.

Панель продолжит работать на отдельном порту, например:

```text
https://panel.example.com:61443
```

Подробности: [HTTPS и fallback](docs/HTTPS.md).

## Основные разделы

| Раздел | Назначение |
|---|---|
| **System** | память, ресурсы, службы, журналы и диагностика |
| **Clients** | клиенты, сроки, ссылки, подписки и статистика трафика |
| **Xray Server** | Inbound-профиль, Hysteria Studio и итоговый config.json |
| **Network** | Traffic Rules, Outbounds, WARP и DNS |
| **Security** | HTTP/HTTPS, пароль, сессии, allowlist и журналы входа |
| **Maintenance** | резервные копии, восстановление и обслуживание |

## Hysteria 2 через WARP

Подтверждён рабочий маршрут:

```text
Клиент → Hysteria 2 → Xray → WARP → Интернет
```

Hysteria 2 остаётся входящим профилем, а WARP используется как Default Outbound. Клиентскую ссылку, UDP-порт, Auth, TLS и masquerade менять не требуется. Пошаговое включение и возврат на `direct`: [Cloudflare WARP](docs/WARP.md#подтверждённый-сценарий-hysteria-2-через-warp).

## Документация

- [Руководство пользователя](docs/USER-GUIDE.md)
- [Установка](docs/INSTALLATION.md)
- [Интерфейс и раздел System](docs/PANEL.md)
- [Clients & Traffic Studio](docs/CLIENTS.md)
- [Ссылки, QR-коды и подписки](docs/PROTECTED-LINKS.md)
- [Xray Server и Inbound-профили](docs/SERVER.md)
- [Traffic Rules](docs/TRAFFIC-RULES.md)
- [Outbounds](docs/OUTBOUNDS.md)
- [DNS](docs/DNS.md)
- [Cloudflare WARP](docs/WARP.md)
- [JSON и Generated Config](docs/JSON-EDITOR.md)
- [HTTPS и fallback](docs/HTTPS.md)
- [Security](docs/SECURITY.md)
- [Maintenance и резервные копии](docs/MAINTENANCE.md)
- [Диагностика](docs/DIAGNOSTICS.md)
- [Полное удаление](docs/UNINSTALL.md)

## Обновление

Повторно запустите установочную команду. Установщик обнаружит существующую установку, сохранит SQLite, пользователей, UUID/Auth, ключи, подписки, сетевые настройки, статистику и текущий режим HTTP/HTTPS.

Перед изменениями создаётся резервная копия. При ошибке выполняется автоматический откат.

После обновления проверьте:

```bash
cd /opt/xpanel-mvp
.venv/bin/python -m xpanel --version
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
systemctl is-active xpanel-traffic.timer
```

## Полное удаление

Обычный uninstall устроен **безопасно по умолчанию**: он удаляет панель и её службы, но не удаляет Xray, Nginx, сертификаты и резервные копии без явного выбора. Подробности: [Полное удаление](docs/UNINSTALL.md).

Обычный uninstall удаляет панель и её службы, но по умолчанию сохраняет Xray, Nginx, сертификаты и резервные копии.

Для полной очистки отдельного тестового сервера:

```bash
sudo bash /opt/xpanel-mvp/FULL-UNINSTALL-SG-PANEL.sh --yes
```

Скрипт удаляет SG-Panel, Xray, WARP, Nginx, Certbot, сертификаты, fallback/заглушку, резервные копии и swap. SSH, сеть Ubuntu, пользовательские файлы в `/home` и Security Group EC2 не изменяются.

## Проверенное состояние RC30

На реальном EC2 подтверждены:

- чистая установка и обновление;
- все пять Inbound-профилей;
- fallback обычного HTTPS на локальный Nginx;
- создание клиентов, прямые ссылки, QR-коды и подписки;
- общий и персональный учёт трафика;
- персональный и общий сброс статистики;
- Hysteria 2 через v2rayN;
- Hysteria 2 с выходом всего трафика через Cloudflare WARP;
- полный uninstall.

Функцию, которая не перечислена как проверенная, не следует считать подтверждённой только по наличию кнопки или кода.

## Основные пути

```text
/opt/xpanel-mvp                         приложение
/opt/xpanel-mvp/data/panel.db           SQLite
/usr/local/etc/xray/config.json         активная конфигурация Xray
/etc/xpanel-mvp/web.env                 параметры backend
/etc/xpanel-mvp/panel-access.env        публичный режим панели
/root/sg-panel-backups                  резервные копии
/root/sg-panel-first-user.txt           первая клиентская ссылка
```

## Ответственность

Используйте проект в соответствии с законодательством вашей страны и правилами провайдера. Перед установкой на сервер с другими сервисами изучите действия installer, updater и полного uninstall.

Проект: **Ser.Gor**.
