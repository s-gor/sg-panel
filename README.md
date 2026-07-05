<p align="center">
  <img src="xpanel/static/favicon.svg" width="92" alt="SG-Panel">
</p>

<h1 align="center">SG-Panel</h1>

<p align="center">
  Собственная веб-панель для установки, настройки и безопасного обслуживания Xray-сервера.
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.10.0--rc45-35d69a">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Xray" src="https://img.shields.io/badge/Xray-v26.5.9-5b8def">
  <img alt="Tests" src="https://img.shields.io/badge/tests-364%20%2B%202%20subtests-35d69a">
</p>

<p align="center">
  <img src="docs/assets/sg-panel-rc45-graphite.png" alt="SG-Panel v0.10.0 RC45 — тема Графит">
</p>

> Текущая версия: **`v0.10.0-rc45`**. Основная тема — **Графит**. В панели оставлены ровно две темы: **Графит** и **Светлая**.

## Что такое SG-Panel

SG-Panel разворачивает и обслуживает один собственный Xray-сервер на Ubuntu Server 24.04. Панель управляет клиентами, входящими профилями, подписками, трафиком, маршрутами, Outbounds, DNS, Cloudflare WARP, HTTPS, резервными копиями и обновлениями.

Проект не пытается быть универсальной панелью для любых схем. В интерфейсе доступны только те режимы, которые SG-Panel умеет полностью сформировать, проверить, применить и восстановить при ошибке.

```text
Клиент
   |
   v
SG-Panel / Xray Server
   |
   +-- direct ------> Интернет через IP сервера
   +-- warp --------> Интернет через Cloudflare WARP
   +-- outbound ----> Другой Xray-сервер
```

## Основные возможности

### Пять доступных входящих профилей

SG-Panel поддерживает пять доступных входящих профилей, сгруппированных по типу внешней защиты.

| Семья | Профиль | Публичная точка | Сертификат |
|---|---|---|---|
| **REALITY · без сертификата** | `VLESS REALITY` | TCP, обычно `443` | не нужен |
| **REALITY · без сертификата** | `VLESS XHTTP-REALITY` | TCP/XHTTP, обычно `443` | не нужен |
| **TLS · нужен сертификат** | `VLESS XHTTP-TLS` | TCP `443` через Nginx | нужен |
| **TLS · нужен сертификат** | `Hysteria 2` | QUIC/UDP, основной порт `443` | нужен |
| **TLS · нужен сертификат** | `XHTTP-TLS + Hysteria 2` | TCP и UDP одновременно | нужен |

Для XHTTP доступны режимы `auto`, `packet-up`, `stream-up` и `stream-one`. Выбранный режим сохраняется и в серверной конфигурации, и в клиентской ссылке.

### Multi-Inbound

- до трёх `VLESS REALITY` точек: `Primary`, `Backup`, `Alt`;
- до трёх `VLESS XHTTP-TLS` Inbound через один публичный `TCP/443`, разные Path и локальные порты `8443`, `8444`, `8445`;
- до трёх `Hysteria 2` Inbound на отдельных UDP-портах;
- смешанный профиль объединяет до трёх XHTTP и до трёх Hysteria 2 Inbound;
- при Vision несколько публичных REALITY-точек обслуживаются одним общим Xray Inbound;
- сохранённые, но неактивные ссылки не исчезают со страницы клиента;
- постоянная подписка содержит только реально активные соединения.

### Clients & Traffic Studio

- отдельный UUID или Hysteria auth для каждого клиента;
- имя, комментарий, срок действия и включение/отключение;
- прямая ссылка, QR-код и постоянная подписка;
- последняя активность и online-состояние;
- текущая скорость, сессия, день, месяц и общий трафик;
- график за 14 дней;
- персональный и общий сброс статистики без удаления профилей.

### Network

- `Default Outbound`;
- Traffic Rules с приоритетами;
- пользовательские VLESS Outbounds;
- Cloudflare WARP для всего трафика или отдельных направлений;
- встроенный DNS Xray: UDP/TCP, DoH, DoQ Local и hosts-записи;
- Sniffing и `Route only`.

### Безопасное применение конфигурации

Любое изменение Inbound, Clients, Network или JSON проходит один обязательный цикл:

1. Изменить параметры.
2. Нажать **«Проверить конфигурацию»**.
3. SG-Panel применит черновик только к временной копии SQLite.
4. Панель сформирует полный кандидат `config.json` и выполнит `xray run -test`.
5. Только после успешной проверки станет доступно **«Сохранить и применить»**.

Если проверка не проходит, рабочая база и запущенный Xray не заменяются. Если после проверки изменить хотя бы одно поле, сохранение снова блокируется до новой проверки.

### Доступ и защита панели

- backend слушает только `127.0.0.1:8080`;
- публичный доступ обслуживает Nginx на отдельном порту;
- первая установка возможна по IP и HTTP;
- HTTPS с Let's Encrypt включается позже из интерфейса;
- смена пароля, управление сессиями и журнал входов;
- IP allowlist отдельно для панели и подписок;
- CSRF-защита форм.

### Резервные копии и обновления

- создание и проверка резервной копии;
- скачивание SQLite и итогового `config.json`;
- восстановление с повторной генерацией конфигурации;
- автоматическая копия перед опасными операциями;
- rollback при ошибке применения;
- отдельная вкладка `Maintenance → Updates`;
- проверка Xray Core по Stable и Pre-release каналам;
- автоматический rollback при неудачном обновлении.

### Встроенная справка

Раздел **Help** объясняет профили, Inbound, публичные точки входа, XTLS Vision, активные и сохранённые ссылки, TLS/HTTPS, Traffic Rules, Outbounds, DNS, резервные копии, обновления и диагностику. Контекстные значки `?` открывают сразу нужный раздел.

## Две темы

<table>
<tr>
<td width="50%" valign="top">
<strong>Графит</strong><br><br>
Основная тема SG-Panel. Использует общую палитру SG Client / SG-Panel. Зелёный цвет применяется только к активным и успешным состояниям.
<br><br>
<img src="docs/assets/sg-panel-rc45-graphite.png" alt="Тема Графит">
</td>
<td width="50%" valign="top">
<strong>Светлая</strong><br><br>
Второй рабочий режим для пользователей, которым нужен светлый интерфейс. Системная тема удалена, автоматического переключения по ОС нет.
<br><br>
<img src="docs/assets/sg-panel-rc45-light.png" alt="Светлая тема">
</td>
</tr>
</table>

Подробнее: [Темы SG-Panel](docs/THEMES.md).

## Требования

- Ubuntu Server 24.04 LTS;
- архитектура `amd64`;
- права `root` или `sudo`;
- минимум 1 ГиБ RAM;
- публичный или локальный IPv4 либо hostname;
- отдельный TCP-порт панели, по умолчанию `61443`.

Домен и сертификат не требуются для первой установки с `VLESS REALITY`. Они понадобятся для HTTPS панели и TLS-профилей.

## Порты

| Порт | Назначение | Открывать извне |
|---:|---|---|
| `22/tcp` | SSH | только административный IP |
| `80/tcp` | SG-заглушка и HTTP-01 Let's Encrypt | да, для выпуска и продления сертификата |
| `443/tcp` | VLESS и обычный HTTPS/fallback на локальный Nginx с SG-заглушкой | для клиентов |
| `443/udp` | основной Hysteria 2 | для клиентов Hysteria 2 |
| `8443/udp`, `9443/udp` | дополнительные Hysteria 2 | только если включены |
| `61443/tcp` | HTTP/HTTPS панели | только административный IP или локальная сеть |
| `8080/tcp` | backend SG-Panel | не открывать |
| `8443/tcp`–`8445/tcp` | локальные XHTTP listener за Nginx | не открывать |

TCP и UDP — разные транспортные протоколы. Например, `443/tcp` может обслуживать Nginx/XHTTP, а `443/udp` — Hysteria 2.

## Чистая установка

**Первоначальная установка больше не требует домена.** Начальная панель работает по HTTP, а HTTPS включается позже в разделе `Безопасность → Доступ к панели`.

Установщик сначала собирает все ответы, включая пароль и его повтор, и только затем начинает установку. После начала системных операций дополнительных вопросов нет.

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Не используйте `curl | bash`: интерактивный мастер должен читать ответы с клавиатуры.

Когда мастер показывает рекомендуемое значение, например:

```text
Порт панели [61443]:
```

для его принятия просто нажмите **Enter**.

После завершения откройте адрес, показанный установщиком:

```text
http://SERVER_IP:61443
```

Первая клиентская ссылка сохраняется в:

```bash
sudo cat /root/sg-panel-first-user.txt
```

Подробности: [Установка](docs/INSTALLATION.md).

## Первый порядок проверки

1. Открыть `System → Resources`.
2. Убедиться, что SG-Panel, Xray и Nginx активны.
3. Открыть `Clients` и проверить первого клиента.
4. Импортировать прямую ссылку или подписку.
5. Проверить реальное подключение.
6. Только после этого менять Inbound, WARP, Traffic Rules или DNS.

## Обновление

1. Откройте `Maintenance → Updates`.
2. Нажмите **«Проверить сейчас»**.
3. Убедитесь, что показана ожидаемая версия.
4. Нажмите **«Обновить до …»**.
5. Следите за живым журналом до состояния **«Готово»** или **«Восстановлено»**.

Перед изменением сервера updater создаёт страховочную копию приложения, SQLite, Xray, WARP, DNS, Traffic Rules, Outbounds, Nginx, systemd-файлов и сведений о сертификатах. Затем проверяются локальный `/health`, `xray run -test`, Xray, Nginx и таймеры. При ошибке выполняется автоматический rollback.

Установленный более новый Xray не понижается обычным обновлением SG-Panel.

## Полное удаление

Обычный uninstall устроен безопасно по умолчанию: он удаляет панель и её службы, но не удаляет Xray, Nginx, сертификаты и резервные копии без явного выбора.

Для полной очистки отдельного тестового сервера:

```bash
sudo bash /opt/xpanel-mvp/FULL-UNINSTALL-SG-PANEL.sh --yes
```

Скрипт не изменяет SSH, сеть Ubuntu, пользовательские файлы в `/home` и Security Group провайдера.

## Документация

### Начало работы

- [С чего начать](docs/START-HERE.md)
- [Руководство пользователя](docs/USER-GUIDE.md)
- [Установка](docs/INSTALLATION.md)
- [Интерфейс, Help и темы](docs/PANEL.md)
- [Темы SG-Panel](docs/THEMES.md)

### Клиенты и подключения

- [Clients & Traffic Studio](docs/CLIENTS.md)
- [Ссылки, QR-коды и подписки](docs/PROTECTED-LINKS.md)
- [Xray Server и Inbound-профили](docs/SERVER.md)
- [Схемы движения трафика](docs/TRAFFIC-FLOWS.md)

### Network

- [Traffic Rules](docs/TRAFFIC-RULES.md)
- [Outbounds](docs/OUTBOUNDS.md)
- [DNS](docs/DNS.md)
- [Cloudflare WARP](docs/WARP.md)

### Конфигурация, безопасность и обслуживание

- [JSON и Generated Config](docs/JSON-EDITOR.md)
- [HTTPS и fallback](docs/HTTPS.md)
- [Security](docs/SECURITY.md)
- [Резервные копии и обновления](docs/MAINTENANCE.md)
- [Диагностика](docs/DIAGNOSTICS.md)
- [Полное удаление](docs/UNINSTALL.md)

## Что нового в RC45

- оставлены ровно две темы: **Графит** и **Светлая**;
- **Графит** установлен по умолчанию;
- системная тема и автоматическое переключение по ОС удалены;
- старые значения `system` и `dark` автоматически переводятся в `graphite`;
- графитовая палитра применена к оболочке, меню, карточкам, формам, JSON-редакторам, входу, статусам и страницам профилей;
- активный профиль, UUID, REALITY-ключи, Short ID, XHTTP Path, Hysteria auth, порты, сертификаты и клиентские ссылки не изменяются.

Полное описание: [Release Notes RC45](RELEASE-NOTES-RC45.md). История проекта: [CHANGELOG](CHANGELOG.md).

## Основные пути на сервере

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

Используйте проект в соответствии с законодательством своей страны и правилами провайдера. Перед установкой на сервер с другими сервисами изучите installer, updater и полный uninstall.

Проект: **Ser.Gor**.
