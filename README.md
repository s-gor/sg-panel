<p align="center">
  <img src="xpanel/static/favicon.svg" width="92" alt="SG-Panel">
</p>

<h1 align="center">SG-Panel</h1>

<p align="center">
  Веб-панель для установки, настройки и безопасного обслуживания собственного Xray-сервера.
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.10.0--rc70-35d69a">
  <img alt="Build" src="https://img.shields.io/badge/build-FIX40%20UI23-5b8def">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%2B-E95420?logo=ubuntu&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Xray" src="https://img.shields.io/badge/Xray-v26.6.27-5b8def">
</p>

<p align="center">
  <img src="docs/assets/sg-panel-rc45-graphite.png" alt="SG-Panel — тема Графит">
</p>

> Текущая чистая GitHub-база: **`v0.10.0-rc70` · `Preview 9 · FIX40 · UI23`**.
>
> Ветка содержит Hysteria2 Salamander FinalMask, компактный Cluster, пошаговый Cascade, восстановленную карточку SG-Node и Worker `0.7.0`. Отвергнутый Routing UI25 и экспериментальные UI24-обёртки установщика в базу не входят.

## Что умеет SG-Panel

SG-Panel управляет собственным Xray-сервером на Ubuntu 22.04 и новее:

- VLESS REALITY;
- VLESS XHTTP REALITY;
- VLESS XHTTP TLS;
- Hysteria2;
- смешанный XHTTP TLS + Hysteria2;
- Hysteria2 Salamander FinalMask;
- клиенты, устройства, QR-коды и постоянные subscriptions;
- Routing, пользовательские Outbounds, DNS и Cloudflare WARP;
- GeoFiles с staging, `xray run -test`, backup и rollback;
- Controller, SG-Node, центральная клиентская база и deployments;
- Cascade через SG-Node или вторую самостоятельную SG-Panel;
- HTTPS, резервные копии, диагностика и обновления.

Проект показывает в обычном интерфейсе только те операции, которые может сформировать, проверить, применить и восстановить при ошибке.

## Архитектура

```text
Клиент
   |
   v
Controller / SG-Panel
   |
   +-- Direct -----------------> Интернет через Controller
   +-- WARP -------------------> Интернет через Cloudflare WARP
   +-- Outbound ---------------> Другой Xray-сервер
   +-- Cascade через SG-Node --> Интернет через выбранную Node
```

Controller является источником истины для клиентов. Один клиент может иметь отдельные deployments на Controller и SG-Node без создания нового UUID/Auth.

## Hysteria2 Salamander

Salamander хранится и применяется на уровне конкретного Hysteria2 Inbound. SG-Panel:

- генерирует отдельный криптографически стойкий пароль;
- безопасно объединяет Salamander с существующим `finalmask`;
- сохраняет `quicParams`, TCP-слои и другие UDP-слои;
- проверяет минимальную версию Xray `v26.3.27`;
- строит полный candidate и запускает `xray run -test`;
- использует один URI builder для Copy, QR, downloads и subscriptions;
- не выводит пароль в обычные журналы и diagnostic bundle;
- сохраняет тот же пароль в backup/restore.

Подробный контракт: [Hysteria2 Salamander FinalMask](docs/HYSTERIA2-SALAMANDER.md).

**Граница приёмки:** код, миграция, candidate, URI, backup и rollback реализованы. Реальное внешнее подключение Hysteria2 + Salamander ещё должно быть подтверждено отдельным live-тестом.

## Cluster и SG-Node

Cluster поддерживает:

- компактный список Controller и SG-Node;
- onboarding через `+ Добавить SG-Node`;
- Agent и Worker;
- централизованные клиентские deployments;
- атомарные задания с локальным `xray run -test`, backup и rollback;
- сохранение существующего Xray-конфига Node при служебных операциях Cascade.

Версии runtime текущей базы:

```text
Agent  0.5.0
Worker 0.7.0
```

Agent сообщает Controller реальную версию Worker `0.7.0`.

Подробнее: [Cluster и SG-Node](docs/MULTI-NODE.md).

## Cascade

Два режима:

1. **SG-Node из Cluster** — выбрать online Node и включить Cascade одной кнопкой.
2. **Другая SG-Panel** — создать служебную ссылку на сервере выхода и вставить её на сервере подключения клиентов.

Controller не заменяет полный Xray config SG-Node. Worker объединяет только управляемый служебный доступ, проверяет candidate и выполняет rollback при ошибке.

Подробнее: [Cascade](docs/CASCADE.md).

## GeoFiles и Routing

GeoFiles работают парой `geoip.dat` + `geosite.dat` и поддерживают:

- встроенный комплект SG Client;
- Loyalsoldier;
- RunetFreedom;
- RoscomVPN;
- пользовательские HTTPS URL;
- загрузку или выбор локальной пары.

Полный будущий Routing и Xray config проверяются со staging до изменения live-файлов. Отсутствующие geo-категории не удаляются автоматически из пользовательских правил.

Подробнее: [Routing](docs/ROUTING.md) и [GeoFiles](docs/EXPERT-TRANSPORT-GEOFILES.md).

## Установка из GitHub

На чистой Ubuntu 22.04 или новее:

```bash
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh
sudo bash /tmp/install-sg-panel.sh
```

Не используйте `curl | bash`: мастер задаёт начальные вопросы в интерактивном терминале.

Установщик:

1. ждёт завершения cloud-init и apt/dpkg;
2. устанавливает системные зависимости;
3. определяет публичный IPv4;
4. один раз запрашивает пароль, порт, адрес, имя сервера и Reality-параметры;
5. устанавливает SG-Panel, Xray и Nginx;
6. создаёт первый профиль;
7. проверяет службы и итоговый Xray config.

Начальная установка работает по HTTP и не требует домена или TLS-сертификата. HTTPS включается позднее из панели.

Подробности: [Установка](docs/INSTALLATION.md).

## Обновление из локального исходного дерева

В корне проверенной версии:

```bash
sudo bash install-or-upgrade.sh
```

Updater создаёт страховочную копию и при ошибке возвращает приложение, SQLite, Xray config, доступ панели и Node runtime.

## Полное удаление

```bash
sudo bash FULL-UNINSTALL-SG-PANEL.sh
```

Подробности: [Удаление](docs/UNINSTALL.md).

## Разработка и проверка

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m compileall -q xpanel tests
find . -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
```

GitHub Actions запускает тесты на Python 3.12 и 3.13.

## Структура

```text
xpanel/       приложение и веб-интерфейс
node_agent/   SG-Node Agent и Worker
deploy/       установка, обновление и обслуживание
tests/        функциональные и регрессионные тесты
docs/         пользовательская и техническая документация
assets/       встроенные GeoFiles
```

## Документация

- [Начало работы](docs/START-HERE.md)
- [Установка](docs/INSTALLATION.md)
- [Пользовательское руководство](docs/USER-GUIDE.md)
- [Clients](docs/CLIENTS.md)
- [Routing](docs/ROUTING.md)
- [Outbounds](docs/OUTBOUNDS.md)
- [Cluster и SG-Node](docs/MULTI-NODE.md)
- [Cascade](docs/CASCADE.md)
- [Hysteria2 Salamander](docs/HYSTERIA2-SALAMANDER.md)
- [Backup](docs/BACKUPS.md)
- [Diagnostics](docs/DIAGNOSTICS.md)
- [Security](docs/SECURITY.md)
- [Changelog](CHANGELOG.md)

## Текущая линия

Эта публикация является чистой cumulative-базой UI23. Дальнейшие изменения должны идти от неё без возврата удалённых build-отчётов, временных архивов и отвергнутых UI24/UI25.
