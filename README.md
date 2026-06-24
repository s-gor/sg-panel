# SG-Panel v0.9.3 — EC2 Ready

SG-Panel — небольшая панель управления Xray Reality на Python, Flask и
SQLite.

Версия 0.9.3 сохраняет все функции и дизайн v0.9.2, но добавляет полноценный
сценарий первой установки на Amazon EC2.

## Главное в v0.9.3

- мастер `deploy/ec2-first-install.sh`;
- Xray Reality на `443`;
- панель через Nginx HTTPS на private-порту `61443`;
- выбор внешнего HTTPS-порта пользователем;
- допустимый диапазон внешнего порта `49152–65535`;
- автоматическое резервирование выбранного порта в Linux;
- backend панели только на `127.0.0.1:8080`;
- автоматическое получение сертификата Let's Encrypt;
- проверка Dynu A-записи до выпуска сертификата;
- автоматическая настройка renewal hook для Nginx;
- печать готовой VLESS-ссылки после установки.

Полная инструкция:

```text
README-EC2.md
```

## Быстрый запуск на EC2

До запуска:

1. создайте EC2;
2. назначьте Elastic IP;
3. направьте Dynu A-запись на Elastic IP;
4. откройте в Security Group TCP `22`, `80`, `443` и `61443`;
5. не открывайте TCP `8080`.

На сервере:

```bash
sudo -i
apt update
apt install -y unzip

unzip -q /tmp/SG-Panel-v0.9.3.zip \
  -d /tmp/sg-panel-v093

cd /tmp/sg-panel-v093/xpanel-mvp
./deploy/ec2-first-install.sh
```

После установки:

```text
Xray:         https не используется, VLESS Reality на ДОМЕН:443
SG-Panel:  https://ДОМЕН:61443
Backend GUI:  127.0.0.1:8080
```

## Обычная локальная установка или обновление

```bash
sudo ./install-or-upgrade.sh
```

Стандартный установщик сохраняет:

- SQLite-базу;
- пользователей;
- Reality-ключи;
- routing и outbounds;
- DNS;
- подписки;
- настройки безопасности;
- пароль GUI;
- текущий Xray-конфиг.

## Проверка версии

```bash
cd /opt/xpanel-mvp
.venv/bin/python -m xpanel --version
```

Ожидается:

```text
xpanel 0.9.3
```

## Основные возможности

- VLESS Reality inbound;
- пользователи, UUID, сроки действия и статистика;
- клиентские ссылки, QR-коды и постоянные подписки;
- генерация, backup и проверка `config.json`;
- Routing и VLESS Reality outbounds;
- управляемый DNS Xray;
- диагностика и восстановление;
- защита входа, сессии, IP allowlist и аудит;
- GUI и CLI.

## Структура портов EC2

```text
22       SSH, только доверенный IP
80       Let's Encrypt HTTP-01
443      Xray Reality
61443    SG-Panel HTTPS, только доверенный IP
8080     backend панели, только localhost
```

## Перед версией 1.0.0

Версия 0.9.3 предназначена для контрольной чистой установки на EC2. После
проверки установки, перезагрузки, сертификата и подключения клиента сборка
будет зафиксирована как стабильная версия 1.0.0.
