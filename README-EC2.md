# SG-Panel v0.9.3: установка на Amazon EC2

Эта версия предназначена для первой реальной проверки SG-Panel на EC2.
После успешной проверки именно эта схема станет основой версии 1.0.0.

## Итоговая схема

```text
Dynu-домен:443
    → Xray Reality

Dynu-домен:61443
    → Nginx HTTPS
    → SG-Panel 127.0.0.1:8080

Dynu-домен:80
    → ACME HTTP-01 для Let's Encrypt
```

Один Dynu-домен можно использовать одновременно:

```text
vpn-example.dynu.net:443    → Xray Reality
vpn-example.dynu.net:61443  → SG-Panel HTTPS
```

Порт `8080` является внутренним и не должен открываться в AWS Security Group.

## 1. Создание EC2

Рекомендуется:

```text
AMI: Ubuntu Server 24.04 LTS
Instance type: t3.micro для проверки или t3.small для постоянной работы
Disk: 16–20 GB gp3
Public subnet: да
Auto-assign public IPv4: можно включить для первого запуска
```

После создания назначьте инстансу Elastic IP. Затем создайте в Dynu A-запись,
указывающую на этот Elastic IP.

Пример:

```text
vpn-example.dynu.net → 203.0.113.10
```

## 2. AWS Security Group

До запуска установщика создайте правила:

| Протокол | Порт | Источник | Назначение |
|---|---:|---|---|
| TCP | 22 | ваш внешний IP `/32` | SSH |
| TCP | 80 | `0.0.0.0/0` | Let's Encrypt HTTP-01 |
| TCP | 443 | `0.0.0.0/0` | Xray Reality |
| TCP | 61443 | ваш внешний IP `/32` | HTTPS панели |

Если при установке выбран другой порт панели, откройте именно его вместо
`61443`.

Не открывайте:

```text
TCP 8080
```

## 3. Копирование архива

На компьютере:

```powershell
scp "$env:USERPROFILE\Downloads\SG-Panel-v0.9.3.zip" \
  ubuntu@PUBLIC_IP:/tmp/
```

Если AMI или пользователь другой, замените `ubuntu` на нужное имя.

Подключение:

```powershell
ssh ubuntu@PUBLIC_IP
```

## 4. Запуск мастера

На EC2:

```bash
sudo -i
apt update
apt install -y unzip

rm -rf /tmp/sg-panel-v093
mkdir -p /tmp/sg-panel-v093

unzip -q /tmp/SG-Panel-v0.9.3.zip \
  -d /tmp/sg-panel-v093

cd /tmp/sg-panel-v093/xpanel-mvp

./deploy/ec2-first-install.sh
```

Мастер запросит:

```text
Домен подключения Xray в Dynu
Домен HTTPS-панели
Email для Let's Encrypt
Внешний HTTPS-порт панели [61443]
Имя первого пользователя [Sergey]
Reality target [www.microsoft.com:443]
Reality SNI [www.microsoft.com]
Пароль администратора панели
```

Один домен можно указать в первых двух полях.

## 5. Что делает мастер

Мастер последовательно:

1. проверяет версию архива;
2. устанавливает системные пакеты;
3. определяет публичный IPv4 EC2;
4. проверяет, что Dynu A-записи уже указывают на этот IP;
5. устанавливает Xray 26.3.27;
6. устанавливает SG-Panel;
7. привязывает backend GUI к `127.0.0.1:8080`;
8. создаёт Reality-ключи;
9. создаёт первого пользователя;
10. формирует и проверяет `config.json`;
11. запускает Xray на `443`;
12. получает сертификат Let's Encrypt через порт `80`;
13. настраивает Nginx HTTPS на выбранном порту;
14. резервирует порт панели в Linux;
15. выполняет финальную проверку Xray, Nginx и GUI;
16. печатает VLESS-ссылку первого пользователя.

## 6. Открытие панели

Если выбран порт по умолчанию:

```text
https://ВАШ-ДОМЕН:61443
```

Вход выполняется паролем, заданным при установке.

## 7. Проверка служб

```bash
cd /opt/xpanel-mvp

.venv/bin/python -m xpanel --version
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
systemctl is-active xpanel-maintenance.timer
```

Ожидается:

```text
xpanel 0.9.3
active
active
active
active
```

Проверка портов:

```bash
ss -lntp | grep -E ':80|:443|:8080|:61443'
```

Ожидаемая схема:

```text
0.0.0.0:80       nginx
0.0.0.0:443      xray
127.0.0.1:8080   waitress-serve
0.0.0.0:61443    nginx
```

## 8. Почему используется порт 61443

Диапазон `49152–65535` предназначен для private/dynamic ports и не закреплён
IANA за конкретными публичными сервисами. Для собственной административной
панели это понятнее, чем занимать произвольный registered port.

Linux может использовать часть высоких портов для временных исходящих
соединений. Поэтому установщик добавляет выбранный порт в:

```text
net.ipv4.ip_local_reserved_ports
```

Проверка:

```bash
sysctl net.ipv4.ip_local_reserved_ports
```

## 9. Сертификат

Nginx оставляет порт `80` для каталога:

```text
/.well-known/acme-challenge/
```

Это позволяет Certbot автоматически обновлять сертификат. После обновления
срабатывает deploy hook, который перезагружает Nginx.

Проверка renewal без выпуска нового сертификата:

```bash
certbot renew --dry-run
```

## 10. Обновление панели

Следующие версии устанавливаются стандартным скриптом:

```bash
cd /tmp/НОВАЯ-ВЕРСИЯ/xpanel-mvp
sudo ./install-or-upgrade.sh
```

Существующие база, пароль, Reality-ключи и настройки сохраняются.

## 11. Что установщик не делает

Мастер не изменяет AWS Security Group и не создаёт Elastic IP через AWS API.
Эти действия выполняются в AWS Console до установки.

Мастер также не создаёт Dynu-запись: он только проверяет, что запись уже
указывает на публичный IPv4 EC2.

## Установка из GitHub Release

После публикации релиза в репозитории `s-gor/sg-panel` установка выполняется без ручного копирования ZIP:

```bash
sudo -i
apt update
apt install -y curl unzip
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh \
  -o /tmp/install-sg-panel.sh
chmod +x /tmp/install-sg-panel.sh
VERSION=v0.9.3 /tmp/install-sg-panel.sh
```

Скрипт скачивает ZIP и файл SHA-256 из GitHub Releases, проверяет контрольную сумму и только затем запускает EC2-мастер.
