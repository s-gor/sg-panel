# Чистая установка SG-Panel

Инструкция рассчитана на новый Ubuntu EC2 без других сайтов, панелей и сертификатов.

## 1. Создайте сервер

Минимальная конфигурация для личного использования:

```text
Ubuntu
1 vCPU
1 ГиБ RAM
публичный IPv4
```

При малом объёме памяти установщик создаёт swap `2 ГиБ`.

## 2. Настройте Security Group

| Порт | Протокол | Источник |
|---:|---|---|
| `22` | TCP | ваш публичный IP `/32` |
| `80` | TCP | `0.0.0.0/0` |
| `443` | TCP | `0.0.0.0/0` |
| `61443` | TCP | ваш публичный IP `/32` |

Если выберете другой порт панели, откройте его вместо `61443`.

Не открывайте:

```text
8080
8443
```

## 3. Подготовьте DNS

Создайте A-запись домена на публичный IPv4 EC2.

Проверка с Windows:

```powershell
nslookup secure-vpn.example.net
```

Проверка на сервере:

```bash
curl -4 -s https://checkip.amazonaws.com
getent ahostsv4 secure-vpn.example.net
```

Оба адреса должны совпадать.

## 4. Запустите установку

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Пустой вывод после `bash -n` означает, что синтаксис загрузчика корректен.

## 5. Ответьте на вопросы мастера

Пример:

```text
Домен Xray-сервера: secure-vpn.example.net
Домен HTTPS-панели: secure-vpn.example.net
Внешний HTTPS-порт панели [61443]: Enter
Имя первого пользователя [sg-admin]: Enter
Reality target [www.bing.com:443]: Enter
Reality SNI [www.bing.com]: Enter
Пароль администратора панели: ваш пароль
```

Для Xray и панели можно использовать один домен, потому что они работают на разных портах.

## 6. Ожидаемый результат

В конце установщик должен сообщить, что SG-Panel, Xray и Nginx запущены.

Проверка:

```bash
systemctl is-active xpanel-web
systemctl is-active xray
systemctl is-active nginx
systemctl is-active xpanel-maintenance.timer
```

Ожидается:

```text
active
active
active
active
```

Проверка версии:

```bash
cd /opt/xpanel-mvp
.venv/bin/python -m xpanel --version
```

Ожидается:

```text
xpanel 0.10.0-rc9
```

## 7. Откройте панель

```text
https://secure-vpn.example.net:61443
```

Вход выполняется только по паролю администратора. Отдельного имени администратора нет.

Пользователь `sg-admin` является пользователем Xray, а не администратором панели.

## 8. Проверьте первое подключение

Получите ссылку:

```bash
sudo cat /root/sg-panel-first-user.txt
```

Импортируйте её в клиент и подключитесь.

На странице **Обзор** проверьте:

```text
Xray: active
Inbound: RAW/TCP + REALITY
Default Outbound: DIRECT
Пользователи: 1 / 1
```

## 9. Проверка портов

```bash
ss -ltnp | grep -E ':80|:443|:61443|:8080|:8443'
```

Для начального `RAW/TCP + REALITY` ожидается:

```text
Nginx слушает 80
Xray слушает 443
Nginx слушает порт панели
SG-Panel слушает только 127.0.0.1:8080
```

`8443` появится после переключения на `XHTTP + TLS`.

## Если установка прервалась

Повторно запустите ту же команду. Установщик распознаёт незавершённое состояние и снова открывает мастер.

При ошибке Let's Encrypt проверьте:

- A-запись домена;
- доступность `80/tcp`;
- отсутствие другого процесса на `80`;
- лимиты выпуска сертификатов.

Удаление старого сертификата не сбрасывает лимит Let's Encrypt.

## Установка из ZIP

```bash
unzip SG-Panel-v0.10.0-RC9-GITHUB.zip
cd sg-panel-main
sudo bash deploy/ec2-first-install.sh
```

Используется тот же мастер, что и при установке из GitHub.

## Обновление существующей установки

Повторно запустите команду установки. Мастер не задаёт начальные вопросы и сохраняет текущие настройки.

Для сознательной смены домена или порта панели:

```bash
sudo bash /tmp/install-sg-panel.sh --reconfigure
```
