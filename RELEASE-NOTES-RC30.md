# SG-Panel v0.10.0 RC30

RC30 объединяет установку по IP, четыре доступных Inbound-профиля, Clients & Traffic Studio, долговременную статистику и безопасный fallback обычного HTTPS на локальный Nginx.

## Inbound-профили

В интерфейсе доступны:

- `RAW/TCP + REALITY`;
- `XHTTP + REALITY`;
- `XHTTP + TLS`;
- `Hysteria 2 + TLS`.

Для `XHTTP + REALITY` и `XHTTP + TLS` доступны `auto`, `packet-up`, `stream-up` и `stream-one`. На реальном сервере подтверждена работа `XHTTP + TLS` во всех четырёх режимах. `auto` остаётся значением по умолчанию, но не является единственным вариантом.

Скрытая внутренняя совместимость с `gRPC + TLS` сохранена в backend и тестах, однако профиль не показывается в интерфейсе и не входит в число четырёх доступных профилей.

Переключение профиля сохраняет клиентов, UUID/Auth, подписки, Network-настройки и накопленную статистику. Применение возможно только после проверки модели и `xray run -test`.

## Hysteria Studio

- QUIC/UDP и TLS;
- автоматические и ручные performance-параметры;
- congestion-настройки;
- port hopping;
- masquerade;
- ручная диагностика;
- ссылка, QR-код и подписка.

## Hysteria 2 через WARP

На реальном EC2 подтверждён маршрут:

```text
Клиент → Hysteria 2 → Xray → WARP → Интернет
```

WARP работает как Default Outbound Xray и не требует изменения Hysteria-ссылки, UDP-порта, Auth, TLS или masquerade. Возврат на обычный выход выполняется переключением WARP mode на **«Не использовать WARP»** и повторным применением конфигурации.

## Clients & Traffic Studio

- поиск, фильтры и сортировка;
- подробная карточка клиента;
- срок действия и последняя активность;
- online-состояние;
- текущая сессия, день, месяц и всё время;
- текущая скорость и график за 14 дней;
- персональный и общий сброс статистики.

Статистика сохраняется в SQLite и не теряется после restart Xray, обновления или reboot.

## Fallback и заглушка

- локальная SG-заглушка публикуется на HTTP `80`;
- для Reality-профилей обычный HTTPS собственного домена направляется на локальный Nginx, а клиентский трафик остаётся у Xray;
- для XHTTP + TLS Nginx обслуживает обычный HTTPS и передаёт в Xray только клиентский path;
- при Hysteria 2 Xray использует UDP `443`, а Nginx может показывать заглушку на TCP `443`.

## Безопасность конфигурации

- обязательная предварительная проверка;
- временная копия SQLite;
- подписанный краткоживущий результат проверки;
- блокировка сохранения после любого изменения;
- резервная копия перед применением;
- автоматический rollback;
- Xray `v26.5.9`.

## Установка и доступ

Новая установка начинается по HTTP и не требует домена. HTTPS включается позже в `Security → Panel Access`.

Backend работает на `127.0.0.1:8080`, публичный порт панели выбирается отдельно.

## Полный uninstall

`FULL-UNINSTALL-SG-PANEL.sh --yes` удаляет SG-Panel, Xray, WARP, Nginx, Certbot, сертификаты, fallback, резервные копии и swap с живой зелёной строкой прогресса.

SSH, сеть Ubuntu, `/home` и Security Group EC2 не изменяются.

## Проверено на EC2

- чистая установка и обновление;
- четыре доступных Inbound-профиля;
- Hysteria 2 через v2rayN;
- fallback обычного HTTPS;
- общий и персональный трафик;
- сброс статистики;
- полный uninstall.

## Установка

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates unzip && curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/install-from-github.sh -o /tmp/install-sg-panel.sh && bash -n /tmp/install-sg-panel.sh && chmod 700 /tmp/install-sg-panel.sh && sudo bash /tmp/install-sg-panel.sh
```

Подробности находятся в [README](README.md) и [руководстве пользователя](docs/USER-GUIDE.md).
