# Inbound-профили

Полное актуальное описание четырёх доступных профилей находится в документе [SERVER.md](SERVER.md).

## Hysteria 2: быстрая памятка

`Hysteria 2 + TLS` работает поверх QUIC/UDP. Для стандартной точки подключения откройте
`443/udp` в Security Group EC2 и в локальном firewall сервера.

Проверка прослушиваемых UDP-портов:

```bash
sudo ss -lnup
```

Прямая клиентская ссылка для этого профиля начинается с:

```text
hysteria2://
```

Настройки TLS, port hopping, masquerade и ручная проверка описаны в разделе
[Hysteria 2 + TLS](SERVER.md#hysteria-2--tls).
