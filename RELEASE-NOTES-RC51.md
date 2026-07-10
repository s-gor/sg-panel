# SG-Panel v0.10.0-rc51

## Expert больше не спрятан

- отдельный пункт главного меню **Expert**;
- вкладки **Transport** и **GeoFiles**;
- статусная карточка Expert на странице Xray Server;
- безопасные эффективные значения `Auto`, `{}`, `Off` и «Не применимо» вместо пустых полей;
- редактирование по умолчанию заблокировано и включается только явной кнопкой;
- примеры остаются только примерами и не попадают в профиль автоматически.

## Panel exposure

В Security добавлены режимы:

- Direct through Nginx;
- Cloudflare Proxy;
- Cloudflare Tunnel + Access.

Показываются HTTPS origin, публичный порт, Cloudflare edge, origin lockdown, состояние `cloudflared`, Access и источник клиентского IP. SG-Panel не имитирует автоматическую настройку Cloudflare: внешние DNS, firewall, Tunnel и Access должны быть выполнены отдельно и явно подтверждены.

## Сохранено из RC50

- XHTTP Mode, Server/Client Extra;
- Server/Client FinalMask;
- ECH и certificate pinning;
- V2Fly, Loyalsoldier, RunetFreedom, Custom URL и Local GeoFiles;
- validate-first, `xray run -test`, backup и rollback;
- управляемый экспорт без раскрытия секретного ECH server key.

SG Client в RC51 не изменяется.
