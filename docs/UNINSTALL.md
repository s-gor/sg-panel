# Удаление SG-Panel

Есть два разных сценария.

## Обычное удаление панели

Обычный uninstall удаляет SG-Panel и её службы, но по умолчанию сохраняет Xray, Nginx, сертификаты и резервные копии.

```bash
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/deploy/uninstall.sh -o /tmp/uninstall-sg-panel.sh && bash -n /tmp/uninstall-sg-panel.sh && chmod 700 /tmp/uninstall-sg-panel.sh && sudo bash /tmp/uninstall-sg-panel.sh
```

Следуйте вопросам мастера и внимательно читайте, какие дополнительные компоненты предлагается удалить.

## Что обычно сохраняется

- `/usr/local/bin/xray`;
- `/usr/local/etc/xray/config.json`;
- Nginx;
- Certbot и сертификаты;
- резервные копии;
- SSH и сеть Ubuntu;
- пользовательские файлы `/home`.

Конкретный результат зависит от выбранных ответов мастера.

## Полная очистка тестового сервера

Используйте только на отдельном сервере, где перечисленные компоненты не обслуживают другие проекты:

```bash
sudo bash /opt/xpanel-mvp/FULL-UNINSTALL-SG-PANEL.sh --yes
```

Полный скрипт удаляет:

- SG-Panel и SQLite;
- Xray и конфигурацию;
- WARP/wgcf;
- Nginx и SG fallback;
- Certbot и сертификаты Let's Encrypt;
- резервные копии SG-Panel;
- созданный панелью swap.

Не изменяются:

- SSH;
- сеть Ubuntu;
- Security Group EC2;
- пользовательские файлы в `/home`.

## Перед удалением

Скачайте нужные резервные копии и сохраните:

```text
/opt/xpanel-mvp/data/panel.db
/usr/local/etc/xray/config.json
/root/sg-panel-backups/
```

## Проверка после удаления

```bash
systemctl status xpanel-web --no-pager
systemctl status xray --no-pager
systemctl status nginx --no-pager
sudo ss -lntup
```

Для полной очистки службы и порты SG-Panel/Xray/Nginx должны отсутствовать.

После полного удаления рекомендуется перезагрузить сервер:

```bash
sudo reboot
```
