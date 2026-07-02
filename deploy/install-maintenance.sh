#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ошибка: запустите скрипт от root" >&2
  exit 1
fi

cat > /etc/systemd/system/xpanel-maintenance.service <<'UNIT'
[Unit]
Description=SG-Panel expiry maintenance
After=xray.service

[Service]
Type=oneshot
WorkingDirectory=/opt/xpanel-mvp
EnvironmentFile=-/etc/xpanel-mvp/web.env
ExecStart=/opt/xpanel-mvp/.venv/bin/python -m xpanel expire-users --apply
User=root
Group=root
UNIT

cat > /etc/systemd/system/xpanel-maintenance.timer <<'UNIT'
[Unit]
Description=Run SG-Panel expiry maintenance

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true
Unit=xpanel-maintenance.service

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/xpanel-traffic.service <<'UNIT'
[Unit]
Description=SG-Panel persistent Xray traffic collector
After=xray.service

[Service]
Type=oneshot
WorkingDirectory=/opt/xpanel-mvp
EnvironmentFile=-/etc/xpanel-mvp/web.env
ExecStart=/opt/xpanel-mvp/.venv/bin/python -m xpanel collect-traffic --online
User=root
Group=root
Nice=10
UNIT

cat > /etc/systemd/system/xpanel-traffic.timer <<'UNIT'
[Unit]
Description=Collect Xray user traffic for SG-Panel

[Timer]
OnBootSec=45s
OnUnitActiveSec=60s
AccuracySec=10s
Persistent=true
Unit=xpanel-traffic.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now xpanel-maintenance.timer
systemctl enable --now xpanel-traffic.timer
