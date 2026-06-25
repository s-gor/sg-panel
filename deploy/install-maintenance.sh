#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ошибка: запустите скрипт от root" >&2
  exit 1
fi

cat > /etc/systemd/system/xpanel-maintenance.service <<'EOF'
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
EOF

cat > /etc/systemd/system/xpanel-maintenance.timer <<'EOF'
[Unit]
Description=Run SG-Panel expiry maintenance

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true
Unit=xpanel-maintenance.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now xpanel-maintenance.timer
