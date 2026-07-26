# SG-Panel UI23 Repair4 XMUX UI Fix 1

## Update an existing installation

Use `SG-PANEL-FIX40-UI23-REPAIR4-XMUX-UI-FIX1.run`:

```bash
chmod +x SG-PANEL-FIX40-UI23-REPAIR4-XMUX-UI-FIX1.run
sudo ./SG-PANEL-FIX40-UI23-REPAIR4-XMUX-UI-FIX1.run
```

Run first on SG-Node, then on Controller. This is an in-place update through
`install-or-upgrade.sh`; a clean reinstall is not required.

## Clean installation

Use `SG-PANEL-FIX40-FULL-UI23-REPAIR4-XMUX-UI-FIX1.run` only on a new server.

Both packages support `--verify-only` and contain the exact same source payload.
