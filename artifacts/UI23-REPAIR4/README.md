# SG-Panel UI23 Repair4 — Xray Radio Fix 1

Current cumulative Repair4 package.

## Update an existing SG-Panel or SG-Node

```bash
curl -fL https://raw.githubusercontent.com/s-gor/sg-panel/main/artifacts/UI23-REPAIR4/SG-PANEL-FIX40-UI23-REPAIR4-XRAY-RADIO-FIX1.run -o SG-PANEL-FIX40-UI23-REPAIR4-XRAY-RADIO-FIX1.run
chmod +x SG-PANEL-FIX40-UI23-REPAIR4-XRAY-RADIO-FIX1.run
sudo ./SG-PANEL-FIX40-UI23-REPAIR4-XRAY-RADIO-FIX1.run
```

Run first on SG-Node, then on Controller.

## Clean installation on a new Ubuntu EC2

```bash
curl -fL https://raw.githubusercontent.com/s-gor/sg-panel/main/artifacts/UI23-REPAIR4/SG-PANEL-FIX40-FULL-UI23-REPAIR4-XRAY-RADIO-FIX1.run -o SG-PANEL-FIX40-FULL-UI23-REPAIR4-XRAY-RADIO-FIX1.run
chmod +x SG-PANEL-FIX40-FULL-UI23-REPAIR4-XRAY-RADIO-FIX1.run
sudo ./SG-PANEL-FIX40-FULL-UI23-REPAIR4-XRAY-RADIO-FIX1.run
```

## What changed

All radio controls on Xray Server now use compact circular indicators. The inherited tall rectangular input frames were removed page-wide. XMUX and Salamander logic and values were not changed.

Both `.run` files contain the exact same `SG-PANEL-FIX40-UI23-REPAIR4-SOURCE.zip` payload and support `--verify-only`.
