# SG-Panel UI23 Repair4 — current package

Current cumulative UI: **Global Buttons Preview 3 Outline**.

## Update an existing Controller or SG-Node

```bash
curl -fL https://raw.githubusercontent.com/s-gor/sg-panel/main/artifacts/UI23-REPAIR4/SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run -o SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
chmod +x SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
sudo ./SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
```

Update SG-Node first, then Controller.

## Clean installation

```bash
curl -fL https://raw.githubusercontent.com/s-gor/sg-panel/main/artifacts/UI23-REPAIR4/SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run -o SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
chmod +x SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
sudo ./SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
```

## Full removal

```bash
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/FULL-UNINSTALL-SG-PANEL.sh -o /tmp/FULL-UNINSTALL-SG-PANEL.sh
sudo bash /tmp/FULL-UNINSTALL-SG-PANEL.sh
```

Both `.run` packages contain the exact same `SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE-SOURCE.zip` payload and support `--verify-only`.
