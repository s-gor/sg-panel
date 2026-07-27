# Текущая рабочая линия SG-Panel

## SG-Panel Preview 9 · FIX40 · UI23 Repair4

Накопительная база включает:

- UI23 и Repair4;
- Hysteria2 Salamander FinalMask;
- видимые профили XMUX и исправленное состояние проверки/применения;
- Routing Gateway Preview 1–3;
- исправление radio-индикаторов Xray Server;
- Global Buttons Preview 1–3;
- текущий визуальный принцип: прозрачная кнопка с единой окантовкой, цветная заливка только у выбранного/активного состояния и во время нажатия.

## Пакеты в GitHub после публикации

### Обновление существующей установки

`artifacts/UI23-REPAIR4/SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run`

```bash
curl -fL https://raw.githubusercontent.com/s-gor/sg-panel/main/artifacts/UI23-REPAIR4/SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run -o SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
chmod +x SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
sudo ./SG-PANEL-FIX40-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
```

Обновлять сначала SG-Node, затем Controller.

### Чистая установка

`artifacts/UI23-REPAIR4/SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run`

```bash
curl -fL https://raw.githubusercontent.com/s-gor/sg-panel/main/artifacts/UI23-REPAIR4/SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run -o SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
chmod +x SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
sudo ./SG-PANEL-FIX40-FULL-UI23-REPAIR4-GLOBAL-BUTTONS-PREVIEW3-OUTLINE.run
```

### Полное удаление

```bash
curl -fsSL https://raw.githubusercontent.com/s-gor/sg-panel/main/FULL-UNINSTALL-SG-PANEL.sh -o /tmp/FULL-UNINSTALL-SG-PANEL.sh
sudo bash /tmp/FULL-UNINSTALL-SG-PANEL.sh
```

## Проверки текущего SOURCE

- 201 pytest-тест;
- 38 Jinja-шаблонов;
- Python compileall;
- Bash syntax;
- проверка обоих автономных `.run`;
- побайтовое сравнение встроенных payload с SOURCE ZIP.

До окончательного принятия нужны зелёные GitHub Actions и живая визуальная проверка обеих тем.
