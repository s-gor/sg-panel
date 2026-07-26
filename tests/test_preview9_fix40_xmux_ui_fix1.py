from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_xmux_profiles_are_real_radio_controls_with_explicit_current_state() -> None:
    template = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")

    assert 'data-xmux-current="{{ xmux.settings.xmux_mode }}"' in template
    assert "Сейчас применяется" in template
    assert "Это сохранённое состояние базы" in template
    assert template.count('type="radio" name="xmux_mode"') == 3
    assert 'value="auto"' in template
    assert 'value="reduced"' in template
    assert 'value="expert"' in template
    assert "Сейчас активен" in template
    assert "Выбран профиль" in template
    assert "Сейчас он ещё не действует" in template
    assert '<select name="xmux_mode"' not in template


def test_xmux_cards_distinguish_saved_and_pending_selection() -> None:
    template = (ROOT / "xpanel/templates/settings.html").read_text(encoding="utf-8")

    assert "item.classList.toggle('is-current', isCurrent)" in template
    assert "item.classList.toggle('is-selected', isSelected)" in template
    assert "currentBadge.hidden = !isCurrent" in template
    assert "pendingBadge.hidden = !isSelected || isCurrent" in template
    assert "выполните проверку и сохранение" in template
    assert "уже сохранён и сейчас применяется" in template


def test_validation_gate_inserts_controls_for_nested_custom_action_layouts() -> None:
    base = (ROOT / "xpanel/templates/base.html").read_text(encoding="utf-8")

    assert "const buttonParent = saveButton.parentElement;" in base
    assert "buttonParent.insertBefore(validateButton, saveButton);" in base
    assert "const statusAnchor = actionWrap || buttonParent;" in base
    assert "statusAnchor.insertAdjacentElement('beforebegin', status);" in base

    # These old operations threw a DOMException when the save button was nested
    # inside a custom action container such as Settings -> Xray Server.
    assert "actionWrap.insertBefore(validateButton, saveButton);" not in base
    assert "form.insertBefore(status, parent);" not in base
