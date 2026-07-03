from xpanel.service import _memory_status


def test_memory_status_uses_available_memory_not_existing_swap():
    assert _memory_status(51.2) == ("normal", "Памяти достаточно")
    assert _memory_status(25.0) == ("warning", "Запас памяти снижается")
    assert _memory_status(15.0) == ("high", "Мало доступной памяти")
    assert _memory_status(8.0) == ("critical", "Критически мало памяти")
