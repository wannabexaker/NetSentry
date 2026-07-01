from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netsentry.core.notifier import TelegramNotifier
from netsentry.core.plugin import PluginContext
from netsentry.plugins.telegram_bot import TelegramBotPlugin


def _plugin(tmp_path: Path) -> TelegramBotPlugin:
    notifier = TelegramNotifier("<TOKEN>", "1", allowed_chats=[1])
    ctx = PluginContext(
        name="telegram_bot",
        config={"worker_threads": 2},
        router=Mock(),
        notifier=notifier,
        vault=Mock(),
        logger=logging.getLogger("test.telegram_bot"),
        state_dir=str(tmp_path),
        notifiers_by_id={"tg": notifier},
    )
    plugin = TelegramBotPlugin(ctx)
    plugin.on_load()
    return plugin


def _update(update_id: int, command: str) -> dict:
    return {
        "update_id": update_id,
        "message": {"chat": {"id": 1}, "text": command},
    }


def test_slow_handler_does_not_block_fast_handler_and_offset_is_persisted(
    tmp_path: Path,
) -> None:
    plugin = _plugin(tmp_path)
    slow_started = threading.Event()
    release_slow = threading.Event()
    fast_finished = threading.Event()

    def slow(*_args: object) -> None:
        slow_started.set()
        release_slow.wait(2)

    plugin._command_map = {
        "/slow": SimpleNamespace(on_command=slow),
        "/fast": SimpleNamespace(on_command=lambda *_args: fast_finished.set()),
    }
    plugin._executor = ThreadPoolExecutor(max_workers=2)
    try:
        plugin._accept_update(_update(10, "/slow"))
        assert slow_started.wait(1)
        plugin._accept_update(_update(11, "/fast"))

        assert fast_finished.wait(1)
        assert (tmp_path / "update_id").read_text() == "11"
    finally:
        release_slow.set()
        plugin._executor.shutdown(wait=True)
        plugin._executor = None


def test_poll_failures_are_collapsed_and_recovery_logged(
    tmp_path: Path,
    caplog,
) -> None:
    plugin = _plugin(tmp_path)
    caplog.set_level(logging.DEBUG, logger="test.telegram_bot")

    assert plugin._record_poll_failure("Temporary failure in name resolution") == 1.0
    assert plugin._record_poll_failure("Temporary failure in name resolution") == 2.0
    assert plugin._record_poll_failure("Temporary failure in name resolution") == 4.0
    plugin._record_poll_success()

    degraded = [r for r in caplog.records if "connectivity degraded" in r.message]
    restored = [r for r in caplog.records if "connectivity restored" in r.message]
    assert len([r for r in degraded if r.levelno == logging.WARNING]) == 1
    assert len(restored) == 1
    assert restored[0].levelno == logging.INFO
    assert "3 failures" in restored[0].message


def test_update_is_not_dispatched_when_offset_persistence_fails(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    plugin._save_offset = Mock(side_effect=OSError("disk unavailable"))  # type: ignore[method-assign]
    plugin._submit_update = Mock()  # type: ignore[method-assign]

    with pytest.raises(OSError, match="disk unavailable"):
        plugin._accept_update(_update(12, "/fast"))

    plugin._submit_update.assert_not_called()
