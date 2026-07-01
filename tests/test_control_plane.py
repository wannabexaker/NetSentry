from __future__ import annotations

import logging
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from netsentry.core.notifier import TelegramNotifier
from netsentry.core.plugin import PluginContext
from netsentry.plugins.telegram_bot import TelegramBotPlugin


def _bot(
    tmp_path: Path,
    *,
    allowed: tuple[int, ...] = (42,),
    confirm: tuple[str, ...] = ("/rotate",),
    burst: int = 3,
) -> TelegramBotPlugin:
    notifier = TelegramNotifier("<TOKEN>", "1", allowed_chats=list(allowed))
    ctx = PluginContext(
        name="telegram_bot",
        config={
            "worker_threads": 1,
            "confirm_commands": list(confirm),
            "rate_limit_burst": burst,
            "rate_limit_per_sec": 0.0,  # no refill during a test
        },
        router=Mock(),
        notifier=notifier,
        vault=Mock(),
        logger=logging.getLogger("test.cp"),
        state_dir=str(tmp_path),
        notifiers_by_id={"tg": notifier},
    )
    plugin = TelegramBotPlugin(ctx)
    plugin.on_load()
    plugin._tg = Mock()
    plugin._tg.allowed_chats = set(allowed)
    return plugin


def _cmd(text: str, *, chat: int = 42, sender: int = 42) -> dict:
    return {
        "update_id": 1,
        "message": {"chat": {"id": chat}, "from": {"id": sender}, "text": text},
    }


def _callback(data: str, *, chat: int = 42, sender: int = 42) -> dict:
    return {
        "id": "cb1",
        "from": {"id": sender},
        "message": {"chat": {"id": chat}, "message_id": 1},
        "data": data,
    }


# ─── rate limiting ───────────────────────────────────────────────


def test_rate_limit_blocks_after_burst(tmp_path: Path) -> None:
    bot = _bot(tmp_path, burst=3)
    assert [bot._rate_ok(42) for _ in range(3)] == [True, True, True]
    assert bot._rate_ok(42) is False


# ─── confirmation tier ───────────────────────────────────────────


def test_destructive_command_is_held_for_confirmation(tmp_path: Path) -> None:
    bot = _bot(tmp_path, confirm=("/rotate",))
    handler = Mock()
    bot._command_map = {"/rotate": SimpleNamespace(on_command=handler)}

    bot._handle_update(_cmd("/rotate"))

    handler.assert_not_called()  # not executed immediately
    assert bot._tg.send_to.called
    assert len(bot._pending) == 1
    # a confirm keyboard was offered
    _, kwargs = bot._tg.send_to.call_args
    assert kwargs.get("buttons")


def test_confirm_callback_runs_the_command(tmp_path: Path) -> None:
    bot = _bot(tmp_path, confirm=("/rotate",))
    handler = Mock()
    bot._command_map = {"/rotate": SimpleNamespace(on_command=handler)}

    bot._handle_update(_cmd("/rotate now"))
    nonce = next(iter(bot._pending))
    bot._handle_callback(_callback(f"telegram_bot:confirm:{nonce}"))

    handler.assert_called_once_with("/rotate", "now", 42)


def test_cancel_callback_does_not_run_the_command(tmp_path: Path) -> None:
    bot = _bot(tmp_path)
    handler = Mock()
    bot._command_map = {"/rotate": SimpleNamespace(on_command=handler)}
    bot._pending["n2"] = {
        "cmd": "/rotate",
        "args": "",
        "chat_id": 42,
        "expiry": time.monotonic() + 60,
    }

    bot._handle_callback(_callback("telegram_bot:cancel:n2"))
    handler.assert_not_called()


def test_non_destructive_command_runs_directly(tmp_path: Path) -> None:
    bot = _bot(tmp_path, confirm=("/rotate",))
    handler = Mock()
    bot._command_map = {"/status": SimpleNamespace(on_command=handler)}

    bot._handle_update(_cmd("/status"))
    handler.assert_called_once()


# ─── callback sender verification ────────────────────────────────


def test_callback_from_unauthorized_sender_is_rejected(tmp_path: Path) -> None:
    bot = _bot(tmp_path, allowed=(42,))
    handler = Mock()
    bot._command_map = {"/rotate": SimpleNamespace(on_command=handler)}
    bot._pending["n3"] = {
        "cmd": "/rotate",
        "args": "",
        "chat_id": 42,
        "expiry": time.monotonic() + 60,
    }

    # chat 42 is whitelisted, but the *presser* (999) is not.
    bot._handle_callback(_callback("telegram_bot:confirm:n3", sender=999))

    handler.assert_not_called()
    bot._tg.answer_callback.assert_called_with("cb1", "Not authorized")
