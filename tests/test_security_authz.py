from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from netsentry.core.notifier import TelegramNotifier
from netsentry.core.plugin import PluginContext
from netsentry.core.router import MikroTikRouter, _valid_mac
from netsentry.plugins.telegram_bot import TelegramBotPlugin


# ─── fail-closed authorization ───────────────────────────────────


def _bot(tmp_path: Path, allowed: list[int] | None) -> TelegramBotPlugin:
    notifier = TelegramNotifier("<TOKEN>", "1", allowed_chats=allowed)
    ctx = PluginContext(
        name="telegram_bot",
        config={"worker_threads": 1},
        router=Mock(),
        notifier=notifier,
        vault=Mock(),
        logger=logging.getLogger("test.authz"),
        state_dir=str(tmp_path),
        notifiers_by_id={"tg": notifier},
    )
    plugin = TelegramBotPlugin(ctx)
    plugin.on_load()
    return plugin


def test_empty_whitelist_denies_everyone_fail_closed(tmp_path: Path) -> None:
    bot = _bot(tmp_path, allowed=None)
    assert bot._is_authorized(1) is False
    assert bot._is_authorized(999) is False


def test_whitelist_allows_only_listed_chats(tmp_path: Path) -> None:
    bot = _bot(tmp_path, allowed=[42])
    assert bot._is_authorized(42) is True
    assert bot._is_authorized(43) is False


def test_unauthorized_command_is_not_dispatched(tmp_path: Path) -> None:
    bot = _bot(tmp_path, allowed=[42])
    handler = Mock()
    # /status is not a confirm-gated command, so it dispatches directly.
    bot._command_map = {"/status": SimpleNamespace(on_command=handler)}

    bot._handle_update(
        {"update_id": 1, "message": {"chat": {"id": 999}, "text": "/status"}}
    )
    handler.assert_not_called()

    bot._handle_update(
        {"update_id": 2, "message": {"chat": {"id": 42}, "text": "/status"}}
    )
    handler.assert_called_once()


# ─── router command-injection hardening ──────────────────────────


def test_valid_mac_normalises_and_rejects_injection() -> None:
    assert _valid_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert _valid_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"
    # anything that could carry a second RouterOS command is rejected
    assert _valid_mac('AA:BB:CC:DD:EE:FF"; /system reboot') is None
    assert _valid_mac("AA:BB:CC:DD:EE:FF; /system reboot") is None
    assert _valid_mac("not-a-mac") is None
    assert _valid_mac("") is None


def _router() -> tuple[MikroTikRouter, Mock]:
    router = MikroTikRouter("router.invalid", "netsentry", "key")
    ssh = Mock(return_value=(0, "OK\n"))
    router._ssh = ssh  # type: ignore[method-assign]
    return router, ssh


def test_malicious_mac_never_reaches_ssh() -> None:
    evil = 'AA:BB:CC:DD:EE:FF"; /system reboot; :put "'
    for op in ("disconnect_mac", "unblock_mac"):
        router, ssh = _router()
        assert getattr(router, op)(evil) is False
        ssh.assert_not_called()

    router, ssh = _router()
    assert router.block_mac(evil, comment="x") is False
    ssh.assert_not_called()


def test_valid_mac_reaches_ssh_normalised() -> None:
    router, ssh = _router()
    assert router.disconnect_mac("aa:bb:cc:dd:ee:ff") is True
    (command,) = ssh.call_args.args
    assert "AA:BB:CC:DD:EE:FF" in command
    assert ";" not in command.split("mac-address=")[1]


def test_block_comment_is_quoted_safely() -> None:
    router, ssh = _router()
    assert router.block_mac("aa:bb:cc:dd:ee:ff", comment='evil" ; /system reboot')
    command = ssh.call_args.args[0]
    # the injected quote is escaped inside the RouterOS string literal
    assert 'comment="evil\\" ; /system reboot"' in command


def test_file_ops_quote_their_argument() -> None:
    router, ssh = _router()
    router.delete_file('x"; /system reboot')
    assert '/file remove [find name="x\\"; /system reboot"]' in ssh.call_args.args[0]
