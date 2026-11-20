from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import Mock

from netsentry.core.plugin import PluginContext
from netsentry.core.router import MikroTikRouter, _routeros_quote
from netsentry.plugins.guest_wifi_rotator import GuestWifiRotatorPlugin


def _router_for_passphrase(
    commands: list[str],
    *,
    stale_interface: str | None = None,
) -> MikroTikRouter:
    router = MikroTikRouter("router.invalid", "netsentry", "key")
    password = "guest-amber-river-1234"

    def fake_ssh(command: str, timeout: int = 10) -> tuple[int, str]:
        commands.append(command)
        if command.startswith("/interface wifi security set"):
            return 0, "OK\n"
        if "find where security=" in command:
            return 0, "*A;*B\n"
        if "get *A name" in command:
            return 0, "wifi3\n"
        if "get *B name" in command:
            return 0, "wifi4\n"
        if command.startswith("/interface wifi set "):
            return 0, "OK\n"
        if "/interface wifi security get" in command:
            return 0, password + "\n"
        if 'find name="wifi3"' in command:
            value = "old-password" if stale_interface == "wifi3" else password
            return 0, value + "\n"
        if 'find name="wifi4"' in command:
            value = "old-password" if stale_interface == "wifi4" else password
            return 0, value + "\n"
        raise AssertionError(f"Unexpected command: {command}")

    router._ssh = fake_ssh  # type: ignore[method-assign]
    return router


def test_passphrase_updates_profile_and_every_referencing_interface() -> None:
    commands: list[str] = []
    router = _router_for_passphrase(commands)

    assert router.set_wifi_passphrase(
        "guest-visitor",
        "guest-amber-river-1234",
    )

    inline_sets = [c for c in commands if c.startswith("/interface wifi set ")]
    assert len(inline_sets) == 2
    assert any("set *A" in c and "security.passphrase=" in c for c in inline_sets)
    assert any("set *B" in c and "security.passphrase=" in c for c in inline_sets)
    assert any("security get" in c and "passphrase" in c for c in commands)
    assert any('find name="wifi3"' in c and "security.passphrase" in c for c in commands)
    assert any('find name="wifi4"' in c and "security.passphrase" in c for c in commands)


def test_routeros_quoted_values_cannot_break_out() -> None:
    assert _routeros_quote('value"; :error escaped') == '"value\\"; :error escaped"'


def test_verify_failure_notifies_owner_without_success_qr(tmp_path: Path) -> None:
    commands: list[str] = []
    router = _router_for_passphrase(commands, stale_interface="wifi4")
    notifier = Mock()
    ctx = PluginContext(
        name="guest_wifi_rotator",
        config={
            "ssid": "Guest",
            "security_profile": "guest-visitor",
            "password_prefix": "guest",
            "diceware_words": 2,
            "diceware_digits": 4,
        },
        router=router,
        notifier=notifier,
        vault=Mock(),
        logger=logging.getLogger("test.guest_wifi"),
        state_dir=str(tmp_path),
    )
    plugin = GuestWifiRotatorPlugin(ctx)
    plugin.on_load()
    plugin._generate_passphrase = Mock(  # type: ignore[method-assign]
        return_value="guest-amber-river-1234"
    )
    plugin._send_qr = Mock()  # type: ignore[method-assign]

    plugin.rotate(target_chat=42)

    notifier.send_to.assert_called_once()
    text = notifier.send_to.call_args.args[1]
    assert text.startswith("❌ Guest password — NOT changed")
    assert "Profile=" not in text and "verification" not in text   # no internals
    labels = [k["text"] for row in notifier.send_to.call_args.kwargs["buttons"] for k in row]
    assert labels == ["🔁 Try again", "🔐 Current password"]
    notifier.send.assert_not_called()
    notifier.notify.assert_not_called()                  # a reply, not an alert
    plugin._send_qr.assert_not_called()
    assert plugin.health()[0].notified                   # the watchdog won't alert again


def test_scheduled_rotation_failure_is_an_attention_alert(tmp_path: Path) -> None:
    router = Mock()
    router.set_wifi_passphrase.return_value = False
    notifier = Mock()
    ctx = PluginContext(
        name="guest_wifi_rotator",
        config={"ssid": "Guest", "security_profile": "guest-visitor"},
        router=router, notifier=notifier, vault=Mock(),
        logger=logging.getLogger("test.guest_wifi"), state_dir=str(tmp_path))
    plugin = GuestWifiRotatorPlugin(ctx)
    plugin.on_load()

    plugin.rotate()

    kind, text = notifier.notify.call_args.args
    assert kind == "attention" and "NOT changed" in text
    notifier.send_to.assert_not_called()


def test_typed_rotate_asks_its_own_question_and_cancel_changes_nothing(tmp_path: Path) -> None:
    router = Mock()
    notifier = Mock()
    ctx = PluginContext(
        name="guest_wifi_rotator",
        config={"ssid": "Guest", "security_profile": "guest-visitor"},
        router=router, notifier=notifier, vault=Mock(),
        logger=logging.getLogger("test.guest_wifi"), state_dir=str(tmp_path))
    plugin = GuestWifiRotatorPlugin(ctx)
    plugin.on_load()

    plugin.on_command("/rotate", "", 42)

    question = notifier.send_to.call_args
    assert question.args[1].startswith("🔄 Change the Guest password now?")
    yes, cancel = question.kwargs["buttons"][0]
    assert yes["text"] == "🔄 Yes, change it" and cancel["text"] == "✖ Cancel"
    router.set_wifi_passphrase.assert_not_called()

    plugin.on_callback(cancel["callback_data"], 42, 7, "cb")

    assert notifier.edit_message.call_args.args[:3] == (42, 7, "✖ Nothing changed.")
    router.set_wifi_passphrase.assert_not_called()
    assert "/rotate" in GuestWifiRotatorPlugin.CONFIRMS_ITSELF


def test_router_stats_returns_none_when_ssh_is_unreachable() -> None:
    router = MikroTikRouter("router.invalid", "netsentry", "key")
    router._ssh = Mock(return_value=(-1, ""))  # type: ignore[method-assign]

    assert router.stats() is None
