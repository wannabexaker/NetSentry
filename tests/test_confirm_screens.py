"""Destructive actions take two taps, results and cancels replace the question,
and the bot always answers — even a command it doesn't know."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netsentry.core.events import RESTART_REQUESTED, EventBus
from netsentry.core.notifier import TelegramNotifier
from netsentry.core.notify import NotifyPolicy
from netsentry.core.plugin import PluginContext
from netsentry.core.scheduler import Scheduler
from netsentry.plugins.guest_wifi_rotator import GuestWifiRotatorPlugin
from netsentry.plugins.power import PowerPlugin
from netsentry.plugins.security_actions import SecurityActionsPlugin
from netsentry.plugins.settings import SettingsPlugin
from netsentry.plugins.telegram_bot import TelegramBotPlugin

MAC = "AA:BB:CC:DD:EE:0F"


def _ctx(name: str, tmp_path: Path, **kw) -> PluginContext:
    return PluginContext(
        name=name, config=kw.pop("config", {}), router=kw.pop("router", Mock()),
        notifier=kw.pop("notifier", Mock()), vault=Mock(),
        logger=logging.getLogger(f"test.{name}"), state_dir=str(tmp_path / name), **kw)


def _buttons(call) -> list[dict]:
    markup = call.kwargs.get("buttons") if "buttons" in call.kwargs else call.args[3]
    return [k for row in markup or [] for k in row]


# ─── block / disconnect (security_actions) ──────────────────────────

def _security(tmp_path: Path) -> SecurityActionsPlugin:
    router = Mock()
    router.wifi_clients.return_value = [SimpleNamespace(
        mac=MAC, ssid="Home", signal_dbm=-51, band="5ghz")]
    router.dhcp_leases.return_value = [SimpleNamespace(
        mac=MAC, ip="192.0.2.30", hostname="Lenovo-Idea-Tab")]
    router.block_mac.return_value = True
    router.disconnect_mac.return_value = True
    p = SecurityActionsPlugin(_ctx("security_actions", tmp_path, router=router))
    p.ctx._all_plugins = [p]  # type: ignore[attr-defined]
    return p


def test_block_from_a_new_device_alert_asks_first_with_the_device_name(tmp_path: Path) -> None:
    p = _security(tmp_path)

    p.on_callback(f"security_actions:block:{MAC}", 42, 7, "cb")   # the alert's 🚫 button

    p.router.block_mac.assert_not_called()
    question = p.notifier.edit_message.call_args
    assert question.args[:2] == (42, 7)
    assert question.args[2].startswith(
        "🚫 Block Lenovo-Idea-Tab? It can't join any WiFi until you unblock it.")
    yes, cancel = _buttons(question)
    assert yes["text"] == "🚫 Yes, block" and cancel["text"] == "✖ Cancel"
    assert len(yes["callback_data"].encode()) <= 64

    p.on_callback(yes["callback_data"], 42, 7, "cb")

    assert p.router.block_mac.call_args.args[0] == MAC        # the whole MAC, not "AA"
    assert p.notifier.edit_message.call_args.args[2] == "🚫 Blocked Lenovo-Idea-Tab."
    # The only button left is the way back; one tap undoes it.
    (undo,) = _buttons(p.notifier.edit_message.call_args)
    assert undo == {"text": "↩ Unblock", "callback_data": f"security_actions:unblock:{MAC}"}
    p.router.unblock_mac.return_value = True
    p.on_callback(undo["callback_data"], 42, 7, "cb")
    assert p.router.unblock_mac.call_args.args[0] == MAC
    assert p.notifier.edit_message.call_args.args[2] == (
        "✅ Unblocked Lenovo-Idea-Tab. It can join again.")
    assert _buttons(p.notifier.edit_message.call_args) == []


def test_cancel_changes_nothing(tmp_path: Path) -> None:
    p = _security(tmp_path)
    p.on_callback(f"security_actions:act:block:{MAC}", 42, 7, "cb")
    cancel = _buttons(p.notifier.edit_message.call_args)[1]

    p.on_callback(cancel["callback_data"], 42, 7, "cb")

    p.router.block_mac.assert_not_called()
    assert p.notifier.edit_message.call_args.args[2] == "✖ Nothing changed."


def test_kick_picks_a_device_by_its_full_mac_and_disconnects_it(tmp_path: Path) -> None:
    p = _security(tmp_path)
    p.on_command("/kick", "", 42)
    pick = _buttons(p.notifier.send_to.call_args)[0]
    assert pick["text"].startswith("Lenovo-Idea-Tab") and "-51 dBm" in pick["text"]

    p.on_callback(pick["callback_data"], 42, 7, "cb")
    options = _buttons(p.notifier.edit_message.call_args)
    assert "Lenovo-Idea-Tab" in p.notifier.edit_message.call_args.args[2]

    disconnect = next(k for k in options if "Disconnect" in k["text"])
    p.on_callback(disconnect["callback_data"], 42, 7, "cb")
    p.router.disconnect_mac.assert_called_once_with(MAC)       # one tap: it can rejoin
    assert p.notifier.edit_message.call_args.args[2].startswith(
        "📴 Disconnected Lenovo-Idea-Tab.")

    block = next(k for k in options if "Block permanently" in k["text"])
    p.on_callback(block["callback_data"], 42, 7, "cb")
    p.router.block_mac.assert_not_called()                     # …but blocking asks first
    assert "🚫 Block Lenovo-Idea-Tab?" in p.notifier.edit_message.call_args.args[2]


def test_a_refused_block_says_what_is_still_true(tmp_path: Path) -> None:
    p = _security(tmp_path)
    p.router.block_mac.side_effect = RuntimeError("ssh: connection reset")
    p.on_callback(f"security_actions:act:yes:{MAC}", 42, 7, "cb")
    text = p.notifier.edit_message.call_args.args[2]
    assert "was NOT blocked" in text and "can still join" in text
    assert "ssh" not in text


@pytest.mark.parametrize("forged", [
    "security_actions:block:AA",                    # what the old split(":") produced
    "security_actions:act:yes:not-a-mac",
    "security_actions:act:yes:AA:BB:CC:DD:EE:FF:00",
    "security_actions:nope:AA:BB:CC:DD:EE:FF",
])
def test_malformed_callbacks_touch_nothing(tmp_path: Path, forged: str) -> None:
    p = _security(tmp_path)
    p.on_callback(forged, 42, 7, "cb")
    p.router.block_mac.assert_not_called()
    p.router.disconnect_mac.assert_not_called()


# ─── pausing a job, notification mode (settings) ────────────────────

@pytest.fixture
def sched(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("time.tzname", ("UTC", "UTC"))
    s = Scheduler()
    s.start()
    yield s
    s.shutdown()


def test_notification_mode_is_picked_with_buttons_and_kept(tmp_path: Path, sched) -> None:
    sched.load_overrides(tmp_path / "overrides.json")
    sched.add_cron("0 8 * * *", lambda: None, name="morning_briefing.daily")
    notifier = Mock()
    notifier.policy = NotifyPolicy("normal", tmp_path / "mode.json")
    p = SettingsPlugin(_ctx("settings", tmp_path, scheduler=sched, notifier=notifier))
    p.on_load()

    p.on_command("/settings", "", 42)
    home = notifier.send_to.call_args
    assert "🔔 Notifications" in home.args[1] and "Normal" in home.args[1]
    row = next(k for k in _buttons(home) if k["text"] == "🔔 Notifications")

    p.on_callback(row["callback_data"], 42, 7, "cb")
    screen = notifier.edit_message.call_args
    assert "Relaxed" in screen.args[2] and "Everything" in screen.args[2]
    labels = [k["text"] for k in _buttons(screen)]
    assert "✓ 🔔 Normal" in labels                               # the current one is marked

    relaxed = next(k for k in _buttons(screen) if "Relaxed" in k["text"])
    p.on_callback(relaxed["callback_data"], 42, 7, "cb")
    assert NotifyPolicy("normal", tmp_path / "mode.json").mode == "relaxed"
    assert "✓ 😌 Relaxed" in [k["text"] for k in _buttons(notifier.edit_message.call_args)]

    p.on_callback("settings:n:deafening", 42, 7, "cb")         # forged: refused
    assert NotifyPolicy("normal", tmp_path / "mode.json").mode == "relaxed"


# ─── the bot ────────────────────────────────────────────────────────

def _bot(tmp_path: Path, confirm: list[str] | None = None) -> TelegramBotPlugin:
    notifier = TelegramNotifier("<TOKEN>", "1", allowed_chats=[42])
    config = {"worker_threads": 1}
    if confirm is not None:
        config["confirm_commands"] = confirm
    bot = TelegramBotPlugin(_ctx("telegram_bot", tmp_path, config=config, notifier=notifier,
                                 notifiers_by_id={"tg": notifier}))
    bot.on_load()
    bot._tg = Mock()
    bot._tg.allowed_chats = {42}
    return bot


def _update(text: str) -> dict:
    return {"update_id": 1, "message": {"chat": {"id": 42}, "from": {"id": 42}, "text": text}}


def _press(data: str) -> dict:
    return {"id": "cb", "from": {"id": 42},
            "message": {"chat": {"id": 42}, "message_id": 9}, "data": data}


def test_default_confirm_list_no_longer_names_a_command_that_does_not_exist(
        tmp_path: Path) -> None:
    assert "/reboot" not in _bot(tmp_path)._confirm_cmds


def test_unknown_command_and_start_open_the_menu(tmp_path: Path) -> None:
    bot = _bot(tmp_path)
    menu = SimpleNamespace(ctx=SimpleNamespace(name="menu"), show_home=Mock())
    bot.ctx._all_plugins = [bot, menu]  # type: ignore[attr-defined]

    bot._handle_update(_update("/bogus"))
    assert menu.show_home.call_args.kwargs["note"] == "ℹ️ /bogus isn't a command I know."

    bot._handle_update(_update("/start"))
    assert menu.show_home.call_args.kwargs["note"] == ""


def test_without_a_menu_an_unknown_command_still_gets_an_answer(tmp_path: Path) -> None:
    bot = _bot(tmp_path)
    bot._handle_update(_update("/bogus"))
    assert "isn't a command I know" in bot._tg.send_to.call_args.args[1]


def test_a_crashing_command_never_shows_the_exception(tmp_path: Path) -> None:
    bot = _bot(tmp_path)
    bot._command_map = {"/scan": SimpleNamespace(
        on_command=Mock(side_effect=RuntimeError("Traceback secret /home/pi")))}
    bot._handle_update(_update("/scan"))
    text = bot._tg.send_to.call_args.args[1]
    assert text.startswith("❌ /scan didn't finish") and "secret" not in text


def test_a_command_that_asks_its_own_question_is_never_asked_twice(tmp_path: Path) -> None:
    bot = _bot(tmp_path, confirm=["/rotate", "/reboot"])     # an old config.yaml
    handler = Mock()
    bot._command_map = {"/rotate": SimpleNamespace(
        on_command=handler, CONFIRMS_ITSELF=GuestWifiRotatorPlugin.CONFIRMS_ITSELF)}

    bot._handle_update(_update("/rotate"))

    handler.assert_called_once_with("/rotate", "", 42)       # its own question comes next
    assert bot._pending == {}


def test_generic_confirm_and_cancel_replace_the_question(tmp_path: Path) -> None:
    bot = _bot(tmp_path, confirm=["/danger"])
    handler = Mock()
    bot._command_map = {"/danger": SimpleNamespace(on_command=handler)}

    bot._handle_update(_update("/danger"))
    nonce = next(iter(bot._pending))
    bot._handle_callback(_press(f"telegram_bot:cancel:{nonce}"))
    assert bot._tg.edit_message.call_args.args == (42, 9, "✖ Nothing changed.", [])
    handler.assert_not_called()

    bot._handle_update(_update("/danger now"))
    nonce = next(iter(bot._pending))
    bot._handle_callback(_press(f"telegram_bot:confirm:{nonce}"))
    assert bot._tg.edit_message.call_args.args == (42, 9, "⏳ Running /danger now…", [])
    handler.assert_called_once_with("/danger", "now", 42)

    bot._handle_callback(_press(f"telegram_bot:confirm:{nonce}"))   # tapped again later
    assert "expired" in bot._tg.edit_message.call_args.args[2]
    assert handler.call_count == 1


# ─── the owner's own restart is announced to the monitors ───────────

def test_router_restart_tells_the_monitors_it_was_asked_for(tmp_path: Path) -> None:
    events = EventBus()
    heard: list[dict] = []
    events.subscribe(RESTART_REQUESTED, heard.append)
    p = PowerPlugin(_ctx("power", tmp_path, events=events))
    p._after = Mock()  # type: ignore[method-assign]
    p.on_load()

    p.restart("router", 42)

    assert heard == [{"target": "router"}]
    assert p.has_isp_plug() is False
