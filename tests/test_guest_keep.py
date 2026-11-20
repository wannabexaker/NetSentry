"""Guest devices that keep their password (/keep) — router rule + buttons."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.events import EventBus
from netsentry.core.plugin import PluginContext
from netsentry.core.router import (
    DhcpLease,
    MikroTikRouter,
    WifiClient,
    _exact_regexp,
    _keep_label,
    _routeros_quote,
)
from netsentry.plugins.guest_wifi_rotator import GuestWifiRotatorPlugin

PHONE = "F2:27:2C:00:00:01"
TABLET = "46:AB:CB:00:00:02"
OTHER = "AA:BB:CC:00:00:03"
CHAT = 42


# ─── the router rule ─────────────────────────────────────────────

def _router(answer: str, rc: int = 0) -> tuple[MikroTikRouter, list[str]]:
    router = MikroTikRouter("192.0.2.1", "netsentry", "key")
    commands: list[str] = []

    def fake_ssh(command: str, timeout: int = 10) -> tuple[int, str]:
        commands.append(command)
        return rc, answer

    router._ssh = fake_ssh  # type: ignore[method-assign]
    return router, commands


def test_keeping_copies_the_password_on_the_router_and_goes_first() -> None:
    router, commands = _router("KEEP added 1 33\n")

    assert router.keep_wifi_passphrase(PHONE.lower(), "Cielo", "Aunt's phone") == "added"

    (command,) = commands
    assert f"mac-address={PHONE}" in command
    assert 'ssid-regexp="^Cielo\\$"' in command          # this network only, exactly
    assert "client-isolation=yes" in command
    assert "place-before=($all->0)" in command           # first matching rule wins
    assert 'comment="netsentry-keep Aunts phone"' in command
    # The password is read and written by the router itself: only the variable
    # appears in what we send, and only a device connected to that network counts.
    assert "passphrase=$pass" in command
    assert 'registration-table find mac-address=F2:27:2C:00:00:01 ssid="Cielo"' in command


def test_isolation_can_be_left_off() -> None:
    router, commands = _router("KEEP added 1 12\n")
    assert router.keep_wifi_passphrase(PHONE, "Guest", isolate=False) == "added"
    assert "client-isolation=no" in commands[0]


@pytest.mark.parametrize("answer, rc, result", [
    ("KEEP exists 1 33\n", 0, "exists"),
    ("KEEP not-connected 0 0\n", 0, "not-connected"),
    ("KEEP failed 0 0\n", 0, "failed"),          # e.g. no usable password found
    ("KEEP added 0 0\n", 0, "failed"),           # said added, but no rule is there
    ("KEEP added 1 0\n", 0, "failed"),           # rule without a password
    ("KEEP added 2 33\n", 0, "failed"),          # two rules for one device
    ("KEEP added 1 33\n", 1, "failed"),
    ("bad command name access-list\n", 0, "failed"),
    ("", 0, "failed"),
])
def test_keep_result_is_what_the_router_reads_back(answer: str, rc: int, result: str) -> None:
    router, _ = _router(answer, rc)
    assert router.keep_wifi_passphrase(PHONE, "Cielo") == result


@pytest.mark.parametrize("mac, ssid", [
    ("not-a-mac", "Cielo"), ("F2:27:2C:00:00:01; /system reset", "Cielo"),
    (PHONE, ""), (PHONE, "x" * 33), (PHONE, "Cie\nlo"),
])
def test_keep_refuses_bad_input_without_touching_the_router(mac: str, ssid: str) -> None:
    router, commands = _router("KEEP added 1 33\n")
    assert router.keep_wifi_passphrase(mac, ssid) == "failed"
    assert commands == []


def test_network_names_and_labels_cannot_change_the_command() -> None:
    assert _exact_regexp("Cielo") == "^Cielo$"
    assert _exact_regexp("My.Guest+(5G)") == r"^My\.Guest\+\(5G\)$"
    assert _routeros_quote("pa$$word") == '"pa\\$\\$word"'
    assert _keep_label('Θεία "phone"; /system reset-configuration') == "phone system reset-configuration"
    assert _keep_label("x" * 80) == "x" * 32
    router, commands = _router("KEEP added 1 33\n")
    router.keep_wifi_passphrase(PHONE, 'Gu"est$1', 'a"b; :c')
    assert 'ssid="Gu\\"est\\$1"' in commands[0]
    assert 'comment="netsentry-keep ab c"' in commands[0]


def test_release_removes_only_the_keep_rule() -> None:
    router, commands = _router("KEEP 0\n")
    assert router.release_wifi_passphrase(PHONE) is True
    assert commands[0].startswith(
        f'/interface wifi access-list remove [/interface wifi access-list find '
        f'mac-address={PHONE} comment~"^netsentry-keep"]')

    still_there, _ = _router("KEEP 1\n")
    assert still_there.release_wifi_passphrase(PHONE) is False
    refused, commands = _router("KEEP 0\n")
    assert refused.release_wifi_passphrase("nonsense") is False and commands == []


def test_list_of_kept_devices() -> None:
    router, commands = _router(
        f"KEEP {PHONE} netsentry-keep Aunts phone\n"
        f"KEEP {TABLET.lower()} netsentry-keep\n"
        "KEEP garbage netsentry-keep x\n"
        "something else\n"
        "KEEP-END\n")
    assert router.kept_wifi_passphrases() == {PHONE: "Aunts phone", TABLET: ""}
    assert "passphrase" not in commands[0]               # the list never asks for passwords

    cut_short, _ = _router(f"KEEP {PHONE} netsentry-keep x\n")
    assert cut_short.kept_wifi_passphrases() is None     # not "nobody": unknown
    down, _ = _router("", rc=255)
    assert down.kept_wifi_passphrases() is None


def test_a_block_goes_above_every_other_rule_and_unblock_leaves_the_rest() -> None:
    router, commands = _router("")
    assert router.block_mac(PHONE, "blocked by owner")
    assert "action=reject" in commands[0] and "place-before=($all->0)" in commands[0]

    assert router.unblock_mac(PHONE)
    assert commands[1] == (f"/interface wifi access-list remove "
                           f"[find mac-address={PHONE} action=reject]")


# ─── the buttons ─────────────────────────────────────────────────

class _FakeRouter:
    """A router with a guest network, a main network and an access list."""

    def __init__(self) -> None:
        self.kept: dict[str, str] = {}
        self.online = [
            WifiClient(PHONE, "Cielo", "wifi4", -60, "2ghz-n", "wpa2-psk"),
            WifiClient(TABLET, "Cielo", "wifi4", -40, "2ghz-n", "wpa2-psk"),
            WifiClient(OTHER, "Sky", "wifi1", -50, "5ghz-ax", "wpa2-psk"),
        ]
        self.reachable = True
        self.calls: list[tuple] = []

    def wifi_clients(self) -> list[WifiClient]:
        return list(self.online)

    def dhcp_leases(self) -> list[DhcpLease]:
        return [DhcpLease(PHONE, "10.2.2.9", "Redmi-13C-5G"),
                DhcpLease(TABLET, "10.2.2.10", "Lenovo-Idea-Tab")]

    def kept_wifi_passphrases(self):
        return dict(self.kept) if self.reachable else None

    def keep_wifi_passphrase(self, mac, ssid, label="", isolate=True) -> str:
        self.calls.append(("keep", mac, ssid, label, isolate))
        if not self.reachable:
            return "failed"
        if mac in self.kept:
            return "exists"
        if not any(c.mac == mac and c.ssid == ssid for c in self.online):
            return "not-connected"
        self.kept[mac] = label
        return "added"

    def release_wifi_passphrase(self, mac) -> bool:
        self.calls.append(("release", mac))
        return self.reachable and self.kept.pop(mac, None) is not None

    def get_wifi_passphrase(self, profile):
        return "guest-amber-river-1234"

    def set_wifi_passphrase(self, profile, passphrase) -> bool:
        return True


def _plugin(tmp_path: Path) -> tuple[GuestWifiRotatorPlugin, _FakeRouter, list]:
    router = _FakeRouter()
    events = EventBus()
    seen: list = []
    events.subscribe("router.config.expected_change", lambda payload: seen.append(payload))
    ctx = PluginContext(
        name="guest_wifi_rotator",
        config={"ssid": "Cielo", "security_profile": "cielo-visitor"},
        router=router, notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.guest_keep"), state_dir=str(tmp_path), events=events)
    plugin = GuestWifiRotatorPlugin(ctx)
    plugin.on_load()
    return plugin, router, seen


def _press(plugin: GuestWifiRotatorPlugin, data: str) -> tuple[str, list[dict]]:
    plugin.notifier.edit_message.reset_mock()
    plugin.on_callback(f"guest_wifi_rotator:{data}", CHAT, 7, "cb1")
    call = plugin.notifier.edit_message.call_args
    return call.args[2], [b for row in call.kwargs["buttons"] for b in row]


def _texts(buttons: list[dict]) -> list[str]:
    return [b["text"] for b in buttons]


def test_keep_opens_with_buttons_and_explains_itself(tmp_path: Path) -> None:
    plugin, _, _ = _plugin(tmp_path)

    plugin.on_command("/keep", "", CHAT)

    text = plugin.notifier.send_to.call_args.args[1]
    rows = plugin.notifier.send_to.call_args.kwargs["buttons"]
    assert "No device yet" in text and "stays on the guest network" in text
    assert [b["text"] for row in rows for b in row] == ["➕ Add a device", "🗓 Password rotation"]


def test_only_devices_on_the_guest_network_are_offered(tmp_path: Path) -> None:
    plugin, _, _ = _plugin(tmp_path)

    text, buttons = _press(plugin, "ka")

    assert "Connected to Cielo right now" in text
    assert _texts(buttons) == ["Lenovo-Idea-Tab", "Redmi-13C-5G", "🔄 Refresh", "⬅ Back"]
    assert buttons[0]["callback_data"] == f"guest_wifi_rotator:kp:{TABLET}"
    assert all(len(b["callback_data"].encode()) <= 64 for b in buttons)


def test_one_tap_keeps_a_device_and_the_change_is_announced_as_ours(tmp_path: Path) -> None:
    plugin, router, seen = _plugin(tmp_path)

    text, buttons = _press(plugin, f"kp:{PHONE}")

    assert router.calls == [("keep", PHONE, "Cielo", "Redmi-13C-5G", True)]
    assert router.kept == {PHONE: "Redmi-13C-5G"}
    assert "✅ Redmi-13C-5G keeps its password from now on (it reconnects" in text and "🟢 Redmi-13C-5G" in text
    assert "✖ Redmi-13C-5G" in _texts(buttons)
    assert seen == [{"source": "guest_wifi_rotator", "what": "guest keeps password"}]

    text, buttons = _press(plugin, "ka")                  # no longer offered
    assert _texts(buttons) == ["Lenovo-Idea-Tab", "🔄 Refresh", "⬅ Back"]


def test_a_device_that_left_meanwhile_changes_nothing(tmp_path: Path) -> None:
    plugin, router, seen = _plugin(tmp_path)
    router.online = [c for c in router.online if c.mac != PHONE]

    text, _ = _press(plugin, f"kp:{PHONE}")

    assert "is not connected to Cielo right now, so nothing was changed" in text
    assert router.kept == {} and seen == []


def test_a_device_on_another_network_cannot_be_kept(tmp_path: Path) -> None:
    plugin, router, _ = _plugin(tmp_path)
    _press(plugin, f"kp:{OTHER}")
    assert router.kept == {}


def test_removing_takes_a_second_tap(tmp_path: Path) -> None:
    plugin, router, seen = _plugin(tmp_path)
    router.kept = {PHONE: "Redmi-13C-5G"}

    text, buttons = _press(plugin, f"kx:{PHONE}")

    assert "Make Redmi-13C-5G a normal guest again?" in text
    assert router.kept == {PHONE: "Redmi-13C-5G"} and router.calls == []
    assert buttons[0]["callback_data"] == f"guest_wifi_rotator:kX:{PHONE}"

    text, _ = _press(plugin, f"kX:{PHONE}")

    assert router.kept == {} and "is a normal guest again" in text
    assert seen == [{"source": "guest_wifi_rotator", "what": "guest no longer keeps password"}]


def test_kept_device_that_is_away_is_listed_by_its_stored_name(tmp_path: Path) -> None:
    plugin, router, _ = _plugin(tmp_path)
    gone = "02:11:22:33:44:55"
    router.kept = {gone: "Old tablet", TABLET: "x"}

    text, _ = _press(plugin, "k")

    assert "⚪ Old tablet — not connected now" in text
    assert "🟢 Lenovo-Idea-Tab" in text


def test_router_trouble_is_said_plainly_and_nothing_is_assumed(tmp_path: Path) -> None:
    plugin, router, seen = _plugin(tmp_path)
    router.reachable = False

    text, buttons = _press(plugin, "k")
    assert "The router did not answer" in text and "🔄 Try again" in _texts(buttons)

    router.kept = {}
    plugin.router.kept_wifi_passphrases = lambda: {}      # list works, the change does not
    text, _ = _press(plugin, f"kp:{PHONE}")
    assert "The router did not accept it. Nothing was changed." in text and seen == []


@pytest.mark.parametrize("data", ["kp:not-a-mac", "kX:", "kx:F2:27:2C:00:00", "kp:F2:27:2C:00:00:01:99"])
def test_malformed_buttons_do_nothing(tmp_path: Path, data: str) -> None:
    plugin, router, _ = _plugin(tmp_path)
    plugin.on_callback(f"guest_wifi_rotator:{data}", CHAT, 7, "cb1")
    assert router.calls == []
    plugin.notifier.answer_callback.assert_called_once_with("cb1", "?")


def test_dashboard_status_is_in_words_and_never_holds_the_password(tmp_path: Path) -> None:
    plugin, _, _ = _plugin(tmp_path)

    status = plugin.api_status()

    assert status == {"ssid": "Cielo", "schedule": "Every week on Mon at 09:00",
                      "next": "", "last": ""}

    plugin._apply_schedule(None, "never")
    assert plugin.api_status()["schedule"] == "Never (only when you ask)"


def test_dashboard_switch_uses_the_same_path_as_the_buttons(tmp_path: Path) -> None:
    plugin, router, seen = _plugin(tmp_path)

    assert plugin.api_keep(PHONE.lower(), True) == "added"
    assert plugin.api_keep(PHONE, True) == "exists"
    assert plugin.api_keep(OTHER, True) == "not-connected"
    assert plugin.api_keep("nonsense", True) == "failed"
    assert plugin.api_keep(PHONE, False) == "removed"
    assert plugin.api_keep(PHONE, False) == "failed"          # nothing left to remove
    assert router.kept == {}
    assert [e["what"] for e in seen] == ["guest keeps password", "guest no longer keeps password"]


def test_rotation_screen_links_here_and_the_rotation_message_names_who_is_spared(
        tmp_path: Path) -> None:
    plugin, router, _ = _plugin(tmp_path)
    router.kept = {PHONE: "Redmi-13C-5G", TABLET: "Lenovo-Idea-Tab"}

    plugin.on_command("/rotation", "", CHAT)
    rows = plugin.notifier.send_to.call_args.kwargs["buttons"]
    assert rows[-1] == [{"text": "👤 Devices that keep their password",
                         "callback_data": "guest_wifi_rotator:k"}]

    plugin._send_qr = Mock()  # type: ignore[method-assign]
    plugin.rotate(target_chat=CHAT)
    assert plugin._send_qr.call_args.kwargs["note"] == (
        "👤 Not affected (they keep their own password): Lenovo-Idea-Tab, Redmi-13C-5G")

    router.kept = {}
    plugin.rotate(target_chat=CHAT)
    assert plugin._send_qr.call_args.kwargs["note"] == ""
