"""lan_scanner: the device list, naming devices (typed and by button), the
interactive watcher, vendor lookup and the ping sweep."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from netsentry.core.events import EventBus
from netsentry.core.plugin import PluginContext
from netsentry.core.tag_store import TagStore
from netsentry.plugins.lan_scanner import LanScannerPlugin, _is_private_mac

PHONE = "AA:BB:CC:DD:EE:01"      # WiFi, has a hostname
CAMERA = "AA:BB:CC:DD:EE:02"     # WiFi, no hostname
PRINTER = "AA:BB:CC:DD:EE:03"    # Ethernet
GHOST = "AA:BB:CC:DD:EE:04"      # only in the ARP table
CHAT = 42


def _router() -> Mock:
    r = Mock()
    r.dhcp_leases.return_value = [
        SimpleNamespace(mac=PHONE, ip="192.0.2.10", hostname="pixel"),
        SimpleNamespace(mac=CAMERA, ip="192.0.2.11", hostname=""),
        SimpleNamespace(mac=PRINTER, ip="192.0.2.12", hostname="printer"),
    ]
    r.wifi_clients.return_value = [
        SimpleNamespace(mac=PHONE, ssid="Home", signal_dbm=-51, last_activity_ms=10,
                        interface="wifi1"),
        SimpleNamespace(mac=CAMERA, ssid="IoT", signal_dbm=-70, last_activity_ms=9000,
                        interface="wifi-iot"),
    ]
    r.ethernet_clients.return_value = [SimpleNamespace(mac=PRINTER, port="ether3")]
    r.arp_table.return_value = [
        SimpleNamespace(mac=PHONE, ip="192.0.2.10", interface="bridge"),
        SimpleNamespace(mac=GHOST, ip="192.0.2.99", interface="bridge"),
    ]
    return r


def _plugin(tmp_path: Path, **config) -> LanScannerPlugin:
    notifier = Mock()
    ctx = PluginContext(
        name="lan_scanner", config=config, router=_router(), notifier=notifier,
        vault=Mock(), logger=logging.getLogger("test.lan"), state_dir=str(tmp_path),
        events=EventBus(), notifiers_by_id={"tg": notifier},
    )
    p = LanScannerPlugin(ctx)
    p.on_load()
    return p


def _sent(p: LanScannerPlugin) -> list[str]:
    return [c.args[1] for c in p.notifier.send_to.call_args_list]


def _buttons(p: LanScannerPlugin) -> list[dict]:
    """Every button of every message sent so far, flattened."""
    return [b for c in p.notifier.send_to.call_args_list
            for row in (c.kwargs.get("buttons") or []) for b in row]


def _press(p: LanScannerPlugin, data: str) -> None:
    p.on_callback(data, CHAT, 7, "cb1")


# ─── inventory ───────────────────────────────────────────────────

def test_inventory_merges_the_router_tables(tmp_path: Path) -> None:
    items = {i["mac"]: i for i in _plugin(tmp_path)._build_inventory()}
    assert set(items) == {PHONE, CAMERA, PRINTER, GHOST}
    assert items[PHONE]["iface"] == "WiFi:Home" and items[PHONE]["signal"] == -51
    assert items[PRINTER]["iface"] == "Ethernet:ether3"
    assert items[GHOST]["ip"] == "192.0.2.99" and items[GHOST]["iface"] == "bridge"
    assert items[CAMERA]["ip"] == "192.0.2.11"        # from the lease, no ARP entry


def test_inventory_survives_a_router_without_arp_or_ethernet(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.router.arp_table.side_effect = RuntimeError("no such command")
    p.router.ethernet_clients.side_effect = RuntimeError("no such command")
    assert {i["mac"] for i in p._build_inventory()} == {PHONE, CAMERA, PRINTER}


def test_lan_lists_everything_grouped_with_buttons_for_the_rest(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.set_tag(PRINTER, "Office printer")
    p.on_command("/lan", "", CHAT)
    text = _sent(p)[0]
    assert "LAN inventory (4)" in text
    assert text.index("WiFi:") < text.index("Ethernet:") < text.index("Bridges:")
    assert "🏷 Office printer" in text and "-51dBm" in text
    assert "/lan tag" not in text                       # nothing to type
    data = {b["callback_data"] for b in _buttons(p)}
    assert {"lan_scanner:view:unknown", "lan_scanner:view:known",
            "lan_scanner:ping:-", "lan_scanner:dash:-"} <= data
    assert "lan_scanner:view:all" not in data           # already looking at it


def test_known_and_unknown_views(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.set_tag(PRINTER, "Office printer")
    p.on_command("/lan", "known", CHAT)
    assert "Tagged devices (1)" in _sent(p)[0] and PRINTER in _sent(p)[0]
    p.notifier.reset_mock()
    p.on_command("/lan", "unknown", CHAT)
    assert "Unknown devices (3)" in _sent(p)[0] and PRINTER not in _sent(p)[0]


def test_unknown_view_offers_one_name_button_per_device(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.set_tag(PRINTER, "Office printer")
    p.on_command("/lan", "unknown", CHAT)
    name_buttons = [b for b in _buttons(p) if ":tagprompt:" in b["callback_data"]]
    assert {b["callback_data"].split(":", 2)[2] for b in name_buttons} == {PHONE, CAMERA, GHOST}
    assert any("pixel" in b["text"] for b in name_buttons)       # hostname as the hint
    assert all(len(b["callback_data"].encode()) <= 64 for b in _buttons(p))


def test_empty_views_say_so(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/lan", "known", CHAT)
    assert "nothing in that view" in _sent(p)[0]


def test_a_long_list_is_split_and_buttons_go_under_the_last_part(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p._send(CHAT, "x" * 9000, buttons=[[{"text": "b", "callback_data": "lan_scanner:view:all"}]])
    calls = p.notifier.send_to.call_args_list
    assert len(calls) == 3
    assert [bool(c.kwargs.get("buttons")) for c in calls] == [False, False, True]


def test_view_and_dashboard_buttons_run_the_matching_view(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _press(p, "lan_scanner:view:unknown")
    assert "Unknown devices" in _sent(p)[0]
    p.notifier.reset_mock()
    _press(p, "lan_scanner:dash:-")
    assert "lan_dashboard plugin is not loaded" in _sent(p)[0]
    dashboard = Mock()
    dashboard.__class__.__name__ = "LanDashboardPlugin"
    p.ctx._all_plugins = [p, dashboard]  # type: ignore[attr-defined]
    _press(p, "lan_scanner:dash:-")
    dashboard.send_dashboard_link.assert_called_once_with(CHAT)


def test_unknown_subcommand_shows_help(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/lan", "frobnicate", CHAT)
    assert "/lan usage" in _sent(p)[0]
    p.on_command("/other", "", CHAT)                     # not ours: silent
    assert len(_sent(p)) == 1


# ─── naming devices ──────────────────────────────────────────────

def test_tag_and_untag_by_typing(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/lan", f"tag {PHONE.lower()} My phone", CHAT)
    assert p.tag_for(PHONE) == "My phone" and "Tagged" in _sent(p)[-1]
    p.on_command("/lan", f"tag {PHONE} Work phone", CHAT)
    assert 'was: "My phone"' in _sent(p)[-1]
    p.on_command("/lan", f"untag {PHONE}", CHAT)
    assert p.tag_for(PHONE) is None and "Untagged" in _sent(p)[-1]
    p.on_command("/lan", f"untag {PHONE}", CHAT)
    assert "was not tagged" in _sent(p)[-1]


@pytest.mark.parametrize("args, expected", [
    ("tag", "Usage: /lan tag"),
    ("tag not-a-mac Lamp", "Bad MAC"),
    ("untag nope", "Usage: /lan untag"),
    ("search", "Usage: /lan search"),
    ("vendor zz", "Usage: /lan vendor"),
])
def test_bad_input_is_explained_not_crashed(tmp_path: Path, args: str, expected: str) -> None:
    p = _plugin(tmp_path)
    p.on_command("/lan", args, CHAT)
    assert expected in _sent(p)[-1]
    assert p.tags_snapshot() == {}


def test_name_button_then_a_plain_message_names_the_device(tmp_path: Path) -> None:
    """Regression: the MAC in the button has colons of its own. Splitting the
    callback on every colon cut it down to its first byte, so the button under
    every "new device" alert asked for a name for "AA" and then failed."""
    p = _plugin(tmp_path)
    _press(p, f"lan_scanner:tagprompt:{CAMERA}")          # exactly what health_monitor sends
    assert CAMERA in _sent(p)[-1] and "Send me a name" in _sent(p)[-1]
    p.notifier.answer_callback.assert_called_with("cb1", "Send a name")
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": "kitchen-cam"})
    assert p.tag_for(CAMERA) == "kitchen-cam"
    assert "kitchen-cam" in _sent(p)[-1]
    # the prompt is used up: the next message is not taken as another name
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": "hello"})
    assert p.tag_for(CAMERA) == "kitchen-cam"


def test_name_prompt_ignores_other_chats_and_commands(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _press(p, f"lan_scanner:tagprompt:{CAMERA}")
    p.ctx.events.publish("telegram.text", {"chat_id": 999, "text": "intruder"})
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": "/status"})
    assert p.tag_for(CAMERA) is None
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": "x" * 200})
    assert p.tag_for(CAMERA) == "x" * 60                  # long names are cut, not refused


def test_name_button_with_a_broken_mac_does_nothing(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _press(p, "lan_scanner:tagprompt:AA")
    assert p._pending_tag_for_chat == {} and _sent(p) == []
    p.notifier.answer_callback.assert_called_with("cb1", "That device is no longer listed")


def test_search_matches_ip_mac_hostname_and_name(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.set_tag(CAMERA, "Kitchen cam")
    for query, mac in (("pixel", PHONE), ("192.0.2.12", PRINTER), ("kitchen", CAMERA),
                       ("ee:04", GHOST)):
        p.notifier.reset_mock()
        p.on_command("/lan", f"search {query}", CHAT)
        assert "1 matches" in _sent(p)[0] and mac in _sent(p)[0], query
    p.on_command("/lan", "search nothing-like-this", CHAT)
    assert "No matches" in _sent(p)[-1]


def test_a_damaged_tags_file_is_kept_not_overwritten(tmp_path: Path, caplog) -> None:
    """Device names are typed in by hand; a file we cannot read must not be
    treated as "no names" and then saved over."""
    p = _plugin(tmp_path)
    p.set_tag(PHONE, "My phone")
    tags_file = tmp_path / "tags.json"
    tags_file.write_text('{"AA:BB:CC:DD:EE:01": {"name": "My ph', encoding="utf-8")
    with caplog.at_level(logging.ERROR):
        assert p.tags_snapshot() == {}
    assert "damaged" in caplog.text
    assert "My ph" in (tmp_path / "tags.json.corrupt").read_text(encoding="utf-8")
    p.set_tag(CAMERA, "Cam")                              # life goes on with a fresh file
    assert p.tag_for(CAMERA) == "Cam"
    assert "My ph" in (tmp_path / "tags.json.corrupt").read_text(encoding="utf-8")


# ─── vendor lookup ───────────────────────────────────────────────

def test_vendor_from_the_builtin_table(tmp_path: Path) -> None:
    p = _plugin(tmp_path, online_oui_lookup=False)
    p.on_command("/lan", "vendor 04:F4:1C:00:00:01", CHAT)
    assert "MikroTik" in _sent(p)[-1]
    p.on_command("/lan", "vendor 00:11:22:33:44:55", CHAT)
    assert "(unknown)" in _sent(p)[-1]


@pytest.mark.parametrize("mac, private", [
    ("02:BB:34:A6:FB:CA", True), ("AA:BB:CC:DD:EE:01", True), ("DE:AD:BE:EF:00:01", True),
    ("04:F4:1C:D1:48:C4", False), ("B8:27:EB:00:00:01", False),
])
def test_private_addresses_are_recognised(mac: str, private: bool) -> None:
    assert _is_private_mac(mac) is private


def test_private_address_is_never_looked_up_online(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch("urllib.request.urlopen") as urlopen:
        assert "private address" in p._oui_lookup("02:BB:34:A6:FB:CA")
    urlopen.assert_not_called()


def test_online_vendor_lookup_is_cached(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    response = Mock(status=200)
    response.read.return_value = b"Acme Networks"
    response.__enter__ = lambda s: s
    response.__exit__ = lambda *a: False
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        assert p._oui_lookup("00:11:22:33:44:55") == "Acme Networks"
        assert p._oui_lookup("00:11:22:99:99:99") == "Acme Networks"   # same maker prefix
    assert urlopen.call_count == 1
    assert json.loads((tmp_path / "oui_cache.json").read_text("utf-8")) == {
        "00:11:22": "Acme Networks"}
    with patch("urllib.request.urlopen", side_effect=OSError("offline")):
        assert p._oui_lookup("00:99:88:77:66:55") == ""                # no crash offline
    with patch("urllib.request.urlopen") as urlopen:
        assert p._oui_lookup("00:99:88:77:66:55", online=False) == ""
    urlopen.assert_not_called()


# ─── ping sweep ──────────────────────────────────────────────────

def test_ping_rejects_bad_and_oversized_networks(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/lan", "ping not-a-network", CHAT)
    assert "Bad CIDR" in _sent(p)[-1]
    p.on_command("/lan", "ping 10.0.0.0/8", CHAT)
    assert "Refusing to scan" in _sent(p)[-1]


def test_ping_sweep_reports_who_answered(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.set_tag(PHONE, "My phone")

    def fake_run(cmd, **kwargs):
        if cmd[0] == "ping":
            return SimpleNamespace(returncode=0 if cmd[-1] == "192.0.2.1" else 1,
                                   stdout="", stderr="")
        return SimpleNamespace(returncode=0, stderr="", stdout=(
            f"192.0.2.1 dev eth0 lladdr {PHONE.lower()} REACHABLE\n"
            "192.0.2.2 dev eth0  FAILED\n"))

    with patch("netsentry.plugins.lan_scanner.subprocess.run", side_effect=fake_run):
        p.on_command("/lan", "ping 192.0.2.0/30", CHAT)
    texts = _sent(p)
    assert "(2 hosts)" in texts[0]
    assert "1 hosts on 192.0.2.0/30" in texts[1] and "🏷 My phone" in texts[1]


def test_ping_sweep_with_no_answers(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch("netsentry.plugins.lan_scanner.subprocess.run",
               side_effect=subprocess.TimeoutExpired("ping", 2)):
        p.on_command("/lan", "ping 192.0.2.0/30", CHAT)
    assert "0 hosts answered" in _sent(p)[-1]


def test_ping_without_a_network_uses_this_machines_subnet(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        out = {"route": "default via 192.0.2.1 dev eth0 proto dhcp\n",
               "addr": "2: eth0    inet 192.0.2.57/24 brd 192.0.2.255 scope global eth0\n"}
        key = "route" if "route" in cmd else "addr"
        return SimpleNamespace(returncode=0, stdout=out[key], stderr="")

    with patch("netsentry.plugins.lan_scanner.subprocess.run", side_effect=fake_run):
        assert LanScannerPlugin._default_gateway_cidr() == "192.0.2.0/24"
    with patch("netsentry.plugins.lan_scanner.subprocess.run",
               side_effect=FileNotFoundError("ip")):
        assert LanScannerPlugin._default_gateway_cidr() is None
        assert LanScannerPlugin._read_ip_neighbor() == {}
    p = _plugin(tmp_path)
    with patch.object(LanScannerPlugin, "_default_gateway_cidr", return_value=None):
        p.on_command("/lan", "ping", CHAT)
    assert "Could not auto-detect" in _sent(p)[-1]


# ─── /lan watch: "which device did I just switch on?" ────────────

def _watching(p: LanScannerPlugin, names: list[str], awaiting: str | None = None) -> dict:
    p._watch_state = {
        "chat_id": CHAT, "pending_names": list(names), "tagged_in_session": [],
        "baseline": {CAMERA: 9000, PHONE: 10}, "last_alert_ts": 0.0,
        "awaiting_pick": awaiting,
    }
    return p._watch_state


def test_watch_usage_and_status_when_idle(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/lan", "watch", CHAT)
    assert "Usage: /lan watch start" in _sent(p)[-1]
    p.on_command("/lan", "watch status", CHAT)
    assert "No watch is running" in _sent(p)[-1]
    p.on_command("/lan", "watch stop", CHAT)
    assert "No watch is running" in _sent(p)[-1]


def test_watch_notices_the_device_that_just_woke_up(tmp_path: Path) -> None:
    p = _plugin(tmp_path, watch_poll_seconds=0.01, watch_cooldown_seconds=0)
    _watching(p, ["Lamp", "Plug"])
    # The camera was idle (9000 ms) and is now active; the phone was active all along.
    p.router.wifi_clients.return_value = [
        SimpleNamespace(mac=PHONE, ssid="Home", signal_dbm=-51, last_activity_ms=20,
                        interface="wifi1"),
        SimpleNamespace(mac=CAMERA, ssid="IoT", signal_dbm=-70, last_activity_ms=100,
                        interface="wifi-iot"),
    ]
    picked: list = []

    def picker(chat_id, target, pending):
        picked.append((chat_id, target.mac, pending))
        p._watch_stop.set()

    with patch.object(p, "_send_watch_picker", side_effect=picker):
        p._watch_loop()
    assert picked == [(CHAT, CAMERA, ["Lamp", "Plug"])]
    assert p._watch_state["awaiting_pick"] == CAMERA


def test_watch_ignores_devices_that_are_always_busy(tmp_path: Path) -> None:
    p = _plugin(tmp_path, watch_poll_seconds=0.01, watch_cooldown_seconds=0)
    _watching(p, ["Lamp"])
    polls = {"n": 0}

    def clients():
        polls["n"] += 1
        if polls["n"] >= 3:
            p._watch_stop.set()
        return [SimpleNamespace(mac=PHONE, ssid="Home", signal_dbm=-51,
                                last_activity_ms=15, interface="wifi1")]

    p.router.wifi_clients.side_effect = clients
    with patch.object(p, "_send_watch_picker") as picker:
        p._watch_loop()
    picker.assert_not_called()


def test_watch_picker_buttons_fit_and_name_the_device(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    target = SimpleNamespace(mac=CAMERA, ssid="IoT", signal_dbm=-70, interface="wifi-iot")
    p._send_watch_picker(CHAT, target, ["Lamp", "Plug"])
    params = p.notifier.api_post.call_args.args[1]
    rows = json.loads(params["reply_markup"])["inline_keyboard"]
    data = [b["callback_data"] for row in rows for b in row]
    assert f"lan_scanner:watchpick:{CAMERA}:0" in data and f"lan_scanner:watchpick:{CAMERA}:-1" in data
    assert all(len(d.encode()) <= 64 for d in data)


def test_watch_pick_names_the_device(tmp_path: Path) -> None:
    """Regression: same colon-splitting bug — every pick came back "Stale"."""
    p = _plugin(tmp_path)
    state = _watching(p, ["Lamp", "Plug"], awaiting=CAMERA)
    _press(p, f"lan_scanner:watchpick:{CAMERA}:1")
    assert p.tag_for(CAMERA) == "Plug"
    assert state["pending_names"] == ["Lamp"] and state["awaiting_pick"] is None
    assert CAMERA not in state["baseline"]
    p.notifier.answer_callback.assert_called_with("cb1", "Got it")
    assert "Plug" in p.notifier.edit_message.call_args.args[2]


def test_watch_skip_and_stale_picks(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    state = _watching(p, ["Lamp"], awaiting=CAMERA)
    _press(p, f"lan_scanner:watchpick:{PHONE}:0")         # not the device being asked about
    p.notifier.answer_callback.assert_called_with("cb1", "Stale")
    assert p.tag_for(PHONE) is None and state["awaiting_pick"] == CAMERA
    _press(p, f"lan_scanner:watchpick:{CAMERA}:-1")       # skip
    assert p.tag_for(CAMERA) is None and state["awaiting_pick"] is None
    assert state["pending_names"] == ["Lamp"]
    assert "Skipped" in p.notifier.edit_message.call_args.args[2]


def test_watch_start_and_stop_end_to_end(tmp_path: Path) -> None:
    p = _plugin(tmp_path, watch_poll_seconds=0.01)
    p.set_tag(PHONE, "My phone")
    p.on_command("/lan", "watch start Lamp, Plug", CHAT)
    try:
        assert "Watching 1 untagged WiFi clients" in _sent(p)[-1]       # only the camera
        p.on_command("/lan", "watch Other", CHAT)
        assert "already running" in _sent(p)[-1]
        p.on_command("/lan", "watch status", CHAT)
        assert "Remaining names: Lamp, Plug" in _sent(p)[-1]
    finally:
        _press(p, "lan_scanner:watchstop:-")
    assert "Watch stopped" in _sent(p)[-1]
    assert p._watch_thread is None and p._watch_state is None


def test_tag_store_reads_what_the_plugin_wrote(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.set_tag(PHONE, "My phone")
    p.retire_tag(PHONE)
    assert p.tag_info(PHONE) == ("My phone", True)
    assert p.has_active_tag(PHONE) is False
    assert TagStore(tmp_path / "tags.json").name_for(PHONE) == "My phone"
