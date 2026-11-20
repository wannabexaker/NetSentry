from __future__ import annotations

import json
import logging
import time
import types
from pathlib import Path
from unittest.mock import Mock

from netsentry.core import notify
from netsentry.core.events import RESTART_REQUESTED, EventBus
from netsentry.core.plugin import PluginContext
from netsentry.core.router import SystemStats
from netsentry.plugins.health_monitor import HealthMonitorPlugin


def _plugin(tmp_path: Path, router: Mock, notifier: Mock) -> HealthMonitorPlugin:
    ctx = PluginContext(
        name="health_monitor",
        config={"disk_low_mb": 10, "login_fail_threshold": 1},
        router=router,
        notifier=notifier,
        vault=Mock(),
        logger=logging.getLogger("test.health"),
        state_dir=str(tmp_path),
    )
    plugin = HealthMonitorPlugin(ctx)
    plugin.on_load()
    return plugin


def _stats(free_mb: int) -> SystemStats:
    return SystemStats(
        uptime_seconds=100,
        cpu_load_pct=1,
        free_memory_bytes=1,
        total_memory_bytes=2,
        free_disk_bytes=free_mb * 1024 * 1024,
        total_disk_bytes=100 * 1024 * 1024,
        board_name="test",
        routeros_version="7.22.1",
    )


def test_parse_break_alerts_when_reachable_but_unreadable(tmp_path: Path) -> None:
    router = Mock()
    router._ssh = Mock(return_value=(0, "OK\n"))  # SSH works
    router.stats.return_value = None  # but data won't parse
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)

    s: dict = {}
    plugin._check_router_readable(s)  # 1st observation — no alert yet
    assert not notifier.notify.called
    plugin._check_router_readable(s)  # 2nd consecutive — alert
    assert notifier.notify.called
    assert "parsing" in notifier.notify.call_args.args[1].lower()

    # recovery once readable again
    router.stats.return_value = _stats(500)
    notifier.reset_mock()
    plugin._check_router_readable(s)
    assert notifier.notify.called
    assert "readable again" in notifier.notify.call_args.args[1].lower()


def test_parse_break_silent_when_router_unreachable(tmp_path: Path) -> None:
    router = Mock()
    router._ssh = Mock(return_value=(-1, ""))  # SSH itself fails
    router.stats.return_value = None
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    s: dict = {}
    plugin._check_router_readable(s)
    plugin._check_router_readable(s)
    assert not notifier.notify.called  # unreachable != parse break


def test_unreachable_router_skips_disk_alert(tmp_path: Path) -> None:
    router = Mock()
    router.stats.return_value = None
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    state = {}

    plugin._check_disk(state)

    notifier.notify.assert_not_called()
    assert state == {}
    assert not (tmp_path / "alerts.jsonl").exists()


def test_real_low_disk_alerts_once_and_recovery_is_audited(tmp_path: Path) -> None:
    router = Mock()
    router.stats.return_value = _stats(5)
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    state: dict = {}

    plugin._check_disk(state)
    plugin._check_disk(state)
    router.stats.return_value = _stats(20)
    plugin._check_disk(state)

    notifier.notify.assert_called_once()
    entries = [json.loads(line) for line in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    assert [entry["event"] for entry in entries] == ["alert", "recovery"]
    assert "disk_alert_at" not in state


def test_failed_login_first_run_establishes_baseline_then_alerts(tmp_path: Path) -> None:
    router = Mock()
    router.log_tail.return_value = ["login failure for user test"]
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    state: dict = {}

    plugin._check_failed_logins(state)

    notifier.notify.assert_not_called()
    assert state["login_failures_seen"] == 1

    router.log_tail.return_value = [
        "login failure for user test",
        "login failure for user test2",
    ]
    plugin._check_failed_logins(state)

    notifier.notify.assert_called_once()
    entry = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
    assert entry["type"] == "router_login"
    assert entry["details"]["new_failures"] == 1


# ─── one alert per problem, and the owner's own restarts ─────────────

def _named(name: str, **attrs) -> types.SimpleNamespace:
    return types.SimpleNamespace(ctx=types.SimpleNamespace(name=name), COMMANDS=[], **attrs)


def test_unreadable_router_is_left_to_the_watchdog_when_there_is_one(
        tmp_path: Path) -> None:
    router = Mock()
    router._ssh = Mock(return_value=(0, "OK\n"))
    router.stats.return_value = None
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    plugin.ctx._all_plugins = [plugin, _named("self_check")]  # type: ignore[attr-defined]
    assert plugin.health()[0].ok is True
    s: dict = {}

    plugin._check_router_readable(s)
    plugin._check_router_readable(s)
    plugin._save(s)

    notifier.notify.assert_not_called()                  # self_check alerts, once
    assert "router_parse" in (tmp_path / "alerts.jsonl").read_text()   # audit trail kept
    check = plugin.health()[0]                           # …and the watchdog can see it
    assert check.name == "Router system data" and check.ok is False


def test_a_reboot_the_owner_asked_for_is_reported_as_done_not_as_a_surprise(
        tmp_path: Path) -> None:
    router = Mock()
    notifier = Mock()
    events = EventBus()
    ctx = PluginContext(name="health_monitor", config={}, router=router, notifier=notifier,
                        vault=Mock(), logger=logging.getLogger("test.health"),
                        state_dir=str(tmp_path), events=events)
    plugin = HealthMonitorPlugin(ctx)
    plugin.on_load()
    s = {"router_uptime_s": 86400 * 40}

    events.publish(RESTART_REQUESTED, {"target": "router"})
    router.uptime_seconds.return_value = 90
    plugin._check_uptime(s)

    kind, text = notifier.notify.call_args.args
    assert kind == notify.RECOVERY and "restarted as you asked" in text

    # A later reboot nobody asked for is a surprise again.
    s["router_uptime_s"] = 86400
    router.uptime_seconds.return_value = 60
    plugin._check_uptime(s)
    kind, text = notifier.notify.call_args.args
    assert kind == notify.ATTENTION and text.startswith("⚠️ Router restarted — not by you")


def test_internet_outage_is_urgent_and_the_recovery_says_how_long(
        tmp_path: Path, monkeypatch) -> None:
    notifier = Mock()
    plugin = _plugin(tmp_path, Mock(), notifier)
    results = iter([1, 0])
    monkeypatch.setattr("netsentry.plugins.health_monitor.subprocess.run",
                        lambda *a, **k: types.SimpleNamespace(returncode=next(results)))
    s: dict = {}

    plugin._check_internet(s)
    kind, text = notifier.notify.call_args.args
    assert kind == notify.URGENT and text.startswith("🚨 Internet — down")
    assert notifier.notify.call_args.kwargs["buttons"] is None   # no smart plug, no button

    s["internet_down_since"] = time.time() - 14 * 60
    plugin._check_internet(s)
    kind, text = notifier.notify.call_args.args
    assert kind == notify.RECOVERY and text == "✅ Back to normal: Internet (down 14 min)"


def test_internet_alert_offers_the_plug_restart_only_when_there_is_a_plug(
        tmp_path: Path, monkeypatch) -> None:
    notifier = Mock()
    plugin = _plugin(tmp_path, Mock(), notifier)
    power = _named("power", has_isp_plug=lambda: True)
    power.COMMANDS = [{"command": "restart", "description": "restart"}]
    plugin.ctx._all_plugins = [plugin, power, _named("menu")]  # type: ignore[attr-defined]
    monkeypatch.setattr("netsentry.plugins.health_monitor.subprocess.run",
                        lambda *a, **k: types.SimpleNamespace(returncode=1))

    plugin._check_internet({})

    (button,), = notifier.notify.call_args.kwargs["buttons"]
    assert button == {"text": "🔁 Restart internet router", "callback_data": "menu:r:/restart"}


def test_a_new_device_is_fyi_with_a_name_and_a_block_button(tmp_path: Path) -> None:
    mac = "AA:BB:CC:DD:EE:01"
    router = Mock()
    router.wifi_clients.return_value = [types.SimpleNamespace(
        mac=mac, ssid="Home", signal_dbm=-51, band="5ghz")]
    router.ethernet_clients.return_value = []
    router.dhcp_leases.return_value = [types.SimpleNamespace(
        mac=mac, ip="192.0.2.20", hostname="Kitchen-<plug>")]
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    s = {"known_macs": ["AA:BB:CC:DD:EE:99"]}

    plugin._check_new_clients(s)

    kind, text = notifier.notify.call_args.args
    assert kind == notify.INFO
    assert text.startswith("🆕 New device") and "🚨" not in text
    assert "Kitchen-<plug>" in text and "-51 dBm" in text
    block = notifier.notify.call_args.kwargs["buttons"][0][0]
    assert block["callback_data"] == f"security_actions:block:{mac}"
