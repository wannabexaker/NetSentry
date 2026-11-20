"""Health checks that look at results, not activity.

Each one exists because something once failed while every "it ran" check
stayed green.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import PluginContext
from netsentry.core.router import ArpEntry, DhcpLease, MikroTikRouter, WifiClient
from netsentry.plugins import self_check
from netsentry.plugins.pihole_stats import PiholeStatsPlugin
from netsentry.plugins.self_check import SelfCheckPlugin


def _clients(n: int) -> list[WifiClient]:
    return [WifiClient(f"AA:BB:CC:00:00:{i:02X}", "Home", "wifi1", -50, "5ghz", "wpa2-psk")
            for i in range(n)]


def _leases(n: int) -> list[DhcpLease]:
    return [DhcpLease(f"AA:BB:CC:00:01:{i:02X}", f"192.0.2.{i + 1}", f"host{i}") for i in range(n)]


def _arp(complete: int, failed: int = 0) -> list[ArpEntry]:
    return ([ArpEntry(f"AA:BB:CC:00:02:{i:02X}", f"192.0.2.{i + 1}", "bridge", True)
             for i in range(complete)]
            + [ArpEntry(f"AA:BB:CC:00:03:{i:02X}", f"192.0.2.{i + 100}", "bridge", False)
               for i in range(failed)])


def _router(counts, wifi=11, dhcp=12, arp=21) -> Mock:
    router = Mock()
    router.table_counts.return_value = counts
    router.wifi_clients.return_value = _clients(wifi)
    router.dhcp_leases.return_value = _leases(dhcp)
    router.arp_table.return_value = _arp(arp, failed=15)
    return router


def _checker(tmp_path: Path, router, **config) -> SelfCheckPlugin:
    config.setdefault("check_updates", False)
    config.setdefault("error_window_minutes", 0)
    ctx = PluginContext(
        name="self_check", config=config, router=router, notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.outcome"), state_dir=str(tmp_path))
    plugin = SelfCheckPlugin(ctx)
    plugin.on_load()
    ctx._all_plugins = [plugin]  # type: ignore[attr-defined]
    return plugin


def _named(plugin: SelfCheckPlugin, name: str):
    return next((c for c in plugin.checks() if c.name == name), None)


# ─── reading the router ──────────────────────────────────────────

def test_matching_readings_are_reported_with_their_numbers(tmp_path: Path) -> None:
    plugin = _checker(tmp_path, _router({"wifi": 11, "dhcp": 12, "arp": 21}))

    check = _named(plugin, "Reading the router")

    assert check.ok
    assert check.detail == "WiFi devices 11/11 · DHCP leases 12/12 · ARP entries 21/21"


def test_an_empty_reading_while_the_router_has_devices_is_a_problem(tmp_path: Path) -> None:
    # What happened for weeks: the router listed its WiFi clients, the parser
    # matched none, and "no clients" looked like a quiet network.
    plugin = _checker(tmp_path, _router({"wifi": 14, "dhcp": 12, "arp": 21}, wifi=0))

    check = _named(plugin, "Reading the router")

    assert not check.ok
    assert check.detail == "the router lists 14 WiFi devices, NetSentry reads none"


def test_reading_far_fewer_than_the_router_lists_is_a_problem(tmp_path: Path) -> None:
    plugin = _checker(tmp_path, _router({"wifi": 11, "dhcp": 30, "arp": 21}, dhcp=9))
    check = _named(plugin, "Reading the router")
    assert not check.ok and "lists 30 DHCP leases, NetSentry reads only 9" in check.detail


@pytest.mark.parametrize("counts, wifi", [
    ({"wifi": 11, "dhcp": 12, "arp": 21}, 10),     # someone left between the two looks
    ({"wifi": 3, "dhcp": 12, "arp": 21}, 1),       # too few to call it a pattern
    ({"wifi": 0, "dhcp": 12, "arp": 21}, 0),       # nobody on WiFi is not a fault
])
def test_small_differences_and_empty_networks_are_fine(tmp_path: Path, counts, wifi) -> None:
    plugin = _checker(tmp_path, _router(counts, wifi=wifi))
    assert _named(plugin, "Reading the router").ok


def test_failed_arp_entries_do_not_count_as_missed(tmp_path: Path) -> None:
    router = _router({"wifi": 11, "dhcp": 12, "arp": 21})
    plugin = _checker(tmp_path, router)
    assert "ARP entries 21/21" in _named(plugin, "Reading the router").detail


def test_a_router_that_does_not_answer_is_said_so(tmp_path: Path) -> None:
    plugin = _checker(tmp_path, _router(None))
    check = _named(plugin, "Reading the router")
    assert not check.ok and check.detail == "the router did not answer"


def test_a_backend_that_cannot_count_is_simply_not_checked(tmp_path: Path) -> None:
    assert _named(_checker(tmp_path, _router({})), "Reading the router") is None
    assert _named(_checker(tmp_path, Mock()), "Reading the router") is None      # test doubles
    off = _checker(tmp_path, _router({"wifi": 9, "dhcp": 9, "arp": 9}, wifi=0),
                   check_router_readings=False)
    assert _named(off, "Reading the router") is None


def test_a_crash_while_comparing_is_a_problem_not_a_crash(tmp_path: Path) -> None:
    router = _router({"wifi": 11, "dhcp": 12, "arp": 21})
    router.dhcp_leases.side_effect = RuntimeError("boom")
    check = _named(_checker(tmp_path, router), "Reading the router")
    assert not check.ok and check.detail == "could not compare — details are in the log"


def test_the_router_is_not_asked_on_every_refresh(tmp_path: Path, monkeypatch) -> None:
    router = _router({"wifi": 11, "dhcp": 12, "arp": 21})
    plugin = _checker(tmp_path, router)

    for _ in range(5):
        plugin.checks()
    assert router.table_counts.call_count == 1

    monkeypatch.setattr(self_check, "_ROUTER_CHECK_EVERY_S", 0.0)
    plugin.checks()
    assert router.table_counts.call_count == 2


def test_router_counts_are_read_from_one_line() -> None:
    router = MikroTikRouter("192.0.2.1", "netsentry", "key")
    router._ssh = Mock(return_value=(0, "COUNTS wifi=11 dhcp=12 arp=21\n"))  # type: ignore[method-assign]
    assert router.table_counts() == {"wifi": 11, "dhcp": 12, "arp": 21}
    assert "/ip arp find where complete" in router._ssh.call_args.args[0]

    for rc, out in ((1, ""), (0, "bad command name\n"), (0, "COUNTS wifi= dhcp=1 arp=2\n")):
        router._ssh = Mock(return_value=(rc, out))  # type: ignore[method-assign]
        assert router.table_counts() is None


# ─── the error log ───────────────────────────────────────────────

def test_an_error_in_the_log_is_a_problem_for_a_while(tmp_path: Path) -> None:
    plugin = _checker(tmp_path, Mock(), error_window_minutes=60)
    try:
        assert _named(plugin, "Error log").detail == "no errors in the last 60 min"

        logging.getLogger("netsentry.core.router").warning("just a warning")
        assert _named(plugin, "Error log").ok

        logging.getLogger("netsentry.core.router").error("WiFi clients listed but none parsed")
        logging.getLogger("apscheduler.executors.default").error("Job %s raised", "x.daily")
        check = _named(plugin, "Error log")
        assert not check.ok
        assert check.detail == ("2 errors in the last 60 min — latest from "
                                "apscheduler.executors.default: Job x.daily raised")

        # …and it clears by itself once the errors are older than the window.
        plugin._errors.seen = type(plugin._errors.seen)(
            (ts - 3601, name, msg) for ts, name, msg in plugin._errors.seen)
        assert _named(plugin, "Error log").ok
    finally:
        plugin.on_unload()


def test_errors_of_a_plugin_that_already_reports_a_problem_do_not_alert_twice(
        tmp_path: Path) -> None:
    plugin = _checker(tmp_path, Mock(), error_window_minutes=60)
    try:
        logging.getLogger("netsentry.config_backup").error("Router backup failed: no export")
        logging.getLogger("apscheduler.executors.default").error(
            'Job "config_backup.weekly (trigger: cron[...])" raised an exception')

        assert plugin._error_check({"config_backup"}).notified is True     # same problem again
        assert plugin._error_check({"wifi_monitor"}).notified is False     # someone else's
        assert plugin._error_check(set()).notified is False

        logging.getLogger("netsentry.core.router").error("WiFi clients listed but none parsed")
        assert plugin._error_check({"config_backup"}).notified is False    # a new, unexplained one
    finally:
        plugin.on_unload()


def test_one_error_is_singular_and_long_messages_are_cut(tmp_path: Path) -> None:
    plugin = _checker(tmp_path, Mock(), error_window_minutes=30)
    try:
        logging.getLogger("netsentry.plugins.x").error("y" * 500)
        detail = _named(plugin, "Error log").detail
        assert detail.startswith("1 error in the last 30 min — latest from x: yyy")
        assert detail.endswith("…") and len(detail) < 160      # one short line, not the dump
    finally:
        plugin.on_unload()


def test_log_watch_can_be_switched_off_and_is_removed_on_unload(tmp_path: Path) -> None:
    root = logging.getLogger()
    before = len(root.handlers)

    off = _checker(tmp_path, Mock(), error_window_minutes=0)
    assert _named(off, "Error log") is None and len(root.handlers) == before

    on = _checker(tmp_path, Mock(), error_window_minutes=60)
    assert len(root.handlers) == before + 1
    on.on_unload()
    assert len(root.handlers) == before


# ─── the Pi-hole query log ───────────────────────────────────────

def _pihole(tmp_path: Path, answer, **config) -> PiholeStatsPlugin:
    ctx = PluginContext(
        name="pihole_stats", config=config, router=Mock(), notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.pihole"), state_dir=str(tmp_path))
    plugin = PiholeStatsPlugin(ctx)
    plugin.on_load()
    if isinstance(answer, Exception):
        plugin._sql = Mock(side_effect=answer)  # type: ignore[method-assign]
    else:
        plugin._sql = Mock(return_value=answer)  # type: ignore[method-assign]
    return plugin


@pytest.mark.parametrize("answer, ok, detail", [
    ("42", True, "last query just now"),
    ("600", True, "last query 10 min ago"),
    ("5400", False, "no DNS query logged for 90 min — is Pi-hole answering?"),
    ("", False, "the Pi-hole database holds no queries"),
    (RuntimeError("unable to open database file"), False,
     "NetSentry can't read Pi-hole's database — details are in the log"),
])
def test_pihole_query_log_must_be_fresh(tmp_path: Path, answer, ok: bool, detail: str) -> None:
    (check,) = _pihole(tmp_path, answer).health()
    assert check.name == "Pi-hole query log"
    assert (check.ok, check.detail) == (ok, detail)


def test_pihole_staleness_limit_is_configurable(tmp_path: Path) -> None:
    assert not _pihole(tmp_path, "600", stale_minutes=5).health()[0].ok
    assert _pihole(tmp_path, "600", stale_minutes=15).health()[0].ok
