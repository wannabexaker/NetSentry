from __future__ import annotations

import logging
import os
import time
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core import notify
from netsentry.core.events import EventBus
from netsentry.core.notify import HEALTH_ALERTED
from netsentry.core.plugin import HealthCheck, Plugin, PluginContext
from netsentry.core.scheduler import Scheduler
from netsentry.plugins.config_backup import ConfigBackupPlugin
from netsentry.plugins.guest_wifi_rotator import GuestWifiRotatorPlugin
from netsentry.plugins.self_check import SelfCheckPlugin
from netsentry.plugins.threat_detector import ThreatDetectorPlugin, threat_intel
from netsentry.plugins.wifi_monitor import WifiMonitorPlugin


def _ctx(name: str, tmp_path: Path, **kw) -> PluginContext:
    return PluginContext(
        name=name, config=kw.pop("config", {}), router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger(f"test.{name}"),
        state_dir=str(tmp_path / name), **kw)


class _Fake:
    """A plugin whose health we control."""

    def __init__(self, name: str, *checks: HealthCheck, boom: bool = False) -> None:
        self.ctx = types.SimpleNamespace(name=name)
        self.results = list(checks)
        self.boom = boom

    def health(self) -> list[HealthCheck]:
        if self.boom:
            raise RuntimeError("nope")
        return list(self.results)


def _checker(tmp_path: Path, *others, **config) -> SelfCheckPlugin:
    config.setdefault("check_updates", False)      # never ask the host's apt in tests
    config.setdefault("error_window_minutes", 0)   # the log watch has its own tests
    wiring = {k: config.pop(k) for k in ("events", "scheduler") if k in config}
    ctx = _ctx("self_check", tmp_path, config=config, **wiring)
    (tmp_path / "self_check").mkdir(parents=True, exist_ok=True)
    p = SelfCheckPlugin(ctx)
    p.on_load()
    ctx._all_plugins = [p, *others]  # type: ignore[attr-defined]
    return p


# ─── /health ─────────────────────────────────────────────────────

def test_report_puts_problems_first_and_says_how_many(tmp_path: Path) -> None:
    p = _checker(
        tmp_path,
        _Fake("a", HealthCheck("Router backup", True, "last backup 2026-11-16")),
        _Fake("b", HealthCheck("WiFi attack monitor", False, "NOT running — RF-kill")),
    )
    text = p.report()

    assert text.startswith("🩺 Health — ⚠️ 1 check needs you")
    assert text.index("WiFi attack monitor") < text.index("Router backup")
    assert "RF-kill" in text


def test_all_good_report_and_briefing_line(tmp_path: Path) -> None:
    p = _checker(tmp_path, _Fake("a", HealthCheck("Router backup", True)))
    assert "everything is running" in p.report()
    assert "checks OK" in p.summary_line()


def test_briefing_line_names_the_problems(tmp_path: Path) -> None:
    p = _checker(tmp_path, _Fake("b", HealthCheck("Malware-domain feeds", False, "old")))
    line = p.summary_line()
    assert "1 problem" in line and "Malware-domain feeds" in line
    assert "/health" not in line                 # the briefing puts a button under it


def test_a_plugin_whose_health_crashes_is_itself_a_problem(tmp_path: Path) -> None:
    p = _checker(tmp_path, _Fake("flaky", boom=True),
                 _Fake("fine", HealthCheck("Fine thing", True)))
    checks = {c.name: c for c in p.checks()}
    assert checks["flaky self-report"].ok is False
    assert checks["Fine thing"].ok is True               # one bad plugin hides nothing


def test_health_command_sends_report_with_refresh_button(tmp_path: Path) -> None:
    p = _checker(tmp_path)
    p.on_command("/health", "", 42)
    assert p.notifier.send_to.call_args.args[1].startswith("🩺 Health — ")
    assert p.notifier.send_to.call_args.kwargs["buttons"][0][0]["callback_data"] == "self_check:refresh"

    p.on_callback("self_check:refresh", 42, 7, "cb")
    assert p.notifier.edit_message.call_args.args[:2] == (42, 7)


# ─── watchdog ────────────────────────────────────────────────────

def test_watchdog_alerts_once_after_confirmation_then_reports_recovery(tmp_path: Path) -> None:
    wifi = _Fake("wifi", HealthCheck("WiFi attack monitor", True))
    p = _checker(tmp_path, wifi)

    p.watch()
    p.notifier.notify.assert_not_called()             # healthy: silence

    wifi.results = [HealthCheck("WiFi attack monitor", False, "NOT running — RF-kill")]
    p.watch()
    p.notifier.notify.assert_not_called()             # one bad reading could be a blip
    p.watch()
    kind, text = p.notifier.notify.call_args.args
    assert kind == notify.ATTENTION and "RF-kill" in text
    assert text.startswith("⚠️ WiFi attack monitor — stopped working")
    full = p.notifier.notify.call_args.kwargs["buttons"][0][0]
    assert full == {"text": "🩺 Full check", "callback_data": "self_check:full"}
    assert "/health" not in text                          # a button, not typed syntax

    for _ in range(5):                                    # still broken: no nagging
        p.watch()
    assert p.notifier.notify.call_count == 1

    wifi.results = [HealthCheck("WiFi attack monitor", True)]
    p.watch()
    kind, text = p.notifier.notify.call_args.args
    assert kind == notify.RECOVERY
    assert text.startswith("✅ Back to normal: WiFi attack monitor (down ")
    assert p.notifier.notify.call_count == 2


def test_full_check_button_under_an_alert_sends_a_new_report(tmp_path: Path) -> None:
    p = _checker(tmp_path, _Fake("a", HealthCheck("Router backup", True)))
    p.on_callback("self_check:full", 42, 7, "cb")
    p.notifier.edit_message.assert_not_called()           # the alert stays readable
    assert p.notifier.send_to.call_args.args[1].startswith("🩺 Health — ")


def test_a_check_the_plugin_already_alerted_about_gets_only_the_recovery(
        tmp_path: Path) -> None:
    backup = _Fake("config_backup",
                   HealthCheck("Router config backup", False, "failed", notified=True))
    p = _checker(tmp_path, backup)

    for _ in range(4):
        p.watch()
    p.notifier.notify.assert_not_called()                 # the plugin said it already
    assert "Router config backup" in p.report()           # /health still shows it

    backup.results = [HealthCheck("Router config backup", True)]
    p.watch()
    kind, text = p.notifier.notify.call_args.args
    assert kind == notify.RECOVERY and "Router config backup" in text
    assert p.notifier.notify.call_count == 1


def test_a_failed_job_is_not_a_second_alert_when_its_plugin_already_says_so(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.tzname", ("UTC", "UTC"))
    sched = Scheduler()

    def boom() -> None:
        raise RuntimeError("the router did not write the export")

    sched.add_cron("0 3 * * 0", boom, name="config_backup.weekly")
    with pytest.raises(RuntimeError):
        sched._sched.get_job("config_backup.weekly").func()
    backup = _Fake("config_backup",
                   HealthCheck("Router config backup", False, "failed", notified=True))
    p = _checker(tmp_path, backup, scheduler=sched)

    job = next(c for c in p.checks() if c.name.startswith("Scheduled job"))
    assert job.ok is False and job.notified               # listed, but not re-alerted
    p.watch()
    p.watch()
    p.notifier.notify.assert_not_called()


def test_an_alert_made_by_a_plugin_is_followed_by_a_recovery_even_between_rounds(
        tmp_path: Path) -> None:
    events = EventBus()
    wifi = _Fake("wifi_monitor", HealthCheck("WiFi attack monitor", True))
    p = _checker(tmp_path, wifi, events=events)

    # The radio went down and came back before the watchdog ever looked.
    events.publish(HEALTH_ALERTED, {"check": "WiFi attack monitor"})
    p.watch()

    kind, text = p.notifier.notify.call_args.args
    assert kind == notify.RECOVERY and "WiFi attack monitor" in text
    assert p.notifier.notify.call_count == 1


def test_watchdog_does_not_repeat_an_alert_after_a_restart(tmp_path: Path) -> None:
    broken = _Fake("wifi", HealthCheck("WiFi attack monitor", False, "down"))
    p = _checker(tmp_path, broken)
    p.watch()
    p.watch()
    assert p.notifier.notify.call_count == 1

    again = _checker(tmp_path, broken)                    # new process, same state dir
    again.watch()
    again.watch()
    again.notifier.notify.assert_not_called()


def test_watchdog_blip_never_alerts(tmp_path: Path) -> None:
    wifi = _Fake("wifi", HealthCheck("WiFi attack monitor", False, "blip"))
    p = _checker(tmp_path, wifi)
    p.watch()
    wifi.results = [HealthCheck("WiFi attack monitor", True)]
    p.watch()
    wifi.results = [HealthCheck("WiFi attack monitor", False, "blip")]
    p.watch()
    p.notifier.notify.assert_not_called()


def test_low_disk_is_a_problem(tmp_path: Path) -> None:
    p = _checker(tmp_path, min_free_mb=10**9)
    disk = next(c for c in p.checks() if c.name == "Disk space")
    assert disk.ok is False and "MB free" in disk.detail


def test_disk_limit_is_a_share_of_the_disk_whatever_its_size(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil as _shutil
    from collections import namedtuple
    Usage = namedtuple("Usage", "total used free")
    gb = 1024 ** 3

    def disk(total_gb: float, free_gb: float):
        return lambda _path: Usage(int(total_gb * gb), int((total_gb - free_gb) * gb), int(free_gb * gb))

    def check(**config):
        p = _checker(tmp_path, **config)
        return next(c for c in p.checks() if c.name == "Disk space")

    monkeypatch.setattr(_shutil, "disk_usage", disk(57, 30))             # an SD card half full
    half = check()
    assert half.ok and half.detail == "47% full · 30 GB free"

    monkeypatch.setattr(_shutil, "disk_usage", disk(57, 6))              # 89% full, 6 GB still free
    full = check()
    assert not full.ok and full.detail == "89% full (6 GB free) — the limit is 85%"

    assert check(disk_max_used_pct=95).ok                                 # the owner's own limit
    assert check(disk_max_used_pct=0).ok                                  # share not checked
    monkeypatch.setattr(_shutil, "disk_usage", disk(500, 60))            # a big disk: 88% is still 60 GB
    assert not check().ok                                                 # …and still over the share


# ─── scheduler: failed jobs are visible ──────────────────────────

def test_scheduler_remembers_a_failing_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.tzname", ("UTC", "UTC"))
    sched = Scheduler()
    calls = {"n": 0}

    def flaky() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("router said no")

    sched.add_cron("0 3 * * *", flaky, name="backup.weekly")
    job = sched._sched.get_job("backup.weekly")
    with pytest.raises(RuntimeError):
        job.func()
    assert "router said no" in sched.job_stats()["backup.weekly"]["last_error"]

    p = _checker(tmp_path)
    p.ctx.scheduler = sched
    bad = [c for c in p.checks() if not c.ok]
    assert [c.name for c in bad] == ["Scheduled job backup.weekly"]

    job.func()                                            # next run succeeds
    assert sched.job_stats()["backup.weekly"]["last_error"] == ""
    assert all(c.ok for c in p.checks())


# ─── what each plugin reports about itself ───────────────────────

def test_plugins_report_nothing_by_default() -> None:
    assert Plugin.health(Mock()) == []


def test_wifi_monitor_health(tmp_path: Path) -> None:
    p = WifiMonitorPlugin(_ctx("wifi_monitor", tmp_path))
    p._iface, p._started_ts, p._last_frames_ts = "wlan1", time.time(), 0.0

    p._status = "NOT running — could not bring wlan1 up: RF-kill"
    assert p.health()[0].ok is False and "RF-kill" in p.health()[0].detail

    p._status = "monitoring"
    assert p.health()[0].ok is True
    p._started_ts = p._last_frames_ts = time.time() - 3600   # up, but deaf for an hour
    assert p.health()[0].ok is False and "heard nothing" in p.health()[0].detail


def test_config_backup_health(tmp_path: Path) -> None:
    p = ConfigBackupPlugin(_ctx("config_backup", tmp_path,
                                config={"backup_dir": str(tmp_path / "bk")}))
    p.on_load()
    assert p.health()[0].ok is False                       # nothing there yet

    (tmp_path / "bk").mkdir()
    fresh = tmp_path / "bk" / "router-2026-11-16_0300.rsc"
    fresh.write_text("x", encoding="utf-8")
    assert p.health()[0].ok is True

    old = time.time() - 20 * 86400
    os.utime(fresh, (old, old))
    assert p.health()[0].ok is False and "days old" in p.health()[0].detail


def test_rotation_health_flags_a_failed_rotation_until_one_succeeds(tmp_path: Path) -> None:
    p = GuestWifiRotatorPlugin(_ctx("guest_wifi_rotator", tmp_path, config={
        "ssid": "Guest", "security_profile": "guest-visitor"}))
    p.on_load()
    p._send_qr = Mock()  # type: ignore[method-assign]
    assert p.health()[0].ok is True

    p.router.set_wifi_passphrase.return_value = False
    p.rotate()
    assert p.health()[0].ok is False and "failed" in p.health()[0].detail

    p.router.set_wifi_passphrase.return_value = True
    p.rotate()
    assert p.health()[0].ok is True


def test_threat_detector_health(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = ThreatDetectorPlugin(_ctx("threat_detector", tmp_path))
    (tmp_path / "threat_detector").mkdir(parents=True, exist_ok=True)
    p.on_load()
    by_name = lambda: {c.name: c for c in p.health()}  # noqa: E731

    assert by_name()["Malware-domain feeds"].ok is False         # nothing downloaded

    monkeypatch.setattr(threat_intel, "_fetch",
                        lambda url, timeout: {f"bad{i}.example" for i in range(500)})
    threat_intel.refresh(p._intel_file)
    assert by_name()["Malware-domain feeds"].ok is True

    p._loaded_ts = time.time() - 7200                            # up 2h, never scanned
    assert by_name()["Threat detection cycle"].ok is False
    p._last_cycle_ts = time.time()
    assert by_name()["Threat detection cycle"].ok is True

    assert "switched off" in by_name()["LAN open-port scan"].detail
    p.api_set_scan("exposure", True)
    assert by_name()["LAN open-port scan"].ok is False           # on, but has never run
    with p._state_lock:
        s = p._state()
        s["exposure_ts"] = time.time()
        p._save(s)
    assert by_name()["LAN open-port scan"].ok is True

    assert "Detector settings" not in by_name()
    (tmp_path / "threat_detector" / "state.json.corrupt").write_text("{", encoding="utf-8")
    assert by_name()["Detector settings"].ok is False


def test_waiting_updates_need_attention_they_did_not_stop_working(tmp_path: Path) -> None:
    updates = _Fake("x", HealthCheck("Raspberry Pi system updates", False,
                                     "1 security update waiting"))
    p = _checker(tmp_path, updates)
    p.watch()
    p.watch()
    kind, text = p.notifier.notify.call_args.args
    assert text.startswith("⚠️ Raspberry Pi system updates — needs attention")
    assert "stopped working" not in text
