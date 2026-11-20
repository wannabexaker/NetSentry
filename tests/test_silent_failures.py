"""Things that used to fail without a word: the WiFi monitor giving up at
start-up for the life of the process, and the malware feed going stale."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from netsentry.core.plugin import PluginContext
from netsentry.plugins.threat_detector import ThreatDetectorPlugin, threat_intel
from netsentry.plugins.wifi_monitor import WifiMonitorPlugin


def _wifi(tmp_path: Path) -> WifiMonitorPlugin:
    ctx = PluginContext(
        name="wifi_monitor", config={}, router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger("test.wifi_health"),
        state_dir=str(tmp_path),
    )
    p = WifiMonitorPlugin(ctx)        # on_load() would start the radio thread
    p._iface = "wlan1"
    p._retry_seconds = 60
    p._status = "starting"
    p._stop = Mock(spec=threading.Event)
    p._stop.is_set.return_value = False
    return p


def test_monitor_retries_and_reports_down_then_back(tmp_path: Path) -> None:
    p = _wifi(tmp_path)
    p._iface_up_monitor = Mock(side_effect=[  # type: ignore[method-assign]
        (False, "could not bring wlan1 up: Operation not possible due to RF-kill"),
        (False, "could not bring wlan1 up: Operation not possible due to RF-kill"),
        (True, ""),
    ])

    assert p._wait_for_radio() is True

    assert p._iface_up_monitor.call_count == 3
    assert p._stop.wait.call_count == 2                 # waited between attempts
    states = [c.args[0] for c in p.notifier.notify.call_args_list]
    assert states == ["attention", "recovery"]          # told once down, once back
    down = p.notifier.notify.call_args_list[0].args[1]
    assert down.startswith("⚠️ WiFi attack monitor — not running")
    assert "sudo rfkill unblock wifi" in down and "`" not in down   # no literal Markdown
    assert p._status == "monitoring"


def test_with_the_watchdog_loaded_the_monitor_alerts_once_and_leaves_the_recovery_to_it(
        tmp_path: Path) -> None:
    p = _wifi(tmp_path)
    p.ctx._all_plugins = [p, SimpleNamespace(ctx=SimpleNamespace(name="self_check"))]
    p.ctx.events = Mock()
    p._iface_up_monitor = Mock(side_effect=[  # type: ignore[method-assign]
        (False, "monitor mode failed: No such device"), (True, "")])
    seen: list = []
    p._stop.wait.side_effect = lambda *_: seen.append(p.health()[0])

    assert p._wait_for_radio() is True

    assert [c.args[0] for c in p.notifier.notify.call_args_list] == ["attention"]
    p.ctx.events.publish.assert_called_once_with("health.alerted",
                                                 {"check": "WiFi attack monitor"})
    assert seen[0].ok is False and seen[0].notified      # while down: already told


def test_monitor_that_starts_fine_says_nothing(tmp_path: Path) -> None:
    p = _wifi(tmp_path)
    p._iface_up_monitor = Mock(return_value=(True, ""))  # type: ignore[method-assign]

    assert p._wait_for_radio() is True

    p.notifier.notify.assert_not_called()
    p._stop.wait.assert_not_called()


def test_monitor_stops_retrying_on_shutdown_and_shows_why_in_status(tmp_path: Path) -> None:
    p = _wifi(tmp_path)
    p._iface_up_monitor = Mock(  # type: ignore[method-assign]
        return_value=(False, "monitor mode failed: No such device"))
    p._stop.is_set.side_effect = [False, False, True]

    assert p._wait_for_radio() is False

    assert p.notifier.notify.call_count == 1         # not once per retry
    assert "No such device" in p._status


def _threat(tmp_path: Path) -> ThreatDetectorPlugin:
    ctx = PluginContext(
        name="threat_detector", config={}, router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger("test.intel_health"),
        state_dir=str(tmp_path),
    )
    p = ThreatDetectorPlugin(ctx)
    p.on_load()
    return p


def _cache(tmp_path: Path, age_days: int) -> None:
    ts = (datetime.now() - timedelta(days=age_days)).isoformat(timespec="seconds")
    (tmp_path / "threat_feeds.json").write_text(
        json.dumps({"ts": ts, "domains": {"bad.example": "URLhaus"}}), encoding="utf-8")


def test_stale_feed_warns_owner_once_a_week(tmp_path: Path, monkeypatch) -> None:
    p = _threat(tmp_path)
    _cache(tmp_path, age_days=29)
    monkeypatch.setattr(threat_intel, "refresh", lambda *a, **k: (0, False))

    p.refresh_feeds()
    p.refresh_feeds()                                    # next night: no repeat

    assert p.notifier.notify.call_count == 1
    state, text = p.notifier.notify.call_args.args
    assert state == "attention" and "29 days" in text


def test_short_feed_outage_stays_quiet(tmp_path: Path, monkeypatch) -> None:
    p = _threat(tmp_path)
    _cache(tmp_path, age_days=2)
    monkeypatch.setattr(threat_intel, "refresh", lambda *a, **k: (0, False))

    p.refresh_feeds()

    p.notifier.notify.assert_not_called()


def test_successful_refresh_never_warns(tmp_path: Path, monkeypatch) -> None:
    p = _threat(tmp_path)
    _cache(tmp_path, age_days=40)
    monkeypatch.setattr(threat_intel, "refresh", lambda *a, **k: (1234, True))

    p.refresh_feeds()

    p.notifier.notify.assert_not_called()
