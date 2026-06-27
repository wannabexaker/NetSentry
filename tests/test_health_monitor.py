from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import Mock

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


def test_unreachable_router_skips_disk_alert(tmp_path: Path) -> None:
    router = Mock()
    router.stats.return_value = None
    notifier = Mock()
    plugin = _plugin(tmp_path, router, notifier)
    state = {}

    plugin._check_disk(state)

    notifier.send_state.assert_not_called()
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

    notifier.send_state.assert_called_once()
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

    notifier.send_state.assert_not_called()
    assert state["login_failures_seen"] == 1

    router.log_tail.return_value = [
        "login failure for user test",
        "login failure for user test2",
    ]
    plugin._check_failed_logins(state)

    notifier.send_state.assert_called_once()
    entry = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
    assert entry["type"] == "router_login"
    assert entry["details"]["new_failures"] == 1
