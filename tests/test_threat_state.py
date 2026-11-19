"""The threat detector's state file is shared by several threads (the scan
cycle, the daily report, the WiFi monitor, /allow · /scans · /audit). Losing it
silently re-baselines the detector and forgets the owner's allow-list."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from unittest.mock import Mock

from netsentry.core.plugin import PluginContext
from netsentry.plugins.threat_detector import ThreatDetectorPlugin


def _plugin(tmp_path: Path) -> ThreatDetectorPlugin:
    ctx = PluginContext(
        name="threat_detector", config={}, router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger("test.threat_state"),
        state_dir=str(tmp_path),
    )
    plugin = ThreatDetectorPlugin(ctx)
    plugin.on_load()
    plugin._device_names = lambda: {}  # type: ignore[method-assign]
    plugin._arp_pairs = lambda: []  # type: ignore[method-assign]
    plugin._recent_domain_clients = lambda: {"www.example.org": {"10.0.0.5"}}  # type: ignore[method-assign]
    return plugin


def test_settings_changed_during_a_cycle_survive_it(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.run_checks()                                   # baseline

    def owner_acts_mid_cycle() -> dict:
        # The cycle has already read its copy of the state; meanwhile the owner
        # trusts a domain, toggles a detector, and the WiFi monitor records a finding.
        p.api_set_allow("cdn.example.net", True)
        p.api_set_scan("new_domain", True)
        p.record_finding("deauth_nearby", "aa:bb:cc:dd:ee:ff", "seen nearby")
        return {"www.example.org": {"10.0.0.5"}, "new.example.org": {"10.0.0.5"}}

    p._recent_domain_clients = owner_acts_mid_cycle  # type: ignore[method-assign]
    p.run_checks()

    state = p._state()
    assert state["allowed_domains"] == ["cdn.example.net"]
    assert state["scans_enabled"] == {"new_domain": True}
    assert "deauth_nearby:aa:bb:cc:dd:ee:ff" in state["alerted"]
    assert "new.example.org" in state["known_domains"]      # the cycle's own work too


def test_corrupt_state_is_quarantined_and_reported_not_silently_reset(
    tmp_path: Path, caplog,
) -> None:
    p = _plugin(tmp_path)
    (tmp_path / "state.json").write_text('{"allowed_domains": ["x.example"', encoding="utf-8")

    with caplog.at_level(logging.ERROR):
        assert p._state() == {}

    assert "corrupt" in caplog.text
    kept = tmp_path / "state.json.corrupt"
    assert kept.exists() and "x.example" in kept.read_text(encoding="utf-8")
    assert not (tmp_path / "state.json").exists()


def test_missing_state_is_a_normal_first_run(tmp_path: Path, caplog) -> None:
    p = _plugin(tmp_path)
    with caplog.at_level(logging.ERROR):
        assert p._state() == {}
    assert caplog.text == ""
    assert not (tmp_path / "state.json.corrupt").exists()


def test_concurrent_writers_never_leave_an_unreadable_file(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.run_checks()
    big = [f"d{i}.example.org" for i in range(4000)]     # make each write take a while
    with p._state_lock:
        s = p._state()
        s["known_domains"] = big
        p._save(s)

    errors: list[Exception] = []

    def allow_many(prefix: str) -> None:
        try:
            for i in range(25):
                p.api_set_allow(f"{prefix}{i}.example.net", True)
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)

    def read_many() -> None:
        try:
            for _ in range(200):
                # Through the plugin, as every in-process reader does. (A raw
                # read would also be safe on POSIX, where the replace is atomic
                # under open readers; Windows refuses to replace an open file.)
                assert p._state().get("initialized") is True
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)

    threads = [threading.Thread(target=allow_many, args=(pfx,)) for pfx in "abc"]
    threads += [threading.Thread(target=read_many) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    allowed = p._state()["allowed_domains"]
    assert len(allowed) == 75                           # no lost updates
    assert not (tmp_path / "state.json.corrupt").exists()
