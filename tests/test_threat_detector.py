from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import Mock

from netsentry.core.plugin import PluginContext
from netsentry.plugins.threat_detector import ThreatDetectorPlugin
from netsentry.plugins.threat_detector.detectors import (
    arp_conflicts,
    arp_mac_changes,
    dns_tunnel_findings,
    new_domains,
    shannon_entropy,
)

TUNNEL = "a1b2c3d4e5f6g7h8i9j0.exfil.evil.com"  # long, high-entropy label


# ─── pure detectors ──────────────────────────────────────────────


def test_entropy_orders_random_above_repetitive() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a1b2c3d4e5")


def test_dns_tunnel_flags_high_entropy_label_only() -> None:
    findings = dns_tunnel_findings([TUNNEL, "www.google.com", "api.github.com"])
    subjects = {f.subject for f in findings}
    assert TUNNEL in subjects
    assert "www.google.com" not in subjects
    assert "api.github.com" not in subjects


def test_dns_tunnel_flags_excessive_depth() -> None:
    findings = dns_tunnel_findings(["a.b.c.d.e.f.g.h.example.com"])
    assert findings and findings[0].kind == "dns_tunnel"


def test_dns_tunnel_respects_allow_suffixes() -> None:
    assert dns_tunnel_findings([TUNNEL], allow_suffixes=("evil.com",)) == []


def test_new_domains_are_relative_to_baseline() -> None:
    out = new_domains(["a.com", "b.com"], baseline={"a.com"})
    assert [f.subject for f in out] == ["b.com"]


def test_arp_conflict_when_one_ip_has_two_macs() -> None:
    out = arp_conflicts(
        [("192.168.1.5", "AA:BB:CC:00:00:01"), ("192.168.1.5", "AA:BB:CC:00:00:02")]
    )
    assert out and out[0].subject == "192.168.1.5"


def test_arp_mac_change_vs_baseline() -> None:
    out = arp_mac_changes({"192.168.1.9": "DE:AD:BE:EF:00:02"}, {"192.168.1.9": "DE:AD:BE:EF:00:01"})
    assert out and out[0].kind == "arp_change"
    # unchanged host produces nothing
    assert arp_mac_changes({"192.168.1.9": "DE:AD:BE:EF:00:01"}, {"192.168.1.9": "DE:AD:BE:EF:00:01"}) == []


# ─── plugin behaviour ────────────────────────────────────────────


def _plugin(tmp_path: Path, notifier: Mock) -> ThreatDetectorPlugin:
    ctx = PluginContext(
        name="threat_detector",
        config={},
        router=Mock(),
        notifier=notifier,
        vault=Mock(),
        logger=logging.getLogger("test.threat"),
        state_dir=str(tmp_path),
    )
    plugin = ThreatDetectorPlugin(ctx)
    plugin.on_load()
    return plugin


def test_first_run_is_a_silent_baseline(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domains = lambda: [TUNNEL, "www.google.com"]  # type: ignore[method-assign]
    p._arp_pairs = lambda: [("192.168.1.10", "AA:BB:CC:DD:EE:01")]  # type: ignore[method-assign]

    p.run_checks()

    notifier.send_state.assert_not_called()  # nothing fired on first run
    assert p._state().get("initialized") is True


def test_new_anomaly_alerts_after_baseline(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domains = lambda: ["www.google.com"]  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p.run_checks()  # baseline

    p._recent_domains = lambda: ["www.google.com", TUNNEL]  # type: ignore[method-assign]
    p.run_checks()

    assert notifier.send_state.called
    texts = [c.args[1] for c in notifier.send_state.call_args_list]
    assert any(TUNNEL in t for t in texts)


def test_threats_command_reports_on_demand(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domains = lambda: [TUNNEL]  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]

    p.on_command("/threats", "", 42)

    notifier.send_to.assert_called_once()
    assert TUNNEL in notifier.send_to.call_args.args[1]
