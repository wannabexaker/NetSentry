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
    port_scan_findings,
    rogue_dhcp_findings,
    shannon_entropy,
    suspicious_tld_findings,
)

# Many distinct high-entropy sub-domains under one parent = tunnel/DGA pattern.
RANDOM_SUBS = [
    "a1b2c3d4e5f6g7h8i9j0.exfil.evil.com",
    "z9y8x7w6v5u4t3s2r1q0.exfil.evil.com",
    "m1n2b3v4c5x6z7a8s9d0.exfil.evil.com",
    "q1w2e3r4t5y6u7i8o9p0.exfil.evil.com",
    "l1k2j3h4g5f6d7s8a9z0.exfil.evil.com",
    "p0o9i8u7y6t5r4e3w2q1.exfil.evil.com",
]


# ─── pure detectors ──────────────────────────────────────────────


def test_entropy_orders_random_above_repetitive() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a1b2c3d4e5")


def test_dns_tunnel_flags_many_random_subdomains_under_one_parent() -> None:
    findings = dns_tunnel_findings(RANDOM_SUBS + ["www.google.com"])
    subjects = {f.subject for f in findings}
    assert "evil.com" in subjects
    assert "www.google.com" not in subjects


def test_dns_tunnel_ignores_single_random_cdn_subdomain() -> None:
    # A lone random-looking but legit CDN sub-domain must not trigger.
    assert dns_tunnel_findings(["ngoktfk9nrzwb694vfcpjibjxphejx.ext-twitch.tv"]) == []


def test_dns_tunnel_ignores_deep_but_benign_domains() -> None:
    assert (
        dns_tunnel_findings(
            [
                "array509.prod.do.dsp.mp.microsoft.com",
                "de.business.smartcamera.api.io.mi.com",
            ]
        )
        == []
    )


def test_dns_tunnel_flags_very_long_fqdn() -> None:
    long = "a1b2c3" * 15 + ".evil.com"  # > 80 chars
    out = dns_tunnel_findings([long])
    assert out and out[0].subject == long


def test_dns_tunnel_respects_allow_suffixes() -> None:
    assert dns_tunnel_findings(RANDOM_SUBS, allow_suffixes=("evil.com",)) == []


def test_suspicious_tld_flags_high_abuse_tlds_only() -> None:
    out = suspicious_tld_findings(
        ["free-prize.tk", "login.xyz", "www.google.com", "api.github.io"]
    )
    subjects = {f.subject for f in out}
    assert {"free-prize.tk", "login.xyz"} <= subjects
    assert "www.google.com" not in subjects
    assert "api.github.io" not in subjects


def test_suspicious_tld_respects_allow_suffixes() -> None:
    assert suspicious_tld_findings(["ok.top"], allow_suffixes=("ok.top",)) == []


def test_new_domains_are_relative_to_baseline() -> None:
    out = new_domains(["a.com", "b.com"], baseline={"a.com"})
    assert [f.subject for f in out] == ["b.com"]


def test_rogue_dhcp_flags_servers_not_on_allowlist() -> None:
    out = rogue_dhcp_findings(
        [("192.168.1.1", "AA:BB:CC:00:00:01"), ("192.168.1.66", "DE:AD:BE:EF:00:99")],
        allowed={"192.168.1.1"},
    )
    assert [f.subject for f in out] == ["192.168.1.66"]


def test_port_scan_flags_high_fanout_source_only() -> None:
    events = [("10.0.0.5", f"10.0.0.{i}", 22) for i in range(20)]
    out = port_scan_findings(events, min_distinct_targets=15)
    assert out and out[0].subject == "10.0.0.5"
    assert port_scan_findings([("10.0.0.9", "10.0.0.1", 80)], min_distinct_targets=15) == []


def test_arp_conflict_when_one_ip_has_two_macs() -> None:
    out = arp_conflicts(
        [("192.168.1.5", "AA:BB:CC:00:00:01"), ("192.168.1.5", "AA:BB:CC:00:00:02")]
    )
    assert out and out[0].subject == "192.168.1.5"


def test_arp_mac_change_vs_baseline() -> None:
    out = arp_mac_changes(
        {"192.168.1.9": "DE:AD:BE:EF:00:02"}, {"192.168.1.9": "DE:AD:BE:EF:00:01"}
    )
    assert out and out[0].kind == "arp_change"
    assert (
        arp_mac_changes(
            {"192.168.1.9": "DE:AD:BE:EF:00:01"}, {"192.168.1.9": "DE:AD:BE:EF:00:01"}
        )
        == []
    )


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


def _dc(domains: list[str], client: str = "192.168.1.5") -> dict[str, set[str]]:
    return {d: {client} for d in domains}


def test_first_run_is_a_silent_baseline(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domain_clients = lambda: _dc(RANDOM_SUBS + ["www.google.com"])  # type: ignore[method-assign]
    p._arp_pairs = lambda: [("192.168.1.10", "AA:BB:CC:DD:EE:01")]  # type: ignore[method-assign]

    p.run_checks()

    notifier.send.assert_not_called()  # nothing fired on first run
    notifier.send_state.assert_not_called()
    assert p._state().get("initialized") is True


def test_new_anomaly_sends_one_digest_after_baseline(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domain_clients = lambda: _dc(["www.google.com"])  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p.run_checks()  # baseline

    p._recent_domain_clients = lambda: _dc(["www.google.com", *RANDOM_SUBS])  # type: ignore[method-assign]
    p.run_checks()

    # ONE consolidated message, plain text (no per-finding photo spam).
    notifier.send.assert_called_once()
    notifier.send_state.assert_not_called()
    text = notifier.send.call_args.args[0]
    assert "evil.com" in text
    assert "192.168.1.5" in text  # device attribution present


def test_threats_command_reports_on_demand(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domain_clients = lambda: _dc(RANDOM_SUBS)  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]

    p.on_command("/threats", "", 42)

    notifier.send_to.assert_called_once()
    assert "evil.com" in notifier.send_to.call_args.args[1]
