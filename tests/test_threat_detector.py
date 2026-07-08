from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

from netsentry.core.plugin import PluginContext
from netsentry.plugins.threat_detector import ThreatDetectorPlugin
from netsentry.plugins.threat_detector import threat_intel
from netsentry.plugins.threat_detector.detectors import (
    DEFAULT_ALLOW_SUFFIXES,
    arp_conflicts,
    arp_mac_changes,
    config_drift_findings,
    dns_tunnel_findings,
    exposure_findings,
    known_malicious_findings,
    new_domains,
    normalize_export,
    parse_nmap_grepable,
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


# ─── config drift + exposure (pure) ──────────────────────────────

def test_normalize_export_drops_header_and_blanks() -> None:
    raw = (
        "# 2026-07-03 12:00:00 by RouterOS 7.22.1\n"
        "# software id = ABCD-1234\n"
        "\n"
        "/ip firewall filter add chain=input action=drop\n"
        "  /ip service set www disabled=yes\n"
    )
    assert normalize_export(raw) == [
        "/ip firewall filter add chain=input action=drop",
        "/ip service set www disabled=yes",
    ]


def test_config_drift_findings_reports_change_with_sections() -> None:
    old = ["/ip firewall filter add chain=input action=accept",
           "/user add name=admin group=full"]
    new = ["/ip firewall filter add chain=input action=accept",
           "/ip firewall nat add chain=srcnat action=masquerade"]
    out = config_drift_findings(old, new)
    assert len(out) == 1
    assert out[0].kind == "config_drift"
    assert out[0].severity == "warning"
    assert "/ip firewall nat" in out[0].detail  # added section
    assert "/user" in out[0].detail             # removed section


def test_config_drift_findings_empty_when_unchanged() -> None:
    same = ["/ip service set www disabled=yes"]
    assert config_drift_findings(same, list(same)) == []


def test_parse_nmap_grepable() -> None:
    out = "\n".join([
        "# Nmap 7.94 scan",
        "Host: 192.168.1.10 ()\tStatus: Up",
        "Host: 192.168.1.10 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\tIgnored State: closed (98)",
        "Host: 192.168.1.20 ()\tPorts: 443/open/tcp//https///",
    ])
    assert parse_nmap_grepable(out) == {
        "192.168.1.10": [22, 80],
        "192.168.1.20": [443],
    }


def test_exposure_findings_flags_only_new_ports() -> None:
    current = {"192.168.1.10": [22, 23, 80], "192.168.1.20": [443]}
    baseline = {"192.168.1.10": [22, 80], "192.168.1.20": [443]}
    out = exposure_findings(current, baseline)
    assert len(out) == 1
    assert out[0].kind == "exposure"
    assert out[0].subject == "192.168.1.10"
    assert "23" in out[0].detail


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


def test_known_malicious_flags_domains_on_feed_incl_parents() -> None:
    feed = {"evil.com": "URLhaus", "bad-c2.net": "ThreatFox"}
    out = known_malicious_findings(
        ["sub.evil.com", "www.google.com", "bad-c2.net"], feed
    )
    subjects = {f.subject for f in out}
    assert subjects == {"sub.evil.com", "bad-c2.net"}  # parent match + exact
    assert all(f.kind == "known_malicious" and f.severity == "attack" for f in out)
    assert known_malicious_findings(["sub.evil.com"], {}) == []  # no feed → nothing


def test_threat_intel_hostfile_parsing() -> None:
    sample = (
        "# comment line\n"
        "0.0.0.0 malware-drop.example\n"
        "0.0.0.0 c2.bad.net\n"
        "127.0.0.1 localhost\n"
        "\n"
        "plain-domain.evil\n"
    )
    got = threat_intel._parse_hostfile(sample)
    assert got == {"malware-drop.example", "c2.bad.net", "plain-domain.evil"}


def test_rogue_dhcp_flags_servers_not_on_allowlist() -> None:
    # (mac, ip); the router's own server MAC is allow-listed, the rogue is not.
    out = rogue_dhcp_findings(
        [("AA:BB:CC:00:00:01", "192.168.1.1"), ("DE:AD:BE:EF:00:99", "192.168.1.66")],
        allowed={"AA:BB:CC:00:00:01"},
    )
    assert [f.subject for f in out] == ["192.168.1.66"]


def test_port_scan_flags_each_scanner_once() -> None:
    # scanner IPs come from the router's PSD address-list
    out = port_scan_findings(["192.168.1.50", "192.168.1.50", "10.0.0.9"])
    assert [f.subject for f in out] == ["192.168.1.50", "10.0.0.9"]
    assert all(f.kind == "port_scan" for f in out)
    assert port_scan_findings([]) == []


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


def test_config_drift_grace_absorbs_expected_rotation(tmp_path: Path) -> None:
    # The weekly guest-WiFi rotation changes the router on purpose; its own
    # change must not trip the NS-CFG-001 tamper alarm, but real drift still must.
    p = _plugin(tmp_path, Mock())
    cfg_a = "/interface bridge add name=bridge\n/ip service set www disabled=yes"
    cfg_b = cfg_a + "\n/interface bridge filter add chain=forward action=drop in-interface=wifi3"
    cfg_c = cfg_b + "\n/interface bridge port add bridge=bridge interface=wifi3"
    cfg_d = cfg_c + "\n/ip firewall nat add chain=srcnat action=masquerade"
    st: dict = {}

    p.router.export_text = Mock(return_value=cfg_a)
    assert p._config_drift_findings(st) == []                 # first run = silent baseline

    st["drift_ts"] = 0                                         # bypass the throttle
    p.router.export_text = Mock(return_value=cfg_b)
    assert len(p._config_drift_findings(st)) == 1             # unexpected change -> alarm

    st["drift_ts"] = 0
    p._on_expected_config_change({"profile": "guest"})        # rotation event opens grace
    p.router.export_text = Mock(return_value=cfg_c)
    assert p._config_drift_findings(st) == []                 # absorbed, no alarm

    st["drift_ts"] = 0
    p._config_grace_until = 0.0                               # window over
    p.router.export_text = Mock(return_value=cfg_d)
    assert len(p._config_drift_findings(st)) == 1             # drift alarms again


def test_detection_is_silent_and_reported_on_demand(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: _dc(["www.google.com"])  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p.run_checks()  # baseline

    p._recent_domain_clients = lambda: _dc(["www.google.com", *RANDOM_SUBS])  # type: ignore[method-assign]
    p.run_checks()

    # report mode: nothing is pushed on detection
    notifier.send.assert_not_called()
    notifier.send_state.assert_not_called()

    # but the finding is recorded and /report delivers it, with attribution
    p.on_command("/report", "", 42)
    text = notifier.send_to.call_args.args[1]
    assert "evil.com" in text
    assert "192.168.1.5" in text


def test_immediate_attacks_opt_in_pushes_attacks(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._immediate_attacks = True  # opt in
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: _dc(["www.google.com"])  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p.run_checks()  # baseline
    p._recent_domain_clients = lambda: _dc(["www.google.com", *RANDOM_SUBS])  # type: ignore[method-assign]
    p.run_checks()
    assert notifier.send.called  # attack pushed immediately when opted in


def test_audit_mode_forces_new_domain_then_expires(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p.on_command("/audit", "24", 42)
    assert p._enabled()["new_domain"] is True
    p.on_command("/audit", "off", 42)
    assert p._enabled()["new_domain"] is False


def test_domain_journal_records_history_and_notes(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: _dc(["shop.example.com"], client="192.168.1.7")  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p.run_checks()  # records the domain in the journal

    p.on_command("/note", "shop.example.com my webshop", 42)
    p.on_command("/domains", "", 42)
    text = notifier.send_to.call_args.args[1]
    assert "shop.example.com" in text
    assert "my webshop" in text
    assert "192.168.1.7" in text


def test_threats_command_reports_on_demand(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._recent_domain_clients = lambda: _dc(RANDOM_SUBS)  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p._device_names = lambda: {}  # type: ignore[method-assign]

    p.on_command("/threats", "", 42)

    notifier.send_to.assert_called_once()
    assert "evil.com" in notifier.send_to.call_args.args[1]


# ─── operator control (scans / log) ──────────────────────────────


def test_new_domain_scan_is_off_by_default(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    assert p._enabled()["new_domain"] is False
    assert p._enabled()["dns_tunnel"] is True


def test_scans_list_shows_every_detector(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p.on_command("/scans", "", 42)
    text = notifier.send_to.call_args.args[1]
    for key in (
        "dns_tunnel", "suspicious_tld", "new_domain", "arp_conflict",
        "arp_change", "rogue_dhcp", "port_scan",
    ):
        assert key in text


def test_scans_toggle_persists_and_disables_detector(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: _dc(RANDOM_SUBS)  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]

    p.on_command("/scans", "dns_tunnel off", 42)
    assert p._enabled()["dns_tunnel"] is False

    notifier.reset_mock()
    p.on_command("/threats", "", 42)
    text = notifier.send_to.call_args.args[1]
    assert "evil.com" not in text  # the disabled detector produced nothing
    assert "clear" in text.lower()


def test_scans_toggle_rejects_unknown_key(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p.on_command("/scans", "bogus on", 42)
    assert "Unknown" in notifier.send_to.call_args.args[1]


def test_streaming_cdn_not_flagged_as_tunnel() -> None:
    # YouTube CDN: many random per-server sub-domains — must NOT be a false alarm.
    subs = [f"rr{i}---sn-ab{i}cdxyz.googlevideo.com" for i in range(8)]
    assert dns_tunnel_findings(subs, allow_suffixes=DEFAULT_ALLOW_SUFFIXES) == []


def test_allow_command_trusts_domain_and_suppresses_it(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: _dc(RANDOM_SUBS)  # under evil.com  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]

    p.on_command("/allow", "evil.com", 42)
    assert "evil.com" in p._effective_allow_suffixes()

    notifier.reset_mock()
    p.on_command("/threats", "", 42)
    text = notifier.send_to.call_args.args[1]
    assert "evil.com" not in text  # now trusted → not flagged


def test_deny_removes_a_trusted_domain(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    p.on_command("/allow", "example.com", 42)
    assert "example.com" in p._effective_allow_suffixes()
    p.on_command("/deny", "example.com", 42)
    assert "example.com" not in p._effective_allow_suffixes()


def test_api_domains_allow_and_note(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: _dc(["shop.example.com"], client="192.168.1.7")  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]
    p.run_checks()  # populate the journal

    rows = p.api_domains()
    assert any(r["domain"] == "shop.example.com" for r in rows)

    p.api_set_allow("shop.example.com", True)
    p.api_set_note("shop.example.com", "my shop")
    row = next(r for r in p.api_domains() if r["domain"] == "shop.example.com")
    assert row["note"] == "my shop"
    assert row["allowed"] is True

    p.api_set_allow("shop.example.com", False)
    assert "shop.example.com" not in p._effective_allow_suffixes()


def test_taxonomy_ids_unique_and_indexed() -> None:
    from netsentry.plugins.threat_detector import _ID_TO_KIND, _SCANS
    ids = [v["id"] for v in _SCANS.values()]
    assert all(i.startswith("NS-") for i in ids)
    assert len(ids) == len(set(ids))                 # every id unique
    assert _ID_TO_KIND["NS-DNS-001"] == "dns_tunnel"
    for v in _SCANS.values():                         # every entry is explainable
        assert v["fp"] and v["means"] and v["action"]


def test_api_explainer_and_taxonomy(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    assert p.explain_id("dns_tunnel") == "NS-DNS-001"

    ex = p.api_explainer("ns-dns-001")               # case-insensitive lookup
    assert ex["kind"] == "dns_tunnel"
    assert ex["fp"]                                   # false-positive guidance present
    assert ex["domain_subject"] is True
    assert isinstance(ex["instances"], list)

    assert p.api_explainer("NS-BOGUS-999") is None
    tax = p.api_taxonomy()
    assert {t["id"] for t in tax} >= {"NS-MAL-001", "NS-CFG-001", "NS-EXP-001"}


def test_record_finding_ingests_and_dedups(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    # A wifi_monitor-style ingestion: recorded once, then deduped by subject.
    assert p.record_finding("rogue_ap", "de:ad:be:ef:00:01", "evil twin", immediate=True) is True
    assert p.record_finding("rogue_ap", "de:ad:be:ef:00:01", "evil twin", immediate=True) is False
    assert p.record_finding("bogus_kind", "x", "y") is False

    kinds = [f["type"] for f in p.api_findings(50)]
    assert "rogue_ap" in kinds
    # immediate=True pushed it, with the NS id in the message.
    assert notifier.send.called
    assert "NS-WIFI-002" in notifier.send.call_args.args[0]


def test_config_drift_alerts_on_router_change(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    p._drift_interval_s = 0  # no throttle in the test
    p._device_names = lambda: {}  # type: ignore[method-assign]
    p._recent_domain_clients = lambda: {}  # type: ignore[method-assign]
    p._arp_pairs = lambda: []  # type: ignore[method-assign]

    p.router.export_text.return_value = "# hdr\n/ip service set www disabled=yes\n"
    p.run_checks()  # first run establishes the drift baseline silently

    p.router.export_text.return_value = (
        "# hdr\n/ip service set www disabled=yes\n/user add name=x group=full\n"
    )
    p.run_checks()  # config changed → should record a drift finding

    kinds = [f["type"] for f in p.api_findings(50)]
    assert "config_drift" in kinds


def test_api_recent_findings_windows_by_severity_and_age(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    now = datetime.now()

    def iso(hours_ago: float) -> str:
        return (now - timedelta(hours=hours_ago)).isoformat(timespec="seconds")

    rows = [
        {"ts": iso(1),   "severity": "info",    "subject": "fresh-info",     "type": "suspicious_tld"},
        {"ts": iso(48),  "severity": "info",    "subject": "old-info",       "type": "suspicious_tld"},   # >24h → out
        {"ts": iso(2),   "severity": "warning", "subject": "fresh-warn",     "type": "suspicious_tld"},
        {"ts": iso(100), "severity": "attack",  "subject": "recent-attack",  "type": "dns_tunnel"},       # <7d → in
        {"ts": iso(200), "severity": "attack",  "subject": "old-attack",     "type": "dns_tunnel"},       # >7d → out
        {"ts": "",       "severity": "info",    "subject": "no-ts",          "type": "suspicious_tld"},   # unparseable → out
        {"ts": iso(1),   "severity": "warning", "subject": "shop.example.com", "type": "new_domain"},     # discovery → out
        {"ts": iso(1),   "severity": "attack",  "subject": "x.googlevideo.com", "type": "dns_tunnel"},    # trusted CDN → out
    ]
    p.api_findings = lambda limit=50: rows  # type: ignore[method-assign,assignment]

    subs = {f["subject"] for f in p.api_recent_findings()}
    assert subs == {"fresh-info", "fresh-warn", "recent-attack"}


def test_api_scan_toggle_and_intel(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    assert p.api_set_scan("dns_tunnel", False) is True
    assert not next(s for s in p.api_scans() if s["key"] == "dns_tunnel")["enabled"]
    assert p.api_set_scan("bogus", True) is False
    assert "count" in p.api_intel()


def test_threatlog_reads_recorded_findings(tmp_path: Path) -> None:
    notifier = Mock()
    p = _plugin(tmp_path, notifier)
    p._record_alert(
        "dns_tunnel", "alert",
        {"subject": "evil.com", "detail": "x", "severity": "attack",
         "clients": ["192.168.1.5"]},
    )
    p.on_command("/threatlog", "", 42)
    text = notifier.send_to.call_args.args[1]
    assert "evil.com" in text and "192.168.1.5" in text
