"""threat_detector — active detection over data NetSentry already sees.

Runs DNS heuristics (tunnel/DGA, newly-seen domains) over the Pi-hole FTL DB
and ARP heuristics (IP/MAC conflicts, MAC changes) over the router ARP table.
Findings go to Telegram and the append-only alerts.jsonl audit log.

First run establishes a silent baseline (no alerts) — like health_monitor —
so only genuinely new anomalies notify. `/threats` runs an on-demand scan.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from ...core import netscan
from ...core.plugin import Plugin, ScheduledTask
from . import threat_intel
from .detectors import (
    DEFAULT_ALLOW_SUFFIXES,
    DEFAULT_SUSPICIOUS_TLDS,
    Finding,
    arp_conflicts,
    arp_mac_changes,
    config_drift_findings,
    dns_tunnel_findings,
    exposure_findings,
    known_malicious_findings,
    new_domains,
    normalize_export,
    port_scan_findings,
    rogue_dhcp_findings,
    suspicious_tld_findings,
    weak_service_findings,
)

# Single source of truth for every finding type = the NetSentry taxonomy.
# Each entry carries a STABLE id (NS-XXX-NNN, cite it like a CVE), label,
# severity, detection confidence, a plain-language meaning ("means"), the
# common false-positive causes ("fp" — the anxiety-killer), what to do
# ("action"), a MITRE ATT&CK technique, and any prerequisite. Order = display.
# IDs are permanent: never renumber, only append.
_SCANS: dict[str, dict] = {
    "known_malicious": {
        "id": "NS-MAL-001", "confidence": "high", "mitre": "T1071.004",
        "label": "Known-malicious domain", "severity": "attack", "default": True,
        "means": "A domain on a downloaded malware/C2/phishing blocklist "
                 "(abuse.ch URLhaus/ThreatFox) — CONFIRMED bad, not a guess.",
        "fp": "Rare. A blocklist can occasionally flag a shared CDN/hoster. If "
              "it's a mainstream service, verify before panic; otherwise real.",
        "action": "Real threat. See who queried it (/domains <domain>), isolate/"
                  "kick that device, and scan it for malware.",
    },
    "dns_tunnel": {
        "id": "NS-DNS-001", "confidence": "medium", "mitre": "T1071.004",
        "label": "DNS tunnel / DGA", "severity": "attack", "default": True,
        "means": "A device made many random-looking sub-domain lookups under one "
                 "domain — a classic sign of data exfiltration or malware C2.",
        "fp": "The most common false alarm. Streaming/CDN/API providers (YouTube, "
              "Twitch, Netflix, Google APIs, Facebook) use many random sub-domains. "
              "If the parent is one of those, it's benign → Trust it.",
        "action": "If the device was streaming or using a known app (YouTube, "
                  "Twitch, Netflix…), it's a false alarm → tap /allow <domain>. "
                  "If you don't recognise it, check that device (/kick to cut it).",
    },
    "suspicious_tld": {
        "id": "NS-DNS-002", "confidence": "low", "mitre": "T1568",
        "label": "Suspicious TLD", "severity": "warning", "default": True,
        "means": "A lookup to a TLD frequently abused by malware/phishing "
                 "(.tk, .top, .zip, .mov…).",
        "fp": "Legit businesses do use .top/.xyz/.io/.zip. A single lookup is not "
              "proof — check the domain before acting.",
        "action": "Look up the domain. If you know it's fine → /allow <domain>. "
                  "If not, treat the device as suspect.",
    },
    "arp_conflict": {
        "id": "NS-ARP-001", "confidence": "medium", "mitre": "T1557.002",
        "label": "ARP conflict", "severity": "attack", "default": True,
        "means": "One IP is claimed by two MAC addresses — possible ARP spoofing "
                 "/ device impersonation on the LAN.",
        "fp": "A device with two interfaces (WiFi+Ethernet) on one IP, or fast "
              "DHCP-lease reuse, can trigger this. Confirm both MACs are "
              "unexpected before acting.",
        "action": "Serious. Identify both devices (/lan). If one is unexpected, "
                  "/kick or /block its MAC and power-cycle the network.",
    },
    "arp_change": {
        "id": "NS-ARP-002", "confidence": "medium", "mitre": "T1557",
        "label": "ARP / MAC change", "severity": "attack", "default": True,
        "means": "A device's IP↔MAC mapping changed since baseline — possible "
                 "man-in-the-middle, or simply a replaced device.",
        "fp": "Normal if you swapped/rebooted a device or it got a new NIC. Only "
              "worry if the IP is a gateway or a critical host.",
        "action": "If you just swapped/added a device, ignore. Otherwise "
                  "investigate that IP — possible MITM.",
    },
    "new_domain": {
        "id": "NS-DNS-003", "confidence": "info", "mitre": "-",
        "label": "New domain", "severity": "info", "default": False,
        "means": "A domain never seen on your network before. Normal while "
                 "browsing — OFF by default; turn on for an audit.",
        "fp": "Everything is 'new' the first time seen. Pure discovery — expect "
              "hundreds while browsing. Not a threat, excluded from the verdict.",
        "action": "Informational — a catalogue of what your devices fetch. Browse "
                  "with /domains, label with /note, trust noise with /allow.",
    },
    "rogue_dhcp": {
        "id": "NS-DHCP-001", "confidence": "high", "mitre": "T1557",
        "label": "Rogue DHCP server", "severity": "attack", "default": False,
        "means": "A DHCP server on your LAN other than the router — can hijack "
                 "all traffic.",
        "fp": "A second router/AP not in bridge mode, or a VM host, can answer "
              "DHCP. Confirm it isn't your own gear before unplugging.",
        "action": "Serious. Find and unplug the device at that MAC/IP — nothing "
                  "but your router should hand out addresses.",
        "needs": "router: /ip dhcp-server alert",
    },
    "port_scan": {
        "id": "NS-SCAN-001", "confidence": "medium", "mitre": "T1046",
        "label": "Port scan", "severity": "attack", "default": False,
        "means": "One source probed many hosts/ports — reconnaissance.",
        "fp": "Your own scans (this tool's exposure scan, a vuln scanner) and "
              "mDNS/UPnP discovery trigger it. Ignore if the source is you.",
        "action": "If it's a scanner you ran yourself, ignore. Otherwise the "
                  "device at that IP may be compromised — investigate / /kick.",
        "needs": "router: firewall drop-logging",
    },
    "config_drift": {
        "id": "NS-CFG-001", "confidence": "high", "mitre": "T1601",
        "label": "Router config change", "severity": "warning", "default": True,
        "means": "The router's configuration changed since the last check — a "
                 "new firewall rule, user, port-forward, or service. If it "
                 "wasn't you, the router may have been tampered with.",
        "fp": "Fires on ANY change you make yourself — a firmware update or you "
              "adding a rule. If it was you, it's fine; the new state becomes the "
              "baseline automatically.",
        "action": "Did you (or an update) change the router? If yes, ignore — "
                  "the new state becomes the baseline. If not, log in and review "
                  "the changed sections, then /backup.",
        "needs": "router: /export (read)",
    },
    "exposure": {
        "id": "NS-EXP-001", "confidence": "high", "mitre": "T1046",
        "label": "New open port", "severity": "warning", "default": False,
        "means": "A device on your LAN started listening on a TCP port it "
                 "wasn't before (e.g. an IoT gadget opened telnet after an "
                 "update) — new attack surface.",
        "fp": "A device you just installed or updated may legitimately open a new "
              "port. Check whether the change was expected for that host.",
        "action": "If you just installed/changed that device, ignore. Otherwise "
                  "investigate why it's exposing a service — it may be "
                  "compromised or misconfigured.",
        "needs": "Pi: nmap installed",
    },
    "weak_service": {
        "id": "NS-EXP-002", "confidence": "high", "mitre": "T1210",
        "label": "Weak / default-cred service", "severity": "attack", "default": False,
        "means": "A device exposes a plaintext admin service (telnet, ftp, "
                 "rlogin, VNC, RDP) or a web panel still on its DEFAULT "
                 "PASSWORD — an easy way in for anyone on the network.",
        "fp": "A device you intentionally run with telnet/VNC on a trusted LAN "
              "may be expected. A default-password hit is almost never a false "
              "alarm — change it.",
        "action": "Disable the plaintext service or put it behind the firewall; "
                  "for a default password, log in and change it immediately.",
        "needs": "Pi: nmap installed",
    },
    "deauth_flood": {
        "id": "NS-WIFI-001", "confidence": "high", "mitre": "T1498",
        "label": "WiFi deauth attack", "severity": "attack", "default": True,
        "means": "A burst of 802.11 deauthentication/disassociation frames is "
                 "kicking devices off your WiFi — jamming, or the setup for an "
                 "evil-twin / handshake-capture attack.",
        "fp": "A congested channel or a flaky AP can emit a few deauths; a "
              "sustained flood from ONE source is the real signal.",
        "action": "Someone nearby is attacking your WiFi. Note the source MAC, "
                  "look for unknown devices/people, and enable WPA3 / 802.11w "
                  "(protected management frames) on your AP.",
        "needs": "monitor-mode WiFi adapter",
    },
    "rogue_ap": {
        "id": "NS-WIFI-002", "confidence": "medium", "mitre": "T1557.004",
        "label": "Rogue AP / evil-twin", "severity": "attack", "default": True,
        "means": "One of YOUR network names (SSID) is being broadcast by an "
                 "access point that isn't yours — an evil-twin trying to lure "
                 "your devices into connecting to it.",
        "fp": "A mesh node / second AP of yours from a different vendor could "
              "trip this. If it's your gear, add its BSSID to allow_bssids.",
        "action": "Don't connect to WiFi until resolved. Locate the flagged "
                  "BSSID, and make sure your devices only trust your real AP. "
                  "WPA3 / 802.11w helps here too.",
        "needs": "monitor-mode WiFi adapter",
    },
}

# Reverse index: NS id -> kind. Built once; ids are unique and permanent.
_ID_TO_KIND: dict[str, str] = {v["id"]: k for k, v in _SCANS.items()}

_SEV_ICON = {"attack": "🚨", "warning": "⚠️", "info": "ℹ️"}


def _label(kind: str) -> str:
    return _SCANS.get(kind, {}).get("label", kind)


class ThreatDetectorPlugin(Plugin):
    COMMANDS = [
        {"command": "report", "description": "📊 Detailed report (since last report)"},
        {"command": "threats", "description": "🛡 Live scan — what's happening now"},
        {"command": "domains", "description": "📇 Domain history (/domains <search>)"},
        {"command": "note", "description": "📝 Label a domain: /note <domain> <text>"},
        {"command": "allow", "description": "✅ Trust a domain (stop alerting): /allow <domain>"},
        {"command": "deny", "description": "🚫 Un-trust a domain: /deny <domain>"},
        {"command": "threatlog", "description": "📜 Recent findings log"},
        {"command": "scans", "description": "🎛 List / turn detectors on·off"},
        {"command": "audit", "description": "🔍 Audit mode: /audit <hours> | off"},
        {"command": "intel", "description": "🧠 Threat-feed status / refresh"},
    ]

    def on_load(self) -> None:
        self._state_file = Path(self.ctx.state_dir) / "state.json"
        self._alerts_file = Path(self.ctx.state_dir) / "alerts.jsonl"
        self._journal_file = Path(self.ctx.state_dir) / "domains.json"
        self._intel_file = Path(self.ctx.state_dir) / "threat_feeds.json"
        self._interval_min = int(self.cfg.get("interval_minutes", 10))
        # Reporting: by default NOTHING is pushed on detection. Findings are
        # recorded silently; a scheduled report (report_cron) and /report / on
        # demand deliver the summary. Set immediate_attacks: true to also push
        # attack-severity findings the moment they are seen.
        self._report_cron = str(self.cfg.get("report_cron", "0 9 * * *"))
        self._immediate_attacks = bool(self.cfg.get("immediate_attacks", False))
        self._ftl_db = self.cfg.get("ftl_db_path") or "/etc/pihole/pihole-FTL.db"
        self._window_min = int(self.cfg.get("dns_window_minutes", 60))
        self._entropy_bits = float(self.cfg.get("dns_entropy_bits", 3.6))
        self._min_label_len = int(self.cfg.get("dns_min_label_len", 20))
        self._min_random_subdomains = int(self.cfg.get("dns_min_random_subdomains", 5))
        # Router config-drift + LAN exposure run on their own (slower) cadence —
        # /export and nmap are heavier than the DNS/ARP scans.
        self._drift_interval_s = int(self.cfg.get("config_drift_interval_s", 1800))
        self._exposure_interval_s = int(self.cfg.get("exposure_interval_s", 86400))
        self._nmap_bin = str(self.cfg.get("nmap_bin", "nmap"))
        self._nmap_ports = str(self.cfg.get("nmap_ports", "--top-ports 100"))
        # Subnets to actively sweep for host discovery (CIDR). Empty = only the
        # router's live ARP IPs (backward compatible). Set e.g.
        # ["192.168.1.0/24", "192.168.88.0/24"] to see the whole network.
        self._discovery_subnets = [
            str(s) for s in (self.cfg.get("discovery_subnets", []) or [])
        ]
        self._bad_tlds = tuple(
            self.cfg.get("dns_suspicious_tlds", []) or DEFAULT_SUSPICIOUS_TLDS
        )
        # Configured allow-suffixes extend (not replace) the built-in CDN list,
        # unless the operator opts out with dns_allow_defaults: false.
        configured = tuple(
            s.lower().strip(".") for s in self.cfg.get("dns_allow_suffixes", [])
        )
        base = DEFAULT_ALLOW_SUFFIXES if self.cfg.get("dns_allow_defaults", True) else ()
        self._allow_suffixes = tuple(dict.fromkeys(base + configured))
        # Digest: batch a scan's findings into ONE message instead of spamming
        # one (photo) message per finding.
        self._max_alert_lines = int(self.cfg.get("max_alert_lines", 15))
        self._max_new_examples = int(self.cfg.get("max_new_domain_examples", 8))
        self._dhcp_allowed = set(self.cfg.get("dhcp_allowed_servers", []))
        self._port_scan_min = int(self.cfg.get("port_scan_min_distinct", 15))
        # Per-scan default enabled-state (config sets the default; the operator
        # flips any scan live with /scans <key> on|off, persisted in state).
        self._scan_defaults = {
            "dns_tunnel": True,
            "suspicious_tld": True,
            "arp_conflict": bool(self.cfg.get("arp_checks", True)),
            "arp_change": bool(self.cfg.get("arp_checks", True)),
            "new_domain": bool(self.cfg.get("new_domain", False)),
            "rogue_dhcp": bool(self.cfg.get("rogue_dhcp", False)),
            "port_scan": bool(self.cfg.get("port_scan", False)),
        }

    def _enabled(self) -> dict[str, bool]:
        """Effective on/off per scan: state override → config default.

        Audit mode (see /audit) force-enables `new_domain` until it expires.
        """
        state = self._state()
        overrides = state.get("scans_enabled", {})
        result = {
            k: bool(overrides.get(k, self._scan_defaults.get(k, _SCANS[k]["default"])))
            for k in _SCANS
        }
        audit_until = state.get("audit_until")
        if audit_until and datetime.now().isoformat() < audit_until:
            result["new_domain"] = True
        return result

    def scheduled_tasks(self) -> list[ScheduledTask]:
        n = self._interval_min
        cron = f"*/{n} * * * *" if 1 <= n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [
            # Frequent, SILENT detection — records to alerts.jsonl + domains.json.
            ScheduledTask(cron=cron, func=self.run_checks, name="scan"),
            # Delivered report on a schedule (default daily 09:00).
            ScheduledTask(cron=self._report_cron, func=self.send_report, name="report"),
            # Refresh the local threat-intel blocklists (daily 04:30).
            ScheduledTask(cron="30 4 * * *", func=self.refresh_feeds, name="intel"),
        ]

    def refresh_feeds(self) -> None:
        count, ok = threat_intel.refresh(self._intel_file)
        if ok:
            self.log.info("threat_intel refreshed: %d known-bad domains", count)
        else:
            self.log.warning("threat_intel refresh failed (kept previous cache)")

    # ─── state / audit ───────────────────────────────────────────

    def _state(self) -> dict:
        try:
            return json.loads(self._state_file.read_text())
        except Exception:
            return {}

    def _save(self, s: dict) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state_file.write_text(json.dumps(s, indent=2))

    def _record_alert(self, kind: str, event: str, details: dict) -> None:
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": kind,
            "event": event,
            "details": details,
        }
        self._alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with self._alerts_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    # ─── domain journal (history + your notes) ───────────────────

    def _journal(self) -> dict:
        try:
            return json.loads(self._journal_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_journal(self, j: dict) -> None:
        # Keep the newest 15k domains by last_seen to bound the file.
        if len(j) > 15000:
            keep = sorted(j.items(), key=lambda kv: kv[1].get("last_seen", ""))[-15000:]
            j = dict(keep)
        self._journal_file.parent.mkdir(parents=True, exist_ok=True)
        self._journal_file.write_text(json.dumps(j, indent=1, sort_keys=True))

    def _update_journal(self, domain_clients: dict[str, set[str]], now_iso: str) -> dict:
        """Record first/last-seen + which client(s) asked, per domain."""
        j = self._journal()
        for dom, clients in domain_clients.items():
            entry = j.get(dom)
            if entry is None:
                j[dom] = {
                    "first_seen": now_iso, "last_seen": now_iso,
                    "clients": sorted(clients), "count": 1, "note": "",
                }
            else:
                entry["last_seen"] = now_iso
                entry["clients"] = sorted(set(entry.get("clients", [])) | clients)
                entry["count"] = int(entry.get("count", 0)) + 1
        self._save_journal(j)
        return j

    # ─── data gathering ──────────────────────────────────────────

    def _recent_domain_clients(self) -> dict[str, set[str]]:
        """Map each recently-queried domain -> the client IP(s) that asked.

        Pi-hole v6 exposes `queries` as a view that already resolves both the
        domain and the client to strings.
        """
        try:
            r = subprocess.run(
                [
                    "sqlite3",
                    "-noheader",
                    "-separator",
                    "|",
                    self._ftl_db,
                    "SELECT DISTINCT domain, client FROM queries "
                    f"WHERE timestamp > strftime('%s','now','-{self._window_min} minutes') "
                    "AND domain IS NOT NULL AND domain != '' "
                    "LIMIT 40000;",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode != 0:
                self.log.warning("FTL query failed: %s", r.stderr[-160:])
                return {}
        except Exception as exc:
            self.log.warning("FTL read failed: %s", exc)
            return {}
        mapping: dict[str, set[str]] = defaultdict(set)
        for line in r.stdout.splitlines():
            domain, _, client = line.strip().partition("|")
            domain = domain.strip().lower()
            # Skip reverse-DNS lookups and Pi-hole pseudo-entries — pure noise.
            if (
                not domain
                or domain.endswith(".arpa")
                or "." not in domain
                or any(ch in domain for ch in "*+ ")
            ):
                continue
            mapping[domain].add(client)
        return mapping

    def _recent_domains(self) -> list[str]:
        return list(self._recent_domain_clients().keys())

    def _device_names(self) -> dict[str, str]:
        """Best-effort IP -> friendly name (DHCP hostnames + Tailscale names)."""
        names: dict[str, str] = {}
        try:
            for lease in self.router.dhcp_leases() or []:
                ip = getattr(lease, "ip", "")
                host = getattr(lease, "hostname", "") or ""
                if ip and host:
                    names[ip] = host
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["tailscale", "status"], capture_output=True, text=True, timeout=4
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith("100.") and parts[0].count(".") == 3:
                        names.setdefault(parts[0], parts[1])
        except Exception:
            pass
        return names

    def _label_client(self, ip: str, names: dict[str, str]) -> str:
        name = names.get(ip)
        return f"{name} ({ip})" if name else (ip or "?")

    def _arp_pairs(self) -> list[tuple[str, str]]:
        try:
            entries = self.router.arp_table()
        except Exception as exc:
            self.log.warning("ARP read failed: %s", exc)
            return []
        pairs: list[tuple[str, str]] = []
        for e in entries or []:
            ip = getattr(e, "ip", "")
            mac = getattr(e, "mac", "")
            if ip and mac:
                pairs.append((ip, mac))
        return pairs

    def _dhcp_servers_seen(self) -> list[tuple[str, str]]:
        """DHCP servers the router flagged as UNKNOWN — as (mac, ip) pairs.

        RouterOS `/ip dhcp-server alert` (with a `valid-server` set) records a
        detected rogue in the entry's `unknown-server` field and logs it under
        topic `dhcp`. We read both; returns [] until a rogue is actually seen,
        so the check is inert on a healthy network.
        """
        servers: list[tuple[str, str]] = []
        ssh = getattr(self.router, "_ssh", None)
        if ssh is not None:
            try:
                rc, out = ssh("/ip dhcp-server alert print detail")
                if rc == 0:
                    for m in re.finditer(r"unknown-server=([0-9A-Fa-f:,]+)", out or ""):
                        for mac in m.group(1).split(","):
                            if mac.strip():
                                servers.append((mac.strip(), ""))
            except Exception:
                pass
        try:
            for line in self.router.log_tail(n=300, topic_filter="dhcp") or []:
                if "unknown dhcp server" not in line.lower():
                    continue
                mac_m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if mac_m:
                    servers.append((mac_m.group(1), ip_m.group(1) if ip_m else ""))
        except Exception:
            pass
        best: dict[str, tuple[str, str]] = {}
        for mac, ip in servers:
            key = mac.upper()
            if key not in best or (ip and not best[key][1]):
                best[key] = (mac, ip)
        return list(best.values())

    def _port_scanners(self) -> list[str]:
        """IPs the router's PSD firewall rules tagged into `port-scanners`.

        Needs the `psd` add-src-to-address-list rules on the router; returns []
        (list absent = no scans) so the check is inert until a scan is caught.
        """
        ssh = getattr(self.router, "_ssh", None)
        if ssh is None:
            return []
        try:
            rc, out = ssh(
                "/ip firewall address-list print terse where list=port-scanners"
            )
        except Exception:
            return []
        ips: list[str] = []
        if rc == 0:
            for line in (out or "").splitlines():
                for tok in line.split():
                    if tok.startswith("address="):
                        ips.append(tok.split("=", 1)[1])
        return ips

    # ─── detection run ───────────────────────────────────────────

    def _effective_allow_suffixes(self) -> tuple[str, ...]:
        """Built-in + config allow-list plus anything you added live via /allow."""
        custom = self._state().get("allowed_domains", [])
        return tuple(dict.fromkeys(self._allow_suffixes + tuple(custom)))

    def _collect(self, recent: list[str], arp_pairs: list[tuple[str, str]],
                 baseline: dict, *, relative: bool,
                 enabled: dict[str, bool]) -> list[Finding]:
        findings: list[Finding] = []
        allow = self._effective_allow_suffixes()
        if enabled.get("known_malicious"):
            feed_map, _ = threat_intel.load(self._intel_file)
            findings += known_malicious_findings(recent, feed_map)
        if enabled["dns_tunnel"]:
            findings += dns_tunnel_findings(
                recent,
                min_label_len=self._min_label_len,
                entropy_bits=self._entropy_bits,
                min_random_subdomains=self._min_random_subdomains,
                allow_suffixes=allow,
            )
        if enabled["suspicious_tld"]:
            findings += suspicious_tld_findings(
                recent, bad_tlds=self._bad_tlds, allow_suffixes=allow
            )
        if enabled["arp_conflict"]:
            findings += arp_conflicts(arp_pairs)
        if enabled["rogue_dhcp"]:
            findings += rogue_dhcp_findings(self._dhcp_servers_seen(), self._dhcp_allowed)
        if enabled["port_scan"]:
            findings += port_scan_findings(self._port_scanners())
        if relative:
            if enabled["new_domain"]:
                findings += new_domains(
                    recent,
                    set(baseline.get("known_domains", [])),
                    allow_suffixes=allow,
                )
            if enabled["arp_change"]:
                findings += arp_mac_changes(
                    {ip: mac for ip, mac in arp_pairs},
                    baseline.get("ip_mac", {}),
                )
        return findings

    def _config_drift_findings(self, state: dict) -> list[Finding]:
        """Router config tamper alarm (throttled; own baseline in state).

        First run establishes the baseline silently. Afterwards, any change vs.
        the baseline yields one finding and the new state becomes the baseline.
        """
        now = time.time()
        if now - float(state.get("drift_ts", 0)) < self._drift_interval_s:
            return []
        try:
            text = self.router.export_text()
        except Exception:
            self.log.exception("config drift: export_text failed")
            return []
        if not isinstance(text, str) or not text.strip():
            return []
        state["drift_ts"] = now
        lines = normalize_export(text)
        baseline = state.get("config_baseline")
        if baseline is None:
            state["config_baseline"] = lines
            self.log.info("config drift: baseline established (%d lines)", len(lines))
            return []
        findings = config_drift_findings(baseline, lines)
        if findings:
            state["config_baseline"] = lines  # advance so we don't re-alert
        return findings

    def _exposure_scan(self, state: dict, arp_ips: list[str]) -> dict[str, list[int]] | None:
        """Throttled active LAN scan: actively discover the configured subnets
        (nmap ping sweep), union with the router's live ARP IPs, then open-TCP
        port-scan the lot. Returns the current ``{ip: [ports]}`` map, or None
        when throttled / nothing to scan. Powers both NS-EXP-001 and NS-EXP-002.
        """
        now = time.time()
        if now - float(state.get("exposure_ts", 0)) < self._exposure_interval_s:
            return None
        hosts: set[str] = set()
        if self._discovery_subnets:
            hosts |= set(netscan.discover(
                self._discovery_subnets, timeout=300, nmap_bin=self._nmap_bin))
        hosts |= {ip for ip in arp_ips if netscan.valid_ip(ip)}
        if not hosts:
            return None
        state["exposure_ts"] = now
        current = netscan.scan_ports(
            sorted(hosts), ports_arg=self._nmap_ports, timeout=600, nmap_bin=self._nmap_bin)
        self.log.info("exposure: scanned %d hosts, %d with open ports",
                      len(hosts), len(current))
        return current

    def _exposure_diff(self, state: dict, current: dict[str, list[int]]) -> list[Finding]:
        """NS-EXP-001 — newly-open ports vs the per-host baseline (which advances)."""
        baseline = state.get("exposure_baseline")
        if baseline is None:
            state["exposure_baseline"] = current
            self.log.info("exposure: baseline established (%d hosts)", len(current))
            return []
        findings = exposure_findings(current, baseline)
        merged = {ip: sorted(set(baseline.get(ip, [])) | set(p))
                  for ip, p in {**baseline, **current}.items()}
        state["exposure_baseline"] = merged
        return findings

    def _weak_findings(self, current: dict[str, list[int]]) -> list[Finding]:
        """NS-EXP-002 — plaintext admin services + default-cred web panels."""
        banners: dict[str, str] = {}
        for ip, ports in current.items():
            if any(p in (80, 8080, 8888) for p in ports):
                body = netscan.http_probe(ip, ports)
                if body:
                    banners[ip] = body
        return weak_service_findings(current, banners)

    def _clients_for(self, f: Finding, domain_clients: dict[str, set[str]]) -> set[str]:
        """Which client IP(s) are behind a finding."""
        if f.kind in ("arp_conflict", "arp_change", "rogue_dhcp", "port_scan",
                      "exposure", "weak_service"):
            return {f.subject}  # the subject already is the offending IP
        if f.kind == "dns_tunnel":
            # subject is a parent domain; union of clients of its sub-domains
            out: set[str] = set()
            for dom, clients in domain_clients.items():
                if dom == f.subject or dom.endswith("." + f.subject):
                    out |= clients
            return out
        return set(domain_clients.get(f.subject, set()))

    def run_checks(self) -> None:
        """Silent detection cycle: record findings + domain history; never push
        by default. Delivery happens via send_report / /report / /threats."""
        state = self._state()
        enabled = self._enabled()
        first_run = not state.get("initialized")
        now_iso = datetime.now().isoformat(timespec="seconds")
        domain_clients = self._recent_domain_clients()
        recent = list(domain_clients.keys())
        arp_pairs = (
            self._arp_pairs()
            if (enabled["arp_conflict"] or enabled["arp_change"])
            else []
        )
        ip_mac_now: dict[str, str] = {}
        for ip, mac in arp_pairs:
            ip_mac_now.setdefault(ip, mac)

        # Domain history/journal — powers /domains, /report, and audit mode.
        self._update_journal(domain_clients, now_iso)

        findings = self._collect(
            recent, arp_pairs, state, relative=not first_run, enabled=enabled
        )

        # One active LAN scan feeds both exposure (NS-EXP-001) and weak-service
        # (NS-EXP-002). weak_service goes through the per-subject dedup below
        # (re-flags the same host once); exposure self-manages via its baseline.
        port_map = None
        if enabled.get("exposure") or enabled.get("weak_service"):
            port_map = self._exposure_scan(state, list(ip_mac_now.keys()))
        if port_map is not None and enabled.get("weak_service"):
            findings += self._weak_findings(port_map)

        alerted = set(state.get("alerted", []))
        fresh: list[Finding] = []
        for f in findings:
            key = f"{f.kind}:{f.subject}"
            if key in alerted:
                continue
            alerted.add(key)
            fresh.append(f)

        # Router config-drift + LAN exposure keep their own baselines and only
        # emit on change, so they bypass the per-subject 'alerted' dedup (a
        # repeat change to the same subject must re-alert). They no-op on their
        # first run (baseline set) and honour their own slow throttle.
        if enabled.get("config_drift"):
            fresh += self._config_drift_findings(state)
        if port_map is not None and enabled.get("exposure"):
            fresh += self._exposure_diff(state, port_map)

        if first_run:
            for f in fresh:
                self._record_alert(f.kind, "baseline", {"subject": f.subject})
        else:
            # Record silently to the audit log (report mode — no push here).
            for f in fresh:
                self._record_alert(
                    f.kind, "alert",
                    {"subject": f.subject, "detail": f.detail, "severity": f.severity,
                     "clients": sorted(self._clients_for(f, domain_clients))},
                )
            # Opt-in: push only genuine attacks the moment they appear.
            if self._immediate_attacks:
                urgent = [f for f in fresh if f.severity == "attack"]
                if urgent:
                    body = self._build_digest(urgent, domain_clients, self._device_names())
                    try:
                        self.notifier.send("🚨 Immediate alert\n" + body)
                    except Exception:
                        self.log.exception("immediate alert send failed")

        # Expire audit mode once its window passes.
        audit_until = state.get("audit_until")
        if audit_until and datetime.now().isoformat() >= audit_until:
            state.pop("audit_until", None)
            self.log.info("threat_detector: audit window ended")

        state["initialized"] = True
        state["known_domains"] = sorted(
            set(state.get("known_domains", []))
            | {d.lower().strip(".") for d in recent if d.strip(".")}
        )[-40000:]
        state["ip_mac"] = ip_mac_now
        state["alerted"] = sorted(alerted)[-40000:]
        self._save(state)
        if first_run:
            self.log.info(
                "threat_detector baseline established (%d domains, %d hosts)",
                len(recent), len(ip_mac_now),
            )
        elif fresh:
            self.log.info("threat_detector recorded %d finding(s) [report mode]", len(fresh))

    def _build_digest(
        self,
        findings: list[Finding],
        domain_clients: dict[str, set[str]],
        names: dict[str, str],
    ) -> str:
        """One clear, plain-text message: what happened, why it matters, who."""
        if not findings:
            return ""
        alerts = [f for f in findings if f.kind != "new_domain"]
        new = [f for f in findings if f.kind == "new_domain"]

        header_bits = []
        if alerts:
            header_bits.append(f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}")
        if new:
            header_bits.append(f"{len(new)} new domain{'s' if len(new) != 1 else ''}")
        lines = [
            "🛡 Homelab Monitor — " + (" · ".join(header_bits) or "all clear"),
            datetime.now().strftime("%Y-%m-%d %H:%M"),
        ]

        by_kind: dict[str, list[Finding]] = defaultdict(list)
        for f in alerts:
            by_kind[f.kind].append(f)
        for kind in _SCANS:  # severity/display order
            group = by_kind.get(kind)
            if not group:
                continue
            icon = _SEV_ICON.get(_SCANS[kind]["severity"], "•")
            nsid = _SCANS[kind]["id"]
            lines.append("")
            lines.append(f"{icon} {_label(kind)} ({len(group)})  [{nsid}]")
            lines.append(f"  ↳ {_SCANS[kind]['means']}")
            for f in group[: self._max_alert_lines]:
                who = ", ".join(
                    self._label_client(c, names)
                    for c in sorted(self._clients_for(f, domain_clients))[:3]
                )
                lines.append(
                    f"  • {f.subject} — {f.detail}" + (f"  ·  {who}" if who else "")
                )
            if len(group) > self._max_alert_lines:
                lines.append(f"  … +{len(group) - self._max_alert_lines} more")
            action = _SCANS[kind].get("action")
            if action:
                lines.append(f"  👉 {action}")
            link = self._explain_link(kind)
            if link:
                lines.append(f"  🔎 Explain {nsid}: {link}")

        if new:
            per_device: dict[str, int] = defaultdict(int)
            for f in new:
                for c in self._clients_for(f, domain_clients) or {"?"}:
                    per_device[c] += 1
            top = sorted(per_device.items(), key=lambda kv: kv[1], reverse=True)
            lines.append("")
            lines.append(f"ℹ️ New domains ({len(new)}) — by device:")
            for ip, count in top[:6]:
                lines.append(f"  • {self._label_client(ip, names)}: {count}")
            lines.append(
                "  e.g. " + ", ".join(f.subject for f in new[: self._max_new_examples])
            )

        lines.append("")
        lines.append("↳ /threats live · /threatlog history · /scans on·off")
        return "\n".join(lines)

    # ─── delivered report (scheduled + on demand) ────────────────

    def _alerts_since(self, since_iso: str) -> list[dict]:
        out: list[dict] = []
        try:
            for line in self._alerts_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("event") == "alert" and e.get("ts", "") >= since_iso:
                    out.append(e)
        except Exception:
            pass
        return out

    def _dashboard(self):
        """The lan_dashboard sibling plugin, for building deep-links."""
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(getattr(p, "ctx", None), "name", "") == "lan_dashboard":
                return p
        return None

    def _explain_link(self, kind: str) -> str:
        """One-click Telegram→dashboard explainer link for a finding kind."""
        dash = self._dashboard()
        nsid = _SCANS.get(kind, {}).get("id", "")
        return dash.explain_url(nsid) if (dash and nsid) else ""

    def _build_report(self, since_iso: str, title: str) -> str:
        alerts = self._alerts_since(since_iso)
        journal = self._journal()
        new_doms = [
            (d, m) for d, m in journal.items() if m.get("first_seen", "") >= since_iso
        ]
        names = self._device_names()
        by_kind: dict[str, list[dict]] = defaultdict(list)
        for e in alerts:
            by_kind[e.get("type", "")].append(e)
        real = {k: v for k, v in by_kind.items() if k != "new_domain"}
        total_alerts = sum(len(v) for v in real.values())

        lines = [f"🛡 {title}", f"since {since_iso[:16].replace('T', ' ')}", ""]

        # Verdict first — tell the operator whether anything needs them.
        if total_alerts == 0:
            lines.append("✅ Nothing needs your attention.")
        else:
            lines.append(f"⚠️ {total_alerts} item(s) to review — actions are below each one.")
        dash = self._dashboard()
        home = dash.deep_link("/threats") if dash else ""
        if home:
            lines.append(f"🔎 Open dashboard: {home}")

        # Audit context — explain a high new-domain count is expected, not scary.
        audit_until = self._state().get("audit_until")
        if audit_until and datetime.now().isoformat() < audit_until:
            lines.append(
                f"📋 Audit mode is ON (until {audit_until[:16].replace('T', ' ')}): "
                "every new domain is being *recorded*, not alerted — a high count "
                "here is expected and normal."
            )

        for kind in _SCANS:
            group = real.get(kind)
            if not group:
                continue
            icon = _SEV_ICON.get(_SCANS[kind]["severity"], "•")
            nsid = _SCANS[kind]["id"]
            lines.append(f"\n{icon} {_label(kind)} ({len(group)})  [{nsid}]")
            lines.append(f"  ↳ {_SCANS[kind]['means']}")
            for e in group[: self._max_alert_lines]:
                d = e.get("details", {})
                who = ", ".join(
                    self._label_client(c, names) for c in (d.get("clients") or [])[:3]
                )
                lines.append(
                    f"  • {d.get('subject', '')} — {d.get('detail', '')}"
                    + (f"  ·  {who}" if who else "")
                )
            action = _SCANS[kind].get("action")
            if action:
                lines.append(f"  👉 {action}")
            link = dash.explain_url(nsid) if dash else ""
            if link:
                lines.append(f"  🔎 Explain {nsid}: {link}")

        if new_doms:
            per_device: dict[str, int] = defaultdict(int)
            for _d, m in new_doms:
                for c in m.get("clients", []) or ["?"]:
                    per_device[c] += 1
            lines.append(f"\nℹ️ New domains ({len(new_doms)}) — by device:")
            for ip, count in sorted(per_device.items(), key=lambda kv: -kv[1])[:8]:
                lines.append(f"  • {self._label_client(ip, names)}: {count}")
            lines.append(
                "  e.g. " + ", ".join(d for d, _ in new_doms[: self._max_new_examples])
            )
            lines.append(
                "  ↳ These are records, not alarms. Browse /domains, label /note."
            )

        lines.append("\n── What you can do ──")
        lines.append("✅ /allow <domain>  — trust it, stop the alert (e.g. false alarms)")
        lines.append("📝 /note <domain> <text>  — label it so you remember what it is")
        lines.append("📇 /domains <search>  — full history  ·  🎛 /scans  — detectors on/off")
        return "\n".join(lines)

    def send_report(self) -> None:
        """Scheduled delivery: report since the last report, then advance."""
        state = self._state()
        since = state.get("last_report_ts") or (
            datetime.now() - timedelta(days=1)
        ).isoformat(timespec="seconds")
        report = self._build_report(since, "Homelab Monitor — periodic report")
        try:
            self.notifier.send(report)
        except Exception:
            self.log.exception("scheduled report send failed")
        state = self._state()
        state["last_report_ts"] = datetime.now().isoformat(timespec="seconds")
        self._save(state)

    # ─── public API (consumed by the web dashboard) ──────────────

    def api_domains(self) -> list[dict]:
        """The domain journal as rows for the web UI."""
        journal = self._journal()
        names = self._device_names()
        allow = self._effective_allow_suffixes()

        def is_allowed(d: str) -> bool:
            return any(d == a or d.endswith("." + a) for a in allow)

        rows = []
        for d, m in journal.items():
            rows.append({
                "domain": d,
                "first_seen": m.get("first_seen", ""),
                "last_seen": m.get("last_seen", ""),
                "count": int(m.get("count", 0)),
                "clients": [self._label_client(c, names) for c in m.get("clients", [])],
                "note": m.get("note", ""),
                "allowed": is_allowed(d),
            })
        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        return rows

    def api_set_allow(self, domain: str, on: bool) -> None:
        domain = (domain or "").strip().lower().strip(".")
        if not domain:
            return
        state = self._state()
        cur = state.get("allowed_domains", [])
        if on and domain not in cur:
            cur.append(domain)
            state["allowed_domains"] = cur
            state["alerted"] = [
                a for a in state.get("alerted", []) if not a.endswith(":" + domain)
            ]
            self._save(state)
        elif not on and domain in cur:
            cur.remove(domain)
            state["allowed_domains"] = cur
            self._save(state)

    def api_set_note(self, domain: str, text: str) -> None:
        domain = (domain or "").strip().lower().strip(".")
        if not domain:
            return
        journal = self._journal()
        entry = journal.get(domain)
        if entry is None:
            now = datetime.now().isoformat(timespec="seconds")
            entry = {"first_seen": now, "last_seen": now, "clients": [], "count": 0}
            journal[domain] = entry
        entry["note"] = (text or "")[:200]
        self._save_journal(journal)

    def api_scans(self) -> list[dict]:
        enabled = self._enabled()
        return [
            {"key": k, "id": _SCANS[k]["id"], "enabled": enabled[k],
             "label": _SCANS[k]["label"], "severity": _SCANS[k]["severity"],
             "means": _SCANS[k]["means"]}
            for k in _SCANS
        ]

    _DOMAIN_KINDS = frozenset(
        {"known_malicious", "dns_tunnel", "suspicious_tld", "new_domain"}
    )

    def api_taxonomy(self) -> list[dict]:
        """The full finding catalogue (one row per NS id), for a reference page."""
        enabled = self._enabled()
        out = []
        for k, s in _SCANS.items():
            out.append({
                "id": s["id"], "kind": k, "label": s["label"],
                "severity": s["severity"], "confidence": s.get("confidence", ""),
                "mitre": s.get("mitre", "-"), "enabled": enabled.get(k, False),
            })
        return out

    def api_explainer(self, nsid: str) -> dict | None:
        """Everything about one finding type + its recent live instances.

        Powers the Telegram deep-link target (``/finding/<id>``): what it is,
        why it matters, the common false positives, what to do, and the actual
        matches on this network right now.
        """
        kind = _ID_TO_KIND.get((nsid or "").strip().upper())
        if not kind:
            return None
        s = _SCANS[kind]
        instances = [f for f in self.api_findings(500) if f.get("type") == kind][:50]
        return {
            "id": s["id"], "kind": kind, "label": s["label"],
            "severity": s["severity"], "confidence": s.get("confidence", ""),
            "mitre": s.get("mitre", "-"),
            "means": s.get("means", ""), "fp": s.get("fp", ""),
            "action": s.get("action", ""), "needs": s.get("needs", ""),
            "enabled": self._enabled().get(kind, False),
            "domain_subject": kind in self._DOMAIN_KINDS,
            "instances": instances,
        }

    def explain_id(self, kind: str) -> str:
        """The NS id for a finding kind (empty if unknown)."""
        return _SCANS.get(kind, {}).get("id", "")

    def record_finding(self, kind: str, subject: str, detail: str, *,
                       clients: list[str] | None = None, immediate: bool = False) -> bool:
        """Ingest a finding produced by another plugin (e.g. wifi_monitor) into
        the unified pipeline: dedup by (kind, subject), record to the audit log
        so it shows in the dashboard / reports / explainer, and optionally push
        it right away with its NS id + explain deep-link. Returns True if newly
        recorded.
        """
        if kind not in _SCANS or not subject:
            return False
        if not self._enabled().get(kind, True):
            return False
        state = self._state()
        key = f"{kind}:{subject}"
        alerted = set(state.get("alerted", []))
        if key in alerted:
            return False
        alerted.add(key)
        state["alerted"] = sorted(alerted)[-40000:]
        self._save(state)
        sev = _SCANS[kind]["severity"]
        self._record_alert(kind, "alert", {
            "subject": subject, "detail": detail, "severity": sev,
            "clients": clients or [],
        })
        if immediate or self._immediate_attacks:
            nsid = _SCANS[kind]["id"]
            msg = (f"{_SEV_ICON.get(sev, '•')} {_label(kind)}  [{nsid}]\n"
                   f"  • {subject} — {detail}\n"
                   f"  👉 {_SCANS[kind].get('action', '')}")
            link = self._explain_link(kind)
            if link:
                msg += f"\n  🔎 Explain {nsid}: {link}"
            try:
                self.notifier.send(msg)
            except Exception:
                self.log.exception("record_finding push failed")
        return True

    def api_set_scan(self, key: str, on: bool) -> bool:
        if key not in _SCANS:
            return False
        state = self._state()
        overrides = state.get("scans_enabled", {})
        overrides[key] = bool(on)
        state["scans_enabled"] = overrides
        self._save(state)
        return True

    def api_intel(self) -> dict:
        feed_map, ts = threat_intel.load(self._intel_file)
        return {"count": len(feed_map), "updated": ts}

    def api_findings(self, limit: int = 50) -> list[dict]:
        out = []
        for e in self._alerts_since("")[-limit:][::-1]:
            d = e.get("details", {})
            kind = e.get("type", "")
            out.append({
                "ts": e.get("ts", ""), "type": kind,
                "id": _SCANS.get(kind, {}).get("id", ""),
                "label": _label(kind), "severity": d.get("severity", ""),
                "subject": d.get("subject", ""), "detail": d.get("detail", ""),
                "clients": d.get("clients", []),
            })
        return out

    def api_recent_findings(self, warn_hours: int = 24, attack_hours: int = 168) -> list[dict]:
        """Findings relevant *now* for the at-a-glance verdict.

        Filters the accumulated ``alerts.jsonl`` audit history down to what a
        human should actually act on, so the banner is not permanently pinned:

        * ``new_domain`` is dropped — that is domain *discovery*, already shown
          in the Threats domain table; it is not a threat verdict input.
        * subjects the operator has trusted (allow-list) are dropped.
        * attack-severity is kept for ``attack_hours`` (default 7d), everything
          else for ``warn_hours`` (default 24h).
        """
        now = datetime.now()
        warn_cut = now - timedelta(hours=warn_hours)
        attack_cut = now - timedelta(hours=attack_hours)
        allow = self._effective_allow_suffixes()

        def is_trusted(subject: str) -> bool:
            s = (subject or "").lower().strip(".")
            return any(s == a or s.endswith("." + a) for a in allow)

        out: list[dict] = []
        for f in self.api_findings(500):
            if f.get("type") == "new_domain" or is_trusted(f.get("subject", "")):
                continue
            try:
                when = datetime.fromisoformat(f.get("ts", ""))
            except ValueError:
                continue
            cut = attack_cut if f.get("severity") == "attack" else warn_cut
            if when >= cut:
                out.append(f)
        return out

    # ─── on-demand ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/threats":
            self._cmd_threats(chat_id)
        elif command == "/scans":
            self._cmd_scans(chat_id, args)
        elif command == "/threatlog":
            self._cmd_threatlog(chat_id, args)
        elif command == "/report":
            self._cmd_report(chat_id)
        elif command == "/domains":
            self._cmd_domains(chat_id, args)
        elif command == "/note":
            self._cmd_note(chat_id, args)
        elif command == "/audit":
            self._cmd_audit(chat_id, args)
        elif command == "/allow":
            self._cmd_allow(chat_id, args)
        elif command == "/deny":
            self._cmd_deny(chat_id, args)
        elif command == "/intel":
            self._cmd_intel(chat_id, args)

    def _cmd_intel(self, chat_id: int, args: str) -> None:
        if args.strip().lower() in ("refresh", "update", "sync"):
            self.notifier.send_to(chat_id, "⏳ Refreshing threat feeds…")
            count, ok = threat_intel.refresh(self._intel_file)
            self.notifier.send_to(
                chat_id,
                f"🧠 Feeds {'updated' if ok else 'refresh FAILED (kept old cache)'}: "
                f"{count} known-bad domains.",
            )
            return
        feed_map, ts = threat_intel.load(self._intel_file)
        when = ts[:16].replace("T", " ") if ts else "never (run /intel refresh)"
        self.notifier.send_to(
            chat_id,
            f"🧠 Local threat intel (abuse.ch URLhaus + ThreatFox)\n"
            f"{len(feed_map)} known-bad domains · updated {when}\n"
            "Every check runs on-device — your domains never leave the network.\n"
            "↳ /intel refresh to update now.",
        )

    def _cmd_allow(self, chat_id: int, args: str) -> None:
        domain = args.strip().lower().strip(".")
        if not domain:
            current = self._state().get("allowed_domains", [])
            listed = "\n".join(f"  • {d}" for d in current) or "  (none yet)"
            self.notifier.send_to(
                chat_id,
                "✅ Trusted domains you added:\n" + listed
                + "\n↳ /allow <domain> to add, /deny <domain> to remove.",
            )
            return
        self.api_set_allow(domain, True)
        self.notifier.send_to(
            chat_id,
            f"✅ Trusting {domain} (and its sub-domains) — it won't be flagged again.",
        )

    def _cmd_deny(self, chat_id: int, args: str) -> None:
        domain = args.strip().lower().strip(".")
        if domain in self._state().get("allowed_domains", []):
            self.api_set_allow(domain, False)
            self.notifier.send_to(chat_id, f"🚫 No longer trusting {domain}.")
        else:
            self.notifier.send_to(chat_id, f"'{domain}' wasn't in your trusted list.")

    def _cmd_report(self, chat_id: int) -> None:
        since = self._state().get("last_report_ts") or (
            datetime.now() - timedelta(days=1)
        ).isoformat(timespec="seconds")
        self.notifier.send_to(
            chat_id, self._build_report(since, "Homelab Monitor — report")
        )

    def _cmd_domains(self, chat_id: int, args: str) -> None:
        journal = self._journal()
        query = args.strip().lower()
        items = [
            (d, m) for d, m in journal.items()
            if not query or query in d or query in (m.get("note", "").lower())
        ]
        if not items:
            self.notifier.send_to(
                chat_id,
                "📇 No domains recorded yet."
                if not journal else f"📇 No domains match '{query}'.",
            )
            return
        items.sort(key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
        names = self._device_names()
        lines = [f"📇 Domains ({len(items)}" + (f" matching '{query}'" if query else "") + "):"]
        for d, m in items[:40]:
            first = m.get("first_seen", "")[:10]
            who = ", ".join(self._label_client(c, names) for c in (m.get("clients") or [])[:2])
            note = f"  📝 {m['note']}" if m.get("note") else ""
            lines.append(f"• {d}  (first {first}, ×{m.get('count', 0)}) {who}{note}")
        if len(items) > 40:
            lines.append(f"… +{len(items) - 40} more — refine with /domains <text>")
        lines.append("\n↳ /note <domain> <your label> to annotate")
        self.notifier.send_to(chat_id, "\n".join(lines))

    def _cmd_note(self, chat_id: int, args: str) -> None:
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            self.notifier.send_to(chat_id, "Usage: /note <domain> <label/note>")
            return
        domain, note = parts[0].strip().lower(), parts[1].strip()
        journal = self._journal()
        entry = journal.get(domain)
        if entry is None:
            # allow annotating even if not yet auto-recorded
            now = datetime.now().isoformat(timespec="seconds")
            entry = {"first_seen": now, "last_seen": now, "clients": [], "count": 0}
            journal[domain] = entry
        entry["note"] = note[:200]
        self._save_journal(journal)
        self.notifier.send_to(chat_id, f"📝 Noted: {domain} → {note[:200]}")

    def _cmd_audit(self, chat_id: int, args: str) -> None:
        a = args.strip().lower()
        state = self._state()
        if a in ("off", "stop", "0"):
            state.pop("audit_until", None)
            self._save(state)
            self.notifier.send_to(
                chat_id, "🔍 Audit mode off — new_domain back to its normal setting."
            )
            return
        try:
            hours = float(a) if a else 24.0
        except ValueError:
            hours = 24.0
        until = (datetime.now() + timedelta(hours=hours)).isoformat(timespec="seconds")
        state["audit_until"] = until
        self._save(state)
        self.notifier.send_to(
            chat_id,
            f"🔍 Audit mode ON for {hours:g}h — recording every new domain per "
            f"device (silent). Ends {until[:16].replace('T', ' ')}.\n"
            "Review anytime with /domains or /report.",
        )

    def _cmd_threats(self, chat_id: int) -> None:
        enabled = self._enabled()
        domain_clients = self._recent_domain_clients()
        recent = list(domain_clients.keys())
        arp_pairs = (
            self._arp_pairs()
            if (enabled["arp_conflict"] or enabled["arp_change"])
            else []
        )
        findings = self._collect(
            recent, arp_pairs, self._state(), relative=True, enabled=enabled
        )
        if not findings:
            on_count = sum(1 for v in enabled.values() if v)
            self.notifier.send_to(
                chat_id,
                f"🛡 All clear — no findings in the last {self._window_min}m "
                f"({on_count} detector(s) on, {len(recent)} domains seen).\n"
                "↳ /scans to see or change what's monitored.",
            )
            return
        names = self._device_names()
        self.notifier.send_to(
            chat_id, self._build_digest(findings, domain_clients, names)
        )

    def _cmd_scans(self, chat_id: int, args: str) -> None:
        parts = args.split()
        if len(parts) >= 2 and parts[1].lower() in ("on", "off"):
            key, want = parts[0].lower(), parts[1].lower() == "on"
            if key not in _SCANS:
                self.notifier.send_to(
                    chat_id, f"❓ Unknown scan '{key}'. Send /scans to list them."
                )
                return
            state = self._state()
            overrides = state.get("scans_enabled", {})
            overrides[key] = want
            state["scans_enabled"] = overrides
            self._save(state)
            self.notifier.send_to(
                chat_id,
                f"{'✅ Enabled' if want else '❌ Disabled'}: {_label(key)}",
            )
            return
        enabled = self._enabled()
        lines = ["🎛 Detectors  —  /scans <key> on|off"]
        for key, meta in _SCANS.items():
            mark = "✅" if enabled[key] else "❌"
            needs = f"  ⚙️ needs {meta['needs']}" if meta.get("needs") else ""
            lines.append(f"\n{mark} {key}  ({meta['severity']}){needs}")
            lines.append(f"   {meta['means']}")
        self.notifier.send_to(chat_id, "\n".join(lines))

    def _cmd_threatlog(self, chat_id: int, args: str) -> None:
        try:
            n = min(50, max(1, int(args.strip()))) if args.strip() else 15
        except ValueError:
            n = 15
        try:
            raw = self._alerts_file.read_text(encoding="utf-8").splitlines()
        except Exception:
            raw = []
        alerts = []
        for line in raw[-500:]:
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event") == "alert":
                alerts.append(e)
        if not alerts:
            self.notifier.send_to(
                chat_id, "📜 No findings recorded yet — all quiet so far."
            )
            return
        lines = [f"📜 Last {min(n, len(alerts))} findings (newest first):"]
        for e in alerts[-n:][::-1]:
            d = e.get("details", {})
            icon = _SEV_ICON.get(d.get("severity", ""), "•")
            ts = e.get("ts", "")[:16].replace("T", " ")
            clients = ", ".join(d.get("clients", []) or [])
            who = f"  ·  {clients}" if clients else ""
            lines.append(
                f"{icon} {ts}  {_label(e.get('type', ''))}: {d.get('subject', '')}{who}"
            )
        self.notifier.send_to(chat_id, "\n".join(lines))
