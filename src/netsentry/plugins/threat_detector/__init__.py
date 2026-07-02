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
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from ...core.plugin import Plugin, ScheduledTask
from .detectors import (
    DEFAULT_ALLOW_SUFFIXES,
    DEFAULT_SUSPICIOUS_TLDS,
    Finding,
    arp_conflicts,
    arp_mac_changes,
    dns_tunnel_findings,
    new_domains,
    port_scan_findings,
    rogue_dhcp_findings,
    suspicious_tld_findings,
)

_KIND_LABELS = {
    "dns_tunnel": "DNS tunnel/DGA",
    "suspicious_tld": "Suspicious TLD",
    "new_domain": "New domain",
    "arp_conflict": "ARP conflict",
    "arp_change": "ARP/MAC change",
    "rogue_dhcp": "Rogue DHCP server",
    "port_scan": "Port scan",
}


class ThreatDetectorPlugin(Plugin):
    COMMANDS = [
        {"command": "threats", "description": "🛡 Run a threat scan now"},
    ]

    def on_load(self) -> None:
        self._state_file = Path(self.ctx.state_dir) / "state.json"
        self._alerts_file = Path(self.ctx.state_dir) / "alerts.jsonl"
        self._interval_min = int(self.cfg.get("interval_minutes", 10))
        self._ftl_db = self.cfg.get("ftl_db_path") or "/etc/pihole/pihole-FTL.db"
        self._window_min = int(self.cfg.get("dns_window_minutes", 60))
        self._entropy_bits = float(self.cfg.get("dns_entropy_bits", 3.6))
        self._min_label_len = int(self.cfg.get("dns_min_label_len", 20))
        self._min_random_subdomains = int(self.cfg.get("dns_min_random_subdomains", 5))
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
        self._arp_enabled = bool(self.cfg.get("arp_checks", True))
        # Digest: batch a scan's findings into ONE message instead of spamming
        # one (photo) message per finding.
        self._max_alert_lines = int(self.cfg.get("max_alert_lines", 15))
        self._max_new_examples = int(self.cfg.get("max_new_domain_examples", 8))
        # Network detectors that need a router feature enabled first, so they
        # are opt-in (off by default). See docs/PLUGINS.md.
        self._rogue_dhcp = bool(self.cfg.get("rogue_dhcp", False))
        self._dhcp_allowed = set(self.cfg.get("dhcp_allowed_servers", []))
        self._port_scan = bool(self.cfg.get("port_scan", False))
        self._port_scan_min = int(self.cfg.get("port_scan_min_distinct", 15))

    def scheduled_tasks(self) -> list[ScheduledTask]:
        n = self._interval_min
        cron = f"*/{n} * * * *" if 1 <= n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [ScheduledTask(cron=cron, func=self.run_checks, name="scan")]

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
        if not self._arp_enabled:
            return []
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
        """Best-effort read of DHCP servers the router flagged as unknown.

        Needs `/ip dhcp-server alert` configured on the router; returns [] if
        unavailable, so the check stays inert until the operator enables it.
        """
        ssh = getattr(self.router, "_ssh", None)
        if ssh is None:
            return []
        try:
            _rc, out = ssh("/ip dhcp-server alert print terse")
        except Exception:
            return []
        servers: list[tuple[str, str]] = []
        for line in (out or "").splitlines():
            ip = mac = ""
            for tok in line.split():
                if tok.startswith("address="):
                    ip = tok.split("=", 1)[1]
                elif tok.startswith("mac-address="):
                    mac = tok.split("=", 1)[1]
            if ip:
                servers.append((ip, mac))
        return servers

    def _scan_events(self) -> list[tuple[str, str, int]]:
        """Best-effort parse of firewall drop logs into (src_ip, dst_ip, dport).

        Needs the router's drop rules to log; returns [] otherwise.
        """
        try:
            lines = self.router.log_tail(n=500, topic_filter="firewall")
        except Exception:
            return []
        events: list[tuple[str, str, int]] = []
        for ln in lines or []:
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+):\d+->(\d+\.\d+\.\d+\.\d+):(\d+)", ln
            )
            if m:
                events.append((m.group(1), m.group(2), int(m.group(3))))
        return events

    # ─── detection run ───────────────────────────────────────────

    def _collect(self, recent: list[str], arp_pairs: list[tuple[str, str]],
                 baseline: dict, *, relative: bool) -> list[Finding]:
        findings = dns_tunnel_findings(
            recent,
            min_label_len=self._min_label_len,
            entropy_bits=self._entropy_bits,
            min_random_subdomains=self._min_random_subdomains,
            allow_suffixes=self._allow_suffixes,
        )
        findings += suspicious_tld_findings(
            recent, bad_tlds=self._bad_tlds, allow_suffixes=self._allow_suffixes
        )
        findings += arp_conflicts(arp_pairs)
        if self._rogue_dhcp:
            findings += rogue_dhcp_findings(self._dhcp_servers_seen(), self._dhcp_allowed)
        if self._port_scan:
            findings += port_scan_findings(
                self._scan_events(), min_distinct_targets=self._port_scan_min
            )
        if relative:
            findings += new_domains(
                recent,
                set(baseline.get("known_domains", [])),
                allow_suffixes=self._allow_suffixes,
            )
            findings += arp_mac_changes(
                {ip: mac for ip, mac in arp_pairs},
                baseline.get("ip_mac", {}),
            )
        return findings

    def _clients_for(self, f: Finding, domain_clients: dict[str, set[str]]) -> set[str]:
        """Which client IP(s) are behind a finding."""
        if f.kind in ("arp_conflict", "arp_change", "rogue_dhcp", "port_scan"):
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
        state = self._state()
        first_run = not state.get("initialized")
        domain_clients = self._recent_domain_clients()
        recent = list(domain_clients.keys())
        arp_pairs = self._arp_pairs()
        ip_mac_now: dict[str, str] = {}
        for ip, mac in arp_pairs:
            ip_mac_now.setdefault(ip, mac)

        findings = self._collect(recent, arp_pairs, state, relative=not first_run)
        alerted = set(state.get("alerted", []))
        fresh: list[Finding] = []
        for f in findings:
            key = f"{f.kind}:{f.subject}"
            if key in alerted:
                continue
            alerted.add(key)
            fresh.append(f)

        if first_run:
            for f in fresh:
                self._record_alert(f.kind, "baseline", {"subject": f.subject})
        elif fresh:
            names = self._device_names()
            for f in fresh:
                clients = sorted(self._clients_for(f, domain_clients))
                self._record_alert(
                    f.kind, "alert",
                    {"subject": f.subject, "detail": f.detail,
                     "severity": f.severity, "clients": clients},
                )
            digest = self._build_digest(fresh, domain_clients, names)
            if digest:
                try:
                    self.notifier.send(digest)  # plain text, no photo, ONE message
                except Exception:
                    self.log.exception("threat digest send failed")

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
            self.log.info("threat_detector: %d new finding(s) in digest", len(fresh))

    def _build_digest(
        self,
        findings: list[Finding],
        domain_clients: dict[str, set[str]],
        names: dict[str, str],
    ) -> str:
        """One consolidated, plain-text message for a scan's new findings."""
        alerts = [f for f in findings if f.kind != "new_domain"]
        new = [f for f in findings if f.kind == "new_domain"]
        lines = ["🛡 Homelab Monitor — scan summary"]

        for f in alerts[: self._max_alert_lines]:
            icon = "🚨" if f.severity == "attack" else "⚠️"
            who = ", ".join(self._label_client(c, names) for c in sorted(self._clients_for(f, domain_clients))[:3])
            label = _KIND_LABELS.get(f.kind, f.kind)
            lines.append(f"{icon} {label}: {f.subject} — {f.detail}" + (f" [from {who}]" if who else ""))
        if len(alerts) > self._max_alert_lines:
            lines.append(f"… +{len(alerts) - self._max_alert_lines} more alerts")

        if new:
            # Attribute new domains to devices instead of one message each.
            per_device: dict[str, int] = defaultdict(int)
            for f in new:
                for c in self._clients_for(f, domain_clients) or {"?"}:
                    per_device[c] += 1
            top = sorted(per_device.items(), key=lambda kv: kv[1], reverse=True)
            lines.append("")
            lines.append(f"📋 {len(new)} new domains from {len(per_device)} device(s):")
            for ip, count in top[:6]:
                lines.append(f"  • {self._label_client(ip, names)}: {count}")
            examples = ", ".join(f.subject for f in new[: self._max_new_examples])
            lines.append(f"  e.g. {examples}")
            lines.append("(full detail in threat_detector/alerts.jsonl · /threats for a live scan)")
        return "\n".join(lines) if len(lines) > 1 else ""

    # ─── on-demand ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/threats":
            return
        domain_clients = self._recent_domain_clients()
        recent = list(domain_clients.keys())
        arp_pairs = self._arp_pairs()
        findings = self._collect(recent, arp_pairs, self._state(), relative=True)
        if not findings:
            self.notifier.send_to(
                chat_id, "🛡 No threats detected in the recent window."
            )
            return
        names = self._device_names()
        digest = self._build_digest(findings, domain_clients, names)
        self.notifier.send_to(chat_id, digest or "🛡 No notable findings.")
