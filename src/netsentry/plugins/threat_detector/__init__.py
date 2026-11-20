"""threat_detector — active detection over data NetSentry already sees.

Runs DNS heuristics (tunnel/DGA, newly-seen domains) over the Pi-hole FTL DB
and ARP heuristics (IP/MAC conflicts, MAC changes) over the router ARP table.
Findings go to Telegram and the append-only alerts.jsonl audit log.

First run establishes a silent baseline (no alerts) — like health_monitor —
so only genuinely new anomalies notify. `/threats` runs an on-demand scan.

The plugin is split by concern; this module keeps the lifecycle and the
detection cycle itself:

    taxonomy.py     the NS-XXX-NNN table (what each finding means)
    detectors.py    pure detection functions (no I/O)
    threat_intel.py downloaded blocklists
    store.py        state, alert log and domain journal on disk
    sources.py      reading Pi-hole and the router
    reports.py      digest and report text
    api.py          methods the dashboard and other plugins call
    telegram_ui.py  slash commands and button screens
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from ...core import netscan, notify, ui
from ...core.plugin import HealthCheck, Plugin, ScheduledTask
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
from .api import ApiMixin
from .reports import ReportsMixin
from .sources import SourcesMixin
from .store import _CYCLE_KEYS, StoreMixin
from .taxonomy import _ID_TO_KIND, _SCANS
from .telegram_ui import TelegramMixin

__all__ = ["ThreatDetectorPlugin", "threat_intel", "_ID_TO_KIND", "_SCANS"]


class ThreatDetectorPlugin(StoreMixin, SourcesMixin, ReportsMixin, ApiMixin,
                           TelegramMixin, Plugin):
    COMMANDS = [
        {"command": "report", "description": "📰 Findings since the last report"},
        {"command": "threats", "description": "🛡 Check for findings now"},
        {"command": "domains", "description": "📇 Domains your devices looked up",
         "usage": "/domains <word>"},
        {"command": "note", "description": "📝 Label a domain",
         "usage": "/note <domain> <label>"},
        {"command": "allow", "description": "🤝 Trust a domain", "usage": "/allow <domain>"},
        {"command": "deny", "description": "↩️ Stop trusting a domain",
         "usage": "/deny <domain>"},
        {"command": "threatlog", "description": "📜 Finding log",
         "usage": "/threatlog [how many]"},
        {"command": "scans", "description": "🎛 Switch detectors on or off",
         "usage": "/scans <detector> on|off"},
        {"command": "audit", "description": "🔍 Record all new domains (audit)",
         "usage": "/audit <hours> | /audit off"},
        {"command": "intel", "description": "🧠 Malware-domain lists",
         "usage": "/intel refresh"},
    ]

    def on_load(self) -> None:
        self._state_file = Path(self.ctx.state_dir) / "state.json"
        # Scans, the daily report, the WiFi monitor and the /allow · /scans
        # commands all read-modify-write this one file from different threads.
        self._state_lock = threading.RLock()
        self._loaded_ts = time.time()
        self._last_cycle_ts = 0.0            # last detection cycle that completed
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
        # A plugin that changes the router on purpose (e.g. the weekly guest-WiFi
        # rotation) publishes an event; we then absorb the resulting config drift
        # for a grace window instead of raising the NS-CFG-001 tamper alarm, so
        # the system's own scheduled change doesn't cry wolf. Drift outside the
        # window still alerts.
        self._config_grace_until = 0.0
        if self.ctx.events:
            for event in ("wifi.password.rotated", "router.config.expected_change"):
                self.ctx.events.subscribe(event, self._on_expected_config_change)
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
            return
        self.log.warning("threat_intel refresh failed (kept previous cache)")
        self._warn_if_feeds_stale()

    def _warn_if_feeds_stale(self, max_age_days: int = 7) -> None:
        """Tell the owner (at most weekly) when the malware feed has gone stale.

        A failed refresh keeps the old cache, which is right for a blip — but a
        source that is gone for good would otherwise leave known-malicious
        detection quietly matching against an ever older list.
        """
        _, ts = threat_intel.load(self._intel_file)
        try:
            age = datetime.now() - datetime.fromisoformat(ts)
        except (TypeError, ValueError):
            age = timedelta(days=max_age_days)          # never fetched at all
        if age < timedelta(days=max_age_days):
            return
        today = datetime.now().date().isoformat()
        with self._state_lock:
            state = self._state()
            last = state.get("intel_stale_notified", "")
            if last and (datetime.now().date() - datetime.fromisoformat(last).date()).days < 7:
                return
            state["intel_stale_notified"] = today
            self._save(state)
        since = ts[:10] if ts else "never"
        try:
            self.notifier.notify(
                notify.ATTENTION,
                f"⚠️ Threat feeds — not updated since {since}\n"
                f"{age.days} days without an update: known-malware domain detection "
                "is running on an old list. The feed source may have moved.",
                buttons=ui.rows(ui.command_row(self.ctx, ("🧠 Feed status", "/intel"))))
        except Exception:
            self.log.exception("stale-feed warning send failed")

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

    def _on_expected_config_change(self, payload: dict) -> None:
        """Open a grace window after a plugin deliberately changes the router.

        The guest-WiFi rotation publishes ``wifi.password.rotated`` and the
        scheduled channel scan ``router.config.expected_change``; both
        re-provision radios, which churns bridge / interface config for a while. During the window the drift scan still
        advances its baseline but does not raise NS-CFG-001, so the system's own
        scheduled change doesn't trip its tamper alarm. Unexpected drift outside
        the window still alerts.
        """
        self._config_grace_until = time.time() + 3 * self._drift_interval_s
        self.log.info(
            "config drift: grace window opened after expected change (%s)",
            (payload or {}).get("source") or (payload or {}).get("profile") or "rotation",
        )

    def _config_drift_findings(self, state: dict) -> list[Finding]:
        """Router config tamper alarm (throttled; own baseline in state).

        First run establishes the baseline silently. Afterwards, any change vs.
        the baseline yields one finding and the new state becomes the baseline —
        unless we're inside a post-rotation grace window (an expected change).
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
            if now < self._config_grace_until:
                self.log.info(
                    "config drift: absorbed %d change(s) during the grace window "
                    "after an expected change (e.g. scheduled rotation)", len(findings))
                return []
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
                    body = self._build_digest(
                        urgent, domain_clients, self._device_names(),
                        headline=ui.header(ui.ATTACK, "Attack seen", "on your network"))
                    try:
                        self.notifier.notify(notify.URGENT, body,
                                             buttons=self._digest_buttons(urgent))
                    except Exception:
                        self.log.exception("immediate alert send failed")

        state["initialized"] = True
        state["known_domains"] = sorted(
            set(state.get("known_domains", []))
            | {d.lower().strip(".") for d in recent if d.strip(".")}
        )[-40000:]
        state["ip_mac"] = ip_mac_now

        # A cycle can take a while (router export, nmap). Anything another
        # thread saved meanwhile - an /allow, a detector toggle, audit mode, the
        # report timestamp, a WiFi finding - must survive: write back only the
        # keys this cycle owns, onto the state as it is on disk *now*.
        with self._state_lock:
            current = self._state()
            for key in _CYCLE_KEYS:
                if key in state:
                    current[key] = state[key]
            current["alerted"] = sorted(
                alerted | set(current.get("alerted", [])))[-40000:]
            # Expire audit mode once its window passes.
            audit_until = current.get("audit_until")
            if audit_until and datetime.now().isoformat() >= audit_until:
                current.pop("audit_until", None)
                self.log.info("threat_detector: audit window ended")
            self._save(current)
        self._last_cycle_ts = time.time()
        if first_run:
            self.log.info(
                "threat_detector baseline established (%d domains, %d hosts)",
                len(recent), len(ip_mac_now),
            )
        elif fresh:
            self.log.info("threat_detector recorded %d finding(s) [report mode]", len(fresh))

    def health(self) -> list[HealthCheck]:
        now = time.time()
        out: list[HealthCheck] = []

        age = now - (self._last_cycle_ts or self._loaded_ts)
        limit = 3 * self._interval_min * 60
        out.append(HealthCheck(
            "Threat detection cycle", age <= limit,
            (f"last completed {int(age // 60)} min ago" if self._last_cycle_ts
             else "has not completed a cycle yet")))

        domains, ts = threat_intel.load(self._intel_file)
        feeds = threat_intel.feed_status(self._intel_file)
        try:
            feed_age = datetime.now() - datetime.fromisoformat(ts)
        except (TypeError, ValueError):
            feed_age = None
        dead = []
        for name, st in feeds.items():
            try:
                last_ok = datetime.fromisoformat(st.get("last_ok") or "")
            except ValueError:
                last_ok = None
            if last_ok is None or datetime.now() - last_ok > timedelta(days=3):
                dead.append(name)
        if not domains or feed_age is None:
            out.append(HealthCheck("Malware-domain feeds", False, "no list downloaded yet"))
        elif feed_age > timedelta(days=3):
            out.append(HealthCheck("Malware-domain feeds", False,
                                   f"list not updated for {feed_age.days} days"))
        elif dead:
            out.append(HealthCheck("Malware-domain feeds", False,
                                   "no fresh data for 3+ days from: " + ", ".join(dead)))
        else:
            out.append(HealthCheck("Malware-domain feeds", True,
                                   f"{len(domains):,} domains, updated {ui.when_text(ts)}"))

        enabled = self._enabled()
        if enabled.get("exposure") or enabled.get("weak_service"):
            last = float(self._state().get("exposure_ts", 0))
            scan_age = now - last
            if not last:
                ok = now - self._loaded_ts < 3 * self._interval_min * 60
                detail = "has not run yet"
            else:
                ok = scan_age <= 2 * self._exposure_interval_s + 3600
                detail = f"last ran {scan_age / 3600:.0f} h ago"
            out.append(HealthCheck("LAN open-port scan", ok, detail))
        else:
            out.append(HealthCheck("LAN open-port scan", True, "switched off in Detectors"))

        corrupt = self._state_file.with_suffix(".json.corrupt")
        try:
            reset_at = corrupt.stat().st_mtime
        except OSError:
            reset_at = 0.0
        if reset_at and now - reset_at < 7 * 86400:
            when = ui.fmt_when(datetime.fromtimestamp(reset_at))
            out.append(HealthCheck(
                "Detector settings", False,
                f"they were damaged and reset on {when} — check the trusted list "
                "and the detectors"))
        return out
