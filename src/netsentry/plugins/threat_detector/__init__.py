"""threat_detector — active detection over data NetSentry already sees.

Runs DNS heuristics (tunnel/DGA, newly-seen domains) over the Pi-hole FTL DB
and ARP heuristics (IP/MAC conflicts, MAC changes) over the router ARP table.
Findings go to Telegram and the append-only alerts.jsonl audit log.

First run establishes a silent baseline (no alerts) — like health_monitor —
so only genuinely new anomalies notify. `/threats` runs an on-demand scan.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path

from ...core.plugin import Plugin, ScheduledTask
from .detectors import (
    Finding,
    arp_conflicts,
    arp_mac_changes,
    dns_tunnel_findings,
    new_domains,
)

_KIND_LABELS = {
    "dns_tunnel": "DNS tunnel/DGA",
    "new_domain": "New domain",
    "arp_conflict": "ARP conflict",
    "arp_change": "ARP/MAC change",
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
        self._allow_suffixes = tuple(
            s.lower().strip(".") for s in self.cfg.get("dns_allow_suffixes", [])
        )
        self._arp_enabled = bool(self.cfg.get("arp_checks", True))

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

    def _recent_domains(self) -> list[str]:
        try:
            r = subprocess.run(
                [
                    "sqlite3",
                    "-noheader",
                    self._ftl_db,
                    "SELECT DISTINCT d.domain FROM queries q "
                    "JOIN domain_by_id d ON q.domain=d.id "
                    f"WHERE q.timestamp > strftime('%s','now','-{self._window_min} minutes') "
                    "LIMIT 20000;",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode != 0:
                self.log.warning("FTL query failed: %s", r.stderr[-160:])
                return []
            return [line.strip() for line in r.stdout.splitlines() if line.strip()]
        except Exception as exc:
            self.log.warning("FTL read failed: %s", exc)
            return []

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

    # ─── detection run ───────────────────────────────────────────

    def _collect(self, recent: list[str], arp_pairs: list[tuple[str, str]],
                 baseline: dict, *, relative: bool) -> list[Finding]:
        findings = dns_tunnel_findings(
            recent,
            min_label_len=self._min_label_len,
            entropy_bits=self._entropy_bits,
            allow_suffixes=self._allow_suffixes,
        )
        findings += arp_conflicts(arp_pairs)
        if relative:
            findings += new_domains(recent, set(baseline.get("known_domains", [])))
            findings += arp_mac_changes(
                {ip: mac for ip, mac in arp_pairs},
                baseline.get("ip_mac", {}),
            )
        return findings

    def run_checks(self) -> None:
        state = self._state()
        first_run = not state.get("initialized")
        recent = self._recent_domains()
        arp_pairs = self._arp_pairs()
        ip_mac_now: dict[str, str] = {}
        for ip, mac in arp_pairs:
            ip_mac_now.setdefault(ip, mac)

        findings = self._collect(recent, arp_pairs, state, relative=not first_run)
        alerted = set(state.get("alerted", []))
        emitted = 0
        for f in findings:
            key = f"{f.kind}:{f.subject}"
            if key in alerted:
                continue
            alerted.add(key)
            if first_run:
                self._record_alert(f.kind, "baseline", {"subject": f.subject})
            else:
                self._emit(f)
                emitted += 1

        state["initialized"] = True
        state["known_domains"] = sorted(
            set(state.get("known_domains", []))
            | {d.lower().strip(".") for d in recent if d.strip(".")}
        )[-20000:]
        state["ip_mac"] = ip_mac_now
        state["alerted"] = sorted(alerted)[-10000:]
        self._save(state)
        if first_run:
            self.log.info(
                "threat_detector baseline established (%d domains, %d hosts)",
                len(recent),
                len(ip_mac_now),
            )
        elif emitted:
            self.log.info("threat_detector emitted %d new finding(s)", emitted)

    def _emit(self, f: Finding) -> None:
        icon = "🚨" if f.severity == "attack" else "⚠️"
        label = _KIND_LABELS.get(f.kind, f.kind)
        text = f"{icon} {label}\n{f.subject}\n{f.detail}"
        try:
            self.notifier.send_state(f.severity, text)
        except Exception:
            self.log.exception("threat alert send failed")
        self._record_alert(
            f.kind, "alert",
            {"subject": f.subject, "detail": f.detail, "severity": f.severity},
        )

    # ─── on-demand ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/threats":
            return
        recent = self._recent_domains()
        arp_pairs = self._arp_pairs()
        findings = self._collect(recent, arp_pairs, self._state(), relative=True)
        if not findings:
            self.notifier.send_to(
                chat_id, "🛡 No threats detected in the recent window."
            )
            return
        lines = ["🛡 Threat scan:"]
        for f in findings[:30]:
            icon = "🚨" if f.severity == "attack" else "⚠️"
            lines.append(f"{icon} [{f.kind}] {f.subject} — {f.detail}")
        if len(findings) > 30:
            lines.append(f"… and {len(findings) - 30} more")
        self.notifier.send_to(chat_id, "\n".join(lines))
