"""
health_monitor — Periodic checks: internet, router uptime, disk, failed logins,
new WiFi/Ethernet clients. Sends Telegram alerts.

Runs on a configurable interval (default 5 minutes).
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from ..core.plugin import Plugin, ScheduledTask


class HealthMonitorPlugin(Plugin):
    def on_load(self) -> None:
        self._state_file = Path(self.ctx.state_dir) / "state.json"
        self._alerts_file = Path(self.ctx.state_dir) / "alerts.jsonl"
        # Cron from interval_minutes (default 5)
        self._interval_min = int(self.cfg.get("interval_minutes", 5))
        self._ping_target = self.cfg.get("ping_target", "1.1.1.1")
        self._disk_low_mb = int(self.cfg.get("disk_low_mb", 10))
        self._login_thresh = int(self.cfg.get("login_fail_threshold", 1))
        self._login_window_min = int(self.cfg.get("login_fail_window_minutes", 5))
        self._mac_whitelist = self.cfg.get("mac_whitelist_prefixes", [])

    def scheduled_tasks(self) -> list[ScheduledTask]:
        # Convert interval_minutes to */N * * * * cron
        n = self._interval_min
        cron = f"*/{n} * * * *" if 1 <= n < 60 else f"0 */{n // 60} * * *"
        return [ScheduledTask(cron=cron, func=self.run_checks, name="checks")]

    # ─── state ───────────────────────────────────────────────────

    def _state(self) -> dict:
        try:
            return json.loads(self._state_file.read_text())
        except Exception:
            return {}

    def _save(self, s: dict) -> None:
        self._state_file.write_text(json.dumps(s, indent=2))

    def _record_alert(self, alert_type: str, event: str, details: dict) -> None:
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": alert_type,
            "event": event,
            "details": details,
        }
        self._alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with self._alerts_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    # ─── checks ─────────────────────────────────────────────────

    def run_checks(self) -> None:
        s = self._state()
        try:
            self._check_internet(s)
            self._check_uptime(s)
            self._check_disk(s)
            self._check_failed_logins(s)
            self._check_new_clients(s)
        except Exception as e:
            self.log.exception("Check failed: %s", e)
        self._save(s)

    def _check_internet(self, s: dict) -> None:
        try:
            r = subprocess.run(
                ["ping", "-c", "2", "-W", "3", self._ping_target],
                capture_output=True, text=True, timeout=8,
            )
            up = r.returncode == 0
        except Exception:
            up = False
        was_up = s.get("internet_up", True)
        if not up and was_up:
            self.notifier.send_state("offline",
                f"🚨 Internet DOWN (ping {self._ping_target} failed)")
            self._record_alert("internet", "alert", {"target": self._ping_target})
        elif up and not was_up:
            self.notifier.send_state("protected", "✅ Internet RESTORED")
            self._record_alert("internet", "recovery", {"target": self._ping_target})
        s["internet_up"] = up

    def _check_uptime(self, s: dict) -> None:
        cur = self.router.uptime_seconds()
        if cur == 0:
            return
        last = s.get("router_uptime_s")
        if last is not None and cur + 60 < last:
            self.notifier.send_state("warning",
                f"🔄 Router REBOOTED\n"
                f"Prev uptime: {timedelta(seconds=last)}\n"
                f"New uptime:  {timedelta(seconds=cur)}"
            )
            self._record_alert(
                "router_uptime",
                "alert",
                {"previous_seconds": last, "current_seconds": cur},
            )
        s["router_uptime_s"] = cur

    def _check_disk(self, s: dict) -> None:
        stats = self.router.stats()
        if stats is None:
            self.log.warning("Skipping disk check: router unreachable")
            return
        free_mb = stats.free_disk_bytes / 1024 / 1024
        last_iso = s.get("disk_alert_at")
        last = datetime.fromisoformat(last_iso) if last_iso else None
        now = datetime.now()
        if free_mb < self._disk_low_mb:
            if not last or last < now - timedelta(days=1):
                self.notifier.send_state("warning",
                    f"⚠️ Router low disk: {free_mb:.1f} MB free "
                    f"(threshold {self._disk_low_mb} MB)"
                )
                self._record_alert(
                    "router_disk",
                    "alert",
                    {"free_mb": round(free_mb, 1), "threshold_mb": self._disk_low_mb},
                )
                s["disk_alert_at"] = now.isoformat()
        else:
            if s.pop("disk_alert_at", None):
                self._record_alert(
                    "router_disk",
                    "recovery",
                    {"free_mb": round(free_mb, 1), "threshold_mb": self._disk_low_mb},
                )

    def _check_failed_logins(self, s: dict) -> None:
        lines = self.router.log_tail(n=200, topic_filter="account")
        fails = [line for line in lines if "login failure" in line]
        cur_count = len(fails)
        last_count = s.get("login_failures_seen")
        if last_count is None:
            s["login_failures_seen"] = cur_count
            self.log.info("Baseline: %d failed router logins", cur_count)
            return
        if cur_count < last_count:
            s["login_failures_seen"] = cur_count
            self.log.info(
                "Failed-login counter moved backwards (%d -> %d); reset baseline",
                last_count,
                cur_count,
            )
            return
        delta = cur_count - last_count
        last_iso = s.get("login_alert_at")
        last = datetime.fromisoformat(last_iso) if last_iso else None
        now = datetime.now()
        if delta >= self._login_thresh:
            if not last or last < now - timedelta(minutes=self._login_window_min):
                severity = "🚨🚨" if delta >= 5 else "🚨"
                hdr = (
                    f"{severity} Brute-force: {delta} failed logins"
                    if delta >= 5 else
                    "🚨 Failed login on router"
                    if delta == 1 else
                    f"🚨 {delta} failed logins"
                )
                body = "\n".join(fails[-delta:][:8])
                self.notifier.send_state("attack", f"{hdr}\n\n{body}")
                self._record_alert(
                    "router_login",
                    "alert",
                    {"new_failures": delta, "sample": fails[-delta:][:8]},
                )
                s["login_alert_at"] = now.isoformat()
        s["login_failures_seen"] = cur_count

    def _check_new_clients(self, s: dict) -> None:
        wifi = self.router.wifi_clients()
        ether = self.router.ethernet_clients()
        cur_macs = {c.mac for c in wifi} | {c.mac for c in ether}
        known = set(s.get("known_macs", []))
        if not known:
            s["known_macs"] = sorted(cur_macs)
            self.log.info("Baseline: %d known MACs", len(cur_macs))
            return
        new = cur_macs - known
        # Whitelist
        new = {m for m in new if not any(m.startswith(p.upper())
                                          for p in self._mac_whitelist)}
        if new:
            leases = {lease.mac: lease for lease in self.router.dhcp_leases()}
            wifi_map = {c.mac: c for c in wifi}
            ether_map = {c.mac: c for c in ether}
            tagger = self._find_tagger()
            lines = [f"🚨 New client{'s' if len(new) > 1 else ''} detected", "━━━━━━━━━━━━━━━━━"]
            buttons = []
            for mac in sorted(new):
                lease = leases.get(mac)
                ip = lease.ip if lease else "?"
                host = (lease.hostname if lease else "") or "(no hostname)"
                wc = wifi_map.get(mac)
                ec = ether_map.get(mac)
                where = (f"SSID {wc.ssid} {wc.signal_dbm}dBm {wc.band}" if wc
                         else f"Ethernet {ec.port}" if ec else "?")
                tag = None
                tag_retired = False
                has_active_tag = False
                if tagger and hasattr(tagger, "tag_info"):
                    tag, tag_retired = tagger.tag_info(mac)
                elif tagger and hasattr(tagger, "tag_for"):
                    tag = tagger.tag_for(mac)
                if tagger and hasattr(tagger, "has_active_tag"):
                    has_active_tag = tagger.has_active_tag(mac)
                else:
                    has_active_tag = bool(tag)
                tag_text = f"{tag} (retired)" if tag and tag_retired else tag
                tag_line = f"   🏷 Known as: {tag_text}\n" if tag_text else ""
                lines.append(
                    f"📱 {mac}\n{tag_line}   {where}\n   IP: {ip}  Host: {host}"
                )
                if tagger and hasattr(tagger, "tag_label"):
                    label = tagger.tag_label(mac, ip, host)
                else:
                    label = tag_text or host or ip or mac
                row = [{"text": f"🚫 Block {label[:18]}",
                        "callback_data": f"security_actions:block:{mac}"}]
                if not has_active_tag:
                    row.append({"text": "🏷 Tag",
                                "callback_data": f"lan_scanner:tagprompt:{mac}"})
                buttons.append(row)
            self.notifier.send_state("warning", "\n".join(lines), buttons=buttons)
            self._record_alert(
                "new_client",
                "alert",
                {"macs": sorted(new)},
            )

        s["known_macs"] = sorted(known | cur_macs)

    # ─── helpers ────────────────────────────────────────────────

    def _find_tagger(self):
        """Locate the lan_scanner plugin (if loaded) for MAC tag lookups."""
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(p, "__class__", None).__name__ == "LanScannerPlugin":
                return p
        return None
