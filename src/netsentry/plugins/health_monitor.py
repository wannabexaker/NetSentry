"""
health_monitor — Periodic checks: internet, router uptime, disk, failed logins,
new WiFi/Ethernet clients. Sends Telegram alerts.

Runs on a configurable interval (default 5 minutes).

Every alert here is unprompted, so it goes through ``notifier.notify`` with a
kind (see ``core/notify.py``): an outage or failed login is urgent, a reboot or
low disk needs attention, a new device is FYI. A restart the owner asked for
through /restart is not reported as a surprise.
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

from ..core import notify, ui
from ..core.events import RESTART_REQUESTED
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

# A reboot / outage this soon after the owner asked for one is the one he asked for.
_EXPECTED_WINDOW_S = 30 * 60


class HealthMonitorPlugin(Plugin):
    def on_load(self) -> None:
        self._state_file = Path(self.ctx.state_dir) / "state.json"
        self._alerts_file = Path(self.ctx.state_dir) / "alerts.jsonl"
        # Written by the event handler (another thread), read by the checks —
        # kept out of state.json so neither can overwrite the other's write.
        self._expected_file = Path(self.ctx.state_dir) / "expected_restarts.json"
        # Cron from interval_minutes (default 5)
        self._interval_min = int(self.cfg.get("interval_minutes", 5))
        self._ping_target = self.cfg.get("ping_target", "1.1.1.1")
        self._disk_low_mb = int(self.cfg.get("disk_low_mb", 10))
        self._login_thresh = int(self.cfg.get("login_fail_threshold", 1))
        self._login_window_min = int(self.cfg.get("login_fail_window_minutes", 5))
        self._mac_whitelist = self.cfg.get("mac_whitelist_prefixes", [])
        if self.ctx.events is not None:
            self.ctx.events.subscribe(RESTART_REQUESTED, self._on_restart_requested)

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

    def _notify(self, kind: str, text: str, buttons: list | None = None) -> None:
        try:
            self.notifier.notify(kind, text, buttons=buttons)
        except Exception:
            self.log.exception("health_monitor: could not notify")

    # ─── restarts the owner asked for ───────────────────────────

    def _on_restart_requested(self, payload: dict) -> None:
        target = str((payload or {}).get("target") or "")
        if target not in ("router", "isp"):
            return
        expected = self._expected()
        expected[target] = time.time()
        try:
            self._expected_file.parent.mkdir(parents=True, exist_ok=True)
            self._expected_file.write_text(json.dumps(expected), encoding="utf-8")
        except OSError:
            self.log.exception("could not remember the requested restart")

    def _expected(self) -> dict:
        try:
            data = json.loads(self._expected_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _asked_for(self, target: str) -> float | None:
        """When the owner asked for this restart, if it was within the window."""
        ts = self._expected().get(target)
        if isinstance(ts, (int, float)) and time.time() - ts < _EXPECTED_WINDOW_S:
            return float(ts)
        return None

    # ─── checks ─────────────────────────────────────────────────

    def run_checks(self) -> None:
        s = self._state()
        try:
            self._check_internet(s)
            self._check_router_readable(s)
            self._check_uptime(s)
            self._check_disk(s)
            self._check_failed_logins(s)
            self._check_new_clients(s)
        except Exception as e:
            self.log.exception("Check failed: %s", e)
        self._save(s)

    def _check_router_readable(self, s: dict) -> None:
        """Alert if the router is reachable but its output can't be parsed.

        Distinguishes a real outage from a silent parsing break (e.g. a RouterOS
        upgrade changed the print format): if a trivial SSH probe succeeds yet
        `stats()` yields nothing, parsing is likely broken. Requires two
        consecutive observations to avoid flapping on a transient timeout.

        With the self-check watchdog loaded, this is reported through
        ``health()`` ("Router system data") and the watchdog alerts — together
        with its own "Reading the router" check, in one message — and announces
        the recovery. Only without a watchdog does this plugin alert itself.
        """
        ssh = getattr(self.router, "_ssh", None)
        if ssh is None:
            return
        try:
            rc, out = ssh(":put OK")
        except Exception:
            return
        if rc != 0 or "OK" not in out:
            return  # unreachable — not a parsing break; handled elsewhere
        broken = self.router.stats() is None
        count = s.get("router_parse_broken_count", 0) + 1 if broken else 0
        s["router_parse_broken_count"] = count
        alerted = s.get("router_parse_alerted", False)
        speak = not notify.watchdog_loaded(self.ctx)
        if count >= 2 and not alerted:
            self.log.warning("Router answers but its data cannot be parsed")
            if speak:
                self._notify(
                    notify.ATTENTION,
                    f"{ui.header(ui.ATTENTION, 'Router data', 'unreadable')}\n"
                    "The router answers, but its data can't be read — a RouterOS "
                    "update may have changed its output so parsing fails. Device "
                    "lists and checks may stay empty until NetSentry is updated.")
            self._record_alert("router_parse", "alert", {})
            s["router_parse_alerted"] = True
            s["router_parse_since"] = time.time()
        elif count == 0 and alerted:
            since = s.pop("router_parse_since", None)
            if speak:
                lasted = f" ({ui.duration(time.time() - since)})" if since else ""
                self._notify(notify.RECOVERY,
                             f"{ui.OK} Back to normal: router data readable again{lasted}")
            self._record_alert("router_parse", "recovery", {})
            s["router_parse_alerted"] = False

    def health(self) -> list[HealthCheck]:
        name = "Router system data"
        if self._state().get("router_parse_alerted"):
            return [HealthCheck(name, False,
                                "the router answers, but its system data (uptime, disk) "
                                "can't be read — a RouterOS update may have changed "
                                "its output")]
        return [HealthCheck(name, True, "readable")]

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
            s["internet_down_since"] = time.time()
            self._record_alert("internet", "alert", {"target": self._ping_target})
            if self._asked_for("isp") is not None:
                # The owner just power-cycled the ISP router; /restart reports
                # by itself when the internet is back.
                self.log.info("Internet down after the requested ISP-router restart")
            else:
                self._notify(
                    notify.URGENT,
                    f"{ui.header(ui.ATTACK, 'Internet', 'down')}\n"
                    f"No answer from {self._ping_target}. The home network itself "
                    "still works.", self._internet_buttons())
        elif up and not was_up:
            since = s.pop("internet_down_since", None)
            lasted = f" (down {ui.duration(time.time() - since)})" if since else ""
            self._notify(notify.RECOVERY, f"{ui.OK} Back to normal: Internet{lasted}")
            self._record_alert("internet", "recovery", {"target": self._ping_target})
        s["internet_up"] = up

    def _internet_buttons(self) -> list | None:
        """[🔁 Restart internet router] — only when a smart plug can do it. It
        opens the /restart screen; nothing is switched without a second tap."""
        power = ui.plugin_named(self.ctx, "power")
        has_plug = getattr(power, "has_isp_plug", None)
        try:
            if not (callable(has_plug) and has_plug()):
                return None
        except Exception:
            return None
        return ui.rows(ui.command_row(self.ctx, ("🔁 Restart internet router", "/restart")))

    def _check_uptime(self, s: dict) -> None:
        cur = self.router.uptime_seconds()
        if cur == 0:
            return
        last = s.get("router_uptime_s")
        if last is not None and cur + 60 < last:
            asked = self._asked_for("router")
            if asked is not None:
                # The restart the owner asked for in /restart: report it as done.
                took = max(0.0, time.time() - asked)
                self._notify(notify.RECOVERY,
                             f"{ui.OK} Router is back — restarted as you asked "
                             f"(about {ui.duration(took)})")
                expected = self._expected()
                expected.pop("router", None)
                try:
                    self._expected_file.write_text(json.dumps(expected), encoding="utf-8")
                except OSError:
                    self.log.exception("could not clear the requested restart")
            else:
                self._notify(
                    notify.ATTENTION,
                    f"{ui.header(ui.ATTENTION, 'Router restarted', 'not by you')}\n"
                    f"It had been running for {ui.duration(last)}; up again for "
                    f"{ui.duration(cur)} now. A power cut or a crash can do this.")
            self._record_alert(
                "router_uptime",
                "alert" if asked is None else "requested",
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
                self._notify(
                    notify.ATTENTION,
                    f"{ui.header(ui.ATTENTION, 'Router storage', 'almost full')}\n"
                    f"{free_mb:.1f} MB free (warning below {self._disk_low_mb} MB). "
                    "Backups and logs on the router may start failing.")
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
                hdr = (
                    ui.header(ui.ATTACK, f"{delta} failed router logins", "brute force?")
                    if delta >= 5 else
                    ui.header(ui.ATTACK, "Router login", "failed")
                    if delta == 1 else
                    ui.header(ui.ATTACK, f"{delta} failed router logins")
                )
                body = "\n".join(fails[-delta:][:8])
                self._notify(notify.URGENT, f"{hdr}\n\n{body}", ui.rows(ui.command_row(
                    self.ctx, ("📋 Router log", "/log"), ("🛡 Security", "/security"))))
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
            # A new device is worth knowing about, not an emergency.
            lines = [ui.header(ui.NEW, "New device" if len(new) == 1
                               else ui.plural(len(new), "new device"),
                               "joined the network")]
            buttons = []
            for mac in sorted(new):
                lease = leases.get(mac)
                ip = lease.ip if lease else "?"
                host = (lease.hostname if lease else "") or ""
                wc = wifi_map.get(mac)
                ec = ether_map.get(mac)
                where = (f"WiFi {wc.ssid} · {wc.signal_dbm} dBm · {wc.band}" if wc
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
                name = ui.device_label(mac, name=tag_text, hostname=host)
                lines.append(f"📱 {name}\n   {where}\n   IP {ip} · {mac}")
                if tagger and hasattr(tagger, "tag_label"):
                    label = tagger.tag_label(mac, ip, host or "(no hostname)")
                else:
                    label = tag_text or host or ip or mac
                # Block opens a "are you sure?" step in security_actions.
                row = [{"text": f"🚫 Block {label[:18]}",
                        "callback_data": f"security_actions:block:{mac}"}]
                if not has_active_tag:
                    row.append({"text": "🏷 Name it",
                                "callback_data": f"lan_scanner:tagprompt:{mac}"})
                buttons.append(row)
            self._notify(notify.INFO, "\n".join(lines), buttons)
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
