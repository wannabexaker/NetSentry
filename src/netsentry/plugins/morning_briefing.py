"""morning_briefing — Daily 08:00 overnight digest."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta

from ..core import notify, ui
from ..core.plugin import Plugin, ScheduledTask


class MorningBriefingPlugin(Plugin):
    def on_load(self) -> None:
        self._overnight_start_hour = int(self.cfg.get("overnight_start_hour", 20))
        self._ftl_db = self.cfg.get("ftl_db_path", "/etc/pihole/pihole-FTL.db")

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("cron", "0 8 * * *")
        return [ScheduledTask(cron=cron, func=self.send_briefing, name="daily")]

    def send_briefing(self) -> None:
        now = datetime.now()
        overnight_start = (now - timedelta(days=1)).replace(
            hour=self._overnight_start_hour, minute=0, second=0, microsecond=0
        )
        start_ts = int(overnight_start.timestamp())
        end_ts = int(now.timestamp())

        # Router stats
        stats = self.router.stats()
        uptime_s = stats.uptime_seconds if stats else 0
        reboot = bool(stats and uptime_s < 12 * 3600)

        # Internet check
        internet, ping_ms = "unknown", None
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "2", "1.1.1.1"],
                               capture_output=True, text=True, timeout=4)
            internet = "up" if r.returncode == 0 else "down"
            m = re.search(r"time=([\d.]+)\s*ms", r.stdout)
            if m:
                ping_ms = float(m.group(1))
        except Exception:
            pass

        # Pi-hole overnight
        ph_total = ph_blocked = 0
        ph_top: list[tuple[str, int]] = []
        try:
            t = self._sql(
                f"SELECT COUNT(*), SUM(CASE WHEN status IN (1,4,5,6,7,8,9,10,11) "
                f"THEN 1 ELSE 0 END) FROM queries "
                f"WHERE timestamp BETWEEN {start_ts} AND {end_ts};"
            )
            if t and "|" in t:
                ph_total, ph_blocked = map(lambda x: int(x or 0), t.split("|"))
            t2 = self._sql(
                f"SELECT d.domain, COUNT(*) FROM queries q "
                f"JOIN domain_by_id d ON q.domain=d.id "
                f"WHERE q.timestamp BETWEEN {start_ts} AND {end_ts} "
                f"AND q.status IN (1,4,5,6,7,8,9,10,11) "
                f"GROUP BY d.domain ORDER BY COUNT(*) DESC LIMIT 3;"
            )
            for ln in (t2 or "").splitlines():
                try:
                    d, c = ln.split("|")
                    ph_top.append((d, int(c)))
                except Exception:
                    pass
        except Exception:
            pass

        # vnstat overnight
        rx_b = tx_b = 0
        try:
            r = subprocess.run(["vnstat", "--json", "h", "-i", "eth0"],
                               capture_output=True, text=True, timeout=10)
            data = json.loads(r.stdout)
            for h in data["interfaces"][0]["traffic"]["hour"]:
                if start_ts <= h["timestamp"] <= end_ts:
                    rx_b += h["rx"]
                    tx_b += h["tx"]
        except Exception:
            pass

        # WiFi clients now
        wifi = self.router.wifi_clients()

        mem_pct = (1 - stats.free_memory_bytes / stats.total_memory_bytes) * 100 if stats else None
        free_disk_mb = stats.free_disk_bytes / 1024 / 1024 if stats else None

        # The briefing is a report: it never makes a sound in normal mode. Its
        # first line still says at a glance whether the night was quiet.
        if internet == "down":
            verdict = f"{ui.ATTACK} internet down"
        elif not stats:
            verdict = f"{ui.ATTENTION} router not answering"
        elif reboot:
            verdict = f"{ui.ATTENTION} router restarted overnight"
        elif free_disk_mb is not None and free_disk_mb < 10:
            verdict = f"{ui.ATTENTION} router storage almost full"
        else:
            verdict = f"{ui.OK} quiet night"

        pct = (ph_blocked / ph_total * 100) if ph_total else 0
        lines = [
            ui.title("☀️", "Good morning", verdict),
            (f"🖥 Router: up {ui.duration(uptime_s)} · CPU {stats.cpu_load_pct}% · "
             f"memory {mem_pct:.0f}% · {ui.size(stats.free_disk_bytes)} free"
             if stats and mem_pct is not None else
             "🖥 Router: not answering over SSH"),
            f"📶 WiFi devices now: {len(wifi)}",
            ui.item(f"🌍 Internet: {internet}"
                    + (f" · {ping_ms:.0f} ms" if ping_ms and internet == "up" else ""),
                    f"overnight ↓ {ui.size(rx_b)} ↑ {ui.size(tx_b)}"),
            f"🧱 Ad blocking overnight: {ph_total:,} lookups · {ph_blocked:,} blocked "
            f"({pct:.1f}%)",
        ]
        if ph_top:
            lines.append("   Most blocked: " + ", ".join(f"{d[:40]} ({c:,})" for d, c in ph_top))
        # One line from the self-check, so a monitor that quietly stopped
        # shows up in the first message of the day.
        checker = ui.plugin_named(self.ctx, "self_check")
        if checker is not None:
            try:
                lines.append(checker.summary_line())
            except Exception:
                self.log.exception("self-check summary failed")

        buttons = ui.rows(
            ([ui.button("🩺 Full check", "self_check:full")] if checker is not None else [])
            + ui.command_row(self.ctx, ("📊 Network now", "/status")))
        self.notifier.notify(notify.REPORT, "\n".join(lines), buttons=buttons)

    def _sql(self, q: str) -> str:
        r = subprocess.run(
            ["sqlite3", "-separator", "|", self._ftl_db, q],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
