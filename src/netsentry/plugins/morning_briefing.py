"""morning_briefing — Daily 08:00 overnight digest."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta

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
        internet, ping_ms = "?", None
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "2", "1.1.1.1"],
                               capture_output=True, text=True, timeout=4)
            internet = "✅ OK" if r.returncode == 0 else "❌ DOWN"
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

        lines = [
            "☀️ Good morning! Network briefing",
            f"📅 {now.strftime('%A %d %b %Y')}  ⏰ {now.strftime('%H:%M')}",
            "━━━━━━━━━━━━━━━━━",
            "",
            "🖥 Router",
            (
                f"  ⏱  Uptime: {_dur(uptime_s)}"
                + ("  ⚠️ REBOOTED overnight!" if reboot else "")
                if stats else
                "  ⚠️ Router unreachable over SSH"
            ),
            (
                f"  💻 CPU: {stats.cpu_load_pct}%   💾 RAM: {mem_pct:.0f}% used"
                if stats and mem_pct is not None else
                "  💻 CPU/RAM: unavailable"
            ),
            (
                f"  💿 Free disk: {free_disk_mb:.1f} MB"
                if free_disk_mb is not None else
                "  💿 Free disk: unavailable"
            ),
            f"  📶 WiFi clients now: {len(wifi)}",
            "",
            "🌍 Internet",
            f"  Status: {internet}"
            + (f"  ({ping_ms:.0f} ms)" if ping_ms else ""),
            f"  Overnight: ↓ {_h(rx_b)}  ↑ {_h(tx_b)}  Σ {_h(rx_b+tx_b)}",
            "",
            "🛡 Pi-hole (overnight)",
            f"  📊 Queries: {ph_total:,}",
            f"  🚫 Blocked: {ph_blocked:,} "
            f"({(ph_blocked/ph_total*100) if ph_total else 0:.1f}%)",
        ]
        if ph_top:
            lines.append("  Top blocked:")
            for d, c in ph_top:
                lines.append(f"    {c:>3}× {d[:40]}")
        lines.append("\nTap /status for current snapshot.")

        # Pick a state icon by overnight health: warning if anything sketchy,
        # offline if no internet, otherwise protected.
        if "❌" in internet:
            state = "offline"
        elif not stats or reboot or (free_disk_mb is not None and free_disk_mb < 10):
            state = "warning"
        else:
            state = "protected"
        self.notifier.send_state(state, "\n".join(lines))

    def _sql(self, q: str) -> str:
        r = subprocess.run(
            ["sqlite3", "-separator", "|", self._ftl_db, q],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 else ""


def _dur(secs: int) -> str:
    d, secs = divmod(secs, 86400)
    h, _ = divmod(secs, 3600)
    return f"{d}d {h}h" if d else f"{h}h"


def _h(b: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"
