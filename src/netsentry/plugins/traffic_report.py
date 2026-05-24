"""
traffic_report — Daily vnstat-based traffic digest.

Sends a formatted Telegram report at the configured cron (default 21:00).
Includes hourly bar chart, top 3 hours, vs yesterday, monthly totals.
"""

from __future__ import annotations

import json
import subprocess
from datetime import date, timedelta

from ..core.plugin import Plugin, ScheduledTask


class TrafficReportPlugin(Plugin):
    def on_load(self) -> None:
        self._iface = self.cfg.get("interface", "eth0")
        self._bar = int(self.cfg.get("bar_width", 16))
        self._isp_nominal = self.cfg.get("isp_nominal_mbps")

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("cron", "0 21 * * *")
        return [ScheduledTask(cron=cron, func=self.send_report, name="daily")]

    # ─── report ──────────────────────────────────────────────────

    def send_report(self) -> None:
        try:
            hours = self._vnstat("h")["interfaces"][0]["traffic"]["hour"]
            days = self._vnstat("d")["interfaces"][0]["traffic"]["day"]
        except Exception as e:
            self.log.exception("vnstat failed: %s", e)
            self.notifier.send(f"❌ vnstat error: {e}")
            return

        today = date.today()
        yesterday = today - timedelta(days=1)

        def matches(item, d):
            di = item["date"]
            return (di["year"], di["month"], di["day"]) == (d.year, d.month, d.day)

        today_hours = [h for h in hours if matches(h, today)]
        today_rx = sum(h["rx"] for h in today_hours)
        today_tx = sum(h["tx"] for h in today_hours)
        today_total = today_rx + today_tx

        y_day = next((d for d in days if matches(d, yesterday)), None)
        y_total = (y_day["rx"] + y_day["tx"]) if y_day else 0

        month_days = [d for d in days
                      if d["date"]["year"] == today.year
                      and d["date"]["month"] == today.month]
        m_rx = sum(d["rx"] for d in month_days)
        m_tx = sum(d["tx"] for d in month_days)
        m_total = m_rx + m_tx

        # Hourly chart
        hourly_lines = []
        if today_hours:
            max_hour = max(h["rx"] + h["tx"] for h in today_hours)
            for h in sorted(today_hours, key=lambda x: x["time"]["hour"]):
                t = h["rx"] + h["tx"]
                bar = _bar(t, max_hour, self._bar)
                hourly_lines.append(
                    f"{h['time']['hour']:02d}h │{bar}│ {_human(t)}"
                )

        top3 = sorted(today_hours,
                      key=lambda h: h["rx"] + h["tx"], reverse=True)[:3]

        # Comparison
        if y_total > 0 and today_total > 0:
            pct = (today_total - y_total) / y_total * 100
            arrow = "📈" if pct > 0 else "📉"
            cmp_str = f"{arrow} {pct:+.1f}% vs χθες"
        else:
            cmp_str = "— χωρίς σύγκριση"

        days_so_far = today.day
        m_avg = m_total / days_so_far if days_so_far else 0

        lines = [
            "📊 Daily Network Report",
            f"📅 {today.strftime('%A, %d %b %Y')}",
            f"🔌 Interface: {self._iface}",
            "",
            "━━ ΣΗΜΕΡΑ ━━",
            f"↓ RX: {_human(today_rx)}",
            f"↑ TX: {_human(today_tx)}",
            f"Σ Total: {_human(today_total)}",
            cmp_str,
            "",
        ]
        if hourly_lines:
            lines.append("━━ ΩΡΙΑΙΑ ━━")
            lines.append("```")
            lines.extend(hourly_lines)
            lines.append("```")
            lines.append("")
        if top3:
            lines.append("🏆 Top 3 ώρες:")
            for i, h in enumerate(top3):
                lines.append(
                    f"  {i+1}. {h['time']['hour']:02d}:00 → "
                    f"{_human(h['rx']+h['tx'])} "
                    f"(↓{_human(h['rx'])} ↑{_human(h['tx'])})"
                )
            lines.append("")
        lines.extend([
            f"━━ ΜΗΝΑΣ {today.strftime('%B')} ━━",
            f"↓ {_human(m_rx)}  ↑ {_human(m_tx)}",
            f"Σ {_human(m_total)}",
            f"Μ.Ο/μέρα: {_human(m_avg)} ({days_so_far} ημέρες)",
        ])
        if self._isp_nominal:
            lines.append(f"📊 Nominal ISP: {self._isp_nominal} Mbps")
        self.notifier.send("\n".join(lines))

    def _vnstat(self, mode: str) -> dict:
        r = subprocess.run(
            ["vnstat", "--json", mode, "-i", self._iface],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return json.loads(r.stdout)


def _human(b: float) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    return f"{b:.1f} {units[i]}"


def _bar(value: float, max_val: float, width: int) -> str:
    if max_val <= 0:
        return " " * width
    blocks = " ▏▎▍▌▋▊▉█"
    filled = (value / max_val) * width
    full = int(filled)
    rem = filled - full
    s = "█" * full
    if rem > 0 and full < width:
        s += blocks[int(rem * 8)]
    return s.ljust(width)
