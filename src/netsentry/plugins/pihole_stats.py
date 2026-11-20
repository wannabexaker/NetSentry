"""pihole_stats — /pi command, reads FTL SQLite DB directly."""

from __future__ import annotations

import subprocess

from ..core import ui
from ..core.plugin import HealthCheck, Plugin


class PiholeStatsPlugin(Plugin):
    COMMANDS = [
        {"command": "pi", "description": "🧱 Ad blocking today (Pi-hole)"},
    ]

    def on_load(self) -> None:
        self._db = (self.cfg.get("ftl_db_path")
                    or "/etc/pihole/pihole-FTL.db")

        self._stale_s = max(1, int(self.cfg.get("stale_minutes", 30))) * 60

    def health(self) -> list[HealthCheck]:
        # Threat detection and "who asked" read this database. If Pi-hole stops
        # writing to it they keep running and simply find nothing.
        name = "Pi-hole query log"
        try:
            raw = self._sql("SELECT CAST(strftime('%s','now') AS INTEGER) - MAX(timestamp) "
                            "FROM queries;")
        except Exception as e:
            self.log.warning("Pi-hole database unreadable: %s", e)
            return [HealthCheck(name, False, "NetSentry can't read Pi-hole's database "
                                             "— details are in the log")]
        try:
            age = float(raw)
        except ValueError:
            return [HealthCheck(name, False, "the Pi-hole database holds no queries")]
        if age > self._stale_s:
            return [HealthCheck(name, False, f"no DNS query logged for {int(age // 60)} min "
                                             "— is Pi-hole answering?")]
        return [HealthCheck(name, True, f"last query {ui.ago(age)}")]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/pi":
            return
        try:
            total, blocked = self._today_totals()
            # Pi-hole v6: `queries` is a view that resolves domain/client to
            # strings, so no domain_by_id / client_by_id join is needed.
            top_blocked = self._sql(
                "SELECT domain, COUNT(*) c FROM queries "
                "WHERE timestamp > strftime('%s','now','start of day') "
                "AND status IN (1,4,5,6,7,8,9,10,11) "
                "GROUP BY domain ORDER BY c DESC LIMIT 5;"
            )
            top_clients = self._sql(
                "SELECT client, COUNT(*) FROM queries "
                "WHERE timestamp > strftime('%s','now','start of day') "
                "GROUP BY client ORDER BY COUNT(*) DESC LIMIT 5;"
            )
        except Exception:
            self.log.exception("Pi-hole database read failed")
            self.notifier.send_to(chat_id, "❌ No ad-blocking numbers — NetSentry couldn't "
                                           "read Pi-hole's database. Details are in the log.")
            return

        pct = (blocked / total * 100) if total else 0
        lines = [
            ui.title("🧱", "Ad blocking today", f"{pct:.1f}% blocked"),
            f"🔎 Lookups: {total:,}",
            f"🚫 Blocked: {blocked:,}",
            f"➡️ Let through: {total - blocked:,}",
        ]
        if top_blocked:
            lines.append("\n🚫 Most blocked")
            for ln in top_blocked.splitlines():
                try:
                    d, c = ln.split("|")
                    lines.append(f"• {ui.item(d[:40], f'{int(c):,}×')}")
                except Exception:
                    pass
        if top_clients:
            lines.append("\n📡 Busiest devices")
            for ln in top_clients.splitlines():
                try:
                    ip, c = ln.split("|")
                    lines.append(f"• {ui.item(ip, f'{int(c):,} lookups')}")
                except Exception:
                    pass
        self.notifier.send_to(chat_id, "\n".join(lines), buttons=[ui.nav_row()])

    def _today_totals(self) -> tuple[int, int]:
        """``(queries, blocked)`` since midnight."""
        totals = self._sql(
            "SELECT COUNT(*), SUM(CASE WHEN status IN (1,4,5,6,7,8,9,10,11) "
            "THEN 1 ELSE 0 END) FROM queries "
            "WHERE timestamp > strftime('%s','now','start of day');"
        )
        if totals and "|" in totals:
            try:
                total, blocked = (int(x or 0) for x in totals.split("|"))
                return total, blocked
            except ValueError:
                pass
        return 0, 0

    def api_today(self) -> dict | None:
        """Today's totals for the web dashboard; None when the database is unreadable."""
        try:
            total, blocked = self._today_totals()
        except Exception:
            return None
        return {"total": total, "blocked": blocked,
                "pct": round(blocked / total * 100, 1) if total else 0.0}

    def _sql(self, query: str) -> str:
        r = subprocess.run(
            ["sqlite3", "-separator", "|", self._db, query],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-200:])
        return r.stdout.strip()
