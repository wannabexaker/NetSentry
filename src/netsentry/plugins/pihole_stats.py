"""pihole_stats — /pi command, reads FTL SQLite DB directly."""

from __future__ import annotations

import subprocess

from ..core.plugin import Plugin


class PiholeStatsPlugin(Plugin):
    COMMANDS = [
        {"command": "pi", "description": "🛡 Pi-hole stats (today)"},
    ]

    def on_load(self) -> None:
        self._db = (self.cfg.get("ftl_db_path")
                    or "/etc/pihole/pihole-FTL.db")

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/pi":
            return
        try:
            totals = self._sql(
                "SELECT COUNT(*), SUM(CASE WHEN status IN (1,4,5,6,7,8,9,10,11) "
                "THEN 1 ELSE 0 END) FROM queries "
                "WHERE timestamp > strftime('%s','now','start of day');"
            )
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
        except Exception as e:
            self.notifier.send_to(chat_id, f"❌ Pi-hole DB read failed: {e}")
            return

        total, blocked = 0, 0
        if totals and "|" in totals:
            try:
                total, blocked = map(lambda x: int(x or 0), totals.split("|"))
            except Exception:
                pass
        pct = (blocked / total * 100) if total else 0
        lines = [
            "🛡 Pi-hole stats (today)",
            "━━━━━━━━━━━━━━━━━",
            f"📊 Queries: {total:,}",
            f"🚫 Blocked: {blocked:,} ({pct:.1f}%)",
            f"✅ Allowed: {total - blocked:,}",
        ]
        if top_blocked:
            lines.append("\n🚫 Top blocked:")
            for ln in top_blocked.splitlines():
                try:
                    d, c = ln.split("|")
                    lines.append(f"  {int(c):>4}× {d[:40]}")
                except Exception:
                    pass
        if top_clients:
            lines.append("\n📡 Top clients:")
            for ln in top_clients.splitlines():
                try:
                    ip, c = ln.split("|")
                    lines.append(f"  {int(c):>5}× {ip}")
                except Exception:
                    pass
        self.notifier.send_to(chat_id, "\n".join(lines))

    def _sql(self, query: str) -> str:
        r = subprocess.run(
            ["sqlite3", "-separator", "|", self._db, query],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-200:])
        return r.stdout.strip()
