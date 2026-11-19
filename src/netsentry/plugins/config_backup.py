"""
config_backup — Weekly export + binary backup of router config, kept locally.
Includes /backup on-demand command.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from pathlib import Path

from ..core.plugin import HealthCheck, Plugin, ScheduledTask


class ConfigBackupPlugin(Plugin):
    COMMANDS = [
        {"command": "backup", "description": "💾 Trigger router config backup now"},
    ]

    def on_load(self) -> None:
        self._dir = Path(os.path.expanduser(
            self.cfg.get("backup_dir", "~/backups/router")
        ))
        self._retention_days = int(self.cfg.get("retention_days", 30))
        # Weekly by default, so anything older than this means a backup was missed.
        self._max_age_days = float(self.cfg.get("max_age_days", 8))

    def health(self) -> list[HealthCheck]:
        name = "Router config backup"
        try:
            newest = max((f.stat().st_mtime for f in self._dir.glob("router-*.rsc")),
                         default=0.0)
        except OSError as e:
            return [HealthCheck(name, False, f"backup folder unreadable: {e}")]
        if not newest:
            return [HealthCheck(name, False, f"no backups found in {self._dir}")]
        age_days = (datetime.now().timestamp() - newest) / 86400
        when = datetime.fromtimestamp(newest).strftime("%Y-%m-%d")
        limit = self._max_age_days
        sched = self.ctx.scheduler
        if sched is not None and hasattr(sched, "schedule_of"):
            info = sched.schedule_of(f"{self.ctx.name}.weekly")
            if isinstance(info, dict) and info.get("paused"):
                return [HealthCheck(name, True, f"paused in /settings — last backup {when}")]
            interval = sched.interval_seconds(f"{self.ctx.name}.weekly")
            if isinstance(interval, (int, float)) and interval > 0:
                limit = interval / 86400 * 1.15 + 1
        if age_days > limit:
            return [HealthCheck(name, False,
                                f"newest backup is {age_days:.0f} days old ({when})")]
        return [HealthCheck(name, True, f"last backup {when}")]

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("cron", "0 3 * * 0")
        return [ScheduledTask(cron=cron, func=self.do_backup, name="weekly")]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/backup":
            self.notifier.send_to(chat_id, "💾 Triggering backup…")
            threading.Thread(target=self.do_backup, daemon=True).start()

    def do_backup(self) -> None:
        ts = datetime.now().strftime("%Y-%m-%d_%H%M")
        name = f"router-{ts}"
        self._dir.mkdir(parents=True, exist_ok=True)

        # Trigger export + binary backup on the router
        ok_export = self.router.export_config(name)
        if not ok_export:
            self.notifier.send("❌ Router export failed")
            return
        # Binary backup
        rc, _ = self.router._ssh(f'/system backup save name={name} dont-encrypt=yes') \
            if hasattr(self.router, "_ssh") else (1, "")
        if rc != 0:
            self.notifier.send("❌ Router binary backup failed")
            return

        # Fetch both
        rsc_local = self._dir / f"{name}.rsc"
        bak_local = self._dir / f"{name}.backup"
        ok1 = self.router.fetch_file(f"{name}.rsc", str(rsc_local))
        ok2 = self.router.fetch_file(f"{name}.backup", str(bak_local))
        if not (ok1 and ok2):
            self.notifier.send(f"❌ SCP failed (rsc={ok1}, backup={ok2})")
            return

        # Cleanup on router
        self.router.delete_file(f"{name}.rsc")
        self.router.delete_file(f"{name}.backup")

        # Rotation
        cutoff = datetime.now().timestamp() - self._retention_days * 86400
        removed = 0
        for f in self._dir.glob("router-*"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1

        rsc_sz = rsc_local.stat().st_size
        bak_sz = bak_local.stat().st_size
        self.notifier.send(
            f"✅ Backup OK ({datetime.now():%Y-%m-%d %H:%M})\n"
            f"  {name}.rsc ({rsc_sz} B)\n"
            f"  {name}.backup ({bak_sz} B)\n"
            f"  Rotation: removed {removed} old files"
        )
