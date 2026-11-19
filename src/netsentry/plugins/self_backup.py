"""
self_backup — back up NetSentry's own settings and state.

`config_backup` saves the *router's* config. This saves NetSentry's: the
config file, the encrypted vault and its key, and each plugin's state (device
names, allow-list, detector settings, schedules, domain history). It exists so
that a damaged file or a slip of the hand costs a restore, not a rebuild.

Left out on purpose: logs, cloned repositories and the downloaded threat feeds
(all large, all re-creatable).

⚠️ The archive contains the vault *and* its key, i.e. everything needed to read
your secrets — exactly like the live files it copies. It is written owner-only
(0600) into an owner-only folder on the same disk. It protects against a broken
or deleted file, not against losing the SD card: copy it somewhere else for that.

Commands:
    /snapshot      back up now

Config keys:
    backup_dir     where archives go (default ~/backups/netsentry)
    config_dir     NetSentry's config folder (default ~/.config/netsentry)
    cron           schedule (default Sundays 03:30)
    keep           how many archives to keep (default 8)
"""

from __future__ import annotations

import fnmatch
import os
import tarfile
import threading
from datetime import datetime
from pathlib import Path

from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_SKIP = ("*.log", "*.log.*", "repos", "threat_feeds.json", "*.tmp", "*.png",
         "*.corrupt", "__pycache__")


class SelfBackupPlugin(Plugin):
    COMMANDS = [
        {"command": "snapshot", "description": "🗄 Back up NetSentry's own settings now"},
    ]

    def on_load(self) -> None:
        self._dir = Path(os.path.expanduser(self.cfg.get("backup_dir", "~/backups/netsentry")))
        self._config_dir = Path(os.path.expanduser(
            self.cfg.get("config_dir", "~/.config/netsentry")))
        self._state_root = Path(self.ctx.state_dir).parent
        self._keep = max(1, int(self.cfg.get("keep", 8)))
        self._lock = threading.Lock()
        # First install: don't wait up to a week for the first archive.
        if not any(self._dir.glob("netsentry-*.tar.gz")):
            timer = threading.Timer(float(self.cfg.get("first_backup_delay_s", 45)),
                                    self._first_backup)
            timer.daemon = True
            timer.start()

    def _first_backup(self) -> None:
        try:
            self.backup()
        except Exception:
            self.log.exception("first self-backup failed")

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("cron", "30 3 * * 0")
        return [ScheduledTask(cron=cron, func=self.scheduled_backup, name="weekly")]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/snapshot":
            return
        try:
            path, files, size = self.backup()
        except Exception as e:
            self.log.exception("self-backup failed")
            self.notifier.send_to(chat_id, f"❌ Backup failed: {e}")
            return
        self.notifier.send_to(
            chat_id,
            f"🗄 NetSentry backed up\n  {path.name}\n  {files} files, {size / 1024:.0f} KB\n"
            f"  kept in {self._dir} (newest {self._keep})\n"
            "It holds your vault and its key — treat it like a password file.")

    def scheduled_backup(self) -> None:
        """The weekly run: silent on success, loud on failure (and via /health)."""
        try:
            self.backup()
        except Exception as e:
            self.log.exception("scheduled self-backup failed")
            self.notifier.send_state("warning", f"🗄 NetSentry self-backup failed: {e}")
            raise

    def backup(self) -> tuple[Path, int, int]:
        """Write one archive; returns ``(path, files, bytes)``."""
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._dir, 0o700)
            stamp = f"netsentry-{datetime.now():%Y-%m-%d_%H%M%S}"
            target = self._dir / f"{stamp}.tar.gz"
            extra = 1
            while target.exists():               # two backups in the same second
                extra += 1
                target = self._dir / f"{stamp}-{extra}.tar.gz"
            tmp = target.with_suffix(".partial")
            files = 0
            # Create owner-only from the first byte: it holds the vault key.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
                for root, arc in ((self._config_dir, "config"), (self._state_root, "state")):
                    for path in sorted(self._files(root)):
                        tar.add(path, arcname=f"{arc}/{path.relative_to(root).as_posix()}",
                                recursive=False)
                        files += 1
            if files == 0:
                tmp.unlink(missing_ok=True)
                raise RuntimeError("nothing to back up — config and state folders are empty")
            tmp.replace(target)
            self._prune()
            self.log.info("self-backup: %s (%d files)", target.name, files)
            return target, files, target.stat().st_size

    def _files(self, root: Path):
        if not root.is_dir():
            return
        backup_dir = self._dir.resolve()
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = [d for d in dirnames
                           if not _skipped(d) and (here / d).resolve() != backup_dir]
            for name in filenames:
                path = here / name
                if not _skipped(name) and path.is_file() and not path.is_symlink():
                    yield path

    def _prune(self) -> None:
        archives = sorted(self._dir.glob("netsentry-*.tar.gz"),
                          key=lambda f: f.stat().st_mtime, reverse=True)
        for old in archives[self._keep:]:
            old.unlink(missing_ok=True)

    def health(self) -> list[HealthCheck]:
        name = "NetSentry self-backup"
        try:
            newest = max((f.stat().st_mtime for f in self._dir.glob("netsentry-*.tar.gz")),
                         default=0.0)
        except OSError as e:
            return [HealthCheck(name, False, f"backup folder unreadable: {e}")]
        limit_days = 8.0
        sched = self.ctx.scheduler
        if sched is not None and hasattr(sched, "schedule_of"):
            info = sched.schedule_of(f"{self.ctx.name}.weekly")
            if isinstance(info, dict) and info.get("paused"):
                return [HealthCheck(name, True, "paused in /settings")]
            interval = sched.interval_seconds(f"{self.ctx.name}.weekly")
            if isinstance(interval, (int, float)) and interval > 0:
                limit_days = interval / 86400 * 1.15 + 1
        if not newest:
            return [HealthCheck(name, False, "no backup yet — tap /snapshot")]
        age_days = (datetime.now().timestamp() - newest) / 86400
        when = datetime.fromtimestamp(newest).strftime("%Y-%m-%d")
        if age_days > limit_days:
            return [HealthCheck(name, False, f"newest backup is {age_days:.0f} days old ({when})")]
        return [HealthCheck(name, True, f"last backup {when}")]


def _skipped(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in _SKIP)
