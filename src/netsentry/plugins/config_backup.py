"""
config_backup — Weekly copy of the router's configuration, kept locally.
Includes /backup on-demand command.

Two files per run:

    router-<date>.rsc      the settings as text (`/export`). Always made.
                           RouterOS leaves passwords out of it.
    router-<date>.backup   the full (binary) backup. Needs the `policy`
                           permission on the router account. A least-privilege
                           account does not have it; the run then keeps the
                           text export, says so, and stops asking the router
                           every week (a manual /backup tries again).

Config keys:
    backup_dir       where the files go (default ~/backups/router)
    retention_days   older files are removed (default 30) — except the newest
                     file of each kind, which is always kept, and full backups
                     while the router refuses to make new ones
    max_age_days     /health complains when the newest backup is older (default 8)
    binary_backup    false = never try the full backup (default true)
"""

from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timedelta
from pathlib import Path

from ..core import notify, ui
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_CHECK = "Router config backup"

# Only files this plugin itself names are ever fetched from or removed on the router.
_OUR_FILE_RE = re.compile(r"^router-(\d{4}-\d{2}-\d{2}_\d{4})\.(rsc|backup)$")


def _made_at(path: Path) -> datetime | None:
    """When a backup file was made, from its name — a file copied late still
    carries the date of the configuration inside it."""
    m = _OUR_FILE_RE.match(path.name)
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d_%H%M") if m else None
    except ValueError:
        return None


class BackupError(RuntimeError):
    """The run did not produce a usable backup."""


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
        state = Path(self.ctx.state_dir)
        self._no_binary = state / "binary_unavailable"   # the router refused the full backup
        self._failed = state / "last_failure"

    def health(self) -> list[HealthCheck]:
        name = _CHECK
        failed = self._read(self._failed)
        if failed:
            # do_backup() told the owner when it failed.
            return [HealthCheck(name, False, f"the last run failed: {failed}", notified=True)]
        try:
            newest = max((f.stat().st_mtime for f in self._dir.glob("router-*.rsc")),
                         default=0.0)
        except OSError as e:
            return [HealthCheck(name, False, f"backup folder unreadable: {e}")]
        if not newest:
            return [HealthCheck(name, False, f"no backups found in {self._dir}")]
        age_days = (datetime.now().timestamp() - newest) / 86400
        when = datetime.fromtimestamp(newest).strftime("%Y-%m-%d")
        kind = " (settings as text only)" if self._no_binary.exists() else ""
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
        return [HealthCheck(name, True, f"last backup {when}{kind}")]

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("cron", "0 3 * * 0")
        return [ScheduledTask(cron=cron, func=self.do_backup, name="weekly")]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/backup":
            self.notifier.send_to(chat_id, f"{ui.WORKING} Backing up the router config…")
            threading.Thread(target=self._manual_backup, args=(chat_id,), daemon=True).start()

    def _manual_backup(self, chat_id: int | None = None) -> None:
        try:
            self.do_backup(manual=True, chat_id=chat_id)
        except BackupError:
            pass                                 # already reported to the owner

    def do_backup(self, manual: bool = False, chat_id: int | None = None) -> None:
        """One backup run. Raises :class:`BackupError` (after telling the owner)
        when nothing usable was saved, so the scheduler records the failure.

        A /backup is answered in its chat; the weekly run is unprompted, so its
        success is a ``success`` message (not sent in normal mode) and its
        failure needs the owner's attention.
        """
        try:
            message = self._run(manual)
        except BackupError as e:
            self.log.error("Router backup failed: %s", e)
            self._write(self._failed, f"{datetime.now():%Y-%m-%d %H:%M} — {e}")
            text = (f"{ui.header(ui.FAILED, 'Router backup', 'NOT made')}\n"
                    f"{str(e)[:1].upper()}{str(e)[1:]}. The backups made before are "
                    "still there.")
            buttons = ui.rows(ui.command_row(self.ctx, ("🔁 Try again", "/backup")))
            if manual and chat_id is not None:
                self.notifier.send_to(chat_id, text, buttons=buttons)
            else:
                self.notifier.notify(notify.ATTENTION, text, buttons=buttons)
            notify.report_problem(self.ctx, _CHECK)
            raise
        self._failed.unlink(missing_ok=True)
        if manual and chat_id is not None:
            self.notifier.send_to(chat_id, message)
        else:
            self.notifier.notify(notify.SUCCESS, message)

    def _run(self, manual: bool) -> str:
        name = f"router-{datetime.now():%Y-%m-%d_%H%M}"
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.log.error("backup folder %s unusable: %s", self._dir, e)
            raise BackupError("the backup folder on this machine can't be used") from e

        if not self.router.export_config(name):
            raise BackupError("the router did not write the export")
        export = self._dir / f"{name}.rsc"
        if not (self.router.fetch_file(f"{name}.rsc", str(export)) and self._size(export)):
            raise BackupError("the export could not be copied from the router")
        lines = [f"  {export.name} — settings as text ({self._size(export):,} B)"]

        lines.append(self._full_backup(name, manual))
        on_router = self._tidy_router()
        removed = self._rotate()
        if removed or on_router:
            lines.append(f"  Tidied up: removed {removed} old file(s) here "
                         f"and {on_router} from the router")
        return f"✅ Router backup saved ({datetime.now():%Y-%m-%d %H:%M})\n" + "\n".join(lines)

    def _full_backup(self, name: str, manual: bool) -> str:
        """Try the full backup; one line for the report either way."""
        if not self.cfg.get("binary_backup", True):
            return "  ℹ️ Full backup is switched off in the config."
        full_backups = self._ours("backup")
        have = f" Newest full backup here: {full_backups[-1].name}." if full_backups else ""
        if self._no_binary.exists() and not manual:
            return ("  ℹ️ Text export only — the router account NetSentry uses may not "
                    f"make a full backup.{have}")
        save = getattr(self.router, "backup_save", None)
        if not (callable(save) and save(name) is True):
            self._write(self._no_binary, f"{datetime.now():%Y-%m-%d %H:%M}")
            return ("  ⚠️ Full backup not made: the router refused it (the account "
                    "NetSentry uses lacks that permission). The text export has every "
                    f"setting but no passwords.{have}")
        full = self._dir / f"{name}.backup"
        if not (self.router.fetch_file(f"{name}.backup", str(full)) and self._size(full)):
            full.unlink(missing_ok=True)
            return "  ⚠️ Full backup was made on the router but could not be copied here."
        self._no_binary.unlink(missing_ok=True)
        return f"  {full.name} — full backup ({self._size(full):,} B)"

    def _tidy_router(self) -> int:
        """Remove our own files from the router once a copy is safely here.

        Also clears what earlier failed runs left behind. A file is only
        removed when it carries one of our names and a non-empty local copy
        exists (it is fetched first if it does not).
        """
        lister = getattr(self.router, "files_with_prefix", None)
        names = lister("router-") if callable(lister) else None
        removed = 0
        for remote in names if isinstance(names, list) else []:
            if not _OUR_FILE_RE.match(remote):
                continue
            local = self._dir / remote
            if not self._size(local):
                if not (self.router.fetch_file(remote, str(local)) and self._size(local)):
                    local.unlink(missing_ok=True)
                    continue
            if self.router.delete_file(remote):
                removed += 1
        return removed

    def _ours(self, kind: str) -> list[Path]:
        """Our files of one kind (``rsc`` / ``backup``), oldest first."""
        dated = [(made, f) for f in self._dir.glob(f"router-*.{kind}")
                 if (made := _made_at(f)) is not None]
        return [f for _, f in sorted(dated)]

    def _rotate(self) -> int:
        """Drop files past the retention.

        The newest of each kind always stays, and full backups are left alone
        while the router refuses to make new ones: the ones here may be the
        only ones there are.
        """
        cutoff = datetime.now() - timedelta(days=self._retention_days)
        kinds = ["rsc"] if self._no_binary.exists() else ["rsc", "backup"]
        removed = 0
        for kind in kinds:
            for f in self._ours(kind)[:-1]:
                if _made_at(f) < cutoff:
                    f.unlink()
                    removed += 1
        return removed

    @staticmethod
    def _size(path: Path) -> int:
        try:
            return path.stat().st_size
        except OSError:
            return 0

    @staticmethod
    def _read(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def _write(self, path: Path, text: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError:
            self.log.exception("could not write %s", path.name)
