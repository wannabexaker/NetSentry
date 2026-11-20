"""
self_backup — back up NetSentry's own settings and state.

`config_backup` saves the *router's* config. This saves NetSentry's: the
config file, the encrypted vault and its key, and each plugin's state (device
names, allow-list, detector settings, schedules, domain history). It exists so
that a damaged file or a slip of the hand costs a restore, not a rebuild.

Left out on purpose: logs, cloned repositories and the downloaded threat feeds
(all large, all re-creatable).

Two kinds of archive, for two different accidents:

* **On this machine** (weekly, and `/snapshot`): the full thing, *including the
  vault key* — everything needed to read your secrets, exactly like the live
  files it copies. Written owner-only (0600) into an owner-only folder. It
  protects against a broken or deleted file, not against a dead disk.
* **A copy away from this machine** (a button under `/snapshot`, optionally
  every week): the same archive **without the vault key**, sent to you as a
  Telegram document. It survives a dead SD card. Because the key stays here,
  the secrets inside it cannot be read by anyone — which also means that after
  a total loss you re-enter the secrets (bot token, …) by hand; everything else
  (settings, device names, lists, schedules, history) comes back from the copy.

Commands:
    /snapshot      back up now; buttons for the away-copy

Config keys:
    backup_dir      where archives go (default ~/backups/netsentry)
    config_dir      NetSentry's config folder (default ~/.config/netsentry)
    cron            schedule (default Sundays 03:30)
    keep            how many archives to keep (default 8)
    offsite_weekly  also send the keyless copy after each scheduled backup
                    (default false; the button under /snapshot overrides it)
"""

from __future__ import annotations

import fnmatch
import os
import tarfile
import threading
from datetime import datetime
from pathlib import Path

from ..core import notify, ui
from ..core.jsonstore import read_json, write_json
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_CHECK = "NetSentry self-backup"
_OFFSITE_CHECK = "NetSentry copy to Telegram"
_FAILED_TEXT = (f"{ui.header(ui.FAILED, 'NetSentry backup', 'NOT made')}\n"
                "The archive couldn't be written. The backups made before are still "
                "there; details are in the log.")

_SKIP = ("*.log", "*.log.*", "repos", "threat_feeds.json", "*.tmp", "*.png",
         "*.corrupt", "*.partial", "__pycache__")
# Never part of a copy that leaves this machine: the vault key (and anything
# else that is a bare key file). Without it `secrets.enc` is unreadable.
_KEYS = ("secrets.key", "*.key", "*.pem")
_TELEGRAM_LIMIT = 45 * 1024 * 1024      # bots may upload 50 MB; stay clear of it


class SelfBackupPlugin(Plugin):
    COMMANDS = [
        {"command": "snapshot", "description": "🗄 Back up NetSentry itself now"},
    ]

    def on_load(self) -> None:
        self._dir = Path(os.path.expanduser(self.cfg.get("backup_dir", "~/backups/netsentry")))
        self._config_dir = Path(os.path.expanduser(
            self.cfg.get("config_dir", "~/.config/netsentry")))
        self._state_root = Path(self.ctx.state_dir).parent
        self._keep = max(1, int(self.cfg.get("keep", 8)))
        self._lock = threading.Lock()
        self._offsite_file = Path(self.ctx.state_dir) / "offsite.json"
        self._failed_file = Path(self.ctx.state_dir) / "last_failure"
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
        except Exception:
            self.log.exception("self-backup failed")
            self.notifier.send_to(chat_id, _FAILED_TEXT)
            return
        self._failed_file.unlink(missing_ok=True)
        self.notifier.send_to(
            chat_id,
            ui.title(ui.OK, "NetSentry backup", "saved") + "\n"
            + ui.item(path.name, ui.plural(files, "file"), ui.size(size)) + "\n"
            f"Kept in {self._dir} (the newest {self._keep}).\n"
            "It holds your vault and its key — treat it like a password file.\n\n"
            + self._offsite_text(),
            buttons=self._offsite_buttons() + [ui.nav_row()])

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # self_backup:send | self_backup:weekly:<on|off>
        verb, _, arg = data.partition(":")[2].partition(":")
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "send":
            ack("Preparing the copy…")
            ok, detail = self.send_copy(chat_id)
            if not ok:
                self.notifier.send_to(chat_id, f"{ui.FAILED} The copy was NOT sent: {detail}. "
                                               "The backups on this machine are untouched.")
        elif verb == "weekly" and arg in ("on", "off"):
            self._set_offsite(weekly=(arg == "on"))
            ack("Weekly copy on" if arg == "on" else "Weekly copy off")
            edit = getattr(self.notifier, "edit_message", None)
            if edit:
                edit(chat_id, message_id, ui.title("🗄", "NetSentry backup") + "\n"
                     + self._offsite_text(),
                     buttons=self._offsite_buttons() + [ui.nav_row()])
        else:
            ack()

    def scheduled_backup(self) -> None:
        """The weekly run: silent on success, loud on failure (and via /health)."""
        try:
            self.backup()
        except Exception:
            self.log.exception("scheduled self-backup failed")
            self._mark_failed()
            self.notifier.notify(notify.ATTENTION, _FAILED_TEXT,
                                 buttons=ui.rows(ui.command_row(
                                     self.ctx, ("🔁 Try again", "/snapshot"))))
            notify.report_problem(self.ctx, _CHECK)
            raise
        self._failed_file.unlink(missing_ok=True)
        if self._offsite().get("weekly"):
            ok, detail = self.send_copy(getattr(self.notifier, "chat_id", None))
            if not ok:
                self.notifier.notify(
                    notify.ATTENTION,
                    f"{ui.header(ui.FAILED, 'Weekly copy to Telegram', 'NOT sent')}\n"
                    f"{detail[:1].upper()}{detail[1:]}. The backup on this machine was "
                    "made as usual.")
                notify.report_problem(self.ctx, _OFFSITE_CHECK)

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
            files = self._write_archive(tmp, with_key=True)
            if files == 0:
                tmp.unlink(missing_ok=True)
                raise RuntimeError("nothing to back up — config and state folders are empty")
            tmp.replace(target)
            self._prune()
            self.log.info("self-backup: %s (%d files)", target.name, files)
            return target, files, target.stat().st_size

    def _write_archive(self, target: Path, *, with_key: bool) -> int:
        """Write a tar.gz of config + state to ``target``; returns the file count."""
        files = 0
        # Owner-only from the first byte: the full archive holds the vault key.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
            for root, arc in ((self._config_dir, "config"), (self._state_root, "state")):
                for path in sorted(self._files(root, with_key=with_key)):
                    tar.add(path, arcname=f"{arc}/{path.relative_to(root).as_posix()}",
                            recursive=False)
                    files += 1
        return files

    def _files(self, root: Path, *, with_key: bool = True):
        if not root.is_dir():
            return
        backup_dir = self._dir.resolve()
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = [d for d in dirnames
                           if not _skipped(d) and (here / d).resolve() != backup_dir]
            for name in filenames:
                path = here / name
                if _skipped(name) or (not with_key and _is_key(name)):
                    continue
                if path.is_file() and not path.is_symlink():
                    yield path

    # ─── the copy that leaves this machine ───────────────────────

    def send_copy(self, chat_id: int | str | None) -> tuple[bool, str]:
        """Send the keyless archive to ``chat_id`` as a Telegram document.

        Returns ``(ok, detail)``; ``detail`` says why not when it failed. The
        outcome is remembered for /health.
        """
        send = getattr(self.notifier, "send_document", None)
        if send is None or chat_id is None:
            return self._offsite_result(False, "this notifier cannot send files")
        when = datetime.now()
        name = f"netsentry-copy-{when:%Y-%m-%d_%H%M}.tar.gz"
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._dir, 0o700)
            tmp = self._dir / "away-copy.partial"
            try:
                files = self._write_archive(tmp, with_key=False)
                size = tmp.stat().st_size
                if files == 0:
                    return self._offsite_result(False, "nothing to back up")
                if size > _TELEGRAM_LIMIT:
                    return self._offsite_result(
                        False, f"the copy is {size / 1048576:.0f} MB — too big for Telegram")
                sent = bool(send(
                    chat_id, str(tmp), filename=name,
                    caption=(f"🗄 NetSentry copy — {ui.fmt_when(when)}\n"
                             f"{ui.plural(files, 'file')}, {ui.size(size)} — without the vault key.\n"
                             "Keep this message; it is what brings your settings back "
                             "if this machine's disk dies.")))
            except OSError:
                self.log.exception("away-copy failed")
                return self._offsite_result(False, "the copy couldn't be written on this machine")
            finally:
                tmp.unlink(missing_ok=True)
        if not sent:
            return self._offsite_result(False, "Telegram did not accept the file")
        self.log.info("self-backup: keyless copy sent (%d files, %d bytes)", files, size)
        return self._offsite_result(True, "")

    def _offsite(self) -> dict:
        state = read_json(self._offsite_file, {})
        state.setdefault("weekly", bool(self.cfg.get("offsite_weekly", False)))
        return state

    def _set_offsite(self, **changes) -> None:
        state = self._offsite()
        state.update(changes)
        write_json(self._offsite_file, state)

    def _offsite_result(self, ok: bool, detail: str) -> tuple[bool, str]:
        now = datetime.now().isoformat(timespec="seconds")
        if ok:
            self._set_offsite(last_sent=now, last_error="")
        else:
            self._set_offsite(last_error=detail, last_failed=now)
        return ok, detail

    def _offsite_text(self) -> str:
        state = self._offsite()
        last = ui.when_text(state.get("last_sent") or "", default="never")
        weekly = ("on — after each scheduled backup" if state.get("weekly")
                  else "off")
        return ("📤 Copy away from this machine\n"
                f"Last sent: {last} · every week: {weekly}\n"
                "The backup above lives on this machine's disk, so it dies with it. "
                "A copy sent to you here survives that. It goes without the vault "
                "key, so nobody can read the secrets in it; after a total loss you "
                "re-enter those by hand and everything else comes back.")

    def _offsite_buttons(self) -> list:
        name = self.ctx.name
        weekly = bool(self._offsite().get("weekly"))
        return [
            [{"text": "📤 Send me a copy now", "callback_data": f"{name}:send"}],
            [{"text": ("🔁 Weekly copy: ON — tap to turn off" if weekly
                       else "🔁 Weekly copy: OFF — tap to turn on"),
              "callback_data": f"{name}:weekly:{'off' if weekly else 'on'}"}],
        ]

    def _prune(self) -> None:
        archives = sorted(self._dir.glob("netsentry-*.tar.gz"),
                          key=lambda f: f.stat().st_mtime, reverse=True)
        for old in archives[self._keep:]:
            old.unlink(missing_ok=True)

    def _mark_failed(self) -> None:
        try:
            self._failed_file.parent.mkdir(parents=True, exist_ok=True)
            self._failed_file.write_text(f"{datetime.now():%Y-%m-%d %H:%M}", encoding="utf-8")
        except OSError:
            self.log.exception("could not record the failed self-backup")

    def health(self) -> list[HealthCheck]:
        name = _CHECK
        try:
            failed = self._failed_file.read_text(encoding="utf-8").strip()
        except OSError:
            failed = ""
        if failed:
            # scheduled_backup() told the owner when it failed.
            return [HealthCheck(name, False,
                                f"the scheduled backup on {ui.when_text(failed, default=failed)} failed",
                                notified=True)]
        try:
            newest = max((f.stat().st_mtime for f in self._dir.glob("netsentry-*.tar.gz")),
                         default=0.0)
        except OSError:
            self.log.exception("self-backup folder unreadable")
            return [HealthCheck(name, False, "the backup folder can't be read — "
                                             "details are in the log")]
        limit_days = 8.0
        sched = self.ctx.scheduler
        if sched is not None and hasattr(sched, "schedule_of"):
            info = sched.schedule_of(f"{self.ctx.name}.weekly")
            if isinstance(info, dict) and info.get("paused"):
                return [HealthCheck(name, True, "paused in Settings")]
            interval = sched.interval_seconds(f"{self.ctx.name}.weekly")
            if isinstance(interval, (int, float)) and interval > 0:
                limit_days = interval / 86400 * 1.15 + 1
        if not newest:
            return [HealthCheck(name, False, "no backup yet")]
        age_days = (datetime.now().timestamp() - newest) / 86400
        when = ui.fmt_day(datetime.fromtimestamp(newest))
        if age_days > limit_days:
            return [HealthCheck(name, False,
                                f"the newest backup is {age_days:.0f} days old ({when})")]
        return [HealthCheck(name, True, f"last backup {when}"),
                *self._offsite_health(limit_days)]

    def _offsite_health(self, limit_days: float) -> list[HealthCheck]:
        """Only when the weekly away-copy is switched on: did it really go out?"""
        state = self._offsite()
        if not state.get("weekly"):
            return []
        name = _OFFSITE_CHECK
        sent, failed = str(state.get("last_sent") or ""), str(state.get("last_failed") or "")
        if failed > sent:                             # ISO timestamps sort as text
            # Every attempt reports its own failure (a reply, or the weekly alert).
            return [HealthCheck(name, False,
                                f"last attempt failed: {state.get('last_error') or 'unknown'}",
                                notified=True)]
        if not sent:
            return [HealthCheck(name, True, "switched on; first copy goes with the next backup")]
        try:
            age_days = (datetime.now() - datetime.fromisoformat(sent)).total_seconds() / 86400
        except ValueError:
            self.log.warning("self-backup: unreadable away-copy timestamp %r", sent)
            return [HealthCheck(name, False, "the time of the last copy can't be read")]
        if age_days > limit_days:
            return [HealthCheck(name, False, f"last copy went out {age_days:.0f} days ago")]
        return [HealthCheck(name, True, f"last copy sent {ui.when_text(sent)}")]


def _skipped(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in _SKIP)


def _is_key(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in _KEYS)
