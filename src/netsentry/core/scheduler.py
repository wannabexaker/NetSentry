"""Thin wrapper over APScheduler for cron-based plugin tasks."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

log = logging.getLogger(__name__)

# Standard cron counts weekdays from Sunday (0 or 7 = Sun, 1 = Mon … 6 = Sat);
# APScheduler counts from Monday (0 = Mon … 6 = Sun) and does not translate in
# `from_crontab`. Names mean the same thing in both, so we rewrite numbers.
_DOW_NAMES = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")


def _cron_dow_to_names(field: str) -> str:
    """Rewrite the numeric weekdays of a crontab day-of-week field as names.

    ``1`` -> ``mon``, ``1-5`` -> ``mon,tue,wed,thu,fri``, ``0,6`` -> ``sun,sat``.
    Ranges are expanded so a wrap like ``5-7`` (Fri–Sun) stays valid. ``*``,
    ``*/n`` and already-named values pass through untouched.
    """
    out: list[str] = []
    for part in field.split(","):
        base, _, step = part.partition("/")
        if base == "*" or not any(ch.isdigit() for ch in base):
            out.append(part)
            continue
        lo, _, hi = base.partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            out.append(part)                 # mixed/unknown: let APScheduler judge
            continue
        first, last = int(lo), int(hi) if hi else int(lo)
        stride = int(step) if step.isdigit() and int(step) > 0 else 1
        if first > 7 or last > 7 or first > last:
            out.append(part)                 # invalid: surfaces as a bad cron
            continue
        days = [_DOW_NAMES[n % 7] for n in range(first, last + 1, stride)]
        out.extend(dict.fromkeys(days))      # 0 and 7 are both Sunday
    return ",".join(out)


def cron_trigger(cron: str) -> CronTrigger:
    """Build a trigger from a standard 5-field crontab (m h dom mon dow).

    Raises ``ValueError`` on a malformed expression.
    """
    fields = cron.split()
    if len(fields) != 5:
        raise ValueError(f"cron needs 5 fields (m h dom mon dow), got {len(fields)}")
    fields[4] = _cron_dow_to_names(fields[4])
    return CronTrigger.from_crontab(" ".join(fields))


def cron_is_valid(cron: str) -> bool:
    try:
        cron_trigger(cron)
        return True
    except (ValueError, TypeError):
        return False


class Scheduler:
    def __init__(self) -> None:
        self._sched = BackgroundScheduler(timezone="UTC")
        # Use system local timezone
        try:
            import time
            tz = time.tzname[0]
        except Exception:
            tz = None
        if tz:
            self._sched.configure(timezone=tz)
        # name -> {runs, failures, last_start, last_ok, last_error}
        self._stats: dict[str, dict] = {}
        # What each job was registered with, and the owner's changes on top
        # (cron string, or None for "paused"). Overrides survive restarts.
        self._jobs: dict[str, tuple[str, Callable[[], None]]] = {}
        self._overrides: dict[str, str | None] = {}
        self._overrides_file: Path | None = None

    def load_overrides(self, path: Path) -> None:
        """Read the owner's schedule changes; call before jobs are registered."""
        self._overrides_file = path
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            log.error("Unreadable schedule overrides %s — using defaults", path)
            return
        if isinstance(data, dict):
            self._overrides = {
                str(name): cron for name, cron in data.items()
                if cron is None or (isinstance(cron, str) and cron_is_valid(cron))}

    def _persist_overrides(self) -> None:
        if self._overrides_file is None:
            return
        try:
            self._overrides_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._overrides_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._overrides), encoding="utf-8")
            tmp.replace(self._overrides_file)
        except OSError:
            log.exception("Could not save schedule overrides")

    def set_schedule(self, name: str, cron: str | None) -> bool:
        """Change when a registered job runs (``None`` pauses it) — live and persistent."""
        if name not in self._jobs or (cron is not None and not cron_is_valid(cron)):
            return False
        self._overrides[name] = cron
        self._persist_overrides()
        default, func = self._jobs[name]
        return self.add_cron(default, func, name)

    def clear_schedule(self, name: str) -> bool:
        """Back to the schedule the job was registered with."""
        if name not in self._jobs:
            return False
        self._overrides.pop(name, None)
        self._persist_overrides()
        default, func = self._jobs[name]
        return self.add_cron(default, func, name)

    def schedule_of(self, name: str) -> dict | None:
        """``{default, cron, overridden, paused, next_run}`` for a registered job."""
        if name not in self._jobs:
            return None
        default = self._jobs[name][0]
        overridden = name in self._overrides
        cron = self._overrides[name] if overridden else default
        return {"default": default, "cron": cron, "overridden": overridden,
                "paused": cron is None, "next_run": self.next_run(name)}

    def interval_seconds(self, name: str) -> float | None:
        """Time between two consecutive runs of a job, or None if it isn't scheduled."""
        job = self._sched.get_job(name)
        if job is None:
            return None
        try:
            now = datetime.now(job.trigger.timezone)
            first = job.trigger.get_next_fire_time(None, now)
            second = job.trigger.get_next_fire_time(first, first)
            return (second - first).total_seconds()
        except Exception:
            return None

    def _tracked(self, name: str, func: Callable[[], None]) -> Callable[[], None]:
        """Wrap a job so /health can tell whether its last run succeeded."""
        stats = self._stats.setdefault(
            name, {"runs": 0, "failures": 0, "last_start": 0.0,
                   "last_ok": 0.0, "last_error": ""})

        def run() -> None:
            stats["runs"] += 1
            stats["last_start"] = time.time()
            try:
                func()
            except Exception as e:
                stats["failures"] += 1
                stats["last_error"] = f"{type(e).__name__}: {e}"[:200]
                raise
            stats["last_ok"] = time.time()
            stats["last_error"] = ""

        return run

    def job_stats(self) -> dict[str, dict]:
        """Snapshot of every job's run history since start-up."""
        return {name: dict(st) for name, st in self._stats.items()
                if self._sched.get_job(name) is not None}

    def add_cron(self, cron: str, func: Callable[[], None], name: str) -> bool:
        """cron is a standard 5-field expression: m h dom mon dow.

        Re-adding an existing ``name`` replaces its schedule, so this is also how
        a plugin reschedules itself at runtime. Returns False on a bad cron.

        ``cron`` is the job's *default*; a stored owner override (see
        :meth:`set_schedule`) takes precedence, including "paused".
        """
        self._jobs[name] = (cron, func)
        if name in self._overrides:
            cron_or_none = self._overrides[name]
            if cron_or_none is None:
                if self._sched.get_job(name) is not None:
                    self._sched.remove_job(name)
                log.info("Scheduled %s — paused by owner", name)
                return True
            cron = cron_or_none
        try:
            trigger = cron_trigger(cron)
        except Exception as e:
            log.error("Bad cron %r for %s: %s", cron, name, e)
            return False
        self._sched.add_job(self._tracked(name, func), trigger, id=name, name=name,
                            replace_existing=True, misfire_grace_time=300)
        log.info("Scheduled %s @ %s", name, cron)
        return True

    def add_interval(self, seconds: int, func: Callable[[], None], name: str) -> None:
        self._sched.add_job(func, "interval", seconds=seconds, id=name, name=name,
                            replace_existing=True)
        log.info("Scheduled %s every %ds", name, seconds)

    def remove(self, name: str) -> bool:
        """Unschedule a job. Returns False if it wasn't scheduled."""
        if self._sched.get_job(name) is None:
            return False
        self._sched.remove_job(name)
        log.info("Unscheduled %s", name)
        return True

    def next_run(self, name: str) -> datetime | None:
        job = self._sched.get_job(name)
        return getattr(job, "next_run_time", None) if job else None

    def start(self) -> None:
        self._sched.start()

    def shutdown(self) -> None:
        self._sched.shutdown(wait=False)

    def list_jobs(self) -> list[dict]:
        return [
            {"id": j.id, "next_run": str(j.next_run_time)}
            for j in self._sched.get_jobs()
        ]
