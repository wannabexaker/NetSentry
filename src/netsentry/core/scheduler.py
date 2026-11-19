"""Thin wrapper over APScheduler for cron-based plugin tasks."""

from __future__ import annotations

import logging
from datetime import datetime
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

    def add_cron(self, cron: str, func: Callable[[], None], name: str) -> bool:
        """cron is a standard 5-field expression: m h dom mon dow.

        Re-adding an existing ``name`` replaces its schedule, so this is also how
        a plugin reschedules itself at runtime. Returns False on a bad cron.
        """
        try:
            trigger = cron_trigger(cron)
        except Exception as e:
            log.error("Bad cron %r for %s: %s", cron, name, e)
            return False
        self._sched.add_job(func, trigger, id=name, name=name,
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
