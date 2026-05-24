"""Thin wrapper over APScheduler for cron-based plugin tasks."""

from __future__ import annotations

import logging
from typing import Callable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

log = logging.getLogger(__name__)


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

    def add_cron(self, cron: str, func: Callable[[], None], name: str) -> None:
        """cron is a standard 5-field expression: m h dom mon dow"""
        try:
            trigger = CronTrigger.from_crontab(cron)
        except Exception as e:
            log.error("Bad cron %r for %s: %s", cron, name, e)
            return
        self._sched.add_job(func, trigger, id=name, name=name,
                            replace_existing=True, misfire_grace_time=300)
        log.info("Scheduled %s @ %s", name, cron)

    def add_interval(self, seconds: int, func: Callable[[], None], name: str) -> None:
        self._sched.add_job(func, "interval", seconds=seconds, id=name, name=name,
                            replace_existing=True)
        log.info("Scheduled %s every %ds", name, seconds)

    def start(self) -> None:
        self._sched.start()

    def shutdown(self) -> None:
        self._sched.shutdown(wait=False)

    def list_jobs(self) -> list[dict]:
        return [
            {"id": j.id, "next_run": str(j.next_run_time)}
            for j in self._sched.get_jobs()
        ]
