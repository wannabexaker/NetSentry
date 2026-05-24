"""Runtime orchestrator — wires everything together and runs the bot loop."""

from __future__ import annotations

import logging
import logging.handlers
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any

from .ai import AIClient, build_ai
from .config import Config, load as load_config
from .events import EventBus
from .loader import load_plugins
from .notifier import Notifier, build_notifier
from .plugin import Plugin
from .router import Router, build_router
from .scheduler import Scheduler
from .vault import Vault

log = logging.getLogger(__name__)


class Runtime:
    """Holds router, notifier, vault, scheduler, events, plugins. Runs the main loop."""

    def __init__(self, config_path: str | None = None) -> None:
        self.vault = Vault()
        self.config: Config = load_config(
            Path(config_path) if config_path else None, vault=self.vault
        )
        self._setup_logging()

        self.router: Router = build_router(self.config.router)
        self.notifiers_by_id: dict[str, Notifier] = {
            n.id: build_notifier({"type": n.type, **n.config})
            for n in self.config.notifiers
        }
        # Primary notifier — first in list, or `tg`
        self.notifier: Notifier = (
            self.notifiers_by_id.get("tg")
            or next(iter(self.notifiers_by_id.values()))
        )

        self.ai: AIClient = build_ai(getattr(self.config, "ai", None))
        log.info("AI client: %s", self.ai)

        self.events = EventBus()
        self.scheduler = Scheduler()
        self.plugins: list[Plugin] = []
        self._stop = threading.Event()

    # ─── lifecycle ───────────────────────────────────────────────

    def start(self) -> None:
        log.info("NetSentry starting")
        self.plugins = load_plugins(
            self.config,
            router=self.router, notifier=self.notifier, vault=self.vault,
            scheduler=self.scheduler, events=self.events,
            notifiers_by_id=self.notifiers_by_id,
            ai=self.ai,
        )

        # Make full plugin list accessible to each plugin (for the bot
        # dispatcher; others can ignore).
        for p in self.plugins:
            p.ctx._all_plugins = self.plugins  # type: ignore[attr-defined]

        # Register schedules
        for p in self.plugins:
            for task in p.scheduled_tasks():
                self.scheduler.add_cron(task.cron, task.func,
                                        name=f"{p.ctx.name}.{task.name}")
        self.scheduler.start()
        log.info("Scheduler started. Jobs: %s", self.scheduler.list_jobs())

        # Find the telegram_bot plugin — it owns the bot loop
        bot = next((p for p in self.plugins
                    if p.ctx.name == "telegram_bot"), None)
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())

        if bot and hasattr(bot, "run_forever"):
            try:
                bot.run_forever(self._stop)   # blocks
            except Exception as e:
                log.exception("Bot crashed: %s", e)
        else:
            log.info("No telegram_bot plugin — running scheduler-only mode")
            while not self._stop.is_set():
                self._stop.wait(60)

        self.shutdown()

    def stop(self) -> None:
        log.info("Stop signal received")
        self._stop.set()

    def shutdown(self) -> None:
        log.info("Shutting down")
        self.scheduler.shutdown()
        for p in self.plugins:
            try:
                p.on_unload()
            except Exception:
                log.exception("on_unload error")

    # ─── helpers ─────────────────────────────────────────────────

    def _setup_logging(self) -> None:
        cfg = self.config.logging or {}
        level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)
        fmt = "%(asctime)s %(name)s [%(levelname)s] %(message)s"
        root = logging.getLogger()
        root.setLevel(level)
        # Stream handler
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter(fmt))
        root.handlers.clear()
        root.addHandler(sh)
        # File handler with rotation
        log_file = cfg.get("file")
        if log_file:
            log_file = os.path.expanduser(log_file)
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=cfg.get("max_size_mb", 10) * 1024 * 1024,
                backupCount=cfg.get("backup_count", 3),
            )
            fh.setFormatter(logging.Formatter(fmt))
            root.addHandler(fh)
