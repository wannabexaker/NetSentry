"""In-process pub/sub event bus for plugin decoupling."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

log = logging.getLogger(__name__)


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Callable]] = defaultdict(list)

    def subscribe(self, event: str, handler: Callable[[dict], None]) -> None:
        self._subs[event].append(handler)

    def publish(self, event: str, payload: dict) -> None:
        handlers = self._subs.get(event, [])
        log.debug("Event %s → %d subs", event, len(handlers))
        for h in handlers:
            try:
                h(payload)
            except Exception as e:
                log.exception("Event handler for %s crashed: %s", event, e)
