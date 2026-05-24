"""
Plugin base class + context object.

Every plugin is a subclass of `Plugin`. It receives a `PluginContext` with
references to router, notifier(s), vault, scheduler, event bus, logger.

The base class declares the lifecycle:
    plugin.on_load(ctx)        — called once at startup
    plugin.on_command(cmd, …)  — when a Telegram /command is received
    plugin.on_callback(data, …) — when an inline button is pressed
    plugin.on_event(name, payload) — when another plugin publishes an event
    plugin.scheduled_tasks()   — returns list of (cron, callable) to register

A plugin only needs to override the methods it uses.
"""

from __future__ import annotations

import logging
from abc import ABC
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from .ai import AIClient
    from .notifier import Notifier
    from .router import Router
    from .vault import Vault


@dataclass
class PluginContext:
    """What a plugin gets when loaded."""
    name: str
    config: dict[str, Any]
    router: "Router"
    notifier: "Notifier"
    vault: "Vault"
    logger: logging.Logger
    state_dir: str            # ~/.local/share/netsentry/<plugin>/

    # Set by the runtime after plugin discovery; plugins use these to
    # interact with the rest of the system.
    scheduler: Any = None     # APScheduler instance
    events: Any = None        # EventBus instance

    # Other notifiers, addressable by id
    notifiers_by_id: dict[str, "Notifier"] = field(default_factory=dict)

    # AI client (DisabledAI if no ai: block in config).
    ai: "AIClient" = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ScheduledTask:
    cron: str                   # standard 5-field cron expression
    func: Callable[[], None]
    name: str                   # unique within the plugin


class Plugin(ABC):
    """Base class for NetSentry plugins."""

    # Override in subclass for slash-menu registration.
    # Format: [{"command": "rotate", "description": "🔄 Rotate guest password"}]
    COMMANDS: list[dict[str, str]] = []

    def __init__(self, ctx: PluginContext):
        self.ctx = ctx
        self.log = ctx.logger
        self.cfg = ctx.config
        self.router = ctx.router
        self.notifier = ctx.notifier
        self.vault = ctx.vault
        self.ai = ctx.ai

    # ─── lifecycle ───────────────────────────────────────────────

    def on_load(self) -> None:
        """Called once after construction. Use for setup, baselines."""
        pass

    def on_unload(self) -> None:
        """Called on shutdown / reload. Use for cleanup."""
        pass

    # ─── hooks ───────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        """Handle a Telegram /command. Override to react."""
        pass

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        """Handle an inline-keyboard button press."""
        pass

    def on_event(self, event: str, payload: dict[str, Any]) -> None:
        """React to a published event."""
        pass

    def scheduled_tasks(self) -> list[ScheduledTask]:
        """Return cron-scheduled tasks this plugin owns."""
        return []
