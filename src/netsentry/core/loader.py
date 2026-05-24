"""Dynamic plugin discovery + instantiation."""

from __future__ import annotations

import importlib
import inspect
import logging
import os
from pathlib import Path

from .plugin import Plugin, PluginContext
from .config import Config, PluginConfig

log = logging.getLogger(__name__)


def _state_dir(plugin_name: str) -> str:
    base = os.environ.get("NETSENTRY_STATE_DIR",
                          os.path.expanduser("~/.local/share/netsentry"))
    path = Path(base) / plugin_name
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def load_plugins(config: Config, *, router, notifier, vault,
                 scheduler, events,
                 notifiers_by_id: dict | None = None,
                 ai=None) -> list[Plugin]:
    """Import each enabled plugin module, find the Plugin subclass, instantiate."""
    instances: list[Plugin] = []
    for pc in config.plugins:
        if not pc.enabled:
            log.info("Plugin %s disabled — skipping", pc.name)
            continue
        cls = _find_plugin_class(pc.name)
        if cls is None:
            log.error("Plugin %s: no Plugin subclass found", pc.name)
            continue
        ctx = PluginContext(
            name=pc.name,
            config=pc.config,
            router=router,
            notifier=notifier,
            vault=vault,
            logger=logging.getLogger(f"netsentry.{pc.name}"),
            state_dir=_state_dir(pc.name),
            scheduler=scheduler,
            events=events,
            notifiers_by_id=notifiers_by_id or {},
            ai=ai,
        )
        try:
            inst = cls(ctx)
            inst.on_load()
            instances.append(inst)
            log.info("Loaded plugin: %s", pc.name)
        except Exception as e:
            log.exception("Plugin %s failed to load: %s", pc.name, e)
    return instances


def _find_plugin_class(name: str) -> type[Plugin] | None:
    """Look for `netsentry.plugins.<name>` and find a Plugin subclass within."""
    module_name = f"netsentry.plugins.{name}"
    try:
        mod = importlib.import_module(module_name)
    except ImportError as e:
        log.error("Cannot import %s: %s", module_name, e)
        return None
    # Prefer an explicit PLUGIN constant
    if hasattr(mod, "PLUGIN") and inspect.isclass(mod.PLUGIN) and issubclass(mod.PLUGIN, Plugin):
        return mod.PLUGIN
    # Else first Plugin subclass found
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if obj is not Plugin and issubclass(obj, Plugin) and obj.__module__ == module_name:
            return obj
    return None
