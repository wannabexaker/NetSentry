"""
YAML config loader with vault-variable substitution.

`${vault:KEY}` placeholders in YAML are replaced with the decrypted secret.
Example:
    token: ${vault:TELEGRAM_TOKEN}    →    token: "8705…"

Also supports `${env:KEY}` for environment variables (less common).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .vault import Vault, VaultError

_VAR_RE = re.compile(r"\$\{(vault|env):([A-Za-z0-9_.-]+)\}")


class ConfigError(ValueError):
    """Raised when configuration is structurally invalid or incomplete."""


_PLUGIN_REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "guest_wifi_rotator": ("ssid", "security_profile"),
}


def _default_config_path() -> Path:
    return Path(os.environ.get("NETSENTRY_CONFIG",
                               os.path.expanduser("~/.config/netsentry/config.yaml")))


@dataclass
class PluginConfig:
    name: str
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class NotifierConfig:
    id: str
    type: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    router: dict[str, Any]
    notifiers: list[NotifierConfig]
    plugins: list[PluginConfig]
    integrations: dict[str, Any]
    logging: dict[str, Any]
    raw: dict[str, Any]
    ai: dict[str, Any] | None = None

    def plugin(self, name: str) -> PluginConfig | None:
        return next((p for p in self.plugins if p.name == name), None)

    def notifier(self, notifier_id: str) -> NotifierConfig | None:
        return next((n for n in self.notifiers if n.id == notifier_id), None)


def _expand(value: Any, vault: Vault) -> Any:
    """Recursively expand ${vault:KEY} / ${env:KEY} in strings."""
    if isinstance(value, str):
        def sub(m: re.Match[str]) -> str:
            kind, key = m.group(1), m.group(2)
            if kind == "vault":
                v = vault.get(key)
                if v is None:
                    raise ConfigError(
                        f"Vault key {key!r} is referenced by the configuration but missing"
                    )
                return v
            if kind == "env":
                return os.environ.get(key, "")
            return m.group(0)
        return _VAR_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand(v, vault) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, vault) for v in value]
    return value


def _require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be a mapping")
    return value


def _validate(expanded: dict[str, Any]) -> None:
    """Validate startup-critical keys before services and plugins are built."""
    router = _require_mapping(expanded.get("router"), "router")
    for key in ("host", "user", "ssh_key"):
        if not router.get(key):
            raise ConfigError(f"router.{key} is required")

    notifiers = expanded.get("notifiers")
    if not isinstance(notifiers, list) or not notifiers:
        raise ConfigError("notifiers must contain at least one notifier")
    notifier_ids: set[str] = set()
    for index, item in enumerate(notifiers):
        notifier = _require_mapping(item, f"notifiers[{index}]")
        notifier_id = str(notifier.get("id", "")).strip()
        notifier_type = str(notifier.get("type", "")).strip()
        if not notifier_id:
            raise ConfigError(f"notifiers[{index}].id is required")
        if notifier_id in notifier_ids:
            raise ConfigError(f"duplicate notifier id: {notifier_id}")
        notifier_ids.add(notifier_id)
        if not notifier_type:
            raise ConfigError(f"notifiers[{index}].type is required")
        if notifier_type == "telegram":
            for key in ("token", "chat_id"):
                if not notifier.get(key):
                    raise ConfigError(f"notifiers[{index}].{key} is required for telegram")
            allowed = notifier.get("allowed_chats")
            if not allowed or not isinstance(allowed, list):
                raise ConfigError(
                    f"notifiers[{index}].allowed_chats must be a non-empty list — "
                    "the bot controls the router, so an empty whitelist "
                    "(fail-open authorization) is refused"
                )

    plugins = expanded.get("plugins", [])
    if not isinstance(plugins, list):
        raise ConfigError("plugins must be a list")
    plugin_names: set[str] = set()
    for index, item in enumerate(plugins):
        plugin = _require_mapping(item, f"plugins[{index}]")
        name = str(plugin.get("name", "")).strip()
        if not name:
            raise ConfigError(f"plugins[{index}].name is required")
        if name in plugin_names:
            raise ConfigError(f"duplicate plugin name: {name}")
        plugin_names.add(name)
        plugin_config = _require_mapping(
            plugin.get("config", {}),
            f"plugins[{index}].config",
        )
        if not plugin.get("enabled", True):
            continue
        for key in _PLUGIN_REQUIRED_KEYS.get(name, ()):
            if not plugin_config.get(key):
                raise ConfigError(f"enabled plugin {name!r} requires config key {key!r}")


def load(path: Path | None = None, vault: Vault | None = None) -> Config:
    """Load config from YAML, expand vault refs, return structured Config."""
    cfg_path = path or _default_config_path()
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be a mapping")

    v = vault or Vault()
    if not v.exists():
        raise VaultError("Vault not initialized. Run `netsentry init` first.")

    expanded = _expand(raw, v)
    _validate(expanded)

    return Config(
        router=expanded.get("router", {}),
        notifiers=[NotifierConfig(id=n["id"], type=n["type"],
                                  config={k: v for k, v in n.items() if k not in {"id", "type"}})
                   for n in expanded.get("notifiers", [])],
        plugins=[PluginConfig(name=p["name"], enabled=p.get("enabled", True),
                              config=p.get("config", {}))
                 for p in expanded.get("plugins", [])],
        integrations=expanded.get("integrations", {}),
        logging=expanded.get("logging", {}),
        raw=expanded,
        ai=expanded.get("ai"),
    )
