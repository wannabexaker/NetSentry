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
                    raise KeyError(f"Vault key missing: {key}")
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


def load(path: Path | None = None, vault: Vault | None = None) -> Config:
    """Load config from YAML, expand vault refs, return structured Config."""
    cfg_path = path or _default_config_path()
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    v = vault or Vault()
    if not v.exists():
        raise VaultError("Vault not initialized. Run `netsentry init` first.")

    expanded = _expand(raw, v)

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
