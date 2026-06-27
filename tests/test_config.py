from __future__ import annotations

from pathlib import Path

import pytest

from netsentry.core.config import ConfigError, load


class FakeVault:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def exists(self) -> bool:
        return True

    def get(self, name: str) -> str | None:
        return self.values.get(name)


def _config_text(extra: str = "") -> str:
    return f"""
router:
  type: mikrotik
  host: ${{vault:ROUTER_HOST}}
  user: netsentry
  ssh_key: /home/user/.ssh/router
notifiers:
  - id: tg
    type: telegram
    token: ${{vault:TELEGRAM_TOKEN}}
    chat_id: "${{vault:CHAT_ID}}"
plugins:
  - name: guest_wifi_rotator
    enabled: true
    config:
      ssid: Guest
      security_profile: guest-visitor
logging: {{}}
integrations: {{}}
{extra}
"""


def test_vault_placeholders_expand_recursively(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_config_text(), encoding="utf-8")
    vault = FakeVault(
        {
            "ROUTER_HOST": "router.invalid",
            "TELEGRAM_TOKEN": "placeholder-token",
            "CHAT_ID": "123",
        }
    )

    config = load(path, vault=vault)  # type: ignore[arg-type]

    assert config.router["host"] == "router.invalid"
    assert config.notifier("tg").config["token"] == "placeholder-token"  # type: ignore[union-attr]
    assert config.notifier("tg").config["chat_id"] == "123"  # type: ignore[union-attr]


def test_missing_vault_reference_fails_with_clear_message(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_config_text(), encoding="utf-8")
    vault = FakeVault({"ROUTER_HOST": "router.invalid", "CHAT_ID": "123"})

    with pytest.raises(ConfigError, match="TELEGRAM_TOKEN.*missing"):
        load(path, vault=vault)  # type: ignore[arg-type]


def test_enabled_guest_rotator_requires_profile_and_ssid(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        _config_text().replace("      security_profile: guest-visitor\n", ""),
        encoding="utf-8",
    )
    vault = FakeVault(
        {
            "ROUTER_HOST": "router.invalid",
            "TELEGRAM_TOKEN": "placeholder-token",
            "CHAT_ID": "123",
        }
    )

    with pytest.raises(ConfigError, match="security_profile"):
        load(path, vault=vault)  # type: ignore[arg-type]
