# NetSentry documentation

These documents cover installation, internals, plugin configuration, and
day-two operation of the Raspberry Pi service. Start with Installation for a
new host and Operations for an existing deployment.

## Operator guides

- [Installation](INSTALL.md) — host, vault, config, systemd, and upgrade.
- [Operations](OPERATIONS.md) — service control, logs, secrets, plugin toggles,
  and backups.
- [Guest WiFi rotation](GUEST_WIFI.md) — RouterOS profile/inline behavior,
  exact commands, verification, and recovery.
- [Troubleshooting](TROUBLESHOOTING.md) — bot, DNS, router, dashboard, health,
  and Ollama failure paths.
- [Security](SECURITY.md) — operator threat model and deployment controls.
- [Threat model](THREAT_MODEL.md) — adversarial view: threats mapped to controls.

## Reference

- [How it works](HOW_IT_WORKS.md) — deep technical reference: what every
  function does and how, including the detection internals.
- [Architecture](ARCHITECTURE.md) — components, concurrency, data flow, and
  state.
- [Plugins](PLUGINS.md) — commands, config defaults, schedules, and state.
- [Changelog](CHANGELOG.md) — release history.
