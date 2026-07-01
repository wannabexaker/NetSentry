# Changelog

All notable changes to NetSentry.

## [0.3.0] — 2026-06-27

### Fixed

- Guest WiFi rotation now updates the RouterOS v7 security profile and every
  referencing `/interface wifi` inline `security.passphrase`, then verifies
  every target before sending a success QR.
- Telegram command and callback handlers run in a four-worker pool by default;
  slow commands no longer freeze long polling. Accepted update offsets are
  persisted before dispatch.
- Router stats return an explicit unavailable result after failed SSH instead
  of fabricated zero values. Status, health, and morning briefing consumers
  handle it safely.
- Health monitoring establishes a failed-login baseline on first run, resets
  the baseline after log rotation, skips disk checks while the router is
  unreachable, and audits disk recovery.
- Telegram polling uses exponential backoff and collapses repeated identical
  connectivity failures into one warning plus one recovery log entry.
- Router configuration writes are serialized with a shared re-entrant lock.
- The wheel build no longer force-includes package data that `packages`
  already ships, so `pip install .` (non-editable) succeeds instead of failing
  on a duplicate-path error.

### Security

- Guest passwords use `secrets` instead of the Mersenne Twister.
- The LAN dashboard defaults to the Tailscale IPv4 address or loopback,
  advertises a reachable host, and compares its per-process token in constant
  time. `0.0.0.0` is opt-in.
- YouTube and GitHub subprocess inputs are allowlisted and passed after an
  end-of-options `--` separator.
- GitHub clones default to `~/.local/share/netsentry/repos`, which is writable
  under the existing systemd sandbox.

### Added

- Append-only `health_monitor/alerts.jsonl` alert and recovery audit log.
- Startup validation for critical router/notifier/plugin keys and unresolved
  vault references.
- Offline unit coverage for guest WiFi verification, router unreachability,
  health guards, worker dispatch, Telegram backoff, config expansion, and
  security input checks.
- Operator documentation for guest WiFi, operations, troubleshooting,
  security, installation, architecture, and plugins.

## [0.2.4] — 2026-05-23

### Added

- New plugin `lan_dashboard` with `/lan dashboard` command: mobile real-time
  per-device traffic, inline MAC tagging, and shared `tags.json` state.
- Router `wifi_traffic()` and `ip_accounting_snapshot()` methods.

## [0.2.3] — 2026-05-23

### Added

- `/lan watch start <name1,name2,...>` interactive MAC identification using
  WiFi `last-activity` changes.
- Persistent watch sessions and device-tag workflow.
- `WifiClient.last_activity_ms` and RouterOS duration parsing.

## [0.2.2] — 2026-05-22

### Added

- `lan_scanner` with inventory, tags, search, vendor lookup, ping sweep, and
  unknown-client workflows.
- Router ARP abstraction and RouterOS pretty-print parsing.
- New-client tag actions and `telegram.text` event publication.

## [0.2.1] — 2026-05-22

### Changed

- YouTube bookmarks became a save/export workflow with transcript documents,
  watched state, tags, search, and Markdown export.
- GitHub explorer became a save/bundle workflow with manifest context, tags,
  search, and Markdown export.
- Added Telegram document upload support.

## [0.2.0] — 2026-05-22

### Added

- Shield-themed branding and five canonical state icons.
- `AIClient`, local `OllamaClient`, and disabled fallback.
- YouTube bookmark and GitHub explorer plugins.
- AI and plugin examples in `config.example.yaml`.

## [0.1.0] — 2026-05-22

### Added

- Initial Python package, core abstractions, plugin loader, scheduler, event
  bus, encrypted vault, Telegram notifier, MikroTik router adapter, CLI, and
  systemd unit.
- Initial router, Pi-hole, speed test, security, guest WiFi, health, traffic,
  channel scan, backup, morning briefing, and Telegram bot plugins.
