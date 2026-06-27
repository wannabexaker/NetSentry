# Architecture

NetSentry is one Python process managed by systemd. Core services provide
router, notification, scheduling, configuration, vault, AI, and event-bus
abstractions. Plugins contain operator-facing behavior.

## Component map

```text
CLI / systemd
    └── Runtime
        ├── Config + encrypted Vault
        ├── Router
        │   └── MikroTikRouter (RouterOS v7 wifi-qcom over SSH)
        ├── Notifier
        │   └── TelegramNotifier (HTTPS long polling and sends)
        ├── AIClient
        │   ├── OllamaClient
        │   └── DisabledAI
        ├── EventBus
        ├── Scheduler
        └── Plugins
            ├── telegram_bot
            ├── router_info, security_actions, health_monitor
            ├── guest_wifi_rotator, channel_scan, config_backup
            ├── pihole_stats, speedtest, traffic_report, morning_briefing
            ├── lan_scanner, lan_dashboard
            └── youtube_bookmarks, github_explorer
```

`core/runtime.py` builds the services, loads enabled plugins, registers their
scheduled tasks, starts the scheduler, and gives the main thread to the
Telegram poll loop.

## Concurrency model

The process has four execution areas:

1. The main thread performs Telegram `getUpdates` long polling. It persists an
   accepted update ID before submitting work.
2. A bounded four-worker pool by default handles Telegram commands and
   callbacks. Slow `/speedtest`, `/yt`, `/gh`, `/scan`, and `/backup` work does
   not stop polling. Extra accepted work waits in the executor queue.
3. APScheduler runs cron jobs in its own worker threads.
4. `lan_dashboard` owns one HTTP server thread and one router polling thread.

All MikroTik mutating operations share one internal re-entrant write lock.
Router reads remain concurrent. The lock covers guest passphrase changes,
client disconnect/block/unblock, reboot, configuration export, and router file
deletion.

## Command flow

```text
Telegram update
  -> poll loop validates response
  -> update_id persisted
  -> worker-pool submission
  -> chat-ID authorization
  -> command/callback lookup
  -> plugin handler
  -> core service (router/notifier/event bus)
  -> Telegram response
```

Handler exceptions stay inside the worker. The bot logs the exception and
reports the failure to the originating chat. Poll failures keep the persisted
offset, back off from 1 to 30 seconds, emit one degraded warning for repeated
identical failures, and emit one recovery message.

## Scheduled-task flow

```text
plugin.scheduled_tasks()
  -> Runtime registers cron with Scheduler
  -> APScheduler worker invokes plugin method
  -> plugin uses shared core services
  -> router write lock serializes mutations with live commands
```

## Router abstraction

`core/router.py` declares the vendor-neutral `Router` interface.
`MikroTikRouter` uses OpenSSH key authentication and ControlMaster
multiplexing. RouterOS v7.22.1 `as-value` output is unreliable, so operational
tables use defensive pretty-print parsing.

`Router.stats()` returns `SystemStats | None`. `None` means the SSH query did
not produce usable data. Plugins must report or skip unavailable data instead
of treating it as genuine zero CPU, memory, or disk.

Guest WiFi rotation writes the named security profile and every `/interface
wifi` that references it, then reads every target back. See
[Guest WiFi rotation](GUEST_WIFI.md).

## Other core services

- `Config` loads YAML, resolves `${vault:KEY}` and `${env:KEY}`, and validates
  startup-critical keys before services are built.
- `Vault` stores Fernet-encrypted values in `secrets.enc`; the separate
  `secrets.key` controls decryption.
- `Notifier` isolates plugins from Telegram-specific transport details.
- `AIClient` selects local Ollama or a disabled implementation.
- `Scheduler` wraps APScheduler cron registration.
- `EventBus` is synchronous in-process pub/sub. Publishers must keep event
  handlers short or explicitly move expensive work to a thread.
- `loader.py` imports enabled plugin modules independently and gives each a
  dedicated state directory.

## State and files

| Path | Purpose |
|---|---|
| `~/.config/netsentry/config.yaml` | Main configuration |
| `~/.config/netsentry/secrets.key` | Fernet key, mode `0400` |
| `~/.config/netsentry/secrets.enc` | Encrypted vault, mode `0600` |
| `~/.local/share/netsentry/<plugin>/` | Per-plugin state |
| `~/.local/share/netsentry/netsentry.log` | Rotating application log |
| `~/.local/share/netsentry/repos/` | Default GitHub clone directory |
| `~/backups/router/` | Default router backup directory |

See [Plugins](PLUGINS.md) for exact state files and [Security](SECURITY.md) for
the trust boundaries.
