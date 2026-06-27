# Plugins

Each plugin is enabled or disabled under `plugins:` in `config.yaml`. Types
below are YAML types. Cron values use standard five-field syntax.

## `telegram_bot`

Owns Telegram long polling, authorization, command routing, and the worker
pool. Command: `/help`. Config: `worker_threads` (`int`, default `4`). No
schedule. State: `telegram_bot/update_id`.

## `router_info`

Read-only router and Pi diagnostics. Commands: `/status`, `/clients`, `/wan`,
`/services`, `/log`. No config keys or schedule. State:
`router_info/last_public_ip`. An unreachable stats query is reported as
unavailable, never as zeroed router data.

## `security_actions`

Disconnects or blocks WiFi clients and summarizes security status. Commands:
`/kick`, `/security`. No config keys, schedule, or state files. Router changes
use the shared write lock.

## `guest_wifi_rotator`

Rotates or displays the guest WiFi password and sends a QR code. Commands:
`/rotate`, `/guest`.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `ssid` | string | required | SSID encoded in the QR |
| `security_profile` | string | required | RouterOS WiFi security profile |
| `password_prefix` | string | `guest` | Generated-password prefix |
| `rotation_cron` | string | `0 9 * * 1` | Monday at 09:00 |
| `diceware_words` | int | `4` | Number of words |
| `diceware_digits` | int | `4` | Trailing digits |
| `throttle_seconds` | int | `30` | Manual rotation throttle |

Passwords use cryptographic randomness. Rotation writes and verifies both the
profile and every referencing interface; no success QR is sent after a failed
read-back. QR PNGs are temporary under the plugin state directory and are
deleted after sending. See [Guest WiFi rotation](GUEST_WIFI.md).

## `health_monitor`

Checks internet reachability, router uptime/disk, failed logins, and new
clients. It has no command.

| Key | Type | Default |
|---|---:|---|
| `interval_minutes` | int | `5` |
| `ping_target` | string | `1.1.1.1` |
| `disk_low_mb` | int | `10` |
| `login_fail_threshold` | int | `1` |
| `login_fail_window_minutes` | int | `5` |
| `mac_whitelist_prefixes` | list[string] | `[]` |

Schedule: derived from `interval_minutes`. State: `health_monitor/state.json`
and append-only `health_monitor/alerts.jsonl`. The first failed-login sample is
a baseline. Disk checks are skipped when router stats are unavailable.

## `pihole_stats`

Reads Pi-hole FTL SQLite statistics. Command: `/pi`. Config: `ftl_db_path`
(`string`, default `/etc/pihole/pihole-FTL.db`). No schedule or state file.

## `speedtest`

Runs the installed speed-test CLI and reports the result. Command:
`/speedtest`. Config: `isp_nominal_mbps` (`number`, optional). No schedule or
state. Concurrent speed tests are rejected by an internal lock.

## `traffic_report`

Sends a daily `vnstat` traffic digest. No command.

| Key | Type | Default |
|---|---:|---|
| `interface` | string | `eth0` |
| `cron` | string | `0 21 * * *` |
| `bar_width` | int | `16` |
| `isp_nominal_mbps` | number | unset |

No plugin state file; `vnstat` owns its database.

## `morning_briefing`

Sends a daily router, internet, WiFi, Pi-hole, and traffic digest. No command.
Config: `cron` (`string`, default `0 8 * * *`), `overnight_start_hour`
(`int`, default `20`), and `ftl_db_path` (`string`, default
`/etc/pihole/pihole-FTL.db`). No state file.

## `channel_scan`

Runs a RouterOS 5 GHz neighbor scan and recommends a channel. Command: `/scan`.
Config: `scan_interface` (`string`, default `wifi1`),
`scan_duration_seconds` (`int`, default `10`), and `cron` (`string`, default
`30 4 * * 0`). The temporary router scan file is removed; there is no local
state file.

## `config_backup`

Exports text and binary router backups, fetches them, removes router-side
temporary files, and applies retention. Command: `/backup`. Config:
`backup_dir` (`string`, default `~/backups/router`), `retention_days` (`int`,
default `30`), and `cron` (`string`, default `0 3 * * 0`). State is the backup
directory itself.

## `lan_scanner`

Builds a merged ARP/DHCP/WiFi inventory and manages persistent device tags.
Command family: `/lan known|unknown|tag|untag|search|vendor|ping|watch|dashboard`.

| Key | Type | Default |
|---|---:|---|
| `online_oui_lookup` | bool | `true` |
| `watch_idle_threshold_ms` | int | `1500` |
| `watch_poll_seconds` | number | `1.5` |
| `watch_cooldown_seconds` | int | `12` |

No schedule. State: `lan_scanner/tags.json`, `lan_scanner/oui_cache.json`, and
watch-session data stored with the tag state.

## `lan_dashboard`

Serves the live per-device traffic dashboard used by `/lan dashboard`.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `bind_host` | string | `auto` | Tailscale IPv4, else `127.0.0.1` |
| `public_host` | string | `auto` | Host included in the Telegram URL |
| `bind_port` | int | `8088` | HTTP port |
| `poll_interval_s` | number | `2.0` | Router polling interval |
| `history_samples` | int | `120` | Samples retained per device |

No schedule or private state file; it shares `lan_scanner/tags.json`. The
dashboard token is generated on every process start and checked with a
constant-time comparison. `0.0.0.0` remains an explicit opt-in.

## `youtube_bookmarks`

Stores YouTube bookmarks and exports metadata/transcripts. Command family:
`/yt <URL>|list|unwatched|get|show|watched|unwatch|tag|search|remind|delete|export`.
Config: `yt_dlp_bin` (`string`, default `yt-dlp`), `max_transcript_chars`
(`int`, default `250000`), and `lang_priority` (`list[string]`, default
`[el, en]`). No schedule. State: `youtube_bookmarks/bookmarks.json`.
Only full HTTP(S) YouTube URLs are accepted; subprocess arguments use `--`.

## `github_explorer`

Shallow-clones public GitHub repositories and creates local Markdown bundles.
Command family: `/gh <owner/repo>|list|show|bundle|tag|search|delete|export`.

| Key | Type | Default |
|---|---:|---|
| `base_dir` | string | `~/.local/share/netsentry/repos` |
| `clone_depth` | int | `50` |
| `max_files_listed` | int | `200` |
| `max_readme_chars` | int | `12000` |
| `bundle_max_inline_file_chars` | int | `4000` |
| `bundle_inline_extras` | list[string] | common manifest/build files |

No schedule. State: `github_explorer/repos.json`; repositories live under
`base_dir`. Inputs must be a GitHub HTTP(S) URL or `owner/repo`. Clone
arguments use `--`, and the default directory is allowed by the systemd unit.
