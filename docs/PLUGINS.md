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

## `self_check`

NetSentry watching NetSentry. Command: `/health`. Every plugin may implement
`health()` and return `HealthCheck(name, ok, detail)` items; this plugin gathers
them (plus scheduled jobs whose last run raised, and free disk space), shows
them on demand, and runs a watchdog that alerts when a check goes bad and again
when it recovers. State file: `status.json` (which checks are currently failing,
so a restart doesn't repeat an alert).

| Key | Type | Default | Notes |
|---|---:|---|---|
| `interval_minutes` | int | `10` | Watchdog period |
| `confirm_checks` | int | `2` | Consecutive bad readings before alerting |
| `min_free_mb` | int | `500` | Free space required in the state directory |

## `settings`

`/settings` shows the movable scheduled jobs with their schedule and next run,
and changes them with buttons (new time, pause, back to default). Stored in
`scheduler/overrides.json` in the state directory; internal heartbeats (scans,
health checks) are deliberately not listed. No config keys.

## `power`

`/restart` restarts the router (its own reboot command), NetSentry (clean exit;
systemd restarts it) or the Raspberry Pi. The Pi reboot needs the root helper
units `deploy/netsentry-power.path` and `deploy/netsentry-power.service`:
NetSentry writes `power/request`, the path unit sees it and reboots. State
files: `request` (consumed by the helper), `pending.json` (so the restart is
reported when NetSentry is back).

| Key | Type | Default | Notes |
|---|---:|---|---|
| `helper_wait_s` | float | `20` | Wait before reporting "helper not installed" |
| `isp_plug.host` | string | — | Address of the Shelly plug feeding the ISP router; enables the button |
| `isp_plug.off_seconds` | int | `10` | How long the power stays off (3–120) |
| `isp_plug.switch` | int | `0` | Socket number on the plug |
| `isp_plug.via_router_port` | int | — | Set when NetSentry cannot reach the plug directly: the router forwards this port, from the NetSentry host only, to the plug |

The plug must have no password and must be set to power up again after a power
cut ("restore last" or "on"); the screen checks this and offers to set it. The
plug stays reachable during the restart because it is the ISP router that loses
power, not your own router. Put the plug where its WiFi does not depend on the
device it feeds.

## `locator`

`/where`: a rough position for every WiFi device, from signal strength at the
router and at ESP32 sensors placed around the home. Full guide, hardware list
and limits: [LOCATOR.md](LOCATOR.md). Schedule: sensors are polled every
`poll_minutes` (for `/health`) and on every `/where`. State: `locator/map.png`
(the last drawn map); readings are kept in memory only.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `floor.width_m`, `floor.height_m` | number | `10` | Size of the floor plan |
| `floor.image` | string | — | Optional PNG of the plan, drawn under the map |
| `router.x`, `router.y` | number | — | Position of the router; makes it an anchor |
| `sensors` | list | `[]` | `{id, name, host, x, y[, via_router_port]}` per sensor |
| `token` | string | — | Shared key, if the sensors were flashed with one |
| `poll_minutes` | int | `10` | Background poll interval |
| `rssi_at_1m`, `exponent` | number | measured | Fix the signal model by hand |
| `router_gain_db` | number | `5` | How much better the router hears than a sensor |

## `self_backup`

Backs up NetSentry's own config, vault and plugin state. Command: `/snapshot`.
Schedule: weekly (`cron`, movable with `/settings`). The archive holds the
vault key; it is written 0600 into a 0700 folder.

That archive lives on the same disk as what it protects. For a copy that
survives the disk, `/snapshot` offers "📤 Send me a copy now" and a weekly
switch: the same archive **without the vault key** (`secrets.key`), sent to the
owner as a Telegram document. The encrypted vault is in it but cannot be read
without the key. Keep the key itself somewhere else (a password manager) if you
want the secrets back too; otherwise re-enter them after a restore.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `backup_dir` | string | `~/backups/netsentry` | Must be writable under the unit's `ReadWritePaths` |
| `config_dir` | string | `~/.config/netsentry` | What to back up besides the state directory |
| `cron` | string | `30 3 * * 0` | Sunday 03:30 |
| `keep` | int | `8` | Archives retained |
| `offsite_weekly` | bool | `false` | Send the keyless copy after each scheduled backup (the button overrides it) |

Restore: stop the service, extract the archive, copy `config/` over
`~/.config/netsentry` and `state/` over `~/.local/share/netsentry`, start the
service.

## `who_asked`

Finds the device behind a DNS lookup. Command: `/who [domain]`. Reads Pi-hole's
query database, correlates router-forwarded lookups with the router's
WiFi-connect / DHCP log, and can install a temporary passive logging rule on the
router to catch the sender of the next lookup (polled every 5 minutes; at most
five at a time). State file: `traces.json` (active traces).

| Key | Type | Default | Notes |
|---|---:|---|---|
| `ftl_db_path` | string | `/etc/pihole/pihole-FTL.db` | Pi-hole FTL database |
| `lookback_days` | int | `30` | Query history considered |
| `join_window_s` | int | `15` | "Joined just before the lookup" window |
| `trace_days` | int | `7` | A trace gives up and removes its rule after this |

## `menu`

`/menu` shows every registered command as buttons, grouped by area; tapping one
runs it through the normal dispatcher (same confirmation gate). No config keys,
schedule, or state files.

## `guest_wifi_rotator`

Rotates or displays the guest WiFi password and sends a QR code. Commands:
`/rotate`, `/guest`, `/rotation`, `/keep`.

`/keep` is for the guest who is not a one-time visitor — a relative whose
phone lives on the guest network. Pick the device from the list of what is
connected to the guest network right now, and it keeps the password it has:
when the password rotates, that device stays connected and everyone else needs
the new one. It stays on the guest network (and isolated from other WiFi
devices unless `keep_isolated: false`). Removing a device takes a second tap.

How it works: one WiFi access-list rule per device, at the top of the list,
carrying the device's own passphrase. The password is copied on the router and
never leaves it. Limits worth knowing:

- The device is recognised by its WiFi address. Phones use a private address
  per network, which stays the same until the network is "forgotten" on the
  device — after that, add it again.
- The kept password is the guest password of the day the device was added.
  Someone who knew that password *and* copies the device's address could join
  the guest network — where they would have got with the password anyway.
- WPA2-PSK networks only; WPA3 does not allow per-device passwords.

`/rotation` shows and changes **when** the password rotates, effective
immediately (the running job is re-armed, no restart). It is driven entirely by
buttons — choose the frequency, then the day and time, one tap per step — so
there is nothing to memorise. The typed forms below do the same thing:

| Command | Schedule |
|---|---|
| `/rotation` | status, next/last rotation, one-tap buttons |
| `/rotation now` | rotate right away (asks to confirm) |
| `/rotation daily [HH:MM]` | every day (default 09:00) |
| `/rotation weekly [mon..sun] [HH:MM]` | once a week (default Mon) |
| `/rotation monthly [1-28] [HH:MM]` | once a month (default day 1) |
| `/rotation yearly [DD-MM] [HH:MM]` | once a year (default 01-01) |
| `/rotation cron <m h dom mon dow>` | any 5-field cron |
| `/rotation never` | no automatic rotation; `/rotate` still works |
| `/rotation default` | drop the override, use `rotation_cron` again |

The `/rotation` screen also links to `/keep`, and the message that announces a
new password names the devices that were not affected.

A schedule set this way is stored in `schedule.json` in the plugin state
directory and overrides `rotation_cron` across restarts.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `ssid` | string | required | SSID encoded in the QR |
| `security_profile` | string | required | RouterOS WiFi security profile |
| `password_prefix` | string | `guest` | Generated-password prefix |
| `rotation_cron` | string | `0 9 * * 1` | Monday at 09:00; overridden by `/rotation` |
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

## `threat_detector`

Active detection over data NetSentry already sees. DNS heuristics (tunnel/DGA — a
registrable parent accumulating many high-entropy sub-domains, high-abuse TLDs,
plus newly-seen domains) run over the Pi-hole FTL DB;
ARP heuristics (one IP with multiple MACs, an IP whose MAC changed) run over the
router ARP table. **Report mode by default** — scans record silently to
`alerts.jsonl` + a domain journal (`domains.json`); nothing is pushed on
detection. Commands: `/report` (period report, also on `report_cron`, default
daily 09:00), `/threats` (live scan now), `/domains [text]` (browse/search the
journal — first-seen, device, your notes), `/note <domain> <text>` (annotate),
`/threatlog [n]` (recent findings), `/scans` (list/toggle detectors, live,
persisted), `/audit <hours>|off` (force new_domain on for a window). Detectors:
`dns_tunnel`, `suspicious_tld`,
`arp_conflict`, `arp_change` on by default; `new_domain`, `rogue_dhcp`,
`port_scan` off by default. Config: `interval_minutes`
(`int`, 10), `ftl_db_path` (`string`), `dns_window_minutes` (`int`, 60),
`dns_entropy_bits` (`float`, 3.6), `dns_min_label_len` (`int`, 20),
`dns_min_random_subdomains` (`int`, 5), `dns_allow_suffixes` (`list[str]`, `[]`),
`arp_checks` (`bool`, true). Opt-in network detectors (off by default, each needs
a router feature enabled first): `rogue_dhcp` (`bool`, false — needs `/ip
dhcp-server alert`), `dhcp_allowed_servers` (`list[str]`), `port_scan` (`bool`,
false — needs firewall drop logging), `port_scan_min_distinct` (`int`, 15).
Schedule:
derived from `interval_minutes`. State: `threat_detector/state.json` and
append-only `threat_detector/alerts.jsonl`. The first run establishes a silent
baseline; only new anomalies notify afterward.

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
`/lan` carries buttons for the other views; the "not named yet" view has one
button per device (tap, then reply with the name). The same naming button sits
under every new-device alert.

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
`[el, en]`), and `save_pasted_links` (`bool`, default `true`: a message that
is only a YouTube link is saved without a command). No schedule. State:
`youtube_bookmarks/bookmarks.json`. `/yt` alone opens the library as buttons.
Only full HTTP(S) YouTube URLs are accepted; subprocess arguments use `--`.
Without `yt-dlp`, titles come from YouTube's keyless oEmbed endpoint and
transcripts are unavailable.

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
| `offer_pasted_links` | bool | `true` |

No schedule. State: `github_explorer/repos.json`; repositories live under
`base_dir`. Inputs must be a GitHub HTTP(S) URL or `owner/repo`. Clone
arguments use `--`, and the default directory is allowed by the systemd unit.
`/gh` alone lists the saved repositories as buttons; a pasted repository link
asks before cloning.

A clone is untrusted content: it is checked out with `core.symlinks=false`,
only regular files inside the clone are read into a bundle, and deleting a
repository never removes a folder outside `base_dir`.
