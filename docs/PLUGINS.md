# Plugins

Each plugin is enabled or disabled under `plugins:` in `config.yaml`. Types
below are YAML types. Cron values use standard five-field syntax.

## `telegram_bot`

Owns Telegram long polling, authorization, command routing, and the worker
pool. Command: `/help`. Config: `worker_threads` (`int`, default `4`),
`confirm_commands` (`list`, default `[]` — extra commands that need a "Yes"
tap; commands that ask their own question, `Plugin.CONFIRMS_ITSELF`, are never
asked twice). `/start` and unknown commands open the `/menu` home. `/help`
lists every command with its typed forms (each plugin's optional `"usage"`
key in `COMMANDS`) — the only place typed syntax is shown. During a plugin's
`on_callback` the bot exposes the tapped message's keyboard
(`keyboard_of(chat, message)`), so a button can turn into a record
(`✔ Trusted …`) without rebuilding the others. No schedule. State:
`telegram_bot/update_id`.

How loud unprompted messages are is the notifier's `notify_mode`
(`relaxed` | `normal` | `everything`, default `normal`), changeable in
`/settings → 🔔 Notifications` and stored in `notify/<notifier id>-mode.json`;
see `core/notify.py` and [UI conventions](UI.md).

## `router_info`

Read-only router and Pi diagnostics. Commands: `/status`, `/clients`, `/wan`,
`/services`, `/log`. No config keys or schedule. State:
`router_info/last_public_ip`. An unreachable stats query is reported as
unavailable, never as zeroed router data. `/status`, `/clients` and `/wan` carry
`🔄 Refresh` (redrawn in place); `/clients` lists devices by network, name
first (the owner's name, else the DHCP hostname, else the MAC).

## `security_actions`

Disconnects or blocks WiFi clients and summarizes security status. Commands:
`/kick`, `/security`. No config keys, schedule, or state files. Router changes
use the shared write lock. Blocking (from `/kick` or the 🚫 button under a
new-device alert) always asks first, naming the device.

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
| `disk_max_used_pct` | int | `85` | How full the disk may get, as a share of its size; `0` = do not check |
| `error_window_minutes` | int | `60` | An error in the log is a problem for this long; `0` = do not watch the log |
| `check_router_readings` | bool | `true` | Compare parsed router lists with the router's own counts |

"It ran" is not "it worked", so two of its own checks look at results:

- **Reading the router** — the router counts its WiFi devices, DHCP leases and
  complete ARP entries itself; the parsed lists must roughly match (an empty
  list while the router has entries, or fewer than half of six or more, is a
  problem). Asked at most every five minutes.
- **Error log** — anything logged at ERROR by any part of NetSentry, with the
  latest message. It clears by itself once the errors are older than the window.

A plugin whose work can go quiet without failing should report a result of its
own from `health()` (see `pihole_stats`, `config_backup`).

One problem → one alert → one recovery. A plugin that alerts the owner about
its own failure returns that check with `notified=True` and calls
`notify.report_problem(ctx, check_name)`; the watchdog then sends no second
alert but still sends the "✅ Back to normal: … (down 14 min)" message. A failed
scheduled job is not alerted separately while its plugin's own check is
failing. `/health` still lists everything. `status.json` also keeps when each
problem started (`since`).

## `site_watch`

Watches the owner's web apps. Each site has a health address (ideally
`/healthz`, answering `{"ok": true, "status": "ok", "version": "…", "commit":
"…"}` with 200, or 503 when something it needs is down); every
`interval_minutes` each one is asked in turn, over IPv4 only (the host may have
an IPv6 address but no IPv6 route). Command: `/sites`. Off by default.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `interval_minutes` | int | `5` | How often every site is checked |
| `timeout_s` | number | `10` | Per request |
| `fail_after` | int | `2` | Bad readings in a row before a site counts as down |
| `sites` | list | `[]` | Each `{name, url, fallback_url?, paused?}`; `url` must be http(s) |

A site is **up** when it answers HTTP 200 and, if the answer is JSON, it does not
say `"ok": false` and its `status` (when present) is ok / healthy / up. A 200
HTML page is up too (the site answers, it has no health data). Anything else is
a bad reading with a one-line reason: `timeout after 10 s`, `connection
refused`, `HTTP 503, database not ok`, `db not ok`. When `url` answers 404 and
a `fallback_url` is set, the fallback is asked instead; `/sites` then says
`no /healthz yet`, as it does for a site whose answer is an HTML page.

After `fail_after` bad readings the owner gets one alert — urgent when nothing
answers or the answer is a 5xx, attention otherwise — and one `✅ Back to
normal: <site> (down 25 min)` when it answers well again; nothing in between.
With `self_check` loaded this plugin sends neither: each non-paused site is a
`health()` check (`Site: <name>`, e.g. `HTTP 503 since 14:05` or `ok · v0.1.0 ·
013a590 · 0.1 s`) and the watchdog alerts and recovers it, so one problem gives
one message. A site whose `version` or `commit` changes between good readings
gives one FYI line, `ℹ️ <site> now runs v0.2.0 (abc1234)` — a deploy landed;
never on the first reading. A `paused: true` site (a demo stopped on purpose) is
listed and checked, never alerts and is not a health check.

`/sites` shows one line per site — state, version and commit, response time,
`no /healthz yet`, `paused`, and since when it has been in its state — with
`🔄 Check now` (checks and redraws the same message) and one `🔎 <site>` detail
button per site. The morning briefing gets one line (`🛰 Sites: 5 up · 1
paused`, or the ones that are not ok). State: `site_watch/state.json`
(per site: last reading, bad readings in a row, since when, last version).

## `settings`

`/settings` shows the movable scheduled jobs with their schedule and next run,
and changes them with buttons (new time, pause — after a second tap — back to
default). Stored in `scheduler/overrides.json` in the state directory; internal
heartbeats (scans, health checks) are deliberately not listed. The
`🔔 Notifications` row switches the notification mode. The Guest WiFi schedule
row opens the rotator's screen in place, with `⬅ Back` to Settings. No config
keys.

## `access`

`/access` shows how to reach and manage NetSentry from another computer, as one
screen refreshed in place: the host's name, model and OS; its Tailscale and LAN
addresses; the `ssh user@host` line; the systemd unit with its status / restart
/ `journalctl -f` commands, the version and how long it has been up; where the
code, config file, vault folder, state and backups are; the repository; and
whether the router — and, when configured, the gaming PC and the HIDway relay —
answer from here. Everything is discovered at run time (slow facts in parallel,
each with a few seconds' limit); lines for things that are not there are left
out. Buttons: the dashboard (URL button), `🩺 Health`, `🗄 Back up now` and
`🔁 Restart…` (only when those plugins are loaded — they run the existing
commands), and `➕ New computer`: the steps to give another computer ssh access
(Tailscale, `ssh-keygen`, append the key from a computer that already has
access, test).

It never shows keys, tokens, passwords, vault values, chat ids, file contents,
or the dashboard link as text (that link carries a login token). It never adds
an ssh key and takes none through Telegram: whoever held the Telegram account
could then give themselves a shell on the host.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `service` | string | `netsentry.service` | The systemd unit shown in the commands |
| `repo_url` | string | the code folder's git remote | Shown without any credentials in it |
| `ssh_host` | string | Tailscale address, else LAN address | The host in the ssh line, e.g. a MagicDNS name |

## `read_access`

A read-only window for another program (an AI agent, a status card): it may
ask `status`, `findings`, `alerts` or `health` over ssh and nothing else. The
contract and the cleaning rules are in [READ_ACCESS.md](READ_ACCESS.md); the
key set-up in [tools/read-agent/README.md](../tools/read-agent/README.md).
Off by default. No Telegram command.

The plugin writes one snapshot, `read_access/snapshot.json` (atomic, mode
0600), at start-up (as soon as the other plugins are wired) and then every
`interval_minutes`. It only reads what other plugins already hold —
`self_check.checks()`, `threat_detector.api_recent_findings()`, the
notifier's alert journal and notification mode, `lan_dashboard.device_counts()`,
`workstation.last_state()`, `health_monitor.internet_up()` and the HIDway
relay's state file — and makes no router, PC or relay call of its own. Each
source is optional: a missing plugin or a failing call leaves its part `null`
or empty. Every outside string is cleaned (control characters, secrets, links,
home paths, public IPs, MACs shortened) and each section is cut to fit an
8 KB answer. The outside half, `tools/read-agent/netsentry_read.py`, is the
only thing the key may run (standard library only, `python3 -I`).

The alert journal lives in the notifier layer (`core/notify.py`,
`AlertJournal`): every `notifier.notify(kind, …)` call is noted — time, kind,
`sound` / `silent` / `not_sent` / `failed`, and the first line of the text
only — in `notify/<notifier id>-alerts.json`, the last 200 kept. Replies sent
with `send` / `send_to` are not noted.

Health: one "Read access snapshot" check, present only while the snapshot
cannot be written.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `interval_minutes` | int | `1` | How often the snapshot is rewritten (the agent refuses snapshots older than 10 min) |

## `power`

`/restart` restarts the router (its own reboot command), NetSentry (clean exit;
systemd restarts it) or the Raspberry Pi. The Pi reboot needs the root helper
units `deploy/netsentry-power.path` and `deploy/netsentry-power.service`:
NetSentry writes `power/request`, the path unit sees it and reboots. State
files: `request` (consumed by the helper), `pending.json` (so the restart is
reported when NetSentry is back). "X is back" and "the internet is back" are
`recovery` messages (silent in normal mode) with a `🩺 Full check` button.

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

## `workstation`

`/pc`: watch and manage a PC (a gaming / AI PC) — set-up from zero and the
security model are in [WORKSTATION.md](WORKSTATION.md). Reaches the PC with ssh
as a key that the PC pins to `tools/pc-agent/pc-agent.ps1` (a fixed action
list; `core/pc_agent.py` keeps the same list and refuses before ssh runs),
wakes it with a Wake-on-LAN packet (`core/wol.py`), and can keep one ssh port
forward to LM Studio alive on demand (`core/tunnel.py`) for `ai: provider:
openai`. Off/asleep is a normal state (shown, never alerted, health OK); a PC
that answers but refuses or answers nonsense is the only health fault.

Schedule: `watch` every `poll_minutes`. It sends `info` when the PC came on
without NetSentry waking it (not within 30 min of its own wake), `attention`
when the GPU is at or over `gpu_temp_alert_c` on two checks in a row (then one
`recovery`), `attention` when disk C is under `disk_free_alert_gb` (then one
`recovery`), and — with `idle_hours` set — one `info` with a Sleep button after
that long with no game, no model and GPU load under 5 % on every check. State:
`workstation/watch.json` (`was_on`, `hot_streak`, `hot_alerted`,
`disk_alerted`, `idle_since`, `idle_announced`, `woken_at`). The dashboard's
System page shows a read-only card from `api_status()` (never waits for ssh;
refreshed in the background at most once a minute).

Callback data: `workstation:v` (refresh), `:new` (open as a new message),
`:wake`, `:go:<id>` (wake + start), `:ask:<sleep|shutdown|restart>`, `:do:<…>`,
`:abort` (cancel a pending shutdown/restart), `:no` (cancel the confirmation).
Buttons of older versions: `:ai` and `:sh:…` open the [`ai_control`](#ai_control)
screens (they never act); `:start:<id>`, `:stop:<id>` and `:vram` show `/pc`.
The `🤖 AI Mission Control` button appears when `ai_control` is loaded.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `name` | string | `Gaming PC` | What to call it |
| `host`, `user`, `ssh_key` | string | — | All three needed, else the plugin does nothing |
| `port` | int | `22` | ssh port |
| `connect_timeout_s` | int | `8` | ssh connect timeout; an off PC costs this much per check |
| `mac`, `wake_to` | string | — | Wake-on-LAN; `wake_to` = `host[:port]` (port 9), a relay or a broadcast |
| `services` | list | `[lmstudio, hermes, openclaw]` | Service ids the `wake_and_start` buttons and `links` may name (`start <id>` on the PC script's list) |
| `wake_and_start` | list | `[]` | Ids that get `🤖 Start X` even while the PC is off |
| `links` | map | `{}` | `{id: URL}` — a button to open the service once it runs |
| `remote_keyboard_url` | string | — | Adds `⌨️ Open remote keyboard` where a login is needed; empty = the dashboard's Remote page when [`remote_keyboard`](#remote_keyboard) is configured and `public_base_url` is set |
| `gpu_temp_alert_c` | int | `85` | |
| `disk_free_alert_gb` | int | `20` | |
| `poll_minutes` | int | `5` | `0` = no scheduled check |
| `idle_hours` | number | `0` | `0` = off; never sleeps the PC by itself |
| `wake_wait_minutes` | number | `4` | How long a wake waits for the PC to answer |
| `ai_tunnel_port` | int | `0` | Local port of the LM Studio tunnel; `ai.config.base_url` must be `http://127.0.0.1:<port>/v1` |
| `ai_remote_port` | int | `1234` | LM Studio's port on the PC (must match `permitopen`) |

## `ai_control`

`/aicontrol`: AI Mission Control on the gaming PC — services on/off, Start all /
Stop all, load/unload a model, switch an agent's model, game mode, and the
Tailscale share of each page. Guide: [WORKSTATION.md](WORKSTATION.md#ai-mission-control-aicontrol).
No config of its own: it borrows the [`workstation`](#workstation) plugin's agent
(`pc_agent()`), so it needs that plugin loaded and configured; without it,
`/aicontrol` says "not set up". Runs pc-agent's `summary`, `share <page> on|off`
and `mc …` actions (`core/pc_agent.py` checks every service and model name
against the agent's patterns before ssh starts). Changes run on a worker thread,
one at a time. No schedule, no state on disk.

Callback data: `ai_control:h` (main / refresh), `:m` (models), `:p` (pages),
`:am` (agents), `:ag:<tag>:<i>` (an agent's models), `:s:<service>:1|0`,
`:sa` (start all), `:xa` / `:xy` (ask / do stop all), `:g:1|0` (game mode),
`:ld:<tag>:<i>` (load), `:ul` (unload), `:us:<tag>:<agent i>:<model i>`,
`:sh:<tag>:<page i>:1|0`. `<tag>` is a checksum of the list the buttons were
drawn from (kept in memory); a list that is gone or changed is fetched and
shown again instead of acted on.

```yaml
- name: ai_control
  enabled: true
  config: {}
```

## `remote_keyboard`

The dashboard's **Remote** tab: type, press special keys and use a touchpad
on the PC from the phone, as real USB input through HIDway's relay on the same
host — set-up, the page and the security model are in
[WORKSTATION.md](WORKSTATION.md#remote-keyboard-and-mouse). Off unless the
plugin is enabled **and** `relay_host` is set (or `transport: local`);
for UDP, without `key` it sets nothing up unless `allow_plaintext: true`. No
Telegram command: `/pc` links to the page when nobody is logged in on the PC.

Two ways to the relay (`transport`). **Local socket** (relay v0.7.2+, HIDway
`docs/RELAY.md` "Local socket"): a `SOCK_SEQPACKET` connection to
`local_socket` that only members of the socket's group may open; packets go
in the clear (the relay takes no envelope there, and needs no allow-list
entry or key); the connection opens on arm, a lost one is closed and the next
input reopens it, disarming closes it (which also releases). **UDP**, as
below. `auto` (default) picks the socket when the relay's state file says
`local_socket=on` — or, for an older relay that does not say, when the socket
file exists — and it connects; otherwise UDP. Without `relay_host`, `auto`
never uses UDP; `local` never does. The log says once which way and why; the
Remote page, `/health`, `/access` and the read-only snapshot show it as one
word.

How it talks to the relay (`core/hidway.py`, a byte-exact copy of HIDway's
`common/protocol.h` and `common/hidway_crypto.c`): UDP to
`relay_host:relay_port` from a socket bound to `source_host`, one random
session per arm, complete keyboard/mouse states paced `key_interval_ms`
apart, sealed with XChaCha20-Poly1305 when a key is set; every action ends
with nothing held, then a RELEASE. Arming sends a PROBE (never forwarded to
the PC) and needs the relay's answer; every action needs the relay's
acknowledgement or the page says it may not have arrived. The rules — armed
window, allow-lists, caps, rate limit, never taking over from a live HIDway
client — are in `core/remote_input.py`; the key table and US layout in
`core/hid_keys.py`.

Health: one "Remote keyboard" check, read passively from the relay's state
file: a fault when settings do not load, the relay is not running, the
relay's encryption does not match the key setting (UDP), or the local socket
is off while it is the only way (`transport: local`); OK otherwise (with the
transport and whether the Pico is connected).

Dashboard API (session cookie; `Cache-Control: no-store` on every answer;
404 when not configured): `GET /remote`, `GET /api/remote/status`; JSON POSTs
`/api/remote/arm`, `/api/remote/key` `{key, mods[]}`, `/api/remote/text`
`{text, enter}`, `/api/remote/mouse` `{dx, dy, wheel, click, double}`; and
`/api/remote/disarm` (any body — the page's `sendBeacon` on leaving). Answers
are `{ok, state}` or `{ok: false, error, message, state}`; none contains what
was typed. Refusals: 400 bad input, 409 not armed / busy / another sender in
control, 415 not JSON, 429 too fast, 502 not acknowledged, 503 relay
unusable.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `transport` | string | `auto` | `auto` (socket when available, else UDP), `local` (socket only), `udp` (UDP only) |
| `local_socket` | string | `/run/hidway/inject.sock` | The relay's local socket (`HIDWAY_LOCAL_SOCKET`); empty = never use it |
| `relay_host` | string | — | The address `hidwayd` listens on (its `HIDWAY_BIND`); UDP only |
| `relay_port` | int | `47800` | `HIDWAY_PORT` |
| `source_host` | string | = `relay_host` | Address NetSentry sends from; must be in the relay's `HIDWAY_ALLOW_EXTRA` |
| `key` | string | — | 64 hex characters, the relay's `hidwayd.key`; use `${vault:HIDWAY_KEY}` |
| `allow_plaintext` | bool | `false` | Only for a relay without `--key-file` |
| `relay_state_file` | string | `/run/hidway/state` | Read to see whether the relay runs and who is in control |
| `idle_timeout_s` | number | `180` | Disarms after this long without input (15–3600) |
| `rate_limit_per_s` | number | `25` | Inputs per second (at most 60) |
| `max_text_chars` | int | `128` | Per send (at most 256) |
| `max_mouse_step` | int | `400` | Largest move per send, in mouse counts (at most 2000) |
| `key_interval_ms` | number | `10` | Pause between key states (4–50) |

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
five at a time). State file: `traces.json` (active traces). A trace hit arrives
as an `attention` message (it answers a question the owner set up, so it is
never dropped); "nobody asked, rule removed" is `info`.

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

Schedule: derived from `interval_minutes`. State: `health_monitor/state.json`,
`health_monitor/expected_restarts.json` and append-only
`health_monitor/alerts.jsonl`. The first failed-login sample is a baseline.
Disk checks are skipped when router stats are unavailable. A router reboot or
internet outage within 30 minutes of a `/restart` the owner asked for is not
reported as a surprise. "The router answers but its data can't be read" is a
`health()` check (`Router system data`); with `self_check` loaded the watchdog
alerts and recovers it, otherwise this plugin alerts itself.

## `pihole_stats`

Reads Pi-hole FTL SQLite statistics. Command: `/pi`. Config: `ftl_db_path`
(`string`, default `/etc/pihole/pihole-FTL.db`) and `stale_minutes` (`int`,
default `30`). No schedule or state file. Its health check fails when no DNS
query has been logged for `stale_minutes` or the database cannot be read —
threat detection and `/who` read the same database and would otherwise keep
running and find nothing.

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

The report and `/threats` open with the verdict (`🛡 Daily report — ⚠️ 2 to
review`), give one line per kind of finding (three subjects, then `+N more`)
and put everything else on buttons: `✅ Trust <domain>` (turns into `✔ Trusted
<domain>` once tapped), `🔎 Who asked?`, the Domains / Detectors / Finding log
screens, and — only when `lan_dashboard` has a public address — `🖥 Open in
dashboard` and one explainer per kind as URL buttons (the link carries the
dashboard token, so it is never printed). Bare `/allow` and `/deny` open the
trusted list; bare `/note` shows the domains with one line on how to label one.

## `speedtest`

Runs the installed speed-test CLI and reports the result. Command:
`/speedtest`. Config: `isp_nominal_mbps` (`number`, optional). No schedule or
state. Concurrent speed tests are rejected by an internal lock.

## `traffic_report`

Sends a daily `vnstat` traffic digest (English; sizes as `12 MB`). No command.

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
`/etc/pihole/pihole-FTL.db`). No state file. Its last lines are the self-check
summary and, with `site_watch` loaded, the sites line; the `🩺 Full check` and `📊 Network now` buttons sit under it.

## `channel_scan`

Runs a RouterOS 5 GHz neighbor scan and recommends a channel. Command: `/scan`.
Config: `scan_interface` (`string`, default `wifi1`),
`scan_duration_seconds` (`int`, default `10`), and `cron` (`string`, default
`30 4 * * 0`). The temporary router scan file is removed; there is no local
state file.

## `config_backup`

Copies the router's configuration to the NetSentry host every week, and on
`/backup`. Each run makes the settings as text (`router-<date>.rsc`, RouterOS
leaves passwords out of it) and tries the full backup (`router-<date>.backup`).

The full backup needs the `policy` permission on the router account. A
least-privilege account does not have it: the run then keeps the text export,
says that the full backup was not made, and stops asking the router each week
(`/backup` tries again, e.g. after you grant the permission). A run that yields
no export at all is a failed job: the owner is told and `/health` shows it.

Files this plugin left on the router are removed once a non-empty copy is on
the host. Retention never removes the newest file of each kind, and leaves full
backups alone while the router cannot make new ones.

Config: `backup_dir` (`string`, default `~/backups/router`), `retention_days`
(`int`, default `30`), `max_age_days` (`number`, default `8`), `binary_backup`
(`bool`, default `true`), and `cron` (`string`, default `0 3 * * 0`).

## `lan_scanner`

Builds a merged ARP/DHCP/WiFi inventory and manages persistent device names
(stored as "tags"; the owner reads "name / unnamed").
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

Serves the web dashboard opened with `/dashboard` (or `/lan dashboard`). Five
sections (six with Remote), laid out for a phone first:

| Section | What it shows |
|---|---|
| **Home** | One verdict that answers "does anything need me?" — an attack-level finding first, then a monitor that stopped (named), then findings to review, then unnamed devices, else "All clear" — with up to three tappable rows to the page that fixes it and one state picture matching the verdict. Below it: device counts, devices per WiFi network, and one line each for system health and the guest network |
| **Devices** | Every device live: traffic, name (else hostname), address, the network/band/signal it is on. Sorted "Unnamed first" by default (also Name A→Z, By network, Busiest now — re-sorted at most every 10 s). Tap a device to name it, mark it as no longer used, block it or port-scan it; a guest device can be told to keep its password (same as `/keep`). Block, "no longer used" and the keep switch need a second tap, like the Telegram buttons; the result shows next to the device |
| **Threats** | Findings, detectors on/off, domains with notes; trust a domain (a false alarm) or stop trusting it |
| **Library** | Saved videos and repositories |
| **System** | Is every monitor running (problems first), router load and uptime, Pi-hole totals for today, the guest password schedule and who keeps their own, and every scheduled job with its next run and how the last one went |
| **Remote** | Only when [`remote_keyboard`](#remote_keyboard) is configured: keyboard, special keys and touchpad for the PC, disarmed until you arm it |

Every page shares one status pill in the header — `live` (the Devices stream),
`updated 14:02`, or `⚠ offline — retrying`; on Remote `armed 2:41` /
`disarmed` (`NS.status.show`) — and one time format
(`Mon 23 Nov 09:00`, 24-hour, the year only when it is not this year; "14 min
ago" for the last 24 hours). The tab badges count only what needs you, the
same on every page: Threats = findings to review, System = failing checks,
Devices = unnamed devices; Library has none. `/api/overview` carries them as
`badges` together with the `verdict` (`level` `ok|review|attention|attack`,
`headline`, `reason`, `picture`, `items[{label, detail, href}]`).

The state pictures (`assets/states/`) are served by `/state/<name>.png` as a
256 px copy made once with Pillow and kept in the plugin state directory
(`state-pictures/`); without Pillow the original is served. Like every route
it needs the session cookie.

The System section is read-only: schedules are changed with `/settings` and
`/rotation`. It never shows a WiFi password. What it gathers (plugin health
checks, one router query, one Pi-hole query) is shared between open tabs and
refreshed at most every 30 seconds; a part that cannot be read is left out
rather than failing the page.

| Key | Type | Default | Notes |
|---|---:|---|---|
| `bind_host` | string | `auto` | Tailscale IPv4, else `127.0.0.1` |
| `public_host` | string | `auto` | Host included in the Telegram URL |
| `public_base_url` | string | empty | HTTPS address in front of the dashboard (e.g. `tailscale serve`); used for the links sent in Telegram |
| `bind_port` | int | `8088` | HTTP port |
| `poll_interval_s` | number | `15.0` | Router polling interval (never below 3 s) |
| `history_samples` | int | `120` | Samples retained per device |

It shares `lan_scanner/tags.json`. The dashboard token is kept in the plugin
state directory (owner-only) so a restart does not log you out; it is exchanged
once for an HttpOnly session cookie and checked with a constant-time
comparison. Every change is a POST, which the cookie's `SameSite=Lax` keeps
other sites from sending. `0.0.0.0` remains an explicit opt-in.

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
