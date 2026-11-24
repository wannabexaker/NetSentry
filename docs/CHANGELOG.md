# Changelog

All notable changes to NetSentry.

## [0.34.0] — 2026-11-24

### Added

- **AI Mission Control plugin (`ai_control`, `/aicontrol`).** The main controls
  of AI Mission Control on the gaming PC, buttons only, one message edited in
  place: one on/off button per service, `▶ Start all` / `⏹ Stop all` (Stop all
  asks once — it also unloads the model), `🎮 Game mode: on/off`; a **Models**
  screen (loaded model with `⏏ Unload`, every installed model with its size and
  `Load`, `🔁 Agent models` → agent → model); a **Pages** screen (full Tailscale
  links and the share switches of 0.33.0). Each action shows `⏳ <what>…` first
  (a model load says it can take a minute), runs on a worker thread, and ends on
  its screen with AI Mission Control's own Last action (✅ / ❌ + reason).
  Buttons for models, agents and pages carry a checksum of the list and an
  index — a list that changed or is gone is shown again, never acted on.
- `core/pc_agent.py`: `mc_service`, `mc_all`, `mc_load`, `mc_unload`,
  `mc_use`, `mc_game` (answer with the summary after the change) and
  `mc_models` (tolerant `McModels`: installed models with size, the models each
  agent may use, game mode). Every service / model name is checked against the
  agent's patterns before ssh starts; `run()` accepts an `mc …` action only when
  it matches a pattern whole. `mc` actions wait 150 s (a model load), `mc models` 20 s.
- `tools/pc-agent/pc-agent.ps1`: the `mc …` actions, as installed on the PC
  (every name compared against AI Mission Control's own lists; changes go
  through `Invoke-TrackedAction`, Source = netsentry).

### Changed

- `/pc` keeps status, wake (and "wake, then start <service>"), sleep / shut
  down / restart and cancel; its per-service start/stop buttons and
  `🧹 Free VRAM` are gone — they live in `/aicontrol` now (Stop all frees the
  GPU). `🤖 AI Mission Control` opens the new plugin in the same message.
  Buttons from older versions still work: the old `/aicontrol` ones open the
  new screens without acting, the old start/stop/VRAM ones show `/pc`.
- `/aicontrol` moved from `workstation` to `ai_control`, which has no config
  of its own and uses the workstation plugin's PC. **Add `- name: ai_control`
  (`enabled: true`, `config: {}`) to `config.yaml`**, or `/aicontrol` and its
  button disappear.

## [0.33.0] — 2026-11-24

### Added

- **Share an AI page over Tailscale from Telegram.** `/aicontrol` has one switch
  per page — `🔗 Share … on Tailscale` / `🚫 Stop sharing …` — that turns AI
  Mission Control's own Tailscale Serve sharing on or off (tailnet only), so
  the page's full link opens from the phone. The answer is the screen after the
  change, with "Last action" saying whether it worked and why not. Needs the
  new `share <page> on|off` action in pc-agent; the PC accepts only pages on
  AI Mission Control's own list. Starting the service behind a page stays on `/pc`.

## [0.32.0] — 2026-11-24

### Added

- **`/aicontrol` — AI Mission Control at a glance, read-only.** Shows what the
  PC's AI launcher says about itself: VRAM and RAM, the loaded model, the game,
  each AI service (🟢 running / ⚪ stopped, with its model; NetSentry itself is
  left out), each web page with its full Tailscale link and whether that link
  opens now (open on the PC *and* Tailscale sharing on), and the last action
  (✅ / ⏳ / ❌ with the reason). Also a `🤖 AI Mission Control` button on the
  `/pc` screen, and listed next to `/pc` in `/menu`. Buttons: `🔄 Refresh` and
  `⬅ PC` — no start/stop here.
- `core/pc_agent.py`: the read-only action `summary` (20 s) is on the allowed
  list, with `PcAgent.summary()` and a tolerant `parse_summary()` (unknown
  fields ignored; missing, null or oddly typed fields empty; text cleaned of
  control characters and capped; never raises).

### Notes

- Needs AI Mission Control 0.5.0+ and `summary` on the PC agent's own list.
  A PC that does not answer says so plainly (with `⚡ Wake` when Wake-on-LAN is
  set up); an agent or launcher that cannot give the summary is reported as too
  old — never a traceback or an old reading.

## [0.31.0] — 2026-11-21

### Added

- **Remote keyboard over the relay's local socket.** HIDway's relay (v0.7.2+)
  can take input on a local socket that only members of a group may open, so
  this host's own address no longer has to be in the relay's allow-list (where
  any program on the host could send keys). New `remote_keyboard` keys:
  `transport` (`auto`, the default: the socket when the relay has it switched
  on and it connects, else UDP as before; `local`: the socket only, never UDP —
  no `relay_host` or key needed; `udp`: as before) and `local_socket` (default
  `/run/hidway/inject.sock`, empty = never). Packets on the socket are always
  plain (the relay accepts no envelope there); a lost connection is closed and
  the next input reconnects; disarming closes it, which also releases.
- The way input goes is one word wherever the relay shows: the Remote page's
  status line (`via local socket` / `via UDP`), the `/health` line
  (`relay running (local)`), `/access` and the read-only snapshot
  (`reaches.hidway_transport`). The log says once which way is used and why.

### Notes

- Over UDP nothing changed: the same packets, byte for byte.

## [0.30.0] — 2026-11-21 — your web sites

### Added

- **`/sites` — are your web apps up?** A new `site_watch` plugin (off by
  default) asks each configured site's health address every 5 minutes —
  ideally `/healthz` answering `{"ok": true, "status": "ok", "version",
  "commit"}` — and shows one line per site: up or not, version and commit,
  response time, since when, and `no /healthz yet` for a site that only answers
  through its `fallback_url` or with a web page. `🔄 Check now` re-checks in the
  same message; each site has a detail button.
- A site that fails `fail_after` checks in a row (default 2) gives one alert
  (attention, not urgent — these are demos) and one recovery with how long it
  was down. The plugin sends the alert itself and hands the check to the
  self-check watchdog, which then sends no second alert and announces the
  recovery. A static page with no health route gets no `no /healthz yet` note. A new `version` or `commit` gives one FYI line: a deploy
  landed. A `paused` site (a demo stopped on purpose) is listed but never alerts.
- One line for the sites in the morning briefing.
### Changed

- "Raspberry Pi system updates" now says **needs attention** instead of
  "stopped working" — an update waiting is not something broken — and while
  one is waiting it is looked at every 30 minutes, so "back to normal" follows
  an upgrade soon instead of up to 6 hours later.

### Notes

- Requests go over IPv4 only, so a host with an IPv6 address but no IPv6
  route never tries (and waits on) an address it cannot reach.

## [0.29.3] — 2026-11-20

### Fixed

- Two `/guest` requests handled in the same second used one picture file, so the
  second could find it already deleted. Each QR picture now has a name of its own.

## [0.29.2] — 2026-11-20

### Fixed

- **`/guest` (and the rotation message) no longer vanish when Telegram is slow.**
  On 2026-11-20 the QR picture's upload timed out and nothing was sent — not the
  picture, not the password. A picture or message Telegram did not answer is now
  tried once more, and if the picture still cannot be delivered its words go out
  as a text message (password tap-to-copy), with a line saying the picture
  didn't go through. A message can, rarely, now arrive twice.

## [0.29.1] — 2026-11-20

### Changed

- **The disk check is a share of the disk, not only a fixed amount.** It used
  to complain below 500 MB free — far too late on an SD card that also holds
  container logs, images and backups. It now also fails above 85% full
  (`disk_max_used_pct`), and always says how full the disk is.

## [0.29.0] — 2026-11-20 — read-only access for another machine

### Added

- **A way for another machine to read NetSentry, and only read.** The mirror
  of the PC agent: an SSH key that this host pins to one small script
  (`tools/read-agent/netsentry_read.py`) accepting exactly four requests —
  `status`, `findings`, `alerts`, `health` — each answered as one line of
  JSON under 8 KB. Meant for an AI agent or a status card elsewhere on your
  network. The contract is in `docs/READ_ACCESS.md`.
- The script never touches the running service or any secret. A new
  `read_access` plugin (off by default) writes a cleaned snapshot once a
  minute; the script only prints from that file. It imports nothing outside
  the standard library, opens no connection and runs nothing.
- Everything that comes from the network (device names, domains, log lines)
  is stripped of control characters, capped in length, and scrubbed of
  tokens, passwords, links, home paths, public addresses and full MAC
  addresses before it is written. Consumers are told to treat every string as
  data, never as an instruction.
- **Alert journal.** Each unprompted message is recorded (time, kind, whether
  it rang, was silent or was not sent, first line only; last 200) — that is
  what the `alerts` request serves.

## [0.28.0] — 2026-11-20 — how to reach it

### Added

- **`/access` — everything needed to reach and manage NetSentry from another
  computer**, on one screen: the host and its addresses, the ssh line, the
  service with the three commands you actually use (status, restart, live
  log), where the code, config, vault, state and backups live, the
  repository, and what NetSentry can reach from where it runs (router, PC,
  HIDway relay). Commands and addresses are tap-to-copy. Buttons open the
  dashboard, the health check, a backup and the restart screen.
- **"New computer"**: the four steps to give another computer access. It is
  instructions only — NetSentry never adds a key itself and never accepts one
  through Telegram, because whoever held the Telegram account could then give
  themselves access.
- The screen shows addresses, paths and commands only: never a key, token,
  password, vault value, or the dashboard link as text.

## [0.27.0] — 2026-11-20 — a keyboard for the PC, from the phone

### Added

- **Dashboard → Remote: type and move the mouse on the PC from a phone**, through
  a HIDway relay running next to NetSentry (a hardware
  keyboard/mouse, so it works at the login screen). New `remote_keyboard`
  plugin; off unless it is configured. Text, the keys a phone keyboard lacks
  (with sticky modifiers and Ctrl+Alt+Del), and a touchpad.
- Built so a password can be typed there:
  keystrokes go phone → dashboard (over your own network, behind its session
  cookie) → relay; they never pass through Telegram, are never logged, stored
  or echoed back, and never appear in an address. Telegram only ever carries a
  button that opens the page.
- The page starts **disarmed**. Arming is explicit, enforced by the server,
  and ends by itself after a few idle minutes or when the page is left. Every
  input is checked against fixed lists and limits; text always ends with all
  keys released.
- It does not fight the relay's own client: it will not arm while that client
  is sending, and disarms itself if the client takes over.
- NetSentry speaks the relay's own encrypted protocol and requires the relay's
  key by default, so the relay keeps every check it already makes.
- `/pc` offers "Open remote keyboard" by itself when nobody is logged in.

Not yet exercised against real hardware — see the live-test steps in
`docs/WORKSTATION.md`.

## [0.26.0] — 2026-11-20 — the gaming PC

### Added

- **`/pc` — manage and watch a Windows PC from NetSentry.** New `workstation`
  plugin. One screen shows whether the PC is on, its GPU (temperature, load,
  memory, watts), RAM, disk, who is logged in, whether a game is running, the
  loaded model and each AI service. Buttons wake it (Wake-on-LAN through a
  relay when the PC is on another subnet), start and stop services, free the
  GPU memory, and sleep / shut down / restart it (two taps; shut down and
  restart can be cancelled for 15 seconds).
- **One tap from a cold PC to a running agent**: wake, wait until it answers,
  start the service, confirm it runs, offer a button that opens it. If nobody
  is logged in on the PC it says so and stops there.
- **It watches the PC** quietly: GPU too hot on two checks in a row, disk
  nearly full, the PC came on by itself, and (optional) left on with nothing
  to do — with a Sleep button, never automatically. A "Gaming PC" card on the
  dashboard's System page.
- **A key that can only run a fixed list.** NetSentry reaches the PC with an
  SSH key that the PC pins to one script (`tools/pc-agent/`): exact-match
  actions only, no shell, no file copy. NetSentry checks the same list before
  it calls ssh. See `docs/WORKSTATION.md`.
- **OpenAI-compatible AI provider** (`ai: provider: openai`) for LM Studio and
  similar servers, reached through an SSH tunnel that the same key is allowed
  to open and that NetSentry keeps up only while it is needed. The model
  server is never exposed on the network.

## [0.25.0] — 2026-11-20 — one voice

The last part of the UI/UX review: the convention in `docs/UI.md` applied to
every remaining Telegram screen.

### Changed

- **Every command has a short description in one style and its own emoji**
  (Telegram's "/" list and the /menu buttons); typed forms live only in
  `/help`, which now lists them for every command.
- **Lists lead with the device's name** and no longer rely on column alignment,
  which Telegram's font does not keep: `/lan`, `/clients`, `/kick`, `/who`,
  `/domains`. The address is shown for devices without a name.
- **The threat report starts with its verdict** (`🛡 Daily report — ⚠️ 2 to
  review`), one line per finding type, and ends in buttons. Dashboard links are
  buttons instead of long addresses in the text. Tapping Trust marks the button
  `✔ Trusted`. "Homelab Monitor" is gone — it is NetSentry everywhere.
- **Every button screen has the same last row** (Back / Menu) and the same
  Refresh; `/status`, `/clients` and `/wan` refresh in place; Settings → Guest
  WiFi opens in place with a way back.
- One vocabulary (name / unnamed, trust / stop trusting, finding, check), one
  date format with English day names whatever the host's language, a space
  before units.
- The traffic report is in English. The morning briefing leads with a verdict
  and ends in buttons. "X is back" messages follow the notification mode.
- Screens no longer show raw exception text; a failing check shows one short
  line of the error and the rest is in the log.

### Fixed

- `/status` no longer needs the router's port reading to say the internet is
  up: an answered ping is the internet working.
- Bare `/deny` replied `'' wasn't in your trusted list`; it opens the list.

## [0.24.0] — 2026-11-20 — alerts you can read, and act on

From the same UI/UX review; this is the Telegram half. The conventions are
written down in `docs/UI.md`, with shared helpers in `core/ui.py`.

### Changed

- **Alerts are text, not pictures.** Every alert used to carry a ~770 KB image
  with the text as its caption; a caption over 1024 characters made the send
  fail and the alert was lost, and a picture message cannot be updated by a
  button. Alerts now open with a state emoji and a bold first line. A message
  too long for Telegram is split instead of rejected. The guest WiFi QR code
  is still a picture — it is the content.
- **One problem, one alert, one recovery.** A plugin that tells you about its
  own failure no longer gets a second alert from the watchdog twenty minutes
  later, nor a third for the failed scheduled job, nor a fourth from the error
  log. `/health` and the dashboard still list every failing check. A recovery
  says how long the problem lasted.
- **Alerts end in a button for the obvious next step** (full check, try again,
  router log, restart the internet router when a smart plug is set up) instead
  of "type /status".
- **Three notification modes**, switched with buttons under `/settings` →
  🔔 Notifications and remembered across restarts (`notify_mode` in the config
  sets the default): *Relaxed* — only attacks and outages make a sound;
  *Normal* — problems make a sound, reports, recoveries and new devices arrive
  silently, routine successes are not sent; *Everything* — all of it, with
  sound. Replies to your own commands are never silenced.
- A restart you asked for with `/restart` is no longer reported as a surprise
  reboot or outage.
- A new device joining is announced with 🆕, not 🚨.
- `/start` and an unknown command open the menu instead of being ignored.
- The guest WiFi password is tap-to-copy. Formatting is opt-in per message,
  every inserted value is escaped, and if Telegram refuses the formatting the
  message is sent again as plain text.
- Failures say what did not happen and what is still true; raw exception text
  and command output are logged, not sent.

### Fixed

- **Block and Disconnect in Telegram never worked.** The device address was cut
  at its first colon, so the router always refused it — in `/kick` and under
  every new-device alert. Fixed, and because Block now really blocks it asks
  first, names the device, and leaves an Unblock button behind.
- Pausing a scheduled job took effect on one tap; it asks first now.
- `/rotate` asked a generic "Confirm: run /rotate?"; it asks the rotation's own
  question. The default confirmation list named a command that does not exist.

## [0.23.0] — 2026-11-20 — the dashboard says what needs you

From a UI/UX review of the whole product; this is the dashboard half.

### Changed

- **Home answers "does anything need me?" for everything, not only threats.**
  The verdict used to read green "All clear" while a monitor was down. It now
  goes: attack-level finding → a check that is failing (named) → findings to
  review → all clear, with up to three rows to tap. Devices without a name are
  a nudge, not a warning. One state picture, small, on this card only.
- **One status pill on every page** — live / updated 14:02 / offline, retrying.
  No page sits on "loading…" when a request fails.
- **Tab badges count only what needs you** (findings, failing checks) and show
  the same numbers on every page. The Threats badge used to switch to the
  number of domains on its own page.
- **Devices:** the name is the main line and the address is secondary; the
  whole identity area opens the edit panel; the list no longer reorders under
  your finger (default sort is unnamed first, then by name; "busiest now"
  re-sorts every 10 s); Block and "no longer used" take a second tap instead
  of a browser dialog; the result of an action is shown next to the device.
- **Same words everywhere:** unnamed / name it / no longer used / trusted.
  One date format (`Mon 23 Nov 09:00`, "14 min ago" within a day).
- Larger tap targets on touch screens; faint text now passes WCAG AA contrast.

### Fixed

- "known-bad feeds" was a count of domains; "1 devices keep their own".
- Pages built parts of themselves with `innerHTML`; they now use text nodes.

## [0.22.0] — 2026-11-20 — "it ran" is not "it worked"

Three faults were found in one night that had been hiding behind green health
checks. These checks look at results instead of activity.

### Added

- **Reading the router** (`/health`, dashboard → System). The router counts its
  own WiFi devices, DHCP leases and ARP entries; NetSentry compares that with
  what its parsers return. "The router lists 14 WiFi devices, NetSentry reads
  none" is now a problem you are told about, instead of looking like a quiet
  network. Also says when the router does not answer at all.
- **Error log.** Anything NetSentry writes to its log as an error counts as a
  problem for an hour (`error_window_minutes`), with the latest message — a
  job that catches its own exception no longer passes as healthy.
- **Pi-hole query log.** Threat detection and `/who` read Pi-hole's database;
  if Pi-hole stops writing to it they keep running and find nothing. The check
  fails when no DNS query has been logged for 30 minutes (`stale_minutes`) or
  the database cannot be read.

## [0.21.1] — 2026-11-20

### Fixed

- **The weekly router backup failed silently when the router account may not
  make a full backup.** With a least-privilege account RouterOS refuses
  `/system backup save` but still answers "success", so the run went on, could
  not copy a file that was never made, and stopped — leaving the text export
  on the router every week, never clearing old files, while `/health` stayed
  green because a new text export kept arriving. Now the run checks that the
  full backup file really exists; if the router refuses, it keeps the text
  export, says plainly that the full backup was not made (and which is the
  newest one it has), and stops asking the router every week — `/backup`
  tries again. Files left on the router by earlier runs are copied if missing
  and then removed. A run that produces no export at all is recorded as a
  failed job and shown by `/health`.
- Retention never removes the newest file of each kind, judges a file by the
  date in its name (a file copied late is still old), and leaves full backups
  alone while the router cannot make new ones.

## [0.21.0] — 2026-11-20 — a more complete dashboard

### Added

- **Dashboard → System.** A new section that answers "is everything running?":
  every monitor's health check with the problems first, router load, memory
  and uptime, Pi-hole totals for today, the guest password schedule with the
  devices that keep their own password, and every scheduled job with its next
  run and whether the last run worked. A red badge on the tab counts what
  needs attention.
- **Devices show where they are connected.** Each device carries its WiFi
  network, band and signal (weak signal is marked), the list can be narrowed
  to one network, and search matches the network name.
- **"Keep password" on a guest device**, next to Block — the same switch as
  `/keep`, with the same confirmation.
- **Home** now shows devices per network (tap one to open that network), one
  line for system health and one for the guest network.
- On a phone all five sections fit in the tab bar.

### Fixed

- Labelled values on the Home page ran together: the row they sit in had no
  layout rule.

## [0.20.0] — 2026-11-20 — guests who stay

### Added

- **`/keep` — guest devices that keep their password.** For the relative whose
  phone lives on the guest network: pick the device from buttons (only what is
  connected to the guest network right now is offered) and it keeps the
  password it has. When the password rotates, it stays connected; everyone
  else needs the new one. Nothing has to be done on the device (it reconnects
  for a moment when added), and it stays
  on the guest network. Removing a device takes a second tap. Also reachable
  from the `/rotation` screen, and the "new password" message names the
  devices that were not affected.
- `Router.keep_wifi_passphrase` / `release_wifi_passphrase` /
  `kept_wifi_passphrases`: one access-list rule per device with its own
  passphrase, placed first, read back after writing. The password is copied on
  the router and never passes through NetSentry.

### Fixed

- **Blocking a device on a network that has a catch-all access rule did
  nothing.** RouterOS applies the first rule that matches; the block was
  appended to the end of the list, below a rule accepting the whole network.
  Blocks now go to the top.
- **Unblocking a device removed every access rule for it**, not only the
  block.
- A `$` in a value sent to the router (a WiFi password, a name) was read by
  RouterOS as a variable and silently dropped. It is now escaped.

## [0.19.1] — 2026-11-20

### Fixed

- **Smart plug: "come back on after a power cut" was refused.** The setting was
  sent with a `+` for a space, which a Shelly does not read as one, so the plug
  answered HTTP 500 and the fix button under `/restart` → Internet router could
  not work. Found on the first run against a real Plug S G3; reading the plug's
  state was not affected.

## [0.19.0] — 2026-11-20 — where in the house is each device

### Added

- **`/where` — a rough position for every WiFi device.** New `locator` plugin.
  Without extra hardware it shows each device's distance from the router. With
  three or more ESP32 sensors at known spots it places devices on the floor
  plan and draws a map (🗺), with a circle for how unsure each position is.
  Fewer than three readings never get coordinates — the list then says "near
  the kitchen sensor". Only devices connected to your own network are shown.
  See `docs/LOCATOR.md`.
- **Sensor firmware** (`firmware/locator-sensor`, PlatformIO, ESP32 / ESP32-C3).
  The board joins your 2.4 GHz network, listens on that channel and answers
  `GET /rssi` with what it hears. It stores and sends nothing on its own.
- **`core/locate.py`** — the maths, pure and tested: log-distance signal model,
  calibration from the known distances between sensors (`fit_path_loss`,
  `fit_level`), and a position estimate computed as a probability map over the
  floor rather than a single intersection of circles.
- A sensor that stops answering is named in `/where` and reported by `/health`.

### Fixed

- **NetSentry saw no WiFi clients at all.** The client list was read from the
  router's column table, and RouterOS leaves out columns that do not fit an
  80-character line. Once one client's uptime grew to `19w5d12h26m24s`, the
  last column disappeared, the parser (which required it) matched nothing, and
  `/status`, `/lan`, new-device alerts and `/lan watch` all silently worked
  with zero WiFi clients. The list is now read from the `detail` form, the
  table parser no longer needs the last column, and "clients listed but none
  readable" is logged as an error instead of passing as an empty network.

## [0.18.0] — 2026-11-20 — restart the ISP router through a smart plug

### Added

- **`/restart` → "🌐 Internet router (smart plug)".** An ISP router usually has
  no way to be restarted remotely, so its power goes through a Shelly plug
  (Gen2 / Gen3 / Plus). The plug is told to switch off and switches *itself*
  back on after `off_seconds`, so the power returns even though the network is
  down meanwhile. The screen first shows what the plug reports (on/off, watts)
  and refuses to restart through a plug that would stay off after a power cut —
  with a button that fixes that setting. NetSentry reports once the internet is
  back. The button only exists when `isp_plug` is configured.
- **One narrow router forward for a plug NetSentry cannot reach.** When the
  NetSentry host sits outside the router (`via_router_port`), the router is
  asked for a single dst-nat rule: from this host only, that port only, to the
  plug only (`Router.port_forward_ensure`). It is created on first use and
  announced to the config-drift detector as an expected change.

## [0.17.0] — 2026-11-20 — tested library plugins, off-device backup copy

### Fixed

- **The "🏷 Tag" button under a new-device alert never worked.** A MAC address
  has colons of its own, and the button handler split its data on every colon,
  so it asked for a name for `AA` and then failed to save it. The `/lan watch`
  picker had the same fault (every pick answered "Stale"). Both now parse the
  MAC whole.
- **A damaged state file is no longer mistaken for an empty one.** Device names
  (`tags.json`), YouTube bookmarks and the saved-repository list were read with
  "any error means empty" — and the next save then overwrote what was there. An
  unreadable file is now moved aside as `<name>.corrupt`, reported in the log,
  and never written over. Those files are also written atomically.
- **`/yt` and `/gh` no longer crash when `yt-dlp` or `git` is missing.** The
  keyless oEmbed fallback for video titles existed but was never reached,
  because the missing-program error escaped first.
- **A failed or timed-out clone leaves nothing behind.** A leftover stub folder
  made the next attempt say "Already cloned" and register an empty repository.
- `/yt list 0` and `/gh list 0` listed everything instead of one entry.

### Security

- **A cloned repository is treated as untrusted content.** Repositories are
  checked out with symlinks disabled, and the README/manifest reader refuses
  links and anything outside the clone — a repo can no longer make a bundle
  carry some other file from the machine.
- **`/gh delete` only deletes inside the repositories folder.** The path comes
  from a JSON file; a wrong path in it now costs the list entry, not a folder.
- Clones run with `GIT_TERMINAL_PROMPT=0`: a private or misspelt repository
  fails at once instead of waiting for a password.

### Added

- **A backup copy that survives a dead disk.** `/snapshot` now has a
  "📤 Send me a copy now" button and a weekly on/off switch. The copy is the
  same archive **without the vault key**, sent to you as a Telegram document:
  nobody can read the secrets in it, and after a total loss everything but the
  secrets comes back from it. `/health` reports a weekly copy that failed or
  stopped going out. Off by default (`offsite_weekly`).
- **`/yt`, `/gh` and `/lan` as buttons.** `/yt` and `/gh` open the saved items
  as a paged button list, each with its own actions (open, mark watched,
  transcript / bundle, delete with a second tap). `/lan` gets buttons for the
  other views, the ping sweep and the dashboard, and the "not named yet" view
  has one button per device — tap it, reply with a name.
- **Paste a link, no command needed.** A message that is nothing but a YouTube
  link is saved; one that is a GitHub repository link asks "Save it?" first.
  (`save_pasted_links`, `offer_pasted_links`.)
- Randomised ("private") MAC addresses are recognised as such instead of being
  sent to the online vendor lookup.
- 144 new tests (267 → 411), most of them for `lan_scanner`,
  `youtube_bookmarks` and `github_explorer`, which had next to none.

### Changed

- **`threat_detector` is split by concern.** The 1,700-line module is now the
  detection cycle plus `taxonomy.py`, `store.py`, `sources.py`, `reports.py`,
  `api.py` and `telegram_ui.py`. Every method moved verbatim; behaviour is
  unchanged.
- Line endings are LF throughout (`.gitattributes`); 34 files had CRLF.

## [0.16.0] — 2026-11-19 — settings, restart, self-backup

### Added

- **`/settings` — move scheduled jobs from Telegram.** Lists the jobs worth
  moving (morning briefing, threat report, traffic report, router backup,
  NetSentry self-backup, channel scan, threat-feed refresh) with their schedule
  in plain words and next run. Tap one to pick a new time with the same
  frequency → day → hour → minute buttons as `/rotation`, pause it, or return it
  to its default. Changes apply live and persist
  (`scheduler/overrides.json`); `config.yaml` stays the default.
- **`/restart` — restart the router, the Raspberry Pi, or NetSentry.** Three
  buttons, each behind an "are you sure?"; NetSentry reports back when it
  returns from a restart it requested. Rebooting the Pi goes through a small
  root-owned systemd path unit (`deploy/netsentry-power.path` + `.service`),
  because the service itself is unprivileged; without the helper you are told
  so and nothing happens.
- **`/snapshot` and a weekly self-backup.** `self_backup` archives NetSentry's
  own config, vault and plugin state (not logs, clones or downloaded feeds) to
  `~/backups/netsentry`, owner-only, keeping the newest 8. The archive contains
  the vault key, like the live files it copies; it guards against a damaged or
  deleted file, not a lost disk.
- **OS updates in `/health`.** On Debian-family hosts the self-check reports
  pending security updates and a required reboot (apt is asked at most every
  six hours).

### Changed

- **Backup health follows the schedule you chose.** "Backup too old" is now
  derived from the job's actual interval (and is quiet while the job is
  paused) instead of assuming weekly.
- **The service unit unblocks the monitor adapter at start.** A USB WiFi
  adapter comes up rfkill soft-blocked after a reboot and the sandboxed service
  cannot lift that itself, which silently disabled `wifi_monitor`. The unit now
  has an `ExecStartPre=+…` line that clears it for `wlan1`.
- The schedule parser and button picker moved to `core/schedules.py` and are
  shared by `/rotation` and `/settings`.

## [0.15.1] — 2026-11-19

### Fixed

- **`/who` buttons now work for very long domain names.** Telegram limits a
  button's data to 64 bytes, so for a long name the "Catch it" button was
  silently left out. Long names now travel as a short reference.

## [0.15.0] — 2026-11-19 — "which device is asking for that?"

### Added

- **`/who` — pin a domain on the device that asks for it.** Pi-hole only knows
  the asker when a device talks to it directly; everything behind the router
  shows up as the router, so a flagged domain could not be traced to a device.
  `/who <domain>` (or the buttons: `/who` lists recently flagged domains, and
  findings in `/threats` and reports now carry a **Who asked?** button) answers
  in three steps:
  1. the devices that asked Pi-hole directly, by name;
  2. for lookups that came through the router, a comparison of the lookup times
     with the router's log of devices joining the network — a lookup that always
     follows the same device connecting gives it away immediately;
  3. **Catch it on its next request**: a passive, temporary logging rule on the
     router (mangle, `action=log`, matches DNS packets containing the name's
     most distinctive label) records the sender's MAC. You get a message when it
     fires; the rule removes itself an hour later, or after `trace_days` (7) if
     nothing asks. It blocks nothing, and is announced to the config-drift
     detector so it does not raise a tamper alarm.
  Enable with `who_asked` under `plugins:`. Router support is an optional
  capability (`Router.dns_trace_*`, `Router.join_events`), implemented for
  MikroTik; IPv4 UDP DNS only.

## [0.14.0] — 2026-11-19 — self-check, button menu, new threat feeds

### Added

- **`/health` and a watchdog — NetSentry now watches itself.** A monitor that
  has quietly stopped looks exactly like "nothing is happening". Every plugin
  can now report whether its work is *really* happening (`Plugin.health()`), and
  the new `self_check` plugin puts it together: `/health` lists every check,
  problems first, with a "Check again" button; a watchdog re-checks every 10
  minutes and messages you when something stops working (after two bad readings
  in a row, so a blip doesn't page you) and again when it recovers; the morning
  briefing gets one self-check line. Covered so far: WiFi attack monitor, threat
  detection cycle, malware-domain feeds, LAN open-port scan, detector settings
  reset, live dashboard polling, router config backup age, guest password
  rotation, Telegram connection, scheduled jobs whose last run failed, disk space.
- **`/menu` — every command as buttons.** Pick an area (Network, Security, Guest
  WiFi, System, Library), tap a command; it runs exactly as if typed, including
  the confirmation step for risky ones. The screens are built from the commands
  the loaded plugins register, so new plugins appear on their own.
- **Choices are buttons too.** `/scans` shows each detector with an on/off
  button; `/audit` offers 1 h / 6 h / 24 h / Off; `/allow` lists your trusted
  domains with a remove button each; and `/threats` and reports carry a
  **Trust <domain>** button under flagged domains, so dismissing a false
  positive is one tap instead of typing `/allow <domain>`.

### Changed

- **Threat feeds moved to sources that still exist.** abuse.ch retired its
  keyless URLhaus / ThreatFox host files (HTTP 410), which froze the list. The
  feeds are now URLhaus via the malware-filter mirror, HaGeZi Threat
  Intelligence Feeds (mini) and Phishing Army — all keyless, no account. A feed
  that fails keeps the entries it contributed last time, an error page can no
  longer be mistaken for a (tiny) blocklist, and the parsed list is cached in
  memory instead of being re-read every cycle.
- **Bare `/audit` shows the choices instead of switching audit mode on for
  24 h.** `/audit 24` (or the 24 hours button) does what bare `/audit` used to.
- Enable the new plugins by adding `self_check` and `menu` to `plugins:` in
  `config.yaml` (see `config.example.yaml`).

## [0.13.2] — 2026-11-19 — no more silent failures

### Fixed

- **The WiFi attack monitor no longer dies quietly.** If the adapter could not
  be put in monitor mode at start-up (rfkill-blocked after a reboot, unplugged,
  driver change) the plugin logged one warning and stayed off for the life of
  the process — which looks exactly like "no attacks". It now retries every
  `retry_seconds` (default 300), tells you once when the monitor is down (with
  the reason, and the rfkill hint when that is the cause) and once when it is
  back, re-initialises the radio after a long run of empty captures, and shows
  the reason in `/wifi`.
- **A stale malware feed is now reported.** A failed refresh correctly keeps the
  previous list, but a source that is gone for good left known-malicious
  detection matching against an ever older cache with only a log line. When the
  list is more than 7 days old you now get a warning (at most weekly).

## [0.13.1] — 2026-11-19 — pick the schedule with buttons; state that can't vanish

### Changed

- **`/rotation` is now button-only — nothing to remember or type.** The menu
  walks you through it one tap at a time: *Every day / week / month / Once a
  year* → the day (weekday, day of month, or month then day — only real dates
  are offered) → the hour → the minutes. Each step redraws the same message and
  has a Back button; nothing is applied until the last tap. *Never*, *Config
  default* and *Change the password now* are one tap. The typed forms still
  work, and a typo now answers with the buttons instead of only an error.

### Fixed

- **The threat detector could silently lose its state — including your
  allow-list and detector toggles.** Its state file is read-modified-written by
  several threads (the 10-minute scan, the daily report, the WiFi monitor,
  `/allow`, `/scans`, `/audit`), with a plain non-atomic write and a read that
  treated *any* failure as "first run". Two writers landing together (the scan
  and the report both fire on the hour) could leave a damaged file, and the
  next scan would then quietly re-baseline over it; a slow scan could also
  overwrite a change made while it ran. Now: writes are atomic (temp file +
  rename) under a lock; a scan writes back only the keys it owns onto the
  state as it is on disk at that moment; and a file that really is corrupt is
  kept as `state.json.corrupt` and reported as an error instead of being
  silently replaced.

## [0.13.0] — 2026-11-19 — choose when the guest password rotates

### Added

- **`/rotation` — set the guest-WiFi rotation schedule from Telegram, live.**
  `/rotation` shows the current schedule, the next and last rotation, and
  one-tap buttons: **Now · Daily · Weekly · Monthly · Yearly · Never**. For a
  specific moment, type it: `/rotation daily 07:30`, `/rotation weekly fri 18:00`,
  `/rotation monthly 15 08:30`, `/rotation yearly 24-12 20:00`, or
  `/rotation cron <m h dom mon dow>`. `/rotation never` stops automatic rotation
  (`/rotate` still works); `/rotation default` returns to `rotation_cron` from
  `config.yaml`. A change re-arms the running job immediately — no restart — and
  is stored in the plugin state dir so it survives restarts and deploys.
  "Now" asks for a second tap before it rotates.

### Fixed

- **Weekday numbers in cron schedules now mean what cron says.** Standard cron
  counts weekdays from Sunday (`0`/`7` = Sun, `1` = Mon), APScheduler from Monday
  (`0` = Mon), and nothing translated between them — so every schedule with a
  numeric weekday ran **one day late**: the documented "Mondays 09:00" rotation
  (`0 9 * * 1`) fired on Tuesdays, and the "Sunday" config backup and channel
  scan (`* * 0`) on Mondays. Numeric weekdays are now rewritten to names before
  scheduling. **Upgrade note:** those jobs move to the documented day.
- **`NS-CFG-001` no longer fires on the scheduled WiFi channel scan.** The scan
  re-provisions the radio just like a rotation does; it now announces itself
  (`router.config.expected_change`) and gets the same drift grace window.

## [0.12.7] — 2026-07-08 — the weekly rotation no longer self-alarms

### Fixed

- **`NS-CFG-001` no longer fires on NetSentry's own weekly guest-WiFi rotation.**
  Rotating the guest passphrase re-provisions the guest radios, which churns
  bridge / interface config for a while — so every week the router-config tamper
  alarm tripped on a change the system itself made. The threat detector now
  listens for the rotation's `wifi.password.rotated` event and opens a short
  grace window (3× the drift-scan interval) during which config drift is folded
  into the baseline silently. Changes *outside* the window still alarm, so
  genuine tamper detection is unaffected. Fully decoupled — the rotator already
  published the event; only the detector changed.

## [0.12.6] — 2026-07-06 — remember “no /ip accounting” across restarts

### Fixed

- **The `/ip accounting` probe no longer re-fires once per restart.** 0.12.3
  stopped the per-poll spam by disabling the probe after the router rejects it,
  but that flag lived only in memory, so every service restart (i.e. every
  deploy) re-probed once and logged a fresh `bad command name accounting` on the
  router. The dashboard now persists the "legacy menu absent" verdict to its
  state dir (`router_accounting_unavailable`) and, on start, skips the probe
  entirely when it's set — so on a RouterOS-v7 box the error appears at most
  once ever, then never again across restarts. Delete that marker file to
  re-probe (e.g. after moving to a router that supports `/ip accounting`).

## [0.12.5] — 2026-07-06 — running version visible from Telegram

### Added

- **`/status` shows the running NetSentry version.** The network dashboard now
  ends with a `🛡 NetSentry vX.Y.Z` footer, so you can confirm at a glance which
  build is actually live on the Pi — straight from Telegram, no SSH needed.

## [0.12.4] — 2026-07-06 — “that deauth wasn’t aimed at you”

### Added

- **`NS-WIFI-003` — “Deauth nearby, not your network” (info).** When the monitor
  sees a deauth/disassoc flood whose target BSSID is **not** one of your access
  points, it no longer just drops it silently — it raises a calm **info-level**
  (ℹ️, not 🚨) notice that says plainly *“seen nearby, but aimed at another
  network — this was NOT your Wi-Fi, nothing to do”*, with the target BSSID and
  signal/proximity. So instead of either a false alarm or radio silence, you get
  a one-line reassurance. `NS-WIFI-001` (attack on **your** AP) is unchanged, and
  a source spraying both your AP and a neighbour’s is still reported only as an
  attack, never double-counted as harmless. Needs a learned baseline; with none
  yet, everything still counts toward the attack path (fail-safe).

## [0.12.3] — 2026-07-06 — stop hammering the router

### Fixed

- **The LAN dashboard no longer floods the router with SSH logins.** Each poll
  opens ~5 sequential SSH sessions to RouterOS (WiFi traffic, WiFi clients, DHCP
  leases, ARP table, IP accounting). The old default `poll_interval_s: 2.0` meant
  ~150 router logins/minute, which under sustained load could wedge the router.
  The default is now **`15.0`**, and a **hard floor of 3 s** caps the worst case
  (~1 login/sec) even if the interval is misconfigured to `0`. Existing configs
  that set `poll_interval_s` explicitly are unaffected (any value ≥ 3 s is kept).
- **The `/ip accounting` probe no longer spams the router log every poll.** On
  RouterOS 7.x the legacy `/ip accounting` menu is usually absent, and the router
  prints `bad command name accounting` to the *session output* (stdout) with
  `rc=0` and an empty stderr — so the old guard, which only scanned stderr, never
  tripped and re-ran the failing command on every poll (filling the router log
  with `executing script from sshd failed`). Detection now scans **both** SSH
  streams for a failure signature and, as a final safety net, disables the probe
  after a few consecutive empty snapshots (the case where RouterOS logs the error
  only to its own log). Once disabled, it is not retried for the life of the
  process.

## [0.12.2] — 2026-07-04 — target-aware deauth detection

### Changed

- **`NS-WIFI-001` deauth detection is now target-aware.** It only counts
  deauth/disassoc frames whose BSSID belongs to *your* access points (matched by
  vendor OUI, so every band/radio counts), instead of every source on the
  channel — neighbour deauth noise on a shared channel no longer false-alarms.
  The finding now names the **target BSSID** and the **strongest signal (dBm)
  with a proximity hint**, so you can confirm it's really you and roughly locate
  the source. Guidance updated: the real mitigation is **802.11w / PMF (WPA3)** —
  blocking the spoofed source MAC does not stop an over-the-air deauth attack.

## [0.12.1] — 2026-07-04 — NS-EXP-002 default-cred false-positive fix

### Fixed

- **`NS-EXP-002` no longer false-positives on login-page reminders.** The
  default-credential heuristic previously matched phrases like "the login
  password is the default one — change it immediately", which Huawei and many
  ISP router login pages show as permanent boilerplate regardless of the real
  password (it flagged a live Huawei HG8145X6 whose password was actually
  strong). It now only fires when a page *exposes* actual default credentials
  (`admin/admin`, `Password: admin`, …), not when it merely reminds you to
  change them. Plaintext-admin port detection (telnet/ftp/VNC/RDP) is unchanged.

## [0.12.0] — 2026-07-04 — WiFi attack monitoring

### Added

- **`wifi_monitor` plugin — passive 802.11 attack detection.** With a
  monitor-mode USB adapter (e.g. RTL8821AU as `wlan1`) it watches management
  frames and raises:
  - **`NS-WIFI-001` deauth/disassoc flood** — someone spraying deauth frames to
    force your devices off WiFi (jamming / evil-twin setup);
  - **`NS-WIFI-002` rogue AP / evil-twin** — one of *your* SSIDs broadcast by an
    access point whose vendor (OUI) isn't your AP's, learned against a baseline
    (your own multiband/mesh BSSIDs are trusted; `allow_bssids` for exceptions).
  The radio handling + capture live in the plugin; the detection is pure and
  tested against real `tcpdump -e` output. Findings flow through
  `threat_detector` so they get the same dashboard cards, reports, and
  one-click explainers as every other NS-… finding. `/wifi` shows status.
- **`threat_detector.record_finding()`** — an ingestion API so sibling plugins
  can push findings (with dedup + immediate push + explain deep-link) into the
  unified pipeline.

### Notes

- Off by default. Enable with a `wifi_monitor` plugin block (`enabled: true`,
  `interface`, `protect_ssids`, `channels`). Needs a monitor-capable adapter
  dedicated to it, and — because the service runs with `NoNewPrivileges` — the
  systemd unit must grant `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`
  (monitor mode + capture) rather than relying on sudo.

## [0.11.0] — 2026-07-04 — active discovery, nmap tools, weak-service

### Added

- **Active LAN discovery.** The exposure scan no longer relies only on the
  router's live ARP cache (which misses sleeping IoT and other subnets): it now
  actively sweeps the configured `discovery_subnets` (nmap ping scan), unions
  with the ARP IPs, and port-scans the lot — so NetSentry finally sees the
  *whole* network, including a second `192.168.88.0/24`.
- **On-demand nmap from the dashboard.** A **🔍 Scan ports** button on each
  device card and a **Scan** button on IP findings run an unprivileged
  service/version scan (`POST /api/tools/nmap`, private-IPv4 only, single-flight)
  and show open ports + service/version inline.
- **`NS-EXP-002` weak / default-credential service.** The scan now flags hosts
  exposing plaintext admin services (telnet, ftp, rlogin, VNC, RDP) or a web
  panel still on its **default password** (HTTP banner heuristic).
- New `core/netscan.py`: a safe nmap engine (strict private-IPv4/CIDR
  validation, fixed argv, pure grepable parsers) shared by the detector and the
  dashboard.

### Notes

- `discovery_subnets` defaults to empty (ARP-only, unchanged) — set it to e.g.
  `["192.168.1.0/24", "192.168.88.0/24"]` to enable full discovery. nmap runs
  unprivileged (TCP connect), no extra sudo.

## [0.10.0] — 2026-07-04 — named findings + one-click explain

### Added

- **NetSentry finding taxonomy** — every finding type now has a stable,
  cite-able id like a CVE: `NS-MAL-001` (known-malicious), `NS-DNS-001` (DNS
  tunnel), `NS-ARP-001` (ARP spoofing), `NS-DHCP-001` (rogue DHCP),
  `NS-SCAN-001` (port scan), `NS-EXP-001` (new open port), `NS-CFG-001` (router
  config change), and more. Each carries a detection **confidence**, a **MITRE
  ATT&CK** technique, and — crucially — a **"common false alarms"** explainer.
- **One-click explain from Telegram.** Every alert and report line now shows its
  `NS-…` id and a deep-link that authenticates and opens a dashboard **explainer
  page** (`/finding/<id>`): what it is, why it matters, the usual false-positive
  causes, exactly what to do, and the live matches on your network — with a
  per-instance **"Trust (false alarm)"** button for domain findings. Kills the
  "is this real or noise?" guesswork.
- Explain links (`ⓘ`) on the Threats page detector chips and finding feed; a new
  `/api/taxonomy` and `/api/finding/<id>`; `/yt`-style report header link to the
  dashboard.

### Security

- The `/auth` deep-link accepts a `next=` target but it is **whitelisted to
  known local paths** (`_safe_next`) — no open-redirect via the parameter.

### Added

- **Config-drift detector (`config_drift`, default on)** — a router tamper
  alarm. Each cycle (throttled ~30 min) it reads `/export terse` (sensitive
  values stay hidden), normalises out the volatile header, and diffs against a
  stored baseline. Any change — a new firewall rule, user, port-forward, or
  service — raises a finding that names the affected sections and counts (never
  the raw config lines), then adopts the new state as baseline. If the router is
  ever tampered with, this is what tells you.
- **LAN exposure scan (`exposure`, opt-in — needs `nmap`)** — an nmap
  `--top-ports` sweep of the active LAN hosts (throttled daily), keeping a
  per-host open-TCP-port baseline and raising a finding when a device opens a
  port it wasn't serving before (e.g. an IoT gadget exposing telnet after an
  update). New attack surface, surfaced.
- **`/yt refresh [idx]`** — re-fetch metadata for bookmarks missing a title.

### Changed / Fixed

- **YouTube bookmarks now reliably capture the real title.** yt-dlp extractors
  go stale; added a keyless **oEmbed fallback** so a saved video gets its title
  and channel even when yt-dlp fails. The Library page shows real titles.

### Notes

- Both new detectors appear as toggleable chips on the Threats page and honour
  the recent-window verdict. `config_drift` needs only router `/export` (read);
  `exposure` needs `nmap` installed on the Pi and the scan enabled.

### Changed

- **The Home and Threats verdict now reflects what you should act on**, not the
  whole accumulated audit log. `threat_detector.api_recent_findings()` powers
  both `/api/overview` and `/api/threats/summary` and:
  - drops `new_domain` findings — that is domain *discovery*, already shown in
    the Threats domain table, not a threat (it was ~730 "warning" rows drowning
    the banner);
  - drops subjects you have trusted (allow-list);
  - keeps attack-severity for 7 days and everything else for 24 hours.
  The full history is still on `/threats` and via `/threatlog`.
- **Added `googleapis.com` to the default CDN/telemetry allow-list**, so the
  DNS-tunnel aggregator stops false-positiving on Google API sub-domain churn
  (alongside the existing `fbcdn.net`, `googlevideo.com`, `gstatic.com`, …).

## [0.8.0] — 2026-07-03 — dashboard redesign, Home, actions + Library

### Added

- **Home / overview page** (`/`) — an at-a-glance landing: a secure/review/alert
  verdict banner (links into Threats), device totals (total, active, untagged,
  blocked) with the current top talker, and threat + library counters. Backed by
  a new one-shot `/api/overview` aggregate. The device table moved to `/devices`;
  the tab bar is now Home · Devices · Threats · Library.
- **Act on a device from its card** — expand a device row for **Block** /
  **Unblock** (confirm-gated), wired to the router's WiFi reject access-list via
  new `/block` and `/unblock` endpoints and a `router.blocked_macs()` reader; a
  blocked device shows a red state on the card. The dashboard now *acts*, not
  only observes.
- **Library page** (`/library`) — your saved **YouTube videos** and **GitHub
  repos** as browsable cards with external links, live search, and counts.
  Backed by new read-only plugin APIs `youtube_bookmarks.api_bookmarks()` and
  `github_explorer.api_repos()`, exposed as auth-gated `/api/library/*` JSON
  endpoints that degrade to empty when a plugin is not loaded.
- **Summary stat strips** on every page (device/active/untagged/traffic on
  Devices; verdict/domains/findings/trusted on Threats; videos/repos/
  unwatched/watched on Library).

### Changed

- **Unified visual design system** (`static/app.css`): one OLED-dark theme with
  "green = secure / amber-red = threat" semantics, replacing the two divergent
  palettes (the Devices page was cyan, Threats was a separate green). System +
  system-mono fonts only — no external font CDN, consistent with the local-only
  privacy stance. SVG icons instead of emoji; WCAG-AAA contrast; visible focus
  rings; 44px touch targets; `prefers-reduced-motion` respected.
- **Shared app shell** with a **tab navigation** (Devices · Threats · Library)
  via a Jinja `base.html`, so the three pages are one coherent app instead of
  standalone screens. Device rows, live SSE, and tag editing are unchanged.

## [0.7.0] — 2026-07-03 — Threats & Domains web UI

### Added

- **Web interface for the domain journal & detectors** — a new
  **Threats & Domains** page in the LAN dashboard (`/threats`) to browse the
  full DNS-domain history comfortably: searchable/sortable table with per-domain
  **Trust** (allow-list) toggles and free-text **notes**, live **detector
  on/off** switches, a **recent-findings** feed, and **threat-intel** status
  with a one-click **feed refresh**. Reachable from a header link on the main
  dashboard; served over the same cookie-authenticated HTTPS session (no new
  ports, no new auth surface).
- **Public plugin API on `threat_detector`** powering the UI —
  `api_domains`, `api_set_allow`, `api_set_note`, `api_scans`, `api_set_scan`,
  `api_intel`, `api_findings`. The Telegram `/allow` and `/deny` commands now
  route through the same `api_set_allow`, so the web toggle and the chat command
  stay consistent.

### Changed

- The dashboard exposes read-through JSON endpoints under `/api/threats/*`,
  all behind the existing `_require_auth` session cookie; they degrade to empty
  payloads when the `threat_detector` plugin is not loaded.

### Fixed

- **Dashboard login no longer breaks on restart.** The session token is now
  **persisted** (owner-only file in the plugin state dir) instead of being
  regenerated on every process start, so a deploy, reboot, or crash no longer
  invalidates the owner's cookie and last `/auth` link (which surfaced as a
  sudden `403`).
- **Session cookie switched from `SameSite=Strict` to `SameSite=Lax`** so the
  link-based login survives the `/auth`→`/` redirect in Telegram's in-app
  browser. All state-changing endpoints are `POST`, which `Lax` still shields
  from cross-site CSRF, so this does not weaken the security model.

## [0.6.0] — 2026-07-02 — port-scan detection & least-privilege

### Changed

- **`port_scan` detector now uses RouterOS PSD** — reads a `port-scanners`
  address-list populated by passive `psd` firewall rules (RouterOS does the
  scan detection), instead of parsing firewall drop logs. No log flood; the
  router-side rules are non-blocking taggers.

### Deployment notes

Operational hardening applied to the live deployment in this cycle (router-side,
not code): NetSentry now connects to the router as a **least-privilege user**
(dedicated group without `policy`, the old full-admin user kept as fallback);
**rogue-DHCP** (`/ip dhcp-server alert`) and **port-scan** (`psd`) detectors are
wired to live router features; the dashboard is served over **HTTPS** via
`tailscale serve`.

## [0.5.0] — 2026-07-02 — detection UX, control & robustness

### Added

- **Router parse-break alert**: health_monitor now distinguishes "router
  unreachable" from "reachable but unreadable" and warns if a RouterOS
  output-format change likely broke parsing (so it never degrades silently).
- **Dashboard HTTPS** via `tailscale serve` (valid cert) + `public_base_url`;
  the dashboard binds loopback and is reached only through the encrypted proxy.
- **Greek technical docs** ([HOW_IT_WORKS.el.md](HOW_IT_WORKS.el.md)).

### Changed

- **`threat_detector` moved to report mode (no push on detection by default).**
  Scans run silently and record to the log + a new **domain journal**; a
  **report** is delivered on `report_cron` (default daily 09:00) and on demand
  with **`/report`**. `immediate_attacks: true` re-enables instant push for
  attack-severity findings only.

### Added

- **Domain journal** (`domains.json`): per-domain `first_seen`, `last_seen`,
  which client(s) asked, count, and your free-text note. Browse/search with
  **`/domains [text]`**, annotate with **`/note <domain> <text>`**.
- **`/audit <hours>|off`** — force `new_domain` on for a window to see what each
  device fetches; auto-reverts.
- **`docs/HOW_IT_WORKS.md`** — deep technical reference for every function,
  including what enabling `/ip dhcp-server alert` does for rogue-DHCP detection.

- `threat_detector` opt-in network detectors (off by default; each needs a
  router feature enabled): **rogue-DHCP** (unexpected DHCP servers vs an
  allow-list) and **port-scan** (a source hitting many distinct targets in the
  firewall drop log).

### Changed

- **`threat_detector` is now operator-controllable and self-explaining.** Each
  finding names *what it is and why it matters*; the digest groups by
  severity (🚨/⚠️/ℹ️) with per-device attribution. New commands: **`/scans`**
  (list every detector with its meaning + status, and `/scans <key> on|off` to
  toggle it live, persisted, no restart), **`/threatlog [n]`** (recent findings
  history), and **`/threats`** (a clear live summary, not raw alerts). The
  noisy **`new_domain`** detector is now **off by default**. Added a
  **`/dashboard`** command to open the live LAN dashboard.
- **`threat_detector` alerting is now a single digest per scan**, plain text and
  **no photo** — instead of one (image) message per finding, which spammed
  chat. New domains are summarised **per device** (which client asked, by IP /
  DHCP hostname) with examples, not one message each.
- **Device attribution**: findings now record and show the client IP(s) behind
  them (in the digest and in `alerts.jsonl`).
- Built-in **CDN/telemetry allow-list** (fbcdn.net, whatsapp.net, akamai, …) on
  by default, so benign churn (e.g. Meta's `netseer` UUID sub-domains) no longer
  triggers DNS-tunnel false positives. Toggle with `dns_allow_defaults`.

## [0.4.0] — 2026-07-02 — security hardening + detection

### Security

- **Fail-closed Telegram authorization.** An empty/absent `allowed_chats` now
  denies every command (was fail-open — anyone could drive the router); config
  validation refuses to start without a non-empty whitelist.
- **RouterOS command-injection hardening.** MAC addresses are validated against
  a strict pattern and file names / block comments are quoted, so no value can
  inject a second RouterOS command via `disconnect`/`block`/`unblock`/`export`/
  `delete`.
- **Dashboard: token out of the URL.** A one-time `/auth?token=` hop exchanges
  the token for an **HttpOnly, Secure, SameSite=Strict** session cookie and
  redirects to a token-less URL; the token no longer appears in page URLs,
  history, referrers, or API request lines. Default bind is loopback with TLS
  terminated by `tailscale serve`.
- **Destructive-command confirmation tier.** Commands in `confirm_commands`
  (default `/rotate`, `/reboot`) require an inline Confirm tap before running.
- **Per-chat rate limiting** (token bucket) on the bot dispatcher.
- **Callback sender verification** — the user pressing an inline button must be
  whitelisted, not merely the chat.

### Added

- CI (`.github/workflows/ci.yml`): ruff + pytest + bandit + pip-audit + gitleaks
  on every push/PR, plus Dependabot.
- **`threat_detector` plugin** — active detection over data NetSentry already
  sees: DNS tunnel/DGA (parent with many high-entropy sub-domains), high-abuse
  TLDs, and newly-seen-domain heuristics over the Pi-hole FTL DB, and ARP
  IP/MAC-conflict + MAC-change detection over the router ARP table. First run is
  a silent baseline; findings go to Telegram and `alerts.jsonl`; `/threats` runs
  an on-demand scan. (Also fixes the Pi-hole v6 `queries` view schema for `/pi`.)
- `docs/THREAT_MODEL.md` — adversarial threat model mapping threats to controls.
- CI generates a CycloneDX SBOM artifact on every run.
- Property-based (Hypothesis) fuzz tests asserting injection-safety invariants
  for the MAC validator and RouterOS quoting over arbitrary input.
- Release workflow: signed build-provenance attestation (keyless Sigstore) plus
  SBOM attached to each tagged release.
- Test suite expanded to 62 offline tests.

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
