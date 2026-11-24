# The gaming PC from Telegram (`/pc`)

The `workstation` plugin lets you see and manage a PC — typically a gaming or
local-AI PC — from Telegram, with buttons only: is it on, how hot is the GPU,
which AI services run; wake it, put it to sleep, shut it down or restart it. A
read-only card on the dashboard's System page shows the same picture. The AI
on the PC itself — services, models, game mode, page sharing — is the
`ai_control` plugin's [`/aicontrol`](#ai-mission-control-aicontrol), which
reaches the PC through this plugin.

## What you need

- A Windows PC with OpenSSH Server (key-only login) and, for the GPU line,
  an NVIDIA card (`nvidia-smi`).
- `tools/pc-agent/pc-agent.ps1` installed on the PC and NetSentry's key
  pinned to it — step by step in [tools/pc-agent/README.md](../tools/pc-agent/README.md).
- Optional: Wake-on-LAN working (checklist in the same README), a launcher
  module that starts/stops your AI services, LM Studio's server on the PC.

## Set-up from zero

1. **On the NetSentry host**, make the key:
   `ssh-keygen -t ed25519 -N "" -C netsentry-pc-restricted -f ~/.ssh/netsentry_pc_ed25519`.
   It must be readable by the user NetSentry runs as (and only by it).
2. **On the PC**, install the agent and authorize the key as described in
   `tools/pc-agent/README.md`. Test from the NetSentry host:
   `ssh -i ~/.ssh/netsentry_pc_ed25519 -o BatchMode=yes user@pc.example status`
   prints one line of JSON; any other command is refused. The first
   connection records the PC's host key (`StrictHostKeyChecking=accept-new`);
   a host key that changes later is refused, and `/pc` says so.
3. **In `config.yaml`**, enable the plugin:

   ```yaml
   - name: workstation
     enabled: true
     config:
       name: Gaming PC
       host: 192.0.2.40              # the PC, LAN or Tailscale address
       user: pcuser
       ssh_key: ~/.ssh/netsentry_pc_ed25519
       mac: AA:BB:CC:DD:EE:FF        # Wake-on-LAN
       wake_to: 192.0.2.1:9          # the router, which forwards UDP 9 to the PC
       services: [lmstudio, hermes, openclaw]
       wake_and_start: [hermes]
       links: {hermes: "https://t.me/<your_agent_bot>"}
   ```

   All keys are in [PLUGINS.md](PLUGINS.md#workstation). Restart NetSentry;
   `/pc` appears in the "/" list and under 🩺 System in `/menu`.
4. **Optional — the AI.** To let NetSentry use the model LM Studio serves on
   the PC, add `ai_tunnel_port: 11234` to the plugin and switch the AI block:

   ```yaml
   ai:
     provider: openai
     config:
       base_url: http://127.0.0.1:11234/v1
       model: gpt-oss-20b
   ```

   NetSentry opens `ssh -N -L 127.0.0.1:11234:127.0.0.1:1234` the first time
   the AI is asked for, re-uses it while it lives, and stops it on shutdown.
   While the PC is off the AI is simply "not available" (retries back off from
   30 s up to 15 min — nothing runs in the background meanwhile).

## The screen

The first line is the verdict: `🖥 Gaming PC — ✅ on`, `— 😴 off or asleep`
(normal, not a problem) or `— ⚠️ not answering as expected` (the PC answers
the network but refuses NetSentry's key, or its answer can't be read — see the
log). When on: GPU temperature, load, VRAM and watts; RAM; free space on C;
up-time; whether someone is logged in; whether a game runs; the loaded model;
and one line per service with its model and memory.

| Button | What happens |
|---|---|
| `⚡ Wake` | Sends the magic packet and waits (up to `wake_wait_minutes`) until the PC answers, then shows the screen |
| `🤖 Start Hermes` | Shown even while the PC is off, for each `wake_and_start` service: wake → wait → start → confirm it runs → `💬 Open Hermes` if a link is set. If nobody is logged in on the PC it stops there and says so: log in on the PC, then tap again |
| `😴 Sleep` | Two taps; confirmed only once the PC stops answering |
| `⏻ Shut down` / `🔁 Restart` | Two taps; happens in 15 s, with `✖ Cancel` until then |
| `🤖 AI Mission Control` | Opens [`/aicontrol`](#ai-mission-control-aicontrol) in the same message (shown when the `ai_control` plugin is loaded) |
| `🔄 Refresh` | Reads the PC again |

Every step edits the same message. When something fails, the message says what
did not happen and what state the PC is in.

## AI Mission Control (`/aicontrol`)

AI Mission Control is the launcher for the local AI on the PC: LM Studio (the
model server), the agents (Hermes, OpenClaw, OpenCode…), their web pages and
game mode. The `ai_control` plugin puts its main controls on one Telegram
message, buttons only. Open it with `/aicontrol`, from `🩺 System` in `/menu`,
or with `🤖 AI Mission Control` on the `/pc` screen.

Set-up: the `workstation` plugin above, configured, plus

```yaml
- name: ai_control
  enabled: true
  config: {}            # no keys — it uses the workstation plugin's PC
```

On the PC it needs **AI Mission Control 0.5.0 or newer** and pc-agent's
`summary`, `share <page> on|off` and `mc …` actions
([tools/pc-agent/README.md](../tools/pc-agent/README.md)). The links come from
the PC at run time — NetSentry stores no host name.

### Main

```
🤖 AI Mission Control 0.5.0 — 11:04
━━━━━━━━━━━━━━━━━
VRAM 1.5 / 15.9 GB · RAM 18.1 / 31.1 GB (42% free)
Model loaded: none
Game: none
Game mode: on — frees the GPU when a game starts

Services
🟢 LM Studio
🟢 Hermes — huihui-qwen3.5-35b-a3b-abliterated
⚪ OpenClaw — gpt-oss-20b
⚪ OpenCode — gpt-oss-20b

Pages
🟢 Hermes Dashboard — open · shared on Tailscale
   https://pc.example.ts.net:9119/
⚪ OpenClaw Web UI — not running · not shared
   https://pc.example.ts.net:18789/

Last action: ✅ Hermes is running (10:52)

[⏹ LM Studio] [⏹ Close Hermes]
[🚀 Open OpenClaw] [🚀 Open OpenCode]
[⏹ Stop all]
[🧠 Models] [🔗 Pages]
[🎮 Game mode: on]
[🔄 Refresh] [⬅ PC]
[🏠 Menu]
```

- LM Studio: `▶` starts it, `⏹` stops it.
- An agent (Hermes, OpenClaw, OpenCode): `🚀 Open` starts it together with its
  web page **and** shares that page on Tailscale, so its link works from the
  phone at once; `⏹ Close` stops sharing and stops it. There is no "start
  all": every agent at once would fill the GPU and the RAM.
- `⏹ Stop all` asks once — it also unloads the model, which frees the GPU.
- Pages say plainly what is wrong when a link won't open: "not running"
  (the service behind it is off), "not shared" (Tailscale sharing is off), or
  "shared — the link works once Hermes runs".
- Starting things runs in a process of its own on the PC, outside the SSH
  connection: Windows ends every process of an SSH session when it closes,
  which used to take a page helper (Hermes' dashboard) down right after it
  started. NetSentry itself is not listed.
- `🎮 Game mode` switches AI Mission Control's "free the GPU when a game
  starts" on or off.
- **Last action** is AI Mission Control's own: ✅ done, ⏳ running, ❌ failed with
  the reason (e.g. a port in use).

### Models

```
🤖 AI Mission Control — models
━━━━━━━━━━━━━━━━━
Loaded: gpt-oss-20b — 32k context · 100% GPU

Installed
🟢 gpt-oss-20b — 11.3 GB
⚪ huihui-qwen3.5-27b-abliterated — 15.4 GB

Agents
Hermes — huihui-qwen3.5-35b-a3b-abliterated
OpenClaw — gpt-oss-20b

[⏏ Unload]
[✔ gpt-oss-20b (loaded)]
[Load huihui-qwen3.5-27b-abliterated]
[🔁 Agent models]
[🔄 Refresh]
[⬅ Back] [🏠 Menu]
```

`Load` loads that model in LM Studio (the PC unloads the others first); it can
take a minute or two and the message says so while it runs. Tapping the model
that is already loaded does nothing. `🔁 Agent models` → pick an agent → pick a
model (the current one is marked `✔ … (now)`): AI Mission Control saves it and
restarts the agent if it runs; the Models screen then shows the change.

### Pages

Each web page with its **full Tailscale link** (tap it on the phone) and a
switch — `🔗 Share <page> on Tailscale` / `🚫 Stop sharing <page>` — that turns
AI Mission Control's Tailscale Serve sharing of that page on or off (only
devices on your tailnet can open it). A link opens only while the page is up
**and** shared — 🟢; 🟡 is open but not shared, ⚪ is closed, and both say
`link won't open now`.

### How it behaves

- Every action first shows `⏳ <what>…` in the same message, then the screen it
  belongs to, with the Last action line. One action at a time; a second tap
  meanwhile is answered "Still busy".
- Buttons for models, agents and pages point into the list that was on the
  screen. If that list changed on the PC (or NetSentry restarted), the tap does
  nothing but show the list again — `ℹ️ The list changed — nothing was done.`
- A PC that does not answer shows `💤 The PC isn't answering — it may be
  asleep or off.` with `⚡ Wake` (when Wake-on-LAN is set up). A PC whose
  agent or launcher cannot give the summary shows that AI Mission Control is
  too old for this, never an old reading. Without a configured `workstation`
  plugin, `/aicontrol` says it is not set up.
- Typed, the answer follows a `⏳ Asking the PC…` line; from a button it
  replaces it.

## What it tells you by itself

Every `poll_minutes` (default 5) it looks at the PC — one short ssh call,
nothing at all is sent while the PC is off:

- `ℹ️ Gaming PC — came on` when it was switched on and NetSentry did not wake it;
- `⚠️ Gaming PC GPU — hot, 88 °C` after two checks in a row at or over
  `gpu_temp_alert_c`, and `✅ … back to 62 °C` once;
- `⚠️ Gaming PC disk C — 12 GB free` under `disk_free_alert_gb`, and one ✅ when
  there is room again;
- with `idle_hours` set: `ℹ️ Gaming PC — idle for 2 h` with a `😴 Sleep` button
  when it sat on with no game, no model and an idle GPU. It never sleeps the
  PC by itself.

Each is said once; what was announced is kept in `workstation/watch.json`. If
the agent starts refusing the key, `/health` shows it and the watchdog alerts
once (and again when it recovers).

## The security model, in plain words

- **A key that can only run a fixed list.** On the PC, NetSentry's key is
  pinned to one script. Whatever NetSentry (or anyone holding the key) asks
  for, the PC runs that script, which compares the request against its list —
  `status`, `summary` (read-only), start/stop of the named services, free VRAM,
  sharing a page, AI Mission Control's `mc …` controls (only for names on AI
  Mission Control's own lists), sleep, hibernate, shut down, restart, cancel —
  and refuses anything else. No shell, no file
  copy, and only one port forward (to LM Studio on the PC's own loopback). The
  key only works from NetSentry's address (`from=`).
- **The same list on this side.** NetSentry refuses any action not on its own
  list before ssh even starts, and never builds a command from text you typed:
  every action comes from a button whose meaning is fixed in code.
- **Easy to take back.** Delete one line from the PC's `authorized_keys` and
  NetSentry can do nothing on the PC.
- **No keystrokes or passwords through Telegram.** NetSentry never types on the
  PC and never asks for or stores its password. Telegram messages are stored by
  Telegram and show up on every device signed into your account; a password
  sent there is a password shared. When a login is needed, `/pc` says so and,
  with the [remote keyboard](#remote-keyboard-and-mouse) set up, adds a
  `⌨️ Open remote keyboard` button: only that link travels through Telegram;
  what you type goes from the dashboard page to the PC and is never logged.
- **Off is not a fault.** A PC that does not answer is off or asleep; it is
  shown as such and never paged. Only a PC that answers but refuses or answers
  nonsense counts as a problem.

## Limits

- `sleep`/`hibernate` drop the connection by design; NetSentry confirms by the
  PC no longer answering (up to a minute).
- A woken PC usually boots to the login screen: services that run inside a
  user session (scheduled "at log on") cannot start until someone logs in.
- The GPU line needs `nvidia-smi`; other GPUs show no GPU line.

## Remote keyboard and mouse

The dashboard's **Remote** tab types and moves the mouse on the PC from your
phone — at the Windows login screen and in the BIOS too, because the input
arrives as a real USB keyboard and mouse. Typical use: `/pc` → `⚡ Wake` →
`⌨️ Open remote keyboard` → Arm → type the password (shown as dots) → Send →
`⏎ Enter`.

It needs HIDway (a separate project) — a relay
(`hidwayd`) on the same host as NetSentry and a Raspberry Pi Pico plugged into
the PC as its keyboard and mouse. NetSentry is one more sender to that relay
(`plugins/remote_keyboard.py`, `core/hidway.py`, `core/remote_input.py`).

### Set-up

1. **HIDway works on its own first** (its Windows client types on the PC).
2. **Encryption on the relay** (NetSentry refuses to send without a key unless
   you say otherwise). If `HIDWAY_EXTRA_OPTS` in `/etc/hidway/hidwayd.conf`
   has no `--key-file` yet, follow HIDway's `docs/RELAY.md`, "End-to-end
   encryption": make `/etc/hidway/hidwayd.key`, add `--key-file` and give the
   HIDway client the same key.
3. **Let this host send.** In `/etc/hidway/hidwayd.conf`, add the relay's own
   address (the `HIDWAY_BIND` value) to the allow-list, keeping what is there:
   `HIDWAY_ALLOW_EXTRA=<existing entries,>100.64.0.10` (comma-separated, at most
   8 peers in all), then `sudo systemctl restart hidwayd`.
4. **Give NetSentry the key** through its vault, not by file access (the
   `hidway` group that may read `hidwayd.key` can also open the Pico's serial
   device directly):
   as the user NetSentry runs as,
   `netsentry secret set HIDWAY_KEY "$(sudo cat /etc/hidway/hidwayd.key)"`
   (the key stays out of the shell history). Do this before step 5: a
   `${vault:…}` the vault does not have stops NetSentry from starting. Change
   it on both sides together when you rotate it.
5. **Enable the plugin** in `config.yaml` and restart NetSentry:

   ```yaml
   - name: remote_keyboard
     enabled: true
     config:
       relay_host: 100.64.0.10       # = HIDWAY_BIND
       key: ${vault:HIDWAY_KEY}
   ```

   The **Remote** tab appears in the dashboard, `/health` gets a "Remote
   keyboard" line, and `/pc` offers `⌨️ Open remote keyboard` whenever nobody is
   logged in (the dashboard needs `public_base_url` for that link).

All keys are in [PLUGINS.md](PLUGINS.md#remote_keyboard).

#### Through the relay's local socket instead (HIDway v0.7.2+)

Steps 2–4 put this host's address in the relay's allow-list, so *any*
program here can send keys, and keep a second copy of the key in NetSentry's
vault. The relay's local socket avoids both: only members of one group may
connect, and the packets never leave the host (no allow-list entry, no key).

1. Switch it on (HIDway `docs/RELAY.md`, "Local socket"):
   `sudo relay/deploy/install.sh --configure --local-socket hidway-inject`, then
   `sudo usermod -a -G hidway-inject <user NetSentry runs as>` and restart
   NetSentry (group membership is read at start).
2. With the default `transport: auto` nothing else is needed: once the relay
   says `local_socket=on`, NetSentry connects to `/run/hidway/inject.sock` and
   says so in its log (`sending over the relay's local socket …`); the Remote
   page shows `via local socket`. If the socket does not connect, `auto`
   falls back to UDP.
3. To stop using UDP for good, set `transport: local` (`relay_host`, `key`
   and `source_host` are then ignored), then take this host's address out of
   `HIDWAY_ALLOW_EXTRA` and restart the relay. With `local`, NetSentry never
   sends over UDP: if the socket is off or refuses the connection, the page
   says so and nothing is sent.

### The page

- **Arm / Disarm** with a countdown. Nothing reaches the PC while disarmed. It
  disarms after `idle_timeout_s` (3 min) without input, when you tap Disarm,
  and when you leave the page or switch away from the browser.
- **Type**: a password field (dots; `Show` reveals it). Default *send on
  Enter*: you see what you typed before it goes. `Send as I type` sends each
  change at once (deletions become Backspace). `Then press Enter` adds Enter.
- **Keys**: Esc, Tab, Backspace, Enter, arrows, Home/End, PgUp/PgDn, Delete,
  Space, Start, Menu, F1–F12, and `Ctrl+Alt+Del`, `Alt+Tab`, `Win+Space`
  (switch keyboard layout). Ctrl, Alt, Shift and Win stay on for the next key
  or the next single letter typed (Ctrl, then `c` = Ctrl+C).
- **Touchpad**: drag to move, tap to click, two-finger tap for a right click,
  two-finger drag to scroll; buttons for left/double/right/middle click and
  scrolling. The speed slider scales movement.
- The line under Arm says whether the relay runs, the Pico is connected, the
  PC is on/asleep/off, whether the link is encrypted (UDP), and the way in
  (`via local socket` / `via UDP`); the pill says who
  is in control (you, the HIDway client, nobody).

### The security model, in plain words

- **Keystrokes never touch Telegram.** Telegram only carries the button that
  opens the page. The page is the dashboard: reachable only on your Tailscale
  network, only with the dashboard's session cookie; every input is a POST
  with a JSON body (the cookie is `SameSite=Lax`, so other sites cannot send
  one), so no key ever appears in a URL or the browser history.
- **Nothing is kept.** NetSentry does not log, store or echo what you type or
  which keys you press — not in its log, not in error messages, not in the
  replies (they say "done", never what). The page stores nothing in the
  browser; every answer is marked `Cache-Control: no-store`. Python cannot
  wipe a string from memory: the text lives in the request until it is
  garbage-collected, like any form value.
- **Disarmed unless you arm it, on both sides.** The server keeps its own
  armed window; a request outside it sends nothing, whatever the page does.
- **Allow-lists everywhere.** Key names come from a fixed table, text is
  capped (`max_text_chars`) and must be typeable on a US keyboard, mouse
  steps are clamped, input is rate limited. Nothing from a request reaches a
  shell or a command.
- **No stuck keys.** Every action is complete states that end with nothing
  held, then a RELEASE — also when sending fails or you disarm mid-word. If
  NetSentry died mid-word, the relay and the Pico each release everything
  after 250 ms without input anyway.
- **HIDway's model stays.** The relay still checks the source address against
  its allow-list and, with a key, accepts only sealed packets
  (XChaCha20-Poly1305, replays refused by timestamp). The allow-list gains one
  entry, this host's own address, which nobody else on the tailnet can send
  from; with encryption on, a program on this host also needs the key, which
  only NetSentry's vault holds outside `/etc/hidway`. Over the local socket
  there is no allow-list entry and no key: the socket file's group decides
  who may send, and nothing crosses the network.
- **No fighting over the keyboard.** The relay serves one sender at a time and
  the newest session wins. NetSentry reads the relay's state file before
  arming and before every action: while the HIDway client is sending, the page
  says so and does not arm; if the client takes over, the page disarms. The
  client takes back control simply by arming.

### Limits

- **Keyboard layout.** A USB keyboard sends key positions; the PC's active
  layout turns them into characters. The page types as a US keyboard does, so
  with the Greek layout active, `a` arrives as `α`. Switch to English first
  (`Win+Space`), or make English the login screen's default. Characters a US
  keyboard has no key for (accents, Greek, emoji) are refused — nothing is
  half-typed.
- **No drag.** A click is press-and-release in one go; holding a button across
  moves is not supported (it would need the page to keep a button held).
- **Speed.** About 10 ms per key state: a 20-character password takes about
  half a second. Mouse moves go about 15 times a second, so the pointer feels
  slightly behind your finger.
- **Phone keyboards.** Some keyboards (Gboard predictions, Samsung) compose
  words before giving them to the page; with `Send as I type` text may arrive
  in bursts. *Send on Enter* is not affected.
- **Clock and encryption.** With encryption on, the relay refuses any packet
  not newer than the last one it accepted from *any* sender. If the HIDway
  client is open on a PC whose clock runs ahead of this host's, the relay can
  refuse NetSentry's packets for that difference (the page then says the relay
  did not confirm). Keep both clocks on NTP. At the login screen the client
  is usually not running.
- The relay's journal gets one `LINK TIMEOUT -> release all` line after each
  action (its normal end-of-input message) and a `new session` line per arm.
