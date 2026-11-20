# The gaming PC from Telegram (`/pc`)

The `workstation` plugin lets you see and manage a PC — typically a gaming or
local-AI PC — from Telegram, with buttons only: is it on, how hot is the GPU,
which AI services run; wake it, start or stop a service, free graphics memory,
put it to sleep, shut it down or restart it. A read-only card on the
dashboard's System page shows the same picture.

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
| `▶ Start X` / `⏹ Stop X` | One tap. A start that needs a logged-in user says so plainly |
| `🧹 Free VRAM` | Asks the launcher to free graphics memory and shows how much is used after |
| `😴 Sleep` | Two taps; confirmed only once the PC stops answering |
| `⏻ Shut down` / `🔁 Restart` | Two taps; happens in 15 s, with `✖ Cancel` until then |
| `🔄 Refresh` | Reads the PC again |

Every step edits the same message. When something fails, the message says what
did not happen and what state the PC is in.

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
  `status`, start/stop of the named services, free VRAM, sleep, hibernate,
  shut down, restart, cancel — and refuses anything else. No shell, no file
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
  sent there is a password shared. When a login is needed, `/pc` says so; a
  later feature may open a remote keyboard through the dashboard (over your
  private network, never logged) — `remote_keyboard_url` is the hook for that
  and only adds a button.
- **Off is not a fault.** A PC that does not answer is off or asleep; it is
  shown as such and never paged. Only a PC that answers but refuses or answers
  nonsense counts as a problem.

## Limits

- `sleep`/`hibernate` drop the connection by design; NetSentry confirms by the
  PC no longer answering (up to a minute).
- A woken PC usually boots to the login screen: services that run inside a
  user session (scheduled "at log on") cannot start until someone logs in.
- The GPU line needs `nvidia-smi`; other GPUs show no GPU line.
