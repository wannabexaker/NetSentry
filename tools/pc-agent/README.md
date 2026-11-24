# pc-agent: what NetSentry may do on a Windows PC

`pc-agent.ps1` is the only program NetSentry's key can run on the PC. NetSentry
connects with ssh and asks for one action by name; the script compares the
request, whole, against a fixed list and refuses anything else (exit code 64).
No shell, no file copy, no other port forward.

| Action | What it does | Answer |
|---|---|---|
| `status` | Up-time, logged-on user, RAM, disk C, GPU, game, models, services | one JSON object |
| `summary` | AI Mission Control's own summary (`Get-MissionControlSummary`, 0.5.0+): VRAM/RAM, loaded model, game, services, pages with links, last action — read-only | one JSON object |
| `start <id>` / `stop <id>` | Starts/stops one service through your launcher module | `{"ok","id","running","reported","reason"?}` |
| `free-vram` | Asks the launcher to free graphics memory | `{"ok","gpu"}` |
| `sleep` / `hibernate` | Answers `{"ok":true}`, then the PC sleeps (the connection drops) | |
| `shutdown` / `restart` | Happens in 15 s | `{"ok":true,"in_seconds":15}` |
| `cancel` | Aborts a pending shutdown/restart | `{"ok":true}` |

The same key may open exactly one local forward, to `127.0.0.1:1234` on the PC
(LM Studio's OpenAI-compatible server), so NetSentry can use the model.

## Install

Everything below runs in an **elevated** PowerShell on the PC. It assumes
OpenSSH Server is installed and key-only (`PasswordAuthentication no` in
`C:\ProgramData\ssh\sshd_config`).

1. **A folder only administrators can change.** The script runs with the
   rights of the account NetSentry logs in as; if anyone else could edit it,
   they could make it do anything.

   ```powershell
   New-Item -ItemType Directory -Force C:\ProgramData\NetSentry | Out-Null
   Copy-Item .\pc-agent.ps1 C:\ProgramData\NetSentry\
   icacls C:\ProgramData\NetSentry /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
   ```

   (`S-1-5-32-544` = Administrators, `S-1-5-18` = SYSTEM — by SID so it works
   in any Windows language.)

2. **Edit the settings block** at the top of the copy: `$Core` (your launcher
   module, or leave it pointing nowhere), `$Services` and `$NeedsLogin`. The
   service ids must match `services` in NetSentry's workstation config.

3. **Make a key on the NetSentry host** (no passphrase — it is restricted
   instead):

   ```sh
   ssh-keygen -t ed25519 -N "" -C netsentry-pc-restricted -f ~/.ssh/netsentry_pc_ed25519
   ```

4. **Authorize it, pinned to the script.** For an account in the
   Administrators group the file is `C:\ProgramData\ssh\administrators_authorized_keys`
   (it must stay readable only by Administrators and SYSTEM); for a standard
   account it is `C:\Users\<user>\.ssh\authorized_keys`. One line:

   ```
   restrict,port-forwarding,permitopen="127.0.0.1:1234",from="<netsentry host>",command="powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\NetSentry\pc-agent.ps1" ssh-ed25519 AAAA...your-public-key... netsentry-pc-restricted
   ```

   - `restrict` turns off everything (shell, PTY, agent/X11 forwarding, all
     port forwards); `port-forwarding` + `permitopen` turn back on exactly the
     one forward to LM Studio. Leave both out if you don't want the AI part.
   - `from="…"` is the NetSentry host's address as the PC sees it (its LAN or
     Tailscale address, e.g. `192.0.2.10`). The key is useless from anywhere else.
   - `command="…"` runs the script whatever the caller asks for; the request
     only reaches it as `SSH_ORIGINAL_COMMAND`.

5. **Test from the NetSentry host:**

   ```sh
   ssh -i ~/.ssh/netsentry_pc_ed25519 -o BatchMode=yes user@pc.example status
   ssh -i ~/.ssh/netsentry_pc_ed25519 -o BatchMode=yes user@pc.example whoami   # must be refused
   ```

The script logs every action (never the text of a refused request) to
`C:\ProgramData\NetSentry\agent.log`.

## Remove access

Delete the key's line from the `authorized_keys` file. Nothing else is needed;
the folder can be deleted too.

## Wake-on-LAN checklist

Waking the PC from Telegram needs all of these:

- **BIOS/UEFI:** "Wake on LAN", "Power On By PCI-E" or similar enabled; "ErP"/
  deep-sleep power saving disabled (it cuts power to the network card).
- **Network card** (Device Manager → the adapter → Advanced / Power Management):
  "Wake on Magic Packet" on, "Allow this device to wake the computer" on, and
  "Only allow a magic packet to wake the computer" on — otherwise ordinary
  network traffic can wake it at night. "Wake on pattern match" off.
- **Fast Startup off** (Control Panel → Power Options → "Choose what the power
  buttons do"). With it on, "shut down" is a half-hibernation in which many
  cards ignore the magic packet.
- **A fixed address:** a static DHCP lease for the PC's MAC, and on a router
  that relays the packet, a static ARP entry — a sleeping PC does not answer
  ARP, so the router would not know where to send it.
- **Another subnet?** A broadcast from NetSentry does not cross the router. Set
  `wake_to` to the router and forward UDP port 9 on it to the PC's address (on
  RouterOS: a `dst-nat` rule for UDP 9 to the PC, plus the static ARP entry).
  On a flat network, `wake_to` can simply be the broadcast address.
- Test: put the PC to sleep, then tap ⚡ Wake in `/pc`.
