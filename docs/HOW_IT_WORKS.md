# NetSentry — how every function works (technical)

This is the deep "what does it do and how, exactly" reference. For day-2 ops see
[OPERATIONS.md](OPERATIONS.md); for the adversary view see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## 1. Runtime & architecture

- **Process model.** `netsentry start` builds a `Runtime` (`core/runtime.py`) that
  loads config, opens the vault, constructs the router / notifier / AI clients,
  starts the APScheduler, discovers plugins, then hands control to `telegram_bot`
  which blocks on a long-poll loop. One process, several threads.
- **Threads.** (a) the Telegram poll loop; (b) a bounded `ThreadPoolExecutor`
  (default 4) that runs each command handler so a slow command can't freeze the
  bot; (c) APScheduler's pool for cron/interval jobs; (d) `lan_dashboard`'s HTTP +
  poll threads. Router **writes** are serialised by a re-entrant lock.
- **Plugins.** Everything user-visible is a plugin (`plugins/`). `loader.py`
  imports `netsentry.plugins.<name>` for each enabled entry in config, finds the
  `Plugin` subclass, builds a `PluginContext` (router, notifier, vault, logger,
  per-plugin `state_dir`, scheduler, event bus), calls `on_load()`, and collects
  `scheduled_tasks()`. A failing plugin is isolated — it can't kill the rest.
- **Config & secrets.** `config.py` loads YAML and expands `${vault:KEY}` /
  `${env:KEY}`; `vault.py` is a Fernet-encrypted key/value store (key file `0400`,
  ciphertext `0600`). Startup **validation** fails fast on missing keys or an
  empty Telegram whitelist.

## 2. Router layer (`core/router.py`) — how it talks to MikroTik

- **Transport.** SSH with an `ssh` ControlMaster socket (one login reused for
  many commands, so the router auth log isn't flooded). Every call is
  `self._ssh("<RouterOS command>")`.
- **Parsing.** RouterOS v7 `as-value` is unreliable on this firmware, so NetSentry
  runs normal `print` commands and parses the **pretty-print** output (grouping
  continuation lines into records, then splitting `key=value` fields).
- **Reads** (`stats`, `wifi_clients`, `dhcp_leases`, `arp_table`, …) return typed
  dataclasses; on SSH failure they return `None`/`[]` so callers can tell
  "unreachable" from "empty" (they never fabricate zeros).
- **Writes** (`set_wifi_passphrase`, `block_mac`, `export_config`, …) take the
  write-lock. All inputs are validated/quoted: MAC addresses must match a strict
  pattern and file names / passphrases are wrapped with `_routeros_quote`, so a
  value can never inject a second RouterOS command.
- **Guest passphrase (the P0 fix).** `set_wifi_passphrase` writes the security
  **profile** *and* every `/interface wifi` that references it (the inline
  `security.passphrase` overrides the profile), then **reads back** all of them
  and returns `True` only if they match.

## 3. Plugins — what each does & how

- **`telegram_bot`** — owns the loop. Registers every plugin's `COMMANDS` with
  Telegram, long-polls `getUpdates`, and dispatches each update on the worker
  pool. **Fail-closed authz**: a command/callback is dropped unless the chat *and*
  the button-presser are in `allowed_chats`. Per-chat token-bucket **rate limit**;
  destructive commands (`confirm_commands`) require an inline **Confirm** tap.
  Poll failures back off exponentially and are logged once (not per retry).
- **`guest_wifi_rotator`** (`/rotate`, `/guest`) — generates a diceware
  passphrase with the `secrets` RNG, calls `set_wifi_passphrase`, and only on a
  verified success sends the Wi-Fi QR. On failure it alerts instead.
- **`router_info`** (`/status /clients /wan /services /log`) — formats router
  reads for Telegram.
- **`security_actions`** (`/kick /security`) — inline keyboard to disconnect or
  block a client MAC (via the validated router writes).
- **`pihole_stats`** (`/pi`) — reads the Pi-hole **FTL SQLite** DB. On Pi-hole v6,
  `queries` is a *view* that already resolves domain/client to strings, so it
  queries those columns directly (no legacy `domain_by_id` join).
- **`health_monitor`** — every 5 min: internet ping, router uptime, disk, failed
  logins, new clients. First run sets a **silent baseline**; only genuine changes
  alert. Writes an append-only `alerts.jsonl`.
- **`threat_detector`** — active detection (see §4).
- **`lan_scanner`** (`/lan …`) — merges router ARP + DHCP + Wi-Fi into a per-MAC
  inventory with friendly-name tags (shared `tag_store`).
- **`lan_dashboard`** (`/dashboard`) — Flask app (see §5).
- **`speedtest`**, **`channel_scan`**, **`config_backup`**, **`traffic_report`**,
  **`morning_briefing`**, **`youtube_bookmarks`** (`/yt`), **`github_explorer`**
  (`/gh`) — periodic/utility plugins; `/yt` and `/gh` validate their URL argument
  against an allowlist and pass it after `--` so it can't be read as a flag.

## 4. threat_detector — detection internals

**Data sources (read-only):** the Pi-hole FTL DB (`SELECT DISTINCT domain, client
FROM queries WHERE timestamp > now-window`) and the router ARP table. Reverse-DNS
(`*.arpa`) and Pi-hole pseudo-entries are dropped as noise.

**Detectors** (pure functions in `detectors.py`, each unit-tested):

| Detector | How it decides |
|---|---|
| `dns_tunnel` | Groups high-entropy sub-domains by registrable parent; flags a parent with ≥ N (default 5) distinct random sub-domains, or any absurdly long FQDN. Aggregation, so one random CDN name never trips it. |
| `suspicious_tld` | Domain's TLD is in a high-abuse list (`.tk .top .zip .mov` …). |
| `new_domain` | Domain not in the baseline set. **Off by default** (browsing churn). |
| `arp_conflict` | One IP seen with two different MACs → spoofing/impersonation. |
| `arp_change` | An IP's MAC changed vs the stored baseline → possible MITM. |
| `rogue_dhcp` | A DHCP server on the LAN not on the allow-list (needs router alert). |
| `port_scan` | A source the router's `psd` firewall rules flagged (tagged into a `port-scanners` address-list — no log flood). |

A built-in **CDN allow-list** (`fbcdn.net`, `whatsapp.net`, akamai, …) suppresses
benign churn (e.g. Meta's `netseer` UUID sub-domains) from false-positiving.

**Delivery model (report mode — the default):**
- The scan runs on `interval_minutes` (default 10) but is **silent**: it records
  each new finding to `alerts.jsonl` and updates the **domain journal**
  (`domains.json`: `first_seen`, `last_seen`, `clients`, `count`, your `note`).
- A **report** is delivered on `report_cron` (default daily 09:00) *and* on demand
  with `/report`; it summarises the period from the log + journal, grouped by
  severity with per-device attribution.
- `immediate_attacks: true` (opt-in) additionally pushes attack-severity findings
  the instant they appear.

**Operator controls (all from Telegram, live, persisted — no restart):**

| Command | Does |
|---|---|
| `/report` | Detailed report since the last report. |
| `/threats` | Live scan of the current window right now. |
| `/threatlog [n]` | Last *n* recorded findings. |
| `/domains [text]` | Browse/search the domain journal (history + your notes). |
| `/note <domain> <text>` | Label a domain so you remember what it is. |
| `/scans` / `/scans <key> on\|off` | List detectors (with meanings) / toggle one. |
| `/audit <hours>\|off` | Force `new_domain` on for a window to see what each device fetches; auto-reverts. |

## 5. lan_dashboard — how the web UI is secured

Flask served by a background thread on the configured bind (loopback recommended).
Auth is a one-time `/auth?token=…` link that swaps the token for an **HttpOnly,
Secure, SameSite=Strict** session cookie and redirects to a token-less URL — so
the token never lingers in the URL, history, or request lines. Reach it over
Tailscale (WireGuard-encrypted); enabling `tailscale serve` adds real HTTPS.

## 6. Appendix — what enabling `/ip dhcp-server alert` does (for rogue-DHCP)

RouterOS can watch an interface for DHCP servers. You add an alert bound to your
LAN bridge and list the *legitimate* server (your router's MAC) as valid:

```
/ip dhcp-server alert
add interface=<lan-bridge> alert-timeout=1h \
    valid-server=<router-dhcp-server-mac> on-alert=""
```

From then on, if any **other** host answers DHCP on that interface, RouterOS
records an "unknown dhcp server" event (and can run `on-alert`). NetSentry's
`rogue_dhcp` detector reads those alert entries and — for any server IP not in
`dhcp_allowed_servers` — raises an attack-severity finding. Without this, there is
no DHCP traffic for NetSentry to see, which is why the detector is off by default.
It is a safe, read-only monitoring feature (it does not block anything); the only
caveat is choosing the right interface and valid-server MAC.
