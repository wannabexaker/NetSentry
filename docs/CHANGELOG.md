# Changelog

All notable changes to NetSentry.

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
