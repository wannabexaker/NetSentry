# NetSentry threat model

Scope: NetSentry running as a systemd service on a Raspberry Pi, controlling a
MikroTik router over SSH and reading Pi-hole data, operated over Telegram and a
LAN dashboard. This complements [`SECURITY.md`](SECURITY.md) (operator controls)
with the adversarial view.

## Assets

| Asset | Why it matters |
|---|---|
| RouterOS SSH key + least-priv user | Full effect an attacker can have on the network |
| Telegram bot token | The remote control plane; token = command authority |
| Vault master key (`secrets.key`) | Decrypts every stored secret |
| Pi-hole FTL DB | DNS history of the whole household |
| Dashboard session token | Read access to live device inventory/traffic |
| Router config backups | The entire network configuration |

## Trust boundaries

1. **Telegram → bot.** Untrusted senders reach the bot; only `allowed_chats`
   are trusted. Fail-closed.
2. **Browser → dashboard.** Untrusted until it presents a valid session cookie.
3. **Bot process → router.** The SSH user bounds the blast radius.
4. **Plugins → external tools** (`git`, `yt-dlp`): user-supplied arguments cross
   into subprocesses.

## Adversaries

- **Remote, no credentials** — finds the bot / dashboard, tries to command it.
- **On-path LAN attacker** — ARP/DHCP spoofing, rogue AP, DNS tunnelling.
- **Compromised client** — malware beaconing / exfil over DNS.
- **Local unprivileged user on the Pi** — tries to read secrets or the SSH key.

## Threats → mitigations (STRIDE-flavoured)

| Threat | Mitigation | Status |
|---|---|---|
| **Spoofing** the operator (unauthorized commands) | Fail-closed `allowed_chats`; callback sender (`from.id`) verified; refuse to start without a whitelist | ✅ |
| **Tampering** via command injection into RouterOS | MAC validation + `_routeros_quote` on every mutating sink | ✅ |
| **Repudiation** / no trail | Append-only `alerts.jsonl`; commands logged to journald | ✅ |
| **Information disclosure** — dashboard token in URL | One-time `/auth` → HttpOnly/Secure/SameSite cookie; token never in URL/logs | ✅ |
| **Information disclosure** — secrets at rest | Fernet vault, key `0400`, ciphertext `0600`, systemd `ProtectHome` | ✅ |
| **Denial of service** — command flooding | Per-chat token-bucket rate limit; bounded worker pool | ✅ |
| **Elevation** — bot process escaping its sandbox | `NoNewPrivileges`, `ProtectSystem=strict`, scoped `ReadWritePaths`, `PrivateTmp` | ✅ |
| **Destructive fat-finger / hijack** | Confirmation tier on destructive commands | ✅ |
| **On-path LAN attack** (ARP spoof / MITM) | `threat_detector`: IP/MAC conflict + MAC-change detection | ✅ detect |
| **DNS exfil / DGA / malware C2** | `threat_detector`: tunnel aggregation + high-abuse TLDs + newly-seen domains | ✅ detect |
| **Supply-chain** — vulnerable/backdoored dependency | CI: `pip-audit`, `bandit`, `gitleaks`, Dependabot, SBOM | ✅ |
| **Transport interception** (dashboard) | Tailscale WireGuard tunnel (always) + optional `tailscale serve` TLS | ◑ TLS pending tailnet HTTPS toggle |

## Residual risks (accepted / roadmap)

- **Router transport is SSH + pretty-print parsing.** A firmware change can
  break parsing; the SSH user is broad. Roadmap: RouterOS REST API + scoped
  token (least privilege). *(Phase 3, not yet done.)*
- **Detection is heuristic.** Tunnel/DGA and ARP signals can miss slow or novel
  attacks and can false-positive; first run baselines silently to limit noise.
- **Rogue-DHCP / deauth / port-scan** detection needs router-side features not
  yet wired.
- **Telegram is a third party.** A Telegram-side compromise or a leaked token is
  outside NetSentry's control; mitigated by whitelist + confirmation + rotation.

## Reporting

Vulnerabilities: see the repository-root `SECURITY.md` reporting policy.
