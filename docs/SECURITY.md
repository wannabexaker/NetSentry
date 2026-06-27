# Operator security model

NetSentry can read network inventory and change router configuration. Treat the
Pi service account, Telegram bot, vault, and RouterOS SSH identity as privileged
components.

## Trust boundaries

- Telegram is the remote control plane. Only configured `allowed_chats` may
  dispatch commands or callbacks.
- The Pi service account can read local state and use the RouterOS SSH key.
- The RouterOS user defines the maximum router impact of a compromised service.
- The LAN dashboard exposes device metadata to anyone holding its current URL
  token and able to reach the bound socket.
- External tools (`git`, `yt-dlp`, `ping`, `vnstat`) are separate processes.

## Required controls

### Telegram

- Keep the bot token only in the encrypted vault.
- Configure an explicit chat-ID whitelist.
- Revoke and replace the bot token after suspected disclosure.
- Review unexpected commands in journald.

The whitelist reduces exposure but does not replace input validation.

### Vault

`secrets.enc` is Fernet-encrypted. `secrets.key` is the decryption authority.
Expected modes are `0600` and `0400` respectively. Back them up separately and
never commit either file. Never store both together off-box.

### Router SSH

- Use a dedicated least-privilege RouterOS v7 user.
- Restrict its source address to the Pi.
- Use a dedicated SSH key with no shared administrative purpose.
- Grant only permissions required by enabled plugins.
- Review router logs and disable unused mutating plugins.

Guest rotation needs read/write access to `/interface wifi security` and
`/interface wifi`. Router writes are serialized inside the process, but the
lock does not coordinate with other external administrators.

### systemd sandbox

The supplied unit enables `NoNewPrivileges`, `PrivateTmp`, strict system
protection, read-only home access, and explicit `ReadWritePaths`. Keep plugin
state, logs, and GitHub clones under `~/.local/share/netsentry`; keep config and
vault under `~/.config/netsentry`.

Any custom writable directory is an explicit sandbox expansion and should be
limited to the exact required path.

### LAN dashboard

The dashboard token is random per process and compared in constant time. It is
included in the URL, so browser history, screenshots, proxies, and chat access
can expose it. Restart NetSentry to rotate the token. Restrict network access
with UFW/Tailscale and avoid public or broad LAN exposure. Use `0.0.0.0` only
after reviewing the firewall.

### Subprocess inputs

YouTube accepts only full HTTP(S) URLs for `youtube.com` or `youtu.be`. GitHub
accepts only GitHub HTTP(S) URLs or `owner/repo`, then constructs the canonical
clone URL. Both pass user values after `--` to stop option parsing. Keep the
chat whitelist even with these controls.

## Data handling

Plugin state may contain MAC addresses, hostnames, URLs, repository metadata,
router log samples, and security alerts. Router backups may include the full
network configuration. Restrict state and backup permissions, encrypt off-box
copies, define retention, and do not attach raw files to public issues.

## Incident actions

1. Stop the service if router control may be compromised.
2. Revoke the Telegram token and RouterOS SSH key.
3. Rotate vault secrets and the vault master key.
4. Review journald, `alerts.jsonl`, RouterOS logs, and recent configuration.
5. Restore from a known-good router backup if required.
6. Restart only after credentials and access boundaries are verified.

For vulnerability reporting policy, see the repository-root `SECURITY.md`.
