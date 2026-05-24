# Security Policy

NetSentry is built around access to routers and home networks. Handle
discovered vulnerabilities accordingly.

## Reporting a vulnerability

Please **do not** open public GitHub issues for security problems.

Instead, open a private **security advisory** on the repository:

  https://github.com/wannabexaker/NetSentry/security/advisories/new

Include:

- A clear description of the issue
- Steps to reproduce
- Affected version (`netsentry --version`)
- Suggested fix if you have one

You will receive an acknowledgement within a reasonable timeframe.

## Scope

| In scope | Out of scope |
|---|---|
| Vault decryption bypass | Compromised host OS |
| Plugin sandbox escape | Stolen Telegram bot token |
| SSH key disclosure | User-misconfigured router rules |
| Privilege escalation via systemd unit | Third-party Python dependencies (report upstream) |

## Operating guidance

- The encrypted vault key (`~/.config/netsentry/secrets.key`, mode 400) must
  never be copied off the host alongside `secrets.enc`. Together they
  decrypt every secret you stored.
- Rotate the Telegram bot token from [@BotFather](https://t.me/BotFather)
  if you suspect compromise. Replace via `netsentry secret set
  TELEGRAM_TOKEN …`.
- The router SSH user used by NetSentry should be source-IP restricted to
  the host running NetSentry. See `docs/INSTALL.md` Step 1.
- Treat `youtube_bookmarks` and `github_explorer` plugins as outbound:
  transcripts and source code are sent to whatever AI endpoint
  `ai.config.host` resolves to. Use a local model when in doubt.
