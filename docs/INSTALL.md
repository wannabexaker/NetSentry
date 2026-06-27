# Installation

This is the supported installation path for a Raspberry Pi or Debian host
running Python 3.11 or newer.

## 1. Prerequisites

- A RouterOS v7 router using `/interface wifi` (`wifi-qcom` on the live
  deployment).
- A dedicated, least-privilege RouterOS SSH user restricted to the Pi source
  address.
- SSH key authentication from the Pi to the router.
- A Telegram bot token and the operator chat ID.
- Tailscale when the LAN dashboard must be reachable remotely.

Do not place real addresses, tokens, usernames, or keys in the repository.

## 2. Install system packages

```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-venv \
  sqlite3 qrencode speedtest-cli vnstat yt-dlp git openssh-client
```

If Pi-hole runs on the same host:

```bash
sudo usermod -aG pihole "$(id -un)"
```

## 3. Verify router SSH

Generate a dedicated key if one does not already exist:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/netsentry-router-key -N ""
```

Import its public key for the dedicated RouterOS user, then verify from the Pi:

```bash
ssh -i ~/.ssh/netsentry-router-key \
  <ROUTER_USER>@<ROUTER_IP> ':put TEST_OK'
```

The expected output is `TEST_OK`.

## 4. Install NetSentry

```bash
git clone <NETSENTRY_REPOSITORY_URL> ~/NetSentry
cd ~/NetSentry
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
netsentry --version
```

For an editable operator checkout, replace the last install command with
`python -m pip install -e .`.

## 5. Initialize config and vault

```bash
netsentry init
netsentry secret set TELEGRAM_TOKEN '<TELEGRAM_TOKEN>'
netsentry secret set TELEGRAM_CHAT_ID '<CHAT_ID>'
netsentry secret set ALLOWED_CHAT_ID '<CHAT_ID>'
netsentry secret set ROUTER_HOST '<ROUTER_IP>'
netsentry secret set ROUTER_USER '<ROUTER_USER>'
netsentry secret set SSH_KEY '<ABSOLUTE_SSH_KEY_PATH>'
netsentry secret list
```

Set `OLLAMA_HOST` only when an enabled plugin uses the local AI integration.
The `secret list` command prints key names, not values.

Edit `~/.config/netsentry/config.yaml`. At minimum, verify:

- the enabled plugin list;
- `guest_wifi_rotator.ssid` and `security_profile`;
- backup and Pi-hole paths;
- dashboard `bind_host` and `public_host`;
- cron schedules.

`lan_dashboard.bind_host: auto` binds the Tailscale IPv4 address when present,
otherwise loopback. Set `0.0.0.0` only as an explicit exposure decision.

## 6. Foreground verification

```bash
netsentry start
```

Send `/help` and `/status`. If guest rotation is enabled, follow the manual
checks in [Guest WiFi rotation](GUEST_WIFI.md) before using `/rotate` in
production. Stop the foreground run with Ctrl-C.

Configuration now fails fast for missing router/notifier fields, unresolved
vault references, duplicate IDs/names, and missing required guest WiFi keys.

## 7. Install systemd service

The repository unit contains the `__USER__` placeholder:

```bash
cd ~/NetSentry
sudo sed "s/__USER__/$(id -un)/g" deploy/netsentry.service | \
  sudo tee /etc/systemd/system/netsentry.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now netsentry
sudo systemctl status netsentry
```

Ensure `ExecStart` points to the installed `netsentry` executable. For the
venv layout above, use `/home/<USER>/NetSentry/.venv/bin/netsentry start`.

## systemd writable paths

`ProtectHome=read-only` is enabled. The template permits writes only to:

```text
/home/__USER__/.config/netsentry
/home/__USER__/.local/share/netsentry
/home/__USER__/backups
```

The GitHub plugin now defaults to
`~/.local/share/netsentry/repos`, so no sandbox widening is required. If
`github_explorer.base_dir`, the log file, or the backup directory is moved
outside these roots, add that exact path to `ReadWritePaths`, run
`systemctl daemon-reload`, and restart the service.

## Dashboard firewall assumptions

The dashboard uses an ephemeral URL token, but the token is not a substitute
for a firewall. Permit TCP `8088` only on the intended Tailscale interface and
keep it blocked on untrusted LAN/WAN interfaces. The token rotates whenever
NetSentry restarts.

## Upgrade to 0.3.0

```bash
cd ~/NetSentry
git pull --ff-only
. .venv/bin/activate
python -m pip install .
sudo systemctl restart netsentry
sudo journalctl -u netsentry -n 100 --no-pager
```

Existing `config.yaml` and state files remain compatible. Add
`telegram_bot.worker_threads`, `lan_dashboard.public_host`, or the new defaults
only when explicit control is needed. See [Operations](OPERATIONS.md) for
routine administration.
