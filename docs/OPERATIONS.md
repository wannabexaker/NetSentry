# Operations

## Service control

```bash
sudo systemctl status netsentry
sudo systemctl start netsentry
sudo systemctl stop netsentry
sudo systemctl restart netsentry
sudo systemctl enable netsentry
sudo systemctl disable netsentry
```

After changing Python code, installed package contents, config, vault values, or
the systemd unit, restart the service. After changing the unit itself, run
`sudo systemctl daemon-reload` first.

## Logs and status

```bash
netsentry status
sudo journalctl -u netsentry -f
sudo journalctl -u netsentry --since '1 hour ago'
sudo journalctl -u netsentry -n 200 --no-pager
tail -f ~/.local/share/netsentry/netsentry.log
```

The file log rotates according to `logging.max_size_mb` and
`logging.backup_count`. Health alert history is separate:

```bash
tail -n 50 ~/.local/share/netsentry/health_monitor/alerts.jsonl
```

## Configuration

The default file is `~/.config/netsentry/config.yaml`. Use
`config.example.yaml` as reference. To disable a plugin:

```yaml
plugins:
  - name: speedtest
    enabled: false
    config: {}
```

Restart and verify the load log. Startup validation rejects missing core keys,
unresolved vault references, duplicate plugin/notifier names, and incomplete
enabled guest WiFi configuration.

## Vault management

```bash
netsentry secret list
netsentry secret set <KEY> '<VALUE>'
netsentry secret get <KEY>
netsentry secret delete <KEY>
netsentry secret rotate-key
```

Avoid `secret get` in recorded terminals. Never put secret values directly in
YAML, documentation, shell history, commits, or service environment files.

## Vault backup and restore

The vault requires both files:

```text
~/.config/netsentry/secrets.key
~/.config/netsentry/secrets.enc
```

Back them up to separate protected locations. Never store `secrets.key` next
to `secrets.enc` off-box; possession of both removes the protection provided by
encryption. Preserve file modes `0400` for the key and `0600` for ciphertext.

Restore both files to their original paths, apply modes, and restart:

```bash
chmod 400 ~/.config/netsentry/secrets.key
chmod 600 ~/.config/netsentry/secrets.enc
sudo systemctl restart netsentry
```

## Router backups

Trigger `/backup` or wait for `config_backup.cron`. Verify both `.rsc` and
`.backup` files exist under `backup_dir`. These files can contain sensitive
network configuration; encrypt off-box copies and restrict access.

## Upgrade checklist

1. Back up config, vault components separately, and router exports.
2. Pull the reviewed release.
3. Install the package into the service environment.
4. Run offline tests when deploying from source.
5. Restart the service and inspect the last 100 journal lines.
6. Test `/help`, `/status`, and required plugins.
7. For 0.3.0, perform the [guest WiFi live verification](GUEST_WIFI.md#live-verification-after-upgrade).
