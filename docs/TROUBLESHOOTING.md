# Troubleshooting

## Bot is unresponsive

Check service state and the latest logs:

```bash
sudo systemctl status netsentry
sudo journalctl -u netsentry -n 200 --no-pager
```

Since 0.3.0 slow commands run in a worker pool and do not stop long polling.
Four simultaneous long operations can still queue later commands. Confirm the
log shows accepted commands and inspect `telegram_bot.worker_threads` before
raising it; more workers increase router and host load.

## `getUpdates` DNS or network failures

Repeated MagicDNS or network failures produce one `connectivity degraded`
warning, debug-level repeats, exponential retry up to 30 seconds, and one
recovery line. The Telegram update offset remains on disk.

NetSentry does not alter host DNS. Diagnose it separately:

```bash
getent hosts api.telegram.org
resolvectl status
tailscale status
```

On deployments where the Pi runs a stable local resolver, the operator may
choose to point the Pi resolver at itself. This is a host networking decision;
review the Pi-hole/Tailscale design and do not automate it through NetSentry.

## Router is unreachable

```bash
ssh -i <SSH_KEY> <ROUTER_USER>@<ROUTER_IP> ':put OK'
sudo journalctl -u netsentry | grep -i 'router\|ssh'
```

`/status` reports unavailable data. Health monitoring skips the disk check,
and morning briefing marks router metrics unavailable. It does not fabricate
zero disk or memory values.

## False disk or failed-login alerts

0.3.0 skips disk alerts when SSH stats are unavailable. It also baselines the
current failed-login tail after a fresh state file and resets the baseline when
the count moves backward after reboot or log rotation.

Inspect state and audit history:

```bash
cat ~/.local/share/netsentry/health_monitor/state.json
tail -n 50 ~/.local/share/netsentry/health_monitor/alerts.jsonl
```

Do not delete state merely to silence a real alert; determine the underlying
disk or login condition first.

## Dashboard does not load

1. Request a new `/lan dashboard` link after every NetSentry restart; the token
   rotates per process.
2. Check the logged bind address and port.
3. Confirm `tailscale ip -4` returns the address used in the link.
4. Confirm TCP `8088` is allowed on `tailscale0` and not unintentionally on
   LAN/WAN interfaces.
5. If using an explicit bind address, set `public_host` to the client-reachable
   host.

`bind_host: auto` uses Tailscale IPv4 or loopback. `0.0.0.0` is opt-in and does
not itself make the host reachable through UFW.

## AI/Ollama is offline

Check that the configured host is reachable and Ollama is listening:

```bash
curl --max-time 2 http://<OLLAMA_HOST>:11434/api/tags
```

Verify the `OLLAMA_HOST` vault key and AI model configuration. A disabled or
unreachable AI client must not block non-AI plugins.

## Guest QR does not work

Follow [Guest WiFi troubleshooting](GUEST_WIFI.md#troubleshooting). The profile
and every referencing interface must return the same hidden passphrase.

## GitHub clone fails under systemd

Use the default `~/.local/share/netsentry/repos`. If `base_dir` points
elsewhere, add the exact directory to systemd `ReadWritePaths`, reload the
unit, and restart. Also verify `git` is installed and the input is a GitHub
HTTP(S) URL or `owner/repo`.
