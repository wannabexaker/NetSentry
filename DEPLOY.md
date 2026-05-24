# NetSentry — Deploy runbook (self-service)

How to push from your workstation and update the Pi without external help.

> Placeholders used throughout — substitute with your own values:
> - `<pi-host>` — the Pi's reachable address (Tailscale IP, LAN IP, or hostname)
> - `<pi-user>` — the Linux user on the Pi that owns `~/NetSentry`
> - `<router-host>` — the MikroTik router's reachable address
> - `<router-ssh-user>` — the dedicated SSH user on the router
> - `<router-ssh-key>` — path to the private key authorised on the router

---

## 0. Before you start

**Repo path (workstation):** `<repo-path>` (for example `~/NetSentry`)
**Service name:** `netsentry.service`

Sanity-check that the service is healthy *now*:
```bash
ssh <pi-user>@<pi-host> "systemctl is-active netsentry.service"
```
Must print `active`. If not, diagnose first (§5) before deploying.

---

## 1. Push from your workstation

```bash
# What changed?
git -C <repo-path> status
git -C <repo-path> diff --stat

# Stage only what you mean to push (safer than `git add -A`)
git -C <repo-path> add <path1> <path2> ...

# Commit
git -C <repo-path> commit -m "feat(xxx): short summary"

# Push
git -C <repo-path> push origin main
```

For a long or multi-line commit message, drop it into a file and use `-F`:
```bash
# pick whatever editor / temp path your OS uses
git -C <repo-path> commit -F /tmp/msg.txt
```

---

## 2. Update on the Pi — one-liner

The common case (code-only change, no new Python deps):

```bash
ssh <pi-user>@<pi-host> "cd ~/NetSentry && git pull --ff-only && sudo systemctl restart netsentry.service && sleep 3 && systemctl is-active netsentry.service && sudo journalctl -u netsentry.service -n 20 --no-pager"
```

Expected:
- `Fast-forward` (or `Already up to date.`)
- `active`
- Logs with no `ERROR` / `Traceback`

---

## 3. Update when a new Python dependency was added

If `pyproject.toml` gained a new package (e.g. `flask`, `requests`):

```bash
ssh <pi-user>@<pi-host> "cd ~/NetSentry && git pull --ff-only && sudo pip install --break-system-packages '<package>>=<version>' && sudo systemctl restart netsentry.service && sleep 3 && systemctl is-active netsentry.service"
```

`--break-system-packages` is required on Raspberry Pi OS (PEP 668). The whole
NetSentry stack is installed this way already — keep the convention.

---

## 4. Update when a new plugin was added

When new code adds a plugin, it must also be added to the Pi's running
config (`~/.config/netsentry/config.yaml`).

```bash
ssh <pi-user>@<pi-host>
# inside the Pi:
cp ~/.config/netsentry/config.yaml /tmp/config-backup-$(date +%s).yaml
nano ~/.config/netsentry/config.yaml
# append a block like:
#   - name: <plugin_name>
#     enabled: true
#     config:
#       <whatever>
# Ctrl+O, Enter, Ctrl+X
sudo systemctl restart netsentry.service
sleep 3 && systemctl is-active netsentry.service
sudo journalctl -u netsentry.service -n 30 --no-pager | grep -E "Loaded plugin|ERROR|Traceback"
exit
```

`config.example.yaml` in the repo always shows the canonical layout —
copy-paste from there.

---

## 5. Diagnosing when something breaks

```bash
# Full status
ssh <pi-user>@<pi-host> "systemctl status netsentry.service --no-pager"

# Last 100 lines
ssh <pi-user>@<pi-host> "sudo journalctl -u netsentry.service -n 100 --no-pager"

# Live tail
ssh <pi-user>@<pi-host> "sudo journalctl -u netsentry.service -f"
# Ctrl+C to exit

# Filter for errors
ssh <pi-user>@<pi-host> "sudo journalctl -u netsentry.service -n 200 --no-pager | grep -E 'ERROR|Traceback|failed'"
```

Common symptoms:

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | New dep not installed | §3 |
| `Plugin xxx failed to load` | Bad plugin syntax or missing from config | Full traceback via journalctl |
| Service `inactive (dead)` | Crash on startup | `journalctl -u netsentry.service -n 100` |
| Telegram bot silent | Vault key wrong or token expired | `netsentry secret list` on the Pi |
| Dashboard 502 / refused | `lan_dashboard` didn't load | grep logs for `lan_dashboard` |

---

## 6. Rollback (if a deploy broke things)

```bash
ssh <pi-user>@<pi-host>
# inside the Pi:
cd ~/NetSentry
git log --oneline -10            # find the previous good sha
git reset --hard <previous-sha>  # roll back
sudo systemctl restart netsentry.service
sleep 3 && systemctl is-active netsentry.service
exit
```

Then on your workstation: fix the issue, create a *new* commit, push. Never
`git push --force` to recover — make a forward commit that supersedes.

---

## 7. RouterOS changes (when the change is on the MikroTik, not in code)

Always export a backup first:
```bash
ssh <pi-user>@<pi-host> "ssh -i ~/.ssh/<router-ssh-key> <router-ssh-user>@<router-host> '/export file=pre-change-$(date +%Y%m%d-%H%M%S)'"
```

Send changes as a `.rsc` script:
```bash
# 1) write the script locally
#    e.g. /ip firewall filter add chain=forward action=accept ...
# 2) copy to the Pi
scp /tmp/change.rsc <pi-user>@<pi-host>:/tmp/change.rsc
# 3) copy to the router and import
ssh <pi-user>@<pi-host> "scp -i ~/.ssh/<router-ssh-key> /tmp/change.rsc <router-ssh-user>@<router-host>:change.rsc && ssh -i ~/.ssh/<router-ssh-key> <router-ssh-user>@<router-host> '/import change.rsc'"
```

Restore from backup if needed:
```bash
ssh <pi-user>@<pi-host> "ssh -i ~/.ssh/<router-ssh-key> <router-ssh-user>@<router-host> '/import pre-change-XXXXXXXX-XXXXXX.rsc'"
```

---

## 8. Cheatsheet

```bash
# === Local ===
git -C <repo-path> status
git -C <repo-path> add <files>
git -C <repo-path> commit -m "..."
git -C <repo-path> push origin main

# === Deploy ===
ssh <pi-user>@<pi-host> "cd ~/NetSentry && git pull --ff-only && sudo systemctl restart netsentry.service && sleep 3 && systemctl is-active netsentry.service"

# === Diagnose ===
ssh <pi-user>@<pi-host> "sudo journalctl -u netsentry.service -n 50 --no-pager"

# === Rollback ===
ssh <pi-user>@<pi-host> "cd ~/NetSentry && git log --oneline -5"
ssh <pi-user>@<pi-host> "cd ~/NetSentry && git reset --hard <sha> && sudo systemctl restart netsentry.service"
```

---

## 9. Things you should never do without thinking twice

- `git push --force` on `main` — history is lost
- `sudo systemctl disable netsentry.service` — service won't start on next boot
- `rm -rf ~/NetSentry` — local checkout is gone (the GitHub repo survives)
- `rm ~/.config/netsentry/secrets.key` — the vault is unrecoverable. **Back this
  file up offline before touching anything in that folder.**
- RouterOS changes without `/export file=pre-change-...` first
