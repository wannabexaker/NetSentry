---
name: Bug report
about: Something is broken in NetSentry
title: ''
labels: bug
---

**Describe the bug**
A clear, concise description.

**Reproduce**
1. Configure ...
2. Run `netsentry ...`
3. Observe ...

**Expected behaviour**

**Actual behaviour**

**Environment**
- NetSentry version: `netsentry --version`
- Python: `python3 --version`
- OS: (e.g. Raspberry Pi OS 12)
- Router model & RouterOS version:
- Plugins enabled: `grep '^  - name' ~/.config/netsentry/config.yaml`

**Logs**

```
paste relevant lines from `journalctl -u netsentry --since=10m`
or from `~/.local/share/netsentry/netsentry.log`
```

**Sanitization checklist**
- [ ] I removed Telegram tokens, chat IDs, public IPs, and SSH keys from
      the pasted output.
