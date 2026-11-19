"""threat_detector · everything the owner does from Telegram.

The slash commands and their button screens (detector switches, audit window,
allow-list, "trust this domain" under a finding). Typed arguments keep working;
the bare command always opens buttons, so there is nothing to memorise.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from . import threat_intel
from .taxonomy import _SCANS, _SEV_ICON, _label


class TelegramMixin:
    """Telegram commands and button screens of :class:`ThreatDetectorPlugin` (mixed into it)."""

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/threats":
            self._cmd_threats(chat_id)
        elif command == "/scans":
            self._cmd_scans(chat_id, args)
        elif command == "/threatlog":
            self._cmd_threatlog(chat_id, args)
        elif command == "/report":
            self._cmd_report(chat_id)
        elif command == "/domains":
            self._cmd_domains(chat_id, args)
        elif command == "/note":
            self._cmd_note(chat_id, args)
        elif command == "/audit":
            self._cmd_audit(chat_id, args)
        elif command == "/allow":
            self._cmd_allow(chat_id, args)
        elif command == "/deny":
            self._cmd_deny(chat_id, args)
        elif command == "/intel":
            self._cmd_intel(chat_id, args)

    def _cmd_intel(self, chat_id: int, args: str) -> None:
        if args.strip().lower() in ("refresh", "update", "sync"):
            self.notifier.send_to(chat_id, "⏳ Refreshing threat feeds…")
            count, ok = threat_intel.refresh(self._intel_file)
            self.notifier.send_to(
                chat_id,
                f"🧠 Feeds {'updated' if ok else 'refresh FAILED (kept old cache)'}: "
                f"{count} known-bad domains.",
            )
            return
        feed_map, ts = threat_intel.load(self._intel_file)
        when = ts[:16].replace("T", " ") if ts else "never (run /intel refresh)"
        self.notifier.send_to(
            chat_id,
            f"🧠 Local threat intel (abuse.ch URLhaus + ThreatFox)\n"
            f"{len(feed_map)} known-bad domains · updated {when}\n"
            "Every check runs on-device — your domains never leave the network.\n"
            "↳ /intel refresh to update now.",
        )

    def _cmd_allow(self, chat_id: int, args: str) -> None:
        domain = args.strip().lower().strip(".")
        if not domain:
            self._show_allow(chat_id, None)
            return
        self.api_set_allow(domain, True)
        self.notifier.send_to(
            chat_id,
            f"✅ Trusting {domain} (and its sub-domains) — it won't be flagged again.",
        )

    def _cmd_deny(self, chat_id: int, args: str) -> None:
        domain = args.strip().lower().strip(".")
        if domain in self._state().get("allowed_domains", []):
            self.api_set_allow(domain, False)
            self.notifier.send_to(chat_id, f"🚫 No longer trusting {domain}.")
        else:
            self.notifier.send_to(chat_id, f"'{domain}' wasn't in your trusted list.")

    def _cmd_report(self, chat_id: int) -> None:
        since = self._state().get("last_report_ts") or (
            datetime.now() - timedelta(days=1)
        ).isoformat(timespec="seconds")
        self.notifier.send_to(
            chat_id, self._build_report(since, "Homelab Monitor — report"),
            buttons=self._report_trust_buttons(since) or None,
        )

    def _cmd_domains(self, chat_id: int, args: str) -> None:
        journal = self._journal()
        query = args.strip().lower()
        items = [
            (d, m) for d, m in journal.items()
            if not query or query in d or query in (m.get("note", "").lower())
        ]
        if not items:
            self.notifier.send_to(
                chat_id,
                "📇 No domains recorded yet."
                if not journal else f"📇 No domains match '{query}'.",
            )
            return
        items.sort(key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
        names = self._device_names()
        lines = [f"📇 Domains ({len(items)}" + (f" matching '{query}'" if query else "") + "):"]
        for d, m in items[:40]:
            first = m.get("first_seen", "")[:10]
            who = ", ".join(self._label_client(c, names) for c in (m.get("clients") or [])[:2])
            note = f"  📝 {m['note']}" if m.get("note") else ""
            lines.append(f"• {d}  (first {first}, ×{m.get('count', 0)}) {who}{note}")
        if len(items) > 40:
            lines.append(f"… +{len(items) - 40} more — refine with /domains <text>")
        lines.append("\n↳ /note <domain> <your label> to annotate")
        self.notifier.send_to(chat_id, "\n".join(lines))

    def _cmd_note(self, chat_id: int, args: str) -> None:
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            self.notifier.send_to(chat_id, "Usage: /note <domain> <label/note>")
            return
        domain, note = parts[0].strip().lower(), parts[1].strip()
        journal = self._journal()
        entry = journal.get(domain)
        if entry is None:
            # allow annotating even if not yet auto-recorded
            now = datetime.now().isoformat(timespec="seconds")
            entry = {"first_seen": now, "last_seen": now, "clients": [], "count": 0}
            journal[domain] = entry
        entry["note"] = note[:200]
        self._save_journal(journal)
        self.notifier.send_to(chat_id, f"📝 Noted: {domain} → {note[:200]}")

    def _cmd_audit(self, chat_id: int, args: str) -> None:
        a = args.strip().lower()
        if not a:
            self._show_audit(chat_id, None)
            return
        if a in ("off", "stop", "0"):
            self._set_audit(None)
            self.notifier.send_to(
                chat_id, "🔍 Audit mode off — new_domain back to its normal setting."
            )
            return
        try:
            hours = float(a)
        except ValueError:
            hours = 24.0
        until = self._set_audit(hours)
        self.notifier.send_to(
            chat_id,
            f"🔍 Audit mode ON for {hours:g}h — recording every new domain per "
            f"device (silent). Ends {until[:16].replace('T', ' ')}.\n"
            "Review anytime with /domains or /report.",
        )

    def _cmd_threats(self, chat_id: int) -> None:
        enabled = self._enabled()
        domain_clients = self._recent_domain_clients()
        recent = list(domain_clients.keys())
        arp_pairs = (
            self._arp_pairs()
            if (enabled["arp_conflict"] or enabled["arp_change"])
            else []
        )
        findings = self._collect(
            recent, arp_pairs, self._state(), relative=True, enabled=enabled
        )
        if not findings:
            on_count = sum(1 for v in enabled.values() if v)
            self.notifier.send_to(
                chat_id,
                f"🛡 All clear — no findings in the last {self._window_min}m "
                f"({on_count} detector(s) on, {len(recent)} domains seen).\n"
                "↳ /scans to see or change what's monitored.",
            )
            return
        names = self._device_names()
        trust = self._trust_buttons(
            [f.subject for f in findings
             if f.kind in self._DOMAIN_KINDS and f.kind != "new_domain"])
        self.notifier.send_to(
            chat_id, self._build_digest(findings, domain_clients, names),
            buttons=trust or None,
        )

    def _cmd_scans(self, chat_id: int, args: str) -> None:
        parts = args.split()
        if len(parts) >= 2 and parts[1].lower() in ("on", "off"):
            key, want = parts[0].lower(), parts[1].lower() == "on"
            if key not in _SCANS:
                self.notifier.send_to(
                    chat_id, f"❓ Unknown scan '{key}'. Send /scans to list them."
                )
                return
            with self._state_lock:
                state = self._state()
                overrides = state.get("scans_enabled", {})
                overrides[key] = want
                state["scans_enabled"] = overrides
                self._save(state)
            self.notifier.send_to(
                chat_id,
                f"{'✅ Enabled' if want else '❌ Disabled'}: {_label(key)}",
            )
            return
        self._show_scans(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # <plugin>:scan:<key> | :audit:<hours|off> | :allow:<domain> | :deny:<domain>
        _, verb, arg = (data.split(":", 2) + ["", ""])[:3]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "scan" and arg in _SCANS:
            want = not self._enabled()[arg]
            self.api_set_scan(arg, want)
            ack(f"{_label(arg)}: {'on' if want else 'off'}")
            self._show_scans(chat_id, message_id)
        elif verb == "audit" and arg in ("1", "6", "24", "off"):
            self._set_audit(None if arg == "off" else float(arg))
            ack("Audit off" if arg == "off" else f"Audit on for {arg}h")
            self._show_audit(chat_id, message_id)
        elif verb == "allow" and arg:
            self.api_set_allow(arg, True)
            ack(f"Trusting {arg}"[:190])
        elif verb == "deny" and arg:
            self.api_set_allow(arg, False)
            ack(f"No longer trusting {arg}"[:190])
            self._show_allow(chat_id, message_id)
        else:
            ack("?")

    def _screen(self, chat_id: int, message_id: int | None, text: str,
                buttons: list) -> None:
        """Redraw a button screen in place, or send it if there's none yet."""
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons or None)

    def _key(self, verb: str, arg: str) -> str | None:
        """callback_data for a button, or None if Telegram's 64-byte cap won't fit it."""
        data = f"{self.ctx.name}:{verb}:{arg}"
        return data if len(data.encode()) <= 64 else None

    def _show_scans(self, chat_id: int, message_id: int | None) -> None:
        enabled = self._enabled()
        lines = ["🎛 Detectors — tap one below to switch it on or off"]
        cells = []
        for key, meta in _SCANS.items():
            mark = "✅" if enabled[key] else "❌"
            needs = f"  ⚙️ needs {meta['needs']}" if meta.get("needs") else ""
            lines.append(f"\n{mark} {meta['label']}  ({meta['severity']}){needs}")
            lines.append(f"   {meta['means']}")
            cells.append({"text": f"{mark} {meta['label']}"[:40],
                          "callback_data": self._key("scan", key)})
        rows = [cells[i:i + 2] for i in range(0, len(cells), 2)]
        self._screen(chat_id, message_id, "\n".join(lines), rows)

    def _show_audit(self, chat_id: int, message_id: int | None) -> None:
        until = self._state().get("audit_until")
        on = bool(until and datetime.now().isoformat() < until)
        status = (f"ON until {until[:16].replace('T', ' ')}" if on else "off")
        text = (
            f"🔍 Audit mode: {status}\n"
            "While on, every domain a device contacts for the first time is "
            "recorded per device (silently) — handy when you want to see what "
            "a new gadget talks to. Review with /domains or /report."
        )
        row = [{"text": label, "callback_data": self._key("audit", arg)}
               for label, arg in (("1 hour", "1"), ("6 hours", "6"),
                                  ("24 hours", "24"), ("Off", "off"))]
        self._screen(chat_id, message_id, text, [row])

    def _show_allow(self, chat_id: int, message_id: int | None) -> None:
        current = self._state().get("allowed_domains", [])
        listed = "\n".join(f"  • {d}" for d in current) or "  (none yet)"
        text = ("✅ Trusted domains you added (sub-domains included):\n" + listed
                + "\n\nTap one to stop trusting it. To trust a domain, tap the "
                "Trust button under a finding in /threats or /report "
                "(or type /allow <domain>).")
        rows = [[{"text": f"🚫 {d}", "callback_data": self._key("deny", d)}]
                for d in current if self._key("deny", d)]
        self._screen(chat_id, message_id, text, rows)

    def _trust_buttons(self, subjects: list[str], limit: int = 6) -> list:
        """One "Trust <domain>" button per flagged domain you haven't trusted yet."""
        allow = self._effective_allow_suffixes()
        has_who = any(getattr(getattr(p, "ctx", None), "name", "") == "who_asked"
                      for p in getattr(self.ctx, "_all_plugins", []))
        rows, seen = [], set()
        for subject in subjects:
            domain = subject.lower().strip(".")
            if self._key("allow", domain) is None:        # a very long FQDN:
                domain = ".".join(domain.split(".")[-3:])  # offer its parent instead
            if (not domain or "." not in domain or domain in seen
                    or self._key("allow", domain) is None
                    or any(domain == a or domain.endswith("." + a) for a in allow)):
                continue
            seen.add(domain)
            row = [{"text": f"✅ Trust {domain}",
                    "callback_data": self._key("allow", domain)}]
            who = f"who_asked:q:{domain}"
            if has_who and len(who.encode()) <= 64:
                row.append({"text": "🔎 Who asked?", "callback_data": who})
            rows.append(row)
            if len(rows) >= limit:
                break
        return rows

    def _report_trust_buttons(self, since_iso: str) -> list:
        """Trust buttons for the flagged domains a report (since ``since_iso``) lists."""
        return self._trust_buttons([
            e.get("details", {}).get("subject", "")
            for e in self._alerts_since(since_iso)
            if e.get("event") == "alert" and e.get("type") in self._DOMAIN_KINDS
            and e.get("type") != "new_domain"
        ])

    def _set_audit(self, hours: float | None) -> str:
        """Turn audit mode on for ``hours`` (or off). Returns the end time, if on."""
        until = "" if hours is None else (
            datetime.now() + timedelta(hours=hours)).isoformat(timespec="seconds")
        with self._state_lock:
            state = self._state()
            if until:
                state["audit_until"] = until
            else:
                state.pop("audit_until", None)
            self._save(state)
        return until

    def _cmd_threatlog(self, chat_id: int, args: str) -> None:
        try:
            n = min(50, max(1, int(args.strip()))) if args.strip() else 15
        except ValueError:
            n = 15
        try:
            raw = self._alerts_file.read_text(encoding="utf-8").splitlines()
        except Exception:
            raw = []
        alerts = []
        for line in raw[-500:]:
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event") == "alert":
                alerts.append(e)
        if not alerts:
            self.notifier.send_to(
                chat_id, "📜 No findings recorded yet — all quiet so far."
            )
            return
        lines = [f"📜 Last {min(n, len(alerts))} findings (newest first):"]
        for e in alerts[-n:][::-1]:
            d = e.get("details", {})
            icon = _SEV_ICON.get(d.get("severity", ""), "•")
            ts = e.get("ts", "")[:16].replace("T", " ")
            clients = ", ".join(d.get("clients", []) or [])
            who = f"  ·  {clients}" if clients else ""
            lines.append(
                f"{icon} {ts}  {_label(e.get('type', ''))}: {d.get('subject', '')}{who}"
            )
        self.notifier.send_to(chat_id, "\n".join(lines))
