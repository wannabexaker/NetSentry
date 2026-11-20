"""threat_detector · everything the owner does from Telegram.

The slash commands and their button screens (detector switches, audit window,
trusted list, "trust this domain" under a finding). Typed arguments keep
working; the bare command always opens buttons, so there is nothing to memorise.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from ...core import ui
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

    def _cmd_intel(self, chat_id: int, args: str, message_id: int | None = None) -> None:
        if args.strip().lower() in ("refresh", "update", "sync"):
            self.notifier.send_to(chat_id, f"{ui.WORKING} Updating the malware-domain lists…")
            count, ok = threat_intel.refresh(self._intel_file)
            text = (f"{ui.OK} Malware-domain lists updated — {count:,} known-bad domains."
                    if ok else
                    f"{ui.FAILED} The lists were NOT updated — a source didn't answer. "
                    f"The previous {count:,} domains are still in use.")
            self.notifier.send_to(chat_id, text, buttons=[ui.nav_row()])
            return
        feed_map, ts = threat_intel.load(self._intel_file)
        when = ui.when_text(ts, default="never")
        text = "\n".join([
            ui.title("🧠", "Malware-domain lists", f"{len(feed_map):,} domains"),
            f"Updated: {when}",
            "Sources: URLhaus, HaGeZi threat list, Phishing Army.",
            "Every check runs on the Pi — your lookups never leave the network.",
        ])
        buttons = [[ui.button("🔄 Update now", f"{self.ctx.name}:v:intel_refresh")],
                   ui.nav_row()]
        self._screen(chat_id, message_id, text, buttons)

    def _cmd_allow(self, chat_id: int, args: str) -> None:
        domain = args.strip().lower().strip(".")
        if not domain:
            self._show_allow(chat_id, None)
            return
        self.api_set_allow(domain, True)
        undo = self._key("deny", domain)
        self.notifier.send_to(
            chat_id,
            f"{ui.OK} Trusted {domain} and its sub-domains — it won't be flagged again.",
            buttons=ui.rows([ui.button("↩️ Undo", undo)] if undo else [], ui.nav_row()),
        )

    def _cmd_deny(self, chat_id: int, args: str) -> None:
        domain = args.strip().lower().strip(".")
        if not domain:
            self._show_allow(chat_id, None)
        elif domain in self._state().get("allowed_domains", []):
            self.api_set_allow(domain, False)
            self.notifier.send_to(chat_id, f"↩️ Stopped trusting {domain}.",
                                  buttons=[ui.nav_row()])
        else:
            self._show_allow(chat_id, None,
                             note=f"{ui.INFO} {domain} wasn't on your trusted list. "
                                  "Nothing changed.")

    def _cmd_report(self, chat_id: int) -> None:
        since = self._state().get("last_report_ts") or (
            datetime.now() - timedelta(days=1)
        ).isoformat(timespec="seconds")
        self.notifier.send_to(
            chat_id, self._build_report(since, self._report_title(False)),
            buttons=self._report_buttons(since),
        )

    def _cmd_domains(self, chat_id: int, args: str, note: str = "") -> None:
        journal = self._journal()
        query = args.strip().lower()
        items = [
            (d, m) for d, m in journal.items()
            if not query or query in d or query in (m.get("note", "").lower())
        ]
        top = [note] if note else []
        if not items:
            self.notifier.send_to(
                chat_id,
                "\n".join(top + ["📇 No domains recorded yet." if not journal
                                 else f"📇 No domains match \"{query}\"."]),
                buttons=[ui.nav_row()],
            )
            return
        items.sort(key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
        names = self._device_names()
        verdict = (f"{len(items)} matching \"{query}\"" if query
                   else ui.plural(len(items), "domain"))
        lines = top + [ui.title("📇", "Domains", verdict)]
        for d, m in items[:40]:
            who = ", ".join(self._label_client(c, names) for c in (m.get("clients") or [])[:2])
            note_text = f"📝 {m['note']}" if m.get("note") else ""
            first = ui.parse_when(m.get("first_seen", ""))
            lines.append("• " + ui.item(d, note_text, f"{m.get('count', 0)}×",
                                        f"since {ui.fmt_day(first)}" if first else "", who))
        if len(items) > 40:
            lines.append(f"{ui.more(40, len(items))} — send /domains and a word to search.")
        self.notifier.send_to(chat_id, "\n".join(lines), buttons=[ui.nav_row()])

    def _cmd_note(self, chat_id: int, args: str) -> None:
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            # Nothing to tap for a free-text label: say plainly what to send,
            # over the list of domains (filtered by the one given, if any).
            self._cmd_domains(
                chat_id, parts[0] if parts else "",
                note="📝 To label a domain, send /note, the domain and your label — "
                     "e.g. /note shop.example.com my webshop")
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
        self.notifier.send_to(chat_id, f"📝 Labelled {domain}: {note[:200]}")

    def _cmd_audit(self, chat_id: int, args: str) -> None:
        a = args.strip().lower()
        if not a:
            self._show_audit(chat_id, None)
            return
        if a in ("off", "stop", "0"):
            self._set_audit(None)
            self.notifier.send_to(
                chat_id, f"{ui.OK} Audit mode is off — new domains are back to their "
                         "normal setting.", buttons=[ui.nav_row()])
            return
        try:
            hours = float(a)
        except ValueError:
            hours = 24.0
        until = self._set_audit(hours)
        self.notifier.send_to(
            chat_id,
            f"{ui.OK} Audit mode is on until {ui.when_text(until)} — every new domain "
            "is recorded per device, silently. It shows up in the next report.",
            buttons=[self._view_row(("📇 Domains", "domains")) + ui.nav_row()],
        )

    def _cmd_threats(self, chat_id: int, message_id: int | None = None) -> None:
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
            text = "\n".join([
                ui.header("🛡", "Live check", f"{ui.OK} all clear"),
                f"No findings in the last {self._window_min} min — "
                f"{ui.plural(on_count, 'detector')} on, "
                f"{ui.plural(len(recent), 'domain')} looked at.",
            ])
            buttons = [self._view_row(("🎛 Detectors", "scans")),
                       [ui.refresh_button(f"{self.ctx.name}:v:threats"), *ui.nav_row()]]
            self._screen(chat_id, message_id, text, buttons)
            return
        names = self._device_names()
        self._screen(chat_id, message_id,
                     self._build_digest(findings, domain_clients, names),
                     self._digest_buttons(findings))

    def _cmd_scans(self, chat_id: int, args: str) -> None:
        parts = args.split()
        if len(parts) >= 2 and parts[1].lower() in ("on", "off"):
            key, want = parts[0].lower(), parts[1].lower() == "on"
            if key not in _SCANS:
                self._show_scans(chat_id, None,
                                 note=f"{ui.FAILED} Unknown detector \"{key}\" — "
                                      "tap one below instead.")
                return
            with self._state_lock:
                state = self._state()
                overrides = state.get("scans_enabled", {})
                overrides[key] = want
                state["scans_enabled"] = overrides
                self._save(state)
            self.notifier.send_to(
                chat_id, f"{ui.OK} {_label(key)} is now {'on' if want else 'off'}.",
                buttons=[self._view_row(("🎛 Detectors", "scans")) + ui.nav_row()],
            )
            return
        self._show_scans(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # <plugin>:scan:<key> | :audit:<hours|off> | :allow:<domain> | :deny:<domain>
        # | :v:<screen> (open a screen) | :noop: (a button that already did its job)
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
            ack("Audit off" if arg == "off" else f"Audit on for {arg} h")
            self._show_audit(chat_id, message_id)
        elif verb == "allow" and arg:
            self.api_set_allow(arg, True)
            ack(f"Trusted {arg}"[:190])
            ui.mark_tapped(self.ctx, self.notifier, chat_id, message_id, data,
                           f"✔ Trusted {arg}"[:60], f"{self.ctx.name}:noop:")
        elif verb == "deny" and arg:
            self.api_set_allow(arg, False)
            ack(f"Stopped trusting {arg}"[:190])
            self._show_allow(chat_id, message_id)
        elif verb == "v":
            ack()
            self._open_view(arg, chat_id, message_id)
        elif verb == "noop":
            ack("Already done")
        else:
            ack("?")

    def _open_view(self, view: str, chat_id: int, message_id: int) -> None:
        """A screen button. Screens edit their own message; from a report or a
        live check (which should stay readable) they open as a new message."""
        if view == "threats":
            self._cmd_threats(chat_id, message_id)          # 🔄 Refresh: in place
        elif view == "scans":
            self._show_scans(chat_id, None)
        elif view == "allow":
            self._show_allow(chat_id, None)
        elif view == "audit":
            self._show_audit(chat_id, None)
        elif view == "domains":
            self._cmd_domains(chat_id, "")
        elif view == "log":
            self._cmd_threatlog(chat_id, "")
        elif view == "intel_refresh":
            self._cmd_intel(chat_id, "refresh")

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

    def _show_scans(self, chat_id: int, message_id: int | None, note: str = "") -> None:
        enabled = self._enabled()
        on = sum(1 for v in enabled.values() if v)
        lines = ([note, ""] if note else []) + [
            ui.title("🎛", "Detectors", f"{on} of {len(_SCANS)} on"),
            "Tap one to switch it on or off.",
        ]
        cells = []
        for key, meta in _SCANS.items():
            mark = "✅" if enabled[key] else "⏸"
            needs = f" (needs {meta['needs']})" if meta.get("needs") else ""
            lines.append(f"\n{mark} {meta['label']}{needs}")
            lines.append(f"   {meta['means']}")
            cells.append(ui.button(f"{mark} {meta['label']}"[:40], self._key("scan", key)))
        rows = [cells[i:i + 2] for i in range(0, len(cells), 2)]
        rows.append([ui.button("🔍 Audit mode", f"{self.ctx.name}:v:audit"),
                     ui.button("✅ Trusted list", f"{self.ctx.name}:v:allow")])
        rows.append(ui.nav_row())
        self._screen(chat_id, message_id, "\n".join(lines), rows)

    def _show_audit(self, chat_id: int, message_id: int | None) -> None:
        until = self._state().get("audit_until")
        on = bool(until and datetime.now().isoformat() < until)
        verdict = f"on until {ui.when_text(until)}" if on else "off"
        text = "\n".join([
            ui.title("🔍", "Audit mode", verdict),
            "While it's on, every domain a device contacts for the first time is "
            "recorded per device, silently — handy to see what a new gadget talks "
            "to. It shows up in the next report.",
            "Turn it on for:",
        ])
        row = [ui.button(label, self._key("audit", arg))
               for label, arg in (("1 hour", "1"), ("6 hours", "6"), ("24 hours", "24"))]
        off = [ui.button("⏹ Turn off", self._key("audit", "off"))] if on else []
        self._screen(chat_id, message_id, text,
                     ui.rows(row, off, [ui.button("📇 Domains", f"{self.ctx.name}:v:domains")],
                             ui.nav_row()) or [])

    def _show_allow(self, chat_id: int, message_id: int | None, note: str = "") -> None:
        current = self._state().get("allowed_domains", [])
        top = [note, ""] if note else []
        if current:
            body = [f"• {d}" for d in current] + [
                "", "Sub-domains are trusted too. Tap one to stop trusting it."]
        else:
            body = ["None yet. To trust a domain, tap ✅ Trust under a finding in a "
                    "report or a live check."]
        text = "\n".join(top + [ui.title("✅", "Trusted domains",
                                         ui.plural(len(current), "domain"))] + body)
        rows = [[ui.button(f"↩️ Stop trusting {d}"[:60], self._key("deny", d))]
                for d in current if self._key("deny", d)]
        rows.append(ui.nav_row())
        self._screen(chat_id, message_id, text, rows)

    def _trust_buttons(self, subjects: list[str], limit: int = 6) -> list:
        """One "Trust <domain>" button per flagged domain you haven't trusted yet."""
        allow = self._effective_allow_suffixes()
        has_who = ui.plugin_named(self.ctx, "who_asked") is not None
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
                chat_id, "📜 No findings recorded yet — all quiet so far.",
                buttons=[ui.nav_row()],
            )
            return
        names = self._device_names()
        shown = alerts[-n:][::-1]
        lines = [ui.title("📜", "Finding log", f"last {len(shown)}, newest first")]
        for e in shown:
            d = e.get("details", {})
            icon = _SEV_ICON.get(d.get("severity", ""), "•")
            who = ", ".join(self._label_client(c, names) for c in (d.get("clients") or [])[:2])
            lines.append(f"{icon} " + ui.item(d.get("subject", "") or "?",
                                              _label(e.get("type", "")), who,
                                              ui.when_text(e.get("ts", ""))))
        self.notifier.send_to(chat_id, "\n".join(lines), buttons=[ui.nav_row()])
