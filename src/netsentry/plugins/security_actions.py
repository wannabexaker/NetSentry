"""
security_actions — Interactive client management.

Commands:
    /kick           Pick a client to disconnect or block (inline keyboard).
    /security       Summary of recent security events.

Callbacks (data prefix = "security_actions:"). A MAC address contains colons,
so the MAC is always the *last* field and is taken whole:
    security_actions:kick:<MAC>         — show options for that MAC
    security_actions:act:disc:<MAC>     — disconnect once (no question: it can rejoin)
    security_actions:act:block:<MAC>    — "are you sure?" for a permanent block
    security_actions:block:<MAC>        — the same question (from a new-device alert)
    security_actions:act:yes:<MAC>      — the confirmed block
    security_actions:unblock:<MAC>      — lift the block (one tap: it only opens a door
                                          the owner closed a moment ago)
    security_actions:act:cancel:-       — cancel: nothing changes
"""

from __future__ import annotations

import re
from datetime import datetime

from ..core import ui
from ..core.plugin import Plugin

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


class SecurityActionsPlugin(Plugin):
    COMMANDS = [
        {"command": "kick",     "description": "👢 Disconnect or block a device",
         "usage": "/kick <MAC>"},
        {"command": "security", "description": "🔒 Router security at a glance"},
    ]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/kick":
            self._cmd_kick(chat_id, args)
        elif command == "/security":
            self._cmd_security(chat_id)

    # ─── /kick ──────────────────────────────────────────────────

    def _cmd_kick(self, chat_id: int, args: str) -> None:
        if args:
            mac = args.strip().upper()
            if not _MAC_RE.match(mac):
                self.notifier.send_to(chat_id, f"{ui.FAILED} That isn't a MAC address "
                                               "(like AA:BB:CC:DD:EE:FF).")
                return
            self._show_kick_options(chat_id, mac)
            return
        clients = self.router.wifi_clients()
        if not clients:
            self.notifier.send_to(chat_id, "📶 No device is on the WiFi right now.")
            return
        self._show_picker(chat_id, None, clients)

    def _show_picker(self, chat_id: int, message_id: int | None, clients: list) -> None:
        names = self._names([c.mac for c in clients])
        buttons = []
        for c in sorted(clients, key=lambda c: names[c.mac].lower()):
            text = ui.item(names[c.mac][:24], c.ssid, f"{c.signal_dbm} dBm")
            buttons.append([ui.button(text[:60], f"{self.ctx.name}:kick:{c.mac}")])
        buttons.append([ui.button(f"{ui.CANCELLED} Cancel", f"{self.ctx.name}:act:cancel:-")])
        self._show(chat_id, message_id,
                   f"👢 Disconnect or block — which device?\n"
                   f"{ui.plural(len(clients), 'device')} on the WiFi now.", buttons)

    def _show_kick_options(self, chat_id: int, mac: str, message_id: int | None = None) -> None:
        name = self._names([mac])[mac]
        text = f"👢 {name}" + (f"\n{mac}" if name != mac else "")
        for c in self.router.wifi_clients():
            if c.mac == mac:
                text += f"\nWiFi {c.ssid} · {c.signal_dbm} dBm · {c.band}"
                break
        text += ("\n\nDisconnect = it drops off now and can rejoin by itself."
                 "\nBlock = it can't join any WiFi until you unblock it.")
        me = self.ctx.name
        buttons = [
            [ui.button("📴 Disconnect once", f"{me}:act:disc:{mac}")],
            [ui.button("🚫 Block permanently", f"{me}:act:block:{mac}")],
            [ui.button("⬅ Back", f"{me}:list:-"),
             ui.button(f"{ui.CANCELLED} Cancel", f"{me}:act:cancel:-")],
        ]
        self._show(chat_id, message_id, text, buttons)

    # ─── callbacks ──────────────────────────────────────────────

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        # Never an unbounded split(":") — the MAC has five colons of its own.
        _, _, rest = data.partition(":")
        verb, _, rest = rest.partition(":")
        sub = ""
        if verb == "act":
            sub, _, rest = rest.partition(":")
        mac = rest.strip().upper()

        if verb == "act" and sub == "cancel":
            ack("Cancelled")
            self._show(chat_id, message_id, ui.NOTHING_CHANGED, [])
            return
        if verb == "list":                       # ⬅ Back from a device to the picker
            ack()
            clients = self.router.wifi_clients()
            if clients:
                self._show_picker(chat_id, message_id, clients)
            else:
                self._show(chat_id, message_id, "📶 No device is on the WiFi right now.", [])
            return
        if verb not in ("kick", "block", "unblock", "act") or not _MAC_RE.match(mac):
            ack("?")
            return
        if verb == "kick":
            ack()
            self._show_kick_options(chat_id, mac, message_id=message_id)
        elif verb == "block" or sub == "block":
            ack()
            self._ask_block(chat_id, message_id, mac)
        elif verb == "unblock":
            self._unblock(chat_id, message_id, mac, ack)
        elif sub == "yes":
            self._block(chat_id, message_id, mac, ack)
        elif sub == "disc":
            self._disconnect(chat_id, message_id, mac, ack)
        else:
            ack("?")

    def _ask_block(self, chat_id: int, message_id: int, mac: str) -> None:
        """The second tap: say what blocking does before it happens."""
        name = self._names([mac])[mac]
        me = self.ctx.name
        self._show(chat_id, message_id,
                   f"🚫 Block {name}? It can't join any WiFi until you unblock it."
                   + (f"\n{mac}" if name != mac else ""),
                   ui.confirm_rows("🚫", "block", f"{me}:act:yes:{mac}",
                                   f"{me}:act:cancel:-"))

    def _block(self, chat_id: int, message_id: int, mac: str, ack) -> None:
        name = self._names([mac])[mac]
        try:
            ok = bool(self.router.block_mac(
                mac, comment=f"Blocked via bot {datetime.now():%Y-%m-%d %H:%M}"))
        except Exception:
            self.log.exception("block of %s failed", mac)
            ok = False
        if ok:
            self.log.warning("Blocked %s (%s) from Telegram", name, mac)
            self._expected_router_change("device blocked")
            ack("Blocked")
            self._show(chat_id, message_id, f"🚫 Blocked {name}.",
                       [[ui.button("↩ Unblock", f"{self.ctx.name}:unblock:{mac}")]])
        else:
            ack("Not blocked")
            self._show(chat_id, message_id,
                       f"{ui.FAILED} {name} was NOT blocked — the router didn't accept it. "
                       "It can still join the WiFi.", [])

    def _unblock(self, chat_id: int, message_id: int, mac: str, ack) -> None:
        name = self._names([mac])[mac]
        try:
            ok = bool(self.router.unblock_mac(mac))
        except Exception:
            self.log.exception("unblock of %s failed", mac)
            ok = False
        if ok:
            self.log.warning("Unblocked %s (%s) from Telegram", name, mac)
            self._expected_router_change("device unblocked")
            ack("Unblocked")
            self._show(chat_id, message_id, f"{ui.OK} Unblocked {name}. It can join again.", [])
        else:
            ack("Not changed")
            self._show(chat_id, message_id,
                       f"{ui.FAILED} {name} is still blocked — the router didn't accept it.",
                       [[ui.button("↩ Unblock", f"{self.ctx.name}:unblock:{mac}")]])

    def _expected_router_change(self, what: str) -> None:
        if self.ctx.events:                     # our own change: not a tamper alarm
            self.ctx.events.publish("router.config.expected_change",
                                    {"source": self.ctx.name, "what": what})

    def _disconnect(self, chat_id: int, message_id: int, mac: str, ack) -> None:
        name = self._names([mac])[mac]
        try:
            ok = bool(self.router.disconnect_mac(mac))
        except Exception:
            self.log.exception("disconnect of %s failed", mac)
            ok = False
        if ok:
            ack("Disconnected")
            self._show(chat_id, message_id,
                       f"📴 Disconnected {name}. It can join again by itself.", [])
        else:
            ack("Not disconnected")
            self._show(chat_id, message_id,
                       f"{ui.FAILED} {name} was NOT disconnected — the router didn't "
                       "accept it (or it had already left).", [])

    # ─── /security ──────────────────────────────────────────────

    def _cmd_security(self, chat_id: int) -> None:
        fails = [line for line in self.router.log_tail(n=200, topic_filter="account")
                 if "login failure" in line]
        # ARP count
        arp_lines = self.router._ssh(":put [:len [/ip arp find]]")[1] \
            if hasattr(self.router, "_ssh") else "?"
        arp_count = arp_lines.strip() if arp_lines else "?"
        # Permanent blocks
        rc, blocks = self.router._ssh("/interface wifi access-list print where action=reject") \
            if hasattr(self.router, "_ssh") else (1, "")
        block_count = sum(1 for line in (blocks or "").splitlines() if "reject" in line)

        verdict = (f"{ui.ATTENTION} {ui.plural(len(fails), 'failed login')}" if fails
                   else f"{ui.OK} no failed logins")
        lines = [
            ui.title("🔒", "Router security", verdict),
            f"🔑 Failed router logins in the log: {len(fails)}",
        ]
        if fails:
            lines.append("Latest:")
            lines.extend(f"• {ui.login_failure(f)}" for f in fails[-5:][::-1])
        lines.extend([
            f"🚫 Devices blocked from the WiFi: {block_count}",
            f"📇 Addresses the router knows (ARP): {arp_count}",
        ])
        buttons = ui.rows(ui.command_row(self.ctx, ("👢 Disconnect or block", "/kick")),
                          ui.nav_row())
        self.notifier.send_to(chat_id, "\n".join(lines), buttons=buttons)

    # ─── helpers ────────────────────────────────────────────────

    def _names(self, macs: list[str]) -> dict[str, str]:
        return ui.device_names(self.ctx, self.router, macs)

    def _show(self, chat_id: int, message_id: int | None, text: str, buttons: list) -> None:
        """Redraw the message the button was on (results and cancels replace the
        question, so no live button is left behind), or send a new one."""
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons or None)
