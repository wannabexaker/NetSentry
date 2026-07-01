"""
security_actions — Interactive client management.

Commands:
    /kick           Pick a client to disconnect or block (inline keyboard).
    /security       Summary of recent security events.

Callbacks (data prefix = "security_actions:"):
    security_actions:kick:<MAC>         — show options for that MAC
    security_actions:act:disc:<MAC>     — disconnect once
    security_actions:act:block:<MAC>    — permanent block
    security_actions:act:cancel:-       — cancel
    security_actions:block:<MAC>        — direct block (from new-client alert)
"""

from __future__ import annotations

from datetime import datetime

from ..core.notifier import TelegramNotifier
from ..core.plugin import Plugin


class SecurityActionsPlugin(Plugin):
    COMMANDS = [
        {"command": "kick",     "description": "👮 Disconnect / block a WiFi client"},
        {"command": "security", "description": "🛡 Security status"},
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
            self._show_kick_options(chat_id, mac)
            return
        clients = self.router.wifi_clients()
        if not clients:
            self.notifier.send_to(chat_id, "📶 No active WiFi clients.")
            return
        leases = {lease.mac: lease for lease in self.router.dhcp_leases()}
        buttons = []
        for c in clients:
            lease = leases.get(c.mac)
            label = (lease.hostname or lease.ip) if lease else c.mac[-8:]
            text = f"{label[:18]}  [{c.ssid}, {c.signal_dbm}dBm]"
            buttons.append([{"text": text,
                             "callback_data": f"security_actions:kick:{c.mac}"}])
        buttons.append([{"text": "✖ Cancel",
                         "callback_data": "security_actions:act:cancel:-"}])
        self._send_buttons(chat_id, "👮 Select a client:", buttons)

    def _show_kick_options(self, chat_id: int, mac: str, message_id: int | None = None) -> None:
        text = f"Action for {mac}"
        # Try to enrich
        for c in self.router.wifi_clients():
            if c.mac == mac:
                text = (
                    f"Action for {mac}\n"
                    f"SSID: {c.ssid}  Signal: {c.signal_dbm} dBm\n"
                    f"Band: {c.band}"
                )
                break
        buttons = [
            [{"text": "📴 Disconnect once",
              "callback_data": f"security_actions:act:disc:{mac}"}],
            [{"text": "🚫 Block permanently",
              "callback_data": f"security_actions:act:block:{mac}"}],
            [{"text": "✖ Cancel",
              "callback_data": "security_actions:act:cancel:-"}],
        ]
        if message_id:
            self._edit(chat_id, message_id, text, buttons)
        else:
            self._send_buttons(chat_id, text, buttons)

    # ─── callbacks ──────────────────────────────────────────────

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        tg = self._tg()
        if not tg:
            return
        parts = data.split(":")
        # Expected: security_actions:<verb>:<rest…>
        if len(parts) < 2:
            tg.answer_callback(callback_id, "?")
            return
        verb = parts[1]

        if verb == "kick":
            # User picked a client from the list — show options
            mac = parts[2] if len(parts) > 2 else ""
            self._show_kick_options(chat_id, mac, message_id=message_id)
            tg.answer_callback(callback_id)
            return

        if verb == "block":
            # Direct block (from health_monitor's new-client alert)
            mac = parts[2] if len(parts) > 2 else ""
            ok = self.router.block_mac(mac, comment=f"Blocked via bot {datetime.now():%Y-%m-%d %H:%M}")
            msg = f"🚫 Blocked {mac}" if ok else "❌ Block failed"
            self._edit(chat_id, message_id, msg, [])
            tg.answer_callback(callback_id, "Done" if ok else "Failed")
            return

        if verb == "act":
            sub = parts[2] if len(parts) > 2 else ""
            mac = parts[3] if len(parts) > 3 else ""
            if sub == "cancel":
                self._edit(chat_id, message_id, "✖ Cancelled.", [])
                tg.answer_callback(callback_id)
                return
            if sub == "disc":
                ok = self.router.disconnect_mac(mac)
                msg = f"📴 Disconnected {mac}" if ok else "❌ Disconnect failed"
            elif sub == "block":
                ok = self.router.block_mac(mac, comment=f"Blocked via bot {datetime.now():%Y-%m-%d %H:%M}")
                msg = f"🚫 Blocked {mac} permanently" if ok else "❌ Block failed"
            else:
                ok = False
                msg = "Unknown action"
            self._edit(chat_id, message_id, msg, [])
            tg.answer_callback(callback_id, "Done" if ok else "Failed")

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

        lines = [
            "🛡 Security Status",
            "━━━━━━━━━━━━━━━━━",
            f"📋 Failed logins (in log): {len(fails)}",
        ]
        if fails:
            lines.append("Last 5:")
            for f in fails[-5:]:
                lines.append(f"  {f[:80]}")
        lines.extend([
            "",
            f"📡 ARP entries: {arp_count}",
            f"🚫 Permanent WiFi blocks: {block_count}",
        ])
        self.notifier.send_to(chat_id, "\n".join(lines))

    # ─── helpers ────────────────────────────────────────────────

    def _tg(self) -> TelegramNotifier | None:
        n = self.ctx.notifiers_by_id.get("tg")
        return n if isinstance(n, TelegramNotifier) else None

    def _send_buttons(self, chat_id: int, text: str, buttons: list) -> None:
        tg = self._tg()
        if not tg:
            return
        tg.api_post("sendMessage", {
            "chat_id": chat_id, "text": text,
            "reply_markup": __import__("json").dumps({"inline_keyboard": buttons}),
        })

    def _edit(self, chat_id: int, message_id: int, text: str, buttons: list) -> None:
        tg = self._tg()
        if not tg:
            return
        tg.edit_message(chat_id, message_id, text, buttons)
