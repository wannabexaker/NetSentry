"""
power — restart the router, the Raspberry Pi, or NetSentry itself, from Telegram.

`/restart` shows three buttons; each asks "are you sure?" before anything
happens. When NetSentry comes back after a restart it requested, it says so.

  * Router — the router's own reboot command, over the usual SSH link.
  * NetSentry — the service exits cleanly and systemd starts it again
    (the unit has ``Restart=always``).
  * Raspberry Pi — NetSentry runs unprivileged and sandboxed, so it cannot
    reboot the machine itself. It drops a request file instead, and a tiny
    root-owned systemd path unit (``deploy/netsentry-power.*``) acts on it. If
    that helper isn't installed, you're told and nothing happens.

Config keys:
    helper_wait_s    how long to wait for the Pi helper before giving up (default 20)
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from pathlib import Path

from ..core.plugin import Plugin

_TARGETS = {
    "router": ("📡 Router", "The router restarts: WiFi and internet drop for 1–2 minutes."),
    "service": ("🛡 NetSentry only", "NetSentry restarts: monitoring pauses for ~15 seconds."),
    "pi": ("🖥 Raspberry Pi", "The whole Pi reboots (Pi-hole too): DNS and monitoring "
                             "are down for 1–2 minutes."),
}


class PowerPlugin(Plugin):
    COMMANDS = [
        {"command": "restart", "description": "🔁 Restart router / Pi / NetSentry"},
    ]

    def on_load(self) -> None:
        self._request = Path(self.ctx.state_dir) / "request"
        self._pending = Path(self.ctx.state_dir) / "pending.json"
        self._helper_wait_s = float(self.cfg.get("helper_wait_s", 20))
        # A request file left over from a previous run must never fire later.
        self._request.unlink(missing_ok=True)
        if self._pending.exists():
            self._after(8.0, self._announce_back)

    # ─── buttons ─────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/restart":
            self._show_menu(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # power:ask:<target> | power:do:<target> | power:menu | power:cancel
        _, verb, target = (data.split(":", 2) + ["", ""])[:3]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "ask" and target in _TARGETS:
            ack()
            label, effect = _TARGETS[target]
            name = self.ctx.name
            self._show(chat_id, message_id, f"⚠️ Restart {label}?\n{effect}", [[
                {"text": "✅ Yes, restart", "callback_data": f"{name}:do:{target}"},
                {"text": "✖ Cancel", "callback_data": f"{name}:cancel"},
            ]])
        elif verb == "do" and target in _TARGETS:
            ack("Restarting…")
            self._show(chat_id, message_id, self.restart(target, chat_id), [])
        elif verb == "cancel":
            ack("Cancelled")
            self._show(chat_id, message_id, "✖ Nothing was restarted.", [])
        else:
            ack()
            self._show_menu(chat_id, message_id)

    def _show_menu(self, chat_id: int, message_id: int | None) -> None:
        name = self.ctx.name
        rows = [[{"text": label, "callback_data": f"{name}:ask:{key}"}]
                for key, (label, _) in _TARGETS.items()]
        self._show(chat_id, message_id,
                   "🔁 Restart\n━━━━━━━━━━━━━━━━━\n"
                   "Pick what to restart — you'll be asked to confirm.", rows)

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons or None)

    # ─── actions ─────────────────────────────────────────────────

    def restart(self, target: str, chat_id: int) -> str:
        """Start the restart; returns the message to show right away."""
        if target == "router":
            try:
                self.router.reboot()
            except Exception as e:
                self.log.exception("router reboot failed")
                return f"❌ Could not tell the router to restart: {e}"
            self.log.warning("Router restart requested from chat %s", chat_id)
            return ("📡 Router is restarting. WiFi and internet will be back in "
                    "1–2 minutes; I'll report the reboot once it's up.")
        self._remember(target, chat_id)
        if target == "service":
            self.log.warning("NetSentry restart requested from chat %s", chat_id)
            self._after(1.5, self._exit_for_restart)
            return "🛡 NetSentry is restarting — back in about 15 seconds."
        self.log.warning("Pi reboot requested from chat %s", chat_id)
        try:
            self._request.parent.mkdir(parents=True, exist_ok=True)
            self._request.write_text("reboot\n", encoding="utf-8")
        except OSError as e:
            self._pending.unlink(missing_ok=True)
            return f"❌ Could not write the reboot request: {e}"
        self._after(self._helper_wait_s, self._helper_did_not_act, chat_id)
        return "🖥 Rebooting the Raspberry Pi — back in 1–2 minutes."

    def _exit_for_restart(self) -> None:
        os.kill(os.getpid(), signal.SIGTERM)       # clean stop; systemd restarts us

    def _helper_did_not_act(self, chat_id: int) -> None:
        """Still alive and the request is still there: nobody is listening for it."""
        if not self._request.exists():
            return
        self._request.unlink(missing_ok=True)
        self._pending.unlink(missing_ok=True)
        self.notifier.send_to(
            chat_id,
            "❌ The Pi did not reboot: the restart helper isn't installed.\n"
            "NetSentry runs without root, so rebooting the Pi needs the small "
            "systemd helper from deploy/netsentry-power.* (see INSTALL).")

    def _remember(self, target: str, chat_id: int) -> None:
        try:
            self._pending.parent.mkdir(parents=True, exist_ok=True)
            self._pending.write_text(
                json.dumps({"target": target, "chat_id": chat_id, "ts": time.time()}),
                encoding="utf-8")
        except OSError:
            self.log.exception("could not record the pending restart")

    def _announce_back(self) -> None:
        try:
            info = json.loads(self._pending.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            info = {}
        self._pending.unlink(missing_ok=True)
        if not info:
            return
        took = int(time.time() - float(info.get("ts", time.time())))
        what = "The Raspberry Pi" if info.get("target") == "pi" else "NetSentry"
        try:
            self.notifier.send_to(info["chat_id"],
                                  f"✅ {what} is back (restart took {took}s). /health")
        except Exception:
            self.log.exception("could not announce the restart")

    def _after(self, seconds: float, func, *args) -> None:
        timer = threading.Timer(seconds, func, args=args)
        timer.daemon = True
        timer.start()
