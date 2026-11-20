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
  * Internet (ISP) router — it usually has no way to be restarted remotely, so
    its power goes through a Shelly smart plug: the plug switches off and
    switches *itself* back on a few seconds later. The button only appears when
    ``isp_plug`` is configured, and it first shows what the plug reports.

Config keys:
    helper_wait_s    how long to wait for the Pi helper before giving up (default 20)
    isp_plug         the smart plug feeding the ISP router (Shelly Gen2/Gen3/Plus):
        host             the plug's address
        switch           which socket of the plug (default 0)
        off_seconds      how long the power stays off (default 10)
        via_router_port  set this when the NetSentry host cannot reach the plug
                         directly (it sits outside the router). NetSentry then
                         asks the router for ONE forward: from this host only,
                         this port only, to the plug only.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from pathlib import Path

from ..core import notify, ui
from ..core.events import RESTART_REQUESTED
from ..core.plugin import Plugin
from ..core.router import local_address_towards as _own_address_towards
from ..core.shelly import PlugError, PlugState, ShellyPlug

_TARGETS = {
    "router": ("📡 Router", "The router restarts: WiFi and internet drop for 1–2 minutes."),
    "service": ("🛡 NetSentry only", "NetSentry restarts: monitoring pauses for ~15 seconds."),
    "pi": ("🖥 Raspberry Pi", "The whole Pi reboots (Pi-hole too): DNS and monitoring "
                             "are down for 1–2 minutes."),
}


class PowerPlugin(Plugin):
    COMMANDS = [
        {"command": "restart", "description": "🔁 Restart router, Pi or NetSentry"},
    ]

    def on_load(self) -> None:
        self._request = Path(self.ctx.state_dir) / "request"
        self._pending = Path(self.ctx.state_dir) / "pending.json"
        self._helper_wait_s = float(self.cfg.get("helper_wait_s", 20))
        plug = self.cfg.get("isp_plug") or {}
        self._plug_host = str(plug.get("host") or "").strip()
        self._plug_switch = int(plug.get("switch", 0))
        self._plug_off_s = max(3, min(int(plug.get("off_seconds", 10)), 120))
        self._plug_via_port = int(plug.get("via_router_port") or 0)
        self._internet_wait_s = float(self.cfg.get("internet_wait_s", 900))
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

        if verb == "isp" and self._plug_host:
            self._isp_callback(target, chat_id, message_id, ack)
        elif verb == "ask" and target in _TARGETS:
            ack()
            label, effect = _TARGETS[target]
            name = self.ctx.name
            self._show(chat_id, message_id, f"{ui.ATTENTION} Restart {label}?\n{effect}",
                       ui.confirm_rows("🔁", "restart", f"{name}:do:{target}",
                                       f"{name}:cancel"))
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
        if self._plug_host:
            rows.append([{"text": "🌐 Internet router (smart plug)",
                          "callback_data": f"{name}:isp:look"}])
        rows.append(ui.nav_row())
        self._show(chat_id, message_id,
                   ui.title("🔁", "Restart") + "\n"
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
            except Exception:
                self.log.exception("router reboot failed")
                return ("❌ The router was NOT restarted — it didn't take the command. "
                        "Everything keeps running as before.")
            self.log.warning("Router restart requested from chat %s", chat_id)
            self._announce_request("router")
            return (f"{ui.WORKING} The router is restarting. WiFi and internet are back "
                    "in 1–2 minutes; you'll hear once it's up.")
        self._remember(target, chat_id)
        if target == "service":
            self.log.warning("NetSentry restart requested from chat %s", chat_id)
            self._after(1.5, self._exit_for_restart)
            return f"{ui.WORKING} NetSentry is restarting — back in about 15 s."
        self.log.warning("Pi reboot requested from chat %s", chat_id)
        try:
            self._request.parent.mkdir(parents=True, exist_ok=True)
            self._request.write_text("reboot\n", encoding="utf-8")
        except OSError:
            self.log.exception("could not write the reboot request")
            self._pending.unlink(missing_ok=True)
            return ("❌ The Pi was NOT rebooted — NetSentry couldn't hand over the "
                    "request. Everything keeps running.")
        self._after(self._helper_wait_s, self._helper_did_not_act, chat_id)
        return f"{ui.WORKING} The Raspberry Pi is restarting — back in 1–2 minutes."

    # ─── the ISP router, through its smart plug ──────────────────

    def _isp_callback(self, step: str, chat_id: int, message_id: int, ack) -> None:
        # power:isp:look | power:isp:go | power:isp:on | power:isp:fix
        try:
            plug = self._plug()
            if step == "go":
                ack("Switching the power off…")
                self._show(chat_id, message_id, self._isp_restart(plug, chat_id), [])
                return
            if step == "on":
                plug.turn_on()
                ack("Plug switched on")
            elif step == "fix":
                plug.come_back_on_after_power_cut()
                ack("Done")
            else:
                ack()
            text, rows = self._isp_screen(plug.state())
        except PlugError as e:
            ack("Plug not reachable")
            text, rows = (ui.title("🌐", "Internet router (smart plug)") + "\n"
                          f"❌ {e}. Nothing was switched."), [[
                              {"text": "🔁 Try again", "callback_data": f"{self.ctx.name}:isp:look"},
                              {"text": "⬅ Back", "callback_data": f"{self.ctx.name}:menu"}]]
        self._show(chat_id, message_id, text, rows)

    def _plug(self) -> ShellyPlug:
        """The plug, reached directly or through one forward on the router."""
        if not self._plug_via_port:
            return ShellyPlug(f"http://{self._plug_host}", self._plug_switch)
        router_host = str(getattr(self.router, "host", "") or "")
        result = self.router.port_forward_ensure(
            "isp-plug", _own_address_towards(router_host), self._plug_via_port,
            self._plug_host, 80)
        if result == "failed":
            raise PlugError("the router would not set up the path to the plug")
        if result == "added":
            self.log.warning("Added the router forward to the ISP-router plug (port %d)",
                             self._plug_via_port)
            if self.ctx.events:                 # our own change: not a tamper alarm
                self.ctx.events.publish("router.config.expected_change",
                                        {"source": self.ctx.name, "what": "plug forward"})
        return ShellyPlug(f"http://{router_host}:{self._plug_via_port}", self._plug_switch)

    def _isp_screen(self, state: PlugState) -> tuple[str, list]:
        name = self.ctx.name
        lines = [ui.title("🌐", "Internet router (smart plug)",
                          "power on" if state.on else "power off"),
                 "The plug answers."]
        if state.watts is not None:
            lines.append(f"Drawing now: {state.watts:.1f} W")
            if state.on and state.watts < 1.0:
                lines.append("⚠️ Nothing seems to be drawing power — is the router "
                             "plugged into this plug?")
        rows: list = []
        if not state.comes_back_by_itself:
            lines.append("⚠️ After a power cut this plug stays OFF, which would leave "
                         "the router off. Fix that first.")
            rows.append([{"text": "🔧 Make it come back ON after a power cut",
                          "callback_data": f"{name}:isp:fix"}])
        elif not state.on:
            lines.append("The plug is off, so the router has no power.")
            rows.append([{"text": "⚡ Switch the plug on", "callback_data": f"{name}:isp:on"}])
        else:
            lines.append(f"\nRestarting cuts the power for {self._plug_off_s} seconds; the "
                         "plug then switches back on by itself. The internet is away "
                         "for 2–4 minutes and NetSentry can only report once it is back.")
            rows.append([{"text": "🔁 Restart it now", "callback_data": f"{name}:isp:go"}])
        rows.append([{"text": "⬅ Back", "callback_data": f"{name}:menu"},
                     {"text": "✖ Cancel", "callback_data": f"{name}:cancel"}])
        return "\n".join(lines), rows

    def _isp_restart(self, plug: ShellyPlug, chat_id: int) -> str:
        state = plug.state()
        if not state.on or not state.comes_back_by_itself:
            return "✖ Not restarted — the plug changed state meanwhile. Nothing was switched."
        self._remember("isp", chat_id)
        try:
            plug.cycle(self._plug_off_s)
        except PlugError:
            self._pending.unlink(missing_ok=True)
            raise
        self.log.warning("ISP router power-cycle requested from chat %s", chat_id)
        self._announce_request("isp")
        self._after(self._plug_off_s + 20, self._wait_for_internet, chat_id, time.time())
        return (f"{ui.WORKING} Power to the internet router is off for {self._plug_off_s} s.\n"
                "You'll hear when the internet is back (usually 2–4 minutes).")

    def _wait_for_internet(self, chat_id: int, started: float) -> None:
        """Report as soon as Telegram is reachable again (it is our only way out)."""
        probe = getattr(self.notifier, "api_get", None)
        deadline = started + self._internet_wait_s
        while time.time() < deadline:
            if probe is None or probe("getMe", timeout=8, log_errors=False):
                self._pending.unlink(missing_ok=True)
                took = time.time() - started
                self._say_back(chat_id, f"{ui.OK} The internet is back — "
                                        f"{ui.duration(took)} after the power was cut.")
                return
            time.sleep(10)
        self.log.error("Internet did not come back within %d s of the ISP router "
                       "power-cycle", int(self._internet_wait_s))

    def has_isp_plug(self) -> bool:
        """True when the internet (ISP) router can be restarted through a plug."""
        return bool(self._plug_host)

    def _announce_request(self, target: str) -> None:
        """Tell the monitors this restart is the owner's own, so the reboot or
        outage that follows is not reported as a surprise."""
        if self.ctx.events:
            self.ctx.events.publish(RESTART_REQUESTED, {"target": target})

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
        took = time.time() - float(info.get("ts", time.time()))
        what = {"pi": "The Raspberry Pi",
                "isp": "The internet router"}.get(info.get("target"), "NetSentry")
        if "chat_id" in info:
            self._say_back(info["chat_id"],
                           f"{ui.OK} {what} is back — the restart took {ui.duration(took)}.")

    def _say_back(self, chat_id, text: str) -> None:
        """"X is back" arrives on its own a while after the tap: a recovery
        message (silent in normal mode), with the full check one tap away."""
        checker = ui.plugin_named(self.ctx, "self_check")
        buttons = ui.rows([ui.button("🩺 Full check", "self_check:full")]
                          if checker is not None else [])
        try:
            self.notifier.notify(notify.RECOVERY, text, buttons=buttons, chat_id=chat_id)
        except Exception:
            self.log.exception("could not announce the restart")

    def _after(self, seconds: float, func, *args) -> None:
        timer = threading.Timer(seconds, func, args=args)
        timer.daemon = True
        timer.start()
