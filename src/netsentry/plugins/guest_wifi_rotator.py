"""
guest_wifi_rotator — Rotate a guest WiFi password on a schedule and on demand.

Telegram commands:
    /rotate    Generate new password + QR, push to router, send QR to chat.
    /guest     Show the current guest password + QR (no rotation).
    /keep      Guest devices that keep their password: pick a device that is
               connected now and it stays on the guest network with the
               password it has, however often the password changes for everyone
               else. Buttons only; removing one takes a second tap.
    /rotation  Show or change *when* the password rotates — takes effect at
               once, no restart:
                 /rotation                      status + one-tap buttons
                 /rotation now                  rotate right away (asks to confirm)
                 /rotation daily [HH:MM]
                 /rotation weekly [mon..sun] [HH:MM]
                 /rotation monthly [1-28] [HH:MM]
                 /rotation yearly [DD-MM] [HH:MM]
                 /rotation cron <m h dom mon dow>
                 /rotation never                stop rotating automatically
                 /rotation default              back to the config.yaml schedule

Config keys:
    ssid                 SSID name to advertise in QR (e.g. "Guest")
    security_profile     Router security profile to update (e.g. "guest-visitor")
    rotation_cron        5-field cron (default: Mondays 09:00). A schedule set
                         with /rotation is stored in the plugin state dir and
                         overrides this until `/rotation default`.
    diceware_words       Words in generated password (default 4)
    diceware_digits      Trailing digits (default 4)
    throttle_seconds     Min interval between manual /rotate calls (default 30)
    keep_isolated        Devices added with /keep cannot see other WiFi devices
                         (default true — it is a guest network)
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
from datetime import datetime
from pathlib import Path

from ..core import notify, ui
from ..core.plugin import HealthCheck, Plugin, ScheduledTask
from ..core.scheduler import cron_is_valid
from ..core.schedules import SchedulePicker, Screen, humanize_cron, parse_schedule


DICEWARE_WORDS = (
    "amber bronze clay coral delta emerald forest granite hazel iris jade kestrel "
    "lotus mango nectar opal pearl quartz raven sable thunder umber violet whisper "
    "xenon yellow zephyr canyon river ocean meadow island summit valley harbor "
    "garden orchard breeze cinder dawn ember frost glade horizon ivory juniper "
    "kelp linden moss nettle oak pinion ridge sienna tundra willow brook cedar "
    "dune elm fern grove"
).split()

_DEFAULT_CRON = "0 9 * * 1"
# One-tap presets offered as buttons; anything finer goes through the command.
_PRESETS = ("daily", "weekly", "monthly", "yearly", "never")

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")

_USAGE = (
    "Usage:\n"
    "/rotation — status + buttons\n"
    "/rotation now\n"
    "/rotation daily [HH:MM]\n"
    "/rotation weekly [mon..sun] [HH:MM]\n"
    "/rotation monthly [1-28] [HH:MM]\n"
    "/rotation yearly [DD-MM] [HH:MM]\n"
    "/rotation cron <m h dom mon dow>\n"
    "/rotation never · /rotation default"
)


class GuestWifiRotatorPlugin(Plugin):
    COMMANDS = [
        {"command": "rotate", "description": "🎲 New Guest WiFi password now"},
        {"command": "guest",  "description": "🔐 Guest WiFi password and QR"},
        {"command": "rotation", "description": "🗓 Guest WiFi password schedule",
         "usage": "/rotation daily HH:MM | weekly <day> HH:MM | monthly <1-28> HH:MM | "
                  "yearly DD-MM HH:MM | cron <5 fields> | never | default | now"},
        {"command": "keep", "description": "📌 Guests that keep their password"},
    ]
    # /rotate asks "Change the <ssid> password now?" itself — never twice.
    CONFIRMS_ITSELF = frozenset({"/rotate"})

    def on_load(self) -> None:
        self._last_rotate_ts = 0.0
        self._schedule_file = Path(self.ctx.state_dir) / "schedule.json"
        self._last_file = Path(self.ctx.state_dir) / "last_rotation"
        self._failed_file = Path(self.ctx.state_dir) / "last_failure"
        self._job = f"{self.ctx.name}.rotate"
        self._picker = SchedulePicker(self.ctx.name, back=f"{self.ctx.name}:m")

    # ─── scheduled rotation ──────────────────────────────────────

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron, _ = self._schedule()
        if cron is None:
            return []
        return [ScheduledTask(cron=cron, func=self.rotate, name="rotate")]

    def _schedule(self) -> tuple[str | None, str]:
        """Effective ``(cron, label)``: the /rotation override, else config."""
        try:
            data = json.loads(self._schedule_file.read_text(encoding="utf-8"))
            cron = data.get("cron")
            if cron is None or cron_is_valid(str(cron)):
                return cron, str(data.get("label") or cron or "never")
            self.log.warning("Ignoring invalid stored rotation schedule %r", cron)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError):
            self.log.warning("Unreadable rotation schedule file; using config")
        cron = str(self.cfg.get("rotation_cron", _DEFAULT_CRON))
        return cron, f"cron {cron} (from config)"

    def _apply_schedule(self, cron: str | None, label: str) -> None:
        """Persist a schedule and re-arm the live job — no restart needed."""
        self._schedule_file.parent.mkdir(parents=True, exist_ok=True)
        self._schedule_file.write_text(
            json.dumps({"cron": cron, "label": label,
                        "set_at": datetime.now().isoformat(timespec="seconds")}),
            encoding="utf-8")
        self._rearm()
        self.log.info("Rotation schedule set: %s", label)

    def _reset_schedule(self) -> None:
        self._schedule_file.unlink(missing_ok=True)
        self._rearm()
        self.log.info("Rotation schedule reset to config")

    def _rearm(self) -> None:
        sched = self.ctx.scheduler
        if sched is None:
            return
        cron, _ = self._schedule()
        if cron is None:
            sched.remove(self._job)
        else:
            sched.add_cron(cron, self.rotate, name=self._job)

    # ─── commands ────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/rotate":
            self._ask_rotate_now(chat_id)
        elif command == "/guest":
            self._handle_show(chat_id)
        elif command == "/rotation":
            self._handle_rotation(chat_id, args.strip())
        elif command == "/keep":
            self._kept_home(chat_id)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # Frequency → day → hour → minute is the shared SchedulePicker; the rest
        # (m menu, set:<preset>, default, now, now!, cancel, and k… for the
        # devices that keep their password) is ours.
        verb, *args = data.split(":")[1:] or [""]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        step = self._picker.step(verb, args)
        if isinstance(step, Screen):
            ack()
            self._show(chat_id, message_id, step.text, step.rows)
        elif isinstance(step, str):
            self._save_choice(step, chat_id, message_id, ack)
        elif verb == "m":
            ack()
            self._send_status(chat_id, message_id)
        elif verb == "ms":                      # opened from /settings: Back returns there
            ack()
            self.show_rotation(chat_id, message_id, back="settings:h")
        elif verb == "set" and len(args) == 1 and args[0] in _PRESETS:
            self._save_choice(args[0], chat_id, message_id, ack)
        elif verb == "default":
            self._reset_schedule()
            ack("Using config.yaml")
            self._send_status(chat_id, message_id)
        elif verb == "now":
            ack()
            self._ask_rotate_now(chat_id)
        elif verb == "now!":
            ack("Rotating…")
            self._handle_rotate(chat_id, message_id)
        elif verb == "cancel":
            ack("Cancelled")
            self._show(chat_id, message_id, ui.NOTHING_CHANGED, [])
        elif verb in ("k", "ka", "kq", "kp", "kx", "kX"):
            self._kept_callback(verb, ":".join(args).upper(), chat_id, message_id, ack)
        else:
            ack("?")

    def _save_choice(self, choice: str, chat_id: int, message_id: int, ack) -> None:
        """Validate a picked schedule (same parser as the typed form) and apply it."""
        try:
            cron, label = parse_schedule(choice)
        except ValueError:
            ack("That choice isn't valid")
            return
        self._apply_schedule(cron, label)
        ack("Saved ✅")
        self._send_status(chat_id, message_id)

    # ─── button pickers ──────────────────────────────────────────

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list) -> None:
        """Redraw the menu message in place (or send it if there is none yet)."""
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons)

    def _handle_rotation(self, chat_id: int, args: str) -> None:
        if not args:
            self._send_status(chat_id)
            return
        word = args.lower()
        if word == "now":
            self._ask_rotate_now(chat_id)
            return
        if word in ("default", "reset"):
            self._reset_schedule()
            self._send_status(chat_id)
            return
        try:
            cron, label = parse_schedule(args)
        except ValueError as e:
            self.notifier.send_to(chat_id, f"❌ Not changed — {e}.\n\n{_USAGE}")
            self._send_status(chat_id)      # …and offer the buttons instead
            return
        self._apply_schedule(cron, label)
        self._send_status(chat_id)

    def _ask_rotate_now(self, chat_id: int) -> None:
        ssid = self.cfg.get("ssid", "Guest")
        name = self.ctx.name
        self.notifier.send_to(
            chat_id,
            f"🔄 Change the {ssid} password now? Devices on it have to rejoin with "
            "the new one (devices that keep their password stay connected).",
            buttons=ui.confirm_rows("🔄", "change it", f"{name}:now!", f"{name}:cancel"))

    def _send_status(self, chat_id: int, message_id: int | None = None) -> None:
        self.show_rotation(chat_id, message_id)

    def show_rotation(self, chat_id: int, message_id: int | None = None,
                      back: str | None = None) -> None:
        """The rotation screen. ``back`` = callback data of the screen it was
        opened from (Settings), for its ⬅ Back button."""
        cron, label = self._schedule()
        sched = self.ctx.scheduler
        nxt = sched.next_run(self._job) if sched is not None else None
        try:
            last = self._last_file.read_text(encoding="utf-8").strip()
        except OSError:
            last = ""
        text = "\n".join([
            ui.title("🗓", f"{self.cfg.get('ssid', 'Guest')} password schedule",
                     humanize_cron(cron) if cron else "never by itself"),
            f"Setting: {label}",
            f"Next change: {ui.fmt_when(nxt) if isinstance(nxt, datetime) else 'none scheduled'}",
            f"Last change: {_stored_when(last) or 'not recorded yet'}",
            "",
            "Tap what you want — day and time are picked with buttons. "
            "Changes apply immediately.",
        ])
        name = self.ctx.name
        buttons = [
            [{"text": "🎲 Change the password now", "callback_data": f"{name}:now"}],
            *self._picker.frequency_rows(),
            [{"text": "⛔ Never", "callback_data": f"{name}:set:never"},
             {"text": "↩ Config default", "callback_data": f"{name}:default"}],
            [{"text": "📌 Devices that keep their password", "callback_data": f"{name}:k"}],
            ui.nav_row(back),
        ]
        self._show(chat_id, message_id, text, buttons)

    # ─── guests who keep their password ──────────────────────────
    # For the relative who lives on the guest network: their device keeps the
    # password it has, so the rotation that protects the network from one-time
    # visitors does not lock them out every week.

    def _kept_callback(self, verb: str, mac: str, chat_id: int, message_id: int, ack) -> None:
        ssid = self.cfg.get("ssid", "Guest")
        me = self.ctx.name
        if verb == "k":
            ack()
            self._kept_home(chat_id, message_id)
        elif verb == "ka":
            ack()
            self._kept_add_screen(chat_id, message_id)
        elif verb == "kq":
            ack()
            self._handle_show(chat_id)
        elif not _MAC_RE.match(mac):
            ack("?")
        elif verb == "kp":
            result, name = self._keep(mac)
            if result == "added":
                ack("Done ✅")
                self._kept_home(chat_id, message_id, note=(
                    f"✅ {name} keeps its password from now on "
                    "(it reconnects for a moment). "
                    "It is recognised by its WiFi address: if the network is "
                    "\"forgotten\" on the device, add it here again."))
            elif result == "exists":
                ack("Already kept")
                self._kept_home(chat_id, message_id)
            elif result == "not-connected":
                ack("Not connected")
                self._kept_add_screen(chat_id, message_id, note=(
                    f"⚠️ {name} is not connected to {ssid} right now, so nothing was changed."))
            else:
                ack("Not changed")
                self._kept_home(chat_id, message_id, note=(
                    "❌ The router did not accept it. Nothing was changed."))
        elif verb == "kx":
            ack()
            name = self._device_names([mac])[mac]
            self._show(chat_id, message_id, (
                f"📌 Make {name} a normal guest again?\n"
                f"It stays connected for now. The next time it joins {ssid} it needs "
                "the password everyone else uses."), [[
                    {"text": "✅ Yes, normal guest", "callback_data": f"{me}:kX:{mac}"},
                    {"text": "⬅ Back", "callback_data": f"{me}:k"}]])
        else:                                   # kX — the confirmed removal
            released, name = self._release(mac)
            if released:
                ack("Done")
                self._kept_home(chat_id, message_id, note=f"✅ {name} is a normal guest again.")
            else:
                ack("Not changed")
                self._kept_home(chat_id, message_id, note=(
                    "❌ The router did not accept it. Nothing was changed."))

    def _keep(self, mac: str) -> tuple[str, str]:
        """Make one device keep its password; ``(router result, device name)``."""
        ssid = self.cfg.get("ssid", "Guest")
        name = self._device_names([mac])[mac]
        result = self.router.keep_wifi_passphrase(
            mac, ssid, label=name, isolate=bool(self.cfg.get("keep_isolated", True)))
        if result == "added":
            self.log.warning("%s (%s) now keeps its %s password", name, mac, ssid)
            self._expected_router_change("guest keeps password")
        return result, name

    def _release(self, mac: str) -> tuple[bool, str]:
        name = self._device_names([mac])[mac]
        released = bool(self.router.release_wifi_passphrase(mac))
        if released:
            self.log.warning("%s (%s) no longer keeps its %s password",
                             name, mac, self.cfg.get("ssid", "Guest"))
            self._expected_router_change("guest no longer keeps password")
        return released, name

    # ─── for the web dashboard (never the password itself) ───────

    def api_status(self) -> dict:
        cron, _ = self._schedule()
        schedule = humanize_cron(cron) if cron else "never (only when you ask)"
        sched = self.ctx.scheduler
        nxt = sched.next_run(self._job) if sched is not None else None
        try:
            last = self._last_file.read_text(encoding="utf-8").strip()
        except OSError:
            last = ""
        return {"ssid": self.cfg.get("ssid", "Guest"),
                "schedule": schedule[:1].upper() + schedule[1:],
                "next": nxt.strftime("%a %Y-%m-%d %H:%M") if nxt else "", "last": last}

    def api_keep(self, mac: str, on: bool) -> str:
        """``added`` / ``exists`` / ``not-connected`` / ``removed`` / ``failed``."""
        mac = (mac or "").upper()
        if not _MAC_RE.match(mac):
            return "failed"
        if on:
            return self._keep(mac)[0]
        return "removed" if self._release(mac)[0] else "failed"

    def _kept_home(self, chat_id: int, message_id: int | None = None, note: str = "") -> None:
        ssid = self.cfg.get("ssid", "Guest")
        me = self.ctx.name
        back = [{"text": "🗓 Password schedule", "callback_data": f"{me}:m"}, *ui.nav_row()]
        kept = self.router.kept_wifi_passphrases()
        head = ui.title("📌", f"{ssid} — kept passwords",
                        ui.plural(len(kept), "device") if isinstance(kept, dict) else "") + "\n"
        if kept is None:
            self._show(chat_id, message_id, head + "❌ The router did not answer. "
                       "Nothing was changed.",
                       [[{"text": "🔁 Try again", "callback_data": f"{me}:k"}], back])
            return
        names = self._device_names(list(kept), fallback=kept)
        online = {c.mac.upper() for c in self._guest_clients()}
        order = sorted(kept, key=lambda m: names[m].lower())
        if kept:
            listed = "\n".join(
                f"{'🟢' if m in online else '⚪'} {names[m]}"
                + ("" if m in online else " — not connected now") for m in order)
            body = (f"When the {ssid} password changes, these stay connected. "
                    f"Everyone else needs the new one.\n\n{listed}\n\n"
                    "Tap a device to make it a normal guest again.")
        else:
            body = ("No device yet.\n\n"
                    f"A device you add keeps the password it has now. When the {ssid} "
                    "password changes, it stays connected and everyone else needs the "
                    "new one. It stays on the guest network.")
        rows = [[{"text": f"✖ {names[m][:40]}", "callback_data": f"{me}:kx:{m}"}] for m in order]
        rows.append([{"text": "➕ Add a device", "callback_data": f"{me}:ka"}])
        rows.append(back)
        self._show(chat_id, message_id, head + body + (f"\n\n{note}" if note else ""), rows)

    def _kept_add_screen(self, chat_id: int, message_id: int | None, note: str = "") -> None:
        ssid = self.cfg.get("ssid", "Guest")
        me = self.ctx.name
        kept = self.router.kept_wifi_passphrases() or {}
        waiting = [c.mac.upper() for c in self._guest_clients() if c.mac.upper() not in kept]
        names = self._device_names(waiting)
        waiting.sort(key=lambda m: names[m].lower())
        head = ui.title("➕", "Which device should keep its password?") + "\n"
        if waiting:
            body = f"Connected to {ssid} right now — tap one:"
            rows = [[{"text": names[m][:40], "callback_data": f"{me}:kp:{m}"}]
                    for m in waiting[:30]]
        else:
            body = (f"No other device is connected to {ssid} right now.\n"
                    "Connect it first with the current password, then come back.")
            rows = [[{"text": "🔐 Show the current password", "callback_data": f"{me}:kq"}]]
        rows.append([ui.refresh_button(f"{me}:ka")])
        rows.append(ui.nav_row(f"{me}:k"))
        self._show(chat_id, message_id, head + body + (f"\n\n{note}" if note else ""), rows)

    def _guest_clients(self) -> list:
        """Devices connected to the guest network right now (empty if unreadable)."""
        ssid = self.cfg.get("ssid", "Guest")
        try:
            return [c for c in self.router.wifi_clients() if c.ssid == ssid]
        except Exception:
            self.log.exception("could not read the WiFi clients")
            return []

    def _device_names(self, macs: list[str],
                      fallback: dict[str, str] | None = None) -> dict[str, str]:
        """Owner's tag, else the name the device gave itself, else the stored label."""
        tagger = next((p for p in getattr(self.ctx, "_all_plugins", [])
                       if hasattr(p, "tag_for")), None)
        try:
            hostnames = {lease.mac.upper(): lease.hostname for lease in self.router.dhcp_leases()}
        except Exception:
            hostnames = {}
        names = {}
        for mac in macs:
            tag = tagger.tag_for(mac) if tagger else None
            names[mac] = tag or hostnames.get(mac) or (fallback or {}).get(mac) or mac
        return names

    def _expected_router_change(self, what: str) -> None:
        if self.ctx.events:                     # our own change: not a tamper alarm
            self.ctx.events.publish("router.config.expected_change",
                                    {"source": self.ctx.name, "what": what})

    def _handle_rotate(self, chat_id: int, message_id: int | None = None) -> None:
        throttle = int(self.cfg.get("throttle_seconds", 30))
        elapsed = time.time() - self._last_rotate_ts
        if elapsed < throttle:
            self._show(chat_id, message_id,
                       f"{ui.WORKING} The password was just changed — try again in "
                       f"{int(throttle - elapsed)} s. Nothing changed.", [])
            return
        self._last_rotate_ts = time.time()
        # The question becomes the progress line, so no live button is left.
        self._show(chat_id, message_id,
                   f"{ui.WORKING} Changing the {self.cfg.get('ssid', 'Guest')} password…", [])
        self.rotate(target_chat=chat_id)

    def _handle_show(self, chat_id: int) -> None:
        profile = self.cfg["security_profile"]
        passphrase = self.router.get_wifi_passphrase(profile)
        ssid = self.cfg.get("ssid", "Guest")
        if not passphrase:
            self.notifier.send_to(chat_id, f"{ui.FAILED} Couldn't read the {ssid} password "
                                           "from the router. Nothing was changed.")
            return
        self._send_qr(chat_id, passphrase, caption_prefix=f"🔐 Current {ssid} password")

    # ─── core logic ──────────────────────────────────────────────

    def rotate(self, target_chat: int | None = None) -> None:
        """Generate new password, push to router, send QR. Used by cron + /rotate."""
        ssid = self.cfg["ssid"]
        profile = self.cfg["security_profile"]
        n_words = int(self.cfg.get("diceware_words", 4))
        n_digits = int(self.cfg.get("diceware_digits", 4))

        new_pass = self._generate_passphrase(n_words, n_digits)
        ok = self.router.set_wifi_passphrase(profile, new_pass)
        if not ok:
            # The router may have taken the new password on some radios and not
            # others, so don't promise "nothing changed" — say what to do.
            msg = (f"{ui.header(ui.FAILED, f'{ssid} password', 'NOT changed')}\n"
                   "The router didn't confirm the new password, so it wasn't sent "
                   "to anyone. Guests may still be on the old one — try again, or "
                   "check which password the router has now.")
            self.log.error("Failed to set and verify passphrase on router profile %s", profile)
            self._mark(self._failed_file)
            me = self.ctx.name
            buttons = [[ui.button("🔁 Try again", f"{me}:now"),
                        ui.button("🔐 Current password", f"{me}:kq")]]
            if target_chat is not None:
                self.notifier.send_to(target_chat, msg, buttons=buttons)
            else:
                self.notifier.notify(notify.ATTENTION, msg, buttons=buttons)
            # Either way the owner has been told; the watchdog only adds the
            # "back to normal" once a rotation works again.
            notify.report_problem(self.ctx, self._check_name())
            return

        self.log.info("Rotated %s passphrase", profile)
        self._mark(self._last_file)
        self._failed_file.unlink(missing_ok=True)

        if self.ctx.events:
            self.ctx.events.publish("wifi.password.rotated",
                                    {"ssid": ssid, "profile": profile})

        chat = target_chat if target_chat is not None else None
        self._send_qr(chat, new_pass, caption_prefix=f"🔐 New {ssid} password",
                      ssid=ssid, note=self._kept_note())

    def _kept_note(self) -> str:
        """One line for the rotation message about the devices it did not touch."""
        try:
            kept = self.router.kept_wifi_passphrases() or {}
            if not isinstance(kept, dict) or not kept:
                return ""
            names = self._device_names(list(kept), fallback=kept)
        except Exception:
            return ""
        listed = ", ".join(sorted(names.values(), key=str.lower)[:6])
        return f"📌 Not affected (they keep their own password): {listed}"

    def _mark(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(datetime.now().strftime("%a %Y-%m-%d %H:%M"), encoding="utf-8")
        except OSError:
            pass

    def _check_name(self) -> str:
        return f"{self.cfg.get('ssid', 'Guest')} password rotation"

    def health(self) -> list[HealthCheck]:
        name = self._check_name()
        try:
            failed = self._failed_file.read_text(encoding="utf-8").strip()
        except OSError:
            failed = ""
        if failed:
            # rotate() told the owner when it failed (reply or alert).
            return [HealthCheck(name, False,
                                f"the last change ({_stored_when(failed) or failed}) failed — "
                                "the router didn't confirm it",
                                notified=True)]
        cron, _ = self._schedule()
        return [HealthCheck(name, True, humanize_cron(cron) if cron
                            else "never by itself — only when you ask")]

    def _send_qr(self, chat_id: int | None, passphrase: str,
                 caption_prefix: str, ssid: str | None = None, note: str = "") -> None:
        """Generate WIFI-format QR code, send via Telegram."""
        ssid = ssid or self.cfg["ssid"]
        wifi_str = f"WIFI:S:{ssid};T:WPA;P:{passphrase};;"
        # A name of its own: two requests in the same second (commands that
        # queued up while Telegram was not answering) must not share one file.
        png_path = Path(self.ctx.state_dir) / f"qr-{int(time.time())}-{secrets.token_hex(4)}.png"
        png_path.parent.mkdir(parents=True, exist_ok=True)
        # The password is tap-to-copy (<code>); every inserted value is escaped.
        caption = ui.lines(
            ui.b(caption_prefix),
            f"WiFi: {ssid}",
            ui.concat("Password: ", ui.code(passphrase)),
            f"Time: {ui.fmt_when(datetime.now())}",
            note or None,
        )
        made = _make_qr(wifi_str, png_path)
        if not made:
            self.log.error("QR code generation failed (qrcode / qrencode missing?)")
            caption = ui.lines(caption, "(The QR code couldn't be made — type the password.)")
        photo = str(png_path) if made else None
        # The QR is the one picture NetSentry still sends: it is the point of
        # the message. A scheduled rotation is a report (it never makes a noise
        # in normal mode, but always arrives); a /rotate or /guest is a reply.
        if chat_id is not None:
            self.notifier.send_to(chat_id, caption, photo_path=photo, html=True)
        else:
            self.notifier.notify(notify.REPORT, caption, html=True, photo_path=photo)

        try:
            png_path.unlink()
        except OSError:
            pass

    def _generate_passphrase(self, n_words: int, n_digits: int) -> str:
        rng = secrets.SystemRandom()
        words = rng.sample(DICEWARE_WORDS, n_words)
        digits = "".join(secrets.choice("0123456789") for _ in range(n_digits))
        prefix = (self.cfg.get("password_prefix") or "guest").lower()
        return f"{prefix}-" + "-".join(words) + "-" + digits


def _stored_when(text: str) -> str:
    """A time stored as ``Mon 2026-11-23 09:00`` (see ``_mark``) as the owner
    reads it; '' when it can't be read."""
    try:
        when = datetime.strptime(text.strip().split(" ", 1)[-1], "%Y-%m-%d %H:%M")
    except ValueError:
        return ""
    return ui.when_text(when)


def _make_qr(content: str, out_path: Path) -> bool:
    """Generate a PNG QR. Tries `qrcode` (pip) first, then `qrencode` (system)."""
    try:
        import qrcode
        img = qrcode.make(content, box_size=10, border=4)
        img.save(out_path)
        return True
    except ImportError:
        pass
    try:
        r = subprocess.run(
            ["qrencode", "-t", "PNG", "-s", "10", "-m", "4", "-o", str(out_path), content],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False
