"""
guest_wifi_rotator — Rotate a guest WiFi password on a schedule and on demand.

Telegram commands:
    /rotate    Generate new password + QR, push to router, send QR to chat.
    /guest     Show the current guest password + QR (no rotation).
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
"""

from __future__ import annotations

import json
import secrets
import subprocess
import time
from datetime import datetime
from pathlib import Path

from ..core.plugin import Plugin, ScheduledTask
from ..core.scheduler import cron_is_valid


DICEWARE_WORDS = (
    "amber bronze clay coral delta emerald forest granite hazel iris jade kestrel "
    "lotus mango nectar opal pearl quartz raven sable thunder umber violet whisper "
    "xenon yellow zephyr canyon river ocean meadow island summit valley harbor "
    "garden orchard breeze cinder dawn ember frost glade horizon ivory juniper "
    "kelp linden moss nettle oak pinion ridge sienna tundra willow brook cedar "
    "dune elm fern grove"
).split()

_DEFAULT_CRON = "0 9 * * 1"
_WEEKDAYS = {
    "mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu",
    "fri": "Fri", "sat": "Sat", "sun": "Sun",
}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTH_DAYS = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
# One-tap presets offered as buttons; anything finer goes through the command.
_PRESETS = ("daily", "weekly", "monthly", "yearly", "never")

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


def parse_schedule(text: str) -> tuple[str | None, str]:
    """Turn ``/rotation`` arguments into ``(cron, label)``.

    ``cron`` is None for "never". Raises ``ValueError`` with a message meant
    for the user when the arguments don't make sense.
    """
    tokens = text.lower().split()
    if not tokens:
        raise ValueError("no schedule given")
    mode, rest = tokens[0], tokens[1:]

    if mode in ("never", "off", "none"):
        return None, "never (manual only)"
    if mode == "cron":
        cron = " ".join(rest)
        if not cron_is_valid(cron):
            raise ValueError("that is not a valid 5-field cron (m h dom mon dow)")
        return cron, f"custom cron {cron}"

    times = [t for t in rest if ":" in t]
    other = [t for t in rest if ":" not in t]
    if len(times) > 1 or len(other) > 1:
        raise ValueError("too many arguments")
    hour, minute = _parse_time(times[0]) if times else (9, 0)
    at = f"{hour:02d}:{minute:02d}"
    arg = other[0] if other else ""

    if mode == "daily":
        if arg:
            raise ValueError("daily only takes a time, e.g. daily 07:30")
        return f"{minute} {hour} * * *", f"every day at {at}"
    if mode == "weekly":
        day = (arg or "mon")[:3]
        if day not in _WEEKDAYS:
            raise ValueError("weekday must be one of mon tue wed thu fri sat sun")
        return f"{minute} {hour} * * {day}", f"every week on {_WEEKDAYS[day]} at {at}"
    if mode == "monthly":
        dom = _parse_int(arg or "1", 1, 28,
                         "day of month must be 1-28 (so it exists in every month)")
        return f"{minute} {hour} {dom} * *", f"every month on day {dom} at {at}"
    if mode == "yearly":
        day_s, sep, month_s = (arg or "01-01").replace("/", "-").partition("-")
        if not sep:
            raise ValueError("yearly date must be DD-MM, e.g. yearly 01-01")
        month = _parse_int(month_s, 1, 12, "month must be 1-12")
        dom = _parse_int(day_s, 1, _MONTH_DAYS[month - 1],
                         "that day does not exist in that month")
        if (dom, month) == (29, 2):
            raise ValueError("29 Feb only exists in leap years — pick another day")
        return (f"{minute} {hour} {dom} {month} *",
                f"once a year on {dom} {_MONTHS[month - 1]} at {at}")
    raise ValueError(f"unknown schedule '{mode}'")


def _describe(mode: str, day: str) -> str:
    """Plain-words summary of a schedule being picked (for the picker titles)."""
    if mode == "weekly":
        return f"Every week on {_WEEKDAYS.get(day, day)}"
    if mode == "monthly":
        return f"Every month on day {day}"
    if mode == "yearly":
        dom, _, month = day.partition("-")
        name = _MONTHS[int(month) - 1] if month.isdigit() and 1 <= int(month) <= 12 else month
        return f"Once a year on {dom} {name}"
    return "Every day"


def _parse_int(text: str, lo: int, hi: int, message: str) -> int:
    if not text.isdigit() or not lo <= int(text) <= hi:
        raise ValueError(message)
    return int(text)


def _parse_time(text: str) -> tuple[int, int]:
    hour_s, _, minute_s = text.partition(":")
    message = "time must be HH:MM (24h), e.g. 09:00"
    return _parse_int(hour_s, 0, 23, message), _parse_int(minute_s, 0, 59, message)


class GuestWifiRotatorPlugin(Plugin):
    COMMANDS = [
        {"command": "rotate", "description": "🔄 Rotate guest WiFi password + QR"},
        {"command": "guest",  "description": "🔐 Show current guest password + QR"},
        {"command": "rotation", "description": "🗓 When the guest password rotates"},
    ]

    def on_load(self) -> None:
        self._last_rotate_ts = 0.0
        self._schedule_file = Path(self.ctx.state_dir) / "schedule.json"
        self._last_file = Path(self.ctx.state_dir) / "last_rotation"
        self._job = f"{self.ctx.name}.rotate"

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
            self._handle_rotate(chat_id)
        elif command == "/guest":
            self._handle_show(chat_id)
        elif command == "/rotation":
            self._handle_rotation(chat_id, args.strip())

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # The schedule is picked entirely with buttons, one small step per tap:
        #   pick:<mode> → (mo:<month> →) d:<mode>:<day> → t:<mode>:<day>:<hh>
        #   → ok:<mode>:<day>:<hh>:<mm>   ("-" stands for "no day", i.e. daily)
        # plus m (menu), set:<preset>, default, now, now!, cancel.
        verb, *args = data.split(":")[1:] or [""]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "m":
            ack()
            self._send_status(chat_id, message_id)
        elif verb == "pick" and args[:1] == ["daily"]:
            ack()
            self._show_hours(chat_id, message_id, "daily", "-")
        elif verb == "pick" and args and args[0] in ("weekly", "monthly", "yearly"):
            ack()
            self._show_days(chat_id, message_id, args[0])
        elif verb == "mo" and len(args) == 1 and args[0].isdigit() and 1 <= int(args[0]) <= 12:
            ack()
            self._show_days(chat_id, message_id, "yearly", month=int(args[0]))
        elif verb == "d" and len(args) == 2:
            ack()
            self._show_hours(chat_id, message_id, args[0], args[1])
        elif verb == "t" and len(args) == 3:
            ack()
            self._show_minutes(chat_id, message_id, *args)
        elif verb == "ok" and len(args) == 4:
            mode, day, hour, minute = args
            choice = " ".join(x for x in (mode, "" if day == "-" else day,
                                           f"{hour}:{minute}") if x)
            self._save_choice(choice, chat_id, message_id, ack)
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
            self._handle_rotate(chat_id)
        elif verb == "cancel":
            ack("Cancelled")
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

    def _grid(self, cells: list[tuple[str, str]], per_row: int) -> list:
        """Rows of buttons from (label, callback-suffix) pairs, plus a Back row."""
        name = self.ctx.name
        keys = [{"text": label, "callback_data": f"{name}:{data}"}
                for label, data in cells]
        rows = [keys[i:i + per_row] for i in range(0, len(keys), per_row)]
        return [*rows, [{"text": "⬅ Back", "callback_data": f"{name}:m"}]]

    def _show_days(self, chat_id: int, message_id: int, mode: str,
                   month: int | None = None) -> None:
        if mode == "weekly":
            text = "🗓 Every week — which day?"
            cells = [(label, f"d:weekly:{day}") for day, label in _WEEKDAYS.items()]
            per_row = 4
        elif mode == "monthly":
            text = "🗓 Every month — which day of the month?"
            cells = [(str(d), f"d:monthly:{d}") for d in range(1, 29)]
            per_row = 7
        elif month is None:
            text = "🗓 Once a year — which month?"
            cells = [(label, f"mo:{m}") for m, label in enumerate(_MONTHS, 1)]
            per_row = 4
        else:
            last = 28 if month == 2 else _MONTH_DAYS[month - 1]
            text = f"🗓 Once a year in {_MONTHS[month - 1]} — which day?"
            cells = [(str(d), f"d:yearly:{d}-{month}") for d in range(1, last + 1)]
            per_row = 7
        self._show(chat_id, message_id, text, self._grid(cells, per_row))

    def _show_hours(self, chat_id: int, message_id: int, mode: str, day: str) -> None:
        cells = [(f"{h:02d}", f"t:{mode}:{day}:{h:02d}") for h in range(24)]
        self._show(chat_id, message_id,
                   f"🕘 {_describe(mode, day)} — at what hour?",
                   self._grid(cells, 6))

    def _show_minutes(self, chat_id: int, message_id: int, mode: str, day: str,
                      hour: str) -> None:
        cells = [(f"{hour}:{m}", f"ok:{mode}:{day}:{hour}:{m}")
                 for m in ("00", "15", "30", "45")]
        self._show(chat_id, message_id,
                   f"🕘 {_describe(mode, day)} — exact time?",
                   self._grid(cells, 4))

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
            self.notifier.send_to(chat_id, f"❌ {e}\n\n{_USAGE}")
            self._send_status(chat_id)      # …and offer the buttons instead
            return
        self._apply_schedule(cron, label)
        self._send_status(chat_id)

    def _ask_rotate_now(self, chat_id: int) -> None:
        ssid = self.cfg.get("ssid", "Guest")
        name = self.ctx.name
        self.notifier.send_to(
            chat_id,
            f"⚠️ Rotate the {ssid} password now? Devices on it will have to rejoin.",
            buttons=[[
                {"text": "✅ Rotate now", "callback_data": f"{name}:now!"},
                {"text": "✖ Cancel", "callback_data": f"{name}:cancel"},
            ]])

    def _send_status(self, chat_id: int, message_id: int | None = None) -> None:
        _, label = self._schedule()
        sched = self.ctx.scheduler
        nxt = sched.next_run(self._job) if sched is not None else None
        try:
            last = self._last_file.read_text(encoding="utf-8").strip()
        except OSError:
            last = ""
        text = (
            f"🗓 {self.cfg.get('ssid', 'Guest')} password rotation\n"
            "━━━━━━━━━━━━━━━━━\n"
            f"Schedule: {label}\n"
            f"Next: {nxt.strftime('%a %Y-%m-%d %H:%M') if nxt else '— none scheduled'}\n"
            f"Last: {last or 'not recorded yet'}\n\n"
            "Tap what you want — day and time are picked with buttons, "
            "nothing to type. Changes apply immediately."
        )
        name = self.ctx.name
        buttons = [
            [{"text": "🔄 Change the password now", "callback_data": f"{name}:now"}],
            [{"text": "Every day", "callback_data": f"{name}:pick:daily"},
             {"text": "Every week", "callback_data": f"{name}:pick:weekly"}],
            [{"text": "Every month", "callback_data": f"{name}:pick:monthly"},
             {"text": "Once a year", "callback_data": f"{name}:pick:yearly"}],
            [{"text": "⛔ Never", "callback_data": f"{name}:set:never"},
             {"text": "↩ Config default", "callback_data": f"{name}:default"}],
        ]
        self._show(chat_id, message_id, text, buttons)

    def _handle_rotate(self, chat_id: int) -> None:
        throttle = int(self.cfg.get("throttle_seconds", 30))
        elapsed = time.time() - self._last_rotate_ts
        if elapsed < throttle:
            self.notifier.send_to(chat_id, f"⏳ Throttled. Try again in {int(throttle - elapsed)}s.")
            return
        self._last_rotate_ts = time.time()
        self.notifier.send_to(chat_id, "🔄 Rotating…")
        self.rotate(target_chat=chat_id)

    def _handle_show(self, chat_id: int) -> None:
        profile = self.cfg["security_profile"]
        passphrase = self.router.get_wifi_passphrase(profile)
        if not passphrase:
            self.notifier.send_to(chat_id, "❌ Couldn't read current passphrase.")
            return
        ssid = self.cfg.get("ssid", "Guest")
        self._send_qr(chat_id, passphrase, caption_prefix=f"🔐 Current {ssid}")

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
            msg = f"❌ Rotation failed: router read-back verification failed. Profile={profile}"
            self.log.error("Failed to set and verify passphrase on router profile %s", profile)
            if target_chat is not None and hasattr(self.notifier, "send_to"):
                self.notifier.send_to(target_chat, msg)
            else:
                self.notifier.send(msg)
            return

        self.log.info("Rotated %s passphrase", profile)
        try:
            self._last_file.write_text(
                datetime.now().strftime("%a %Y-%m-%d %H:%M"), encoding="utf-8")
        except OSError:
            pass

        if self.ctx.events:
            self.ctx.events.publish("wifi.password.rotated",
                                    {"ssid": ssid, "profile": profile})

        chat = target_chat if target_chat is not None else None
        self._send_qr(chat, new_pass, caption_prefix=f"🔐 New {ssid} password",
                      ssid=ssid)

    def _send_qr(self, chat_id: int | None, passphrase: str,
                 caption_prefix: str, ssid: str | None = None) -> None:
        """Generate WIFI-format QR code, send via Telegram."""
        ssid = ssid or self.cfg["ssid"]
        wifi_str = f"WIFI:S:{ssid};T:WPA;P:{passphrase};;"
        png_path = Path(self.ctx.state_dir) / f"qr-{int(time.time())}.png"
        png_path.parent.mkdir(parents=True, exist_ok=True)
        if not _make_qr(wifi_str, png_path):
            self.notifier.send(f"❌ QR generation failed.\nPassword: {passphrase}")
            return

        caption = (
            f"{caption_prefix}\n"
            f"SSID: {ssid}\n"
            f"Password: {passphrase}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        if chat_id is not None:
            self.notifier.send_to(chat_id, caption, photo_path=str(png_path))
        else:
            self.notifier.send(caption, photo_path=str(png_path))

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
