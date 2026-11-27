"""
settings — change *when* things run, from Telegram, without touching config.yaml.

`/settings` lists the scheduled jobs you might want to move (backups, reports,
the morning briefing, scans) with their current schedule and next run. Tap one
and pick a new time with buttons, pause it, or put it back to its default.
A change applies immediately and survives restarts.

The times in `config.yaml` stay the defaults; what you choose here is stored on
top of them (`scheduler/overrides.json`) and "Default" removes it again.
Pausing a job asks first — a paused backup stays paused until someone resumes it.

`🔔 Notifications` switches how loud NetSentry is (relaxed / normal /
everything, see `core/notify.py`); the choice is kept by the notifier and wins
over its `notify_mode` config key.
"""

from __future__ import annotations

from ..core import notify, ui
from ..core.plugin import Plugin
from ..core.schedules import SchedulePicker, Screen, humanize_cron, parse_schedule

# (short key for button data, scheduler job, label). Jobs not listed here are
# internal heartbeats (scans, health checks) that are not meant to be moved.
_JOBS: list[tuple[str, str, str]] = [
    ("mb", "morning_briefing.daily", "☀️ Morning briefing"),
    ("rp", "threat_detector.report", "📰 Findings report"),
    ("tr", "traffic_report.daily", "📈 Traffic report"),
    ("bk", "config_backup.weekly", "💾 Router config backup"),
    ("sb", "self_backup.weekly", "🗄 NetSentry self-backup"),
    ("cs", "channel_scan.weekly", "📻 WiFi channel scan"),
    ("ti", "threat_detector.intel", "🧠 Malware-list update"),
    ("mt", "maintenance.weekly", "🧰 Pi updates notice"),
]
_MODES = ("daily", "weekly", "monthly")


class SettingsPlugin(Plugin):
    COMMANDS = [
        {"command": "settings", "description": "⚙️ Change when things run"},
    ]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/settings":
            self._show_home(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # settings:h | settings:rot | settings:j:<key> | settings:<key>:<verb>[:args]
        parts = data.split(":")[1:]
        head, rest = (parts[0] if parts else ""), parts[1:]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        job = self._job(rest[0]) if head == "j" and rest else self._job(head)
        sched = self.ctx.scheduler
        if head == "n":
            self._notifications(chat_id, message_id, rest[0] if rest else "", ack)
        elif head == "rot":
            ack()
            # The rotation screen opens in place, with ⬅ Back to Settings.
            rotator = ui.plugin_named(self.ctx, "guest_wifi_rotator")
            show = getattr(rotator, "show_rotation", None)
            if callable(show):
                show(chat_id, message_id, back=f"{self.ctx.name}:h")
            else:
                bot = next((p for p in getattr(self.ctx, "_all_plugins", [])
                            if hasattr(p, "dispatch_command")), None)
                if bot is not None:
                    bot.dispatch_command("/rotation", "", chat_id)
        elif job is None or sched is None:
            ack()
            self._show_home(chat_id, message_id)
        elif head == "j":
            ack()
            self._show_job(chat_id, message_id, job)
        else:
            key, name, _ = job
            verb, args = (rest[0] if rest else ""), rest[1:]
            note = ""
            step = SchedulePicker(f"{self.ctx.name}:{key}",
                                  back=f"{self.ctx.name}:j:{key}", modes=_MODES).step(verb, args)
            if isinstance(step, Screen):
                ack()
                self._show(chat_id, message_id, step.text, step.rows)
                return
            if isinstance(step, str):
                try:
                    cron, _ = parse_schedule(step)
                except ValueError:
                    ack("That choice isn't valid")
                    return
                ok = sched.set_schedule(name, cron)
                ack("Saved ✅" if ok else "Could not save")
            elif verb == "pause":
                # Pausing stops a backup or report until someone remembers to
                # resume it — ask first, and say so.
                ack()
                self._show(chat_id, message_id,
                           f"⏸ Pause {job[2]}? It won't run until you resume it here.",
                           ui.confirm_rows("⏸", "pause", f"{self.ctx.name}:{key}:pause!",
                                           f"{self.ctx.name}:{key}:keep"))
                return
            elif verb == "pause!":
                ok = sched.set_schedule(name, None)
                ack("Paused" if ok else "Not paused")
                note = ("⏸ Paused. It won't run until you resume it." if ok
                        else f"{ui.FAILED} Not paused — the change couldn't be saved. "
                             "It runs as before.")
            elif verb == "keep":
                ack("Cancelled")
                note = ui.NOTHING_CHANGED
            elif verb in ("default", "resume"):
                sched.clear_schedule(name)
                ack("Back to default")
            else:
                ack()
            self._show_job(chat_id, message_id, job, note=note)

    # ─── screens ─────────────────────────────────────────────────

    def _jobs(self) -> list[tuple[str, str, str]]:
        """The adjustable jobs that are actually registered in this install."""
        sched = self.ctx.scheduler
        if sched is None:
            return []
        return [j for j in _JOBS if sched.schedule_of(j[1]) is not None]

    def _job(self, key: str) -> tuple[str, str, str] | None:
        return next((j for j in self._jobs() if j[0] == key), None)

    def _line(self, name: str) -> str:
        info = self.ctx.scheduler.schedule_of(name)
        if info["paused"]:
            return "⏸ paused"
        text = humanize_cron(info["cron"])
        nxt = info["next_run"]
        return text + (f"\n   next: {ui.fmt_when(nxt)}" if nxt else "")

    def _show_home(self, chat_id: int, message_id: int | None) -> None:
        name = self.ctx.name
        jobs = self._jobs()
        lines = [ui.header("⚙️", "Settings", "when things run"), ui.RULE]
        for _, job, label in jobs:
            lines.append(f"{label}\n   {self._line(job)}")
        lines.append("\nTap one to change it — applies immediately.")
        rows = [[{"text": label, "callback_data": f"{name}:j:{key}"}]
                for key, _, label in jobs]
        rows.append([{"text": "🗓 Guest WiFi password schedule",
                      "callback_data": f"{name}:rot"}])
        policy = self._policy()
        if policy is not None:
            label, _ = notify.MODE_INFO[policy.mode]
            lines.insert(2, f"🔔 Notifications\n   {label}")
            rows.append([ui.button("🔔 Notifications", f"{name}:n")])
        if self._menu_loaded():
            rows.append(ui.nav_row())
        self._show(chat_id, message_id, "\n".join(lines), rows)

    # ─── 🔔 notifications ───────────────────────────────────────

    def _policy(self):
        policy = getattr(self.notifier, "policy", None)
        return policy if isinstance(policy, notify.NotifyPolicy) else None

    def _notifications(self, chat_id: int, message_id: int | None, choice: str, ack) -> None:
        """How loud NetSentry is: three modes, one line each on what they mean."""
        policy = self._policy()
        if policy is None:
            ack("Not available")
            self._show_home(chat_id, message_id)
            return
        note = ""
        if choice:
            if policy.set_mode(choice):
                ack("Saved ✅")
                note = f"{ui.OK} Saved — applies to the next message."
            else:
                ack("Not saved")
                note = f"{ui.FAILED} Not saved — the mode stays as it was."
        else:
            ack()
        current = policy.mode
        lines = [ui.title("🔔", "Notifications", "how loud")]
        for mode in notify.MODES:
            label, meaning = notify.MODE_INFO[mode]
            mark = " — now" if mode == current else ""
            lines.append(f"{label}{mark}\n   {meaning}")
        lines.append("\nReplies to what you tap or type always arrive with sound.")
        if note:
            lines.append(f"\n{note}")
        me = self.ctx.name
        rows = [[ui.button(("✓ " if mode == current else "") + notify.MODE_INFO[mode][0],
                           f"{me}:n:{mode}")] for mode in notify.MODES]
        rows.append(ui.nav_row(f"{me}:h", home=self._menu_loaded()))
        self._show(chat_id, message_id, "\n".join(lines), rows)

    def _menu_loaded(self) -> bool:
        return ui.plugin_named(self.ctx, "menu") is not None

    def _show_job(self, chat_id: int, message_id: int | None,
                  job: tuple[str, str, str], note: str = "") -> None:
        key, name, label = job
        info = self.ctx.scheduler.schedule_of(name)
        prefix = f"{self.ctx.name}:{key}"
        lines = [label, ui.RULE, f"Now: {self._line(name)}"]
        if note:
            lines.insert(0, note)
        if info["overridden"]:
            lines.append(f"Default: {humanize_cron(info['default'])}")
        lines.append("\nPick how often — then the day and time with buttons.")
        rows = SchedulePicker(prefix, back=f"{self.ctx.name}:j:{key}",
                              modes=_MODES).frequency_rows()
        toggle = ({"text": "▶ Resume", "callback_data": f"{prefix}:resume"}
                  if info["paused"] else
                  {"text": "⏸ Pause", "callback_data": f"{prefix}:pause"})
        last = [toggle]
        if info["overridden"] and not info["paused"]:
            last.append({"text": "↩ Default", "callback_data": f"{prefix}:default"})
        rows += [last, ui.nav_row(f"{self.ctx.name}:h", home=self._menu_loaded())]
        self._show(chat_id, message_id, "\n".join(lines), rows)

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons)
