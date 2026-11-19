"""
self_check — NetSentry watching NetSentry.

Everything else here watches the network. This watches the watchers: a monitor
that has quietly stopped looks exactly like "nothing is happening", so each
plugin reports whether its work is *really* happening (`Plugin.health()`), and
this plugin

  * answers `/health` with the whole picture, problems first;
  * re-checks on a schedule and tells you when something stops working — and
    again when it recovers;
  * contributes one line to the morning briefing.

Config keys:
    interval_minutes   how often to re-check (default 10)
    confirm_checks     consecutive bad results before alerting (default 2), so a
                       momentary blip doesn't page you
    min_free_mb        free space required where NetSentry keeps its state
                       (default 500)
    check_updates      also report pending OS security updates / a required
                       reboot on Debian-family hosts (default true)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
import time
from pathlib import Path

from ..core.plugin import HealthCheck, Plugin, ScheduledTask


class SelfCheckPlugin(Plugin):
    COMMANDS = [
        {"command": "health", "description": "🩺 Is everything actually running?"},
    ]

    def on_load(self) -> None:
        self._interval_min = max(1, int(self.cfg.get("interval_minutes", 10)))
        self._confirm = max(1, int(self.cfg.get("confirm_checks", 2)))
        self._min_free_mb = int(self.cfg.get("min_free_mb", 500))
        self._state_file = Path(self.ctx.state_dir) / "status.json"
        self._check_updates = bool(self.cfg.get("check_updates", True))
        self._updates_cache: tuple[float, HealthCheck | None] = (0.0, None)

    def scheduled_tasks(self) -> list[ScheduledTask]:
        n = self._interval_min
        cron = f"*/{n} * * * *" if n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [ScheduledTask(cron=cron, func=self.watch, name="watch")]

    # ─── gathering ───────────────────────────────────────────────

    def checks(self) -> list[HealthCheck]:
        """Every plugin's health, plus the things only the runtime can see."""
        out: list[HealthCheck] = []
        for p in getattr(self.ctx, "_all_plugins", []):
            if p is self:
                continue
            try:
                out += list(p.health())
            except Exception as e:
                self.log.exception("health() of %s crashed", p.ctx.name)
                out.append(HealthCheck(f"{p.ctx.name} self-report", False,
                                       f"health check crashed: {type(e).__name__}"))
        out += self._job_checks()
        out.append(self._disk_check())
        updates = self._updates_check()
        if updates is not None:
            out.append(updates)
        return out

    def _updates_check(self) -> HealthCheck | None:
        """Pending OS security updates (asked of apt at most every 6 hours)."""
        if not self._check_updates:
            return None
        checked, cached = self._updates_cache
        if time.time() - checked < 6 * 3600:
            return cached
        result = self._read_updates()
        self._updates_cache = (time.time(), result)
        return result

    def _read_updates(self) -> HealthCheck | None:
        apt = shutil.which("apt")
        if apt is None:
            return None                              # not a Debian-family host
        try:
            r = subprocess.run(  # nosec B603 - fixed argv, no shell
                [apt, "list", "--upgradable"], capture_output=True, text=True,
                timeout=30, env={**os.environ, "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError):
            return None
        pending = [line for line in r.stdout.splitlines() if "/" in line and "[" in line]
        security = [line for line in pending if "security" in line.split()[0].lower()]
        reboot = os.path.exists("/var/run/reboot-required")
        name = "Raspberry Pi system updates"
        if security or reboot:
            bits = []
            if security:
                bits.append(f"{len(security)} security update(s) waiting")
            if reboot:
                bits.append("a reboot is needed to finish an update")
            return HealthCheck(name, False, "; ".join(bits) +
                               " — on the Pi: sudo apt update && sudo apt upgrade")
        return HealthCheck(name, True, f"no security updates waiting ({len(pending)} other)")

    def _job_checks(self) -> list[HealthCheck]:
        stats_fn = getattr(self.ctx.scheduler, "job_stats", None)
        if stats_fn is None:
            return []
        stats = stats_fn()
        broken = {name: st["last_error"] for name, st in stats.items()
                  if st.get("last_error")}
        if broken:
            return [HealthCheck(f"Scheduled job {name}", False, f"last run failed: {err}")
                    for name, err in sorted(broken.items())]
        return [HealthCheck("Scheduled jobs", True, f"{len(stats)} jobs, none failing")]

    def _disk_check(self) -> HealthCheck:
        try:
            free_mb = shutil.disk_usage(self.ctx.state_dir).free // (1024 * 1024)
        except OSError as e:
            return HealthCheck("Disk space", False, f"cannot read disk usage: {e}")
        if free_mb < self._min_free_mb:
            return HealthCheck("Disk space", False, f"only {free_mb} MB free")
        return HealthCheck("Disk space", True, f"{free_mb // 1024} GB free")

    # ─── /health ─────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/health":
            self._send_report(chat_id)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        answer = getattr(self.notifier, "answer_callback", None)
        if answer:
            answer(callback_id, "Re-checked")
        self._send_report(chat_id, message_id)

    def report(self) -> str:
        checks = self.checks()
        bad = [c for c in checks if not c.ok]
        good = [c for c in checks if c.ok]
        head = ("✅ Everything is running" if not bad
                else f"⚠️ {len(bad)} thing(s) need attention")
        lines = [f"🩺 NetSentry self-check — {time.strftime('%H:%M')}", head,
                 "━━━━━━━━━━━━━━━━━"]
        for c in bad:
            lines.append(f"❌ {c.name}\n     {c.detail}")
        if bad and good:
            lines.append("")
        for c in good:
            lines.append(f"✅ {c.name}" + (f" — {c.detail}" if c.detail else ""))
        lines.append("\nRe-checked automatically every "
                     f"{self._interval_min} min; you are told when something stops.")
        return "\n".join(lines)

    def _send_report(self, chat_id: int, message_id: int | None = None) -> None:
        text = self.report()
        buttons = [[{"text": "🔄 Check again",
                     "callback_data": f"{self.ctx.name}:refresh"}]]
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons)

    def summary_line(self) -> str:
        """One line for the morning briefing."""
        checks = self.checks()
        bad = [c for c in checks if not c.ok]
        if not bad:
            return f"🩺 Self-check: all {len(checks)} checks OK"
        names = ", ".join(c.name for c in bad[:3]) + ("…" if len(bad) > 3 else "")
        return f"🩺 Self-check: ⚠️ {len(bad)} problem(s) — {names}  (/health)"

    # ─── watchdog ────────────────────────────────────────────────

    def watch(self) -> None:
        """Alert on a check that has gone bad (and stayed bad); say when it's back."""
        checks = self.checks()
        seen = self._load()
        streaks: dict[str, int] = dict(seen.get("streaks", {}))
        alerted: set[str] = set(seen.get("alerted", []))
        current = {c.name: c for c in checks}

        newly_bad: list[HealthCheck] = []
        for name, c in current.items():
            if c.ok:
                streaks.pop(name, None)
                continue
            streaks[name] = streaks.get(name, 0) + 1
            if streaks[name] >= self._confirm and name not in alerted:
                alerted.add(name)
                newly_bad.append(c)
        # Recovered = was alerted, and is now fine (or no longer reported at all).
        recovered = sorted(n for n in alerted if n not in current or current[n].ok)
        alerted -= set(recovered)
        for name in list(streaks):
            if name not in current:
                streaks.pop(name)

        self._save({"streaks": streaks, "alerted": sorted(alerted)})

        if newly_bad:
            body = "\n".join(f"❌ {c.name}\n     {c.detail}" for c in newly_bad)
            self._notify("warning",
                         "🩺 NetSentry self-check: something stopped working\n"
                         f"{body}\n\n/health shows the full picture.")
        if recovered:
            self._notify("protected",
                         "🩺 Back to normal: " + ", ".join(recovered))

    def _notify(self, state: str, text: str) -> None:
        try:
            self.notifier.send_state(state, text)
        except Exception:
            self.log.exception("self_check: could not notify")

    def _load(self) -> dict:
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(self._state_file)
        except OSError:
            self.log.exception("self_check: could not persist status")
