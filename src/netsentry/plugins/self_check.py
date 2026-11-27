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
    disk_max_used_pct  the disk NetSentry lives on may be this full (default 85);
                       on an SD card "nearly full" arrives quietly — logs, images
                       and backups all grow — so the limit is a share of the
                       card, whatever its size. 0 = do not check the share.
    min_free_mb        free space required where NetSentry keeps its state
                       (default 500)
    check_updates      also report pending OS security updates / a required
                       reboot on Debian-family hosts (default true)
    error_window_minutes
                       an error written to the log counts as a problem for this
                       long (default 60; 0 = do not watch the log)
    check_router_readings
                       compare what NetSentry reads from the router with what
                       the router itself counts (default true)

"It ran" is not "it worked". Two checks here look at results rather than
activity, because that is where failures hid before:

  * *Reading the router* — the router counts its own WiFi devices, DHCP leases
    and ARP entries; NetSentry's parsed lists must roughly match. A listing
    that changes shape makes a parser return nothing, and "nothing" looks like
    a quiet network.
  * *Error log* — anything logged at ERROR. A job that catches its own
    exception still "succeeds"; the error line is the only trace.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
import threading
import time
from collections import deque
from pathlib import Path

from ..core import notify, ui
from ..core.notify import HEALTH_ALERTED
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_ROUTER_CHECK_EVERY_S = 300.0      # four router queries: not on every page refresh
_TABLES = (("wifi", "WiFi devices"), ("dhcp", "DHCP leases"), ("arp", "ARP entries"))
#: Checks that report something waiting for the owner, not something broken.
_NOT_BROKEN = frozenset({"Raspberry Pi system updates"})


def _error_owner(logger: str, message: str) -> str:
    """Which plugin an error line belongs to ("" when it cannot be told).

    Plugins log as ``netsentry.<plugin>``; a crashed scheduled job is logged by
    the scheduler library and names the job (``<plugin>.<task>``) in its text.
    """
    parts = logger.split(".")
    if parts[0] == "netsentry" and len(parts) > 1 and parts[1] not in ("core", "plugins"):
        return parts[1]
    if parts[0] == "netsentry" and len(parts) > 2 and parts[1] == "plugins":
        return parts[2]
    if parts[0] == "apscheduler":
        m = re.search(r'"([a-z_]+)\.[a-z_]+', message)
        return m.group(1) if m else ""
    return ""


def _one_line(text: str, limit: int = 100) -> str:
    """The first line of an error, short enough to read in a list. The owner is
    a developer and this line is what tells him what to do; the rest is in the log."""
    first = str(text or "").strip().splitlines()[0] if str(text or "").strip() else "no details"
    return first if len(first) <= limit else first[:limit - 1] + "…"


def _shown(check_name: str) -> str:
    """A check's name as the owner reads it. The stored name stays the key in
    status.json; only ``Scheduled job <plugin>.<task>`` reads better spelled out."""
    if check_name.startswith("Scheduled job "):
        job = check_name.removeprefix("Scheduled job ")
        plugin, _, task = job.partition(".")
        return f"Scheduled job: {plugin.replace('_', ' ')}" + (f" ({task})" if task else "")
    return check_name


class _ErrorLog(logging.Handler):
    """Remembers the last errors written to the log, by any part of NetSentry."""

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.seen: deque[tuple[float, str, str]] = deque(maxlen=50)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.seen.append((record.created, record.name, record.getMessage()[:160]))
        except Exception:                        # nosec B110 - a log hook must never raise
            pass


class SelfCheckPlugin(Plugin):
    COMMANDS = [
        {"command": "health", "description": "🩺 NetSentry health checks"},
    ]

    def on_load(self) -> None:
        self._interval_min = max(1, int(self.cfg.get("interval_minutes", 10)))
        self._confirm = max(1, int(self.cfg.get("confirm_checks", 2)))
        self._min_free_mb = int(self.cfg.get("min_free_mb", 500))
        self._disk_max_used_pct = max(0, min(int(self.cfg.get("disk_max_used_pct", 85)), 100))
        self._state_file = Path(self.ctx.state_dir) / "status.json"
        self._check_updates = bool(self.cfg.get("check_updates", True))
        self._updates_cache: tuple[float, HealthCheck | None] = (0.0, None)
        self._check_router = bool(self.cfg.get("check_router_readings", True))
        self._router_cache: tuple[float, HealthCheck | None] = (0.0, None)
        self._error_window_s = max(0, int(self.cfg.get("error_window_minutes", 60))) * 60
        self._errors: _ErrorLog | None = None
        if self._error_window_s:
            self._errors = _ErrorLog()
            logging.getLogger().addHandler(self._errors)
        # status.json is changed by the watch job and by plugins that tell us
        # they alerted the owner themselves (different threads).
        self._state_lock = threading.Lock()
        if self.ctx.events is not None:
            self.ctx.events.subscribe(HEALTH_ALERTED, self._on_alerted_elsewhere)

    def on_unload(self) -> None:
        if self._errors is not None:
            logging.getLogger().removeHandler(self._errors)

    def scheduled_tasks(self) -> list[ScheduledTask]:
        n = self._interval_min
        cron = f"*/{n} * * * *" if n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [ScheduledTask(cron=cron, func=self.watch, name="watch")]

    # ─── gathering ───────────────────────────────────────────────

    def checks(self) -> list[HealthCheck]:
        """Every plugin's health, plus the things only the runtime can see."""
        out: list[HealthCheck] = []
        failing: set[str] = set()                # plugins whose own check is failing
        for p in getattr(self.ctx, "_all_plugins", []):
            if p is self:
                continue
            try:
                mine = list(p.health())
            except Exception:
                self.log.exception("health() of %s crashed", p.ctx.name)
                mine = [HealthCheck(f"{p.ctx.name} self-report", False,
                                    "its own check stopped on an error — details are "
                                    "in the log")]
            if any(not c.ok for c in mine):
                failing.add(p.ctx.name)
            out += mine
        out += self._job_checks(failing)
        out.append(self._disk_check())
        for extra in (self._router_check(), self._error_check(failing)):
            if extra is not None:
                out.append(extra)
        updates = self._updates_check()
        if updates is not None:
            out.append(updates)
        return out

    def _updates_check(self) -> HealthCheck | None:
        """Pending OS security updates (asked of apt at most every 6 hours)."""
        if not self._check_updates:
            return None
        checked, cached = self._updates_cache
        # apt only reads its local lists here, so it is cheap: while something
        # is waiting, look again every 30 min so "back to normal" follows an
        # upgrade soon instead of up to 6 h later.
        max_age = 30 * 60 if cached is not None and not cached.ok else 6 * 3600
        if time.time() - checked < max_age:
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
                bits.append(f"{ui.plural(len(security), 'security update')} waiting")
            if reboot:
                bits.append("a reboot is needed to finish an update")
            how = (" — /maintenance → Upgrade"
                   if ui.plugin_named(self.ctx, "maintenance") is not None
                   else " — on the Pi: sudo apt update && sudo apt upgrade")
            return HealthCheck(name, False, "; ".join(bits) + how)
        return HealthCheck(name, True, f"no security updates waiting ({len(pending)} other)")

    def _job_checks(self, failing_plugins: set[str] | None = None) -> list[HealthCheck]:
        """One check per failing scheduled job.

        A job whose plugin already reports the problem through its own check is
        still listed, but marked as told: the owner hears about it once, from
        the check that says it in plain words.
        """
        stats_fn = getattr(self.ctx.scheduler, "job_stats", None)
        if stats_fn is None:
            return []
        stats = stats_fn()
        broken = {name: st["last_error"] for name, st in stats.items()
                  if st.get("last_error")}
        if broken:
            failing_plugins = failing_plugins or set()
            return [HealthCheck(f"Scheduled job {name}", False,
                                f"its last run failed: {_one_line(err)}",
                                notified=name.split(".", 1)[0] in failing_plugins)
                    for name, err in sorted(broken.items())]
        return [HealthCheck("Scheduled jobs", True,
                            f"{ui.plural(len(stats), 'job')}, none failing")]

    def _router_check(self) -> HealthCheck | None:
        """Do our parsed lists agree with what the router counts itself?"""
        if not self._check_router:
            return None
        cached_at, cached = self._router_cache
        if time.time() - cached_at < _ROUTER_CHECK_EVERY_S:
            return cached
        check = self._compare_router_readings()
        self._router_cache = (time.time(), check)
        return check

    def _compare_router_readings(self) -> HealthCheck | None:
        name = "Reading the router"
        try:
            counts = self.router.table_counts()
            if counts is None:
                return HealthCheck(name, False, "the router did not answer")
            if not isinstance(counts, dict) or not counts:
                return None                      # this kind of router cannot say
            read = {
                "wifi": len(self.router.wifi_clients()),
                "dhcp": len(self.router.dhcp_leases()),
                "arp": sum(1 for a in self.router.arp_table() if getattr(a, "complete", True)),
            }
        except Exception:
            self.log.exception("could not compare the router readings")
            return HealthCheck(name, False, "could not compare — details are in the log")
        wrong, fine = [], []
        for key, label in _TABLES:
            listed = counts.get(key)
            if not isinstance(listed, int) or listed <= 0:
                continue
            got = read[key]
            if got == 0:
                wrong.append(f"the router lists {listed} {label}, NetSentry reads none")
            elif listed >= 6 and got * 2 < listed:
                wrong.append(f"the router lists {listed} {label}, NetSentry reads only {got}")
            else:
                fine.append(f"{label} {got}/{listed}")
        if wrong:
            return HealthCheck(name, False, "; ".join(wrong))
        return HealthCheck(name, True, " · ".join(fine) or "nothing connected")

    def _error_check(self, failing_plugins: set[str] | None = None) -> HealthCheck | None:
        if self._errors is None:
            return None
        minutes = self._error_window_s // 60
        since = time.time() - self._error_window_s
        recent = [e for e in list(self._errors.seen) if e[0] >= since]
        if not recent:
            return HealthCheck("Error log", True, f"no errors in the last {minutes} min")
        _, logger, message = recent[-1]
        source = _error_owner(logger, message) or logger.removeprefix("netsentry.")
        # Errors written by a plugin whose own check is failing are that same
        # problem again: shown here, but the owner is not alerted a second time.
        explained = bool(failing_plugins) and all(
            _error_owner(name, text) in failing_plugins for _, name, text in recent)
        return HealthCheck(
            "Error log", False,
            f"{ui.plural(len(recent), 'error')} in the last {minutes} min"
            f" — latest from {source.replace('_', ' ')}: {_one_line(message)}",
            notified=explained)

    def _disk_check(self) -> HealthCheck:
        try:
            usage = shutil.disk_usage(self.ctx.state_dir)
        except OSError:
            self.log.exception("cannot read disk usage")
            return HealthCheck("Disk space", False, "can't read how much space is left — "
                                                   "details are in the log")
        free_mb = usage.free // (1024 * 1024)
        used_pct = round(100 * (usage.total - usage.free) / usage.total) if usage.total else 0
        if free_mb < self._min_free_mb:
            return HealthCheck("Disk space", False, f"only {free_mb} MB free")
        if self._disk_max_used_pct and used_pct > self._disk_max_used_pct:
            return HealthCheck("Disk space", False,
                               f"{used_pct}% full ({free_mb // 1024} GB free) — the limit is "
                               f"{self._disk_max_used_pct}%")
        return HealthCheck("Disk space", True, f"{used_pct}% full · {free_mb // 1024} GB free")

    # ─── /health ─────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/health":
            self._send_report(chat_id)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # self_check:refresh (redraw this report) | self_check:full (from an
        # alert: a new message, so the alert itself stays readable)
        answer = getattr(self.notifier, "answer_callback", None)
        if answer:
            answer(callback_id, "Re-checked")
        full = data.partition(":")[2] == "full"
        self._send_report(chat_id, None if full else message_id)

    def report(self) -> str:
        checks = self.checks()
        bad = [c for c in checks if not c.ok]
        good = [c for c in checks if c.ok]
        head = (f"{ui.OK} everything is running" if not bad
                else f"{ui.ATTENTION} {ui.plural(len(bad), 'check')} need{'s' if len(bad) == 1 else ''} you")
        lines = [ui.header("🩺", "Health", head),
                 f"Checked at {time.strftime('%H:%M')} · {ui.plural(len(checks), 'check')}",
                 ui.RULE]
        for c in bad:
            lines.append(f"{ui.ATTENTION} {_shown(c.name)}\n   {c.detail}")
        if bad and good:
            lines.append("")
        for c in good:
            lines.append(f"{ui.OK} {_shown(c.name)}" + (f" — {c.detail}" if c.detail else ""))
        lines.append("\nRe-checked by itself every "
                     f"{self._interval_min} min; you are told when something stops.")
        return "\n".join(lines)

    def _send_report(self, chat_id: int, message_id: int | None = None) -> None:
        text = self.report()
        buttons = [[ui.refresh_button(f"{self.ctx.name}:refresh"), *ui.nav_row()]]
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
            return f"🩺 Health: all {len(checks)} checks OK"
        names = ui.first_few([_shown(c.name) for c in bad], 3)
        return f"🩺 Health: {ui.ATTENTION} {ui.plural(len(bad), 'problem')} — {names}"

    # ─── watchdog ────────────────────────────────────────────────

    def watch(self) -> None:
        """Alert on a check that has gone bad (and stayed bad); say when it's back.

        One problem → one alert → one recovery: a check the owning plugin has
        already alerted about (``notified``, or announced via
        :func:`notify.report_problem`) is tracked without a second alert, and
        still gets its recovery message.
        """
        checks = self.checks()
        now = time.time()
        with self._state_lock:
            seen = self._load()
            streaks: dict[str, int] = dict(seen.get("streaks", {}))
            alerted: set[str] = set(seen.get("alerted", []))
            since: dict[str, float] = dict(seen.get("since", {}))
            current = {c.name: c for c in checks}

            newly_bad: list[HealthCheck] = []
            for name, c in current.items():
                if c.ok:
                    streaks.pop(name, None)
                    continue
                streaks[name] = streaks.get(name, 0) + 1
                since.setdefault(name, now)
                if name in alerted:
                    continue
                if c.notified:
                    alerted.add(name)            # the owner already knows
                elif streaks[name] >= self._confirm:
                    alerted.add(name)
                    newly_bad.append(c)
            # Recovered = was alerted, and is now fine (or no longer reported at all).
            recovered = sorted(n for n in alerted if n not in current or current[n].ok)
            alerted -= set(recovered)
            lasted = {n: now - float(since[n]) for n in recovered if n in since}
            for name in list(streaks):
                if name not in current:
                    streaks.pop(name)
            for name in list(since):
                if name not in alerted and name not in streaks:
                    since.pop(name)

            self._save({"streaks": streaks, "alerted": sorted(alerted),
                        "since": since})

        if newly_bad:
            self._alert(newly_bad)
        if recovered:
            names = ", ".join(_shown(n) + (f" (down {ui.duration(lasted[n])})" if n in lasted else "")
                              for n in recovered)
            self._notify(notify.RECOVERY, f"{ui.OK} Back to normal: {names}")

    def _alert(self, bad: list[HealthCheck]) -> None:
        if len(bad) == 1:
            word = "needs attention" if bad[0].name in _NOT_BROKEN else "stopped working"
            text = f"{ui.header(ui.ATTENTION, _shown(bad[0].name), word)}\n{bad[0].detail}"
        else:
            body = "\n".join(f"{ui.ATTENTION} {_shown(c.name)}\n   {c.detail}" for c in bad)
            word = ("need attention" if all(c.name in _NOT_BROKEN for c in bad)
                    else "stopped working")
            text = f"{ui.ATTENTION} {ui.plural(len(bad), 'check')} {word}\n{body}"
        buttons = [[ui.button("🩺 Full check", f"{self.ctx.name}:full")]]
        self._notify(notify.ATTENTION, text, buttons)

    def _on_alerted_elsewhere(self, payload: dict) -> None:
        """A plugin told the owner about one of its checks itself: count the
        owner as told, and start the clock for the recovery message."""
        name = str((payload or {}).get("check") or "")
        if not name:
            return
        with self._state_lock:
            seen = self._load()
            alerted = set(seen.get("alerted", []))
            since = dict(seen.get("since", {}))
            alerted.add(name)
            since.setdefault(name, time.time())
            seen.update(alerted=sorted(alerted), since=since)
            self._save(seen)

    def _notify(self, kind: str, text: str, buttons: list | None = None) -> None:
        try:
            self.notifier.notify(kind, text, buttons=buttons)
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
