"""
maintenance — keep the Raspberry Pi up to date and tidy, one tap at a time.

`/maintenance` is a button screen:

  * 📋 Status — what is waiting (packages, a restart and why), free disk,
    what Docker could free, the bootloader, SD-card errors this boot, old
    kernels, the last action and whether one is running now. Read-only.
  * ⬆️ Upgrade — checks for updates and shows the exact list first, with what
    each kind of package means (Docker restarts the containers, Tailscale drops
    for a moment, a kernel needs a restart). A second tap upgrades *that list*:
    if it changed in the meantime nothing is upgraded and the new list is shown.
    Never removes packages.
  * 🔄 Restart Pi — the power plugin's restart; afterwards a health report
    (failed services, containers back?, DNS, tunnel, key services).
  * 🧹 Clean Docker — build cache and unused images. Never volumes or containers.
  * 🗑 Old kernels — the `autoremove --purge` list first, then the same check
    as the upgrade.
  * 🧬 Bootloader — stages a newer EEPROM; it applies on the next restart.

Once a week (Saturday 10:00, movable in /settings) it says when updates are
waiting — once per set of packages, with a button into the upgrade.

NetSentry itself runs unprivileged: it writes ONE word into the power plugin's
request file and the root helper (``deploy/netsentry-maintenance-helper.sh``,
started by ``netsentry-power.service``) does the work, answering in a folder
NetSentry can read but not write. Only one action runs at a time. The helper
is a separate service, so a NetSentry restart mid-upgrade does not stop it; the
action NetSentry is waiting for is kept on disk and its result still arrives.

Config keys:
    helper_dir      where the helper answers (default /var/lib/netsentry-maintenance)
    request_file    the request file (default the power plugin's power/request)
    notice_cron     when to look for waiting updates (default "0 10 * * sat";
                    "" turns the notice off)
    helper_wait_s   how long to wait for the helper to pick a request up (default 20)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from ..core import maint, notify, ui
from ..core.jsonstore import read_json, write_json
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

Ack = Callable[..., None]

_CHECK = "Maintenance helper"
_CHANGING = frozenset({"upgrade", "prune", "kernels", "eeprom", "reboot"})
# The file each read-only word answers in; the changing ones answer in result.json.
_OUTPUT = {"refresh": "plan-upgrade.json", "kernels-plan": "plan-kernels.json",
           "status": "status.json", "health": "health.json"}
_MAX_WAIT_S = {"upgrade": 75 * 60, "kernels": 35 * 60, "refresh": 20 * 60,
               "prune": 35 * 60, "health": 10 * 60}
_DEFAULT_MAX_WAIT_S = 10 * 60
_HISTORY_KEEP = 200
_SHOW_PACKAGES = 40
_HASH_CHARS = 12

_DOCKER = re.compile(r"^(docker-|docker\.io$|containerd)")
_KERNEL = re.compile(r"^(linux-image|linux-modules|raspberrypi-kernel)")
_KERNELISH = re.compile(r"^(linux-(image|headers|modules|kbuild|support|config)|"
                        r"raspberrypi-kernel|initramfs)")
_DONE = {"upgrade": "Upgrade", "prune": "Docker clean-up", "kernels": "Old kernels",
         "eeprom": "Bootloader", "reboot": "Restart"}


class MaintenancePlugin(Plugin):
    COMMANDS = [
        {"command": "maintenance", "description": "🧰 Update and tidy the Pi"},
    ]

    def on_load(self) -> None:
        state = Path(self.ctx.state_dir)
        self._out = Path(self.cfg.get("helper_dir") or maint.DEFAULT_OUT_DIR)
        self._request = Path(self.cfg.get("request_file")
                             or state.parent / "power" / "request")
        self._pending_file = state / "pending.json"
        self._history_file = state / "history.jsonl"
        self._notice_file = state / "notice.json"
        self._helper_wait_s = float(self.cfg.get("helper_wait_s", 20))
        self._poll_s = float(self.cfg.get("poll_s", 5))
        self._lock = threading.RLock()
        self._watching = False
        if self._pending():                 # a result we were waiting for before a restart
            self._start_watch()

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = str(self.cfg.get("notice_cron", "0 10 * * sat") or "").strip()
        if not cron or cron.lower() in ("off", "never", "false"):
            return []
        return [ScheduledTask(cron=cron, func=self.weekly_notice, name="weekly")]

    # ─── commands and buttons ────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/maintenance":
            self._show_home(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # maintenance:h | :st | :up[:go:<hash>] | :pr[:go] | :ko[:go:<hash>]
        # | :ee[:go] | :x
        parts = data.split(":")[1:] + ["", "", ""]
        verb, sub, arg = parts[0], parts[1], parts[2]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        go = sub == "go"
        if verb == "st":
            self._start("status", chat_id, message_id, ack, view="status")
        elif verb == "up" and go:
            self._confirm_plan("upgrade", arg, chat_id, message_id, ack)
        elif verb == "up":
            self._start("refresh", chat_id, message_id, ack)
        elif verb == "ko" and go:
            self._confirm_plan("kernels", arg, chat_id, message_id, ack)
        elif verb == "ko":
            self._start("kernels-plan", chat_id, message_id, ack)
        elif verb == "pr" and go:
            self._start("prune", chat_id, message_id, ack)
        elif verb == "pr":
            self._start("status", chat_id, message_id, ack, view="prune")
        elif verb == "ee" and go:
            self._start("eeprom", chat_id, message_id, ack)
        elif verb == "ee":
            self._start("status", chat_id, message_id, ack, view="eeprom")
        elif verb == "x":
            ack("Cancelled")
            self._show(chat_id, message_id, ui.NOTHING_CHANGED, [self._back_row()])
        else:
            ack()
            self._show_home(chat_id, message_id)

    # ─── handing a word to the helper ────────────────────────────

    def _start(self, action: str, chat_id: int, message_id: int | None,
               ack: Ack, *, view: str = "", note: str = "") -> bool:
        """Ask the helper for ``action``; the answer arrives through the watcher."""
        with self._lock:
            refusal = self._refusal()
            if refusal:
                ack("Busy")
                self._show(chat_id, message_id, refusal, [self._back_row()])
                return False
            if not self._out.is_dir():
                ack("Not installed")
                self._show(chat_id, message_id, self._not_installed_text(),
                           [self._back_row()])
                return False
            try:
                self._request.parent.mkdir(parents=True, exist_ok=True)
                self._request.write_text(f"{action}\n", encoding="utf-8")
            except OSError:
                self.log.exception("could not write the maintenance request")
                ack("Failed")
                self._show(chat_id, message_id,
                           f"{ui.FAILED} NetSentry couldn't hand the request over. "
                           "Nothing changed.", [self._back_row()])
                return False
            write_json(self._pending_file, {
                "action": action, "view": view or action, "chat_id": chat_id,
                "message_id": message_id, "requested": time.time()})
        if action in _CHANGING:
            self.log.warning("Maintenance %s requested from chat %s", action, chat_id)
        else:
            self.log.info("Maintenance %s requested from chat %s", action, chat_id)
        self._history(action, "requested")
        ack(_WAIT_TOAST.get(action, "Working…"))
        if message_id is not None or action != "health":
            self._show(chat_id, message_id, (f"{note}\n\n" if note else "")
                       + _WAIT_TEXT.get(action, f"{ui.WORKING} Working…"), [])
        self._start_watch()
        return True

    def _refusal(self) -> str:
        """Why nothing new may start now ('' when it may)."""
        self._check_pending()                       # an answer may be waiting already
        running = maint.busy(self._out)
        if running:
            return (f"{ui.WORKING} {maint.label(running['action'])} is running since "
                    f"{datetime.fromtimestamp(running['started']):%H:%M}. "
                    "Try again when it is done.")
        pending = self._pending()
        if pending:
            return (f"{ui.WORKING} {maint.label(pending.get('action', ''))} was asked for "
                    f"at {datetime.fromtimestamp(float(pending.get('requested', 0))):%H:%M} "
                    "and has not finished yet. Try again when it is done.")
        if self._request.exists():
            return (f"{ui.WORKING} Another request is being handed over right now. "
                    "Try again in a moment.")
        return ""

    def _not_installed_text(self) -> str:
        return (f"{ui.FAILED} The maintenance helper isn't installed, so nothing was done.\n"
                "NetSentry runs without root; apt, Docker clean-up and the restart "
                "need the small root helper from deploy/ (see INSTALL).")

    def is_busy(self) -> str:
        """A sentence when a maintenance action is running or about to ('' if not).
        The power plugin asks before it restarts the Pi."""
        running = maint.busy(self._out)
        if running:
            return (f"{maint.label(running['action'])} is running since "
                    f"{datetime.fromtimestamp(running['started']):%H:%M}")
        pending = self._pending()
        if pending and pending.get("action") != "health":
            return f"{maint.label(pending.get('action', ''))} has just been asked for"
        return ""

    def after_reboot(self, chat_id: int | str) -> None:
        """The power plugin: the Pi is back from a restart the owner asked for.
        Ask the helper for a health report; it arrives as its own message."""
        if not self._out.is_dir():
            return
        self._start("health", chat_id, None, lambda _text="": None)

    # ─── waiting for the answer ──────────────────────────────────

    def _start_watch(self) -> None:
        with self._lock:
            if self._watching:
                return
            self._watching = True
        thread = threading.Thread(target=self._watch, name="maintenance-watch", daemon=True)
        thread.start()

    def _watch(self) -> None:
        try:
            while True:
                try:
                    if self._check_pending():
                        return
                except Exception:
                    self.log.exception("maintenance: checking for the helper's answer failed")
                time.sleep(self._poll_s)
        finally:
            with self._lock:
                self._watching = False

    def _check_pending(self) -> bool:
        """Deliver the helper's answer if it is there; True when nothing is pending."""
        with self._lock:
            pending = self._pending()
            if not pending:
                return True
            action = str(pending.get("action") or "")
            requested = float(pending.get("requested") or 0)
            ignored = maint.read(self._out, "ignored.json")
            if ignored and ignored.get("action") == action \
                    and _num(ignored.get("started")) >= requested - 2:
                self._clear_pending()
                self._history(action, "not done: another action was running")
                self._reply(pending, f"{ui.CANCELLED} Not done: another maintenance action "
                                     "was running. Nothing changed.", [self._back_row()])
                return True
            answer = self._answer(action, requested)
            if answer is not None:
                self._clear_pending()
            else:
                waited = time.time() - requested
                if (self._request.exists() and waited > self._helper_wait_s
                        and not maint.busy(self._out)):
                    self._request.unlink(missing_ok=True)
                    self._clear_pending()
                    self._history(action, "failed: helper not installed")
                    self._reply(pending, self._not_installed_text(), [self._back_row()])
                    return True
                if waited > _MAX_WAIT_S.get(action, _DEFAULT_MAX_WAIT_S):
                    self._clear_pending()
                    self.log.error("maintenance: no answer from the helper for %s", action)
                    self._history(action, "failed: no answer")
                    self._reply(pending, f"{ui.FAILED} {maint.label(action)} gave no answer "
                                         f"within {ui.duration(waited)}. Its log is in "
                                         "/var/log/netsentry-maintenance.",
                                [self._back_row()])
                    return True
                return False
        try:
            self._deliver(pending, answer)
        except Exception:
            self.log.exception("maintenance: could not show the answer to %s", action)
        return True

    def _answer(self, action: str, requested: float) -> dict | None:
        name = _OUTPUT.get(action, "result.json")
        data = maint.read(self._out, name)
        if not data or not data.get("finished"):
            return None
        if name == "result.json" and data.get("action") != action:
            return None
        if _num(data.get("started")) < requested - 2:
            return None
        return data

    def _deliver(self, pending: dict, data: dict) -> None:
        action, view = pending.get("action"), pending.get("view")
        chat_id, message_id = pending.get("chat_id"), pending.get("message_id")
        if action == "health":
            self._deliver_health(chat_id, data)
        elif action == "status":
            self._history("status", "ok")
            if view == "prune":
                text, rows = self._prune_screen(data)
            elif view == "eeprom":
                text, rows = self._eeprom_screen(data)
            else:
                text, rows = self._status_screen(data)
            self._show(chat_id, message_id, text, rows)
        elif action in ("refresh", "kernels-plan"):
            self._history(action, "ok" if data.get("ok", True) else "failed")
            kind = "upgrade" if action == "refresh" else "kernels"
            self._show(chat_id, message_id, *self._plan_screen(kind, data))
        else:
            self._deliver_result(pending, data)

    def _deliver_result(self, pending: dict, data: dict) -> None:
        action = str(pending.get("action"))
        chat_id = pending.get("chat_id")
        if data.get("changed"):
            kind = "upgrade" if action == "upgrade" else "kernels"
            plan = maint.read(self._out, _plan_file(kind)) or {}
            self._history(action, "not done: the list changed")
            text, rows = self._plan_screen(kind, plan, note=(
                f"{ui.ATTENTION} The list changed since you looked, so nothing was done. "
                "Here is the new one."))
            self._show(chat_id, None, text, rows)
            return
        text, rows, outcome = self._result_text(action, data)
        self._history(action, outcome)
        if outcome.startswith("failed"):
            self.log.error("maintenance %s finished: %s", action, outcome)
        else:
            self.log.warning("maintenance %s finished: %s", action, outcome)
        self._show(chat_id, None, text, rows)

    # ─── screens ─────────────────────────────────────────────────

    def _show_home(self, chat_id: int, message_id: int | None) -> None:
        lines = [ui.title("🧰", "Maintenance", "Raspberry Pi")]
        running = maint.busy(self._out)
        if running:
            lines.append(f"{ui.WORKING} {maint.label(running['action'])} is running since "
                         f"{datetime.fromtimestamp(running['started']):%H:%M}.")
        if not self._out.is_dir():
            lines.append(f"{ui.ATTENTION} The root helper isn't installed yet (see INSTALL); "
                         "the buttons will say so.")
        status = maint.read(self._out, "status.json")
        if status and status.get("finished"):
            lines.append(f"Last look ({ui.when_text(status['finished'])}): "
                         + self._status_summary(status))
        recent = self._recent()
        lines.append("\nRecent:" if recent else "\nNothing done here yet.")
        lines += [f"• {line}" for line in recent]
        lines.append("\nPick one. Anything that changes the Pi asks first.")
        me = self.ctx.name
        rows = [[ui.button("📋 Status", f"{me}:st"), ui.button("⬆️ Upgrade", f"{me}:up")]]
        second = [ui.button("🧹 Clean Docker", f"{me}:pr")]
        if self._power() is not None:
            second.insert(0, ui.button("🔄 Restart Pi", "power:ask:pi"))
        rows.append(second)
        rows.append([ui.button("🗑 Old kernels", f"{me}:ko"),
                     ui.button("🧬 Bootloader", f"{me}:ee")])
        rows.append(ui.nav_row(home=self._menu_loaded()) or [])
        self._show(chat_id, message_id, "\n".join(lines), [r for r in rows if r])

    def _status_summary(self, status: dict) -> str:
        bits = [ui.plural(len(status.get("pending") or []), "update") + " waiting"]
        if _restart_reason(status.get("reboot") or {}):
            bits.append("restart needed")
        for disk in status.get("disks") or []:
            if disk.get("path") == "/":
                bits.append(f"{ui.size(_num(disk.get('free')))} free")
        return " · ".join(bits)

    def _status_screen(self, s: dict) -> tuple[str, list]:
        lines = [ui.title("📋", "Raspberry Pi", "status")]
        if s.get("ok") is False:
            lines.append(f"{ui.FAILED} The helper couldn't read the state: "
                         + "; ".join(map(str, s.get("error") or [])))
        pending = s.get("pending") or []
        if s.get("apt_ok") is False:
            lines.append(f"{ui.ATTENTION} apt couldn't list the updates.")
        elif pending:
            lines.append(f"⬆️ {ui.plural(len(pending), 'update')} waiting:")
            lines += _package_lines(pending, indent="   ")
        else:
            lines.append("⬆️ No updates waiting.")
        reason = _restart_reason(s.get("reboot") or {})
        lines.append(f"🔄 Restart needed: {reason}" if reason else "🔄 No restart needed.")
        disks = [f"{d.get('path')} {ui.size(_num(d.get('free')))} free of "
                 f"{ui.size(_num(d.get('total')))}" for d in s.get("disks") or []]
        if disks:
            lines.append("💾 Disk: " + " · ".join(disks))
        lines.append("🐳 " + _docker_line(s.get("docker")))
        lines.append("🧬 " + _eeprom_line(s.get("eeprom")))
        errors = s.get("disk_errors")
        if isinstance(errors, dict):
            count = int(_num(errors.get("count")))
            lines.append("🧪 SD / disk errors this boot: none" if not count else
                         f"🧪 SD / disk errors this boot: {count} — last: {errors.get('last', '')}")
        old = s.get("autoremove") or []
        lines.append(f"🗑 Old kernels / unused packages: {ui.first_few(old)}" if old
                     else "🗑 No old kernels or unused packages.")
        lines.append("🕘 Last action: " + self._last_action_text())
        running = maint.busy(self._out)
        lines.append(f"{ui.WORKING} Running now: {maint.label(running['action']).lower()}"
                     if running else "Nothing is running now.")
        lines.append(f"\nRead {ui.when_text(s.get('finished'), default='just now')}.")
        me = self.ctx.name
        return "\n".join(lines), [[ui.refresh_button(f"{me}:st")], self._back_row()]

    def _last_action_text(self) -> str:
        last = maint.read(self._out, "result.json")
        if not last or not last.get("action"):
            return "none yet"
        name = _DONE.get(str(last["action"]), str(last["action"]))
        when = ui.when_text(last.get("finished"), default="?")
        code = last.get("exit")
        if last.get("changed"):
            verdict = "not done (the list changed)"
        elif code in (0, None):
            verdict = f"{ui.OK} done"
        else:
            verdict = f"{ui.FAILED} failed (exit {code})"
        return f"{name} — {when} — {verdict}"

    def _plan_screen(self, kind: str, plan: dict, note: str = "") -> tuple[str, list]:
        """The exact list the second tap will act on."""
        me = self.ctx.name
        upgrade = kind == "upgrade"
        packages = plan.get("packages") or []
        head = ("⬆️", "Upgrade") if upgrade else ("🗑", "Old kernels")
        lines = [note] if note else []
        if plan.get("ok") is False:
            lines += [ui.title(head[0], head[1], "couldn't check"),
                      f"{ui.FAILED} apt answered with an error, so nothing can be done now:",
                      *[f"   {e}" for e in (plan.get("error") or [])[:4]]]
            return "\n".join(lines), [self._back_row()]
        if not packages:
            lines += [ui.title(head[0], head[1]),
                      f"{ui.OK} Nothing to upgrade — the Pi is up to date." if upgrade
                      else f"{ui.OK} Nothing to remove."]
            if upgrade and plan.get("kept_back"):
                lines.append("Held back by apt (not upgraded): "
                             + ui.first_few(plan["kept_back"], 6))
            return "\n".join(lines), [self._back_row()]
        n = len(packages)
        lines.append(ui.title(head[0], head[1], ui.plural(n, "package")))
        if upgrade and plan.get("update_ok") is False:
            lines.append(f"{ui.ATTENTION} apt-get update failed — this list may be old.")
        if upgrade:
            lines += _package_lines(packages)
            lines += _upgrade_warnings([str(p.get("name", "")) for p in packages])
            if plan.get("kept_back"):
                lines.append("Held back by apt (not upgraded): "
                             + ui.first_few(plan["kept_back"], 6))
            lines.append("\nOnly these are upgraded; nothing is removed.")
            verb, emoji = f"upgrade these {n}", "✅"
        else:
            kernels = [p for p in packages if _KERNELISH.match(str(p.get("name", "")))]
            others = [p for p in packages if p not in kernels]
            lines += [f"{p.get('name')} {p.get('version', '')}".strip()
                      for p in kernels[:_SHOW_PACKAGES]]
            if others:
                lines.append(f"\n{ui.ATTENTION} Also removes (not kernels): "
                             + ", ".join(str(p.get("name")) for p in others[:_SHOW_PACKAGES]))
            lines.append("\nThe running kernel is never in this list; apt keeps it.")
            verb, emoji = f"remove these {n}", "🗑"
        short = str(plan.get("hash", ""))[:_HASH_CHARS]
        verb_key = "up" if upgrade else "ko"
        return "\n".join(lines), ui.confirm_rows(emoji, verb, f"{me}:{verb_key}:go:{short}",
                                                 f"{me}:x")

    def _confirm_plan(self, kind: str, short: str, chat_id: int, message_id: int | None,
                      ack: Ack) -> None:
        """Second tap: only when the plan on disk is the one that was shown."""
        refusal = self._refusal()
        if refusal:
            ack("Busy")
            self._show(chat_id, message_id, refusal, [self._back_row()])
            return
        plan = maint.read(self._out, _plan_file(kind)) or {}
        if not short or not str(plan.get("hash", "")).startswith(short):
            ack("The list changed")
            self._show(chat_id, message_id, *self._plan_screen(kind, plan, note=(
                f"{ui.ATTENTION} The list changed since you looked, so nothing was done. "
                "Here is the new one.")))
            return
        if not plan.get("packages"):
            ack()
            self._show(chat_id, message_id, *self._plan_screen(kind, plan))
            return
        self._start(kind, chat_id, message_id, ack)

    def _prune_screen(self, status: dict) -> tuple[str, list]:
        lines = [ui.title("🧹", "Clean Docker")]
        docker = status.get("docker")
        if not isinstance(docker, dict):
            lines.append("Docker isn't installed on this machine. Nothing to clean.")
            return "\n".join(lines), [self._back_row()]
        lines += [_docker_line(docker),
                  "Removes the build cache and every image that no container uses. "
                  "Never volumes and never containers: your projects' data stays. "
                  "A removed image is downloaded again when it is next needed."]
        me = self.ctx.name
        return "\n".join(lines), ui.confirm_rows("🧹", "clean up", f"{me}:pr:go", f"{me}:x")

    def _eeprom_screen(self, status: dict) -> tuple[str, list]:
        lines = [ui.title("🧬", "Bootloader (EEPROM)")]
        info = status.get("eeprom")
        if not isinstance(info, dict):
            lines.append("rpi-eeprom-update isn't available on this machine.")
            return "\n".join(lines), [self._back_row()]
        lines += [f"Current: {info.get('current') or '?'}",
                  f"Latest: {info.get('latest') or '?'}"]
        if not info.get("update_available"):
            lines.append(f"{ui.OK} The bootloader is up to date.")
            return "\n".join(lines), [self._back_row()]
        lines.append(f"\n{ui.INFO} An update is available. It is staged now and applied on "
                     "the next restart. Restart it on its own, when you are home.")
        me = self.ctx.name
        return "\n".join(lines), ui.confirm_rows("🧬", "stage the update", f"{me}:ee:go",
                                                 f"{me}:x")

    def _result_text(self, action: str, r: dict) -> tuple[str, list, str]:
        """The one message after a changing action: (text, buttons, history outcome)."""
        code = r.get("exit")
        ok = code == 0
        name = _DONE.get(action, action)
        errors = [f"   {e}" for e in (r.get("error") or [])[:6]]
        rows: list = []
        if action == "upgrade" and r.get("nothing"):
            return (f"{ui.OK} Nothing to upgrade — the Pi is up to date.",
                    [self._back_row()], "ok: nothing to upgrade")
        lines = [ui.title(ui.OK if ok else ui.FAILED, name,
                          "done" if ok else f"failed (exit {code})")]
        if action == "upgrade":
            done = r.get("upgraded") or []
            lines.append(f"Upgraded {len(done)}:" if ok else f"Tried {len(done)}:")
            lines += _package_lines(done, indent="   ")
            reason = _restart_reason(r.get("reboot") or {})
            lines.append(f"🔄 Restart needed: {reason}" if reason else "🔄 No restart needed.")
            services = r.get("services")
            if services:
                lines.append("Services that should restart (needrestart): "
                             + ui.first_few(services, 8))
            elif services is not None:
                lines.append("No services need a restart.")
            if reason and self._power() is not None:
                rows.append([ui.button("🔄 Restart Pi", "power:ask:pi")])
            outcome = f"{len(done)} packages"
        elif action == "kernels":
            gone = r.get("removed") or []
            lines.append(("Removed: " if ok else "Tried to remove: ")
                         + ui.first_few([p.get("name") for p in gone], 8))
            outcome = f"{len(gone)} removed"
        elif action == "prune":
            lines.append(f"Freed: build cache {r.get('freed_build', '0B')} · "
                         f"unused images {r.get('freed_images', '0B')}")
            outcome = f"freed {r.get('freed_build', '0B')} + {r.get('freed_images', '0B')}"
        elif action == "eeprom":
            lines += [f"   {line}" for line in (r.get("output") or [])[-4:]]
            if ok:
                lines.append("It is applied on the next restart. Restart it on its own, "
                             "when you are home.")
            outcome = "staged"
        else:
            outcome = "done"
        if not ok:
            lines.append("What it said:")
            lines += errors
            if r.get("log"):
                lines.append(f"Log: {r['log']}")
        rows.append(self._back_row())
        return "\n".join(lines), rows, ("ok: " if ok else f"failed (exit {code}): ") + outcome

    # ─── after a restart ─────────────────────────────────────────

    def _deliver_health(self, chat_id: Any, h: dict) -> None:
        lines, problems = self._health_lines(h)
        verdict = "all good" if not problems else ui.plural(problems, "problem")
        icon = ui.OK if not problems else ui.ATTENTION
        text = ui.title(icon, "Pi after the restart", verdict) + "\n" + "\n".join(lines)
        self._history("reboot", "ok: health all good" if not problems
                      else f"health: {ui.plural(problems, 'problem')}")
        kind = notify.RECOVERY if not problems else notify.ATTENTION
        try:
            self.notifier.notify(kind, text, buttons=ui.rows(self._back_row()),
                                 chat_id=chat_id)
        except Exception:
            self.log.exception("could not send the health report")

    def _health_lines(self, h: dict) -> tuple[list[str], int]:
        if h.get("ok") is False:
            return [f"{ui.FAILED} The health check failed: "
                    + "; ".join(map(str, h.get("error") or []))], 1
        lines: list[str] = []
        problems = 0
        failed = h.get("failed_units") or []
        if failed:
            problems += 1
            lines.append(f"{ui.FAILED} Failed services: {ui.first_few(failed, 8)}")
        else:
            lines.append(f"{ui.OK} No failed services")
        c = h.get("containers") or {}
        if c.get("docker") or c.get("before"):
            before, running = c.get("before") or [], c.get("running") or []
            missing, starting = c.get("missing") or [], c.get("starting") or []
            unhealthy = c.get("unhealthy") or []
            if missing:
                problems += 1
                lines.append(f"{ui.FAILED} Containers not running: {ui.first_few(missing, 8)}")
            else:
                shown = f"{len(before)} of {len(before)}" if before else str(len(running))
                lines.append(f"{ui.OK} Containers: {shown} running")
            if unhealthy:
                problems += 1
                lines.append(f"{ui.FAILED} Unhealthy: {ui.first_few(unhealthy, 8)}")
            if starting:
                lines.append(f"{ui.WORKING} Still starting after "
                             f"{ui.duration(_num(h.get('waited_s')))}: {ui.first_few(starting, 8)}")
        dns = h.get("dns") or {}
        if dns.get("ok"):
            lines.append(f"{ui.OK} DNS answers")
        else:
            problems += 1
            lines.append(f"{ui.FAILED} DNS: {dns.get('detail') or 'no answer'}")
        before_units = set(h.get("units_before") or [])
        for unit, state in sorted((h.get("units") or {}).items()):
            short = unit.removesuffix(".service")
            extra = ""
            if unit == "cloudflared.service" and isinstance(h.get("tunnel"), dict):
                tunnel = h["tunnel"]
                extra = f", {tunnel.get('detail', '')}"
                if state == "active" and tunnel.get("ok") is False:
                    problems += 1
                    lines.append(f"{ui.FAILED} {short} — active{extra}")
                    continue
            if state == "active":
                lines.append(f"{ui.OK} {short} — active{extra}")
            elif unit in before_units or not before_units:
                problems += 1
                lines.append(f"{ui.FAILED} {short} — {state}")
            else:
                lines.append(f"{ui.INFO} {short} — {state} (was not running before either)")
        return lines, problems

    # ─── the weekly notice ───────────────────────────────────────

    def weekly_notice(self) -> None:
        """Once per set of packages: "N updates are waiting", with a button."""
        pending = _upgradable()
        if pending is None:
            return                                   # not a Debian-family host
        key = hashlib.sha256("\n".join(sorted(pending)).encode("utf-8")).hexdigest()
        seen = read_json(self._notice_file, {})
        if not pending:
            if seen.get("hash"):
                write_json(self._notice_file, {})
            return
        if seen.get("hash") == key:
            return
        n = len(pending)
        names = [line.split("/", 1)[0] for line in sorted(pending)]
        text = (f"{ui.INFO} {ui.plural(n, 'update')} {'is' if n == 1 else 'are'} waiting\n"
                f"{ui.first_few(names, 5)}\n"
                "Tap to see the full list; nothing is installed until you confirm.")
        sent = self.notifier.notify(notify.INFO, text, buttons=[[
            ui.button("⬆️ Upgrade", f"{self.ctx.name}:up")]])
        if sent is not False:
            write_json(self._notice_file, {"hash": key, "count": n, "ts": time.time()})

    # ─── health ──────────────────────────────────────────────────

    def health(self) -> list[HealthCheck]:
        if not self._out.is_dir():
            return [HealthCheck(_CHECK, False, "the root helper isn't installed (see INSTALL)")]
        last = maint.read(self._out, "result.json")
        if last and last.get("exit") not in (0, None) and not last.get("changed"):
            name = _DONE.get(str(last.get("action")), str(last.get("action")))
            # The owner got the result message when it failed.
            return [HealthCheck(_CHECK, False,
                                f"the last {name.lower()} failed (exit {last.get('exit')}) — "
                                f"{ui.when_text(last.get('finished'), default='?')}",
                                notified=True)]
        if last and last.get("action"):
            return [HealthCheck(_CHECK, True, "last action: " + self._last_action_text())]
        return [HealthCheck(_CHECK, True, "installed")]

    # ─── small helpers ───────────────────────────────────────────

    def _pending(self) -> dict:
        data = read_json(self._pending_file, {})
        return data if isinstance(data, dict) else {}

    def _clear_pending(self) -> None:
        self._pending_file.unlink(missing_ok=True)

    def _history(self, action: str, outcome: str) -> None:
        """Append one line to history.jsonl (the newest 200 are kept)."""
        entry = json.dumps({"ts": time.time(), "action": action, "result": outcome})
        with self._lock:
            try:
                lines = self._history_file.read_bytes().decode("utf-8").splitlines() \
                    if self._history_file.exists() else []
                lines = [ln for ln in lines if ln.strip()][-(_HISTORY_KEEP - 1):] + [entry]
                self._history_file.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._history_file.with_suffix(".tmp")
                tmp.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
                os.replace(tmp, self._history_file)
            except OSError:
                self.log.exception("could not write the maintenance history")

    def _recent(self, n: int = 5) -> list[str]:
        """The newest ``n`` changing actions that finished, newest first."""
        try:
            raw = self._history_file.read_bytes().decode("utf-8").splitlines()
        except OSError:
            return []
        out = []
        for line in reversed(raw):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict) or e.get("action") not in _CHANGING \
                    or e.get("result") == "requested":
                continue
            out.append(f"{_DONE.get(e['action'], e['action'])} — "
                       f"{ui.when_text(e.get('ts'), default='?')} — {e.get('result', '')}")
            if len(out) >= n:
                break
        return out

    def _reply(self, pending: dict, text: str, rows: list) -> None:
        chat_id, message_id = pending.get("chat_id"), pending.get("message_id")
        if chat_id is None:
            return
        if pending.get("action") == "health":
            self.log.warning("maintenance health check: %s", ui.strip_html(text)[:200])
            return
        self._show(chat_id, message_id, text, rows)

    def _show(self, chat_id: Any, message_id: int | None, text: str, buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        buttons = [row for row in (buttons or []) if row]
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons or None)

    def _back_row(self) -> list[dict[str, str]]:
        return ui.nav_row(f"{self.ctx.name}:h", home=self._menu_loaded())

    def _menu_loaded(self) -> bool:
        return ui.plugin_named(self.ctx, "menu") is not None

    def _power(self) -> Any:
        return ui.plugin_named(self.ctx, "power")


_WAIT_TOAST = {"status": "Reading the Pi…", "refresh": "Checking for updates…",
               "kernels-plan": "Looking for old kernels…", "upgrade": "Upgrading…",
               "kernels": "Removing…", "prune": "Cleaning…", "eeprom": "Staging…"}
_WAIT_TEXT = {
    "status": f"{ui.WORKING} Reading the Pi's state…",
    "refresh": f"{ui.WORKING} Checking for updates (apt-get update)… about a minute.",
    "kernels-plan": f"{ui.WORKING} Looking for old kernels and unused packages…",
    "upgrade": (f"{ui.WORKING} Upgrading. This can take a while on an SD card; "
                "you get one message when it is done."),
    "kernels": f"{ui.WORKING} Removing them. You get one message when it is done.",
    "prune": f"{ui.WORKING} Cleaning Docker. You get one message when it is done.",
    "eeprom": f"{ui.WORKING} Staging the bootloader update…",
}


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _plan_file(kind: str) -> str:
    return "plan-upgrade.json" if kind == "upgrade" else "plan-kernels.json"


def _package_lines(packages: list, indent: str = "") -> list[str]:
    out = []
    for p in packages[:_SHOW_PACKAGES]:
        name, old, new = p.get("name", "?"), p.get("from", ""), p.get("to", "")
        out.append(f"{indent}{name} {old} → {new}" if old else f"{indent}{name} {new} (new)")
    rest = ui.more(min(_SHOW_PACKAGES, len(packages)), len(packages))
    if rest:
        out.append(f"{indent}{rest}")
    return out


def _upgrade_warnings(names: list[str]) -> list[str]:
    out = []
    if any(_DOCKER.match(n) for n in names):
        out.append(f"{ui.ATTENTION} Docker is upgraded: your projects' containers will restart.")
    if "tailscale" in names:
        out.append(f"{ui.ATTENTION} Tailscale drops for a moment.")
    if any(_KERNEL.match(n) for n in names):
        out.append(f"{ui.ATTENTION} A new kernel: the Pi needs a restart afterwards.")
    return out


def _restart_reason(reboot: dict) -> str:
    """Why the Pi needs a restart ('' when it doesn't)."""
    bits = []
    if reboot.get("required"):
        pkgs = reboot.get("packages") or []
        bits.append("asked for by " + ui.first_few(pkgs, 4) if pkgs else "an update asks for it")
    if reboot.get("newest_kernel"):
        bits.append(f"running kernel {reboot.get('running_kernel')}, "
                    f"newest installed {reboot.get('newest_kernel')}")
    return "yes — " + "; ".join(bits) if bits else ""


def _docker_line(docker: Any) -> str:
    if not isinstance(docker, dict):
        return "Docker: not installed"
    return (f"Docker can free: build cache {docker.get('build_cache') or '0B'} · "
            f"unused images {docker.get('images') or '0B'}")


def _eeprom_line(info: Any) -> str:
    if not isinstance(info, dict):
        return "Bootloader: not available here"
    if info.get("update_available"):
        return f"Bootloader: update available (latest {info.get('latest') or '?'})"
    return "Bootloader: up to date"


def _upgradable() -> list[str] | None:
    """``name/suite version arch [upgradable from: old]`` lines from apt's local
    lists (no root, no network); None when apt is not there."""
    apt = shutil.which("apt")
    if apt is None:
        return None
    try:
        r = subprocess.run(  # nosec B603 - fixed argv, no shell
            [apt, "list", "--upgradable"], capture_output=True, text=True,
            timeout=60, env={**os.environ, "LC_ALL": "C"}, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return [line.strip() for line in r.stdout.splitlines() if "/" in line and "[" in line]
