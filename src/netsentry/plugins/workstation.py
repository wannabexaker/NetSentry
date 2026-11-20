"""
workstation — watch and manage a PC (typically a gaming / AI PC) from Telegram.

`/pc` opens one screen, edited in place: is the PC on, how hot and busy its GPU
is, memory and disk, who is logged in, whether a game runs, which model is
loaded, and one line per AI service (LM Studio, Hermes, OpenClaw… — whatever
the PC reports). Buttons wake it, start and stop services, free graphics
memory, and put it to sleep, shut it down or restart it (those three take two
taps; shut down and restart can be cancelled during their 15 s).

How the PC is reached (see docs/WORKSTATION.md and tools/pc-agent/):

  * ssh with a key that the PC pins to ONE script, which accepts a fixed list
    of actions and nothing else. This plugin keeps the same list
    (``core/pc_agent.py``) and never builds a command from text.
  * Wake-on-LAN magic packet to ``wake_to`` (``core/wol.py``) — a relay such as
    the router, when the PC is on another subnet.
  * Optionally one SSH port forward to LM Studio's API on the PC, kept alive
    on demand (``core/tunnel.py``), so ``ai: provider: openai`` works whenever
    the PC is on, with no manual step.

"Off or asleep" is a normal state of a PC: it is shown, never alerted, and
health stays OK. Only a PC that answers but refuses (key removed, script
changed, unreadable answer) is a fault.

A scheduled check (every ``poll_minutes``) tells you, through the normal
notification kinds, when the PC came on without NetSentry waking it (info),
when the GPU stays too hot (attention, then recovery), when disk C runs low
(attention), and — if ``idle_hours`` is set — when it has been on with nothing
to do (info, with a Sleep button; it is never put to sleep automatically).

Config keys (the plugin does nothing until host, user and ssh_key are set):
    name               what to call it (default "Gaming PC")
    host, user, port   ssh target (port default 22)
    ssh_key            private key on this host (restricted on the PC)
    mac, wake_to       Wake-on-LAN: the PC's MAC and where to send the packet
                       (host[:port], port default 9; a relay or a broadcast)
    services           service ids NetSentry may start/stop
                       (default lmstudio, hermes, openclaw)
    wake_and_start     service ids that get a one-tap "wake the PC and start
                       it" button, also while the PC is off
    links              {service id: URL} — a button to open it once it runs
    remote_keyboard_url  when set, "⌨️ Open remote keyboard" appears where a
                       login is needed; without it, the button opens the
                       dashboard's Remote page when the remote_keyboard plugin
                       is configured (docs/WORKSTATION.md)
    gpu_temp_alert_c   default 85
    disk_free_alert_gb default 20
    poll_minutes       default 5 (0 = no scheduled check)
    idle_hours         default 0 = off
    wake_wait_minutes  how long a wake waits for an answer (default 4)
    ai_tunnel_port     local port for the LM Studio tunnel (0 = no tunnel)
    ai_remote_port     the port LM Studio listens on, on the PC (default 1234)
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from ..core import notify, ui, wol
from ..core.jsonstore import read_json, write_json
from ..core.pc_agent import (
    DEFAULT_SERVICES,
    FAULT,
    OFF,
    OK,
    AgentConfigError,
    AgentReply,
    PcAgent,
    PcStatus,
)
from ..core.plugin import HealthCheck, Plugin, ScheduledTask
from ..core.tunnel import TunnelKeeper

ICON = "🖥"
_API_CACHE_S = 60.0          # the dashboard re-reads at most this often
_WAKE_POLL_S = 10.0
_SLEEP_CHECKS = (20.0, 20.0, 20.0)     # look whether a "sleep" really happened
_IDLE_GPU_PCT = 5
_WOKEN_GRACE_S = 1800.0      # "came on" is not news for this long after our own wake

# Display names for the usual services, used only until the PC has said its own.
_KNOWN_NAMES = {"lmstudio": "LM Studio", "hermes": "Hermes", "openclaw": "OpenClaw"}

_POWER = {
    "sleep": ("😴", "sleep", "Put {pc} to sleep?",
              "Everything on it pauses; agents stop answering until it wakes."),
    "shutdown": ("⏻", "shut down", "Shut down {pc}?",
                 "It switches off in 15 s and unsaved work on it is lost. You can "
                 "still cancel during those 15 s."),
    "restart": ("🔁", "restart", "Restart {pc}?",
                "It restarts in 15 s and unsaved work is lost. Agents that need a "
                "logged-in user stay off until someone logs in."),
}


def _url_ok(url: Any) -> bool:
    text = str(url or "").strip()
    return text.startswith(("https://", "http://", "tg://")) and " " not in text


class WorkstationPlugin(Plugin):
    COMMANDS = [
        {"command": "pc", "description": "🎮 Gaming PC, AI agents and power"},
    ]

    # ─── set-up ──────────────────────────────────────────────────

    def on_load(self) -> None:
        cfg = self.cfg
        self._label = str(cfg.get("name") or "Gaming PC").strip()[:30] or "Gaming PC"
        self._setup_error = ""
        self._agent: PcAgent | None = None
        if cfg.get("host") or cfg.get("user") or cfg.get("ssh_key"):
            try:
                self._agent = PcAgent(
                    cfg.get("host", ""), cfg.get("user", ""), cfg.get("ssh_key", ""),
                    port=int(cfg.get("port", 22)),
                    services=cfg.get("services") or DEFAULT_SERVICES,
                    connect_timeout=int(cfg.get("connect_timeout_s", 8)))
            except (AgentConfigError, ValueError, TypeError) as e:
                self._setup_error = str(e)
                self.log.error("workstation: config not usable: %s", e)
        allowed = set(self._agent.services) if self._agent else set()
        self._mac, self._wake_to = self._wake_config()
        self._wake_and_start = [str(s) for s in (cfg.get("wake_and_start") or [])
                                if str(s) in allowed]
        self._links = {str(k): str(v).strip() for k, v in (cfg.get("links") or {}).items()
                       if str(k) in allowed and _url_ok(v)}
        keyboard = cfg.get("remote_keyboard_url") or ""
        self._keyboard_url = str(keyboard).strip() if _url_ok(keyboard) else ""
        self._temp_alert = int(cfg.get("gpu_temp_alert_c", 85))
        self._disk_alert = int(cfg.get("disk_free_alert_gb", 20))
        self._poll_minutes = max(0, int(cfg.get("poll_minutes", 5)))
        self._idle_hours = max(0.0, float(cfg.get("idle_hours", 0)))
        self._wake_wait_s = max(30.0, float(cfg.get("wake_wait_minutes", 4)) * 60)

        self._state_file = Path(self.ctx.state_dir) / "watch.json"
        self._state_lock = threading.Lock()
        self._lock = threading.Lock()
        self._last: tuple[float, AgentReply, PcStatus | None] | None = None
        self._names: dict[str, str] = {}
        self._refreshing = False
        self._busy = False
        # Injectable for tests: no real waiting, no real threads.
        self._sleep = time.sleep
        self._clock = time.monotonic
        self._now = time.time
        self._send_wake = wol.send_magic_packet
        self._tunnel: TunnelKeeper | None = None
        self._setup_tunnel()

    def on_unload(self) -> None:
        if self._tunnel is not None:
            self._tunnel.stop()

    def _keyboard_link(self) -> str:
        """Where "⌨️ Open remote keyboard" goes: ``remote_keyboard_url`` when set,
        else the dashboard's Remote page when the remote_keyboard plugin is
        configured and the dashboard has a phone-reachable address; "" = no
        button. Only a URL travels through Telegram, never a keystroke."""
        if self._keyboard_url:
            return self._keyboard_url
        remote = ui.plugin_named(self.ctx, "remote_keyboard")
        if remote is None or not getattr(remote, "configured", False):
            return ""
        dash = ui.plugin_named(self.ctx, "lan_dashboard")
        link = dash.deep_link("/remote") if dash is not None else ""
        return link if _url_ok(link) else ""

    def _wake_config(self) -> tuple[str, str]:
        mac, target = str(self.cfg.get("mac") or ""), str(self.cfg.get("wake_to") or "")
        if not mac and not target:
            return "", ""
        try:
            wol.parse_mac(mac)
            wol.parse_target(target)
        except wol.WakeError as e:
            self.log.error("workstation: Wake-on-LAN is off, %s", e)
            return "", ""
        return mac, target

    def _setup_tunnel(self) -> None:
        port = int(self.cfg.get("ai_tunnel_port") or 0)
        if not port or self._agent is None:
            return
        attach = getattr(self.ai, "attach_tunnel", None)
        if attach is None:
            self.log.warning("workstation: ai_tunnel_port is set but the AI provider is "
                             "not an OpenAI-compatible one; no tunnel")
            return
        host, ai_port = self.ai.endpoint()
        if host not in ("127.0.0.1", "localhost") or ai_port != port:
            self.log.warning("workstation: ai base_url is %s:%s, not 127.0.0.1:%d; "
                             "the tunnel would lead nowhere — not attached", host, ai_port, port)
            return
        try:
            self._tunnel = TunnelKeeper(
                host=self._agent.host, user=self._agent.user, ssh_key=self._agent.key,
                port=self._agent.port, local_port=port,
                remote_port=int(self.cfg.get("ai_remote_port", 1234)))
        except ValueError as e:
            self.log.error("workstation: no AI tunnel, %s", e)
            return
        attach(self._tunnel.ensure)
        self.log.info("AI reaches the PC through a tunnel on 127.0.0.1:%d", port)

    def scheduled_tasks(self) -> list[ScheduledTask]:
        if self._agent is None or not self._poll_minutes:
            return []
        n = self._poll_minutes
        cron = f"*/{n} * * * *" if n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [ScheduledTask(cron=cron, func=self.watch, name="watch")]

    # ─── reading the PC ──────────────────────────────────────────

    def _fetch(self) -> tuple[AgentReply, PcStatus | None]:
        assert self._agent is not None
        reply, status = self._agent.status()
        if status is not None:
            self._names.update({s.id: s.name for s in status.services})
        self._last = (self._now(), reply, status)
        return reply, status

    def _cached(self, max_age: float = _API_CACHE_S) -> tuple[AgentReply, PcStatus | None]:
        last = self._last
        if last is not None and self._now() - last[0] < max_age:
            return last[1], last[2]
        return self._fetch()

    def _name(self, service_id: str) -> str:
        return self._names.get(service_id) or _KNOWN_NAMES.get(service_id) \
            or service_id.capitalize()

    # ─── Telegram ────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/pc":
            return
        if self._agent is None:
            self._show(chat_id, None, *self._not_set_up())
            return
        self._show(chat_id, None, *self._screen(*self._fetch()))

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # workstation:<verb>[:<arg>] — v | new | wake | go:<id> | start:<id> |
        # stop:<id> | vram | ask:<power> | do:<power> | abort | no
        _, verb, arg = (data.split(":", 2) + ["", ""])[:3]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if self._agent is None:
            ack("Not set up")
            self._show(chat_id, message_id, *self._not_set_up())
            return
        if verb in ("wake", "go"):
            self._begin_wake(chat_id, message_id, arg if verb == "go" else None, ack)
        elif verb in ("start", "stop"):
            if arg not in self._agent.services:
                ack("Not available")
                return
            ack("Starting…" if verb == "start" else "Stopping…")
            self._service_action(verb, arg, chat_id, message_id)
        elif verb == "vram":
            ack("Freeing…")
            self._free_vram(chat_id, message_id)
        elif verb == "ask" and arg in _POWER:
            ack()
            self._ask_power(arg, chat_id, message_id)
        elif verb == "do" and arg in _POWER:
            ack("Sending…")
            self._do_power(arg, chat_id, message_id)
        elif verb == "abort":
            ack("Cancelling…")
            self._abort(chat_id, message_id)
        elif verb == "no":
            ack("Cancelled")
            self._show(chat_id, message_id, *self._screen(*self._cached(),
                                                          note=ui.NOTHING_CHANGED))
        elif verb == "new":
            ack()
            self._show(chat_id, None, *self._screen(*self._fetch()))
        else:                                   # "v" (refresh) and anything old
            ack()
            self._show(chat_id, message_id, *self._screen(*self._fetch()))

    def _show(self, chat_id: int, message_id: int | None, text: str,
              rows: list | None) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=rows or [])
        else:
            self.notifier.send_to(chat_id, text, buttons=rows or None)

    # ─── the screen ──────────────────────────────────────────────

    def _not_set_up(self) -> tuple[str, list]:
        why = (f"The config is not usable ({self._setup_error})." if self._setup_error
               else "Add host, user and ssh_key to the workstation plugin's config.")
        return (ui.title(ICON, self._label, "not set up") + f"\n{why}\n"
                "How to set it up is in docs/WORKSTATION.md.", [ui.nav_row()])

    def _screen(self, reply: AgentReply, status: PcStatus | None,
                note: str = "") -> tuple[str, list]:
        name = self.ctx.name
        top = f"{note}\n\n" if note else ""
        if reply.outcome == OK and status is not None:
            text, rows = self._on_screen(status)
            return top + text, rows
        if reply.outcome == OFF:
            lines = [ui.title(ICON, self._label, "😴 off or asleep"),
                     "It does not answer: switched off, asleep or off the network. "
                     "That's normal for a PC."]
            rows: list = []
            if self._mac:
                rows.append([ui.button("⚡ Wake", f"{name}:wake")])
                rows += [[ui.button(f"🤖 Start {self._name(s)}", f"{name}:go:{s}")]
                         for s in self._wake_and_start]
            else:
                lines.append("Wake-on-LAN is not set up, so it can only be switched on "
                             "by hand.")
            rows.append([ui.refresh_button(f"{name}:v")])
            rows.append(ui.nav_row())
            return top + "\n".join(lines), rows
        return top + "\n".join([
            ui.title(ICON, self._label, f"{ui.ATTENTION} not answering as expected"),
            f"Something is wrong with the connection: {reply.detail or 'unknown'}.",
            "Nothing was changed. Details are in the log; the set-up is in "
            "docs/WORKSTATION.md."]), [[ui.refresh_button(f"{name}:v")], ui.nav_row()]

    def _on_screen(self, st: PcStatus) -> tuple[str, list]:
        name = self.ctx.name
        lines = [ui.title(ICON, self._label, f"{ui.OK} on")]
        lines += self._reading_lines(st)
        if st.error:
            lines.append(f"{ui.INFO} The PC could not read its AI launcher, so services "
                         "are unknown.")
        if st.services:
            lines.append("")
            for s in st.services:
                state = "running" if s.running else "stopped"
                ram = ui.size(s.ram_mb * 1024 * 1024) + " RAM" if s.ram_mb else ""
                lines.append(ui.item(f"{'🟢' if s.running else '⚪'} {s.name}", state,
                                     s.model or "", ram if s.running else ""))
        rows: list = []
        controls = [ui.button(f"{'⏹ Stop' if s.running else '▶ Start'} {s.name}"[:28],
                              f"{name}:{'stop' if s.running else 'start'}:{s.id}")
                    for s in st.services if self._agent and s.id in self._agent.services]
        rows += [controls[i:i + 2] for i in range(0, len(controls), 2)]
        rows.append(ui.url_row(*[(f"💬 Open {s.name}"[:28], self._links.get(s.id, ""))
                                 for s in st.services if s.running]))
        if not st.logged_on:
            rows.append(ui.url_row(("⌨️ Open remote keyboard", self._keyboard_link())))
        rows.append([ui.button("🧹 Free VRAM", f"{name}:vram"),
                     ui.button("😴 Sleep", f"{name}:ask:sleep")])
        rows.append([ui.button("⏻ Shut down", f"{name}:ask:shutdown"),
                     ui.button("🔁 Restart", f"{name}:ask:restart")])
        rows.append([ui.refresh_button(f"{name}:v")])
        rows.append(ui.nav_row())
        return "\n".join(lines), ui.rows(*rows) or []

    @staticmethod
    def _reading_lines(st: PcStatus) -> list[str]:
        out = []
        g = st.gpu
        if g is not None:
            vram = (f"VRAM {_gb(g.vram_used_mb)} / {_gb(g.vram_total_mb)}"
                    if g.vram_used_mb is not None and g.vram_total_mb else "")
            out.append(ui.item("🎮 GPU",
                               f"{g.temp_c} °C" if g.temp_c is not None else "",
                               f"{g.load_pct}% load" if g.load_pct is not None else "",
                               vram, f"{g.power_w} W" if g.power_w is not None else ""))
        if st.ram_used_mb is not None and st.ram_total_mb:
            out.append(ui.item("🧠 RAM", f"{_gb(st.ram_used_mb)} / {_gb(st.ram_total_mb)}"))
        if st.disk_free_gb is not None:
            total = f" of {st.disk_total_gb} GB" if st.disk_total_gb else ""
            out.append(ui.item("💽 Disk C", f"{st.disk_free_gb} GB free{total}"))
        if st.uptime_s is not None:
            out.append(ui.item("⏱ Up for", ui.duration(st.uptime_s)))
        out.append("👤 Someone is logged in" if st.logged_on else "👤 Nobody is logged in")
        if st.game_running is not None:
            out.append("🕹 A game is running" if st.game_running else "🕹 No game running")
        out.append(ui.item("🤖 Model loaded", ", ".join(st.models)) if st.models
                   else "🤖 No model loaded")
        return out

    # ─── start / stop / free VRAM ────────────────────────────────

    def _service_action(self, verb: str, service_id: str, chat_id: int,
                        message_id: int) -> None:
        assert self._agent is not None
        label = self._name(service_id)
        self._show(chat_id, message_id,
                   f"{ui.WORKING} {'Starting' if verb == 'start' else 'Stopping'} "
                   f"{label} on {self._label}…", [])
        reply = self._agent.start(service_id) if verb == "start" \
            else self._agent.stop(service_id)
        note = self._start_note(service_id, reply) if verb == "start" \
            else self._stop_note(service_id, reply)
        self._show(chat_id, message_id, *self._screen(*self._fetch(), note=note))

    def _start_note(self, service_id: str, reply: AgentReply) -> str:
        label = self._name(service_id)
        if reply.outcome == OFF:
            return f"{ui.FAILED} {label} was NOT started — {self._label} stopped answering."
        if reply.outcome == FAULT:
            return f"{ui.FAILED} {label} was NOT started — {reply.detail}."
        if reply.data.get("running") is True:
            return f"{ui.OK} {label} is running."
        reason = str(reply.data.get("reason") or "")
        if "logged in" in reason:
            return (f"{ui.ATTENTION} {label} was NOT started — nobody is logged in on the "
                    "PC. Log in on the PC, then tap Start again.")
        if "not available" in reason:
            return (f"{ui.FAILED} {label} was NOT started — the PC can't start services "
                    "(its AI launcher is not installed).")
        return (f"{ui.FAILED} {label} was NOT started — the PC tried, but it is not "
                "running. The PC's agent log has the details.")

    def _stop_note(self, service_id: str, reply: AgentReply) -> str:
        label = self._name(service_id)
        if reply.outcome == OFF:
            return f"{ui.FAILED} {label} was NOT stopped — {self._label} stopped answering."
        if reply.outcome == FAULT:
            return f"{ui.FAILED} {label} was NOT stopped — {reply.detail}."
        if "not available" in str(reply.data.get("reason") or ""):
            return (f"{ui.FAILED} {label} was NOT stopped — the PC can't stop services "
                    "(its AI launcher is not installed).")
        if reply.data.get("running") is False:
            return f"⏹ Stopped {label}."
        return f"{ui.FAILED} {label} is still running — it did not stop."

    def _free_vram(self, chat_id: int, message_id: int) -> None:
        assert self._agent is not None
        self._show(chat_id, message_id, f"{ui.WORKING} Freeing graphics memory on "
                                        f"{self._label}…", [])
        reply = self._agent.run("free-vram")
        if reply.ok and reply.data.get("ok") is not True:
            note = (f"{ui.FAILED} Nothing was freed — the PC can't do that (its AI launcher "
                    "is not installed).")
        elif reply.ok:
            gpu = reply.data.get("gpu") if isinstance(reply.data.get("gpu"), dict) else {}
            used, total = gpu.get("vram_used_mb"), gpu.get("vram_total_mb")
            now = (f" VRAM is now {_gb(used)} / {_gb(total)}."
                   if isinstance(used, int) and isinstance(total, int) and total else "")
            note = f"🧹 Freed the graphics memory.{now}"
        elif reply.outcome == OFF:
            note = f"{ui.FAILED} Nothing was freed — {self._label} stopped answering."
        else:
            note = f"{ui.FAILED} Nothing was freed — {reply.detail}."
        self._show(chat_id, message_id, *self._screen(*self._fetch(), note=note))

    # ─── sleep / shut down / restart ─────────────────────────────

    def _ask_power(self, what: str, chat_id: int, message_id: int) -> None:
        emoji, verb, question, effect = _POWER[what]
        if what == "sleep":
            effect += (" ⚡ Wake brings it back." if self._mac
                       else " Wake-on-LAN is not set up, so only a hand can wake it.")
        name = self.ctx.name
        self._show(chat_id, message_id,
                   f"{ui.ATTENTION} {question.format(pc=self._label)}\n{effect}",
                   ui.confirm_rows(emoji, verb, f"{name}:do:{what}", f"{name}:no"))

    def _do_power(self, what: str, chat_id: int, message_id: int) -> None:
        assert self._agent is not None
        name = self.ctx.name
        verb = _POWER[what][1]
        reply = self._agent.run(what)
        if reply.outcome == OFF:
            self._show(chat_id, message_id,
                       f"{ui.CANCELLED} {self._label} did not answer — it seems to be off "
                       "or asleep already. Nothing was sent.",
                       [[ui.refresh_button(f"{name}:v")], ui.nav_row()])
            return
        if not reply.ok:
            self._show(chat_id, message_id,
                       f"{ui.FAILED} {self._label} did NOT {verb} — {reply.detail}. "
                       "It is still on.", [[ui.refresh_button(f"{name}:v")], ui.nav_row()])
            return
        self.log.warning("PC %s requested from chat %s", what, chat_id)
        if what == "sleep":
            self._show(chat_id, message_id,
                       f"{ui.WORKING} {self._label} is going to sleep — checking that it "
                       "really does…", [])
            self._spawn(self._confirm_asleep, chat_id, message_id)
            return
        seconds = reply.data.get("in_seconds")
        seconds = int(seconds) if isinstance(seconds, int) else 15
        doing = "shuts down" if what == "shutdown" else "restarts"
        self._show(chat_id, message_id,
                   f"{ui.WORKING} {self._label} {doing} in {seconds} s.",
                   [[ui.button("✖ Cancel", f"{name}:abort"),
                     ui.refresh_button(f"{name}:v")]])

    def _confirm_asleep(self, chat_id: int, message_id: int) -> None:
        """A "sleep" is only done once the PC stops answering."""
        name = self.ctx.name
        wake = [ui.button("⚡ Wake", f"{name}:wake")] if self._mac else []
        for wait in _SLEEP_CHECKS:
            self._sleep(wait)
            reply, _ = self._fetch()
            if reply.outcome == OFF:
                self._show(chat_id, message_id,
                           f"😴 {self._label} is asleep — it no longer answers.",
                           ui.rows(wake, [ui.refresh_button(f"{name}:v")], ui.nav_row()) or [])
                return
        self._show(chat_id, message_id,
                   f"{ui.ATTENTION} {self._label} was asked to sleep but still answers — "
                   "something on it keeps it awake.",
                   [[ui.refresh_button(f"{name}:v")], ui.nav_row()])

    def _abort(self, chat_id: int, message_id: int) -> None:
        assert self._agent is not None
        name = self.ctx.name
        reply = self._agent.run("cancel")
        if reply.ok:
            text = f"{ui.CANCELLED} Cancelled — {self._label} stays on."
        elif reply.outcome == OFF:
            text = f"{ui.FAILED} Too late to cancel — {self._label} no longer answers."
        else:
            text = f"{ui.FAILED} NOT cancelled — {reply.detail}. It may still switch off."
        self._show(chat_id, message_id, text,
                   [[ui.refresh_button(f"{name}:v")], ui.nav_row()])

    # ─── wake, and start an agent on a cold PC ───────────────────

    def _begin_wake(self, chat_id: int, message_id: int, service_id: str | None,
                    ack) -> None:
        if service_id is not None and service_id not in self._wake_and_start:
            ack("Not available")
            return
        with self._lock:
            if self._busy:
                ack("Already waking the PC")
                return
            self._busy = True
        ack("Waking…" if service_id is None else f"Starting {self._name(service_id)}…")
        self._show(chat_id, message_id, f"{ui.WORKING} Looking at {self._label}…", [])
        self._spawn(self._wake_flow, chat_id, message_id, service_id)

    def _wake_flow(self, chat_id: int, message_id: int, service_id: str | None) -> None:
        try:
            self._wake_and_maybe_start(chat_id, message_id, service_id)
        except Exception:
            self.log.exception("waking the PC failed")
            self._show(chat_id, message_id,
                       f"{ui.FAILED} That did not finish — something went wrong inside "
                       "NetSentry. Details are in its log.",
                       [[ui.refresh_button(f"{self.ctx.name}:v")], ui.nav_row()])
        finally:
            with self._lock:
                self._busy = False

    def _wake_and_maybe_start(self, chat_id: int, message_id: int,
                              service_id: str | None) -> None:
        assert self._agent is not None
        name = self.ctx.name
        label = self._name(service_id) if service_id else ""
        what = f"{label} was NOT started" if service_id else "Nothing was started"
        retry = f"{name}:go:{service_id}" if service_id else f"{name}:wake"
        again = [[ui.button("🔁 Try again", retry), ui.refresh_button(f"{name}:v")],
                 ui.nav_row()]
        reply, status = self._fetch()
        woke = ""
        if reply.outcome == OFF:
            if not self._mac:
                self._show(chat_id, message_id, *self._screen(
                    reply, status, note=f"{ui.FAILED} {self._label} can't be woken — "
                                        "Wake-on-LAN is not set up (mac and wake_to)."))
                return
            try:
                self._send_wake(self._mac, self._wake_to)
            except wol.WakeError as e:
                self.log.error("wake packet not sent: %s", e)
                self._show(chat_id, message_id,
                           f"{ui.FAILED} The wake signal was NOT sent — {e}. "
                           f"{self._label} is still off.", again)
                return
            self._mark_woken()
            reply, status, took = self._wait_for_answer(chat_id, message_id, label)
            if reply.outcome == OFF:
                self._show(chat_id, message_id, "\n".join([
                    ui.header(ui.FAILED, self._label, "did not wake"),
                    f"No answer within {ui.duration(self._wake_wait_s)} of the wake signal"
                    + (f", so {what}." if service_id else ".")
                    + " It is probably still off or asleep; what to check for "
                      "Wake-on-LAN is in docs/WORKSTATION.md."]),
                    again)
                return
            woke = f"{ui.OK} {self._label} is awake — it took {ui.duration(took)}."
        if reply.outcome == FAULT or status is None:
            self._show(chat_id, message_id, *self._screen(
                reply, status, note=f"{ui.FAILED} {what} — "
                                    f"{reply.detail or 'the PC did not answer as expected'}."))
            return
        if service_id is None:
            self._show(chat_id, message_id, *self._screen(
                reply, status, note=woke or f"{ui.OK} {self._label} is already on."))
            return
        self._start_on_awake_pc(chat_id, message_id, service_id, status, woke)

    def _wait_for_answer(self, chat_id: int, message_id: int,
                         label: str) -> tuple[AgentReply, PcStatus | None, float]:
        started = self._clock()
        then = f", then {label} starts" if label else ""
        shown = ""
        reply: AgentReply = AgentReply(OFF)
        status: PcStatus | None = None
        while self._clock() - started < self._wake_wait_s:
            waited = self._clock() - started
            text = (f"{ui.WORKING} {self._label} — waking…\nWake signal sent. Waiting up to "
                    f"{ui.duration(self._wake_wait_s)} for it to answer{then}."
                    + (f"\n{ui.duration(waited // 60 * 60)} so far." if waited >= 60 else ""))
            if text != shown:
                self._show(chat_id, message_id, text, [])
                shown = text
            self._sleep(_WAKE_POLL_S)
            reply, status = self._fetch()
            if reply.outcome != OFF:
                break
        return reply, status, self._clock() - started

    def _start_on_awake_pc(self, chat_id: int, message_id: int, service_id: str,
                           status: PcStatus, woke: str) -> None:
        assert self._agent is not None
        name = self.ctx.name
        label = self._name(service_id)
        top = f"{woke}\n" if woke else ""
        link = ui.url_row((f"💬 Open {label}", self._links.get(service_id, "")))
        svc = status.service(service_id)
        if svc is not None and svc.running:
            text, rows = self._screen(AgentReply(OK), status,
                                      note=f"{top}{ui.OK} {label} is already running.")
            self._show(chat_id, message_id, text, ui.rows(link, *rows) or [])
            return
        if not status.logged_on:
            self._show(chat_id, message_id, "\n".join(filter(None, [
                ui.header(ui.ATTENTION, self._label, "on, nobody logged in"),
                woke,
                f"{label} was NOT started: it needs someone logged in on the PC. "
                f"Log in on the PC, then tap Start {label} again."])),
                ui.rows(ui.url_row(("⌨️ Open remote keyboard", self._keyboard_link())),
                        [ui.button(f"🤖 Start {label}", f"{name}:go:{service_id}"),
                         ui.refresh_button(f"{name}:v")],
                        ui.nav_row()) or [])
            return
        self._show(chat_id, message_id, f"{top}{ui.WORKING} Starting {label}…", [])
        reply = self._agent.start(service_id)
        note = top + self._start_note(service_id, reply)
        text, rows = self._screen(*self._fetch(), note=note)
        self._show(chat_id, message_id, text,
                   ui.rows(link if reply.data.get("running") is True else [], *rows) or [])

    def _mark_woken(self) -> None:
        with self._state_lock:
            state = read_json(self._state_file, {})
            state["woken_at"] = self._now()
            self._write_state(state)

    def _spawn(self, func, *args) -> None:
        threading.Thread(target=func, args=args, daemon=True,
                         name=f"{self.ctx.name}-worker").start()

    # ─── the scheduled check ─────────────────────────────────────

    def watch(self) -> None:
        """Cheap and silent while the PC is off; tells the owner only what changed."""
        if self._agent is None:
            return
        reply, status = self._fetch()
        if reply.outcome == FAULT:
            return                               # health() reports it; nothing else to say
        messages: list[tuple[str, str, list | None]] = []
        now = self._now()
        with self._state_lock:
            state = read_json(self._state_file, {})
            was_on = state.get("was_on")
            if reply.outcome == OFF or status is None:
                # Off: nothing to measure. A hot GPU or an idle stretch does not
                # survive the PC going off, and is not announced as recovered.
                state.update(was_on=False, hot_streak=0, hot_alerted=False,
                             idle_since=None, idle_announced=False)
            else:
                woken_at = float(state.get("woken_at") or 0)
                if was_on is False and now - woken_at > _WOKEN_GRACE_S:
                    messages.append(self._came_on(status))
                state["was_on"] = True
                messages += self._check_temperature(state, status)
                messages += self._check_disk(state, status)
                messages += self._check_idle(state, status, now)
            self._write_state(state)
        for kind, text, buttons in messages:
            try:
                self.notifier.notify(kind, text, buttons=buttons)
            except Exception:
                self.log.exception("could not send a PC message")

    def _open_row(self) -> list:
        return [[ui.button(f"{ICON} Open {self._label}"[:28], f"{self.ctx.name}:new")]]

    def _came_on(self, st: PcStatus) -> tuple[str, str, list | None]:
        who = "someone is logged in" if st.logged_on else "nobody is logged in yet"
        return (notify.INFO, f"{ui.header(ui.INFO, self._label, 'came on')}\n"
                             f"NetSentry did not wake it; {who}.", self._open_row())

    def _check_temperature(self, state: dict, st: PcStatus) -> list:
        temp = st.gpu.temp_c if st.gpu else None
        if temp is None:
            return []
        if temp >= self._temp_alert:
            state["hot_streak"] = int(state.get("hot_streak") or 0) + 1
            if state["hot_streak"] >= 2 and not state.get("hot_alerted"):
                state["hot_alerted"] = True
                load = st.gpu.load_pct if st.gpu else None
                busy = f" at {load}% load" if load is not None else ""
                return [(notify.ATTENTION,
                         f"{ui.header(ui.ATTENTION, f'{self._label} GPU', f'hot, {temp} °C')}\n"
                         f"Over {self._temp_alert} °C on two checks in a row{busy}. "
                         "Worth checking the fans and airflow.", self._open_row())]
            return []
        state["hot_streak"] = 0
        if state.get("hot_alerted"):
            state["hot_alerted"] = False
            return [(notify.RECOVERY,
                     ui.header(ui.OK, f"{self._label} GPU", f"back to {temp} °C"), None)]
        return []

    def _check_disk(self, state: dict, st: PcStatus) -> list:
        free = st.disk_free_gb
        if free is None:
            return []
        if free < self._disk_alert:
            if state.get("disk_alerted"):
                return []
            state["disk_alerted"] = True
            return [(notify.ATTENTION,
                     f"{ui.header(ui.ATTENTION, f'{self._label} disk C', f'{free} GB free')}\n"
                     f"Under {self._disk_alert} GB. Games and models need room to update.",
                     self._open_row())]
        if state.get("disk_alerted"):
            state["disk_alerted"] = False
            return [(notify.RECOVERY,
                     ui.header(ui.OK, f"{self._label} disk C", f"{free} GB free again"), None)]
        return []

    def _check_idle(self, state: dict, st: PcStatus, now: float) -> list:
        if not self._idle_hours:
            return []
        load = st.gpu.load_pct if st.gpu else None
        idle = (st.game_running is not True and not st.models
                and (load is None or load < _IDLE_GPU_PCT))
        if not idle:
            state.update(idle_since=None, idle_announced=False)
            return []
        since = float(state.get("idle_since") or now)
        state["idle_since"] = since
        if state.get("idle_announced") or now - since < self._idle_hours * 3600:
            return []
        state["idle_announced"] = True
        hours = f"{self._idle_hours:g} h"
        return [(notify.INFO,
                 f"{ui.header(ui.INFO, self._label, f'idle for {hours}')}\n"
                 f"On for {hours} with no game, no model loaded and the GPU under "
                 f"{_IDLE_GPU_PCT}%. It stays on unless you tap Sleep.",
                 [[ui.button("😴 Sleep", f"{self.ctx.name}:ask:sleep")]])]

    def _write_state(self, state: dict) -> None:
        try:
            write_json(self._state_file, state)
        except OSError:
            self.log.exception("could not store what was announced about the PC")

    # ─── health and the dashboard ────────────────────────────────

    def health(self) -> list[HealthCheck]:
        name = f"{self._label} agent"
        if self._agent is None:
            return ([HealthCheck(name, False, f"the config is not usable: {self._setup_error}")]
                    if self._setup_error else [])
        last = self._last
        if last is None:
            return [HealthCheck(name, True, "not checked yet")]
        ts, reply, _ = last
        if reply.outcome == FAULT:
            return [HealthCheck(name, False, f"{reply.detail} — details are in the log")]
        when = ui.when_text(ts, default="")
        if reply.outcome == OFF:
            return [HealthCheck(name, True, f"off or asleep (that's fine), checked {when}")]
        return [HealthCheck(name, True, f"answered {when}")]

    def api_status(self) -> dict[str, Any] | None:
        """A small read-only picture for the dashboard. Never waits for ssh: a
        stale reading starts a refresh in the background and the last one is
        returned meanwhile."""
        if self._agent is None:
            return None
        last = self._last
        if last is None or self._now() - last[0] >= _API_CACHE_S:
            self._refresh_in_background()
        if last is None:
            return {"name": self._label, "state": "unknown", "checked_ts": None}
        ts, reply, st = last
        state = {OK: "on", OFF: "off"}.get(reply.outcome, "fault")
        out: dict[str, Any] = {"name": self._label, "state": state, "checked_ts": ts}
        if state == "fault":
            out["problem"] = reply.detail
        if state != "on" or st is None:
            return out
        g = st.gpu
        out.update({
            "uptime_s": st.uptime_s, "logged_on": st.logged_on,
            "game_running": st.game_running, "models": list(st.models),
            "ram_used_mb": st.ram_used_mb, "ram_total_mb": st.ram_total_mb,
            "disk_free_gb": st.disk_free_gb, "disk_total_gb": st.disk_total_gb,
            "gpu": None if g is None else {
                "name": g.name, "temp_c": g.temp_c, "load_pct": g.load_pct,
                "vram_used_mb": g.vram_used_mb, "vram_total_mb": g.vram_total_mb,
                "power_w": g.power_w},
            "services": [{"name": s.name, "running": s.running, "model": s.model,
                          "ram_mb": s.ram_mb} for s in st.services],
        })
        return out

    def _refresh_in_background(self) -> None:
        with self._lock:
            if self._refreshing:
                return
            self._refreshing = True

        def refresh() -> None:
            try:
                self._fetch()
            except Exception:
                self.log.exception("PC status refresh failed")
            finally:
                with self._lock:
                    self._refreshing = False

        self._spawn(refresh)


def _gb(mb: Any) -> str:
    return f"{mb / 1024:.1f} GB" if isinstance(mb, (int, float)) else "?"
