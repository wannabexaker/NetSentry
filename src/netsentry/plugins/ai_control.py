"""
ai_control — AI Mission Control on the gaming PC, from Telegram (`/aicontrol`).

AI Mission Control is the launcher for the local AI on the PC (LM Studio, the
agents, their web pages, game mode). This plugin puts its main controls on one
message, edited in place, with buttons only:

  * Main: memory, the loaded model, each service with an on/off button, Start
    all / Stop all (Stop all asks once: it also unloads the model), game mode,
    and the way to the two screens below.
  * Models: what is loaded (⏏ Unload), every installed model with its size and
    a Load button, and 🔁 Agent models — pick an agent, then its model.
  * Pages: each web page with its full Tailscale link and a share switch.

Every action first shows ``⏳ <what>…`` in the same message, runs on a worker
thread (a model load takes a minute) and ends on the screen it belongs to,
with AI Mission Control's own "Last action" line (✅ ok / ❌ failed + why).

The PC is the ``workstation`` plugin's: this plugin has no config of its own
and borrows that plugin's agent (one host, one key, one Wake-on-LAN set-up).
Without a configured workstation, `/aicontrol` says so.

Buttons that point into a list (models, agents, pages) carry a checksum of
the list and the index: names never travel in callback data, and a list that
is gone (a restart) or changed since the buttons were drawn is fetched and
shown again instead of acted on. Services go by their id, checked against the last summary.
"""

from __future__ import annotations

import threading
import zlib
from typing import Any, Callable

from ..core import ui
from ..core.pc_agent import (
    MC_SERVICE_RE,
    OFF,
    SUMMARY_UNUSABLE,
    AgentReply,
    McModels,
    McPage,
    McService,
    McSummary,
    PcAgent,
    page_slug,
)
from ..core.plugin import Plugin

ICON = "🤖"
TITLE = "AI Mission Control"
_ASKING = f"{ui.WORKING} Asking the PC…"
_LAST_ICON = {"ok": ui.OK, "running": ui.WORKING, "failed": ui.FAILED}
_BROKEN = (f"{ui.FAILED} That did not finish — something went wrong inside NetSentry. "
           "Details are in its log.")
_CHANGED = f"{ui.INFO} The list changed — nothing was done. Pick again."
_SLOW = "This can take a minute or two; this message changes when it is done."

Screen = tuple[str, list]
Action = Callable[[], "tuple[AgentReply, McSummary | None]"]


class AiControlPlugin(Plugin):
    COMMANDS = [
        {"command": "aicontrol", "description": "🤖 AI Mission Control on the gaming PC"},
    ]

    def on_load(self) -> None:
        self._lock = threading.Lock()
        self._busy = False
        self._summary: McSummary | None = None
        self._models: McModels | None = None
        # kind -> (items, tag): what the index buttons of that list mean
        self._lists: dict[str, tuple[tuple, str]] = {}
        self._spawn = self._thread              # tests run it inline

    # ─── the PC (the workstation plugin's) ───────────────────────

    def _workstation(self) -> Any:
        return ui.plugin_named(self.ctx, "workstation")

    def _agent(self) -> PcAgent | None:
        getter = getattr(self._workstation(), "pc_agent", None)
        return getter() if callable(getter) else None

    def _can_wake(self) -> bool:
        return getattr(self._workstation(), "can_wake", False) is True

    # ─── Telegram ────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/aicontrol":
            return
        if self._agent() is None:
            self._show(chat_id, None, *self._not_set_up())
            return
        # No message id comes back from a send, so the answer follows the
        # "asking" line; from a button it replaces it.
        self.notifier.send_to(chat_id, _ASKING)
        self._show(chat_id, None, *self._safe(self._main_screen))

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # ai_control:<verb>[:<arg>] — h (main) | m (models) | p (pages) |
        # am (agents) | ag:<tag>:<i> (an agent's models) | s:<service>:1|0 |
        # sa (start all) | xa (ask: stop all) | xy (stop all) | g:1|0 (game mode) |
        # ld:<tag>:<i> (load) | ul (unload) | us:<tag>:<agent i>:<model i> |
        # sh:<tag>:<page i>:1|0 (share a page over Tailscale, or stop)
        _, verb, arg = (data.split(":", 2) + ["", ""])[:3]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        agent = self._agent()
        if agent is None:
            ack("Not set up")
            self._show(chat_id, message_id, *self._not_set_up())
            return
        where = (chat_id, message_id)
        if verb == "m":
            ack()
            self._refresh(*where, self._models_screen)
        elif verb == "p":
            ack()
            self._refresh(*where, self._pages_screen)
        elif verb == "am":
            ack()
            self._refresh(*where, self._agents_screen)
        elif verb == "ag":
            ack()
            self._agent_pick(*where, arg)
        elif verb == "xa":
            ack()
            self._show(*where, f"{ui.ATTENTION} Stop all AI services?\nThis also unloads the "
                               "model, which frees the GPU. Agents stop answering until they "
                               "are started again.",
                       ui.confirm_rows("⏹", "stop all", self._cb("xy"), self._cb("h")))
        elif verb == "s":
            self._service(agent, *where, arg, ack)
        elif verb == "sa":
            self._act(*where, ack, "Starting…", f"{ui.WORKING} Starting everything…\n{_SLOW}",
                      lambda: agent.mc_all(True), "Nothing was started", self._main_from)
        elif verb == "xy":
            self._act(*where, ack, "Stopping…",
                      f"{ui.WORKING} Stopping everything and unloading the model…",
                      lambda: agent.mc_all(False), "Nothing was stopped", self._main_from)
        elif verb == "g" and arg in ("1", "0"):
            on = arg == "1"
            self._act(*where, ack, "Game mode…",
                      f"{ui.WORKING} Turning game mode {'on' if on else 'off'}…",
                      lambda: agent.mc_game(on), "Game mode was NOT changed", self._main_from)
        elif verb == "ld":
            self._load(agent, *where, arg, ack)
        elif verb == "ul":
            self._act(*where, ack, "Unloading…", f"{ui.WORKING} Unloading the model…",
                      agent.mc_unload, "The model was NOT unloaded", self._models_from)
        elif verb == "us":
            self._use(agent, *where, arg, ack)
        elif verb == "sh":
            self._share(agent, *where, arg, ack)
        else:                                   # "h" (main, refresh) and anything old
            ack()
            self._refresh(*where, self._main_screen)

    def _cb(self, verb: str) -> str:
        return f"{self.ctx.name}:{verb}"

    def _show(self, chat_id: int, message_id: int | None, text: str,
              rows: list | None) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=rows or [])
        else:
            self.notifier.send_to(chat_id, text, buttons=rows or None)

    def _refresh(self, chat_id: int, message_id: int, build: Callable[[], Screen],
                 note: str = "") -> None:
        self._show(chat_id, message_id, _ASKING, [])
        text, rows = self._safe(build)
        self._show(chat_id, message_id, f"{note}\n\n{text}" if note else text, rows)

    def _safe(self, build: Callable[[], Screen]) -> Screen:
        try:
            return build()
        except Exception:                       # never leave "Asking the PC…" standing
            self.log.exception("AI Mission Control screen failed")
            return _BROKEN, self._back_rows()

    def _thread(self, func: Callable[..., None], *args: Any) -> None:
        threading.Thread(target=func, args=args, daemon=True,
                         name=f"{self.ctx.name}-worker").start()

    # ─── lists behind index buttons ──────────────────────────────

    def _remember(self, kind: str, items: tuple) -> str:
        """Keep the list the buttons are drawn from; its tag is a checksum of
        its content, so a button only ever acts on the very list it was drawn
        from — also across a restart, which starts with no list at all."""
        tag = f"{zlib.crc32(repr(items).encode('utf-8')):08x}"
        self._lists[kind] = (items, tag)
        return tag

    def _pick(self, kind: str, tag: str, index: str) -> Any:
        """The item a button meant, or None when the list is gone or changed."""
        items, current = self._lists.get(kind, ((), ""))
        if not current or tag != current or not index.isdigit():
            return None
        i = int(index)
        return items[i] if i < len(items) else None

    # ─── actions ─────────────────────────────────────────────────

    def _act(self, chat_id: int, message_id: int, ack: Callable[[str], None], toast: str,
             waiting: str, call: Action, failed: str,
             after: Callable[[McSummary], Screen]) -> None:
        """One change on the PC: ``⏳`` first, the work on a worker thread, then
        the screen it belongs to (or what went wrong). One at a time."""
        with self._lock:
            if self._busy:
                ack("Still busy with the last action")
                return
            self._busy = True
        ack(toast)
        try:
            self._show(chat_id, message_id, waiting, [])
            self._spawn(self._finish, chat_id, message_id, call, failed, after)
        except Exception:
            with self._lock:
                self._busy = False
            raise

    def _finish(self, chat_id: int, message_id: int, call: Action, failed: str,
                after: Callable[[McSummary], Screen]) -> None:
        try:
            reply, summary = call()
            if reply.ok and summary is not None:
                self._summary = summary
                screen = after(summary)
            else:
                screen = self._problem(reply, failed)
        except Exception:
            self.log.exception("AI Mission Control action failed")
            screen = _BROKEN, self._back_rows()
        finally:
            with self._lock:
                self._busy = False
        self._show(chat_id, message_id, *screen)

    def _service(self, agent: PcAgent, chat_id: int, message_id: int, arg: str,
                 ack: Callable[[str], None]) -> None:
        sid, _, flag = arg.rpartition(":")
        svc = next((v for v in _shown(self._summary) if v.id == sid), None)
        if svc is None or flag not in ("1", "0") or not MC_SERVICE_RE.fullmatch(sid):
            ack("The list changed")
            self._refresh(chat_id, message_id, self._main_screen, note=_CHANGED)
            return
        start = flag == "1"
        self._act(chat_id, message_id, ack, "Starting…" if start else "Stopping…",
                  f"{ui.WORKING} {'Starting' if start else 'Stopping'} {svc.name}…",
                  lambda: agent.mc_service(sid, "start" if start else "stop"),
                  f"{svc.name} was NOT {'started' if start else 'stopped'}", self._main_from)

    def _load(self, agent: PcAgent, chat_id: int, message_id: int, arg: str,
              ack: Callable[[str], None]) -> None:
        gen, _, index = arg.partition(":")
        key = self._pick("models", gen, index)
        if key is None:
            ack("The list changed")
            self._refresh(chat_id, message_id, self._models_screen, note=_CHANGED)
            return
        if key in _loaded(self._summary):
            ack("Already loaded")
            return
        self._act(chat_id, message_id, ack, "Loading…",
                  f"{ui.WORKING} Loading {key}…\n{_SLOW}", lambda: agent.mc_load(key),
                  f"{key} was NOT loaded", self._models_from)

    def _use(self, agent: PcAgent, chat_id: int, message_id: int, arg: str,
             ack: Callable[[str], None]) -> None:
        gen, _, rest = arg.partition(":")
        a_index, _, m_index = rest.partition(":")
        picked = self._pick("agents", gen, a_index)
        keys = picked[1] if picked else ()
        if picked is None or not m_index.isdigit() or int(m_index) >= len(keys):
            ack("The list changed")
            self._refresh(chat_id, message_id, self._agents_screen, note=_CHANGED)
            return
        sid, key = picked[0], keys[int(m_index)]
        name = self._name(sid)
        if key == self._current_model(sid):
            ack("Already using it")
            return
        self._act(chat_id, message_id, ack, "Switching…",
                  f"{ui.WORKING} Switching {name} to {key}…\nIf it runs, it restarts.",
                  lambda: agent.mc_use(sid, key), f"{name} was NOT switched",
                  self._models_from)

    def _share(self, agent: PcAgent, chat_id: int, message_id: int, arg: str,
               ack: Callable[[str], None]) -> None:
        gen, _, rest = arg.partition(":")
        index, _, flag = rest.partition(":")
        slug = self._pick("pages", gen, index)
        if slug is None or flag not in ("1", "0"):
            ack("The list changed")
            self._refresh(chat_id, message_id, self._pages_screen, note=_CHANGED)
            return
        on = flag == "1"
        self._act(chat_id, message_id, ack, "Sharing…" if on else "Stopping the share…",
                  f"{ui.WORKING} Telling the PC…", lambda: agent.share(slug, on),
                  "The share was NOT changed", self._pages_from)

    # ─── reading the PC ──────────────────────────────────────────

    def _read_summary(self) -> tuple[AgentReply, McSummary | None]:
        agent = self._agent()
        if agent is None:
            return AgentReply(OFF), None
        reply, summary = agent.summary()
        if summary is not None:
            self._summary = summary
        return reply, summary

    def _read_models(self) -> McModels | None:
        agent = self._agent()
        if agent is None:
            return None
        _, models = agent.mc_models()
        self._models = models
        return models

    def _name(self, service_id: str) -> str:
        svc = next((v for v in (self._summary.services if self._summary else ())
                    if v.id == service_id), None)
        return svc.name if svc else service_id.capitalize()

    def _current_model(self, service_id: str) -> str:
        svc = next((v for v in (self._summary.services if self._summary else ())
                    if v.id == service_id), None)
        return svc.model if svc else ""

    # ─── screens ─────────────────────────────────────────────────

    def _not_set_up(self) -> Screen:
        return (ui.title(ICON, TITLE, "not set up") + "\nNo PC is set up. AI Mission Control "
                "is reached through the workstation plugin: give it host, user and ssh_key "
                "(docs/WORKSTATION.md).", [ui.nav_row()])

    def _back_rows(self, *extra: list) -> list:
        return ui.rows(*extra, [ui.refresh_button(self._cb("h")),
                                ui.button("⬅ PC", "workstation:v")], ui.nav_row()) or []

    def _problem(self, reply: AgentReply, failed: str = "") -> Screen:
        head = ui.title(ICON, TITLE)
        if reply.outcome == OFF:
            wake = [ui.button("⚡ Wake", "workstation:wake")] if self._can_wake() else []
            top = f"{ui.FAILED} {failed} — the PC stopped answering.\n\n" if failed else ""
            return (f"{top}{head}\n💤 The PC isn't answering — it may be asleep or off.",
                    self._back_rows(wake))
        if reply.detail == SUMMARY_UNUSABLE:
            return (f"{head}\n{ui.ATTENTION} AI Mission Control on the PC gave no usable "
                    "summary — it is probably too old for this (needs 0.5.0 or newer). "
                    "Details are in the log.", self._back_rows())
        if failed:
            return (f"{head}\n{ui.FAILED} {failed} — {reply.detail or 'unknown'}. "
                    "Details are in the log.", self._back_rows())
        return (f"{head}\n{ui.ATTENTION} Something is wrong with the connection: "
                f"{reply.detail or 'unknown'}. Details are in the log; the set-up is in "
                "docs/WORKSTATION.md.", self._back_rows())

    def _main_screen(self) -> Screen:
        reply, summary = self._read_summary()
        return self._main_from(summary) if reply.ok and summary is not None \
            else self._problem(reply)

    def _main_from(self, s: McSummary) -> Screen:
        game = s.game_auto_free
        if game is None:                # an AI Mission Control older than 0.5.1
            models = self._read_models()
            game = models.game_auto_free if models is not None else None
        text = summary_text(s, pages=True, game_mode=game)
        toggles = [ui.button(f"{'⏹' if v.running else '▶'} {v.name}"[:28],
                             self._cb(f"s:{v.id}:{0 if v.running else 1}"))
                   for v in _shown(s) if MC_SERVICE_RE.fullmatch(v.id)]
        rows = [toggles[i:i + 2] for i in range(0, len(toggles), 2)]
        rows.append([ui.button("▶ Start all", self._cb("sa")),
                     ui.button("⏹ Stop all", self._cb("xa"))])
        rows.append([ui.button("🧠 Models", self._cb("m")),
                     ui.button("🔗 Pages", self._cb("p"))])
        if game is not None:
            rows.append([ui.button(f"🎮 Game mode: {'on' if game else 'off'}",
                                   self._cb(f"g:{0 if game else 1}"))])
        return text, self._back_rows(*rows)

    def _models_screen(self) -> Screen:
        reply, summary = self._read_summary()
        return self._models_from(summary) if reply.ok and summary is not None \
            else self._problem(reply)

    def _models_from(self, s: McSummary) -> Screen:
        head = ui.title(ICON, TITLE, "models")
        back = [[ui.refresh_button(self._cb("m"))], ui.nav_row(self._cb("h"))]
        models = self._read_models()
        if models is None:
            return (f"{head}\n{ui.ATTENTION} The PC gave no model list — its agent is "
                    "probably older than this (it needs the `mc models` action). Details "
                    "are in the log.", back)
        gen = self._remember("models", tuple(m.key for m in models.models))
        self._remember("agents", models.agents)
        loaded = _loaded(s)
        lines = [head]
        lines += [ui.item(f"Loaded: {m.name}", *_model_bits(m))
                  for m in s.models] or ["Loaded: none"]
        lines += ["", "Installed"] if models.models else ["", "Installed: none reported"]
        lines += [ui.item(f"{'🟢' if m.key in loaded else '⚪'} {m.key}", _gb(m.size_mb))
                  for m in models.models]
        if models.agents:
            lines += ["", "Agents"]
            lines += [ui.item(self._name(sid), self._current_model(sid) or "no model")
                      for sid, _ in models.agents]
        lines += _last_lines(s)
        rows: list = []
        if loaded:
            rows.append([ui.button("⏏ Unload", self._cb("ul"))])
        for i, m in enumerate(models.models):
            label = f"✔ {m.key} (loaded)" if m.key in loaded else f"Load {m.key}"
            rows.append([ui.button(label, self._cb(f"ld:{gen}:{i}"))])
        if models.agents:
            rows.append([ui.button("🔁 Agent models", self._cb("am"))])
        return "\n".join(lines), ui.rows(*rows, *back) or []

    def _agents_screen(self) -> Screen:
        reply, summary = self._read_summary()
        if not reply.ok or summary is None:
            return self._problem(reply)
        back = [[ui.refresh_button(self._cb("am"))], ui.nav_row(self._cb("m"))]
        models = self._read_models()
        head = ui.title(ICON, TITLE, "agent models")
        if models is None or not models.agents:
            return f"{head}\nThe PC lists no agent whose model can be switched.", back
        gen = self._remember("agents", models.agents)
        self._remember("models", tuple(m.key for m in models.models))
        lines = [head, "Pick an agent, then the model it should use."]
        rows = []
        for i, (sid, _) in enumerate(models.agents):
            current = self._current_model(sid) or "no model"
            lines.append(ui.item(self._name(sid), current))
            rows.append([ui.button(f"{self._name(sid)} · {current}"[:60],
                                   self._cb(f"ag:{gen}:{i}"))])
        return "\n".join(lines), ui.rows(*rows, *back) or []

    def _agent_pick(self, chat_id: int, message_id: int, arg: str) -> None:
        gen, _, index = arg.partition(":")
        picked = self._pick("agents", gen, index)
        if picked is None:
            self._refresh(chat_id, message_id, self._agents_screen, note=_CHANGED)
            return
        sid, keys = picked
        name, current = self._name(sid), self._current_model(sid)
        lines = [ui.title(ICON, TITLE, f"{name} model"), f"Now: {current or 'no model'}"]
        lines.append(f"Pick the model {name} should use. If it runs, it restarts."
                     if keys else f"The PC lists no model {name} may use.")
        rows = [[ui.button(f"✔ {key} (now)" if key == current else key,
                           self._cb(f"us:{gen}:{index}:{i}"))] for i, key in enumerate(keys)]
        self._show(chat_id, message_id, "\n".join(lines),
                   ui.rows(*rows, ui.nav_row(self._cb("am"))) or [])

    def _pages_screen(self) -> Screen:
        reply, summary = self._read_summary()
        return self._pages_from(summary) if reply.ok and summary is not None \
            else self._problem(reply)

    def _pages_from(self, s: McSummary) -> Screen:
        shareable = [g for g in s.pages if page_slug(g.id) and g.tailscale_url]
        gen = self._remember("pages", tuple(page_slug(g.id) for g in shareable))
        lines = [ui.title(ICON, TITLE, "pages")]
        lines += _page_lines(s.pages) or ["No pages reported."]
        lines += _last_lines(s)
        rows = []
        for i, page in enumerate(shareable):
            what = f"{page.name} {page.label}".strip()
            if page.tailscale_shared:
                rows.append([ui.button(f"🚫 Stop sharing {what}", self._cb(f"sh:{gen}:{i}:0"))])
            else:
                rows.append([ui.button(f"🔗 Share {what} on Tailscale",
                                       self._cb(f"sh:{gen}:{i}:1"))])
        return "\n".join(lines), ui.rows(*rows, [ui.refresh_button(self._cb("p"))],
                                         ui.nav_row(self._cb("h"))) or []


# ─── text ────────────────────────────────────────────────────────

def _shown(s: McSummary | None) -> list[McService]:
    """The services on the PC (not NetSentry itself, nothing remote)."""
    return [v for v in (s.services if s else ()) if not v.remote and v.id != "netsentry"]


def _loaded(s: McSummary | None) -> set[str]:
    return {m.name for m in (s.models if s else ())}


def _gb(mb: int | None) -> str:
    return f"{mb / 1024:.1f} GB" if mb else ""


def _hhmm(value: str) -> str:
    when = ui.parse_when(value)
    return f"{when:%H:%M}" if when else ""


def _page_lines(pages: tuple[McPage, ...]) -> list[str]:
    out = []
    for g in pages:
        icon = "🟢" if g.opens else "🟡" if g.available else "⚪"
        out.append(ui.item(f"{icon} {g.name} {g.label}".strip(),
                           "open" if g.available else "closed",
                           "Tailscale on" if g.tailscale_shared else "Tailscale off",
                           "" if g.opens else "link won't open now"))
        out.append(f"   {g.tailscale_url}" if g.tailscale_url else "   no Tailscale link")
    return out


def _last_lines(s: McSummary) -> list[str]:
    last = s.last_action
    if last is None:
        return []
    ended = _hhmm(last.ended)
    return ["", f"Last action: {_LAST_ICON.get(last.state, ui.INFO)} "
                + ui.item(last.summary, last.reason) + (f" ({ended})" if ended else "")]


def _model_bits(m) -> tuple[str, str]:
    """``64k context`` and where it runs (``100% GPU``, ``CPU``). Where it runs
    comes from ``Placement`` (AI Mission Control 0.5.1+); an older summary only
    has ``Processor``, which may repeat the context (``ctx 64k``) — not said twice."""
    ctx = ""
    if m.context:
        whole_k = m.context >= 1024 and m.context % 1024 == 0
        ctx = f"{m.context // 1024}k context" if whole_k else f"{m.context} context"
    where = m.placement or ("" if m.processor.lower().startswith("ctx") else m.processor)
    return ctx, where


def summary_text(s: McSummary, *, pages: bool = True, game_mode: bool | None = None) -> str:
    """AI Mission Control's summary as one plain-text screen. Page links are
    printed whole: Telegram makes them tappable, and the owner opens them on
    his phone. ``pages=False`` (the main screen) puts one count line in place
    of the pages, which have a screen of their own."""
    lines = [ui.title(ICON, f"{TITLE} {s.version}".strip(), _hhmm(s.time))]
    memory = []
    if s.vram_used_mib is not None and s.vram_total_mib:
        memory.append(f"VRAM {s.vram_used_mib / 1024:.1f} / {s.vram_total_mib / 1024:.1f} GB")
    if s.ram_free_mb is not None and s.ram_total_mb:
        used = max(0, s.ram_total_mb - s.ram_free_mb)
        free = f" ({s.ram_free_percent:.0f}% free)" if s.ram_free_percent is not None else ""
        memory.append(f"RAM {used / 1024:.1f} / {s.ram_total_mb / 1024:.1f} GB{free}")
    if memory:
        lines.append(" · ".join(memory))
    if not s.models:
        lines.append("Model loaded: none")
    for m in s.models:
        lines.append(ui.item(f"Model loaded: {m.name}", *_model_bits(m)))
    lines.append(f"Game: {s.game or 'none'}")
    if game_mode is not None:
        lines.append("Game mode: on — frees the GPU when a game starts" if game_mode
                     else "Game mode: off")

    services = _shown(s)
    lines += ["", "Services"] if services else ["", "Services: none reported"]
    lines += [ui.item(f"{'🟢' if v.running else '⚪'} {v.name}", v.model) for v in services]

    if pages and s.pages:
        lines += ["", "Pages", *_page_lines(s.pages)]
    elif s.pages:
        shared = sum(1 for g in s.pages if g.tailscale_shared)
        lines += ["", f"Pages: {len(s.pages)} · {shared} shared on Tailscale"]
    return "\n".join(lines + _last_lines(s))
