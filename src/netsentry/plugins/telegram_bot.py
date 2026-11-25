"""
telegram_bot — Long-polling dispatcher.

Owns the bot loop. Discovers every plugin's COMMANDS at startup, registers
them with Telegram (setMyCommands), and dispatches incoming messages /
callback queries to the right plugin.

Callback routing convention: callback_data starts with `<plugin_name>:`.
"""

from __future__ import annotations

import secrets
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from ..core import ui
from ..core.notifier import TelegramNotifier
from ..core.plugin import HealthCheck, Plugin


class TelegramBotPlugin(Plugin):
    COMMANDS = [
        {"command": "help", "description": "❔ Every command and how to type it"},
    ]

    def on_load(self) -> None:
        # State file: last seen update_id
        self._state_file = Path(self.ctx.state_dir) / "update_id"
        self._stop_evt: threading.Event | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._poll_backoff_s = 1.0
        self._poll_backoff_max_s = 30.0
        self._poll_failure_count = 0
        self._poll_failure_started_at = 0.0
        self._last_poll_error = ""

        # We need a Telegram notifier specifically (not just any Notifier).
        notifier = self.ctx.notifiers_by_id.get("tg") or self.notifier
        if not isinstance(notifier, TelegramNotifier):
            self.log.error("telegram_bot requires a TelegramNotifier")
            self._tg = None
            return
        self._tg = notifier

        # Build command map by polling all other plugins' COMMANDS
        # (deferred to first run_forever call to ensure all plugins are loaded)
        self._command_map: dict[str, Plugin] = {}

        # ─── control-plane guards ────────────────────────────────
        # Per-chat token-bucket rate limit (anti-flood / anti-abuse).
        self._cp_lock = threading.Lock()
        self._rl_burst = float(self.cfg.get("rate_limit_burst", 8))
        self._rl_rate = float(self.cfg.get("rate_limit_per_sec", 0.5))
        self._buckets: dict[int, tuple[float, float]] = {}
        # Commands that must be confirmed with an inline button before running.
        # Empty by default: the risky commands ask their own, clearer question
        # (Plugin.CONFIRMS_ITSELF), and those are never asked twice.
        self._confirm_cmds = {
            c if c.startswith("/") else f"/{c}"
            for c in self.cfg.get("confirm_commands", [])
        }
        self._pending: dict[str, dict] = {}
        self._keyboards: dict[tuple[int, int], list | None] = {}
        self._pending_ttl_s = float(self.cfg.get("confirm_ttl_s", 120))

    # ─── dispatcher build ────────────────────────────────────────

    def _build_dispatch_table(self, all_plugins: list[Plugin]) -> None:
        """Collect every plugin's commands; build command→plugin map."""
        combined: list[dict[str, str]] = []
        seen: set[str] = set()
        for p in all_plugins:
            for c in getattr(p, "COMMANDS", []) or []:
                name = c["command"]
                if name in seen:
                    self.log.warning("Duplicate command /%s (plugin %s)", name, p.ctx.name)
                    continue
                seen.add(name)
                combined.append({"command": name, "description": c["description"]})
                self._command_map[f"/{name}"] = p
        # Register with Telegram so the slash-menu shows up nicely
        if self._tg:
            ok = self._tg.set_commands(combined)
            self.log.info("Registered %d commands with Telegram (ok=%s)", len(combined), ok)

    # ─── runtime entry from Runtime.start() ──────────────────────

    def run_forever(self, stop_event: threading.Event) -> None:
        if self._tg is None:
            self.log.error("No Telegram notifier — bot disabled")
            stop_event.wait()
            return
        # Need to know all plugins. The runtime injects this via ctx.events
        # but a simpler way: read from ctx._all_plugins (set by Runtime).
        all_plugins = getattr(self.ctx, "_all_plugins", [self])
        self._build_dispatch_table(all_plugins)
        self._stop_evt = stop_event

        last_id = self._load_offset()
        self.log.info("Bot loop starting (offset=%d)", last_id)
        worker_count = max(1, int(self.cfg.get("worker_threads", 4)))
        self._executor = ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="netsentry.bot",
        )

        try:
            while not stop_event.is_set():
                resp = self._tg.get_updates(offset=last_id + 1, timeout=30)
                if not resp or not resp.get("ok"):
                    delay = self._record_poll_failure(self._poll_failure_message(resp))
                    stop_event.wait(delay)
                    continue

                self._record_poll_success()
                for update in resp.get("result", []):
                    try:
                        last_id = self._accept_update(update)
                    except OSError:
                        self.log.exception(
                            "Could not persist Telegram update offset; update not dispatched"
                        )
                        stop_event.wait(1)
                        break
        finally:
            self._executor.shutdown(wait=False, cancel_futures=False)
            self._executor = None

    def _accept_update(self, update: dict) -> int:
        """Persist offset when an update is accepted, then handle async."""
        update_id = int(update["update_id"])
        self._save_offset(update_id)
        self._submit_update(update)
        return update_id

    def _submit_update(self, update: dict) -> None:
        if self._executor is None:
            self._handle_update(update)
            return
        future = self._executor.submit(self._handle_update, update)
        future.add_done_callback(self._worker_done)

    def _worker_done(self, future: Future) -> None:
        try:
            future.result()
        except Exception:
            self.log.exception("Telegram update worker crashed")

    def _poll_failure_message(self, resp: dict | None) -> str:
        if self._tg and self._tg.last_error:
            return self._tg.last_error
        if isinstance(resp, dict):
            description = resp.get("description") or resp.get("error_code") or "not ok"
            return f"Telegram getUpdates returned {description}"
        return "Telegram getUpdates returned no response"

    def _record_poll_failure(self, message: str) -> float:
        now = time.monotonic()
        if self._poll_failure_count == 0:
            self._poll_failure_started_at = now
            self._last_poll_error = message
            self.log.warning("Telegram connectivity degraded: %s", message)
        elif message == self._last_poll_error:
            self.log.debug("Telegram connectivity still degraded: %s", message)
        else:
            self._last_poll_error = message
            self.log.warning("Telegram connectivity degraded: %s", message)

        self._poll_failure_count += 1
        delay = self._poll_backoff_s
        self._poll_backoff_s = min(self._poll_backoff_s * 2, self._poll_backoff_max_s)
        return delay

    def _record_poll_success(self) -> None:
        if self._poll_failure_count:
            elapsed = max(0.0, time.monotonic() - self._poll_failure_started_at)
            self.log.info(
                "Telegram connectivity restored after %.0fs / %d failures",
                elapsed,
                self._poll_failure_count,
            )
        self._poll_backoff_s = 1.0
        self._poll_failure_count = 0
        self._poll_failure_started_at = 0.0
        self._last_poll_error = ""

    # ─── update routing ──────────────────────────────────────────

    def _rate_ok(self, chat_id: int) -> bool:
        """Per-chat token bucket: burst capacity, refilled at rate/sec."""
        now = time.monotonic()
        with self._cp_lock:
            tokens, last = self._buckets.get(chat_id, (self._rl_burst, now))
            tokens = min(self._rl_burst, tokens + (now - last) * self._rl_rate)
            if tokens < 1.0:
                self._buckets[chat_id] = (tokens, now)
                return False
            self._buckets[chat_id] = (tokens - 1.0, now)
            return True

    def _send_confirmation(self, chat_id: int, cmd: str, args: str) -> None:
        """Hold a destructive command behind an explicit inline confirmation."""
        nonce = secrets.token_urlsafe(8)
        with self._cp_lock:
            self._pending[nonce] = {
                "cmd": cmd,
                "args": args,
                "chat_id": chat_id,
                "expiry": time.monotonic() + self._pending_ttl_s,
            }
        label = f"{cmd} {args}".strip()
        buttons = ui.confirm_rows("✅", "run it", f"telegram_bot:confirm:{nonce}",
                                  f"telegram_bot:cancel:{nonce}")
        self._tg.send_to(chat_id, f"{ui.ATTENTION} Run {label}?", buttons=buttons)

    def _handle_confirm_callback(self, data: str, chat_id: int, cb: dict) -> None:
        _, action, nonce = (data.split(":", 2) + ["", ""])[:3]
        cb_id = cb["id"]
        message_id = (cb.get("message") or {}).get("message_id")
        with self._cp_lock:
            pending = self._pending.pop(nonce, None)
        if (
            not pending
            or pending["expiry"] < time.monotonic()
            or pending["chat_id"] != chat_id
        ):
            self._tg.answer_callback(cb_id, "Expired")
            self._replace(chat_id, message_id,
                          f"{ui.CANCELLED} This question expired. Nothing changed.")
            return
        label = f"{pending['cmd']} {pending['args']}".strip()
        if action == "cancel":
            self._tg.answer_callback(cb_id, "Cancelled")
            self._replace(chat_id, message_id, ui.NOTHING_CHANGED)
            return
        if action != "confirm":
            self._tg.answer_callback(cb_id, "Unknown")
            return
        self._tg.answer_callback(cb_id, "Confirmed")
        # The question becomes a record of what was confirmed; no live buttons.
        self._replace(chat_id, message_id, f"{ui.WORKING} Running {label}…")
        target = self._command_map.get(pending["cmd"])
        if not target:
            return
        try:
            target.on_command(pending["cmd"], pending["args"], chat_id)
        except Exception:
            self.log.exception("Confirmed handler for %s crashed", pending["cmd"])
            self._tg.send_to(chat_id, _crash_text(pending["cmd"]))

    def _replace(self, chat_id: int, message_id: int | None, text: str) -> None:
        """Edit the message the button was on (no buttons left), or say it anew."""
        if message_id is not None:
            self._tg.edit_message(chat_id, message_id, text, [])
        else:
            self._tg.send_to(chat_id, text)

    def _is_authorized(self, chat_id: int) -> bool:
        """Fail-closed authorization. An empty/absent whitelist denies everyone.

        Config validation already refuses to start without a non-empty
        `allowed_chats`, so an empty set at runtime means a misconfiguration —
        in which case denying all commands is the safe outcome, never open.
        """
        allowed = self._tg.allowed_chats
        if not allowed:
            self.log.error(
                "SECURITY: no allowed_chats configured — denying all Telegram "
                "commands (fail-closed)"
            )
            return False
        return chat_id in allowed

    def _handle_update(self, update: dict) -> None:
        cb = update.get("callback_query")
        if cb:
            self._handle_callback(cb)
            return
        msg = update.get("message")
        if not msg or "text" not in msg:
            return
        chat_id = msg["chat"]["id"]
        if not self._is_authorized(chat_id):
            self.log.info("Ignoring unauthorized chat %s", chat_id)
            return
        text = msg["text"].strip()
        parts = text.split(maxsplit=1)
        if not parts or not parts[0].startswith("/"):
            # Plain-text reply (no slash): publish for plugins that have
            # an open prompt (e.g. lan_scanner waiting for a tag name).
            if text and self.ctx.events:
                self.ctx.events.publish(
                    "telegram.text",
                    {"chat_id": chat_id, "text": text},
                )
            return
        cmd = parts[0].split("@")[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        self.log.info("Command %r from chat %s", cmd, chat_id)
        if self.ctx.events:
            # A command ends any open prompt (e.g. /who waiting for a search word).
            self.ctx.events.publish("telegram.command", {"chat_id": chat_id, "command": cmd})

        if not self._rate_ok(chat_id):
            self.log.warning("Rate limit hit for chat %s (%s)", chat_id, cmd)
            self._tg.send_to(chat_id, "⏳ Too many commands — slow down a moment.")
            return

        if not self.dispatch_command(cmd, args, chat_id):
            # /start (first contact) or a typo: never leave the owner with no
            # answer — open the button menu instead.
            note = "" if cmd == "/start" else f"{ui.INFO} {cmd} isn't a command I know."
            self._open_menu(chat_id, note)

    def dispatch_command(self, cmd: str, args: str, chat_id: int) -> bool:
        """Run a slash command exactly as if it had been typed.

        Also the entry point for menu buttons, so a tapped command goes through
        the same confirmation gate and error handling. Returns False when no
        plugin owns the command.
        """
        if cmd == "/help":
            self._send_help(chat_id)
            return True

        target = self._command_map.get(cmd)
        if not target:
            return False

        if cmd in self._confirm_cmds and cmd not in getattr(target, "CONFIRMS_ITSELF", ()):
            self._send_confirmation(chat_id, cmd, args)
            return True

        try:
            target.on_command(cmd, args, chat_id)
        except Exception:
            self.log.exception("Handler for %s crashed", cmd)
            self._tg.send_to(chat_id, _crash_text(cmd))
        return True

    def _open_menu(self, chat_id: int, note: str) -> None:
        menu = ui.plugin_named(self.ctx, "menu")
        show = getattr(menu, "show_home", None)
        if callable(show):
            try:
                show(chat_id, note=note)
                return
            except Exception:
                self.log.exception("could not open the menu")
        self._send_help(chat_id, note=note)

    def command_catalog(self) -> list[tuple[str, str, str]]:
        """Every registered command as ``(command, description, plugin_name)``."""
        out = []
        for cmd, plugin in self._command_map.items():
            desc = next((c["description"] for c in plugin.COMMANDS
                         if f"/{c['command']}" == cmd), "")
            out.append((cmd, desc, plugin.ctx.name))
        return out

    def health(self) -> list[HealthCheck]:
        if self._tg is None:
            return [HealthCheck("Telegram connection", False, "no Telegram notifier")]
        if self._poll_failure_count and self._poll_failure_started_at:
            down = time.monotonic() - self._poll_failure_started_at
            if down > 600:
                return [HealthCheck(
                    "Telegram connection", False,
                    f"unreachable for {int(down // 60)} min: {self._last_poll_error}")]
        return [HealthCheck("Telegram connection", True, "receiving commands")]

    def _handle_callback(self, cb: dict) -> None:
        chat_id = cb["message"]["chat"]["id"]
        sender_id = cb.get("from", {}).get("id")
        # The person pressing the button must be whitelisted — not merely the
        # chat the message lives in (matters in groups).
        if not self._is_authorized(chat_id) or (
            sender_id is not None and not self._is_authorized(sender_id)
        ):
            self._tg.answer_callback(cb["id"], "Not authorized")
            return
        data = cb.get("data", "")
        plugin_name = data.split(":", 1)[0] if ":" in data else ""
        if plugin_name == "telegram_bot":
            self._handle_confirm_callback(data, chat_id, cb)
            return
        target = next((p for p in getattr(self.ctx, "_all_plugins", [])
                       if p.ctx.name == plugin_name), None)
        if not target:
            self._tg.answer_callback(cb["id"], "Unknown action")
            return
        message_id = cb["message"]["message_id"]
        key = (chat_id, message_id)
        keyboard = (cb["message"].get("reply_markup") or {}).get("inline_keyboard")
        with self._cp_lock:
            self._keyboards[key] = keyboard
        try:
            target.on_callback(data, chat_id, message_id, cb["id"])
        except Exception:
            self.log.exception("Callback for %s crashed", plugin_name)
            self._tg.answer_callback(cb["id"], "Error")
        finally:
            with self._cp_lock:
                self._keyboards.pop(key, None)

    def keyboard_of(self, chat_id: int, message_id: int) -> list | None:
        """The buttons of the message whose button is being handled right now
        (only during that plugin's ``on_callback``), so a plugin can change one
        button without rebuilding the others."""
        with self._cp_lock:
            keyboard = self._keyboards.get((chat_id, message_id))
        return [list(row) for row in keyboard] if keyboard else None

    # ─── /help ──────────────────────────────────────────────────

    def _send_help(self, chat_id: int, note: str = "") -> None:
        """Every command, and the one place that shows how to type them."""
        entries = dict(self._command_map)
        commands = sorted(set(entries) | {"/help"})
        lines = ([note, ""] if note else []) + [
            ui.title("❔", "NetSentry commands", str(len(commands)))]
        for cmd in commands:
            plugin = entries.get(cmd, self)
            spec = next((c for c in plugin.COMMANDS if f"/{c['command']}" == cmd), {})
            lines.append(f"{cmd} — {spec.get('description', '')}")
            if spec.get("usage"):
                lines.append(f"   ⌨ {spec['usage']}")
        lines.append("\nThe bare command always opens buttons — nothing to remember.")
        menu = ui.plugin_named(self.ctx, "menu")
        buttons = [[ui.button("🧭 All as buttons", "menu:h")]] if menu is not None else None
        self._tg.send_to(chat_id, "\n".join(lines), buttons=buttons)

    # ─── state ──────────────────────────────────────────────────

    def _load_offset(self) -> int:
        try:
            return int(self._state_file.read_text().strip())
        except Exception:
            return 0

    def _save_offset(self, offset: int) -> None:
        temporary = self._state_file.with_suffix(".tmp")
        temporary.write_text(str(offset), encoding="utf-8")
        temporary.replace(self._state_file)


def _crash_text(cmd: str) -> str:
    """What the owner sees when a command handler raised: what did not happen,
    never the exception itself (that goes to the log)."""
    return (f"{ui.FAILED} {cmd} didn't finish — something went wrong inside NetSentry. "
            "Details are in its log; nothing else was affected.")
