"""
telegram_bot — Long-polling dispatcher.

Owns the bot loop. Discovers every plugin's COMMANDS at startup, registers
them with Telegram (setMyCommands), and dispatches incoming messages /
callback queries to the right plugin.

Callback routing convention: callback_data starts with `<plugin_name>:`.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from ..core.notifier import TelegramNotifier
from ..core.plugin import Plugin


class TelegramBotPlugin(Plugin):
    COMMANDS = [
        {"command": "help", "description": "ℹ️ List available commands"},
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

        if cmd == "/help":
            self._send_help(chat_id)
            return

        target = self._command_map.get(cmd)
        if not target:
            return  # silently ignore unknown
        try:
            target.on_command(cmd, args, chat_id)
        except Exception as e:
            self.log.exception("Handler for %s crashed", cmd)
            self._tg.send_to(chat_id, f"❌ {cmd} crashed: {e}")

    def _handle_callback(self, cb: dict) -> None:
        chat_id = cb["message"]["chat"]["id"]
        if not self._is_authorized(chat_id):
            self._tg.answer_callback(cb["id"], "Not authorized")
            return
        data = cb.get("data", "")
        plugin_name = data.split(":", 1)[0] if ":" in data else ""
        target = next((p for p in getattr(self.ctx, "_all_plugins", [])
                       if p.ctx.name == plugin_name), None)
        if not target:
            self._tg.answer_callback(cb["id"], "Unknown action")
            return
        try:
            target.on_callback(
                data, chat_id, cb["message"]["message_id"], cb["id"]
            )
        except Exception:
            self.log.exception("Callback for %s crashed", plugin_name)
            self._tg.answer_callback(cb["id"], "Error")

    # ─── /help ──────────────────────────────────────────────────

    def _send_help(self, chat_id: int) -> None:
        lines = ["🤖 NetSentry commands", "━━━━━━━━━━━━━━━━━"]
        for cmd, plugin in sorted(self._command_map.items()):
            desc = next(
                (c["description"] for c in plugin.COMMANDS if f"/{c['command']}" == cmd),
                "",
            )
            lines.append(f"  {cmd:<14} {desc}")
        lines.append("\n💡 Tap '/' to open the menu.")
        self._tg.send_to(chat_id, "\n".join(lines))

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
