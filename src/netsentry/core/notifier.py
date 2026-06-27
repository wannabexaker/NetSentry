"""
Notification dispatcher. Abstract `Notifier`, concrete `TelegramNotifier`.

Plugins call `notify.send(...)` without caring which channel(s) are configured.
Future: DiscordNotifier, EmailNotifier, PushoverNotifier — all plug in here.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path

log = logging.getLogger(__name__)


class Notifier(ABC):
    """Abstract notification channel."""

    @abstractmethod
    def send(self, text: str, *, buttons: list | None = None,
             photo_path: str | None = None) -> bool: ...

    # ─── visual-language helpers ────────────────────────────────
    # These are concrete so every subclass gets them for free.

    def send_state(self, state: str, text: str, *,
                   buttons: list | None = None) -> bool:
        """Send a notification visually tagged with a canonical state icon.

        states: 'protected' | 'scanning' | 'warning' | 'attack' | 'offline'
        Falls back to plain text if the icon file isn't present.
        """
        try:
            from ..assets import state_icon
            icon = state_icon(state)
            if icon.exists():
                return self.send(text, buttons=buttons, photo_path=str(icon))
        except Exception:
            pass
        return self.send(text, buttons=buttons)

    def send_state_to(self, chat_id, state: str, text: str, *,
                      buttons: list | None = None) -> bool:
        """Like send_state but to a specific chat. Notifiers that support
        multi-target should override; default delegates to send_state."""
        if hasattr(self, "send_to"):
            try:
                from ..assets import state_icon
                icon = state_icon(state)
                if icon.exists():
                    return self.send_to(chat_id, text, buttons=buttons,
                                        photo_path=str(icon))
            except Exception:
                pass
            return self.send_to(chat_id, text, buttons=buttons)
        return self.send_state(state, text, buttons=buttons)


# ─── Telegram ──────────────────────────────────────────────────────

class TelegramNotifier(Notifier):
    """Telegram bot API client (also used by the bot for receiving updates).

    Buttons are passed as a list-of-rows-of-button-dicts:
        [[{"text": "Yes", "callback_data": "yes"}], [{"text": "No", ...}]]
    """

    def __init__(self, token: str, chat_id: str | int,
                 *, allowed_chats: list | None = None):
        self.token = token
        self.chat_id = str(chat_id)
        self.allowed_chats = set(int(c) for c in (allowed_chats or []))
        self.base = f"https://api.telegram.org/bot{token}"
        self.last_error: str | None = None

    # ─── send ────────────────────────────────────────────────────

    def send(self, text: str, *, buttons: list | None = None,
             photo_path: str | None = None) -> bool:
        if photo_path:
            return self._send_photo(self.chat_id, photo_path, caption=text, buttons=buttons)
        return self._send_text(self.chat_id, text, buttons=buttons)

    def send_to(self, chat_id: str | int, text: str, *,
                buttons: list | None = None, photo_path: str | None = None) -> bool:
        if photo_path:
            return self._send_photo(str(chat_id), photo_path, caption=text, buttons=buttons)
        return self._send_text(str(chat_id), text, buttons=buttons)

    # ─── low-level API ───────────────────────────────────────────

    def api_get(
        self,
        method: str,
        params: dict | None = None,
        timeout: int = 35,
        *,
        log_errors: bool = True,
    ) -> dict | None:
        url = f"{self.base}/{method}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                self.last_error = None
                return json.load(r)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            if log_errors:
                log.warning("Telegram %s failed: %s", method, e)
            return None

    def api_post(self, method: str, params: dict, timeout: int = 15) -> dict | None:
        url = f"{self.base}/{method}"
        data = urllib.parse.urlencode(params).encode()
        try:
            with urllib.request.urlopen(url, data=data, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:
            log.warning("Telegram %s failed: %s", method, e)
            return None

    def _send_text(self, chat_id: str, text: str,
                   buttons: list | None = None) -> bool:
        params = {
            "chat_id": chat_id, "text": text,
            "disable_web_page_preview": "true",
        }
        if buttons:
            params["reply_markup"] = json.dumps({"inline_keyboard": buttons})
        r = self.api_post("sendMessage", params)
        return bool(r and r.get("ok"))

    def _send_photo(self, chat_id: str, photo_path: str,
                    caption: str = "", buttons: list | None = None) -> bool:
        boundary = "------NSBoundary" + str(int(time.time()))
        url = f"{self.base}/sendPhoto"
        try:
            data = Path(photo_path).read_bytes()
        except OSError:
            return False
        parts = [
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}\r\n',
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="caption"\r\n\r\n{caption}\r\n',
        ]
        if buttons:
            rm = json.dumps({"inline_keyboard": buttons})
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="reply_markup"\r\n\r\n{rm}\r\n'
            )
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="photo"; filename="image.png"\r\n'
            f"Content-Type: image/png\r\n\r\n"
        )
        body = "".join(parts).encode() + data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.load(r).get("ok", False)
        except Exception as e:
            log.warning("sendPhoto failed: %s", e)
            return False

    def send_document(self, chat_id: str | int, doc_path: str,
                      caption: str = "", filename: str | None = None) -> bool:
        """Upload a file as a Telegram document (50 MB bot upload limit)."""
        boundary = "------NSDocBoundary" + str(int(time.time()))
        url = f"{self.base}/sendDocument"
        try:
            data = Path(doc_path).read_bytes()
        except OSError as e:
            log.warning("send_document open failed: %s", e)
            return False
        fname = filename or Path(doc_path).name
        parts = [
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}\r\n',
        ]
        if caption:
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="caption"\r\n\r\n{caption}\r\n'
            )
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="document"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        )
        body = "".join(parts).encode() + data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r).get("ok", False)
        except Exception as e:
            log.warning("sendDocument failed: %s", e)
            return False

    # ─── helpers used by the bot plugin ──────────────────────────

    def edit_message(self, chat_id: str | int, message_id: int,
                     text: str, buttons: list | None = None) -> None:
        params = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if buttons is not None:
            params["reply_markup"] = json.dumps({"inline_keyboard": buttons})
        self.api_post("editMessageText", params)

    def answer_callback(self, cb_id: str, text: str = "") -> None:
        self.api_post("answerCallbackQuery", {"callback_query_id": cb_id, "text": text})

    def get_updates(self, offset: int, timeout: int = 30) -> dict | None:
        return self.api_get("getUpdates", {"offset": offset, "timeout": timeout},
                            timeout=timeout + 5, log_errors=False)

    def set_commands(self, commands: list[dict[str, str]]) -> bool:
        r = self.api_post("setMyCommands", {"commands": json.dumps(commands)})
        return bool(r and r.get("ok"))


# ─── factory ───────────────────────────────────────────────────────

def build_notifier(cfg: dict) -> Notifier:
    t = cfg.get("type", "telegram")
    if t == "telegram":
        return TelegramNotifier(
            token=cfg["token"], chat_id=cfg["chat_id"],
            allowed_chats=cfg.get("allowed_chats") or [],
        )
    raise ValueError(f"Unknown notifier type: {t}")
