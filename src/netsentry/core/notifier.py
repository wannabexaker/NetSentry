"""
Notification dispatcher. Abstract `Notifier`, concrete `TelegramNotifier`.

Plugins call `notify.send(...)` without caring which channel(s) are configured.
Future: DiscordNotifier, EmailNotifier, PushoverNotifier — all plug in here.

Two ways to send:

* ``send`` / ``send_to`` — a reply, or anything the caller decides about. Always
  delivered, with sound.
* ``notify(kind, text)`` — an unprompted message (alert, recovery, report). The
  owner's notification mode decides whether it makes a sound, arrives silently
  or is not sent at all (see ``core/notify.py``). Its first line is made bold.

Alerts are text, never pictures: a photo caption is limited to 1024 characters
(a longer alert would be lost) and a photo cannot be edited by a later button.
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

from . import ui
from .notify import FAILED, NOT_SENT, AlertJournal, NotifyPolicy

log = logging.getLogger(__name__)

# Legacy state names → the emoji that now opens the message.
_STATE_EMOJI = {
    "protected": ui.OK,
    "scanning": ui.WORKING,
    "warning": ui.ATTENTION,
    "attack": ui.ATTACK,
    "offline": ui.ATTACK,
}


def _with_state(state: str, text: str) -> str:
    """Make the state emoji the first character, unless the text already opens
    with one of the state emoji."""
    if ui.starts_with_state(text):
        return text
    emoji = _STATE_EMOJI.get(state, "")
    return f"{emoji} {text}" if emoji else text


class Notifier(ABC):
    """Abstract notification channel."""

    @abstractmethod
    def send(self, text: str, *, buttons: list | None = None,
             photo_path: str | None = None, silent: bool = False,
             html: bool = False) -> bool: ...

    def send_to(self, chat_id, text: str, *, buttons: list | None = None,
                photo_path: str | None = None, silent: bool = False,
                html: bool = False) -> bool:
        """Send to a specific chat. Single-target notifiers just ``send``."""
        return self.send(text, buttons=buttons, photo_path=photo_path,
                         silent=silent, html=html)

    # ─── how loud ───────────────────────────────────────────────

    @property
    def policy(self) -> NotifyPolicy:
        policy = self.__dict__.get("_policy")
        if policy is None:
            policy = NotifyPolicy()
            self.__dict__["_policy"] = policy
        return policy

    @policy.setter
    def policy(self, value: NotifyPolicy) -> None:
        self.__dict__["_policy"] = value

    # Every unprompted message is noted here (in memory unless a file is given).
    @property
    def journal(self) -> AlertJournal:
        journal = self.__dict__.get("_journal")
        if journal is None:
            journal = AlertJournal()
            self.__dict__["_journal"] = journal
        return journal

    @journal.setter
    def journal(self, value: AlertJournal) -> None:
        self.__dict__["_journal"] = value

    def notify(self, kind: str, text: str, *, buttons: list | None = None,
               html: bool = False, chat_id=None, photo_path: str | None = None) -> bool:
        """Send an unprompted message of ``kind`` (see ``core/notify.py``).

        Returns True when it was delivered or deliberately not sent (the mode
        says so), False when sending failed. Plain text gets a bold first line;
        pass ``html=True`` for text already built with the ``ui`` helpers.
        ``photo_path`` is for the rare message whose picture *is* the content
        (the guest WiFi QR code) — never for decoration.

        Each call is noted in the alert journal (first line only), however it went.
        """
        how = self.policy.delivery(kind)
        if how is None:
            log.info("Not sent (%s message, mode %s): %s",
                     kind, self.policy.mode, text.split("\n", 1)[0][:80])
            self._note_alert(kind, NOT_SENT, text, html)
            return True
        body = text if html else ui.bold_first_line(text)
        silent = how == "silent"
        try:
            if chat_id is not None:
                sent = self.send_to(chat_id, body, buttons=buttons, silent=silent, html=True,
                                    photo_path=photo_path)
            else:
                sent = self.send(body, buttons=buttons, silent=silent, html=True,
                                 photo_path=photo_path)
        except Exception:
            self._note_alert(kind, FAILED, text, html)
            raise
        self._note_alert(kind, how if sent else FAILED, text, html)
        return sent

    def _note_alert(self, kind: str, delivery: str, text: str, html: bool) -> None:
        """Note one unprompted message; never lets the journal cost the alert."""
        try:
            first = next((line for line in str(text or "").splitlines() if line.strip()), "")
            self.journal.record(kind, delivery, ui.strip_html(first) if html else first)
        except Exception:
            log.exception("could not note the alert in the journal")

    # ─── kept for older callers ─────────────────────────────────

    def send_state(self, state: str, text: str, *,
                   buttons: list | None = None) -> bool:
        """A plain text message whose first character is the state's emoji.

        states: 'protected' | 'scanning' | 'warning' | 'attack' | 'offline'.
        (It used to attach a picture; alerts are text now.) Always delivered —
        new code should use :meth:`notify` with a kind instead.
        """
        return self.send(_with_state(state, text), buttons=buttons)

    def send_state_to(self, chat_id, state: str, text: str, *,
                      buttons: list | None = None) -> bool:
        """Like send_state but to a specific chat."""
        return self.send_to(chat_id, _with_state(state, text), buttons=buttons)


# ─── Telegram ──────────────────────────────────────────────────────

#: Added to the words of a picture that could not be delivered.
_NO_PICTURE = "🖼 The picture didn't go through — ask again to get it."


class TelegramNotifier(Notifier):
    """Telegram bot API client (also used by the bot for receiving updates).

    Buttons are passed as a list-of-rows-of-button-dicts:
        [[{"text": "Yes", "callback_data": "yes"}], [{"text": "No", ...}]]
    """

    def __init__(self, token: str, chat_id: str | int,
                 *, allowed_chats: list | None = None,
                 notify_mode: str | None = None,
                 state_file: Path | str | None = None,
                 journal_file: Path | str | None = None):
        self.token = token
        self.chat_id = str(chat_id)
        self.allowed_chats = set(int(c) for c in (allowed_chats or []))
        self.base = f"https://api.telegram.org/bot{token}"
        self.last_error: str | None = None
        self.policy = NotifyPolicy(notify_mode, state_file)
        self.journal = AlertJournal(journal_file)

    #: Pause before the one extra try of a message Telegram did not answer.
    retry_pause_s = 2.0

    def _once_more_if_unanswered(self, call) -> dict | None:
        """Run ``call``; if Telegram gave no answer at all (time-out, reset, a
        gateway error), wait a moment and run it once more. A refusal is an
        answer and is not repeated. The second try can, rarely, deliver a
        message twice — better than not at all."""
        answer = call()
        if answer is None:
            time.sleep(self.retry_pause_s)
            answer = call()
        return answer

    # ─── send ────────────────────────────────────────────────────

    def send(self, text: str, *, buttons: list | None = None,
             photo_path: str | None = None, silent: bool = False,
             html: bool = False) -> bool:
        return self.send_to(self.chat_id, text, buttons=buttons, photo_path=photo_path,
                            silent=silent, html=html)

    def send_to(self, chat_id: str | int, text: str, *,
                buttons: list | None = None, photo_path: str | None = None,
                silent: bool = False, html: bool = False) -> bool:
        if photo_path:
            return self._send_photo(str(chat_id), photo_path, caption=text,
                                    buttons=buttons, silent=silent, html=html)
        return self._send_text(str(chat_id), text, buttons=buttons,
                               silent=silent, html=html)

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
            with urllib.request.urlopen(url, timeout=timeout) as r:  # nosec B310
                self.last_error = None
                return json.load(r)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            if log_errors:
                log.warning("Telegram %s failed: %s", method, e)
            return None

    def api_post(self, method: str, params: dict, timeout: int = 15) -> dict | None:
        r = self._post(method, params, timeout)
        return r if r and r.get("ok") is not False else None

    def _post(self, method: str, params: dict, timeout: int = 15) -> dict | None:
        """POST and return Telegram's answer — also the error answer of a refused
        request (HTTP 400 carries a JSON body saying why)."""
        url = f"{self.base}/{method}"
        data = urllib.parse.urlencode(params).encode()
        try:
            with urllib.request.urlopen(url, data=data, timeout=timeout) as r:  # nosec B310
                return json.load(r)
        except urllib.error.HTTPError as e:
            answer = _error_body(e)
            log.warning("Telegram %s refused: %s", method,
                        answer.get("description") if answer else e)
            return answer or None
        except Exception as e:
            log.warning("Telegram %s failed: %s", method, e)
            return None

    def _send_text(self, chat_id: str, text: str, buttons: list | None = None,
                   silent: bool = False, html: bool = False) -> bool:
        """Send ``text``, split into several messages if it is too long for one;
        the buttons go under the last part."""
        parts = ui.split_message(text)
        ok = True
        for n, part in enumerate(parts):
            last = n == len(parts) - 1
            ok = self._send_one(chat_id, part, buttons if last else None,
                                silent, html) and ok
        return ok

    def _send_one(self, chat_id: str, text: str, buttons: list | None,
                  silent: bool, html: bool) -> bool:
        params = {
            "chat_id": chat_id, "text": text,
            "disable_web_page_preview": "true",
        }
        if silent:
            params["disable_notification"] = "true"
        if buttons:
            params["reply_markup"] = json.dumps({"inline_keyboard": buttons})
        if html:
            params["parse_mode"] = "HTML"
        r = self._once_more_if_unanswered(lambda: self._post("sendMessage", params))
        if html and _formatting_refused(r):
            # A formatting bug must never lose an alert: send it as plain text.
            log.warning("Telegram refused the HTML formatting; sending plain text")
            params.pop("parse_mode")
            params["text"] = ui.strip_html(text)
            r = self._post("sendMessage", params)
        return bool(r and r.get("ok"))

    def _send_photo(self, chat_id: str, photo_path: str, caption: str = "",
                    buttons: list | None = None, silent: bool = False,
                    html: bool = False) -> bool:
        """A photo with its caption. A caption over Telegram's 1024 characters
        would make the whole send fail, so the photo then carries the first line
        and the rest follows as a text message (with the buttons).

        If the picture cannot be delivered, its words are sent as a text
        message: a guest WiFi password must not be lost with its QR code."""
        words = caption
        rest = ""
        if ui.tg_len(caption) > ui.TELEGRAM_CAPTION_LIMIT:
            first, _, rest = caption.partition("\n")
            caption = first[:ui.fit(first, ui.TELEGRAM_CAPTION_LIMIT)]
        sent = self._upload_photo(chat_id, photo_path, caption,
                                  None if rest else buttons, silent, html)
        if not sent:
            log.warning("The picture was not delivered; sending its text instead")
            return self._send_text(chat_id, f"{words}\n\n{_NO_PICTURE}", buttons, silent, html)
        if rest.strip():
            sent = self._send_text(chat_id, rest, buttons, silent, html) and sent
        return sent

    def _upload_photo(self, chat_id: str, photo_path: str, caption: str,
                      buttons: list | None, silent: bool, html: bool) -> bool:
        try:
            data = Path(photo_path).read_bytes()
        except OSError:
            log.warning("The picture to send cannot be read: %s", Path(photo_path).name)
            return False
        fields = {"chat_id": chat_id, "caption": caption}
        if buttons:
            fields["reply_markup"] = json.dumps({"inline_keyboard": buttons})
        if silent:
            fields["disable_notification"] = "true"
        if html:
            fields["parse_mode"] = "HTML"
        r = self._once_more_if_unanswered(lambda: self._multipart(
            "sendPhoto", fields, "photo", "image.png", "image/png", data))
        if html and _formatting_refused(r):
            log.warning("Telegram refused the caption formatting; sending plain text")
            fields.pop("parse_mode")
            fields["caption"] = ui.strip_html(caption)
            r = self._multipart("sendPhoto", fields, "photo", "image.png", "image/png", data)
        return bool(r and r.get("ok"))

    def _multipart(self, method: str, fields: dict, file_field: str, filename: str,
                   content_type: str, data: bytes, timeout: int = 20) -> dict | None:
        boundary = "------NSBoundary" + str(int(time.time()))
        parts = [f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
                 for key, value in fields.items()]
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        )
        body = "".join(parts).encode() + data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(
            f"{self.base}/{method}", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
                return json.load(r)
        except urllib.error.HTTPError as e:
            answer = _error_body(e)
            log.warning("%s refused: %s", method, answer.get("description") if answer else e)
            return answer or None
        except Exception as e:
            log.warning("%s failed: %s", method, e)
            return None

    def send_document(self, chat_id: str | int, doc_path: str,
                      caption: str = "", filename: str | None = None) -> bool:
        """Upload a file as a Telegram document (50 MB bot upload limit)."""
        try:
            data = Path(doc_path).read_bytes()
        except OSError as e:
            log.warning("send_document open failed: %s", e)
            return False
        fields: dict = {"chat_id": chat_id}
        if caption:
            fields["caption"] = caption[:ui.fit(caption, ui.TELEGRAM_CAPTION_LIMIT)]
        r = self._multipart("sendDocument", fields, "document",
                            filename or Path(doc_path).name,
                            "application/octet-stream", data, timeout=30)
        return bool(r and r.get("ok"))

    # ─── helpers used by the bot plugin ──────────────────────────

    def edit_message(self, chat_id: str | int, message_id: int,
                     text: str, buttons: list | None = None, *,
                     html: bool = False) -> None:
        """Replace a message's text (and buttons). One message cannot be split,
        so text over the limit is shortened."""
        if ui.tg_len(text) > ui.TELEGRAM_TEXT_LIMIT:
            text = text[:ui.fit(text, ui.TELEGRAM_TEXT_LIMIT - 1)] + "…"
        params = {"chat_id": chat_id, "message_id": message_id, "text": text,
                  "disable_web_page_preview": "true"}
        if buttons is not None:
            params["reply_markup"] = json.dumps({"inline_keyboard": buttons})
        if html:
            params["parse_mode"] = "HTML"
        r = self._post("editMessageText", params)
        if html and _formatting_refused(r):
            params.pop("parse_mode")
            params["text"] = ui.strip_html(text)
            self._post("editMessageText", params)

    def edit_buttons(self, chat_id: str | int, message_id: int,
                     buttons: list | None) -> None:
        """Replace only a message's buttons (its text stays as it is)."""
        self._post("editMessageReplyMarkup", {
            "chat_id": chat_id, "message_id": message_id,
            "reply_markup": json.dumps({"inline_keyboard": buttons or []})})

    def answer_callback(self, cb_id: str, text: str = "") -> None:
        self.api_post("answerCallbackQuery", {"callback_query_id": cb_id, "text": text})

    def get_updates(self, offset: int, timeout: int = 30) -> dict | None:
        return self.api_get("getUpdates", {"offset": offset, "timeout": timeout},
                            timeout=timeout + 5, log_errors=False)

    def set_commands(self, commands: list[dict[str, str]]) -> bool:
        r = self.api_post("setMyCommands", {"commands": json.dumps(commands)})
        return bool(r and r.get("ok"))


def _error_body(e: urllib.error.HTTPError) -> dict:
    try:
        answer = json.loads(e.read().decode("utf-8", "replace"))
        return answer if isinstance(answer, dict) else {}
    except Exception:
        return {}


def _formatting_refused(answer: dict | None) -> bool:
    """Telegram's answer when the HTML in a message is broken."""
    if not answer or answer.get("ok"):
        return False
    text = str(answer.get("description", "")).lower()
    return answer.get("error_code") == 400 and ("parse entities" in text
                                                or "can't find end" in text
                                                or "unsupported start tag" in text)


# ─── factory ───────────────────────────────────────────────────────

def build_notifier(cfg: dict, *, state_file: Path | str | None = None,
                   journal_file: Path | str | None = None) -> Notifier:
    t = cfg.get("type", "telegram")
    if t == "telegram":
        return TelegramNotifier(
            token=cfg["token"], chat_id=cfg["chat_id"],
            allowed_chats=cfg.get("allowed_chats") or [],
            notify_mode=cfg.get("notify_mode"),
            state_file=state_file,
            journal_file=journal_file,
        )
    raise ValueError(f"Unknown notifier type: {t}")
