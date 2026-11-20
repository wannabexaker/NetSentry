"""
Small, pure helpers for every Telegram message and button NetSentry sends.

They exist so that every plugin speaks the same visual language (see
``docs/UI.md``): one meaning per state emoji, a first line that reads well as a
phone notification, buttons that start with a verb, destructive actions that
take two taps, and no raw exception text in front of the owner.

HTML formatting is opt-in. Text that is sent with ``html=True`` must be built
with :func:`esc` / :func:`b` / :func:`code` / :func:`lines` so that every value
that came from the outside world (device names, domains, log lines can all
contain ``<`` or ``&``) is escaped. Keep each tag on one line: long messages are
split at line breaks and a tag that spans lines could be cut in half.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any, Iterable

# ─── vocabulary ─────────────────────────────────────────────────────

RULE = "━" * 17

# One meaning each — never use one of these for anything else.
ATTACK = "🚨"       # attack or outage
ATTENTION = "⚠️"    # needs you
INFO = "ℹ️"         # FYI
OK = "✅"           # OK / done / back to normal
FAILED = "❌"       # an action failed
WORKING = "⏳"      # working on it
CANCELLED = "✖"    # cancelled / nothing changed
NEW = "🆕"          # a new device

STATE_EMOJI = (ATTACK, ATTENTION, INFO, OK, FAILED, WORKING, CANCELLED, NEW)

NOTHING_CHANGED = f"{CANCELLED} Nothing changed."

TELEGRAM_TEXT_LIMIT = 4096
TELEGRAM_CAPTION_LIMIT = 1024


# ─── message text ───────────────────────────────────────────────────

def header(icon: str, subject: str, verdict: str = "") -> str:
    """Line 1 of a message: ``<icon> <subject> — <verdict>``.

    This is what the phone shows in the notification, so keep it short
    (about 40 characters).
    """
    head = f"{icon} {subject}".strip()
    return f"{head} — {verdict}" if verdict else head


def starts_with_state(text: str) -> bool:
    return text.lstrip().startswith(STATE_EMOJI)


def plural(n: int, word: str, many: str | None = None) -> str:
    """``plural(1, "device")`` → ``1 device``; ``plural(3, "device")`` → ``3 devices``."""
    return f"{n} {word if n == 1 else (many or word + 's')}"


def ago(seconds: float) -> str:
    """How long ago, for anything under a day: ``just now``, ``14 min ago``, ``3 h ago``."""
    s = max(0, int(seconds))
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    return f"{plural(s // 86400, 'day')} ago"


def duration(seconds: float) -> str:
    """A length of time: ``40 s``, ``14 min``, ``2 h 5 min``, ``3 days``."""
    s = max(0, int(seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h} h {m} min" if m else f"{h} h"
    return plural(s // 86400, "day")


_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def fmt_when(when: datetime, now: datetime | None = None) -> str:
    """``Mon 23 Nov 09:00`` — 24-hour, the year only when it isn't this year.

    English names whatever the host's locale (``%a``/``%b`` would follow it).
    """
    now = now or datetime.now()
    day, month = _DAYS[when.weekday()], _MONTHS[when.month - 1]
    year = f" {when.year}" if when.year != now.year else ""
    return f"{day} {when.day} {month}{year} {when:%H:%M}"


def fmt_day(when: datetime, now: datetime | None = None) -> str:
    """``Mon 23 Nov`` (the year only when it isn't this year)."""
    now = now or datetime.now()
    year = f" {when.year}" if when.year != now.year else ""
    return f"{_DAYS[when.weekday()]} {when.day} {_MONTHS[when.month - 1]}{year}"


def parse_when(value: Any) -> datetime | None:
    """A datetime from an ISO string / epoch seconds / datetime, or None."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)) and value > 0:
        try:
            return datetime.fromtimestamp(value)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00")) \
                .replace(tzinfo=None)
        except ValueError:
            return None
    return None


def when_text(value: Any, now: datetime | None = None, *, default: str = "") -> str:
    """How the owner reads a past moment: ``14 min ago`` under a day, else
    ``Mon 23 Nov 09:00``. Future moments are always the date. Accepts what
    :func:`parse_when` accepts; ``default`` for anything unreadable."""
    when = parse_when(value)
    if when is None:
        return default
    now = now or datetime.now()
    age = (now - when).total_seconds()
    if 0 <= age < 86400:
        return ago(age)
    return fmt_when(when, now)


def title(icon: str, subject: str, verdict: str = "") -> str:
    """First line of a screen or report plus the rule under it."""
    return f"{header(icon, subject, verdict)}\n{RULE}"


def item(name: Any, *details: Any) -> str:
    """One list line that leads with the name: ``Kitchen plug — IoT · 192.0.2.8``.

    Empty details are skipped. No column alignment (Telegram's font is
    proportional).
    """
    kept = [str(d) for d in details if d not in (None, "")]
    return f"{name} — {' · '.join(kept)}" if kept else str(name)


def more(shown: int, total: int) -> str:
    """``+N more`` for the part of a list that was not shown ('' when none)."""
    return f"+{total - shown} more" if total > shown else ""


def first_few(values: Iterable[Any], n: int = 3) -> str:
    """``a, b, c +2 more``."""
    values = [str(v) for v in values]
    text = ", ".join(values[:n])
    rest = more(min(n, len(values)), len(values))
    return f"{text} {rest}" if rest else text


def size(n_bytes: float) -> str:
    """``12 MB`` — a space before the unit, binary steps, at most one decimal."""
    value = float(max(0.0, n_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" or value >= 100 \
                else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"   # pragma: no cover


_LOGIN_FAIL = re.compile(r"login failure for user (?P<user>\S+)"
                         r"(?: from (?P<ip>\S+))?(?: via (?P<via>\S+))?")


def login_failure(line: str) -> str:
    """``admin from 192.0.2.5 (ssh) — 12:34:56`` out of a RouterOS log line
    (``<time> <topics> login failure for user …``); the line itself, cut, when
    it doesn't look like that."""
    m = _LOGIN_FAIL.search(line)
    if not m:
        return line.strip()[:80]
    who = m.group("user") + (f" from {m.group('ip')}" if m.group("ip") else "")
    via = f" ({m.group('via')})" if m.group("via") else ""
    when = " ".join(line[:m.start()].split()[:-1])      # drop the topics column
    return f"{who}{via}" + (f" — {when}" if when else "")


def device_label(mac: str, *, name: str | None = None, hostname: str | None = None) -> str:
    """What to call a device: the owner's name for it, else its own name, else its MAC."""
    for candidate in (name, hostname):
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return mac


def device_names(ctx: Any, router: Any, macs: Iterable[str],
                 fallback: dict[str, str] | None = None) -> dict[str, str]:
    """``{MAC: label}`` using the owner's names (lan_scanner), then DHCP hostnames.

    Not pure — it asks the router for its DHCP leases — but it never raises:
    an unreadable router just means MACs are shown.
    """
    namer = next((p for p in _plugins(ctx) if hasattr(p, "tag_for")), None)
    try:
        hostnames = {lease.mac.upper(): lease.hostname for lease in router.dhcp_leases()}
    except Exception:
        hostnames = {}
    out: dict[str, str] = {}
    for mac in macs:
        key = mac.upper()
        try:
            name = namer.tag_for(key) if namer else None
        except Exception:
            name = None
        out[mac] = device_label(key, name=name,
                                hostname=hostnames.get(key) or (fallback or {}).get(mac))
    return out


# ─── buttons ────────────────────────────────────────────────────────

def button(text: str, data: str) -> dict[str, str]:
    """One inline button. ``data`` must stay within Telegram's 64 bytes."""
    if len(data.encode("utf-8")) > 64:
        raise ValueError(f"callback_data longer than 64 bytes: {data!r}")
    return {"text": text, "callback_data": data}


def confirm_rows(emoji: str, verb: str, yes_data: str, cancel_data: str) -> list:
    """The second tap of a destructive action: ``[<emoji> Yes, <verb>] [✖ Cancel]``."""
    return [[button(f"{emoji} Yes, {verb}", yes_data),
             button(f"{CANCELLED} Cancel", cancel_data)]]


def nav_row(back_data: str | None = None, *, home: bool = True) -> list[dict[str, str]]:
    """Last row of a screen: ``[⬅ Back] [🏠 Menu]``."""
    row = []
    if back_data:
        row.append(button("⬅ Back", back_data))
    if home:
        row.append(button("🏠 Menu", "menu:h"))
    return row


def refresh_button(data: str) -> dict[str, str]:
    return button("🔄 Refresh", data)


def url_button(text: str, url: str) -> dict[str, str]:
    """A button that opens ``url`` — instead of printing a link in the text."""
    return {"text": text, "url": url}


def url_row(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    """URL buttons for the pairs whose URL is not empty (``[]`` when none)."""
    return [url_button(text, url) for text, url in pairs if url]


def command_button(text: str, command: str) -> dict[str, str]:
    """A button that runs ``command`` as if typed (through the menu plugin)."""
    return button(text, f"menu:r:{command}")


def _plugins(ctx: Any) -> list:
    try:
        return list(getattr(ctx, "_all_plugins", []) or [])
    except TypeError:          # a test double without a plugin list
        return []


def plugin_named(ctx: Any, name: str) -> Any:
    return next((p for p in _plugins(ctx)
                 if getattr(getattr(p, "ctx", None), "name", "") == name), None)


def command_row(ctx: Any, *pairs: tuple[str, str]) -> list[dict[str, str]]:
    """Buttons for the obvious next step under an alert, e.g.
    ``command_row(ctx, ("🔁 Try again", "/backup"))``.

    Only commands that really exist in this install get a button, and none at
    all when the menu plugin (which runs them) is not loaded — an alert with a
    dead button is worse than one without.
    """
    if plugin_named(ctx, "menu") is None:
        return []
    known = {f"/{c.get('command')}" for p in _plugins(ctx)
             for c in (getattr(p, "COMMANDS", None) or [])}
    return [command_button(text, cmd) for text, cmd in pairs if cmd in known]


def replace_button(keyboard: list | None, data: str,
                   new: dict[str, str]) -> list | None:
    """A copy of ``keyboard`` with the button whose callback_data is ``data``
    replaced by ``new``; None when the keyboard or the button isn't there."""
    if not keyboard:
        return None
    found = False
    out = []
    for row in keyboard:
        new_row = []
        for btn in row:
            if isinstance(btn, dict) and btn.get("callback_data") == data:
                new_row.append(new)
                found = True
            else:
                new_row.append(btn)
        out.append(new_row)
    return out if found else None


def mark_tapped(ctx: Any, notifier: Any, chat_id: int, message_id: int,
                data: str, text: str, done_data: str) -> bool:
    """After a one-shot button worked, turn it into a record (e.g. ``✔ Trusted``)
    while the message's other buttons stay. Needs the bot's view of the
    keyboard; returns False when that isn't available (the caller's toast is
    then all the owner sees)."""
    bot = next((p for p in _plugins(ctx) if hasattr(p, "keyboard_of")), None)
    edit = getattr(notifier, "edit_buttons", None)
    if bot is None or edit is None:
        return False
    try:
        keyboard = replace_button(bot.keyboard_of(chat_id, message_id), data,
                                  button(text, done_data))
        if keyboard is None:
            return False
        edit(chat_id, message_id, keyboard)
        return True
    except Exception:
        return False


def rows(*row_list: list) -> list | None:
    """Drop empty rows; ``None`` when nothing is left (Telegram wants no keyboard)."""
    kept = [r for r in row_list if r]
    return kept or None


# ─── splitting ──────────────────────────────────────────────────────

def tg_len(text: str) -> int:
    """Length as Telegram counts it (UTF-16 code units: an emoji counts as two)."""
    return len(text.encode("utf-16-le")) // 2


def split_message(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> list[str]:
    """Cut ``text`` into parts Telegram accepts, at line breaks where possible.

    A single line longer than the limit is cut inside the line as a last resort.
    Always returns at least one part.
    """
    if tg_len(text) <= limit:
        return [text]
    parts: list[str] = []
    current = ""
    for line in text.split("\n"):
        while tg_len(line) > limit:                  # one huge line: cut it up
            if current:
                parts.append(current)
                current = ""
            cut = fit(line, limit)
            parts.append(line[:cut])
            line = line[cut:]
        candidate = f"{current}\n{line}" if current else line
        if tg_len(candidate) > limit:
            parts.append(current)
            current = line
        else:
            current = candidate
    if current or not parts:
        parts.append(current)
    return [p for p in parts if p.strip()] or [text[:fit(text, limit)]]


def fit(text: str, limit: int) -> int:
    """How many characters of ``text`` fit in ``limit`` UTF-16 units."""
    used = 0
    for i, ch in enumerate(text):
        used += 2 if ord(ch) > 0xFFFF else 1
        if used > limit:
            return max(1, i)
    return len(text)


# ─── HTML (opt-in) ──────────────────────────────────────────────────

class Safe(str):
    """Text that is already valid Telegram HTML and must not be escaped again."""


def esc(value: Any) -> Safe:
    """Escape one inserted value for ``parse_mode=HTML`` (``Safe`` passes through)."""
    if isinstance(value, Safe):
        return value
    return Safe(html.escape(str(value), quote=False))


def b(value: Any) -> Safe:
    return Safe(f"<b>{esc(value)}</b>")


def i(value: Any) -> Safe:
    return Safe(f"<i>{esc(value)}</i>")


def code(value: Any) -> Safe:
    """Monospace; Telegram makes it tap-to-copy."""
    return Safe(f"<code>{esc(value)}</code>")


def lines(*parts: Any) -> Safe:
    """Join parts with newlines, escaping every part that is not already ``Safe``.

    ``lines(b("⚠️ Backup — failed"), f"Device: {name}")`` escapes ``name``.
    ``None`` parts are skipped, so optional lines are easy.
    """
    return Safe("\n".join(esc(p) for p in parts if p is not None))


def concat(*parts: Any) -> Safe:
    """Like :func:`lines` but on one line."""
    return Safe("".join(esc(p) for p in parts if p is not None))


def bold_first_line(text: str) -> Safe:
    """Escape a plain-text message and make its first line bold."""
    first, sep, rest = text.partition("\n")
    return Safe(f"<b>{esc(first)}</b>" + (sep + esc(rest) if sep else "")) if first.strip() \
        else esc(text)


_TAG = re.compile(r"</?(?:b|strong|i|em|u|ins|s|strike|del|code|pre|a|tg-spoiler|"
                  r"span|blockquote)(?:\s[^>]*)?>", re.IGNORECASE)


def strip_html(text: str) -> str:
    """The plain-text version of an HTML message (the fallback when Telegram
    refuses the formatting)."""
    return html.unescape(_TAG.sub("", text))
