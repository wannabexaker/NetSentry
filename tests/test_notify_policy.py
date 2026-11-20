"""How NetSentry talks: text alerts (no pictures), message splitting, HTML with a
plain-text safety net, and the three notification modes."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from netsentry.core import notify, ui
from netsentry.core.notifier import TelegramNotifier, build_notifier
from netsentry.core.notify import NotifyPolicy, delivery

# ─── helpers: a Telegram that records instead of sending ────────────


class _FakeTelegram(TelegramNotifier):
    def __init__(self, tmp_path: Path | None = None, mode: str | None = None,
                 refuse_html: bool = False) -> None:
        super().__init__("<TOKEN>", "1", allowed_chats=[1], notify_mode=mode,
                         state_file=(tmp_path / "mode.json") if tmp_path else None)
        self.posts: list[tuple[str, dict]] = []
        self.uploads: list[tuple[str, dict]] = []
        self.refuse_html = refuse_html

    def _answer(self, params: dict) -> dict:
        if self.refuse_html and params.get("parse_mode") == "HTML":
            return {"ok": False, "error_code": 400,
                    "description": "Bad Request: can't parse entities: unclosed tag"}
        return {"ok": True, "result": {"message_id": 1}}

    def _post(self, method: str, params: dict, timeout: int = 15) -> dict | None:
        self.posts.append((method, dict(params)))
        return self._answer(params)

    def _multipart(self, method, fields, file_field, filename, content_type, data,
                   timeout=20):
        self.uploads.append((method, dict(fields)))
        return self._answer(fields)


# ─── the table ──────────────────────────────────────────────────────

@pytest.mark.parametrize("kind, relaxed, normal, everything", [
    (notify.URGENT, "sound", "sound", "sound"),
    (notify.ATTENTION, "silent", "sound", "sound"),
    (notify.RECOVERY, "silent", "silent", "sound"),
    (notify.REPORT, "silent", "silent", "sound"),
    (notify.INFO, None, "silent", "sound"),
    (notify.SUCCESS, None, None, "silent"),
])
def test_each_kind_is_as_loud_as_the_table_says(kind, relaxed, normal, everything) -> None:
    assert delivery(kind, "relaxed") == relaxed
    assert delivery(kind, "normal") == normal
    assert delivery(kind, "everything") == everything


def test_unknown_mode_is_normal_and_unknown_kind_is_delivered() -> None:
    assert delivery(notify.INFO, "loud!!") == "silent"
    assert delivery("something-new", "relaxed") == "silent"     # treated as attention


def test_mode_comes_from_config_until_changed_and_the_change_survives_a_restart(
        tmp_path: Path) -> None:
    state = tmp_path / "mode.json"
    policy = NotifyPolicy("relaxed", state)
    assert policy.mode == "relaxed" and not policy.overridden()

    assert policy.set_mode("everything")
    assert NotifyPolicy("relaxed", state).mode == "everything"   # new process, same file
    assert policy.set_mode("shouty") is False                    # unknown: refused
    assert policy.mode == "everything"


def test_a_damaged_or_invalid_stored_mode_means_normal(tmp_path: Path) -> None:
    state = tmp_path / "mode.json"
    state.write_text(json.dumps({"mode": "deafening"}), encoding="utf-8")
    assert NotifyPolicy(None, state).mode == "normal"
    state.write_text("{not json", encoding="utf-8")
    assert NotifyPolicy("everything", state).mode == "everything"  # unreadable → config
    assert NotifyPolicy("nonsense").mode == "normal"


def test_build_notifier_reads_notify_mode(tmp_path: Path) -> None:
    n = build_notifier({"type": "telegram", "token": "<TOKEN>", "chat_id": "1",
                        "allowed_chats": [1], "notify_mode": "relaxed"},
                       state_file=tmp_path / "m.json")
    assert n.policy.mode == "relaxed"


# ─── notify(): sound, silence or nothing ────────────────────────────

def test_notify_in_normal_mode(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)

    tg.notify(notify.URGENT, "🚨 Internet — down\nNo answer.")
    tg.notify(notify.RECOVERY, "✅ Back to normal: Internet (down 14 min)")
    tg.notify(notify.SUCCESS, "✅ Router backup saved")       # not sent in normal

    assert len(tg.posts) == 2
    urgent, recovery = (p for _, p in tg.posts)
    assert "disable_notification" not in urgent
    assert recovery["disable_notification"] == "true"
    assert urgent["text"].startswith("<b>🚨 Internet — down</b>\n")   # bold first line
    assert urgent["parse_mode"] == "HTML"


def test_relaxed_mode_drops_fyi_and_silences_problems(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path, mode="relaxed")
    assert tg.notify(notify.INFO, "🆕 New device — joined the network") is True
    tg.notify(notify.ATTENTION, "⚠️ Router storage — almost full")
    assert len(tg.posts) == 1
    assert tg.posts[0][1]["disable_notification"] == "true"


def test_replies_are_never_silenced_or_suppressed(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path, mode="relaxed")
    tg.send_to(42, "📶 No device is on the WiFi right now.")
    (_, params), = tg.posts
    assert "disable_notification" not in params and "parse_mode" not in params


def test_values_in_an_alert_are_escaped(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    tg.notify(notify.URGENT, "🚨 Router login — failed\nuser <admin> & co")
    assert "user &lt;admin&gt; &amp; co" in tg.posts[0][1]["text"]


def test_refused_formatting_is_retried_as_plain_text_so_the_alert_is_not_lost(
        tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path, refuse_html=True)

    assert tg.notify(notify.URGENT, "🚨 Internet — down\nping <1.1.1.1>") is True

    assert len(tg.posts) == 2
    retry = tg.posts[1][1]
    assert "parse_mode" not in retry
    assert retry["text"] == "🚨 Internet — down\nping <1.1.1.1>"


def test_edit_message_html_falls_back_to_plain_text(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path, refuse_html=True)
    tg.edit_message(42, 7, "<b>Blocked</b> Kitchen plug.", [], html=True)
    assert [p.get("parse_mode") for _, p in tg.posts] == ["HTML", None]
    assert tg.posts[1][1]["text"] == "Blocked Kitchen plug."


# ─── no pictures; long texts ────────────────────────────────────────

def test_state_tagged_messages_are_text_starting_with_the_state_emoji(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    tg.send_state("warning", "Router storage almost full")
    tg.send_state_to(42, "protected", "✅ Back to normal")
    assert tg.uploads == []                                   # no picture, ever
    assert [p["text"] for _, p in tg.posts] == ["⚠️ Router storage almost full",
                                                "✅ Back to normal"]


def test_a_long_message_is_split_at_lines_with_the_buttons_under_the_last_part(
        tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    text = "\n".join(f"line {n} " + "x" * 90 for n in range(100))   # ~10 000 chars
    buttons = [[{"text": "🔄 Refresh", "callback_data": "x:r"}]]

    assert tg.send_to(42, text, buttons=buttons) is True

    parts = [p for _, p in tg.posts]
    assert len(parts) == 3
    assert all(ui.tg_len(p["text"]) <= 4096 for p in parts)
    assert "\n".join(p["text"] for p in parts) == text           # nothing lost
    assert [("reply_markup" in p) for p in parts] == [False, False, True]


def test_a_photo_caption_over_1024_chars_moves_to_a_following_message(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    photo = tmp_path / "qr.png"
    photo.write_bytes(b"\x89PNG")
    caption = "🔐 New Guest password\n" + "\n".join(f"device {n}" for n in range(200))
    buttons = [[{"text": "🔁 Try again", "callback_data": "x:now"}]]

    assert tg.send_to(42, caption, photo_path=str(photo), buttons=buttons) is True

    (method, fields), = tg.uploads
    assert method == "sendPhoto" and fields["caption"] == "🔐 New Guest password"
    assert "reply_markup" not in fields
    follow = tg.posts[-1][1]
    assert follow["text"].startswith("device 0") and "reply_markup" in follow


def test_a_short_photo_caption_stays_on_the_photo(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    photo = tmp_path / "qr.png"
    photo.write_bytes(b"\x89PNG")
    tg.send_to(42, "<b>🔐 Guest</b>", photo_path=str(photo), html=True)
    assert tg.posts == [] and tg.uploads[0][1]["parse_mode"] == "HTML"


# ─── ui helpers ─────────────────────────────────────────────────────

def test_split_message_handles_short_text_and_one_endless_line() -> None:
    assert ui.split_message("hi") == ["hi"]
    parts = ui.split_message("y" * 9000)
    assert [len(p) for p in parts] == [4096, 4096, 808]
    emoji = ui.split_message("🚨" * 3000)                     # 2 UTF-16 units each
    assert all(ui.tg_len(p) <= 4096 for p in emoji) and "".join(emoji) == "🚨" * 3000


def test_dates_and_durations_read_like_people_write_them() -> None:
    now = datetime(2026, 11, 20, 12, 0)
    assert ui.fmt_when(datetime(2026, 11, 23, 9, 0), now) == "Mon 23 Nov 09:00"
    assert ui.fmt_when(datetime(2025, 3, 2, 18, 5), now) == "Sun 2 Mar 2025 18:05"
    assert ui.ago(30) == "just now" and ui.ago(14 * 60) == "14 min ago"
    assert ui.ago(3 * 3600) == "3 h ago" and ui.ago(2 * 86400) == "2 days ago"
    assert ui.duration(840) == "14 min" and ui.duration(7500) == "2 h 5 min"
    assert ui.plural(1, "device") == "1 device" and ui.plural(3, "device") == "3 devices"


def test_html_builder_escapes_every_inserted_value() -> None:
    text = ui.lines(ui.b("⚠️ Router — <odd>"), f"Device: {'Tom & <Jerry>'}",
                    ui.concat("Password: ", ui.code("a<b")), None)
    assert text == ("<b>⚠️ Router — &lt;odd&gt;</b>\nDevice: Tom &amp; &lt;Jerry&gt;\n"
                    "Password: <code>a&lt;b</code>")
    assert ui.strip_html(text) == ("⚠️ Router — <odd>\nDevice: Tom & <Jerry>\n"
                                   "Password: a<b")


def test_buttons_follow_the_convention() -> None:
    yes, cancel = ui.confirm_rows("🚫", "block", "s:act:yes:AA:BB:CC:DD:EE:FF", "s:c")[0]
    assert yes["text"] == "🚫 Yes, block" and cancel["text"] == "✖ Cancel"
    assert ui.nav_row("x:h") == [{"text": "⬅ Back", "callback_data": "x:h"},
                                 {"text": "🏠 Menu", "callback_data": "menu:h"}]
    with pytest.raises(ValueError):
        ui.button("too long", "x" * 65)


def test_command_buttons_only_for_commands_that_exist_and_only_with_a_menu() -> None:
    from types import SimpleNamespace as NS
    backup = NS(ctx=NS(name="config_backup"), COMMANDS=[{"command": "backup"}])
    without_menu = NS(_all_plugins=[backup])
    assert ui.command_row(without_menu, ("🔁 Try again", "/backup")) == []
    with_menu = NS(_all_plugins=[backup, NS(ctx=NS(name="menu"), COMMANDS=[])])
    assert ui.command_row(with_menu, ("🔁 Try again", "/backup"), ("x", "/nope")) == [
        {"text": "🔁 Try again", "callback_data": "menu:r:/backup"}]
