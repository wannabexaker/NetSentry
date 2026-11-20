"""The alert journal: every unprompted message (notify) is noted — when, which
kind, how it went, first line only; replies (send / send_to) are not."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from netsentry.core import notify, ui
from netsentry.core.notifier import TelegramNotifier, build_notifier
from netsentry.core.notify import AlertJournal


class _FakeTelegram(TelegramNotifier):
    def __init__(self, tmp_path: Path, mode: str = "normal", *, ok: bool = True,
                 raise_on_send: bool = False) -> None:
        super().__init__("<TOKEN>", "1", allowed_chats=[1], notify_mode=mode,
                         journal_file=tmp_path / "tg-alerts.json")
        self.ok = ok
        self.raise_on_send = raise_on_send
        self.posts: list[dict] = []

    def _post(self, method: str, params: dict, timeout: int = 15) -> dict | None:
        if self.raise_on_send:
            raise RuntimeError("network down")
        self.posts.append(dict(params))
        return {"ok": self.ok, "result": {"message_id": 1}}


def _entries(tg: TelegramNotifier) -> list[tuple[str, str, str]]:
    return [(e["kind"], e["delivery"], e["text"]) for e in tg.journal.recent(50)]


@pytest.mark.parametrize("mode", notify.MODES)
@pytest.mark.parametrize("kind", notify.KINDS)
def test_each_kind_is_recorded_with_how_it_went(tmp_path: Path, kind: str, mode: str) -> None:
    tg = _FakeTelegram(tmp_path, mode)
    assert tg.notify(kind, f"{kind} happened\nsecond line") is True
    expected = notify.delivery(kind, mode) or "not_sent"
    assert _entries(tg) == [(kind, expected, f"{kind} happened")]
    assert len(tg.posts) == (0 if expected == "not_sent" else 1)


def test_a_refused_send_is_failed_and_an_exception_is_failed_and_still_raised(
        tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path, ok=False)
    assert tg.notify(notify.URGENT, "Internet down") is False
    assert _entries(tg) == [("urgent", "failed", "Internet down")]
    tg = _FakeTelegram(tmp_path / "b", raise_on_send=True)
    with pytest.raises(RuntimeError):
        tg.notify(notify.ATTENTION, "Disk almost full")
    assert _entries(tg) == [("attention", "failed", "Disk almost full")]


def test_only_the_first_line_is_kept_without_tags(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    tg.notify(notify.REPORT, ui.lines(ui.b("📶 New guest password & QR"),
                                      ui.concat("Password: ", ui.code("hunter2-secret"))),
              html=True)
    tg.notify(notify.URGENT, "\n\n  🚨 Router <login> failed  \nfrom 192.0.2.7")
    tg.notify(notify.URGENT, "x" * 500)
    entries = _entries(tg)
    assert entries[2][2] == "📶 New guest password & QR"
    assert entries[1][2] == "🚨 Router <login> failed"       # plain text: nothing stripped
    assert len(entries[0][2]) == 200 and entries[0][2].endswith("…")
    stored = (tmp_path / "tg-alerts.json").read_text(encoding="utf-8")
    assert "hunter2-secret" not in stored and "192.0.2.7" not in stored


def test_replies_are_not_recorded(tmp_path: Path) -> None:
    tg = _FakeTelegram(tmp_path)
    tg.send("a reply")
    tg.send_to(1, "another reply")
    tg.send_state("warning", "an old-style message")
    assert tg.journal.recent() == [] and not (tmp_path / "tg-alerts.json").exists()


def test_it_keeps_the_last_200_newest_first_and_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    clock = iter(range(1_000_000, 1_000_300))
    journal = AlertJournal(path, clock=lambda: float(next(clock)))
    for n in range(250):
        journal.record("info", "silent", f"message {n}")
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 200
    again = AlertJournal(path)
    recent = again.recent(200)
    assert len(recent) == 200 and recent[0]["text"] == "message 249"
    assert recent[-1]["text"] == "message 50"
    assert set(recent[0]) == {"ts", "time", "kind", "delivery", "text"}
    assert [e["text"] for e in again.recent(2)] == ["message 249", "message 248"]
    assert again.recent(0) == []


def test_an_unknown_delivery_is_stored_as_failed(tmp_path: Path) -> None:
    journal = AlertJournal()
    journal.record("urgent", "loudly", "x")
    assert journal.recent()[0]["delivery"] == "failed"


def test_many_threads_at_once(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    journal = AlertJournal(path)
    errors: list[BaseException] = []

    def work(n: int) -> None:
        try:
            for i in range(50):
                journal.record("attention", "sound", f"t{n}-{i}")
        except BaseException as e:      # pragma: no cover - the test fails on it
            errors.append(e)
    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(journal.recent(500)) == 200
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 200


def test_a_journal_that_cannot_write_never_costs_the_alert(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    tg = _FakeTelegram(tmp_path)
    tg.journal = AlertJournal(blocker / "alerts.json")       # its parent is a file
    assert tg.notify(notify.URGENT, "Internet down") is True
    assert len(tg.posts) == 1

    class Broken:
        def record(self, *a, **k):
            raise RuntimeError("boom")
    tg.journal = Broken()  # type: ignore[assignment]
    assert tg.notify(notify.URGENT, "Internet down again") is True


def test_a_damaged_journal_file_starts_empty_and_is_kept_aside(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text("{damaged", encoding="utf-8")
    journal = AlertJournal(path)
    assert journal.recent() == []
    journal.record("info", "silent", "fresh")
    assert [e["text"] for e in AlertJournal(path).recent()] == ["fresh"]
    assert (tmp_path / "alerts.json.corrupt").exists()


def test_a_notifier_without_a_file_journals_in_memory_and_build_passes_the_file(
        tmp_path: Path) -> None:
    tg = TelegramNotifier("<TOKEN>", "1")
    assert tg.journal.recent() == []
    built = build_notifier({"type": "telegram", "token": "<TOKEN>", "chat_id": "1"},
                           journal_file=tmp_path / "tg-alerts.json")
    built._post = lambda method, params, timeout=15: {"ok": True}   # type: ignore[method-assign]
    built.notify(notify.URGENT, "Internet down")
    assert json.loads((tmp_path / "tg-alerts.json").read_text(encoding="utf-8"))[0]["kind"] == "urgent"
