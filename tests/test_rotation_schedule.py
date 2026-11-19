from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import PluginContext
from netsentry.core.scheduler import Scheduler, _cron_dow_to_names, cron_is_valid, cron_trigger
from netsentry.plugins.guest_wifi_rotator import GuestWifiRotatorPlugin, parse_schedule

JOB = "guest_wifi_rotator.rotate"


# ─── scheduler: standard-cron weekdays ───────────────────────────

def test_dow_numbers_follow_standard_cron_not_apscheduler() -> None:
    assert _cron_dow_to_names("1") == "mon"
    assert _cron_dow_to_names("0") == "sun"
    assert _cron_dow_to_names("7") == "sun"
    assert _cron_dow_to_names("1-5") == "mon,tue,wed,thu,fri"
    assert _cron_dow_to_names("5-7") == "fri,sat,sun"      # wraps past APScheduler's week
    assert _cron_dow_to_names("0,6") == "sun,sat"
    assert _cron_dow_to_names("1-5/2") == "mon,wed,fri"
    assert _cron_dow_to_names("*") == "*"
    assert _cron_dow_to_names("fri") == "fri"


def test_cron_monday_really_fires_on_monday() -> None:
    # "0 9 * * 1" is documented as Mondays 09:00; APScheduler alone reads 1 as Tuesday.
    nxt = cron_trigger("0 9 * * 1").get_next_fire_time(None, datetime(2026, 11, 19, 12, 0))
    assert nxt.strftime("%a %H:%M") == "Mon 09:00"
    sunday = cron_trigger("0 3 * * 0").get_next_fire_time(None, datetime(2026, 11, 19, 12, 0))
    assert sunday.strftime("%a") == "Sun"


def test_cron_is_valid() -> None:
    assert cron_is_valid("30 4 * * 0")
    assert not cron_is_valid("61 9 * * *")
    assert not cron_is_valid("0 9 * *")
    assert not cron_is_valid("0 9 * * 9")


# ─── /rotation argument parsing ──────────────────────────────────

@pytest.mark.parametrize(("text", "cron"), [
    ("daily", "0 9 * * *"),
    ("daily 07:30", "30 7 * * *"),
    ("weekly", "0 9 * * mon"),
    ("weekly fri 18:00", "0 18 * * fri"),
    ("weekly 18:00 friday", "0 18 * * fri"),
    ("monthly", "0 9 1 * *"),
    ("monthly 15 08:30", "30 8 15 * *"),
    ("yearly", "0 9 1 1 *"),
    ("yearly 24-12 20:00", "0 20 24 12 *"),
    ("yearly 24/12", "0 9 24 12 *"),
    ("cron 15 3 * * 2,4", "15 3 * * 2,4"),
    ("never", None),
    ("OFF", None),
])
def test_parse_schedule(text: str, cron: str | None) -> None:
    got, label = parse_schedule(text)
    assert got == cron
    assert label
    assert got is None or cron_is_valid(got)


@pytest.mark.parametrize("text", [
    "", "hourly", "daily mon", "daily 25:00", "weekly funday", "monthly 31",
    "monthly 0", "yearly 31-02", "yearly 29-02", "yearly 0101", "cron 99 * * * *",
    "weekly mon tue", "daily 09:00 10:00",
])
def test_parse_schedule_rejects_nonsense(text: str) -> None:
    with pytest.raises(ValueError):
        parse_schedule(text)


# ─── plugin: live, persistent schedule ───────────────────────────

def _plugin(state_dir: Path, scheduler: object | None = None,
            config: dict | None = None) -> GuestWifiRotatorPlugin:
    ctx = PluginContext(
        name="guest_wifi_rotator",
        config={"ssid": "Guest", "security_profile": "guest-visitor", **(config or {})},
        router=Mock(),
        notifier=Mock(),
        vault=Mock(),
        logger=logging.getLogger("test.rotation"),
        state_dir=str(state_dir),
        scheduler=scheduler,
    )
    plugin = GuestWifiRotatorPlugin(ctx)
    plugin.on_load()
    return plugin


def test_default_schedule_comes_from_config(tmp_path: Path) -> None:
    assert [t.cron for t in _plugin(tmp_path).scheduled_tasks()] == ["0 9 * * 1"]
    custom = _plugin(tmp_path, config={"rotation_cron": "0 6 * * *"})
    assert [t.cron for t in custom.scheduled_tasks()] == ["0 6 * * *"]


def test_set_schedule_rearms_live_job_and_survives_restart(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)

    p.on_command("/rotation", "daily 07:30", 42)

    sched.add_cron.assert_called_once_with("30 7 * * *", p.rotate, name=JOB)
    assert "every day at 07:30" in p.notifier.send_to.call_args.args[1]
    # A new process (same state dir) registers the stored schedule, not config's.
    assert [t.cron for t in _plugin(tmp_path).scheduled_tasks()] == ["30 7 * * *"]


def test_never_unschedules_and_stays_off_after_restart(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)

    p.on_command("/rotation", "never", 42)

    sched.remove.assert_called_once_with(JOB)
    sched.add_cron.assert_not_called()
    assert _plugin(tmp_path).scheduled_tasks() == []
    # Manual rotation still works while automatic rotation is off.
    p.router.set_wifi_passphrase.return_value = True
    p._send_qr = Mock()  # type: ignore[method-assign]
    p.rotate(target_chat=42)
    p._send_qr.assert_called_once()


def test_default_drops_the_override(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)
    p.on_command("/rotation", "never", 42)

    p.on_command("/rotation", "default", 42)

    sched.add_cron.assert_called_once_with("0 9 * * 1", p.rotate, name=JOB)
    assert [t.cron for t in _plugin(tmp_path).scheduled_tasks()] == ["0 9 * * 1"]


def test_bad_arguments_change_nothing_and_explain(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)

    p.on_command("/rotation", "monthly 31", 42)

    sched.add_cron.assert_not_called()
    sched.remove.assert_not_called()
    error, menu = (c.args[1] for c in p.notifier.send_to.call_args_list)
    assert "1-28" in error and "Usage" in error
    assert "nothing to type" in menu                  # the buttons are offered instead
    assert [t.cron for t in p.scheduled_tasks()] == ["0 9 * * 1"]


def test_corrupt_schedule_file_falls_back_to_config(tmp_path: Path) -> None:
    (tmp_path / "schedule.json").write_text("{not json", encoding="utf-8")
    assert [t.cron for t in _plugin(tmp_path).scheduled_tasks()] == ["0 9 * * 1"]
    (tmp_path / "schedule.json").write_text('{"cron": "99 99 * * *"}', encoding="utf-8")
    assert [t.cron for t in _plugin(tmp_path).scheduled_tasks()] == ["0 9 * * 1"]


def test_preset_button_applies_immediately_and_refreshes_message(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)

    p.on_callback("guest_wifi_rotator:set:monthly", 42, 7, "cb1")

    sched.add_cron.assert_called_once_with("0 9 1 * *", p.rotate, name=JOB)
    p.notifier.answer_callback.assert_called_once_with("cb1", "Saved ✅")
    assert p.notifier.edit_message.call_args.args[:2] == (42, 7)
    assert "every month on day 1" in p.notifier.edit_message.call_args.args[2]


def test_rotate_now_needs_a_second_tap(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    p.rotate = Mock()  # type: ignore[method-assign]

    p.on_command("/rotation", "now", 42)
    p.on_callback("guest_wifi_rotator:now", 42, 7, "cb1")
    p.rotate.assert_not_called()                      # only asked, twice
    buttons = p.notifier.send_to.call_args.kwargs["buttons"]
    assert buttons[0][0]["callback_data"] == "guest_wifi_rotator:now!"

    p.on_callback("guest_wifi_rotator:now!", 42, 8, "cb2")
    p.rotate.assert_called_once_with(target_chat=42)


def test_unknown_callback_is_ignored(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)
    p.on_callback("guest_wifi_rotator:set:hourly", 42, 7, "cb1")
    p.on_callback("guest_wifi_rotator:bogus", 42, 7, "cb2")
    sched.add_cron.assert_not_called()
    sched.remove.assert_not_called()


def test_real_scheduler_reschedules_and_reports_next_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Scheduler() adopts the OS timezone name, which Windows spells in a way
    # zoneinfo can't resolve; pin it so the test is about scheduling only.
    monkeypatch.setattr("time.tzname", ("UTC", "UTC"))
    sched = Scheduler()
    sched.start()
    try:
        p = _plugin(tmp_path, sched)
        for task in p.scheduled_tasks():
            sched.add_cron(task.cron, task.func, name=JOB)
        assert sched.next_run(JOB).strftime("%a %H:%M") == "Mon 09:00"

        p.on_command("/rotation", "weekly fri 18:00", 42)
        assert sched.next_run(JOB).strftime("%a %H:%M") == "Fri 18:00"
        assert "Next: Fri" in p.notifier.send_to.call_args.args[1]

        p.on_command("/rotation", "never", 42)
        assert sched.next_run(JOB) is None
        assert "none scheduled" in p.notifier.send_to.call_args.args[1]
        assert sched.remove(JOB) is False             # already gone

        p.on_command("/rotation", "daily", 42)        # and back on, live
        assert sched.next_run(JOB) is not None
    finally:
        sched.shutdown()


# ─── button-only flow: nothing to remember or type ───────────────

def _tap(p: GuestWifiRotatorPlugin, label: str) -> None:
    """Press the button with this label on the menu message as last drawn."""
    last = p.notifier.edit_message.call_args or p.notifier.send_to.call_args
    for row in last.kwargs["buttons"]:
        for key in row:
            if key["text"] == label:
                p.on_callback(key["callback_data"], 42, 7, "cb")
                return
    raise AssertionError(f"no button {label!r} on screen")


@pytest.mark.parametrize(("taps", "cron", "label"), [
    (["Every day", "07", "07:30"], "30 7 * * *", "every day at 07:30"),
    (["Every week", "Fri", "18", "18:00"], "0 18 * * fri", "every week on Fri at 18:00"),
    (["Every month", "15", "08", "08:45"], "45 8 15 * *", "every month on day 15 at 08:45"),
    (["Once a year", "Dec", "24", "20", "20:15"], "15 20 24 12 *",
     "once a year on 24 Dec at 20:15"),
])
def test_schedule_can_be_set_with_buttons_only(
    tmp_path: Path, taps: list[str], cron: str, label: str,
) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)
    p.on_command("/rotation", "", 42)

    for step in taps:
        sched.add_cron.assert_not_called()            # nothing applies until the last tap
        _tap(p, step)

    sched.add_cron.assert_called_once_with(cron, p.rotate, name=JOB)
    assert label in p.notifier.edit_message.call_args.args[2]


def test_back_returns_to_menu_without_changing_anything(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)
    p.on_command("/rotation", "", 42)

    _tap(p, "Every week")
    _tap(p, "⬅ Back")

    assert "Schedule:" in p.notifier.edit_message.call_args.args[2]
    sched.add_cron.assert_not_called()


def test_never_and_config_default_buttons(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)
    p.on_command("/rotation", "", 42)

    _tap(p, "⛔ Never")
    sched.remove.assert_called_once_with(JOB)
    _tap(p, "↩ Config default")
    sched.add_cron.assert_called_once_with("0 9 * * 1", p.rotate, name=JOB)


def test_every_picker_button_is_valid_for_telegram(tmp_path: Path) -> None:
    # Telegram rejects callback_data over 64 bytes; and only real dates are offered.
    p = _plugin(tmp_path, Mock())
    presses = [("pick", ["weekly"]), ("pick", ["monthly"]), ("pick", ["yearly"]),
               *[("mo", [str(month)]) for month in range(1, 13)],
               ("d", ["yearly", "31-12"]), ("t", ["yearly", "31-12", "23"])]
    screens = [p._picker.step(verb, args).rows for verb, args in presses]

    keys = [key for screen in screens for row in screen for key in row]
    assert all(len(key["callback_data"].encode()) <= 64 for key in keys)
    feb = [k["text"] for row in screens[4] for k in row if k["text"].isdigit()]
    assert feb[-1] == "28"                              # no 29 Feb
    april = [k["text"] for row in screens[6] for k in row if k["text"].isdigit()]
    assert april[-1] == "30"


def test_forged_final_step_is_rejected(tmp_path: Path) -> None:
    sched = Mock()
    p = _plugin(tmp_path, sched)
    p.on_callback("guest_wifi_rotator:ok:monthly:31:09:00", 42, 7, "cb")
    p.on_callback("guest_wifi_rotator:ok:weekly:funday:09:00", 42, 7, "cb")
    p.on_callback("guest_wifi_rotator:ok:daily:-:25:00", 42, 7, "cb")
    sched.add_cron.assert_not_called()
    assert _plugin(tmp_path).scheduled_tasks()[0].cron == "0 9 * * 1"


def test_successful_rotation_is_remembered_for_status(tmp_path: Path) -> None:
    p = _plugin(tmp_path, Mock())
    p.router.set_wifi_passphrase.return_value = True
    p._send_qr = Mock()  # type: ignore[method-assign]

    p.rotate()
    p.on_command("/rotation", "", 42)

    assert "Last: not recorded yet" not in p.notifier.send_to.call_args.args[1]
