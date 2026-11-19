from __future__ import annotations

import json
import logging
import os
import stat
import sys
import tarfile
import time
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import PluginContext
from netsentry.core.scheduler import Scheduler
from netsentry.core.schedules import SchedulePicker, Screen, humanize_cron, parse_schedule
from netsentry.plugins.config_backup import ConfigBackupPlugin
from netsentry.plugins.power import PowerPlugin
from netsentry.plugins.self_backup import SelfBackupPlugin
from netsentry.plugins.self_check import SelfCheckPlugin
from netsentry.plugins.settings import SettingsPlugin


def _ctx(name: str, tmp_path: Path, **kw) -> PluginContext:
    (tmp_path / "state" / name).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        name=name, config=kw.pop("config", {}), router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger(f"test.{name}"),
        state_dir=str(tmp_path / "state" / name), **kw)


@pytest.fixture()
def sched(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("time.tzname", ("UTC", "UTC"))
    s = Scheduler()
    s.start()
    yield s
    s.shutdown()


def _buttons(call) -> list[dict]:
    return [k for row in call.kwargs["buttons"] for k in row]


# ─── words for schedules ─────────────────────────────────────────

@pytest.mark.parametrize(("cron", "words"), [
    ("0 3 * * 0", "every week on Sun at 03:00"),
    ("30 4 * * 0", "every week on Sun at 04:30"),
    ("0 9 * * mon", "every week on Mon at 09:00"),
    ("0 21 * * *", "every day at 21:00"),
    ("15 8 15 * *", "every month on day 15 at 08:15"),
    ("0 20 24 12 *", "once a year on 24 Dec at 20:00"),
    ("*/10 * * * *", "cron */10 * * * *"),
])
def test_cron_in_plain_words(cron: str, words: str) -> None:
    assert humanize_cron(cron) == words


def test_picker_walks_to_a_choice_the_parser_accepts() -> None:
    picker = SchedulePicker("x:bk", back="x:j:bk", modes=("daily", "weekly", "monthly"))
    assert [k["text"] for row in picker.frequency_rows() for k in row] == \
        ["Every day", "Every week", "Every month"]
    assert picker.step("pick", ["yearly"]) is None            # not offered here
    days = picker.step("pick", ["weekly"])
    assert isinstance(days, Screen) and days.rows[-1][0]["callback_data"] == "x:j:bk"
    assert isinstance(picker.step("d", ["weekly", "sat"]), Screen)
    assert isinstance(picker.step("t", ["weekly", "sat", "04"]), Screen)
    choice = picker.step("ok", ["weekly", "sat", "04", "15"])
    assert parse_schedule(choice)[0] == "15 4 * * sat"
    assert picker.step("bogus", []) is None


# ─── scheduler: owner overrides ──────────────────────────────────

def test_override_moves_a_job_live_and_survives_a_restart(
    tmp_path: Path, sched: Scheduler, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = tmp_path / "overrides.json"
    sched.load_overrides(store)
    sched.add_cron("0 3 * * 0", lambda: None, name="config_backup.weekly")
    assert sched.next_run("config_backup.weekly").strftime("%a %H:%M") == "Sun 03:00"

    assert sched.set_schedule("config_backup.weekly", "30 2 * * wed") is True
    assert sched.next_run("config_backup.weekly").strftime("%a %H:%M") == "Wed 02:30"
    info = sched.schedule_of("config_backup.weekly")
    assert info["overridden"] and info["default"] == "0 3 * * 0"

    again = Scheduler()                                        # "restart"
    again.load_overrides(store)
    again.start()
    try:
        again.add_cron("0 3 * * 0", lambda: None, name="config_backup.weekly")
        assert again.next_run("config_backup.weekly").strftime("%a %H:%M") == "Wed 02:30"
        assert again.clear_schedule("config_backup.weekly") is True
        assert again.next_run("config_backup.weekly").strftime("%a %H:%M") == "Sun 03:00"
        assert json.loads(store.read_text(encoding="utf-8")) == {}
    finally:
        again.shutdown()


def test_pause_and_bad_input(tmp_path: Path, sched: Scheduler) -> None:
    sched.load_overrides(tmp_path / "o.json")
    sched.add_cron("0 21 * * *", lambda: None, name="traffic_report.daily")

    assert sched.set_schedule("traffic_report.daily", None) is True
    assert sched.next_run("traffic_report.daily") is None
    assert sched.schedule_of("traffic_report.daily")["paused"] is True
    assert sched.interval_seconds("traffic_report.daily") is None

    assert sched.set_schedule("traffic_report.daily", "not a cron") is False
    assert sched.set_schedule("no.such.job", "0 1 * * *") is False
    assert sched.schedule_of("no.such.job") is None
    sched.clear_schedule("traffic_report.daily")
    assert sched.interval_seconds("traffic_report.daily") == 86400


def test_corrupt_or_tampered_overrides_fall_back_to_defaults(
    tmp_path: Path, sched: Scheduler,
) -> None:
    store = tmp_path / "o.json"
    store.write_text('{"a.job": "99 99 * * *", "b.job": 5, "c.job": "0 6 * * *"}',
                     encoding="utf-8")
    sched.load_overrides(store)
    for name in ("a.job", "b.job", "c.job"):
        sched.add_cron("0 1 * * *", lambda: None, name=name)
    assert sched.next_run("a.job").hour == 1 and sched.next_run("b.job").hour == 1
    assert sched.next_run("c.job").hour == 6                  # the valid one is honoured


# ─── /settings ───────────────────────────────────────────────────

def _settings(tmp_path: Path, sched: Scheduler) -> SettingsPlugin:
    sched.load_overrides(tmp_path / "overrides.json")
    sched.add_cron("0 3 * * 0", lambda: None, name="config_backup.weekly")
    sched.add_cron("0 8 * * *", lambda: None, name="morning_briefing.daily")
    sched.add_cron("*/10 * * * *", lambda: None, name="threat_detector.scan")
    p = SettingsPlugin(_ctx("settings", tmp_path, scheduler=sched))
    p.on_load()
    return p


def _tap(p, label: str) -> None:
    call = p.notifier.edit_message.call_args or p.notifier.send_to.call_args
    key = next(k for k in _buttons(call) if label in k["text"])
    p.on_callback(key["callback_data"], 42, 7, "cb")


def test_settings_lists_movable_jobs_only(tmp_path: Path, sched: Scheduler) -> None:
    p = _settings(tmp_path, sched)
    p.on_command("/settings", "", 42)

    text = p.notifier.send_to.call_args.args[1]
    assert "Router config backup" in text and "every week on Sun at 03:00" in text
    assert "Morning briefing" in text and "every day at 08:00" in text
    assert "threat_detector.scan" not in text                 # internal heartbeat
    assert "Traffic report" not in text                       # not installed here
    labels = [k["text"] for k in _buttons(p.notifier.send_to.call_args)]
    assert any("Guest password rotation" in t for t in labels)


def test_changing_a_time_with_buttons_only(tmp_path: Path, sched: Scheduler) -> None:
    p = _settings(tmp_path, sched)
    p.on_command("/settings", "", 42)

    for label in ("Router config backup", "Every week", "Wed", "02", "02:30"):
        _tap(p, label)

    assert sched.next_run("config_backup.weekly").strftime("%a %H:%M") == "Wed 02:30"
    shown = p.notifier.edit_message.call_args.args[2]
    assert "every week on Wed at 02:30" in shown and "Default: every week on Sun at 03:00" in shown

    _tap(p, "Default")
    assert sched.next_run("config_backup.weekly").strftime("%a %H:%M") == "Sun 03:00"


def test_pause_and_resume_a_job(tmp_path: Path, sched: Scheduler) -> None:
    p = _settings(tmp_path, sched)
    p.on_command("/settings", "", 42)
    _tap(p, "Morning briefing")
    _tap(p, "Pause")
    assert sched.next_run("morning_briefing.daily") is None
    assert "paused" in p.notifier.edit_message.call_args.args[2]
    _tap(p, "Resume")
    assert sched.next_run("morning_briefing.daily") is not None


def test_settings_ignores_forged_callbacks(tmp_path: Path, sched: Scheduler) -> None:
    p = _settings(tmp_path, sched)
    before = sched.next_run("config_backup.weekly")
    p.on_callback("settings:bk:ok:monthly:31:09:00", 42, 7, "cb")      # no 31st every month
    p.on_callback("settings:zz:pause", 42, 7, "cb")                    # unknown job
    p.on_callback("settings:bk:ok:weekly:funday:09:00", 42, 7, "cb")
    assert sched.next_run("config_backup.weekly") == before
    assert sched.next_run("threat_detector.scan") is not None


def test_backup_health_follows_the_schedule_you_chose(tmp_path: Path, sched: Scheduler) -> None:
    sched.load_overrides(tmp_path / "o.json")
    bk = ConfigBackupPlugin(_ctx("config_backup", tmp_path, scheduler=sched,
                                 config={"backup_dir": str(tmp_path / "bk")}))
    bk.on_load()
    sched.add_cron("0 3 * * 0", bk.do_backup, name="config_backup.weekly")
    (tmp_path / "bk").mkdir()
    f = tmp_path / "bk" / "router-x.rsc"
    f.write_text("x", encoding="utf-8")
    old = time.time() - 20 * 86400
    os.utime(f, (old, old))

    assert bk.health()[0].ok is False                         # weekly, 20 days old
    sched.set_schedule("config_backup.weekly", "0 3 1 * *")
    assert bk.health()[0].ok is True                          # monthly: 20 days is fine
    sched.set_schedule("config_backup.weekly", None)
    assert bk.health()[0].ok is True and "paused" in bk.health()[0].detail


# ─── /restart ────────────────────────────────────────────────────

def _power(tmp_path: Path, **config) -> PowerPlugin:
    p = PowerPlugin(_ctx("power", tmp_path, config=config))
    p._after = Mock()  # type: ignore[method-assign]  (no real timers in tests)
    p.on_load()
    return p


def test_nothing_restarts_without_confirmation(tmp_path: Path) -> None:
    p = _power(tmp_path)
    p.on_command("/restart", "", 42)
    labels = [k["text"] for k in _buttons(p.notifier.send_to.call_args)]
    assert len(labels) == 3 and any("Router" in t for t in labels)

    p.on_callback("power:ask:router", 42, 7, "cb")
    p.router.reboot.assert_not_called()
    assert "Restart 📡 Router?" in p.notifier.edit_message.call_args.args[2]

    p.on_callback("power:cancel", 42, 7, "cb")
    p.router.reboot.assert_not_called()

    p.on_callback("power:do:router", 42, 7, "cb")
    p.router.reboot.assert_called_once()
    p.on_callback("power:do:toaster", 42, 7, "cb")            # unknown target → menu
    p.router.reboot.assert_called_once()


def test_restarting_netsentry_exits_cleanly_and_reports_back(tmp_path: Path) -> None:
    p = _power(tmp_path)
    text = p.restart("service", 42)
    assert "restarting" in text
    delay, func = p._after.call_args.args[:2]
    assert func == p._exit_for_restart and delay > 0
    pending = json.loads((tmp_path / "state" / "power" / "pending.json").read_text("utf-8"))
    assert pending["target"] == "service" and pending["chat_id"] == 42

    after = _power(tmp_path)                                  # the new process
    assert after._after.call_args.args[1] == after._announce_back
    after._announce_back()
    assert "NetSentry is back" in after.notifier.send_to.call_args.args[1]
    assert not (tmp_path / "state" / "power" / "pending.json").exists()
    after._announce_back()                                    # only announced once
    assert after.notifier.send_to.call_count == 1


def test_pi_reboot_goes_through_the_helper_and_admits_when_it_is_missing(tmp_path: Path) -> None:
    p = _power(tmp_path, helper_wait_s=5)
    request = tmp_path / "state" / "power" / "request"

    assert "Rebooting" in p.restart("pi", 42)
    assert request.read_text(encoding="utf-8") == "reboot\n"
    delay, func, chat = p._after.call_args.args
    assert (delay, func, chat) == (5.0, p._helper_did_not_act, 42)

    p._helper_did_not_act(42)                                 # nobody consumed the request
    assert not request.exists()
    assert "helper isn't installed" in p.notifier.send_to.call_args.args[1]
    assert not (tmp_path / "state" / "power" / "pending.json").exists()


def test_stale_reboot_request_never_fires_on_startup(tmp_path: Path) -> None:
    (tmp_path / "state" / "power").mkdir(parents=True)
    (tmp_path / "state" / "power" / "request").write_text("reboot\n", encoding="utf-8")
    _power(tmp_path)
    assert not (tmp_path / "state" / "power" / "request").exists()


def test_router_restart_failure_is_reported(tmp_path: Path) -> None:
    p = _power(tmp_path)
    p.router.reboot.side_effect = RuntimeError("ssh down")
    assert "Could not tell the router" in p.restart("router", 42)


# ─── self-backup ─────────────────────────────────────────────────

def _backup(tmp_path: Path, **config) -> SelfBackupPlugin:
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.yaml").write_text("plugins: []\n", encoding="utf-8")
    (cfg_dir / "secrets.key").write_text("k", encoding="utf-8")
    state = tmp_path / "state"
    (state / "threat_detector").mkdir(parents=True, exist_ok=True)
    (state / "threat_detector" / "state.json").write_text('{"allowed_domains": []}', "utf-8")
    (state / "threat_detector" / "threat_feeds.json").write_text("x" * 5000, "utf-8")
    (state / "netsentry.log").write_text("noise", encoding="utf-8")
    (state / "github_explorer" / "repos" / "big").mkdir(parents=True, exist_ok=True)
    (state / "github_explorer" / "repos" / "big" / "blob").write_text("x", "utf-8")
    p = SelfBackupPlugin(_ctx("self_backup", tmp_path, config={
        "backup_dir": str(tmp_path / "out"), "config_dir": str(cfg_dir),
        "first_backup_delay_s": 99999, **config}))
    p.on_load()
    return p


def test_backup_contains_settings_and_state_but_not_the_bulk(tmp_path: Path) -> None:
    p = _backup(tmp_path)
    path, files, size = p.backup()

    with tarfile.open(path) as tar:
        names = set(tar.getnames())
    assert {"config/config.yaml", "config/secrets.key",
            "state/threat_detector/state.json"} <= names
    assert not any("threat_feeds" in n or n.endswith(".log") or "repos" in n for n in names)
    assert files == len(names) and size > 0
    if sys.platform != "win32":                               # it holds the vault key
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_backup_keeps_only_the_newest_and_never_backs_up_itself(tmp_path: Path) -> None:
    p = _backup(tmp_path, keep=2, backup_dir=str(tmp_path / "state" / "self_backup" / "out"))
    made = []
    for i in range(4):
        path, _, _ = p.backup()
        os.utime(path, (1_700_000_000 + i, 1_700_000_000 + i))
        made.append(path)
    left = sorted(f.name for f in p._dir.glob("netsentry-*.tar.gz"))
    assert len(left) == 2
    with tarfile.open(p._dir / left[-1]) as tar:
        assert not any(n.endswith(".tar.gz") for n in tar.getnames())


def test_snapshot_command_and_health(tmp_path: Path) -> None:
    p = _backup(tmp_path)
    assert p.health()[0].ok is False and "/snapshot" in p.health()[0].detail

    p.on_command("/snapshot", "", 42)
    assert "backed up" in p.notifier.send_to.call_args.args[1]
    assert p.health()[0].ok is True


def test_failed_scheduled_backup_is_loud(tmp_path: Path) -> None:
    p = _backup(tmp_path)
    p.backup = Mock(side_effect=OSError("disk full"))  # type: ignore[method-assign]
    with pytest.raises(OSError):                              # so the scheduler records it
        p.scheduled_backup()
    assert "disk full" in p.notifier.send_state.call_args.args[1]


# ─── OS updates in /health ───────────────────────────────────────

APT = """Listing...
openssl/stable-security 3.0.17-1~deb12u3 arm64 [upgradable from: 3.0.17-1~deb12u2]
vim/stable 2:9.0.1378-2+deb12u2 arm64 [upgradable from: 2:9.0.1378-2]
"""


def _checker(tmp_path: Path, apt_output: str | None) -> SelfCheckPlugin:
    p = SelfCheckPlugin(_ctx("self_check", tmp_path))
    p.on_load()
    return p


def test_pending_security_updates_are_flagged(tmp_path: Path, monkeypatch) -> None:
    import netsentry.plugins.self_check as mod
    p = _checker(tmp_path, APT)
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/apt")
    monkeypatch.setattr(mod.os.path, "exists", lambda path: False)
    runs = []

    def fake_run(*a, **k):
        runs.append(a)
        return types.SimpleNamespace(stdout=APT, returncode=0)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)

    check = p._updates_check()
    assert check.ok is False and "1 security update" in check.detail
    p._updates_check()
    assert len(runs) == 1                                     # cached, apt not asked again

    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        stdout="Listing...\nvim/stable 2 arm64 [upgradable from: 1]\n", returncode=0))
    p._updates_cache = (0.0, None)
    assert p._updates_check().ok is True


def test_no_apt_means_no_update_check(tmp_path: Path, monkeypatch) -> None:
    import netsentry.plugins.self_check as mod
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    assert _checker(tmp_path, None)._updates_check() is None
