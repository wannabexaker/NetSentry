"""/maintenance — the plugin side, with the root helper faked by files."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import PluginContext
from netsentry.plugins import maintenance as mod
from netsentry.plugins.maintenance import MaintenancePlugin
from netsentry.plugins.power import PowerPlugin

CHAT = 42


def _ctx(name: str, tmp_path: Path, config: dict) -> PluginContext:
    (tmp_path / "state" / name).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        name=name, config=config, router=Mock(), notifier=Mock(), vault=Mock(),
        logger=logging.getLogger(f"test.{name}"), state_dir=str(tmp_path / "state" / name))


def _plugin(tmp_path: Path, *, installed: bool = True, **config) -> MaintenancePlugin:
    out = tmp_path / "helper"
    if installed:
        out.mkdir(parents=True, exist_ok=True)
    config.setdefault("helper_dir", str(out))
    p = MaintenancePlugin(_ctx("maintenance", tmp_path, config))
    p._start_watch = Mock()  # type: ignore[method-assign]  (no threads in tests)
    p.on_load()
    return p


def _request(tmp_path: Path) -> Path:
    return tmp_path / "state" / "power" / "request"


def _helper(tmp_path: Path, name: str, data: dict) -> None:
    """What the root helper does: consume the request, answer in its folder."""
    _request(tmp_path).unlink(missing_ok=True)
    data = {"started": time.time(), "finished": time.time() + 1, **data}
    (tmp_path / "helper" / name).write_text(json.dumps(data), encoding="utf-8")


def _last_buttons(p: MaintenancePlugin) -> list[dict]:
    call = [m for m in p.notifier.mock_calls if m[0] in ("edit_message", "send_to")][-1]
    return [b for row in (call.kwargs.get("buttons") or []) for b in row]


def _texts(p: MaintenancePlugin) -> list[str]:
    out = []
    for m in p.notifier.mock_calls:
        if m[0] == "edit_message":
            out.append(m.args[2])
        elif m[0] in ("send_to", "notify"):
            out.append(m.args[1])
    return out


_PLAN = {"ok": True, "update_ok": True, "kept_back": [], "hash": "a" * 64, "packages": [
    {"name": "docker-ce", "from": "5:27.1", "to": "5:27.2"},
    {"name": "tailscale", "from": "1.70", "to": "1.72"},
    {"name": "linux-image-6.12.60+rpt-rpi-v8", "from": "", "to": "1:6.12.60"},
]}


# ─── status ──────────────────────────────────────────────────────

def test_status_asks_the_helper_and_renders_its_answer(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:st", CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "status\n"
    assert "Reading" in _texts(p)[-1]
    assert p._check_pending() is False                     # no answer yet

    _helper(tmp_path, "status.json", {
        "pending": _PLAN["packages"][:2], "apt_ok": True,
        "reboot": {"required": True, "packages": ["libc6"], "running_kernel": "6.12.50",
                   "newest_kernel": "6.12.60"},
        "disks": [{"path": "/", "total": 32e9, "free": 12e9},
                  {"path": "/boot/firmware", "total": 5e8, "free": 4e8}],
        "docker": {"ok": True, "images": "3.4GB (60%)", "build_cache": "2.1GB"},
        "eeprom": {"update_available": True, "current": "Apr 2024", "latest": "Oct 2026"},
        "disk_errors": {"count": 2, "last": "mmc0: timeout waiting for hardware interrupt"},
        "autoremove": ["linux-image-6.12.40+rpt-rpi-v8"]})
    assert p._check_pending() is True
    text = _texts(p)[-1]
    assert "2 updates waiting" in text and "docker-ce 5:27.1 → 5:27.2" in text
    assert "Restart needed: yes" in text and "libc6" in text and "newest installed 6.12.60" in text
    assert "build cache 2.1GB" in text and "unused images 3.4GB" in text
    assert "update available" in text
    assert "SD / disk errors this boot: 2 — last: mmc0" in text
    assert "linux-image-6.12.40" in text and "Last action: none yet" in text
    assert not (tmp_path / "state" / "maintenance" / "pending.json").exists()


# ─── upgrade ─────────────────────────────────────────────────────

def test_upgrade_shows_the_plan_with_warnings_and_needs_a_second_tap(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:up", CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "refresh\n"
    _helper(tmp_path, "plan-upgrade.json", _PLAN)
    p._check_pending()
    text = _texts(p)[-1]
    assert "3 packages" in text and "linux-image-6.12.60+rpt-rpi-v8 1:6.12.60 (new)" in text
    assert "containers will restart" in text
    assert "Tailscale drops for a moment" in text
    assert "needs a restart afterwards" in text
    keys = _last_buttons(p)
    assert keys[0]["text"] == "✅ Yes, upgrade these 3"
    assert keys[0]["callback_data"] == "maintenance:up:go:" + "a" * 12
    assert not _request(tmp_path).exists()                  # nothing upgraded yet

    p.on_callback(keys[0]["callback_data"], CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "upgrade\n"


def test_nothing_to_upgrade_needs_no_confirmation(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:up", CHAT, 7, "cb")
    _helper(tmp_path, "plan-upgrade.json", {**_PLAN, "packages": []})
    p._check_pending()
    assert "Nothing to upgrade" in _texts(p)[-1]
    assert not any("Yes" in k["text"] for k in _last_buttons(p))


def test_a_changed_list_is_shown_again_instead_of_upgraded(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _helper(tmp_path, "plan-upgrade.json", {**_PLAN, "hash": "b" * 64})
    p.on_callback("maintenance:up:go:" + "a" * 12, CHAT, 7, "cb")   # the screen showed "aaa…"
    assert not _request(tmp_path).exists()
    assert "The list changed" in _texts(p)[-1]
    assert _last_buttons(p)[0]["callback_data"] == "maintenance:up:go:" + "b" * 12


def test_the_helper_refuses_a_changed_list_and_the_new_one_is_shown(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _helper(tmp_path, "plan-upgrade.json", _PLAN)
    p.on_callback("maintenance:up:go:" + "a" * 12, CHAT, 7, "cb")
    _helper(tmp_path, "plan-upgrade.json", {**_PLAN, "hash": "c" * 64,
                                            "packages": _PLAN["packages"][:1]})
    _helper(tmp_path, "result.json", {"action": "upgrade", "exit": None, "changed": True})
    p._check_pending()
    assert "The list changed" in _texts(p)[-1] and "1 package" in _texts(p)[-1]
    assert _last_buttons(p)[0]["callback_data"] == "maintenance:up:go:" + "c" * 12


def test_the_result_still_arrives_after_netsentry_restarted(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _helper(tmp_path, "plan-upgrade.json", _PLAN)
    p.on_callback("maintenance:up:go:" + "a" * 12, CHAT, 7, "cb")

    again = _plugin(tmp_path)                               # the new process
    again._start_watch.assert_called_once()
    _helper(tmp_path, "result.json", {
        "action": "upgrade", "exit": 0, "upgraded": _PLAN["packages"][:2],
        "reboot": {"required": True, "packages": ["linux-image-rpi-v8"]},
        "services": ["containerd.service", "ssh.service"]})
    assert again._check_pending() is True
    text = again.notifier.send_to.call_args.args[1]
    assert "Upgrade — done" in text and "Upgraded 2" in text
    assert "Restart needed: yes" in text and "ssh.service" in text
    assert again._recent()[0].startswith("Upgrade — ") and "ok: 2 packages" in again._recent()[0]


def test_a_failed_upgrade_says_so_and_shows_in_health(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _helper(tmp_path, "plan-upgrade.json", _PLAN)
    p.on_callback("maintenance:up:go:" + "a" * 12, CHAT, 7, "cb")
    _helper(tmp_path, "result.json", {"action": "upgrade", "exit": 100,
                                      "upgraded": _PLAN["packages"], "reboot": {},
                                      "error": ["E: dpkg was interrupted"], "log": "/x.log"})
    p._check_pending()
    text = p.notifier.send_to.call_args.args[1]
    assert "failed (exit 100)" in text and "dpkg was interrupted" in text
    check = p.health()[0]
    assert not check.ok and check.notified and "exit 100" in check.detail


# ─── refusing ────────────────────────────────────────────────────

def test_nothing_starts_while_the_helper_is_busy(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    (tmp_path / "helper" / "busy.json").write_text(json.dumps(
        {"action": "upgrade", "started": time.time(), "pid": os.getpid()}), encoding="utf-8")
    for data in ("maintenance:st", "maintenance:up", "maintenance:pr:go", "maintenance:ee:go"):
        p.on_callback(data, CHAT, 7, "cb")
        assert not _request(tmp_path).exists()
        assert "The upgrade is running since" in _texts(p)[-1]

    power = PowerPlugin(_ctx("power", tmp_path, {"maintenance_dir": str(tmp_path / "helper")}))
    power._after = Mock()  # type: ignore[method-assign]
    power.on_load()
    assert "NOT restarted" in power.restart("pi", CHAT)
    assert not _request(tmp_path).exists()


def test_a_stale_busy_file_does_not_block(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    (tmp_path / "helper" / "busy.json").write_text(json.dumps(
        {"action": "upgrade", "started": time.time() - 3 * 3600}), encoding="utf-8")
    p.on_callback("maintenance:st", CHAT, 7, "cb")
    assert _request(tmp_path).exists()


def test_one_request_at_a_time(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:st", CHAT, 7, "cb")
    _request(tmp_path).unlink()                             # the helper took it, still working
    p.on_callback("maintenance:ko", CHAT, 7, "cb")
    assert not _request(tmp_path).exists()
    assert "has not finished yet" in _texts(p)[-1]


def test_a_missing_helper_is_admitted(tmp_path: Path) -> None:
    p = _plugin(tmp_path, installed=False)
    p.on_callback("maintenance:st", CHAT, 7, "cb")
    assert not _request(tmp_path).exists()
    assert "isn't installed" in _texts(p)[-1]
    assert not p.health()[0].ok

    q = _plugin(tmp_path, helper_wait_s=0)                  # folder there, nobody listening
    q.on_callback("maintenance:st", CHAT, 7, "cb")
    time.sleep(0.01)
    assert q._check_pending() is True
    assert "isn't installed" in _texts(q)[-1] and not _request(tmp_path).exists()


def test_a_word_the_busy_helper_ignored_is_reported(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:st", CHAT, 7, "cb")
    _helper(tmp_path, "ignored.json", {"action": "status", "busy_with": "upgrade"})
    assert p._check_pending() is True
    assert "Not done" in _texts(p)[-1]


# ─── docker, kernels, bootloader ─────────────────────────────────

def _status(tmp_path: Path, **extra) -> None:
    _helper(tmp_path, "status.json", {"pending": [], "apt_ok": True, "reboot": {},
                                      "disks": [], **extra})


def test_clean_docker_confirms_then_reports_what_it_freed(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:pr", CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "status\n"
    _status(tmp_path, docker={"ok": True, "images": "1.5GB", "build_cache": "900MB"})
    p._check_pending()
    text = _texts(p)[-1]
    assert "build cache 900MB" in text and "Never volumes" in text
    keys = _last_buttons(p)
    assert keys[0] == {"text": "🧹 Yes, clean up", "callback_data": "maintenance:pr:go"}
    assert not _request(tmp_path).exists()

    p.on_callback("maintenance:pr:go", CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "prune\n"
    _helper(tmp_path, "result.json", {"action": "prune", "exit": 0,
                                      "freed_build": "900MB", "freed_images": "1.4GB"})
    p._check_pending()
    assert "Freed: build cache 900MB · unused images 1.4GB" in _texts(p)[-1]


def test_old_kernels_lists_what_else_goes_and_checks_the_hash(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:ko", CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "kernels-plan\n"
    _helper(tmp_path, "plan-kernels.json", {"ok": True, "hash": "d" * 64, "packages": [
        {"name": "linux-image-6.12.40+rpt-rpi-v8", "version": "1:6.12.40"},
        {"name": "linux-headers-6.12.40+rpt-rpi-v8", "version": "1:6.12.40"},
        {"name": "libfoo1", "version": "2.0"}]})
    p._check_pending()
    text = _texts(p)[-1]
    assert "Also removes (not kernels): libfoo1" in text
    keys = _last_buttons(p)
    assert keys[0]["text"] == "🗑 Yes, remove these 3"
    p.on_callback("maintenance:ko:go:" + "e" * 12, CHAT, 7, "cb")     # stale screen
    assert not _request(tmp_path).exists()
    p.on_callback(keys[0]["callback_data"], CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "kernels\n"
    _helper(tmp_path, "result.json", {"action": "kernels", "exit": 0,
                                      "removed": [{"name": "libfoo1"}]})
    p._check_pending()
    assert "Old kernels — done" in _texts(p)[-1]


def test_bootloader_stages_and_never_restarts(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:ee", CHAT, 7, "cb")
    _status(tmp_path, eeprom={"update_available": True, "current": "Apr 2024",
                              "latest": "Oct 2026", "state": "update available"})
    p._check_pending()
    assert "Latest: Oct 2026" in _texts(p)[-1]
    assert _last_buttons(p)[0]["callback_data"] == "maintenance:ee:go"
    p.on_callback("maintenance:ee:go", CHAT, 7, "cb")
    assert _request(tmp_path).read_text(encoding="utf-8") == "eeprom\n"
    _helper(tmp_path, "result.json", {"action": "eeprom", "exit": 0,
                                      "output": ["EEPROM updates pending."]})
    p._check_pending()
    assert "applied on the next restart" in _texts(p)[-1]
    assert not _request(tmp_path).exists()                  # no reboot was chained

    q = _plugin(tmp_path / "other")
    q.on_callback("maintenance:ee", CHAT, 7, "cb")
    (tmp_path / "other" / "state" / "power" / "request").unlink()
    (tmp_path / "other" / "helper" / "status.json").write_text(json.dumps({
        "started": time.time(), "finished": time.time(),
        "eeprom": {"update_available": False}}), encoding="utf-8")
    q._check_pending()
    assert "up to date" in _texts(q)[-1]
    assert not any("Yes" in k["text"] for k in _last_buttons(q))


def test_cancel_changes_nothing(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_callback("maintenance:x", CHAT, 7, "cb")
    assert "Nothing changed" in _texts(p)[-1] and not _request(tmp_path).exists()


# ─── after a restart ─────────────────────────────────────────────

def test_power_asks_for_a_health_report_after_a_pi_restart(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    power = PowerPlugin(_ctx("power", tmp_path, {"maintenance_dir": str(tmp_path / "helper")}))
    power._after = Mock()  # type: ignore[method-assign]
    power.on_load()
    for plugin in (p, power):
        plugin.ctx._all_plugins = [p, power]  # type: ignore[attr-defined]
    assert "restarting" in power.restart("pi", CHAT)
    _request(tmp_path).unlink()                             # the helper rebooted

    power._announce_back()
    assert _request(tmp_path).read_text(encoding="utf-8") == "health\n"
    p.notifier.send_to.assert_not_called()                  # no "working" message for this

    _helper(tmp_path, "health.json", {
        "containers": {"docker": True, "before": ["web", "db"], "running": ["web"],
                       "missing": ["db"], "starting": [], "unhealthy": []},
        "units": {"netsentry.service": "active", "cloudflared.service": "active",
                  "tailscaled.service": "failed"},
        "units_before": ["netsentry.service", "cloudflared.service", "tailscaled.service"],
        "tunnel": {"ok": True, "detail": "4 tunnel connections"},
        "failed_units": ["tailscaled.service"], "dns": {"ok": True}, "waited_s": 240})
    p._check_pending()
    kind, text = p.notifier.notify.call_args.args[:2]
    assert kind == "attention"
    assert "Containers not running: db" in text and "Failed services: tailscaled.service" in text
    assert "✅ DNS answers" in text and "cloudflared — active, 4 tunnel connections" in text
    assert "❌ tailscaled — failed" in text
    assert any("health" in line for line in p._recent())


def test_all_good_after_a_restart_is_a_recovery(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.after_reboot(CHAT)
    _helper(tmp_path, "health.json", {
        "containers": {"docker": True, "before": ["web"], "running": ["web"],
                       "missing": [], "starting": [], "unhealthy": []},
        "units": {"netsentry.service": "active"}, "failed_units": [],
        "dns": {"ok": True}})
    p._check_pending()
    kind, text = p.notifier.notify.call_args.args[:2]
    assert kind == "recovery" and "all good" in text and "1 of 1 running" in text


# ─── the weekly notice ───────────────────────────────────────────

def test_weekly_notice_once_per_set_and_never_for_zero(tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    p = _plugin(tmp_path)
    waiting = ["docker-ce/bookworm 5:27.2 arm64 [upgradable from: 5:27.1]",
               "tzdata/stable 2026b all [upgradable from: 2026a]"]
    monkeypatch.setattr(mod, "_upgradable", lambda: list(waiting))
    p.weekly_notice()
    kind, text = p.notifier.notify.call_args.args[:2]
    assert kind == "info" and "2 updates are waiting" in text and "docker-ce" in text
    button = p.notifier.notify.call_args.kwargs["buttons"][0][0]
    assert button == {"text": "⬆️ Upgrade", "callback_data": "maintenance:up"}

    p.weekly_notice()                                       # same set: quiet
    assert p.notifier.notify.call_count == 1
    waiting.append("curl/stable 8.1 arm64 [upgradable from: 8.0]")
    p.weekly_notice()
    assert p.notifier.notify.call_count == 2

    waiting.clear()
    p.weekly_notice()
    assert p.notifier.notify.call_count == 2
    monkeypatch.setattr(mod, "_upgradable", lambda: None)  # not Debian
    p.weekly_notice()
    assert p.notifier.notify.call_count == 2


def test_the_notice_schedule_can_be_moved_or_switched_off(tmp_path: Path) -> None:
    tasks = _plugin(tmp_path).scheduled_tasks()
    assert [(t.name, t.cron) for t in tasks] == [("weekly", "0 10 * * sat")]
    assert _plugin(tmp_path / "b", notice_cron="").scheduled_tasks() == []


# ─── buttons and history ─────────────────────────────────────────

def test_every_button_fits_telegram(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.ctx._all_plugins = [p, SimpleNamespace(ctx=SimpleNamespace(name="power"))]  # type: ignore[attr-defined]
    p.on_command("/maintenance", "", CHAT)
    for verb, name, data in (
        ("up", "plan-upgrade.json", _PLAN),
        ("ko", "plan-kernels.json", {"ok": True, "hash": "f" * 64,
                                     "packages": [{"name": "linux-image-x", "version": "1"}]}),
        ("pr", "status.json", {"docker": {"images": "1GB"}}),
        ("ee", "status.json", {"eeprom": {"update_available": True}}),
        ("st", "status.json", {}),
    ):
        p.on_callback(f"maintenance:{verb}", CHAT, 7, "cb")
        _helper(tmp_path, name, data)
        p._check_pending()
    keys = [b for m in p.notifier.mock_calls if m[0] in ("edit_message", "send_to")
            for row in (m.kwargs.get("buttons") or []) for b in row]
    assert keys and all(len(k["callback_data"].encode()) <= 64 for k in keys)


def test_home_lists_the_last_five_actions_and_history_is_capped(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    for i in range(205):
        p._history("prune" if i % 2 else "status", f"ok: {i}")
    lines = (tmp_path / "state" / "maintenance" / "history.jsonl").read_bytes().splitlines()
    assert len(lines) == 200 and b"\r" not in b"".join(lines)
    assert json.loads(lines[-1])["result"] == "ok: 204"
    p.on_command("/maintenance", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    assert text.count("Docker clean-up — ") == 5 and "ok: 203" in text
    labels = [k["text"] for k in _last_buttons(p)]
    assert labels[:2] == ["📋 Status", "⬆️ Upgrade"]
    assert "🔄 Restart Pi" not in labels                    # no power plugin loaded
