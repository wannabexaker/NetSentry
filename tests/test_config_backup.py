"""Router config backup: honest about what was saved, tidy on both sides."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core import notify
from netsentry.core.plugin import PluginContext
from netsentry.core.router import MikroTikRouter
from netsentry.plugins.config_backup import BackupError, ConfigBackupPlugin

DAY = 86400


class _FakeRouter:
    """A router with a file store; the account may or may not make full backups."""

    def __init__(self, *, full_allowed: bool = True) -> None:
        self.files: dict[str, bytes] = {}
        self.full_allowed = full_allowed
        self.export_works = True
        self.copy_works = True
        self.full_attempts = 0

    def export_config(self, name: str) -> bool:
        if self.export_works:
            self.files[f"{name}.rsc"] = b"/interface bridge add name=bridge\n"
        return self.export_works

    def backup_save(self, name: str) -> bool:
        self.full_attempts += 1
        if self.full_allowed:
            self.files[f"{name}.backup"] = b"\x00binary\x00" * 10
        return self.full_allowed

    def files_with_prefix(self, prefix: str) -> list[str]:
        return [n for n in self.files if n.startswith(prefix)]

    def fetch_file(self, remote: str, local: str) -> bool:
        if not self.copy_works or remote not in self.files:
            return False
        Path(local).write_bytes(self.files[remote])
        return True

    def delete_file(self, remote: str) -> bool:
        return self.files.pop(remote, None) is not None


def _plugin(tmp_path: Path, router: _FakeRouter, **config) -> tuple[ConfigBackupPlugin, Path]:
    backups = tmp_path / "backups"
    ctx = PluginContext(
        name="config_backup", config={"backup_dir": str(backups), **config}, router=router,
        notifier=Mock(), vault=Mock(), logger=logging.getLogger("test.config_backup"),
        state_dir=str(tmp_path / "state"))
    plugin = ConfigBackupPlugin(ctx)
    plugin.on_load()
    return plugin, backups


def _said(plugin: ConfigBackupPlugin) -> str:
    """The text of the last thing told to the owner (an alert or a reply)."""
    for name, args, _ in reversed(plugin.notifier.mock_calls):
        if name in ("notify", "send_to"):
            return args[1]
    raise AssertionError("nothing was said")


def _kind(plugin: ConfigBackupPlugin) -> str:
    return plugin.notifier.notify.call_args.args[0]


def _name(days_ago: float, kind: str) -> str:
    made = datetime.now() - timedelta(days=days_ago)
    return f"router-{made:%Y-%m-%d}_0300.{kind}"


def _old(folder: Path, days_ago: float, kind: str, content: bytes = b"x") -> Path:
    """A backup file made ``days_ago`` days ago (the name says so, like real ones)."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / _name(days_ago, kind)
    path.write_bytes(content)
    stamp = time.time() - days_ago * DAY
    os.utime(path, (stamp, stamp))
    return path


def test_both_files_are_saved_and_nothing_is_left_on_the_router(tmp_path: Path) -> None:
    router = _FakeRouter()
    plugin, backups = _plugin(tmp_path, router)

    plugin.do_backup()

    saved = sorted(f.suffix for f in backups.iterdir())
    assert saved == [".backup", ".rsc"]
    assert router.files == {}
    text = _said(plugin)
    assert text.startswith("✅ Router backup — saved") and "Full backup — " in text
    assert plugin.health()[0].ok


def test_a_refused_full_backup_keeps_the_export_and_says_so(tmp_path: Path) -> None:
    router = _FakeRouter(full_allowed=False)
    plugin, backups = _plugin(tmp_path, router)
    last_full = _old(backups, 140, "backup")

    plugin.do_backup()

    assert len(list(backups.glob("*.rsc"))) == 1
    assert router.files == {}                    # the export is not left behind any more
    text = _said(plugin)
    assert text.startswith("✅ Router backup — saved")
    assert "Full backup NOT made: the router refused it" in text
    assert "no passwords" in text
    assert f"Newest full backup here: {last_full.name}" in text
    check = plugin.health()[0]
    assert check.ok and check.detail.endswith("(settings as text only)")


def test_after_a_refusal_the_router_is_not_asked_every_week(tmp_path: Path) -> None:
    router = _FakeRouter(full_allowed=False)
    plugin, _ = _plugin(tmp_path, router)

    plugin.do_backup()
    plugin.do_backup()                           # the next scheduled run
    assert router.full_attempts == 1
    assert "Text export only" in _said(plugin)

    plugin.do_backup(manual=True)                # /backup tries again
    assert router.full_attempts == 2

    router.full_allowed = True                   # the owner granted the permission
    plugin.do_backup(manual=True)
    assert "Full backup — " in _said(plugin)
    plugin.do_backup()                           # …and scheduled runs make it again
    assert router.full_attempts == 4
    assert not plugin.health()[0].detail.endswith("only)")


def test_full_backup_can_be_switched_off(tmp_path: Path) -> None:
    router = _FakeRouter()
    plugin, backups = _plugin(tmp_path, router, binary_backup=False)

    plugin.do_backup()

    assert router.full_attempts == 0 and list(backups.glob("*.backup")) == []
    assert "switched off in the config" in _said(plugin)


def test_leftovers_of_earlier_failed_runs_are_cleared_from_the_router(tmp_path: Path) -> None:
    router = _FakeRouter(full_allowed=False)
    plugin, backups = _plugin(tmp_path, router)
    here = _old(backups, 11, "rsc", b"copied before")
    stranded = _name(180, "backup")
    router.files.update({
        here.name: b"copied before",                          # already here
        stranded: b"never copied",                            # fetched first, then removed
        "router-notes.txt": b"the owner's own file",          # not ours: untouched
        here.name + ".bak": b"not ours either",
    })

    plugin.do_backup()

    assert sorted(router.files) == sorted([here.name + ".bak", "router-notes.txt"])
    assert (backups / stranded).read_bytes() == b"never copied"
    assert "Tidied up: 3 files on the router" in _said(plugin)


def test_a_file_that_cannot_be_copied_stays_on_the_router(tmp_path: Path) -> None:
    router = _FakeRouter(full_allowed=False)
    plugin, backups = _plugin(tmp_path, router)
    plugin.do_backup()                           # a good run first
    stranded = _name(180, "backup")
    router.files[stranded] = b"only copy"
    real_fetch = router.fetch_file
    router.fetch_file = lambda remote, local: (          # type: ignore[method-assign]
        False if remote.endswith(".backup") else real_fetch(remote, local))

    plugin.do_backup()

    assert stranded in router.files
    assert not (backups / stranded).exists()


def test_old_files_go_but_the_newest_of_each_kind_always_stays(tmp_path: Path) -> None:
    router = _FakeRouter()
    plugin, backups = _plugin(tmp_path, router, retention_days=30)
    router.export_works = True
    old_full = _old(backups, 150, "backup")
    old_text = _old(backups, 53, "rsc")
    recent_text = _old(backups, 11, "rsc")

    plugin.do_backup()

    left = {f.name for f in backups.iterdir()}
    assert old_full.name not in left and old_text.name not in left
    assert recent_text.name in left
    assert len([n for n in left if n.endswith(".backup")]) == 1     # today's
    assert "Tidied up: 2 old files here, 2 files on the router" in _said(plugin)


def test_full_backups_are_never_removed_while_no_new_one_can_be_made(tmp_path: Path) -> None:
    router = _FakeRouter(full_allowed=False)
    plugin, backups = _plugin(tmp_path, router, retention_days=30)
    older = _old(backups, 150, "backup")
    last_full = _old(backups, 143, "backup")
    old_text = _old(backups, 53, "rsc")

    plugin.do_backup()

    left = {f.name for f in backups.iterdir()}
    assert {older.name, last_full.name} <= left          # may be the only ones there are
    assert old_text.name not in left                     # text exports still rotate
    assert f"Newest full backup here: {last_full.name}" in _said(plugin)


def test_a_file_fetched_late_is_judged_by_the_date_in_its_name(tmp_path: Path) -> None:
    router = _FakeRouter()
    plugin, backups = _plugin(tmp_path, router, retention_days=30)
    stranded = _name(180, "backup")              # left on the router by an old failed run
    router.files[stranded] = b"very old"
    kept = _old(backups, 20, "backup")

    plugin.do_backup()

    left = {f.name for f in backups.iterdir()}
    assert stranded not in left                  # copied just now, but 180 days old
    assert kept.name in left


@pytest.mark.parametrize("breakage, reason", [
    ("export", "the router did not write the export"),
    ("copy", "the export could not be copied from the router"),
])
def test_a_run_without_an_export_is_a_failure_everyone_hears_about(
        tmp_path: Path, breakage: str, reason: str) -> None:
    router = _FakeRouter()
    plugin, backups = _plugin(tmp_path, router)
    _old(backups, 4, "rsc")                               # health would otherwise look fine
    if breakage == "export":
        router.export_works = False
    else:
        router.copy_works = False

    with pytest.raises(BackupError):                     # so the scheduler records it
        plugin.do_backup()

    text = _said(plugin)
    assert text.startswith("❌ Router backup — NOT made")
    assert reason[1:] in text and "backups made before are still there" in text
    assert _kind(plugin) == notify.ATTENTION
    check = plugin.health()[0]
    assert not check.ok and reason in check.detail
    assert check.notified                                # the watchdog won't alert again

    router.export_works = router.copy_works = True       # the next good run clears it
    plugin.do_backup()
    assert plugin.health()[0].ok


def test_a_good_weekly_backup_is_a_success_message_not_an_alert(tmp_path: Path) -> None:
    plugin, _ = _plugin(tmp_path, _FakeRouter())

    plugin.do_backup()

    assert _kind(plugin) == notify.SUCCESS                # not sent at all in normal mode
    assert "Router backup — saved" in _said(plugin)


def test_manual_backup_reports_failure_without_crashing_its_thread(tmp_path: Path) -> None:
    router = _FakeRouter()
    router.export_works = False
    plugin, _ = _plugin(tmp_path, router)

    plugin._manual_backup(42)

    assert "Router backup — NOT made" in _said(plugin)
    assert plugin.notifier.send_to.call_args.args[0] == 42  # answered where it was asked
    plugin.notifier.notify.assert_not_called()


# ─── the router side ─────────────────────────────────────────────

def _router(answers: list[tuple[int, str]]) -> tuple[MikroTikRouter, list[str]]:
    router = MikroTikRouter("192.0.2.1", "netsentry", "key")
    commands: list[str] = []

    def fake_ssh(command: str, timeout: int = 10) -> tuple[int, str]:
        commands.append(command)
        return answers[len(commands) - 1]

    router._ssh = fake_ssh  # type: ignore[method-assign]
    return router, commands


def test_full_backup_counts_only_when_the_file_exists() -> None:
    # RouterOS answers a refused command with exit status 0.
    refused, commands = _router([(0, "failure: not enough permissions (9)\n"), (0, "BACKUP 0\n")])
    assert refused.backup_save("router-2026-11-22_0300") is False
    assert commands[0] == '/system backup save name="router-2026-11-22_0300" dont-encrypt=yes'
    assert 'name="router-2026-11-22_0300.backup"' in commands[1]

    made, _ = _router([(0, ""), (0, "BACKUP 1\n")])
    assert made.backup_save("router-2026-11-22_0300") is True

    bad_name, commands = _router([])
    assert bad_name.backup_save('x"; /system reset-configuration') is False and commands == []


def test_listing_router_files() -> None:
    router, commands = _router([(0, "FILE router-a.rsc\nFILE router-b.backup\nFILE-END\n")])
    assert router.files_with_prefix("router-") == ["router-a.rsc", "router-b.backup"]
    assert 'name~"^router-"' in commands[0]

    cut_short, _ = _router([(0, "FILE router-a.rsc\n")])
    assert cut_short.files_with_prefix("router-") is None
    refused, commands = _router([])
    assert refused.files_with_prefix('x" or name~"') is None and commands == []
