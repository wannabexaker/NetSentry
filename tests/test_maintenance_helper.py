"""The root maintenance helper (deploy/netsentry-maintenance-helper.sh), run for
real against fake apt-get / docker / systemctl / rpi-eeprom-update. Linux only:
it needs sh, flock semantics and the coreutils the Pi has."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell helper")

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "netsentry-maintenance-helper.sh"

_SIM_UPGRADE = """\
Reading package lists...
The following packages have been kept back:
  held-pkg
The following packages will be upgraded:
  docker-ce tzdata
Inst docker-ce [5:27.1] (5:27.2 Docker:stable [arm64])
Inst tzdata [2026a] (2026b Debian:stable [all])
Conf docker-ce (5:27.2 Docker:stable [arm64])
"""
_SIM_AUTOREMOVE = """\
Purg linux-image-6.12.40+rpt-rpi-v8 [1:6.12.40]
Purg libfoo1 [2.0]
"""

_FAKES = {
    "apt-get": """#!/bin/sh
echo "apt-get $*" >> "$FAKE_CALLS"
case "$*" in
  "-s upgrade --with-new-pkgs") cat "$FAKE_DIR/sim-upgrade" ;;
  "-s autoremove --purge") cat "$FAKE_DIR/sim-autoremove" ;;
esac
exit 0
""",
    "docker": """#!/bin/sh
echo "docker $*" >> "$FAKE_CALLS"
case "$1 $2" in
  "ps --format") printf 'web\\tUp 2 hours (healthy)\\n' ;;
  "builder prune") printf 'Total:\\t1.2GB\\n' ;;
  "image prune") printf 'Total reclaimed space: 800MB\\n' ;;
esac
exit 0
""",
    "systemctl": """#!/bin/sh
echo "systemctl $*" >> "$FAKE_CALLS"
if [ "$1" = show ]; then
  printf 'Id=netsentry.service\\nLoadState=loaded\\nActiveState=active\\n\\n'
  printf 'Id=docker.service\\nLoadState=loaded\\nActiveState=active\\n\\n'
  printf 'Id=hidwayd.service\\nLoadState=not-found\\nActiveState=inactive\\n'
fi
exit 0
""",
    "rpi-eeprom-update": """#!/bin/sh
echo "rpi-eeprom-update $*" >> "$FAKE_CALLS"
printf 'BOOTLOADER: update available\\n   CURRENT: Thu 18 Apr 2024\\n    LATEST: Mon 12 Oct 2026\\n'
""",
    "journalctl": """#!/bin/sh
printf 'mmc0: timeout waiting for hardware interrupt\\nusb 1-1: new device\\n'
""",
}


@pytest.fixture()
def helper(tmp_path: Path):
    fake = tmp_path / "bin"
    fake.mkdir()
    for name, body in _FAKES.items():
        path = fake / name
        # The helper passes a minimal environment, so the fakes get their paths baked in.
        body = (body.replace("$FAKE_CALLS", str(tmp_path / "calls"))
                .replace("$FAKE_DIR", str(tmp_path)))
        path.write_bytes(body.encode())
        path.chmod(0o755)
    (tmp_path / "sim-upgrade").write_text(_SIM_UPGRADE)
    (tmp_path / "sim-autoremove").write_text(_SIM_AUTOREMOVE)
    out, logs = tmp_path / "out", tmp_path / "log"
    request = tmp_path / "home" / "request"
    request.parent.mkdir()
    calls = tmp_path / "calls"
    calls.write_text("")
    env = {"PATH": f"{fake}:/usr/bin:/bin", "NS_MAINT_OUT": str(out),
           "NS_MAINT_LOG": str(logs), "NS_MAINT_LOCK": str(tmp_path / "lock"),
           "NS_MAINT_PYTHON": sys.executable, "NS_MAINT_HEALTH_WAIT": "0"}

    class Helper:
        def __init__(self) -> None:
            self.out, self.request, self.lock = out, request, tmp_path / "lock"

        def run(self, word: str | None) -> subprocess.CompletedProcess:
            if word is not None:
                request.write_text(word)
            return subprocess.run(["sh", str(SCRIPT), str(request)], env=env,
                                  capture_output=True, text=True, timeout=60, check=False)

        def calls(self) -> str:
            return calls.read_text()

        def json(self, name: str) -> dict:
            return json.loads((out / name).read_text())

    return Helper()


def test_an_unknown_word_is_consumed_and_ignored(helper) -> None:
    r = helper.run("rm -rf /\n")
    assert r.returncode == 0 and "ignored an unknown request" in r.stderr
    assert "-rf" not in r.stderr                             # the content is never echoed
    assert not helper.request.exists()
    assert helper.calls() == ""
    helper.run("reboots")                                    # the exact word or nothing
    helper.run("REBOOT")
    assert helper.calls() == ""


def test_a_symlinked_request_is_refused(helper, tmp_path: Path) -> None:
    target = tmp_path / "secret"
    target.write_text("reboot")
    helper.request.symlink_to(target)
    r = helper.run(None)
    assert "not a plain file" in r.stderr and not helper.request.is_symlink()
    assert target.exists() and helper.calls() == ""


def test_reboot_records_what_ran_then_reboots(helper) -> None:
    r = helper.run("reboot\n")
    assert r.returncode == 0, r.stderr
    assert not helper.request.exists()
    assert "systemctl reboot" in helper.calls()
    snap = helper.json("pre-reboot.json")
    assert snap["containers"] == ["web"]
    assert snap["units"] == ["docker.service", "netsentry.service"]
    assert helper.json("result.json")["action"] == "reboot"
    assert not (helper.out / "busy.json").exists()


def test_refresh_writes_the_plan_atomically(helper) -> None:
    assert helper.run("refresh").returncode == 0
    assert "apt-get -o DPkg::Lock::Timeout=300 update" in helper.calls()     # waits for a held apt lock
    plan = helper.json("plan-upgrade.json")
    assert [p["name"] for p in plan["packages"]] == ["docker-ce", "tzdata"]
    assert plan["packages"][0] == {"name": "docker-ce", "from": "5:27.1", "to": "5:27.2"}
    assert plan["kept_back"] == ["held-pkg"] and len(plan["hash"]) == 64
    assert plan["finished"] >= plan["started"]
    assert sorted(f.name for f in helper.out.iterdir()) == ["plan-upgrade.json"]   # no temp files
    assert oct((helper.out / "plan-upgrade.json").stat().st_mode & 0o777) == "0o644"


def test_upgrade_refuses_when_the_list_changed(helper) -> None:
    helper.out.mkdir()
    (helper.out / "plan-upgrade.json").write_text(json.dumps({"hash": "deadbeef"}))
    helper.run("upgrade")
    result = helper.json("result.json")
    assert result["action"] == "upgrade" and result["changed"] is True
    assert "-y" not in helper.calls()
    assert helper.json("plan-upgrade.json")["hash"] == result["hash"]

    helper.run("upgrade")                                    # now it matches what was shown
    calls = helper.calls()
    assert ("apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
            "upgrade --with-new-pkgs") in calls
    assert "full-upgrade" not in calls and "dist-upgrade" not in calls
    result = helper.json("result.json")
    assert result["exit"] == 0 and [p["name"] for p in result["upgraded"]] == ["docker-ce", "tzdata"]


def test_kernels_and_prune_and_eeprom(helper) -> None:
    helper.run("kernels-plan")
    plan = helper.json("plan-kernels.json")
    assert [p["name"] for p in plan["packages"]] == ["linux-image-6.12.40+rpt-rpi-v8", "libfoo1"]
    helper.run("kernels")
    assert "apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef" in helper.calls()
    assert "autoremove --purge" in helper.calls()

    helper.run("prune")
    result = helper.json("result.json")
    assert (result["freed_build"], result["freed_images"]) == ("1.2GB", "800MB")
    assert "volume" not in helper.calls() and "system prune" not in helper.calls()

    helper.run("eeprom")
    assert "rpi-eeprom-update -a" in helper.calls()
    assert "reboot" not in helper.calls()


def test_status_and_health(helper) -> None:
    helper.run("status")
    status = helper.json("status.json")
    assert [p["name"] for p in status["pending"]] == ["docker-ce", "tzdata"]
    assert status["eeprom"]["update_available"] is True
    assert status["disk_errors"]["count"] == 1
    assert status["autoremove"] == ["linux-image-6.12.40+rpt-rpi-v8", "libfoo1"]

    helper.out.joinpath("pre-reboot.json").write_text(json.dumps(
        {"created": 1, "containers": ["web", "db"], "units": ["docker.service"]}))
    helper.run("health")
    health = helper.json("health.json")
    assert health["containers"]["missing"] == ["db"]
    assert health["units"] == {"netsentry.service": "active", "docker.service": "active"}
    assert "dns" in health


def test_a_busy_helper_ignores_the_next_word(helper) -> None:
    import fcntl as _fcntl  # POSIX only, like the whole module
    fd = os.open(helper.lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _fcntl.flock(fd, _fcntl.LOCK_EX)
        helper.run("status")
    finally:
        os.close(fd)
    assert helper.json("ignored.json")["action"] == "status"
    assert not (helper.out / "status.json").exists()
    assert not helper.request.exists()
