"""Dashboard: the System page, per-device network info and the guest "keep" switch."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import HealthCheck, PluginContext
from netsentry.core.router import DhcpLease, SystemStats, WifiClient, WifiTraffic
from netsentry.plugins.lan_dashboard import LanDashboardPlugin, _safe_next

TOKEN = "test-token-abc123"
PHONE = "F2:27:2C:00:00:01"
LAPTOP = "AA:BB:CC:00:00:02"
CAMERA = "AA:BB:CC:00:00:03"


class _Named:
    def __init__(self, name: str) -> None:
        self.ctx = Mock()
        self.ctx.name = name


class _SelfCheck(_Named):
    def __init__(self) -> None:
        super().__init__("self_check")
        self.calls = 0
        self.broken = False

    def checks(self) -> list[HealthCheck]:
        self.calls += 1
        if self.broken:
            raise RuntimeError("boom")
        return [HealthCheck("Threat scan", True, "ran 3 min ago"),
                HealthCheck("WiFi monitor", False, "radio is switched off"),
                HealthCheck("Disk space", True, "61% free")]


class _Pihole(_Named):
    def __init__(self) -> None:
        super().__init__("pihole_stats")

    def api_today(self) -> dict:
        return {"total": 20000, "blocked": 3100, "pct": 15.5}


class _Guest(_Named):
    def __init__(self) -> None:
        super().__init__("guest_wifi_rotator")
        self.cfg = {"ssid": "Cielo"}
        self.asked: list[tuple[str, bool]] = []
        self.answer = "added"

    def api_status(self) -> dict:
        return {"ssid": "Cielo", "schedule": "Every week on Monday at 09:00",
                "next": "Mon 2026-11-23 09:00", "last": "Mon 2026-11-16 09:00"}

    def api_keep(self, mac: str, on: bool) -> str:
        self.asked.append((mac, on))
        return self.answer if on else "removed"


class _Scheduler:
    def __init__(self) -> None:
        self.jobs = {
            "guest_wifi_rotator.rotate": {"cron": "0 9 * * 1", "paused": False,
                                          "next_run": datetime(2026, 11, 23, 9, 0)},
            "config_backup.weekly": {"cron": "0 3 * * 0", "paused": False,
                                     "next_run": datetime(2026, 11, 22, 3, 0)},
            "traffic_report.daily": {"cron": None, "paused": True, "next_run": None},
        }

    def schedule_of(self, name: str):
        return self.jobs.get(name)

    def job_stats(self) -> dict:
        return {"guest_wifi_rotator.rotate": {"last_ok": time.time() - 600, "last_error": ""},
                "config_backup.weekly": {"last_ok": 0.0, "last_start": time.time() - 60,
                                         "last_error": "RuntimeError: scp failed"}}


@pytest.fixture()
def dash(tmp_path: Path):
    router = Mock()
    router.stats.return_value = SystemStats(
        uptime_seconds=3_700_000, cpu_load_pct=4, free_memory_bytes=600, total_memory_bytes=1000,
        free_disk_bytes=1, total_disk_bytes=2, board_name="hAP ax3", routeros_version="7.22.1")
    router.wifi_clients.return_value = [
        WifiClient(PHONE, "Cielo", "wifi4", -78, "2ghz-n", "wpa2-psk", 500),
        WifiClient(LAPTOP, "Sky", "wifi1", -51, "5ghz-ax", "wpa2-psk", 100_000),
    ]
    router.wifi_traffic.return_value = [WifiTraffic(PHONE, 1000, 2000, 500)]
    router.dhcp_leases.return_value = [DhcpLease(PHONE, "10.2.2.9", "Redmi-13C-5G"),
                                       DhcpLease(CAMERA, "10.4.4.20", "cam1")]
    router.arp_table.return_value = []
    router.blocked_macs.return_value = set()
    router.kept_wifi_passphrases.return_value = {PHONE: "Redmi-13C-5G"}
    ctx = PluginContext(
        name="lan_dashboard", config={}, router=router, notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.dashboard.system"), state_dir=str(tmp_path),
        scheduler=_Scheduler())
    plugins = {"check": _SelfCheck(), "pihole": _Pihole(), "guest": _Guest()}
    ctx._all_plugins = list(plugins.values())  # type: ignore[attr-defined]
    plugin = LanDashboardPlugin(ctx)
    # on_load() starts threads and an HTTP server; set up only what the code touches.
    plugin._token = TOKEN
    plugin._lock = threading.RLock()
    plugin._devices = {}
    plugin._blocked, plugin._blocked_refresh_ts = set(), 0.0
    plugin._kept, plugin._kept_refresh_ts = {}, 0.0
    plugin._system_cache, plugin._system_lock = None, threading.Lock()
    plugin._prev_wifi, plugin._last_accounting_ts = {}, None
    plugin._poll_interval_s, plugin._history_samples = 20.0, 10
    plugin._accounting_off, plugin._accounting_empty_warned = True, True
    plugin._started_ts = 1_800_000_000.0
    plugin._scan_lock, plugin._nmap_bin = threading.Lock(), "nmap"
    plugin._tags_snapshot = lambda: {}  # type: ignore[method-assign]
    app = plugin._build_app()
    app.config["TESTING"] = True
    client = app.test_client()
    return client, plugin, plugins, router


def _login(client) -> None:
    client.get("/auth?token=" + TOKEN)


def test_new_routes_need_the_session_cookie(dash) -> None:
    client, _, plugins, _ = dash
    assert client.get("/system").status_code == 403
    assert client.get("/api/system").status_code == 403
    assert client.post("/keep", json={"mac": PHONE}).status_code == 403
    assert plugins["guest"].asked == []
    assert _safe_next("/system") == "/system"


def test_system_page_and_tab_render(dash) -> None:
    client, _, _, _ = dash
    _login(client)
    page = client.get("/system")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "Is everything running?" in html and 'id="tabSystem"' in html
    assert 'class="tab tab--system"' in client.get("/").get_data(as_text=True)


def test_system_snapshot_puts_problems_first_and_never_the_password(dash) -> None:
    client, plugin, _, _ = dash
    _login(client)
    plugin._poll_once(time.time())

    data = client.get("/api/system").get_json()

    assert [c["name"] for c in data["health"]["checks"]] == ["WiFi monitor", "Disk space", "Threat scan"]
    assert data["health"]["problems"] == [
        {"name": "WiFi monitor", "ok": False, "detail": "radio is switched off"}]
    assert data["router"] == {"uptime_s": 3_700_000, "cpu_pct": 4, "memory_pct": 40,
                              "version": "7.22.1", "board": "hAP ax3"}
    assert data["pihole"] == {"total": 20000, "blocked": 3100, "pct": 15.5}
    assert data["guest"]["ssid"] == "Cielo" and data["guest"]["next"] == "Mon 2026-11-23 09:00"
    assert data["guest"]["kept"] == [{"mac": PHONE, "name": "Redmi-13C-5G", "online": True}]
    assert "pass" not in str(data["guest"]).lower().replace("password changes", "")
    assert data["running_since"] == 1_800_000_000.0 and data["version"]


def test_jobs_show_schedule_next_run_and_how_the_last_run_went(dash) -> None:
    client, _, _, _ = dash
    _login(client)

    jobs = {j["label"]: j for j in client.get("/api/system").get_json()["jobs"]}

    assert list(jobs) == ["Guest WiFi password change", "Traffic report", "Router config backup"]
    rotation = jobs["Guest WiFi password change"]
    assert rotation["schedule"] == "every week on Mon at 09:00"
    assert rotation["next"] == "Mon 23 Nov 09:00" and rotation["last"] == "ok"
    backup = jobs["Router config backup"]
    assert backup["last"] == "failed" and backup["error"] == "RuntimeError: scp failed"
    paused = jobs["Traffic report"]
    assert paused["paused"] and paused["schedule"] == "paused" and paused["next"] == ""
    assert paused["last"] == ""                 # has not run since start: say so, not "OK"


def test_one_broken_section_does_not_take_the_page_down(dash) -> None:
    client, _, plugins, router = dash
    _login(client)
    plugins["check"].broken = True
    router.stats.return_value = None            # router unreachable

    data = client.get("/api/system").get_json()

    assert data["health"] is None and data["router"] is None
    assert data["pihole"]["blocked"] == 3100 and data["jobs"]


def test_gathering_is_shared_between_requests(dash) -> None:
    client, plugin, plugins, _ = dash
    _login(client)
    for _ in range(3):
        client.get("/api/system")
        client.get("/api/overview")
    assert plugins["check"].calls == 1

    plugin._system_cache = (time.time() - 31, plugin._system_cache[1])
    client.get("/api/system")
    assert plugins["check"].calls == 2


def test_devices_carry_their_network_signal_and_guest_state(dash) -> None:
    _, plugin, _, _ = dash
    plugin._poll_once(time.time())

    devices = {d["mac"]: d for d in plugin._snapshot_payload()["devices"]}

    phone = devices[PHONE]
    assert (phone["ssid"], phone["band"], phone["signal"]) == ("Cielo", "2ghz-n", -78)
    assert phone["guest"] is True and phone["kept"] is True
    laptop = devices[LAPTOP]
    assert laptop["ssid"] == "Sky" and laptop["guest"] is False and laptop["kept"] is False
    camera = devices[CAMERA]                     # known from DHCP only: not on WiFi
    assert (camera["ssid"], camera["band"], camera["signal"]) == ("", "", None)


def test_a_device_that_leaves_wifi_loses_its_network(dash) -> None:
    _, plugin, _, router = dash
    plugin._poll_once(time.time())
    router.wifi_clients.return_value = []
    router.wifi_traffic.return_value = []
    router.dhcp_leases.return_value = []

    plugin._poll_once(time.time() + 20)

    phone = {d["mac"]: d for d in plugin._snapshot_payload()["devices"]}[PHONE]
    assert (phone["ssid"], phone["signal"]) == ("", None)


def test_kept_list_survives_a_router_that_does_not_answer(dash) -> None:
    _, plugin, _, router = dash
    plugin._poll_once(time.time())
    router.kept_wifi_passphrases.return_value = None

    plugin._poll_once(time.time() + 120)

    assert plugin._kept == {PHONE: "Redmi-13C-5G"}


def test_overview_counts_networks_and_summarises_health(dash) -> None:
    client, plugin, _, _ = dash
    _login(client)
    plugin._poll_once(time.time())

    data = client.get("/api/overview").get_json()

    assert data["devices"]["networks"] == [{"name": "Cielo", "count": 1}, {"name": "Sky", "count": 1}]
    assert data["health"] == {"total": 3, "problems": 1, "first": "WiFi monitor"}
    assert data["guest"]["next"] == "Mon 2026-11-23 09:00"


def test_keep_switch_asks_the_guest_plugin_and_tracks_the_answer(dash) -> None:
    client, plugin, plugins, _ = dash
    _login(client)
    client.get("/api/system")                    # fill the cache: a change must drop it

    reply = client.post("/keep", json={"mac": LAPTOP.lower(), "on": True}).get_json()

    assert reply == {"ok": True, "state": "added", "kept": True}
    assert plugins["guest"].asked == [(LAPTOP, True)]
    assert LAPTOP in plugin._kept and plugin._system_cache is None

    reply = client.post("/keep", json={"mac": LAPTOP, "on": False}).get_json()
    assert reply == {"ok": True, "state": "removed", "kept": False}
    assert LAPTOP not in plugin._kept


def test_keep_switch_reports_refusals_and_changes_nothing(dash) -> None:
    client, plugin, plugins, _ = dash
    _login(client)
    plugins["guest"].answer = "not-connected"

    reply = client.post("/keep", json={"mac": LAPTOP, "on": True}).get_json()

    assert reply == {"ok": False, "state": "not-connected", "kept": False}
    assert plugin._kept == {}
    assert client.post("/keep", json={"mac": "nonsense"}).status_code == 400

    plugin.ctx._all_plugins = []                 # no guest WiFi plugin in this install
    reply = client.post("/keep", json={"mac": LAPTOP, "on": True}).get_json()
    assert reply == {"ok": False, "state": "unavailable", "kept": False}


def test_overview_verdict_and_badges_count_only_what_needs_the_owner(dash) -> None:
    client, plugin, _, _ = dash
    _login(client)
    plugin._poll_once(time.time())

    data = client.get("/api/overview").get_json()

    verdict = data["verdict"]                    # a monitor is down: not "All clear"
    assert verdict["level"] == "attention" and "WiFi monitor" in verdict["reason"]
    assert [i["href"] for i in verdict["items"]] == ["/system", "/devices"]
    assert verdict["items"][1]["label"] == "3 unnamed devices"
    assert data["badges"] == {"threats": 0, "system": 1, "devices": 3}
    assert data["devices"]["unnamed"] == data["devices"]["untagged"] == 3


def test_times_are_also_given_as_epoch_seconds(dash) -> None:
    client, _, _, _ = dash
    _login(client)

    data = client.get("/api/system").get_json()

    assert data["guest"]["next_ts"] == datetime(2026, 11, 23, 9, 0).timestamp()
    assert data["guest"]["last_ts"] == datetime(2026, 11, 16, 9, 0).timestamp()
    jobs = {j["label"]: j for j in data["jobs"]}
    assert jobs["Guest WiFi password change"]["next_ts"] == datetime(2026, 11, 23, 9, 0).timestamp()
    assert jobs["Traffic report"]["next_ts"] is None


def test_state_picture_is_small_cached_and_needs_the_cookie(dash, tmp_path) -> None:
    client, _, _, _ = dash
    assert client.get("/state/protected.png").status_code == 403
    _login(client)
    assert client.get("/state/nonsense.png").status_code == 404
    assert client.get("/state/..%2Fnetsentry-logo.png").status_code == 404

    reply = client.get("/state/protected.png")

    assert reply.status_code == 200 and reply.mimetype == "image/png"
    assert "max-age=604800" in reply.headers["Cache-Control"]
    import io
    image = pytest.importorskip("PIL.Image")             # Pillow comes with qrcode[pil]
    assert max(image.open(io.BytesIO(reply.data)).size) <= 256
    assert len(reply.data) < 200_000
    assert (tmp_path / "state-pictures" / "protected-256.png").is_file()


def test_state_picture_without_pillow_serves_the_original(dash, tmp_path, monkeypatch) -> None:
    import sys
    client, _, _, _ = dash
    _login(client)
    monkeypatch.setitem(sys.modules, "PIL", None)       # "import PIL" now fails

    reply = client.get("/state/warning.png")

    assert reply.status_code == 200 and len(reply.data) > 200_000
    assert not (tmp_path / "state-pictures" / "warning-256.png").exists()
