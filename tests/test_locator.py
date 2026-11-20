"""Locating devices from signal strength: the maths (core.locate) and the
/where plugin around it (sensor reports, naming, buttons, map, health)."""

from __future__ import annotations

import json
import logging
import math
import random
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from netsentry.core.events import EventBus
from netsentry.core.locate import Anchor, PathLoss, fit_level, fit_path_loss, locate
from netsentry.core.plugin import PluginContext
from netsentry.plugins.locator import LocatorPlugin, parse_report

CHAT = 42
MODEL = PathLoss(-45.0, 3.0)
ANCHORS = {
    "s1": Anchor("s1", "Living room", 0.5, 0.5),
    "s2": Anchor("s2", "Bedroom", 11.5, 0.5),
    "s3": Anchor("s3", "Kitchen", 6.0, 8.5),
    "router": Anchor("router", "Router", 1.0, 4.0),
}


def _heard_at(x: float, y: float, ids=("s1", "s2", "s3", "router"), noise=0.0, rng=None) -> dict:
    return {i: MODEL.rssi(math.hypot(x - ANCHORS[i].x, y - ANCHORS[i].y))
            + (rng.gauss(0, noise) if rng else 0.0) for i in ids}


# ─── the maths ───────────────────────────────────────────────────

def test_signal_and_distance_are_two_views_of_one_model() -> None:
    for metres in (0.5, 1, 3, 8, 20):
        assert MODEL.distance(MODEL.rssi(metres)) == pytest.approx(metres, rel=1e-6)
    assert MODEL.rssi(1) == -45.0
    assert MODEL.distance(-10) == 0.3                     # absurdly strong: clamped
    assert MODEL.distance(-150) == 60.0                   # absurdly weak: clamped


def test_three_or_more_anchors_place_a_device_in_an_area() -> None:
    est = locate(_heard_at(8, 3), ANCHORS, MODEL, width_m=12, height_m=9)
    assert est.kind == "area" and est.anchors == 4
    assert math.hypot(est.x - 8, est.y - 3) < 1.0
    assert est.nearest == "s2" and est.nearest_m == pytest.approx(4.3, abs=0.1)
    assert 0.5 <= est.radius_m <= 4.0                     # a spread, never a bare point


def test_noisy_readings_still_land_in_the_right_room() -> None:
    rng = random.Random(7)
    errors = []
    for _ in range(150):
        x, y = rng.uniform(0.5, 11.5), rng.uniform(0.5, 8.5)
        est = locate(_heard_at(x, y, noise=4.0, rng=rng), ANCHORS, MODEL, width_m=12, height_m=9)
        errors.append(math.hypot(est.x - x, est.y - y))
    errors.sort()
    assert errors[len(errors) // 2] < 2.0                 # median: under two metres
    assert errors[int(len(errors) * 0.9)] < 4.0           # nine in ten: under four


@pytest.mark.parametrize("ids", [("s1",), ("s1", "router"), ("router",)])
def test_fewer_than_three_anchors_never_get_coordinates(ids) -> None:
    est = locate(_heard_at(2, 2, ids=ids), ANCHORS, MODEL, width_m=12, height_m=9)
    assert est.kind == "near" and est.x is None and est.radius_m is None
    assert est.anchors == len(ids) and est.nearest in ids and est.nearest_m > 0


def test_unknown_anchors_and_impossible_readings_are_ignored() -> None:
    assert locate({}, ANCHORS, MODEL, width_m=12, height_m=9) is None
    assert locate({"stranger": -50}, ANCHORS, MODEL, width_m=12, height_m=9) is None
    assert locate({"s1": 12, "s2": -400}, ANCHORS, MODEL, width_m=12, height_m=9) is None
    est = locate({**_heard_at(8, 3), "stranger": -20, "s1": 40}, ANCHORS, MODEL,
                 width_m=12, height_m=9)
    assert est.anchors == 3                               # s1's nonsense reading dropped


def test_each_anchor_can_have_its_own_model() -> None:
    louder = PathLoss(-40.0, 3.0)                         # the router hears 5 dB better
    readings = _heard_at(8, 3)
    readings["router"] += 5
    est = locate(readings, ANCHORS, {"router": louder, "s1": MODEL, "s2": MODEL, "s3": MODEL},
                 width_m=12, height_m=9)
    assert math.hypot(est.x - 8, est.y - 3) < 1.0


def test_the_model_can_be_measured_between_known_points() -> None:
    rng = random.Random(3)
    true = PathLoss(-48.0, 3.4)
    samples = [(d, true.rssi(d) + rng.gauss(0, 1.5)) for d in (2, 3.5, 6, 9, 11, 4, 7.5, 10)]
    fitted = fit_path_loss(samples)
    assert fitted.exponent == pytest.approx(3.4, abs=0.4)
    assert fitted.rssi_at_1m == pytest.approx(-48, abs=4)


@pytest.mark.parametrize("samples", [
    [],                                                   # nothing
    [(3, -60), (9, -75)],                                 # too few
    [(5.0, -60), (5.2, -61), (5.1, -60)],                 # all at about the same distance
    [(2, -60), (5, -60.5), (10, -61)],                    # flat: no radio behaves like that
    [(2, -40), (4, -75), (8, -99)],                       # falls off absurdly fast
])
def test_a_model_that_cannot_be_trusted_is_not_returned(samples) -> None:
    assert fit_path_loss(samples) is None


def test_the_level_alone_can_be_measured_when_points_are_equally_far() -> None:
    samples = [(9.7, MODEL.rssi(9.7) + 1), (10.2, MODEL.rssi(10.2) - 1), (11, MODEL.rssi(11))]
    assert fit_path_loss(samples) is None                 # fall-off unknowable here
    level = fit_level(samples)
    assert level.exponent == 3.0 and level.rssi_at_1m == pytest.approx(-45, abs=1)
    assert fit_level([(5, -60)]) is None                  # one sample proves nothing
    assert fit_level([(5, -5), (6, -4)]) is None          # absurd level


# ─── sensor reports ──────────────────────────────────────────────

def _report(sensor_mac: str, seen: list, **extra) -> bytes:
    return json.dumps({"id": "s", "mac": sensor_mac, "fw": 1, "up": 7300, "ch": 6,
                       "seen": seen, **extra}).encode()


def test_a_report_is_read_and_normalised() -> None:
    mac, seen, info = parse_report(_report("aabbccddee01", [["a0b1c2d3e4f5", -61, 12, 3],
                                                           ["a0b1c2d3e4f6", -80, 1, 90]]))
    assert mac == "AA:BB:CC:DD:EE:01"
    assert seen == [("A0:B1:C2:D3:E4:F5", -61), ("A0:B1:C2:D3:E4:F6", -80)]
    assert info == {"uptime_s": 7300, "channel": 6}


def test_a_report_is_untrusted_input() -> None:
    rows = [["a0b1c2d3e4f5", -61, 1, 0],                  # good
            ["A0B1C2D3E4F5", -61, 1, 0],                  # upper case: not our format
            ["a0b1c2d3e4", -61, 1, 0],                    # short
            ["a0b1c2d3e4f5; rm -rf", -61, 1, 0],
            ["a0b1c2d3e4f7", 20, 1, 0],                   # impossible signal
            ["a0b1c2d3e4f7", -161, 1, 0],
            ["a0b1c2d3e4f7", "-61", 1, 0],                # wrong type
            ["a0b1c2d3e4f7", -61, 1, 5000],               # stale
            "junk", [], None]
    _, seen, _ = parse_report(_report("not-a-mac", rows, up="soon", ch=None))
    assert seen == [("A0:B1:C2:D3:E4:F5", -61)]
    _, many, _ = parse_report(_report("aabbccddee01",
                                      [[f"{i:012x}", -60, 1, 0] for i in range(5000)]))
    assert len(many) == 400                               # a flood is cut off
    for bad in (b"[]", b'{"seen": "x"}', b"not json", b'{"id": "s1"}'):
        with pytest.raises(ValueError):
            parse_report(bad)


# ─── the plugin ──────────────────────────────────────────────────

PHONE, CAM, LAPTOP = "A0:B1:C2:D3:E4:01", "A0:B1:C2:D3:E4:02", "A0:B1:C2:D3:E4:03"
NEIGHBOUR = "0E:11:22:33:44:55"
SENSOR_MACS = {"s1": "aabbccddee01", "s2": "aabbccddee02", "s3": "aabbccddee03"}
SENSORS = [
    {"id": "s1", "name": "Living room", "host": "198.51.100.61", "x": 0.5, "y": 0.5},
    {"id": "s2", "name": "Bedroom", "host": "198.51.100.62", "x": 11.5, "y": 0.5},
    {"id": "s3", "name": "Kitchen", "host": "198.51.100.63", "x": 6.0, "y": 8.5},
]


def _plugin(tmp_path: Path, **config) -> LocatorPlugin:
    router = Mock()
    router.host = "192.0.2.1"
    router.wifi_clients.return_value = [
        SimpleNamespace(mac=PHONE, signal_dbm=-52, ssid="Home"),      # 5 GHz: router only
        SimpleNamespace(mac=CAM, signal_dbm=-66, ssid="IoT"),
        SimpleNamespace(mac=LAPTOP, signal_dbm=None, ssid="Home"),
    ]
    router.dhcp_leases.return_value = [SimpleNamespace(mac=CAM, hostname="cam-kitchen")]
    router.port_forward_ensure.return_value = "exists"
    ctx = PluginContext(
        name="locator", config={"floor": {"width_m": 12, "height_m": 9}, **config},
        router=router, notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.locator"), state_dir=str(tmp_path), events=EventBus())
    p = LocatorPlugin(ctx)
    p.on_load()
    return p


def _sensors_hear(p: LocatorPlugin, device_at: dict[str, tuple[float, float]],
                  down: tuple[str, ...] = ()) -> None:
    """Make every sensor report the devices in ``device_at`` (plus each other)."""
    def ask(sensor):
        if sensor.id in down:
            return "not answering (timed out)"
        seen = [(mac, round(MODEL.rssi(math.hypot(x - sensor.x, y - sensor.y))))
                for mac, (x, y) in device_at.items()]
        seen += [(":".join(SENSOR_MACS[o.id][i:i + 2] for i in range(0, 12, 2)).upper(),
                  round(MODEL.rssi(math.hypot(o.x - sensor.x, o.y - sensor.y))))
                 for o in p._sensors if o.id != sensor.id]
        own = ":".join(SENSOR_MACS[sensor.id][i:i + 2] for i in range(0, 12, 2)).upper()
        return own, seen, {"uptime_s": 7300, "channel": 6}

    p._ask = ask  # type: ignore[method-assign]


def _text(p: LocatorPlugin) -> str:
    return p.notifier.send_to.call_args.args[1]


def test_without_sensors_it_still_says_how_far_from_the_router(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    assert p.scheduled_tasks() == [] and p.health() == []
    p.on_command("/where", "", CHAT)
    text = _text(p)
    assert "3 WiFi devices" in text
    assert "cam-kitchen — about" in text and "m from the router" in text
    assert f"{LAPTOP} — not heard right now" in text
    assert "No WiFi sensors are set up yet" in text
    labels = [b["text"] for row in p.notifier.send_to.call_args.kwargs["buttons"] for b in row]
    assert labels == ["🔄 Refresh", "🏠 Menu"]                        # no map without sensors


def test_three_sensors_place_a_device_and_ignore_the_neighbours(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS, router={"x": 1.0, "y": 4.0})
    _sensors_hear(p, {CAM: (6.5, 7.0), NEIGHBOUR: (11, 8)})
    p.poll()
    places = {d["mac"]: d for d in p.places()}
    assert NEIGHBOUR not in places                        # heard, but not on our network
    cam = places[CAM]["estimate"]
    assert cam.kind == "area" and cam.nearest == "s3"
    assert math.hypot(cam.x - 6.5, cam.y - 7.0) < 2.5
    assert places[PHONE]["estimate"].kind == "near"       # only the router hears it
    assert places[PHONE]["estimate"].nearest == "router"
    assert places[LAPTOP]["estimate"] is None

    p.on_command("/where", "", CHAT)
    text = _text(p)
    assert "📍 cam-kitchen — near Kitchen" in text and "within about" in text
    assert text.index("cam-kitchen") < text.index(LAPTOP)  # best-known first
    labels = [b["text"] for row in p.notifier.send_to.call_args.kwargs["buttons"] for b in row]
    assert labels == ["🔄 Refresh", "🗺 Map", "📶 Sensors", "🏠 Menu"]


def test_names_come_from_your_own_labels_first(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    tagger = Mock()
    tagger.tag_for.side_effect = lambda mac: {PHONE: "My phone"}.get(mac)
    p.ctx._all_plugins = [p, tagger]  # type: ignore[attr-defined]
    names = {d["mac"]: d["name"] for d in p.places()}
    assert names == {PHONE: "My phone", CAM: "cam-kitchen", LAPTOP: LAPTOP}
    p.router.dhcp_leases.side_effect = RuntimeError("ssh down")       # names are optional
    assert {d["name"] for d in p.places()} == {"My phone", CAM, LAPTOP}


def test_a_sensor_that_stops_answering_is_said_and_reaches_health(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS)
    assert p.health()[0].ok is True and "pending" in p.health()[0].detail
    _sensors_hear(p, {CAM: (6.5, 7.0)}, down=("s2",))
    p.on_command("/where", "", CHAT)
    assert "Not answering: Bedroom" in _text(p)
    assert p.health()[0].ok is True                       # one miss is not an alarm
    p.poll()
    p.poll()
    check = p.health()[0]
    assert check.ok is False and "Bedroom: not answering" in check.detail
    _sensors_hear(p, {CAM: (6.5, 7.0)})
    p.poll()
    assert p.health()[0].ok is True and "3 sensors answering" in p.health()[0].detail


def test_two_sensors_only_say_near(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS)                # no router anchor configured
    _sensors_hear(p, {CAM: (6.5, 7.0)}, down=("s1",))
    p.poll()
    cam = {d["mac"]: d for d in p.places()}[CAM]["estimate"]
    assert cam.kind == "near" and cam.anchors == 2 and cam.nearest == "s3"
    p.on_command("/where", "", CHAT)
    assert "◦ cam-kitchen — near Kitchen" in _text(p)


def test_the_signal_model_is_measured_between_the_sensors(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS)
    model, origin = p.signal_model()
    assert model == PathLoss() and "typical values" in origin
    _sensors_hear(p, {})
    p.poll()
    model, origin = p.signal_model()
    # these three are all about equally far apart: the level can be measured,
    # the fall-off cannot
    assert origin.startswith("level measured between your sensors")
    assert model.rssi_at_1m == pytest.approx(-45, abs=1) and model.exponent == 3.0
    spread = _plugin(tmp_path / "s", sensors=[SENSORS[0], SENSORS[1],
                                              {**SENSORS[2], "x": 2.0, "y": 3.0}])
    _sensors_hear(spread, {})
    spread.poll()
    model, origin = spread.signal_model()                 # near and far pairs: both known
    assert origin == "measured between your sensors"
    assert model.exponent == pytest.approx(3.0, abs=0.2)
    fixed = _plugin(tmp_path / "f", sensors=SENSORS, rssi_at_1m=-50, exponent=2.5)
    assert fixed.signal_model() == (PathLoss(-50.0, 2.5), "set in the config")


def test_sensors_screen_and_stale_readings(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS)
    _sensors_hear(p, {CAM: (6.5, 7.0)}, down=("s3",))
    p.on_callback("locator:sensors", CHAT, 7, "cb")
    text = p.notifier.edit_message.call_args.args[2]
    assert "✅ Living room — hears 3 devices, up 2 h, channel 6" in text
    assert "⚠️ Kitchen — not answering (timed out)" in text and "Signal model:" in text
    # readings age out instead of pinning a device where it once was
    with patch("netsentry.plugins.locator.time.time", return_value=10**10):
        _sensors_hear(p, {}, down=("s1", "s2", "s3"))
        p.poll()
        assert p._readings == {}


def test_map_is_drawn_and_sent(tmp_path: Path) -> None:
    pytest.importorskip("PIL")
    p = _plugin(tmp_path, sensors=SENSORS, router={"x": 1.0, "y": 4.0})
    _sensors_hear(p, {CAM: (6.5, 7.0)})
    p.on_callback("locator:map", CHAT, 7, "cb")
    call = p.notifier.send_to.call_args
    assert "1 device placed" in call.args[1] and "2 more are only roughly known" in call.args[1]
    picture = Path(call.kwargs["photo_path"])
    assert picture.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and picture.stat().st_size > 2000
    # an unreadable floor plan falls back to the plain grid instead of failing
    broken = _plugin(tmp_path / "b", sensors=SENSORS,
                     floor={"width_m": 12, "height_m": 9, "image": str(tmp_path / "nope.png")})
    _sensors_hear(broken, {CAM: (6.5, 7.0)})
    broken.on_callback("locator:map", CHAT, 7, "cb")
    assert "photo_path" in broken.notifier.send_to.call_args.kwargs


def test_router_trouble_is_reported_not_crashed(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.router.wifi_clients.side_effect = RuntimeError("ssh down")
    p.on_command("/where", "", CHAT)
    assert "could not ask the router" in _text(p)
    p.on_callback("locator:map", CHAT, 7, "cb")
    assert "Could not draw the map" in _text(p)


def test_bad_sensor_entries_are_skipped_not_fatal(tmp_path: Path, caplog) -> None:
    with caplog.at_level(logging.ERROR):
        p = _plugin(tmp_path, sensors=[
            SENSORS[0], {"id": "s2"}, {"id": "Bad Id!", "host": "198.51.100.9", "x": 1, "y": 1},
            {"id": "s4", "host": "198.51.100.9/../x", "x": 1, "y": 1}, "junk"])
    assert [s.id for s in p._sensors] == ["s1"]
    assert caplog.text.count("ignored") == 4


# ─── asking a sensor over HTTP ───────────────────────────────────

def _http(body: bytes):
    response = Mock()
    response.read.return_value = body
    response.__enter__ = lambda s: s
    response.__exit__ = lambda *a: False
    return response


URLOPEN = "netsentry.plugins.locator.urllib.request.urlopen"


def test_asking_a_sensor_directly_with_the_shared_key(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS, token="s3cret key")
    with patch(URLOPEN, return_value=_http(_report("aabbccddee01", []))) as urlopen:
        mac, seen, _ = p._ask(p._sensors[0])
    assert mac == "AA:BB:CC:DD:EE:01" and seen == []
    assert urlopen.call_args.args[0] == "http://198.51.100.61/rssi?k=s3cret+key"
    p.router.port_forward_ensure.assert_not_called()


def test_sensor_failures_become_short_reasons(tmp_path: Path) -> None:
    p = _plugin(tmp_path, sensors=SENSORS)
    s = p._sensors[0]
    with patch(URLOPEN, side_effect=urllib.error.URLError("timed out")):
        assert p._ask(s) == "not answering (timed out)"
    with patch(URLOPEN, side_effect=urllib.error.HTTPError("u", 403, "Forbidden", {}, None)):
        assert p._ask(s) == "wrong key"
    with patch(URLOPEN, return_value=_http(b"<html>some other device</html>")):
        assert p._ask(s) == "answer not understood (wrong firmware?)"


def test_a_sensor_behind_the_router_uses_one_forward_set_up_once(tmp_path: Path) -> None:
    behind = [{**SENSORS[0], "via_router_port": 8111}]
    p = _plugin(tmp_path, sensors=behind)
    p.router.port_forward_ensure.return_value = "added"
    events: list = []
    p.ctx.events.subscribe("router.config.expected_change", events.append)
    with patch(URLOPEN, return_value=_http(_report("aabbccddee01", []))) as urlopen, \
         patch("netsentry.plugins.locator.local_address_towards", return_value="192.0.2.10"):
        p.poll()
        p.poll()
    p.router.port_forward_ensure.assert_called_once_with(
        "sensor-s1", "192.0.2.10", 8111, "198.51.100.61", 80)
    assert urlopen.call_args.args[0] == "http://192.0.2.1:8111/rssi"
    assert len(events) == 1

    refused = _plugin(tmp_path / "r", sensors=behind)
    refused.router.port_forward_ensure.return_value = "failed"
    with patch("netsentry.plugins.locator.local_address_towards", return_value="192.0.2.10"):
        assert "would not set up the path" in refused._ask(refused._sensors[0])
