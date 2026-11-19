"""locator — where in the house is each device? (`/where`)

Small WiFi sensors (ESP32 boards running `firmware/locator-sensor`) sit at known
spots and report how strongly they hear every device. Together with the
router's own reading that gives a rough position: three or more readings place
a device in an area of the floor plan, fewer only say "near that sensor".

What to expect: room-level answers. Walls and people move a reading by several
dB, so every position comes with its spread, and a device heard by fewer than
three anchors is never given coordinates.

What the sensors cannot hear: they are 2.4 GHz radios parked on your access
point's channel. A phone on 5 GHz is only heard by the router, so only its
distance from the router is known.

Only devices connected to your own network are shown — the sensors also hear
the neighbours' devices, and those are ignored.

Commands:
    /where        list + buttons (map, refresh, sensors)

Config keys:
    floor.width_m, floor.height_m   size of the floor plan, metres
    floor.image                     optional PNG of the plan (drawn under the map)
    router.x, router.y              where the router/AP stands (optional anchor)
    sensors                         list of {id, name, host, x, y[, via_router_port]}
    token                           shared key the sensors expect (optional)
    poll_minutes                    background poll for /health (default 10)
    rssi_at_1m, exponent            fix the signal model instead of measuring it
    router_gain_db                  how much better the router hears than a
                                    sensor does (default 5)
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from ...core.locate import Anchor, Estimate, PathLoss, fit_level, fit_path_loss, locate
from ...core.plugin import HealthCheck, Plugin, ScheduledTask
from ...core.router import local_address_towards
from . import render

_ROUTER = "router"                    # anchor id of the router itself
_ID_RE = re.compile(r"^[a-z0-9-]{1,16}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_MAC12_RE = re.compile(r"^[0-9a-f]{12}$")
_FRESH_S = 180                        # a reading older than this says nothing
_MAX_REPORT_BYTES = 64 * 1024
_MAX_SEEN = 400


@dataclass(frozen=True)
class Sensor:
    id: str
    name: str
    host: str
    x: float
    y: float
    via_router_port: int = 0


def parse_report(raw: bytes) -> tuple[str, list[tuple[str, int]], dict]:
    """Validate one sensor's answer → ``(sensor_mac, [(mac, rssi)], info)``.

    A sensor is a cheap board on the IoT network; its answer is treated as
    untrusted input: sizes, types and ranges are all checked.
    """
    data = json.loads(raw.decode("utf-8", "replace"))
    if not isinstance(data, dict) or not isinstance(data.get("seen"), list):
        raise ValueError("not a sensor report")
    seen: list[tuple[str, int]] = []
    for row in data["seen"][:_MAX_SEEN]:
        if not (isinstance(row, list) and len(row) >= 2):
            continue
        mac, rssi = row[0], row[1]
        age = row[3] if len(row) > 3 else 0
        if (isinstance(mac, str) and _MAC12_RE.match(mac) and isinstance(rssi, int)
                and -100 <= rssi <= 0 and isinstance(age, int) and 0 <= age <= 90):
            seen.append((_colon(mac), rssi))
    own = data.get("mac")
    info = {"uptime_s": data.get("up") if isinstance(data.get("up"), int) else None,
            "channel": data.get("ch") if isinstance(data.get("ch"), int) else None}
    return (_colon(own) if isinstance(own, str) and _MAC12_RE.match(own) else ""), seen, info


def _colon(mac12: str) -> str:
    return ":".join(mac12[i:i + 2] for i in range(0, 12, 2)).upper()


class LocatorPlugin(Plugin):
    COMMANDS = [
        {"command": "where", "description": "📍 Where in the house each device is"},
    ]

    def on_load(self) -> None:
        floor = self.cfg.get("floor") or {}
        self._width = float(floor.get("width_m", 10.0))
        self._height = float(floor.get("height_m", 10.0))
        self._floor_image = str(floor.get("image") or "")
        self._token = str(self.cfg.get("token") or "")
        self._router_gain = float(self.cfg.get("router_gain_db", 5.0))
        self._fixed_model = None
        if "rssi_at_1m" in self.cfg or "exponent" in self.cfg:
            self._fixed_model = PathLoss(float(self.cfg.get("rssi_at_1m", -45.0)),
                                         float(self.cfg.get("exponent", 3.0)))
        self._sensors: list[Sensor] = []
        for raw in self.cfg.get("sensors") or []:
            try:
                sensor = Sensor(id=str(raw["id"]), name=str(raw.get("name") or raw["id"]),
                                host=str(raw["host"]), x=float(raw["x"]), y=float(raw["y"]),
                                via_router_port=int(raw.get("via_router_port") or 0))
            except (KeyError, TypeError, ValueError):
                self.log.error("locator: sensor entry ignored (needs id, host, x, y): %r", raw)
                continue
            if not (_ID_RE.match(sensor.id) and _HOST_RE.match(sensor.host)):
                self.log.error("locator: sensor %r ignored (bad id or host)", sensor.id)
                continue
            self._sensors.append(sensor)
        self._anchors = {s.id: Anchor(s.id, s.name, s.x, s.y) for s in self._sensors}
        router = self.cfg.get("router") or {}
        if "x" in router and "y" in router:
            self._anchors[_ROUTER] = Anchor(_ROUTER, "Router", float(router["x"]),
                                            float(router["y"]))
        self._lock = threading.Lock()
        self._readings: dict[tuple[str, str], tuple[float, float]] = {}   # (sensor, MAC) → rssi, when
        self._status: dict[str, dict] = {}                                # sensor id → last poll
        self._forwarded: set[str] = set()
        self._map_file = Path(self.ctx.state_dir) / "map.png"

    def scheduled_tasks(self) -> list[ScheduledTask]:
        if not self._sensors:
            return []
        minutes = max(1, min(int(self.cfg.get("poll_minutes", 10)), 59))
        return [ScheduledTask(cron=f"*/{minutes} * * * *", func=self.poll, name="poll")]

    # ─── talking to the sensors ──────────────────────────────────

    def poll(self) -> None:
        """Ask every sensor what it hears; remember the answers."""
        if not self._sensors:
            return
        with ThreadPoolExecutor(max_workers=len(self._sensors)) as pool:
            results = list(pool.map(self._ask, self._sensors))
        now = time.time()
        with self._lock:
            for sensor, result in zip(self._sensors, results):
                previous = self._status.get(sensor.id, {})
                if isinstance(result, str):
                    self._status[sensor.id] = {
                        "ok": False, "detail": result, "ts": now,
                        "fails": int(previous.get("fails", 0)) + 1,
                        "mac": previous.get("mac", "")}
                    continue
                own_mac, seen, info = result
                self._status[sensor.id] = {"ok": True, "detail": "", "ts": now, "fails": 0,
                                           "mac": own_mac, "heard": len(seen), **info}
                for mac, rssi in seen:
                    old = self._readings.get((sensor.id, mac))
                    smooth = (0.5 * old[0] + 0.5 * rssi
                              if old and now - old[1] < _FRESH_S else float(rssi))
                    self._readings[(sensor.id, mac)] = (smooth, now)
            for key in [k for k, v in self._readings.items() if now - v[1] > _FRESH_S]:
                del self._readings[key]

    def _ask(self, sensor: Sensor) -> tuple[str, list[tuple[str, int]], dict] | str:
        """One sensor's report, or a short reason why there is none."""
        try:
            base = self._base_url(sensor)
            query = "?" + urllib.parse.urlencode({"k": self._token}) if self._token else ""
            with urllib.request.urlopen(f"{base}/rssi{query}", timeout=4) as r:  # nosec B310 - http only
                return parse_report(r.read(_MAX_REPORT_BYTES))
        except urllib.error.HTTPError as e:
            return "wrong key" if e.code in (401, 403) else f"answered HTTP {e.code}"
        except (urllib.error.URLError, OSError) as e:
            return f"not answering ({getattr(e, 'reason', e)})"
        except ValueError:
            return "answer not understood (wrong firmware?)"

    def _base_url(self, sensor: Sensor) -> str:
        if not sensor.via_router_port:
            return f"http://{sensor.host}"
        router_host = str(getattr(self.router, "host", "") or "")
        if sensor.id not in self._forwarded:
            result = self.router.port_forward_ensure(
                f"sensor-{sensor.id}", local_address_towards(router_host),
                sensor.via_router_port, sensor.host, 80)
            if result == "failed":
                raise OSError("the router would not set up the path")
            if result == "added" and self.ctx.events:
                self.ctx.events.publish("router.config.expected_change",
                                        {"source": self.ctx.name, "what": "sensor forward"})
            self._forwarded.add(sensor.id)
        return f"http://{router_host}:{sensor.via_router_port}"

    # ─── from readings to places ─────────────────────────────────

    def signal_model(self) -> tuple[PathLoss, str]:
        """The model for the sensors, and where it came from (for the owner)."""
        if self._fixed_model:
            return self._fixed_model, "set in the config"
        samples = []
        with self._lock:
            macs = {s.id: self._status.get(s.id, {}).get("mac", "") for s in self._sensors}
            for a in self._sensors:
                for b in self._sensors:
                    reading = self._readings.get((a.id, macs.get(b.id, "")))
                    if a.id != b.id and reading:
                        samples.append((((a.x - b.x) ** 2 + (a.y - b.y) ** 2) ** 0.5, reading[0]))
        fitted = fit_path_loss(samples)
        if fitted is not None:
            return fitted, "measured between your sensors"
        level = fit_level(samples)
        if level is not None:
            return level, ("level measured between your sensors, typical fall-off "
                           "(they are all about equally far apart)")
        return PathLoss(), "typical values (the sensors cannot measure each other yet)"

    def places(self) -> list[dict]:
        """Every device on the network with its estimate, best-known first."""
        clients = {c.mac.upper(): c for c in self.router.wifi_clients()}
        names = self._names(clients)
        model, _ = self.signal_model()
        models = {s.id: model for s in self._sensors}
        models[_ROUTER] = PathLoss(model.rssi_at_1m + self._router_gain, model.exponent)
        now = time.time()
        out = []
        with self._lock:
            readings = dict(self._readings)
        for mac, client in clients.items():
            heard = {sid: rssi for (sid, m), (rssi, ts) in readings.items()
                     if m == mac and now - ts < _FRESH_S}
            router_m = None
            if client.signal_dbm is not None and client.signal_dbm < 0:
                router_m = round(models[_ROUTER].distance(client.signal_dbm), 1)
                if _ROUTER in self._anchors:
                    heard[_ROUTER] = float(client.signal_dbm)
            estimate = locate(heard, self._anchors, models,
                              width_m=self._width, height_m=self._height)
            out.append({"mac": mac, "name": names.get(mac, mac), "estimate": estimate,
                        "router_m": router_m, "ssid": getattr(client, "ssid", "")})
        rank = {"area": 0, "near": 1}
        out.sort(key=lambda d: (rank.get(d["estimate"].kind if d["estimate"] else "", 2),
                                d["name"].lower()))
        return out

    def _names(self, clients: dict) -> dict[str, str]:
        tagger = next((p for p in getattr(self.ctx, "_all_plugins", [])
                       if hasattr(p, "tag_for")), None)
        try:
            hostnames = {lease.mac.upper(): lease.hostname for lease in self.router.dhcp_leases()}
        except Exception:
            hostnames = {}
        names = {}
        for mac in clients:
            tag = tagger.tag_for(mac) if tagger else None
            names[mac] = tag or hostnames.get(mac) or mac
        return names

    def _describe(self, place: dict) -> str:
        est: Estimate | None = place["estimate"]
        if est is None or (est.nearest == _ROUTER and est.anchors == 1):
            if place["router_m"] is None:
                return f"• {place['name']} — not heard right now"
            return f"• {place['name']} — about {place['router_m']:g} m from the router"
        anchor = self._anchors[est.nearest].name
        if est.kind == "area":
            return (f"📍 {place['name']} — near {anchor} (~{est.nearest_m:g} m), "
                    f"within about {est.radius_m:g} m")
        return f"◦ {place['name']} — near {anchor} (~{est.nearest_m:g} m)"

    # ─── Telegram ────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/where":
            self._show_list(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # locator:list | locator:map | locator:sensors
        verb = data.partition(":")[2]
        answer = getattr(self.notifier, "answer_callback", None)
        if verb == "map":
            if answer:
                answer(callback_id, "Drawing the map…")
            self._send_map(chat_id)
        elif verb == "sensors":
            if answer:
                answer(callback_id, "")
            self._show_sensors(chat_id, message_id)
        else:
            if answer:
                answer(callback_id, "Listening…")
            self._show_list(chat_id, message_id)

    def _buttons(self, current: str) -> list:
        name = self.ctx.name
        row = [{"text": "🔄 Refresh", "callback_data": f"{name}:list"}]
        if self._sensors:
            row.append({"text": "🗺 Map", "callback_data": f"{name}:map"})
            if current != "sensors":
                row.append({"text": "📡 Sensors", "callback_data": f"{name}:sensors"})
        return [row]

    def _show_list(self, chat_id: int, message_id: int | None) -> None:
        self.poll()
        try:
            places = self.places()
        except Exception as e:
            self.log.exception("locator: could not read the router")
            self._show(chat_id, message_id, f"❌ Could not ask the router: {e}", [])
            return
        lines = [f"📍 Where things are — {len(places)} WiFi devices", "━━━━━━━━━━━━━━━━━"]
        lines += [self._describe(p) for p in places] or ["No WiFi devices connected."]
        if not self._sensors:
            lines.append("\nNo WiFi sensors are set up yet, so this is only each device's "
                         "distance from the router (rough: walls count as extra metres). "
                         "With three sensors it becomes a map — see docs/LOCATOR.md.")
        else:
            down = [s.name for s in self._sensors
                    if not self._status.get(s.id, {}).get("ok")]
            if down:
                lines.append(f"\n⚠️ Not answering: {', '.join(down)} — positions are rougher.")
            lines.append("\n📍 placed by 3+ anchors · ◦ near one sensor · • router only "
                         "(5 GHz or out of the sensors' earshot)")
        self._show(chat_id, message_id, "\n".join(lines)[:3900], self._buttons("list"))

    def _show_sensors(self, chat_id: int, message_id: int | None) -> None:
        self.poll()
        model, origin = self.signal_model()
        lines = ["📡 WiFi sensors", "━━━━━━━━━━━━━━━━━"]
        for s in self._sensors:
            st = self._status.get(s.id, {})
            if st.get("ok"):
                up = st.get("uptime_s")
                uptime = f", up {up // 3600} h" if isinstance(up, int) else ""
                lines.append(f"✅ {s.name} — hears {st.get('heard', 0)} devices"
                             f"{uptime}, channel {st.get('channel', '?')}")
            else:
                lines.append(f"❌ {s.name} — {st.get('detail') or 'no answer yet'}")
        lines.append(f"\nSignal model: {origin} "
                     f"({model.rssi_at_1m:g} dBm at 1 m, exponent {model.exponent:g}).")
        self._show(chat_id, message_id, "\n".join(lines), self._buttons("sensors"))

    def _send_map(self, chat_id: int) -> None:
        self.poll()
        try:
            places = self.places()
            placed = [(p["name"], p["estimate"]) for p in places
                      if p["estimate"] and p["estimate"].kind == "area"]
            render.draw_map(self._map_file, self._width, self._height,
                            list(self._anchors.values()), placed, self._floor_image)
        except Exception as e:
            self.log.exception("locator: could not draw the map")
            self.notifier.send_to(chat_id, f"❌ Could not draw the map: {e}")
            return
        others = len(places) - len(placed)
        caption = (f"🗺 {len(placed)} devices placed"
                   + (f" · {others} more are only roughly known (see the list)" if others else "")
                   + "\nCircles show how unsure each position is.")
        self.notifier.send_to(chat_id, caption, photo_path=str(self._map_file),
                              buttons=self._buttons("map"))

    def _show(self, chat_id: int, message_id: int | None, text: str, buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons or None)

    # ─── /health ─────────────────────────────────────────────────

    def health(self) -> list[HealthCheck]:
        if not self._sensors:
            return []
        with self._lock:
            status = dict(self._status)
        if not status:
            return [HealthCheck("WiFi location sensors", True, "first check pending")]
        down = [f"{s.name}: {status[s.id].get('detail')}" for s in self._sensors
                if s.id in status and int(status[s.id].get("fails", 0)) >= 3]
        if down:
            return [HealthCheck("WiFi location sensors", False, "; ".join(down))]
        return [HealthCheck("WiFi location sensors", True,
                            f"{len(self._sensors)} sensors answering")]
