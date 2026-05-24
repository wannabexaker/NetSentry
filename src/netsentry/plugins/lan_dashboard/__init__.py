"""Mobile LAN traffic dashboard plugin."""

from __future__ import annotations

import json
import re
import secrets
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from flask import Flask, Response, abort, jsonify, render_template, request, send_file
from werkzeug.serving import BaseWSGIServer, make_server

from ...core.plugin import Plugin
from ...core.tag_store import TagStore


UNKNOWN_MAC = "(unknown MAC)"


def _norm_mac(value: str) -> str | None:
    return TagStore.normalize_mac(value)


@dataclass
class DeviceRecord:
    mac: str
    ip: str = ""
    hostname: str = ""
    name: str = ""
    retired: bool = False
    tx_bps: float = 0.0
    rx_bps: float = 0.0
    last_activity_ms: int = 999999999
    last_seen_ts: float = 0.0
    history: deque[dict[str, float]] = field(default_factory=deque)


class LanDashboardPlugin(Plugin):
    """Serve a live per-device LAN traffic dashboard."""

    COMMANDS: list[dict[str, str]] = []

    def on_load(self) -> None:
        self._bind_host = str(self.cfg.get("bind_host", "0.0.0.0"))
        self._bind_port = int(self.cfg.get("bind_port", 8088))
        self._poll_interval_s = max(0.5, float(self.cfg.get("poll_interval_s", 2.0)))
        self._history_samples = max(1, int(self.cfg.get("history_samples", 120)))
        self._token = secrets.token_urlsafe(16)

        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._devices: dict[str, DeviceRecord] = {}
        self._prev_wifi: dict[str, tuple[int, int, float]] = {}
        self._last_accounting_ts: float | None = None
        self._accounting_empty_warned = False

        self._app = self._build_app()
        self._server: BaseWSGIServer | None = None
        self._server_thread = threading.Thread(
            target=self._serve_http,
            daemon=True,
            name="lan_dashboard.http",
        )
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name="lan_dashboard.poll",
        )
        self._server_thread.start()
        self._poll_thread.start()

    def on_unload(self) -> None:
        """Stop polling and shut down the HTTP server."""
        self._stop.set()
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception as exc:
                self.log.warning("lan_dashboard HTTP shutdown failed: %s", exc)
        self._poll_thread.join(timeout=5)
        self._server_thread.join(timeout=5)

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        """Handle direct dispatch if this plugin receives /lan dashboard."""
        if command == "/lan" and args.strip().lower().split(maxsplit=1)[0:1] == ["dashboard"]:
            self.send_dashboard_link(chat_id)

    def send_dashboard_link(self, chat_id: int) -> None:
        """Send the tokenized dashboard URL to a Telegram chat."""
        host = self._discover_public_host()
        url = f"http://{host}:{self._bind_port}/?token={self._token}"
        text = f"LAN dashboard:\n{url}"
        if hasattr(self.notifier, "send_to"):
            self.notifier.send_to(chat_id, text)
        else:
            self.notifier.send(text)

    def _build_app(self) -> Flask:
        base = Path(__file__).parent
        app = Flask(
            __name__,
            template_folder=str(base / "templates"),
            static_folder=str(base / "static"),
            static_url_path="/static",
        )

        @app.get("/")
        def index() -> str:
            self._require_token()
            return render_template(
                "index.html",
                token=request.args.get("token", ""),
            )

        @app.get("/events")
        def events() -> Response:
            self._require_token()
            return Response(
                self._event_stream(),
                mimetype="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                },
            )

        @app.get("/brand/<path:filename>")
        def brand(filename: str) -> Response:
            self._require_token()
            safe = re.fullmatch(r"[a-zA-Z0-9_-]+\.png", filename)
            if not safe:
                abort(404)
            base = Path(__file__).resolve().parents[2] / "assets"
            path = base / filename
            if not path.exists():
                abort(404)
            return send_file(path, mimetype="image/png", max_age=3600)

        @app.post("/tag")
        def tag() -> Response:
            data = self._json_body()
            self._require_token(data)
            mac = _norm_mac(str(data.get("mac", "")))
            name = str(data.get("name", "")).strip()
            if not mac or mac == UNKNOWN_MAC:
                abort(400, "Invalid MAC")
            if not name:
                abort(400, "Name is required")
            self._write_tag(mac, name[:80])
            with self._lock:
                record = self._devices.get(mac)
                if record:
                    record.name = name[:80]
                    record.retired = False
            return jsonify({"ok": True, "mac": mac, "name": name[:80]})

        @app.post("/retire")
        def retire() -> Response:
            data = self._json_body()
            self._require_token(data)
            mac = _norm_mac(str(data.get("mac", "")))
            if not mac or mac == UNKNOWN_MAC:
                abort(400, "Invalid MAC")
            entry = self._retire_tag(mac)
            with self._lock:
                record = self._devices.get(mac)
                if record:
                    record.name = str(entry.get("name", record.name))
                    record.retired = True
            return jsonify({"ok": True, "mac": mac, "name": entry.get("name", "")})

        return app

    def _serve_http(self) -> None:
        try:
            self._server = make_server(
                self._bind_host,
                self._bind_port,
                self._app,
                threaded=True,
            )
            self.log.info(
                "lan_dashboard listening on %s:%d",
                self._bind_host,
                self._bind_port,
            )
            self._server.serve_forever()
        except Exception as exc:
            self.log.exception("lan_dashboard HTTP server failed: %s", exc)

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                self._poll_once(started)
            except Exception as exc:
                self.log.exception("lan_dashboard poll failed: %s", exc)
            wait_s = max(0.1, self._poll_interval_s - (time.time() - started))
            self._stop.wait(wait_s)

    def _poll_once(self, now: float) -> None:
        wifi_traffic = self._safe_call("wifi_traffic", [])
        wifi_clients = self._safe_call("wifi_clients", [])
        dhcp_leases = self._safe_call("dhcp_leases", [])
        arp_entries = self._safe_call("arp_table", [])
        accounting = self._safe_call("ip_accounting_snapshot", {})

        if not accounting and not self._accounting_empty_warned:
            self.log.warning(
                "IP accounting snapshot is empty. Wired traffic needs RouterOS "
                "accounting enabled: run '/ip accounting set enabled=yes' and "
                "'/ip accounting set threshold=10000'. Continuing with WiFi-only data."
            )
            self._accounting_empty_warned = True

        lease_by_mac = {l.mac: l for l in dhcp_leases}
        lease_by_ip = {l.ip: l for l in dhcp_leases if getattr(l, "ip", "")}
        arp_by_mac = {
            a.mac: a for a in arp_entries
            if getattr(a, "mac", "") and getattr(a, "complete", True)
        }
        ip_to_mac = {
            a.ip: a.mac for a in arp_entries
            if getattr(a, "ip", "") and getattr(a, "mac", "")
            and getattr(a, "complete", True)
        }
        wifi_activity = {
            c.mac: int(getattr(c, "last_activity_ms", 999999999))
            for c in wifi_clients
        }

        rates: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        for row in wifi_traffic:
            mac = row.mac.upper()
            prev = self._prev_wifi.get(mac)
            if prev is not None:
                prev_tx, prev_rx, prev_ts = prev
                elapsed = max(0.001, now - prev_ts)
                rates[mac][0] += max(0, row.tx_bytes - prev_tx) / elapsed
                rates[mac][1] += max(0, row.rx_bytes - prev_rx) / elapsed
            self._prev_wifi[mac] = (row.tx_bytes, row.rx_bytes, now)
            wifi_activity[mac] = int(row.last_activity_ms)

        accounting_elapsed = (
            max(0.001, now - self._last_accounting_ts)
            if self._last_accounting_ts is not None
            else self._poll_interval_s
        )
        self._last_accounting_ts = now
        unknown_ips: set[str] = set()
        for ip, byte_pair in accounting.items():
            tx_bytes, rx_bytes = byte_pair
            lease = lease_by_ip.get(ip)
            mac = ip_to_mac.get(ip) or (lease.mac if lease else None) or UNKNOWN_MAC
            rates[mac][0] += tx_bytes / accounting_elapsed
            rates[mac][1] += rx_bytes / accounting_elapsed
            if mac == UNKNOWN_MAC:
                unknown_ips.add(ip)

        tags = self._tags_snapshot()
        all_macs = set(rates) | set(lease_by_mac) | set(arp_by_mac) | set(wifi_activity)
        if unknown_ips:
            all_macs.add(UNKNOWN_MAC)

        with self._lock:
            for mac in all_macs:
                record = self._devices.get(mac)
                if record is None:
                    record = DeviceRecord(mac=mac, history=deque(maxlen=self._history_samples))
                    self._devices[mac] = record
                tx_bps, rx_bps = rates.get(mac, [0.0, 0.0])
                lease = lease_by_mac.get(mac)
                arp = arp_by_mac.get(mac)
                tag_name, retired = self._tag_info(mac, tags)
                record.tx_bps = tx_bps
                record.rx_bps = rx_bps
                record.ip = self._ip_for(mac, arp, lease, unknown_ips)
                record.hostname = getattr(lease, "hostname", "") if lease else ""
                record.name = tag_name
                record.retired = retired
                record.last_activity_ms = wifi_activity.get(mac, 999999999)
                record.last_seen_ts = now if tx_bps or rx_bps else record.last_seen_ts
                record.history.append({
                    "ts": now,
                    "tx_bps": tx_bps,
                    "rx_bps": rx_bps,
                })

            for mac, record in self._devices.items():
                if mac in all_macs:
                    continue
                record.tx_bps = 0.0
                record.rx_bps = 0.0
                record.last_activity_ms = 999999999
                record.history.append({"ts": now, "tx_bps": 0.0, "rx_bps": 0.0})

    def _snapshot_payload(self) -> dict[str, Any]:
        with self._lock:
            devices = [self._record_payload(record) for record in self._devices.values()]
        devices.sort(
            key=lambda d: (-(d["tx_bps"] + d["rx_bps"]), d["last_activity_ms"])
        )
        return {"ts": time.time(), "devices": devices}

    def _record_payload(self, record: DeviceRecord) -> dict[str, Any]:
        return {
            "mac": record.mac,
            "ip": record.ip,
            "hostname": record.hostname,
            "name": record.name,
            "retired": record.retired,
            "tx_bps": round(record.tx_bps, 2),
            "rx_bps": round(record.rx_bps, 2),
            "last_activity_ms": record.last_activity_ms,
            "active": record.last_activity_ms < 2000,
            "can_tag": record.mac != UNKNOWN_MAC,
        }

    def _event_stream(self) -> Iterator[str]:
        last_ping = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            if now - last_ping >= 15:
                yield ": ping\n\n"
                last_ping = now
            payload = json.dumps(self._snapshot_payload(), separators=(",", ":"))
            yield f"data: {payload}\n\n"
            self._stop.wait(1.0)

    def _safe_call(self, method: str, default: Any) -> Any:
        try:
            return getattr(self.router, method)()
        except Exception as exc:
            self.log.warning("%s failed: %s", method, exc)
            return default

    def _json_body(self) -> dict[str, Any]:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def _require_token(self, data: dict[str, Any] | None = None) -> None:
        supplied = request.args.get("token") or request.form.get("token")
        if supplied is None and data is not None:
            supplied = str(data.get("token", ""))
        if supplied != self._token:
            abort(403)

    def _discover_public_host(self) -> str:
        try:
            result = subprocess.run(
                ["tailscale", "ip", "-4"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                first = result.stdout.strip().splitlines()[0:1]
                if first and first[0].strip():
                    return first[0].strip()
        except Exception:
            pass
        try:
            host = socket.gethostbyname(socket.gethostname())
            if host:
                return host
        except Exception:
            pass
        return "0.0.0.0"

    def _lan_scanner(self) -> Any | None:
        for plugin in getattr(self.ctx, "_all_plugins", []):
            if getattr(plugin, "__class__", None).__name__ == "LanScannerPlugin":
                return plugin
        return None

    def _tags_snapshot(self) -> dict[str, Any]:
        scanner = self._lan_scanner()
        if scanner and hasattr(scanner, "tags_snapshot"):
            return scanner.tags_snapshot()
        path = self._fallback_tags_path()
        try:
            return TagStore(path).snapshot()
        except Exception as exc:
            self.log.warning("Could not read tag store %s: %s", path, exc)
            return {}

    def _write_tag(self, mac: str, name: str) -> None:
        scanner = self._lan_scanner()
        if scanner and hasattr(scanner, "set_tag"):
            scanner.set_tag(mac, name)
            return
        TagStore(self._fallback_tags_path()).set(mac, name, source="lan_dashboard")

    def _retire_tag(self, mac: str) -> dict[str, Any]:
        scanner = self._lan_scanner()
        if scanner and hasattr(scanner, "retire_tag"):
            return scanner.retire_tag(mac)
        return TagStore(self._fallback_tags_path()).retire(mac)

    def _fallback_tags_path(self) -> Path:
        return TagStore.fallback_lan_scanner_path()

    def _tag_info(self, mac: str, tags: dict[str, Any]) -> tuple[str, bool]:
        if mac == UNKNOWN_MAC:
            return "", False
        return TagStore.tag_info_from_snapshot(mac, tags)

    def _ip_for(self, mac: str, arp: Any, lease: Any, unknown_ips: set[str]) -> str:
        if mac == UNKNOWN_MAC:
            return ", ".join(sorted(unknown_ips)[:3])
        if arp and getattr(arp, "ip", ""):
            return str(arp.ip)
        if lease and getattr(lease, "ip", ""):
            return str(lease.ip)
        return ""

PLUGIN = LanDashboardPlugin
