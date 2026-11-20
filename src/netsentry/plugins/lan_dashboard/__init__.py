"""Mobile LAN traffic dashboard plugin."""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
)
from werkzeug.serving import BaseWSGIServer, make_server

from ... import __version__
from ...core import hostinfo, netscan
from ...core.plugin import HealthCheck, Plugin
from ...core.remote_input import RemoteError
from ...core.schedules import humanize_cron
from ...core.tag_store import TagStore


UNKNOWN_MAC = "(unknown MAC)"

# Session cookie that replaces the token-in-URL. The one-time token in the
# /auth link is exchanged for this HttpOnly cookie and stripped from the URL.
_COOKIE_NAME = "nsdash_session"
_SESSION_MAX_AGE = 12 * 3600

# The System page gathers from the router, Pi-hole and every plugin's health
# check; one gathering serves every open tab for this long.
_SYSTEM_CACHE_S = 30.0
_KEPT_REFRESH_S = 60.0
# Scheduled jobs worth showing to the owner, in display order.
_JOB_LABELS: list[tuple[str, str]] = [
    ("guest_wifi_rotator.rotate", "Guest WiFi password change"),
    ("morning_briefing.daily", "Morning briefing"),
    ("threat_detector.report", "Threat report"),
    ("traffic_report.daily", "Traffic report"),
    ("config_backup.weekly", "Router config backup"),
    ("self_backup.weekly", "NetSentry self-backup"),
    ("channel_scan.weekly", "WiFi channel scan"),
    ("threat_detector.intel", "Threat-feed refresh"),
    ("workstation.watch", "Gaming PC check"),
]

# The state pictures shipped with the package (1024 px, ~770 KB each). Home
# shows one, matching the verdict, from a small copy made once with Pillow.
_STATES_DIR = Path(__file__).resolve().parents[2] / "assets" / "states"
_STATE_PICTURES = ("protected", "scanning", "warning", "attack", "offline")
_STATE_PICTURE_PX = 256
_STATE_PICTURE_MAX_AGE = 7 * 86400
_PICTURE_LOCK = threading.Lock()
_VERDICT_PICTURE = {"ok": "protected", "review": "warning",
                    "attention": "warning", "attack": "attack"}
# How guest_wifi_rotator.api_status() writes its next/last times.
_GUEST_TIME_FORMAT = "%a %Y-%m-%d %H:%M"


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _local_ts(text: Any, fmt: str = _GUEST_TIME_FORMAT) -> float | None:
    """Epoch seconds for a local-time string, or None when it does not parse."""
    try:
        return datetime.strptime(str(text or "").strip(), fmt).timestamp()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def build_verdict(*, attacks: int, to_review: int,
                  problems: list[dict[str, Any]], unnamed: int) -> dict[str, Any]:
    """Home's answer to "is anything wrong / does anything need me?".

    Order of importance: an attack-level finding, then a monitor that stopped,
    then findings to review, then devices nobody has named yet. ``items`` are
    the (at most three) things to open, most important first; empty when ok.
    """
    items: list[dict[str, str]] = []
    if attacks:
        items.append({"label": _plural(attacks, "finding", "findings") + " at attack level",
                      "detail": "Open Threats and act on them", "href": "/threats"})
    if problems:
        first = problems[0]
        more = len(problems) - 1
        label = (f"{first['name']} is not working" if not more
                 else f"{first['name']} and {_plural(more, 'other', 'others')} are not working")
        items.append({"label": label, "detail": str(first.get("detail") or ""),
                      "href": "/system"})
    if to_review:
        items.append({"label": _plural(to_review, "finding", "findings") + " to review",
                      "detail": "Recent activity worth a look", "href": "/threats"})
    if unnamed:
        items.append({"label": _plural(unnamed, "unnamed device", "unnamed devices"),
                      "detail": "Name " + ("it" if unnamed == 1 else "them")
                                + " so a stranger stands out", "href": "/devices"})

    if attacks:
        level, headline = "attack", "Possible attack"
        reason = (_plural(attacks, "finding", "findings")
                  + " at attack level — act on " + ("it" if attacks == 1 else "them") + " now.")
    elif problems:
        level, headline = "attention", "Something stopped working"
        first = problems[0]
        reason = f"{first['name']} is not working" + (
            f": {first['detail']}" if first.get("detail") else ".")
    elif to_review:
        level = "review"
        headline = "Review " + _plural(to_review, "finding", "findings")
        reason = "Recent activity worth a look — nothing urgent."
    elif unnamed:
        # Naming devices is tidying up, not a fault: it must not turn Home amber
        # for good on a network with a few nameless gadgets. The row stays as a
        # nudge; the verdict is still "all clear".
        level, headline = "ok", "All clear"
        reason = ("No threats, every monitor running. "
                  + _plural(unnamed, "device has", "devices have") + " no name yet.")
    else:
        level, headline = "ok", "All clear"
        reason = "No threats, every monitor running, every device named."
    return {"level": level, "headline": headline, "reason": reason,
            "picture": _VERDICT_PICTURE[level], "items": items[:3]}


def _norm_mac(value: str) -> str | None:
    return TagStore.normalize_mac(value)


def _safe_next(nxt: str) -> str:
    """Whitelist the post-/auth redirect target to a known local dashboard path,
    so the ?next= deep-link param can't be abused for an open redirect."""
    nxt = (nxt or "/").strip()
    if re.fullmatch(r"/(finding/NS-[A-Z]+-\d+|threats|library|devices|system|remote)?", nxt):
        return nxt
    return "/"


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
    ssid: str = ""                 # WiFi network it is on now ("" = wired or away)
    band: str = ""
    signal_dbm: int | None = None
    history: deque[dict[str, float]] = field(default_factory=deque)


class LanDashboardPlugin(Plugin):
    """Serve a live per-device LAN traffic dashboard."""

    COMMANDS = [
        {"command": "dashboard", "description": "🖥 Open the live LAN dashboard"},
    ]

    def on_load(self) -> None:
        self._bind_host = self._resolve_bind_host(str(self.cfg.get("bind_host", "auto")))
        self._bind_port = int(self.cfg.get("bind_port", 8088))
        self._public_host = str(self.cfg.get("public_host", "auto"))
        # When set (e.g. https://host.tailnet.ts.net via `tailscale serve`),
        # the dashboard link is built from it so TLS is terminated upstream.
        self._public_base_url = str(self.cfg.get("public_base_url", "")).strip().rstrip("/")
        # Each poll performs ~5 sequential SSH logins to the router
        # (wifi traffic, wifi clients, DHCP leases, ARP table, IP accounting).
        # A too-small interval floods RouterOS with logins and can wedge it,
        # so the default is conservative and a hard floor caps the worst case
        # (~1 login/sec even if someone sets poll_interval_s: 0).
        self._poll_interval_s = max(3.0, float(self.cfg.get("poll_interval_s", 15.0)))
        self._history_samples = max(1, int(self.cfg.get("history_samples", 120)))
        self._token = self._load_or_create_token()

        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._devices: dict[str, DeviceRecord] = {}
        self._prev_wifi: dict[str, tuple[int, int, float]] = {}
        self._last_accounting_ts: float | None = None
        self._started_ts = time.time()
        self._last_poll_ok_ts = 0.0
        self._accounting_empty_warned = False
        # Once a past run has proven the legacy /ip accounting menu is absent
        # (RouterOS v7), skip the probe for good — otherwise every service
        # restart re-probes once and logs a "bad command name accounting" on
        # the router. The decision is remembered on disk across restarts.
        self._acct_marker = Path(self.ctx.state_dir) / "router_accounting_unavailable"
        self._accounting_off = self._acct_marker.exists()
        self._blocked: set[str] = set()      # MACs on a router reject list
        self._blocked_refresh_ts = 0.0
        self._kept: dict[str, str] = {}      # guest devices that keep their password
        self._kept_refresh_ts = 0.0
        self._system_cache: tuple[float, dict[str, Any]] | None = None
        self._system_lock = threading.Lock()
        self._nmap_bin = str(self.cfg.get("nmap_bin", "nmap"))
        self._scan_lock = threading.Lock()   # one on-demand nmap at a time

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
        """`/dashboard` (or `/lan dashboard`) → send the live dashboard link."""
        if command == "/dashboard":
            self.send_dashboard_link(chat_id)
        elif command == "/lan" and args.strip().lower().split(maxsplit=1)[0:1] == ["dashboard"]:
            self.send_dashboard_link(chat_id)

    def deep_link(self, path: str = "/") -> str:
        """A Telegram-clickable link that authenticates (cookie) then lands on
        ``path``. Empty when no TLS front (public_base_url) is configured — the
        raw loopback URL isn't reachable from a phone, so callers omit the link.
        """
        base = self._public_base_url
        if not base:
            return ""
        return f"{base}/auth?token={self._token}&next={path}"

    def explain_url(self, nsid: str) -> str:
        """Deep-link to a finding's explainer page (``/finding/<NS id>``)."""
        return self.deep_link(f"/finding/{nsid}") if nsid else ""

    def send_dashboard_link(self, chat_id: int) -> None:
        """Send the one-time /auth link to a Telegram chat.

        The token appears only in this /auth hop; the server exchanges it for
        an HttpOnly session cookie and redirects to a token-less URL, so it
        never lands in the page URL, browser history, or API request lines.
        """
        if self._public_base_url:
            url = f"{self._public_base_url}/auth?token={self._token}"
            note = ""
        else:
            host = self._discover_public_host()
            url = f"http://{host}:{self._bind_port}/auth?token={self._token}"
            note = (
                "\n⚠️ No TLS front (public_base_url) configured — set up "
                "`tailscale serve` for HTTPS."
            )
        text = f"LAN dashboard:\n{url}{note}"
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

        @app.get("/auth")
        def auth() -> Response:
            supplied = request.args.get("token", "")
            if not secrets.compare_digest(str(supplied), self._token):
                abort(403)
            resp = make_response(redirect(_safe_next(request.args.get("next", "/"))))
            secure = (
                request.is_secure
                or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
            )
            resp.set_cookie(
                _COOKIE_NAME,
                self._token,
                max_age=_SESSION_MAX_AGE,
                httponly=True,
                secure=secure,
                # Lax (not Strict): the login arrives as a top-level navigation
                # from the Telegram link, and Strict can drop the cookie on the
                # /auth→/ redirect in some in-app browsers. Lax still withholds
                # the cookie on cross-site POSTs, so the mutating endpoints
                # (all POST) keep their CSRF protection.
                samesite="Lax",
                path="/",
            )
            return resp

        @app.get("/")
        def home() -> str:
            self._require_auth()
            return render_template("overview.html")

        @app.get("/devices")
        def devices() -> str:
            self._require_auth()
            return render_template("index.html")

        @app.get("/api/overview")
        def api_overview() -> Response:
            self._require_auth()
            return jsonify(self._overview_snapshot())

        @app.get("/system")
        def system_page() -> str:
            self._require_auth()
            return render_template("system.html")

        @app.get("/api/system")
        def api_system() -> Response:
            self._require_auth()
            return jsonify(self._system_snapshot())

        @app.get("/events")
        def events() -> Response:
            self._require_auth()
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
            self._require_auth()
            safe = re.fullmatch(r"[a-zA-Z0-9_-]+\.png", filename)
            if not safe:
                abort(404)
            base = Path(__file__).resolve().parents[2] / "assets"
            path = base / filename
            if not path.exists():
                abort(404)
            return send_file(path, mimetype="image/png", max_age=3600)

        @app.get("/state/<name>.png")
        def state_picture(name: str) -> Response:
            # Only the five known names: nothing from the URL reaches a path.
            self._require_auth()
            if name not in _STATE_PICTURES:
                abort(404)
            path = self._state_picture(name)
            if path is None:
                abort(404)
            return send_file(path, mimetype="image/png", max_age=_STATE_PICTURE_MAX_AGE)

        @app.post("/tag")
        def tag() -> Response:
            data = self._json_body()
            self._require_auth()
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
            self._require_auth()
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

        @app.post("/block")
        def block() -> Response:
            data = self._json_body()
            self._require_auth()
            mac = _norm_mac(str(data.get("mac", "")))
            if not mac or mac == UNKNOWN_MAC:
                abort(400, "Invalid MAC")
            ok = bool(self.router.block_mac(mac, comment="Blocked from dashboard"))
            if ok:
                self._blocked.add(mac)  # optimistic; poll reconciles
            return jsonify({"ok": ok, "mac": mac, "blocked": ok})

        @app.post("/unblock")
        def unblock() -> Response:
            data = self._json_body()
            self._require_auth()
            mac = _norm_mac(str(data.get("mac", "")))
            if not mac or mac == UNKNOWN_MAC:
                abort(400, "Invalid MAC")
            ok = bool(self.router.unblock_mac(mac))
            if ok:
                self._blocked.discard(mac)
            return jsonify({"ok": ok, "mac": mac, "blocked": not ok})

        @app.post("/keep")
        def keep() -> Response:
            # A guest device keeps its password / follows the network again.
            data = self._json_body()
            self._require_auth()
            mac = _norm_mac(str(data.get("mac", "")))
            if not mac or mac == UNKNOWN_MAC:
                abort(400, "Invalid MAC")
            guest = self._plugin("guest_wifi_rotator")
            if guest is None or not hasattr(guest, "api_keep"):
                return jsonify({"ok": False, "state": "unavailable", "kept": False})
            state = str(guest.api_keep(mac, bool(data.get("on", True))))
            kept = dict(getattr(self, "_kept", {}))
            if state in ("added", "exists"):
                kept[mac] = kept.get(mac, "")
            elif state == "removed":
                kept.pop(mac, None)
            self._kept = kept                   # optimistic; the poll reconciles
            self._system_cache = None
            return jsonify({"ok": state in ("added", "exists", "removed"),
                            "state": state, "kept": mac in kept})

        # ─── threat / domain management (delegates to threat_detector) ──

        @app.get("/threats")
        def threats_page() -> str:
            self._require_auth()
            return render_template("threats.html")

        @app.get("/api/threats/domains")
        def api_threat_domains() -> Response:
            self._require_auth()
            t = self._threat()
            return jsonify(t.api_domains() if t else [])

        @app.get("/api/threats/summary")
        def api_threat_summary() -> Response:
            self._require_auth()
            t = self._threat()
            if not t:
                return jsonify({"scans": [], "intel": {}, "findings": []})
            return jsonify({
                "scans": t.api_scans(),
                "intel": t.api_intel(),
                "findings": t.api_recent_findings(),
            })

        @app.post("/api/threats/allow")
        def api_threat_allow() -> Response:
            data = self._json_body()
            self._require_auth()
            t = self._threat()
            if t:
                t.api_set_allow(str(data.get("domain", "")), bool(data.get("on", True)))
            return jsonify({"ok": True})

        @app.post("/api/threats/note")
        def api_threat_note() -> Response:
            data = self._json_body()
            self._require_auth()
            t = self._threat()
            if t:
                t.api_set_note(str(data.get("domain", "")), str(data.get("text", "")))
            return jsonify({"ok": True})

        @app.post("/api/threats/scan")
        def api_threat_scan() -> Response:
            data = self._json_body()
            self._require_auth()
            t = self._threat()
            ok = bool(t and t.api_set_scan(
                str(data.get("key", "")), bool(data.get("on", True))))
            return jsonify({"ok": ok})

        @app.post("/api/threats/intel-refresh")
        def api_threat_intel_refresh() -> Response:
            self._require_auth()
            t = self._threat()
            if t:
                t.refresh_feeds()
            return jsonify({"ok": True})

        # ─── finding explainer (Telegram deep-link target) ─────────

        @app.get("/finding/<fid>")
        def finding_page(fid: str) -> str:
            self._require_auth()
            return render_template("finding.html", fid=fid)

        @app.get("/api/taxonomy")
        def api_taxonomy() -> Response:
            self._require_auth()
            t = self._threat()
            return jsonify(t.api_taxonomy() if t else [])

        @app.get("/api/finding/<fid>")
        def api_finding(fid: str) -> Response:
            self._require_auth()
            t = self._threat()
            data = t.api_explainer(fid) if t else None
            if data is None:
                abort(404)
            return jsonify(data)

        # ─── on-demand nmap (scan a device/alert IP) ───────────────

        @app.post("/api/tools/nmap")
        def api_tools_nmap() -> Response:
            data = self._json_body()
            self._require_auth()
            ip = netscan.valid_ip(str(data.get("ip", "")))
            if not ip:
                return jsonify({"ok": False, "error": "private IPv4 only"})
            if not self._scan_lock.acquire(blocking=False):
                return jsonify({"ok": False, "error": "a scan is already running"})
            try:
                return jsonify(netscan.scan_ip_detail(ip, nmap_bin=self._nmap_bin))
            finally:
                self._scan_lock.release()

        # ─── library (saved YouTube videos + GitHub repos) ─────────

        @app.get("/library")
        def library_page() -> str:
            self._require_auth()
            return render_template("library.html")

        @app.get("/api/library/youtube")
        def api_library_youtube() -> Response:
            self._require_auth()
            p = self._plugin("youtube_bookmarks")
            return jsonify(p.api_bookmarks() if p else [])

        @app.get("/api/library/github")
        def api_library_github() -> Response:
            self._require_auth()
            p = self._plugin("github_explorer")
            return jsonify(p.api_repos() if p else [])

        self._add_remote_routes(app)
        return app

    # ─── remote keyboard and mouse (delegates to remote_keyboard) ──

    def _remote(self):
        """The remote-input controller when the remote_keyboard plugin is
        loaded and configured, else None (the page and its API then 404)."""
        plugin = self._plugin("remote_keyboard")
        return getattr(plugin, "remote", None) if plugin is not None else None

    def _add_remote_routes(self, app: Flask) -> None:
        """``/remote`` and ``/api/remote/*``. Auth comes first on every route;
        nothing typed is ever logged, stored or echoed back, and every
        response says ``no-store``. Input is a JSON POST only (the cookie's
        SameSite=Lax already keeps other sites out; a JSON body also needs a
        CORS preflight that this app never answers)."""

        @app.context_processor
        def remote_nav() -> dict[str, Any]:
            return {"remote_enabled": self._remote() is not None}

        @app.after_request
        def remote_no_store(resp: Response) -> Response:
            # Every answer under /remote, refusals and errors included.
            if request.path == "/remote" or request.path.startswith("/api/remote/"):
                resp.headers["Cache-Control"] = "no-store, max-age=0"
                resp.headers["Pragma"] = "no-cache"
                resp.headers["Referrer-Policy"] = "no-referrer"
                resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp

        def remote_or_404():
            self._require_auth()
            remote = self._remote()
            if remote is None:
                abort(404)
            return remote

        def answer(action) -> Response:
            remote = remote_or_404()
            try:
                return jsonify({"ok": True, "state": action(remote)})
            except RemoteError as exc:
                resp = jsonify({"ok": False, "error": exc.code, "message": exc.message,
                                "state": remote.status()})
                resp.status_code = exc.status
                return resp

        def json_input() -> dict[str, Any]:
            if not request.is_json:
                abort(415)
            return self._json_body()

        @app.get("/remote")
        def remote_page() -> str:
            remote = remote_or_404()
            return render_template("remote.html", idle_s=int(remote.idle_timeout_s),
                                   max_text=remote.max_text)

        @app.get("/api/remote/status")
        def api_remote_status() -> Response:
            return answer(lambda r: r.status())

        @app.post("/api/remote/arm")
        def api_remote_arm() -> Response:
            remote_or_404()
            json_input()
            return answer(lambda r: r.arm())

        @app.post("/api/remote/disarm")
        def api_remote_disarm() -> Response:
            # Any body (navigator.sendBeacon sends text/plain): disarming is the
            # safe direction and needs nothing from the request.
            return answer(lambda r: r.disarm())

        @app.post("/api/remote/key")
        def api_remote_key() -> Response:
            remote_or_404()
            data = json_input()
            return answer(lambda r: r.press_key(data.get("key"), data.get("mods")))

        @app.post("/api/remote/text")
        def api_remote_text() -> Response:
            remote_or_404()
            data = json_input()
            return answer(lambda r: r.type_text(data.get("text"),
                                                enter=data.get("enter") is True))

        @app.post("/api/remote/mouse")
        def api_remote_mouse() -> Response:
            remote_or_404()
            data = json_input()
            return answer(lambda r: r.mouse(
                data.get("dx", 0), data.get("dy", 0), data.get("wheel", 0),
                data.get("click"), double=data.get("double") is True))

    def _plugin(self, name: str):
        """Locate a sibling plugin instance by context name, if loaded."""
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(getattr(p, "ctx", None), "name", "") == name:
                return p
        return None

    def _threat(self):
        """Locate the threat_detector plugin instance, if loaded."""
        return self._plugin("threat_detector")

    def _state_picture(self, name: str) -> Path | None:
        """A phone-sized copy of a state picture, made once and kept in the
        plugin state dir. Without Pillow (or if resizing fails) the original
        is served; None when the picture is not shipped at all."""
        original = _STATES_DIR / f"{name}.png"
        if not original.is_file():
            return None
        small = Path(self.ctx.state_dir) / "state-pictures" / f"{name}-{_STATE_PICTURE_PX}.png"
        with _PICTURE_LOCK:
            try:
                if small.is_file() and small.stat().st_mtime >= original.stat().st_mtime:
                    return small
            except OSError:
                pass
            try:
                from PIL import Image
            except ImportError:
                return original
            try:
                small.parent.mkdir(parents=True, exist_ok=True)
                tmp = small.with_suffix(".tmp")
                with Image.open(original) as img:
                    img = img.convert("RGBA")
                    img.thumbnail((_STATE_PICTURE_PX, _STATE_PICTURE_PX), Image.LANCZOS)
                    img = img.quantize(colors=256, method=Image.Quantize.FASTOCTREE)
                    img.save(tmp, "PNG", optimize=True)
                os.replace(tmp, small)
                return small
            except Exception as exc:
                self.log.warning("lan_dashboard: cannot make a small %s picture (%s); "
                                 "serving the original", name, exc)
                return original

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

    def health(self) -> list[HealthCheck]:
        limit = max(120.0, 5 * self._poll_interval_s)
        age = time.time() - (self._last_poll_ok_ts or self._started_ts)
        if age > limit:
            return [HealthCheck("Live device dashboard", False,
                                f"no successful router poll for {int(age // 60)} min")]
        return [HealthCheck("Live device dashboard", True,
                            f"polling every {self._poll_interval_s:g}s")]

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                self._poll_once(started)
                self._last_poll_ok_ts = time.time()
            except Exception as exc:
                self.log.exception("lan_dashboard poll failed: %s", exc)
            wait_s = max(0.1, self._poll_interval_s - (time.time() - started))
            self._stop.wait(wait_s)

    def _poll_once(self, now: float) -> None:
        wifi_traffic = self._safe_call("wifi_traffic", [])
        wifi_clients = self._safe_call("wifi_clients", [])
        dhcp_leases = self._safe_call("dhcp_leases", [])
        arp_entries = self._safe_call("arp_table", [])
        if self._accounting_off:
            accounting = {}
        else:
            accounting = self._safe_call("ip_accounting_snapshot", {})
            # The router has confirmed (bad-command signature or repeated empty
            # snapshots) that the legacy menu is gone — persist that so we never
            # probe again, keeping the router log clean across restarts.
            if getattr(self.router, "_accounting_unavailable", False):
                self._accounting_off = True
                try:
                    self._acct_marker.write_text("1", encoding="utf-8")
                except OSError:
                    pass

        # Refresh the blocked-MAC set on a slow cadence (an extra SSH per poll
        # would be wasteful at the 2s traffic interval); block/unblock actions
        # also update it optimistically for instant UI feedback.
        if now - self._blocked_refresh_ts >= 15.0:
            self._blocked = set(self._safe_call("blocked_macs", set()) or set())
            self._blocked_refresh_ts = now
        if (now - self._kept_refresh_ts >= _KEPT_REFRESH_S
                and self._plugin("guest_wifi_rotator") is not None):
            kept = self._safe_call("kept_wifi_passphrases", None)
            if isinstance(kept, dict):          # unreadable: keep what we knew
                self._kept = kept
            self._kept_refresh_ts = now

        if not accounting and not self._accounting_empty_warned:
            self.log.warning(
                "IP accounting snapshot is empty — the legacy /ip accounting menu is "
                "absent on RouterOS v7 (wifi-qcom), so per-device wired traffic is "
                "unavailable on this router. Continuing with WiFi-only data. "
                "(On RouterOS v6 it can be enabled with '/ip accounting set enabled=yes'.)"
            )
            self._accounting_empty_warned = True

        lease_by_mac = {lease.mac: lease for lease in dhcp_leases}
        lease_by_ip = {
            lease.ip: lease for lease in dhcp_leases if getattr(lease, "ip", "")
        }
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
        wifi_by_mac = {c.mac: c for c in wifi_clients}

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
                wifi = wifi_by_mac.get(mac)
                record.ssid = str(getattr(wifi, "ssid", "") or "") if wifi else ""
                record.band = str(getattr(wifi, "band", "") or "") if wifi else ""
                signal = getattr(wifi, "signal_dbm", None) if wifi else None
                record.signal_dbm = signal if isinstance(signal, int) and signal < 0 else None
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
                record.ssid, record.band, record.signal_dbm = "", "", None
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
            "blocked": record.mac in self._blocked,
            "ssid": record.ssid,
            "band": record.band,
            "signal": record.signal_dbm,
            "guest": bool(record.ssid) and record.ssid == self._guest_ssid(),
            "kept": record.mac in getattr(self, "_kept", {}),
        }

    def _guest_ssid(self) -> str:
        guest = self._plugin("guest_wifi_rotator")
        cfg = getattr(guest, "cfg", None)
        return str(cfg.get("ssid", "")) if isinstance(cfg, dict) else ""

    def _overview_snapshot(self) -> dict[str, Any]:
        """One-shot aggregate for the home page (devices + threats + library)."""
        with self._lock:
            recs = list(self._devices.values())
        real = [r for r in recs if r.mac != UNKNOWN_MAC]
        top = None
        if real:
            t = max(real, key=lambda r: r.tx_bps + r.rx_bps)
            rate = round(t.tx_bps + t.rx_bps, 2)
            if rate > 0:
                top = {"label": t.name or t.hostname or t.mac, "rate_bps": rate}
        on_network: dict[str, int] = defaultdict(int)
        for r in real:
            if r.ssid:
                on_network[r.ssid] += 1
        unnamed = sum(1 for r in real if not r.name)
        devices = {
            "total": len(real),
            "active": sum(1 for r in real if r.last_activity_ms < 2000),
            "untagged": unnamed,                # kept for older readers
            "unnamed": unnamed,
            "blocked": len(self._blocked),
            "top": top,
            "networks": [{"name": name, "count": count}
                         for name, count in sorted(on_network.items())],
        }

        det = self._threat()
        attacks = 0
        if det:
            findings = det.api_recent_findings()
            attacks = sum(1 for f in findings if f.get("severity") == "attack")
            if attacks:
                worst = "attack"
            elif any(f.get("severity") == "warning" for f in findings):
                worst = "warning"
            elif findings:
                worst = "info"
            else:
                worst = "none"
            threats = {
                "findings": len(findings),
                "worst": worst,
                "domains": len(det.api_domains()),
                "intel": int(det.api_intel().get("count", 0)),
            }
        else:
            threats = {"findings": 0, "worst": "none", "domains": 0, "intel": 0}

        yt = self._plugin("youtube_bookmarks")
        gh = self._plugin("github_explorer")
        library = {
            "youtube": len(yt.api_bookmarks()) if yt else 0,
            "github": len(gh.api_repos()) if gh else 0,
        }
        system = self._system_snapshot()
        health = system.get("health")
        problems = list(health["problems"]) if health else []
        return {
            "devices": devices, "threats": threats, "library": library,
            "health": ({"total": len(health["checks"]), "problems": len(health["problems"]),
                        "first": (health["problems"][0]["name"] if health["problems"] else "")}
                       if health else None),
            "guest": system.get("guest"),
            "verdict": build_verdict(attacks=attacks, to_review=threats["findings"] - attacks,
                                     problems=problems, unnamed=unnamed),
            # Tab badges count only what needs the owner; Library has none.
            "badges": {"threats": threats["findings"], "system": len(problems),
                       "devices": unnamed},
        }

    # ─── the System page ─────────────────────────────────────────

    def _system_snapshot(self) -> dict[str, Any]:
        """Health, router, Pi-hole, schedule and guest WiFi — gathered at most
        once per ``_SYSTEM_CACHE_S`` however many tabs are open."""
        lock = getattr(self, "_system_lock", None) or threading.Lock()
        with lock:
            cached = getattr(self, "_system_cache", None)
            if cached and time.time() - cached[0] < _SYSTEM_CACHE_S:
                return cached[1]
            snapshot = {
                "ts": time.time(),
                "version": __version__,
                "running_since": getattr(self, "_started_ts", 0.0),
                "health": self._system_part(self._health_part),
                "router": self._system_part(self._router_part),
                "pihole": self._system_part(self._pihole_part),
                "jobs": self._system_part(self._jobs_part) or [],
                "guest": self._system_part(self._guest_part),
                "pc": self._system_part(self._pc_part),
            }
            self._system_cache = (time.time(), snapshot)
            return snapshot

    def _system_part(self, part) -> Any:
        """One section of the page; a section that fails is left out, not fatal."""
        try:
            return part()
        except Exception:
            self.log.exception("System page: %s failed", getattr(part, "__name__", "section"))
            return None

    def _health_part(self) -> dict[str, Any] | None:
        checker = self._plugin("self_check")
        if checker is None or not hasattr(checker, "checks"):
            return None
        checks = [{"name": str(c.name), "ok": bool(c.ok), "detail": str(c.detail or "")}
                  for c in checker.checks()]
        checks.sort(key=lambda c: (c["ok"], c["name"].lower()))
        return {"checks": checks, "problems": [c for c in checks if not c["ok"]]}

    def _router_part(self) -> dict[str, Any] | None:
        stats = self.router.stats()
        uptime = getattr(stats, "uptime_seconds", None)
        if not isinstance(uptime, int):
            return None
        total = int(stats.total_memory_bytes) or 1
        return {
            "uptime_s": uptime,
            "cpu_pct": int(stats.cpu_load_pct),
            "memory_pct": round(100 * (1 - int(stats.free_memory_bytes) / total)),
            "version": str(stats.routeros_version),
            "board": str(stats.board_name),
        }

    def _pihole_part(self) -> dict[str, Any] | None:
        pihole = self._plugin("pihole_stats")
        today = pihole.api_today() if pihole and hasattr(pihole, "api_today") else None
        return today if isinstance(today, dict) else None

    def _jobs_part(self) -> list[dict[str, Any]]:
        sched = getattr(self.ctx, "scheduler", None)
        if sched is None or not hasattr(sched, "schedule_of"):
            return []
        stats = sched.job_stats()
        jobs = []
        for name, label in _JOB_LABELS:
            info = sched.schedule_of(name)
            if not isinstance(info, dict):
                continue
            st = stats.get(name, {})
            nxt = info.get("next_run")
            if st.get("last_error"):
                last = "failed"
            elif st.get("last_ok"):
                last = "ok"
            else:
                last = ""                       # has not run since NetSentry started
            jobs.append({
                "label": label,
                "schedule": "paused" if info.get("paused") else humanize_cron(str(info["cron"])),
                "paused": bool(info.get("paused")),
                "next": nxt.strftime("%a %d %b %H:%M") if nxt else "",
                "next_ts": self._epoch(nxt),
                "last": last,
                "last_ts": float(st.get("last_ok") or st.get("last_start") or 0.0),
                "error": str(st.get("last_error") or ""),
            })
        return jobs

    def _guest_part(self) -> dict[str, Any] | None:
        guest = self._plugin("guest_wifi_rotator")
        if guest is None or not hasattr(guest, "api_status"):
            return None
        status = dict(guest.api_status())
        # The rotator writes "Mon 2026-11-23 09:00"; the page shows every time
        # in one format, so hand it the moment as epoch seconds too.
        status["next_ts"] = _local_ts(status.get("next"))
        status["last_ts"] = _local_ts(status.get("last"))
        kept = dict(getattr(self, "_kept", {}))
        with self._lock:
            records = {mac: self._devices.get(mac) for mac in kept}
        status["kept"] = sorted((
            {"mac": mac,
             "name": (getattr(records[mac], "name", "") or getattr(records[mac], "hostname", "")
                      or label or mac),
             "online": bool(getattr(records[mac], "ssid", ""))}
            for mac, label in kept.items()), key=lambda d: d["name"].lower())
        return status

    def _pc_part(self) -> dict[str, Any] | None:
        """The gaming PC (workstation plugin): read-only. Its api_status() never
        waits for ssh, so the page never does either."""
        pc = self._plugin("workstation")
        if pc is None or not hasattr(pc, "api_status"):
            return None
        status = pc.api_status()
        return dict(status) if isinstance(status, dict) else None

    @staticmethod
    def _epoch(moment: Any) -> float | None:
        try:
            return float(moment.timestamp()) if moment else None
        except (AttributeError, OverflowError, OSError, ValueError):
            return None

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

    def _load_or_create_token(self) -> str:
        """A stable dashboard token that survives restarts.

        Persisting it in the plugin state dir means a deploy, reboot, or crash
        no longer invalidates the owner's session cookie and last `/auth` link
        (which was the cause of surprise 403s). File is owner-only (0600).
        """
        path = Path(self.ctx.state_dir) / "dashboard_token"
        try:
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except FileNotFoundError:
            pass
        except OSError as exc:
            self.log.warning("lan_dashboard: cannot read token file (%s); using ephemeral", exc)
            return secrets.token_urlsafe(16)

        token = secrets.token_urlsafe(16)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(token, encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # non-POSIX filesystem — content is still owner-scoped by dir perms
        except OSError as exc:
            self.log.warning("lan_dashboard: cannot persist token (%s); ephemeral this run", exc)
        return token

    def _require_auth(self) -> None:
        """Authorize via the HttpOnly session cookie (set by /auth).

        The token no longer travels in request URLs or bodies — only in the
        one-time /auth hop — so it cannot leak through history, referrers, or
        access logs.
        """
        supplied = request.cookies.get(_COOKIE_NAME, "")
        if not secrets.compare_digest(str(supplied), self._token):
            abort(403)

    def _resolve_bind_host(self, configured: str) -> str:
        configured = configured.strip()
        if configured and configured.lower() != "auto":
            return configured
        return self._tailscale_ipv4() or "127.0.0.1"

    def _discover_public_host(self) -> str:
        configured = self._public_host.strip()
        if configured and configured.lower() != "auto":
            return configured
        if self._bind_host not in {"0.0.0.0", "::", "127.0.0.1", "localhost"}:  # nosec B104
            return self._bind_host
        tailscale_ip = self._tailscale_ipv4()
        if tailscale_ip:
            return tailscale_ip
        try:
            host = socket.gethostbyname(socket.gethostname())
            if host:
                return host
        except Exception:
            pass
        return "127.0.0.1"

    def _tailscale_ipv4(self) -> str | None:
        return hostinfo.tailscale_ipv4()

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
