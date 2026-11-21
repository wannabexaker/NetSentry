"""
site_watch — are your web apps up?

The owner's web apps run beside NetSentry, each behind its own tunnel, and each
answers a small health address (``/healthz``: ``{"ok": true, "status": "ok",
"version": "…", "commit": "…"}``, or 503 when its database is down). This
plugin asks every one of them on a schedule and tells you when one goes down,
when it is back, and when a new version has landed.

Commands:
    /sites      one line per site; buttons: check now, per-site detail

Config keys:
    interval_minutes   how often to check (default 5)
    timeout_s          per request (default 10)
    fail_after         bad readings in a row before alerting (default 2)
    sites              list of {name, url, fallback_url?, paused?}

A site is good when it answers HTTP 200 and — if the answer is JSON — it does
not say ``"ok": false`` and its ``status`` (when present) is ok/healthy/up. A
200 HTML page counts as up (the site answers, it just has no health data).
``fallback_url`` is asked when ``url`` answers 404, so a site that has no
``/healthz`` yet can still be watched; ``/sites`` shows which ones still lack it.

A paused site is listed and checked but never alerts (a demo stopped on
purpose). Requests go over IPv4 only: the host may have an IPv6 address
without an IPv6 route.

With the self-check watchdog loaded, down and recovery are reported through
``health()`` and the watchdog sends the one alert; without it this plugin
alerts itself. The "new version" line is always this plugin's.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..core import notify, ui
from ..core.jsonstore import read_json, write_json
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_GOOD_STATUS = {"ok", "healthy", "up", "pass"}
_BAD_VALUES = {"down", "error", "fail", "failed", "failing", "unhealthy",
               "degraded", "not ok", "not_ok", "unavailable"}
_META_KEYS = {"ok", "status", "version", "commit", "checks", "time", "timestamp",
              "uptime", "service", "name"}
_BODY_MAX = 64 * 1024
_ICON = "🛰"
_PAUSED = "⏸"
_UNCHECKED = "▫️"

# (status, body, content type) — raises OSError / urllib.error.URLError when
# nothing answered.
Fetch = Callable[[str, float], "tuple[int, bytes, str]"]


# ─── HTTP over IPv4 ──────────────────────────────────────────────────

def _ipv4_connection(address: tuple[str, int], timeout: Any = None,
                     source_address: Any = None, *_: Any, **__: Any) -> socket.socket:
    """``socket.create_connection`` that only tries IPv4 addresses."""
    host, port = address
    error: OSError | None = None
    for family, socktype, proto, _canon, addr in socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_STREAM):
        sock = socket.socket(family, socktype, proto)
        try:
            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(addr)
            return sock
        except OSError as e:
            error = e
            sock.close()
    raise error or OSError(f"no IPv4 address for {host}")


class _IPv4HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _ipv4_connection


class _IPv4HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _ipv4_connection


class _IPv4HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_IPv4HTTPConnection, req)


class _IPv4HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_IPv4HTTPSConnection, req,
                            context=getattr(self, "_context", None))


_OPENER = urllib.request.build_opener(_IPv4HTTPHandler, _IPv4HTTPSHandler)


def fetch(url: str, timeout: float) -> tuple[int, bytes, str]:
    """GET ``url``; an HTTP error status is an answer, not an exception."""
    req = urllib.request.Request(url, headers={
        "User-Agent": f"NetSentry/{__version__} site-watch",
        "Accept": "application/json, text/html;q=0.8, */*;q=0.5"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:  # nosec B310 - http(s) only, checked in config
            return r.status, r.read(_BODY_MAX), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(_BODY_MAX)
        except Exception:
            body = b""
        return e.code, body, (e.headers.get("Content-Type", "") if e.headers else "")


# ─── one reading ─────────────────────────────────────────────────────

@dataclass
class Reading:
    ok: bool
    reason: str = ""            # one line when not ok
    via: str = "healthz"        # "healthz" (url answered) | "fallback" | "page" (no health route expected)
    kind: str = ""              # "json" | "html" | "" (no answer)
    status: int = 0             # HTTP status; 0 = no answer
    version: str = ""
    commit: str = ""
    elapsed: float = 0.0        # seconds
    severe: bool = False        # nothing answered, or a 5xx
    at: float = 0.0

    @property
    def no_healthz(self) -> bool:
        return self.ok and (self.via == "fallback" or (self.kind == "html" and self.via != "page"))


def _failure_reason(error: BaseException, timeout: float) -> str:
    reason = getattr(error, "reason", error)
    if isinstance(reason, (TimeoutError, socket.timeout)) or "timed out" in str(reason):
        return f"timeout after {timeout:g} s"
    if isinstance(reason, socket.gaierror):
        return "name not found (DNS)"
    if isinstance(reason, ConnectionRefusedError):
        return "connection refused"
    if "CERTIFICATE" in str(reason).upper() or "SSL" in type(reason).__name__.upper():
        return "TLS certificate problem"
    return "no connection"


def _short(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    return text[:limit]


def _failing_parts(data: dict) -> list[str]:
    """Names of sub-checks that say they are not fine (``"db": "down"``,
    ``"checks": {"database": false}``)."""
    out: list[str] = []
    nested = data.get("checks")
    pairs = list(nested.items()) if isinstance(nested, dict) else []
    pairs += [(k, v) for k, v in data.items() if k not in _META_KEYS]
    for key, value in pairs:
        if value is False or (isinstance(value, str) and value.strip().lower() in _BAD_VALUES):
            out.append(str(key))
        elif isinstance(value, dict) and (value.get("ok") is False or str(
                value.get("status", "")).strip().lower() in _BAD_VALUES):
            out.append(str(key))
    return out


def _parse_json(body: bytes, content_type: str) -> dict | None:
    text = body.decode("utf-8", "replace").strip()
    if "json" not in content_type.lower() and not text.startswith("{"):
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def evaluate(status: int, body: bytes, content_type: str) -> Reading:
    """Judge one HTTP answer (no network)."""
    data = _parse_json(body, content_type)
    reading = Reading(ok=False, status=status, kind="json" if data is not None else "html")
    if data is not None:
        reading.version = _short(data.get("version"), 40)
        reading.commit = _short(data.get("commit"), 12)
    parts = _failing_parts(data) if data is not None else []
    if status != 200:
        reading.severe = status >= 500
        reading.reason = f"HTTP {status}" + (f", {', '.join(parts)} not ok" if parts else "")
        return reading
    if data is not None:
        state = data.get("status")
        if data.get("ok") is False or (
                state is not None and str(state).strip().lower() not in _GOOD_STATUS):
            reading.reason = (f"{', '.join(parts)} not ok" if parts
                              else f"says status {_short(state, 20)!r}" if state is not None
                              else "says it is not ok")
            return reading
    reading.ok = True
    return reading


# ─── the plugin ──────────────────────────────────────────────────────

class SiteWatchPlugin(Plugin):
    COMMANDS = [
        {"command": "sites", "description": "🛰 Your web sites, up or down"},
    ]

    def on_load(self) -> None:
        self._interval_min = max(1, int(self.cfg.get("interval_minutes", 5)))
        self._timeout = max(1.0, float(self.cfg.get("timeout_s", 10)))
        self._fail_after = max(1, int(self.cfg.get("fail_after", 2)))
        self._sites = self._read_sites(self.cfg.get("sites") or [])
        self._state_file = Path(self.ctx.state_dir) / "state.json"
        self._lock = threading.Lock()          # one round of checks at a time
        self._fetch: Fetch = fetch
        self._clock: Callable[[], float] = time.time
        self._spawn: Callable[..., None] = self._in_thread
        self._state: dict[str, Any] = read_json(self._state_file, {})
        self._handed: list[str] = []           # checks handed to the watchdog this round

    def _read_sites(self, raw: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in raw if isinstance(raw, list) else []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            url = str(entry.get("url") or "").strip()
            fallback = str(entry.get("fallback_url") or "").strip()
            if not name or not _is_http(url) or (fallback and not _is_http(fallback)):
                self.log.warning("site_watch: skipping site %r — needs a name and an "
                                 "http(s) url", name or url)
                continue
            if name in seen:
                self.log.warning("site_watch: site name %r used twice; keeping the first", name)
                continue
            seen.add(name)
            out.append({"name": name, "url": url, "fallback_url": fallback,
                        "paused": bool(entry.get("paused", False))})
        return out

    def scheduled_tasks(self) -> list[ScheduledTask]:
        if not self._sites:
            return []
        n = self._interval_min
        cron = f"*/{n} * * * *" if n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [ScheduledTask(cron=cron, func=self.run_checks, name="checks")]

    # ─── checking ────────────────────────────────────────────────

    def check_site(self, site: dict[str, Any]) -> Reading:
        reading = self._ask(site["url"])
        if reading.status == 404 and site.get("fallback_url"):
            reading = self._ask(site["fallback_url"])
            reading.via = "fallback"
        elif not site.get("fallback_url") and not _expects_healthz(site["url"]):
            reading.via = "page"        # a static page: no "/healthz yet" note
        reading.at = self._clock()
        return reading

    def _ask(self, url: str) -> Reading:
        started = time.monotonic()
        try:
            status, body, content_type = self._fetch(url, self._timeout)
        except Exception as e:      # any failure to get an answer is a reading
            self.log.info("site_watch: %s did not answer: %s", url, e)
            return Reading(ok=False, reason=_failure_reason(e, self._timeout), severe=True,
                           elapsed=time.monotonic() - started)
        reading = evaluate(status, body, content_type)
        reading.elapsed = time.monotonic() - started
        return reading

    def run_checks(self) -> None:
        """One round: every site, one after the other; then alert / recover.

        The plugin always sends the "down" message itself, after ``fail_after``
        readings, and hands the check to the watchdog (``notify.report_problem``)
        so that one sends no second alert. The recovery comes from the watchdog
        when it is loaded, from this plugin otherwise.
        """
        with self._lock:
            speak = not notify.watchdog_loaded(self.ctx)
            self._handed = []
            sites_state = dict(self._state.get("sites", {}))
            messages: list[tuple[str, str, list | None]] = []
            for site in self._sites:
                try:
                    reading = self.check_site(site)
                except Exception:
                    self.log.exception("site_watch: checking %s failed", site["name"])
                    continue
                entry = dict(sites_state.get(site["name"], {}))
                messages += self._apply(site, entry, reading, speak)
                sites_state[site["name"]] = entry
            names = {s["name"] for s in self._sites}
            self._state = {"sites": {k: v for k, v in sites_state.items() if k in names},
                           "last_run": self._clock()}
            try:
                write_json(self._state_file, self._state)
            except OSError:
                self.log.exception("site_watch: could not save state")
        for kind, text, buttons in messages:
            self._notify(kind, text, buttons)
        for check in self._handed:
            notify.report_problem(self.ctx, check)

    def _apply(self, site: dict[str, Any], entry: dict[str, Any], reading: Reading,
               speak: bool) -> list[tuple[str, str, list | None]]:
        """Fold one reading into the site's state; the messages it calls for."""
        out: list[tuple[str, str, list | None]] = []
        name, paused = site["name"], site["paused"]
        was_bad = int(entry.get("streak", 0)) > 0
        first = "last" not in entry
        if reading.ok:
            if was_bad or first:
                entry["since"] = reading.at
            if entry.pop("alerted", False) and not paused and speak:
                lasted = reading.at - float(entry.get("since_bad", reading.at))
                out.append((notify.RECOVERY,
                            f"{ui.OK} Back to normal: {name} (down {ui.duration(lasted)})",
                            None))
            entry["streak"] = 0
            entry.pop("since_bad", None)
            out += self._version_note(name, entry, reading, paused)
        else:
            if not was_bad:
                entry["since"] = entry["since_bad"] = reading.at
            entry["streak"] = int(entry.get("streak", 0)) + 1
            if (not paused and not entry.get("alerted")
                    and entry["streak"] >= self._fail_after):
                entry["alerted"] = True
                out.append(self._down_message(site, entry, reading))
                self._handed.append(f"Site: {name}")
        entry["last"] = asdict(reading)
        return out

    def _version_note(self, name: str, entry: dict[str, Any], reading: Reading,
                      paused: bool) -> list[tuple[str, str, list | None]]:
        old = (entry.get("version", ""), entry.get("commit", ""))
        new = (reading.version, reading.commit)
        if not any(new):
            return []
        entry["version"], entry["commit"] = new
        if paused or not any(old) or old == new:
            return []
        runs = " ".join(p for p in (_v(reading.version),
                                    f"({reading.commit})" if reading.commit else "") if p)
        return [(notify.INFO, f"{ui.INFO} {name} now runs {runs}", None)]

    def _down_message(self, site: dict[str, Any], entry: dict[str, Any],
                      reading: Reading) -> tuple[str, str, list | None]:
        since = self._since(float(entry.get("since_bad", reading.at)))
        # ATTENTION, not URGENT: these sites are demos (owner, 2026-11-21) —
        # worth knowing, not worth waking anyone.
        kind = notify.ATTENTION
        if reading.severe:
            head = ui.header(ui.ATTENTION, site["name"], "down")
        else:
            head = ui.header(ui.ATTENTION, site["name"], "not healthy")
        text = (f"{head}\n{reading.reason} {since} · "
                f"{ui.plural(int(entry['streak']), 'check')} in a row.")
        return kind, text, [[ui.button(f"{_ICON} All sites", f"{self.ctx.name}:n")]]

    # ─── health / briefing ───────────────────────────────────────

    def health(self) -> list[HealthCheck]:
        out = []
        sites_state = self._state.get("sites", {})
        for site in self._sites:
            if site["paused"]:
                continue
            entry = sites_state.get(site["name"], {})
            last = entry.get("last")
            name = f"Site: {site['name']}"
            if not last:
                out.append(HealthCheck(name, True, "not checked yet"))
            elif int(entry.get("streak", 0)) >= self._fail_after:
                out.append(HealthCheck(name, False, f"{last.get('reason') or 'not ok'} "
                                       f"{self._since(float(entry.get('since_bad', 0)))}"))
            else:
                out.append(HealthCheck(name, True, self._good_detail(last)))
        return out

    def _good_detail(self, last: dict[str, Any]) -> str:
        if not last.get("ok"):
            return f"{last.get('reason') or 'not ok'} (re-checking)"
        reading = _reading(last)
        bits = ["ok", _v(reading.version), reading.commit, f"{reading.elapsed:.1f} s"]
        if reading.no_healthz:
            bits.append("no /healthz yet")
        return " · ".join(b for b in bits if b)

    def summary_line(self) -> str:
        """One line for the morning briefing."""
        if not self._sites:
            return ""
        counts = self._counts()
        bad = counts["down"] + counts["failing"]
        tail = [f"{len(counts['up'])} up"] if counts["up"] else []
        if counts["paused"]:
            tail.append(f"{counts['paused']} paused")
        if bad:
            names = ui.first_few(bad, 3)
            return f"{_ICON} Sites: {ui.ATTENTION} {names} not ok" + (
                f" · {' · '.join(tail)}" if tail else "")
        return f"{_ICON} Sites: " + (" · ".join(tail) or "not checked yet")

    def _counts(self) -> dict[str, Any]:
        sites_state = self._state.get("sites", {})
        out: dict[str, Any] = {"up": [], "down": [], "failing": [], "paused": 0,
                               "unchecked": 0, "severe": False}
        for site in self._sites:
            entry = sites_state.get(site["name"], {})
            last = entry.get("last")
            if site["paused"]:
                out["paused"] += 1
            elif not last:
                out["unchecked"] += 1
            elif last.get("ok"):
                out["up"].append(site["name"])
            elif int(entry.get("streak", 0)) >= self._fail_after:
                out["down"].append(site["name"])
                out["severe"] = out["severe"] or bool(last.get("severe"))
            else:
                out["failing"].append(site["name"])
        return out

    # ─── /sites ──────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/sites":
            return
        if self._sites and "last_run" not in self._state:
            self.run_checks()          # first look: check before showing nothing
        self.notifier.send_to(chat_id, self.screen(), buttons=self._buttons())

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # site_watch:s (redraw) | :c (check now) | :d:<i> (detail) | :n (new message)
        verb, _, arg = data.partition(":")[2].partition(":")
        if verb == "c":
            self._ack(callback_id, "Checking…")
            self._edit(chat_id, message_id,
                       f"{ui.WORKING} Checking {ui.plural(len(self._sites), 'site')}…", None)
            self._spawn(self._check_and_show, chat_id, message_id)
        elif verb == "d":
            self._ack(callback_id)
            index = int(arg) if arg.isdigit() else -1
            if 0 <= index < len(self._sites):
                self._edit(chat_id, message_id, self.detail(self._sites[index]),
                           [ui.nav_row(f"{self.ctx.name}:s")])
            else:
                self._edit(chat_id, message_id, self.screen(), self._buttons())
        elif verb == "n":
            self._ack(callback_id)
            self.notifier.send_to(chat_id, self.screen(), buttons=self._buttons())
        else:
            self._ack(callback_id)
            self._edit(chat_id, message_id, self.screen(), self._buttons())

    def _check_and_show(self, chat_id: int, message_id: int) -> None:
        try:
            self.run_checks()
        except Exception:
            self.log.exception("site_watch: check now failed")
        self._edit(chat_id, message_id, self.screen(), self._buttons())

    def screen(self) -> str:
        if not self._sites:
            return (f"{ui.title(_ICON, 'Sites', 'none set up')}\n"
                    "Add your sites under the site_watch plugin in config.yaml "
                    "(name + url of each health address), then restart NetSentry.")
        counts = self._counts()
        if counts["down"]:
            icon = ui.ATTACK if counts["severe"] else ui.ATTENTION
            verdict = f"{icon} {len(counts['down'])} down"
        elif counts["failing"]:
            verdict = f"{ui.ATTENTION} {len(counts['failing'])} not answering right"
        elif counts["up"]:
            verdict = f"{ui.OK} all {len(counts['up'])} up"
        else:
            verdict = "not checked yet"
        last_run = self._state.get("last_run")
        when = (f"Checked {datetime.fromtimestamp(float(last_run)):%H:%M}"
                if last_run else "Not checked yet")
        lines = [ui.title(_ICON, "Sites", verdict)]
        lines += [self._line(site) for site in self._sites]
        lines.append(f"\n{when} · every {self._interval_min} min")
        return "\n".join(lines)

    def _line(self, site: dict[str, Any]) -> str:
        entry = self._state.get("sites", {}).get(site["name"], {})
        last = entry.get("last")
        if not last:
            emoji = _PAUSED if site["paused"] else _UNCHECKED
            return ui.item(f"{emoji} {site['name']}",
                           "paused" if site["paused"] else "", "not checked yet")
        reading = _reading(last)
        streak = int(entry.get("streak", 0))
        since = self._since(float(entry.get("since", reading.at)))
        if reading.ok:
            emoji = ui.OK
            bits = [_v(reading.version), reading.commit, f"{reading.elapsed:.1f} s",
                    "no /healthz yet" if reading.no_healthz else "", f"up {since}"]
        else:
            confirmed = streak >= self._fail_after
            emoji = ui.ATTACK if confirmed and reading.severe else ui.ATTENTION
            bits = [reading.reason, f"{'down' if confirmed else 'failing'} {since}"]
        if site["paused"]:
            emoji = _PAUSED
            bits.insert(0, "paused")
        return ui.item(f"{emoji} {site['name']}", *bits)

    def detail(self, site: dict[str, Any]) -> str:
        entry = self._state.get("sites", {}).get(site["name"], {})
        last = entry.get("last")
        lines = [ui.title(_ICON, site["name"], "paused" if site["paused"] else "")]
        lines.append(f"Health address: {site['url']}")
        if site.get("fallback_url"):
            lines.append(f"Fallback (when it answers 404): {site['fallback_url']}")
        if not last:
            lines.append("\nNot checked yet.")
            return "\n".join(lines)
        reading = _reading(last)
        streak = int(entry.get("streak", 0))
        lines.append("")
        since = self._since(float(entry.get("since", reading.at)))
        lines.append((f"{ui.OK} Up" if reading.ok else f"{ui.ATTENTION} {reading.reason}")
                     + (f" {since}" if since else ""))
        answered = "the fallback address" if reading.via == "fallback" else "the health address"
        lines.append(f"Answered by: {answered}" + (f" · HTTP {reading.status}"
                                                  if reading.status else " · no answer"))
        if reading.no_healthz:
            lines.append("No /healthz yet: " + ("only the fallback answers"
                                               if reading.via == "fallback"
                                               else "a web page answers, no health data"))
        if reading.version or reading.commit:
            lines.append(f"Runs: {' · '.join(p for p in (_v(reading.version), reading.commit) if p)}")
        lines.append(f"Response time: {reading.elapsed:.1f} s")
        if streak:
            lines.append(f"Bad readings in a row: {streak} (alert after {self._fail_after})")
        lines.append(f"Last checked: {ui.when_text(reading.at, default='?')}")
        return "\n".join(lines)

    def _buttons(self) -> list:
        name = self.ctx.name
        rows: list = [[ui.button("🔄 Check now", f"{name}:c"), *ui.nav_row()]]
        cells = [ui.button(f"🔎 {site['name'][:24]}", f"{name}:d:{i}")
                 for i, site in enumerate(self._sites)]
        rows[1:1] = [cells[i:i + 2] for i in range(0, len(cells), 2)]
        return rows

    # ─── helpers ─────────────────────────────────────────────────

    def _since(self, ts: float) -> str:
        """``since 14:05`` today, else ``since Mon 23 Nov 09:00``."""
        if ts <= 0:
            return ""
        when, now = datetime.fromtimestamp(ts), datetime.fromtimestamp(self._clock())
        return f"since {when:%H:%M}" if when.date() == now.date() \
            else f"since {ui.fmt_when(when, now)}"

    def _notify(self, kind: str, text: str, buttons: list | None = None) -> None:
        try:
            self.notifier.notify(kind, text, buttons=buttons)
        except Exception:
            self.log.exception("site_watch: could not notify")

    def _ack(self, callback_id: str, text: str = "") -> None:
        answer = getattr(self.notifier, "answer_callback", None)
        if answer:
            answer(callback_id, text)

    def _edit(self, chat_id: int, message_id: int, text: str, buttons: list | None) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons)

    @staticmethod
    def _in_thread(func: Callable[..., None], *args: Any) -> None:
        threading.Thread(target=func, args=args, daemon=True,
                         name="netsentry.site_watch").start()


def _reading(stored: dict[str, Any]) -> Reading:
    """A :class:`Reading` back from state (unknown keys are ignored)."""
    known = Reading.__dataclass_fields__
    return Reading(**{k: v for k, v in stored.items() if k in known})


def _expects_healthz(url: str) -> bool:
    return url.split("?", 1)[0].rstrip("/").endswith("/healthz")


def _is_http(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def _v(version: str) -> str:
    """``v0.1.0`` (a version that already starts with v is left alone)."""
    if not version:
        return ""
    return version if version[:1] in ("v", "V") else f"v{version}"
