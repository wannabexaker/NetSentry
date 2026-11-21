"""
read_access — a read-only window on NetSentry for another program.

An AI agent or a status card on another computer may ask "what is going on in
my network?" and nothing else. The work is split in two so the program that
answers the outside caller touches no secret and no live code:

  * This plugin, inside the service, writes ONE already-sanitised snapshot,
    ``read_access/snapshot.json`` in its state folder (atomic, mode 0600), once
    at start-up and then every ``interval_minutes``. It is gathered in-process
    from the other plugins — each source optional; a missing plugin or a call
    that fails leaves its part empty, never the whole snapshot.
  * ``tools/read-agent/netsentry_read.py``, outside the service, is the only
    thing the caller's ssh key may run. It compares the request against a
    fixed list (``status``, ``findings``, ``alerts``, ``health``) and prints
    that section of the snapshot as one JSON line.

Nothing here changes anything: it reads what other plugins already know (no
router, PC or relay call of its own) and writes only the snapshot.

Every string that came from outside NetSentry (device names, hostnames,
domains, log lines, check details) is cleaned before it is written: control
characters and escape sequences go, whitespace is collapsed, names are capped
at 40 characters and texts at 160, MAC addresses are shortened, and secrets,
links, home-folder paths and public IP addresses are replaced by a marker.
The contract is in docs/READ_ACCESS.md.

Config keys:
    interval_minutes   how often the snapshot is rewritten (default 1)
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .. import __version__
from ..core import hostinfo, ui
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

FORMAT = 1
SNAPSHOT_NAME = "snapshot.json"
ACTIONS = ("status", "findings", "alerts", "health")
# The whole answer the read agent prints must stay under 8 KB; the agent adds
# nothing but these few envelope fields, so the plugin aims a little lower.
ANSWER_LIMIT = 8000
MAX_ITEMS = 20
NAME_MAX = 40
TEXT_MAX = 160
HEALTH_NAME = "Read access snapshot"

_SEVERITY_RANK = {"attack": 3, "warning": 2, "info": 1}
_DELIVERIES = ("sound", "silent", "not_sent", "failed")
_NSID = re.compile(r"^NS-[A-Z]{2,6}-\d{3}$")

# Checks (from self_check) that answer the questions a person asks first.
_CHECK_ROUTER = "Reading the router"
_CHECK_PIHOLE = "Pi-hole query log"

# ─── cleaning ────────────────────────────────────────────────────────

HIDDEN, LINK, PATH, PUBLIC_IP, LAN_IP = "[hidden]", "[link]", "[path]", "[public IP]", "[LAN IP]"
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]")
_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,15}://\S+")
_TG_TOKEN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{25,}")
_KEY_VALUE = re.compile(
    r"(?i)\b(pass(?:word|phrase|wd)?|pwd|psk|secret|token|api[_-]?key|key|auth)(\s*[:=]\s*)\S+")
_MAC = re.compile(
    r"(?<![0-9A-Fa-f:-])([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2"
    r"[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2([0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
_HOME_PATH = re.compile(
    r"(?:~/|/home/[^/\s]+|/root(?=[/\s]|$)|/Users/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+)\S*")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_LONG_RUN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
# Config keys whose values are secrets (or chat ids) wherever they appear.
_SECRET_KEY = re.compile(r"(?i)token|pass|secret|key|chat|psk|auth|cred|cookie")
_SECRET_MIN_LEN = 6


def short_mac(match: re.Match[str]) -> str:
    """``AA:BB:CC:DD:EE:0F`` → ``AA:BB:CC:xx:xx:0F``: the maker (first three
    octets) and the last octet, enough to tell devices apart, not to copy one."""
    first, _, second, third, last = match.groups()
    return f"{first.upper()}:{second.upper()}:{third.upper()}:xx:xx:{last.upper()}"


class Redactor:
    """Cleans one string from outside NetSentry so it is safe to hand on."""

    def __init__(self, secrets: Iterable[str] = (), home: str = "") -> None:
        # Longest first, so a secret that contains another is hidden whole.
        self._secrets = sorted({s for s in secrets if len(s) >= _SECRET_MIN_LEN},
                               key=len, reverse=True)
        self._home = home if len(home) > 1 else ""

    def clean(self, value: Any, limit: int = TEXT_MAX, *, keep_private_ip: bool = False) -> str:
        if value is None:
            return ""
        text = str(value)[:4 * limit + 512]          # bounded work for a hostile string
        text = _ANSI.sub(" ", text)
        text = "".join(" " if _unprintable(ch) else ch for ch in text)
        for secret in self._secrets:
            text = text.replace(secret, HIDDEN)
        if self._home:
            text = re.sub(re.escape(self._home) + r"\S*", PATH, text)
        text = _URL.sub(LINK, text)
        text = _TG_TOKEN.sub(HIDDEN, text)
        text = _KEY_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{HIDDEN}", text)
        text = _MAC.sub(short_mac, text)
        text = _HOME_PATH.sub(PATH, text)
        text = _IPV4.sub(lambda m: _ip_marker(m.group(0), keep_private_ip), text)
        text = _IPV6.sub(lambda m: _ip_marker(m.group(0), keep_private_ip), text)
        text = _LONG_RUN.sub(_long_run_marker, text)
        text = " ".join(text.split())
        return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _unprintable(ch: str) -> bool:
    # Control, format (zero-width, bidi overrides), private-use, unassigned
    # and every separator except the plain space.
    return ch != " " and unicodedata.category(ch)[0] in "CZ"


def _ip_marker(text: str, keep_private: bool) -> str:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text                                  # a time, a version: not an address
    if address.is_global:
        return PUBLIC_IP
    return text if keep_private else LAN_IP


def _long_run_marker(match: re.Match[str]) -> str:
    # A long run of letters AND digits is a key or token; a long label of
    # letters only (a look-alike domain) is evidence and stays.
    run = match.group(0)
    if any(c.isdigit() for c in run) and any(c.isalpha() for c in run):
        return HIDDEN
    return run


def _iso(ts: float | None) -> str | None:
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return None
    try:
        return datetime.fromtimestamp(float(ts)).astimezone().isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _iso_text(text: Any) -> str | None:
    """A local ISO time written by another plugin, with its offset added."""
    try:
        when = datetime.fromisoformat(str(text or "").strip())
    except ValueError:
        return None
    return when.astimezone().isoformat(timespec="seconds")


def answer_size(action: str, section: dict[str, Any], generated: str) -> int:
    """Bytes of the read agent's answer for this section (it prints exactly this)."""
    envelope = {"ok": True, "action": action, "generated": generated, "age_s": 9999999999}
    return len(json.dumps({**envelope, **section}, ensure_ascii=True,
                          separators=(",", ":")).encode())


def fit(action: str, section: dict[str, Any], generated: str,
        limit: int = ANSWER_LIMIT) -> dict[str, Any]:
    """Drop items from the end (the oldest / least important) until it fits."""
    for key in ("items", "failing"):
        items = section.get(key)
        while isinstance(items, list) and items and answer_size(action, section, generated) > limit:
            items.pop()
    return section


def _home() -> str:
    try:
        return str(Path.home())
    except (RuntimeError, OSError):
        return ""


def _host_uptime(path: str = "/proc/uptime") -> int | None:
    try:
        return int(float(Path(path).read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


# ─── the plugin ──────────────────────────────────────────────────────

class ReadAccessPlugin(Plugin):
    """Writes the read-only snapshot; has no command and changes nothing."""

    def on_load(self) -> None:
        self._interval = max(1, int(self.cfg.get("interval_minutes", 1)))
        self._file = Path(self.ctx.state_dir) / SNAPSHOT_NAME
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._fault = ""
        # Injectable for tests.
        self._now: Callable[[], float] = time.time
        self._started = hostinfo.process_started()
        self._start_first_write()

    def on_unload(self) -> None:
        self._stop.set()

    def scheduled_tasks(self) -> list[ScheduledTask]:
        n = self._interval
        cron = f"*/{n} * * * *" if n < 60 else f"0 */{max(1, n // 60)} * * *"
        return [ScheduledTask(cron=cron, func=self.refresh, name="snapshot")]

    def health(self) -> list[HealthCheck]:
        # Only a real fault is worth a line; a working snapshot says nothing.
        if self._fault:
            return [HealthCheck(HEALTH_NAME, False, f"could not write it: {self._fault}")]
        return []

    # ─── writing ─────────────────────────────────────────────────

    def _start_first_write(self) -> None:
        threading.Thread(target=self._first_write, daemon=True,
                         name="read-access-first").start()

    def _first_write(self) -> None:
        # The runtime hands each plugin the list of the others only after all
        # of them have loaded; wait (briefly) for it so the first snapshot is whole.
        for _ in range(50):
            if getattr(self.ctx, "_all_plugins", None) or self._stop.wait(0.2):
                break
        if not self._stop.is_set():
            self.refresh()

    def refresh(self) -> bool:
        """Gather and write the snapshot. False (and a health fault) when it
        could not be written; a source that fails only empties its part."""
        with self._lock:
            try:
                self._write(json.dumps(self.build(), ensure_ascii=True,
                                       separators=(",", ":"), allow_nan=False))
            except Exception as exc:
                self._fault = (exc.strerror if isinstance(exc, OSError) and exc.strerror
                               else type(exc).__name__)
                self.log.exception("read_access: could not write the snapshot")
                return False
            self._fault = ""
            return True

    def _write(self, text: str) -> None:
        """Atomic, and readable only by the service user (the read agent runs
        as that same user through the restricted key)."""
        self._file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._file.with_name(self._file.name + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            os.chmod(tmp, 0o600)        # a leftover .tmp keeps its old mode otherwise
        except OSError:
            pass
        os.replace(tmp, self._file)

    # ─── gathering ───────────────────────────────────────────────

    def build(self) -> dict[str, Any]:
        """The whole snapshot: four sections, each already cleaned and sized."""
        now = self._now()
        generated = _iso(now) or ""
        red = Redactor(self._secrets(), home=_home())
        checks = self._part("health checks", self._checks)
        findings = self._part("findings", self._findings, red)
        sections = {
            "status": self._status(now, checks, findings),
            "findings": {"items": (findings or [])[:MAX_ITEMS]},
            "alerts": {"items": self._part("alerts", self._alerts, red) or []},
            "health": self._health(now, checks, red),
        }
        for action, section in sections.items():
            fit(action, section, generated)
        return {"format": FORMAT, "generated": generated, "generated_ts": round(now, 3),
                **sections}

    def _part(self, what: str, func: Callable[..., Any], *args: Any) -> Any:
        try:
            return func(*args)
        except Exception:
            self.log.exception("read_access: %s could not be read", what)
            return None

    def _plugin(self, name: str) -> Any:
        return ui.plugin_named(self.ctx, name)

    def _checks(self) -> list[HealthCheck] | None:
        checker = self._plugin("self_check")
        if checker is None or not hasattr(checker, "checks"):
            return None
        return list(checker.checks())

    def _findings(self, red: Redactor) -> list[dict[str, Any]] | None:
        det = self._plugin("threat_detector")
        if det is None or not hasattr(det, "api_recent_findings"):
            return None
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for f in det.api_recent_findings():
            if not isinstance(f, dict):
                continue
            key = (str(f.get("type", "")), str(f.get("subject", "")))
            ts = str(f.get("ts", ""))
            g = groups.get(key)
            if g is None:
                groups[key] = {"f": f, "first": ts, "last": ts}
            else:                                   # one line per (kind, subject)
                g["first"] = min(g["first"], ts)
                g["last"] = max(g["last"], ts)
        items = []
        for g in groups.values():
            f = g["f"]
            severity = str(f.get("severity", ""))
            nsid = str(f.get("id", ""))
            label = str(f.get("label", "") or f.get("type", ""))
            detail = str(f.get("detail", ""))
            items.append({
                "id": nsid if _NSID.match(nsid) else "",
                "severity": severity if severity in _SEVERITY_RANK else "info",
                "subject": red.clean(f.get("subject", ""), NAME_MAX, keep_private_ip=True),
                "first_seen": _iso_text(g["first"]),
                "text": red.clean(f"{label}: {detail}" if detail else label, TEXT_MAX),
                "_last": g["last"],
            })
        # Worst first, then the most recently seen.
        items.sort(key=lambda i: (_SEVERITY_RANK[i["severity"]], i["_last"]), reverse=True)
        for item in items:
            item.pop("_last")
        return items

    def _alerts(self, red: Redactor) -> list[dict[str, Any]]:
        journal = getattr(self.notifier, "journal", None)
        if journal is None or not hasattr(journal, "recent"):
            return []
        out = []
        for e in journal.recent(MAX_ITEMS):
            delivery = str(e.get("delivery", ""))
            out.append({
                "time": _iso(e.get("ts")),
                "kind": red.clean(e.get("kind", ""), 20),
                "delivery": delivery if delivery in _DELIVERIES else "failed",
                "text": red.clean(e.get("text", ""), TEXT_MAX),
            })
        return out

    def _status(self, now: float, checks: list[HealthCheck] | None,
                findings: list[dict[str, Any]] | None) -> dict[str, Any]:
        worst = None
        if findings is not None:
            ranks = [_SEVERITY_RANK[f["severity"]] for f in findings]
            worst = {3: "attack", 2: "warning", 1: "info"}.get(max(ranks, default=0), "none")
        devices = self._part("devices", self._devices)
        return {
            "version": __version__,
            "service_up_s": max(0, int(now - self._started)),
            "host_up_s": _host_uptime(),
            "mode": self._part("notification mode", self._mode),
            "reaches": {
                "router": _router_reachable(checks),
                "gaming_pc": self._part("gaming PC", self._pc),
                "hidway_relay": self._part("HIDway relay", self._relay),
                "hidway_transport": self._part("HIDway transport", self._relay_transport),
            },
            "counts": {
                "findings": None if findings is None else len(findings),
                "worst": worst,
                "failing_checks": None if checks is None else sum(1 for c in checks if not c.ok),
                "devices": None if devices is None else devices["total"],
                "unnamed_devices": None if devices is None else devices["unnamed"],
            },
        }

    def _health(self, now: float, checks: list[HealthCheck] | None,
                red: Redactor) -> dict[str, Any]:
        failing = [{"name": red.clean(c.name, NAME_MAX), "detail": red.clean(c.detail, TEXT_MAX)}
                   for c in (checks or []) if not c.ok][:MAX_ITEMS]
        return {
            "checks_total": None if checks is None else len(checks),
            "failing": failing,
            "internet": self._part("internet", self._internet) or "unknown",
            "router_reachable": _router_reachable(checks),
            "pihole": _pihole(checks),
            "last_checked": None if checks is None else _iso(now),
        }

    # ─── the small sources ───────────────────────────────────────

    def _mode(self) -> str | None:
        policy = getattr(self.notifier, "policy", None)
        mode = getattr(policy, "mode", None)
        return mode if mode in ("relaxed", "normal", "everything") else None

    def _devices(self) -> dict[str, int] | None:
        dash = self._plugin("lan_dashboard")
        counts = dash.device_counts() if dash is not None and hasattr(dash, "device_counts") else None
        if not isinstance(counts, dict):
            return None
        return {"total": int(counts.get("total", 0)), "unnamed": int(counts.get("unnamed", 0))}

    def _pc(self) -> str | None:
        pc = self._plugin("workstation")
        state = pc.last_state() if pc is not None and hasattr(pc, "last_state") else None
        if state is None:
            return None
        return state if state in ("on", "off", "fault", "unknown") else "unknown"

    def _relay(self) -> bool | None:
        # The relay's own state file, read passively (the same look health() takes).
        remote = self._plugin("remote_keyboard")
        controller = getattr(remote, "remote", None)
        if controller is None:
            return None
        return bool(controller.transport.view().running)

    def _relay_transport(self) -> str | None:
        # How the remote keyboard reaches the relay: one word, never a path.
        remote = self._plugin("remote_keyboard")
        controller = getattr(remote, "remote", None)
        if controller is None:
            return None
        word = getattr(controller.transport.view(), "transport", "")
        return word if word in ("local", "udp") else None

    def _internet(self) -> str | None:
        monitor = self._plugin("health_monitor")
        up = monitor.internet_up() if monitor is not None and hasattr(monitor, "internet_up") else None
        return None if up is None else ("up" if up else "down")

    def _secrets(self) -> set[str]:
        """Every value that must never appear in the snapshot: vault values,
        notifier tokens and chat ids, secret-looking config values of every
        plugin, the dashboard's login token and the router password."""
        found: set[str] = set()

        def add(value: Any) -> None:
            if isinstance(value, bool):
                return
            if isinstance(value, (str, int)):
                text = str(value).strip()
                if len(text) >= _SECRET_MIN_LEN:
                    found.add(text)
            elif isinstance(value, (list, tuple, set)):
                for v in value:
                    add(v)
            elif isinstance(value, dict):
                for v in value.values():
                    add(v)

        def walk(cfg: Any) -> None:
            if isinstance(cfg, dict):
                for key, value in cfg.items():
                    if _SECRET_KEY.search(str(key)):
                        add(value)
                    else:
                        walk(value)
            elif isinstance(cfg, list):
                for value in cfg:
                    walk(value)

        try:
            values = self.vault.all() if hasattr(self.vault, "all") else {}
            add(list(values.values()) if isinstance(values, dict) else [])
        except Exception:
            self.log.warning("read_access: the vault could not be read; its values "
                             "are hidden by pattern only")
        notifiers = [self.notifier, *dict(getattr(self.ctx, "notifiers_by_id", {}) or {}).values()]
        for n in notifiers:
            for attr in ("token", "chat_id", "allowed_chats"):
                add(getattr(n, attr, None))
        for p in [self, *(getattr(self.ctx, "_all_plugins", None) or [])]:
            walk(getattr(getattr(p, "ctx", None), "config", None))
        add(getattr(self._plugin("lan_dashboard"), "_token", None))
        for attr in ("password", "key_path"):
            add(getattr(self.router, attr, None))
        return found


def _router_reachable(checks: list[HealthCheck] | None) -> bool | None:
    """From self_check's "Reading the router" (asked of the router at most every
    5 min): answering = reachable, even when its lists do not add up."""
    check = next((c for c in checks or [] if c.name == _CHECK_ROUTER), None)
    if check is None:
        return None
    return check.ok or "did not answer" not in check.detail


def _pihole(checks: list[HealthCheck] | None) -> str:
    check = next((c for c in checks or [] if c.name == _CHECK_PIHOLE), None)
    if check is None:
        return "unknown"
    return "ok" if check.ok else "problem"


PLUGIN = ReadAccessPlugin
