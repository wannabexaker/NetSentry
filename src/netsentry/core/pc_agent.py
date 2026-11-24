"""Client for the PC agent: a fixed list of actions run on a PC over SSH.

On the PC, NetSentry's key is pinned (``authorized_keys`` ``command=``) to one
script, ``tools/pc-agent/pc-agent.ps1``, which compares what it is asked for,
whole, against its own list and refuses anything else. This client keeps a
second, identical list and refuses before ssh is ever started — so a bug or a
crafted callback in NetSentry cannot even *ask* for something else. The action
text is always one of the constants built here, never text a user typed.

Three outcomes, kept apart on purpose because they mean different things:

* ``ok``    — the PC answered and the agent did what was asked.
* ``off``   — the PC did not answer at all (switched off, asleep, no network).
  That is a normal state of a PC, not a fault.
* ``fault`` — the PC answered the network but refused or failed: the key was
  removed, the script changed, its answer cannot be read. That needs the owner.

``sleep``/``hibernate`` are special: the agent prints ``{"ok":true}`` and then
the PC goes to sleep under the open connection, which usually drops or hangs.
A dropped connection right after one of those is the expected success.
"""

from __future__ import annotations

import json
import logging
import math
import re
import subprocess  # nosec B404 - fixed argv (no shell), see _argv
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

log = logging.getLogger(__name__)

OK, OFF, FAULT = "ok", "off", "fault"

POWER_ACTIONS = ("sleep", "hibernate", "shutdown", "restart", "cancel")
_DROPS_CONNECTION = ("sleep", "hibernate")
# ``summary`` is read-only: AI Mission Control's own picture (0.5.0 and newer).
_FIXED_ACTIONS = ("status", "summary", "free-vram") + POWER_ACTIONS

DEFAULT_SERVICES = ("lmstudio", "hermes", "openclaw")

# How long each action may take on the PC (seconds, after connecting).
_TIMEOUTS = {"status": 30, "summary": 20, "share": 45, "free-vram": 60, "sleep": 20, "hibernate": 20,
             "shutdown": 30, "restart": 30, "cancel": 30, "start": 150, "stop": 60}

_SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# ``share <page> on|off``: a page of AI Mission Control shared over Tailscale
# Serve (tailnet only) or not. <page> is the page id as :func:`page_slug` makes it;
# the agent on the PC only accepts slugs of pages on its own list.
_SHARE_RE = re.compile(r"^share ([a-z0-9-]{1,40}) (on|off)$")
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9.-]{0,252}|[0-9A-Fa-f:]{2,39})$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")

# ssh's own messages (exit code 255) that mean "nobody answered".
_UNREACHABLE = ("timed out", "no route to host", "network is unreachable",
                "connection refused", "could not resolve", "name or service not known",
                "temporary failure in name resolution", "host is down",
                "connection closed by", "connection reset", "broken pipe")
# After sleep/hibernate: the connection went down with the PC.
_DROPPED = ("closed by remote host", "connection closed by", "connection reset", "broken pipe", "timeout",
            "timed out")
# ...and the ones that mean "the PC answered and turned us away".
_TURNED_AWAY = ("permission denied", "host key verification failed",
                "remote host identification has changed", "too many authentication",
                "no matching", "unable to negotiate", "identity file", "bad permissions")


# Faults that are about the connection, not about what the agent answered.
_KEY_REFUSED = "the PC refused NetSentry's key"
_NO_SSH = "ssh could not be started on this host"
# A ``summary`` the agent could not give or that cannot be used (an AI Mission
# Control older than 0.5.0, a failed or unreadable answer).
SUMMARY_UNUSABLE = "AI Mission Control on the PC gave no usable summary"


class AgentConfigError(ValueError):
    """The host, user, key or service list in the config is not usable."""


# ─── what the agent says ────────────────────────────────────────

@dataclass(frozen=True)
class AgentReply:
    outcome: str                     # OK | OFF | FAULT
    data: dict[str, Any] = field(default_factory=dict)
    detail: str = ""                 # for the log and /health, never raw stderr in chat
    dropped: bool = False            # sleep/hibernate: the connection went with the PC

    @property
    def ok(self) -> bool:
        return self.outcome == OK


@dataclass(frozen=True)
class GpuInfo:
    name: str
    temp_c: int | None
    load_pct: int | None
    vram_used_mb: int | None
    vram_total_mb: int | None
    power_w: int | None


@dataclass(frozen=True)
class ServiceInfo:
    id: str
    name: str
    running: bool
    ram_mb: int | None
    model: str | None


@dataclass(frozen=True)
class PcStatus:
    host: str
    uptime_s: int | None
    logged_on: bool
    ram_used_mb: int | None
    ram_total_mb: int | None
    disk_free_gb: int | None
    disk_total_gb: int | None
    gpu: GpuInfo | None
    game_running: bool | None
    models: tuple[str, ...]
    services: tuple[ServiceInfo, ...]
    error: str = ""

    def service(self, service_id: str) -> ServiceInfo | None:
        return next((s for s in self.services if s.id == service_id), None)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


def _str_list(value: Any) -> tuple[str, ...]:
    # Windows PowerShell 5.1 writes a one-element array as the bare element.
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return ()
    return tuple(str(v).strip() for v in value if isinstance(v, str) and v.strip())


def parse_status(data: dict[str, Any]) -> PcStatus:
    """A :class:`PcStatus` from the agent's ``status`` JSON; missing or null
    fields become None/empty rather than errors."""
    gpu_raw = data.get("gpu")
    gpu = None
    if isinstance(gpu_raw, dict):
        gpu = GpuInfo(name=str(gpu_raw.get("name") or "GPU"),
                      temp_c=_int(gpu_raw.get("temp_c")),
                      load_pct=_int(gpu_raw.get("load_pct")),
                      vram_used_mb=_int(gpu_raw.get("vram_used_mb")),
                      vram_total_mb=_int(gpu_raw.get("vram_total_mb")),
                      power_w=_int(gpu_raw.get("power_w")))
    raw_services = data.get("services")
    if isinstance(raw_services, dict):          # one service: PowerShell drops the array
        raw_services = [raw_services]
    services = []
    for s in raw_services if isinstance(raw_services, list) else []:
        if not isinstance(s, dict) or not isinstance(s.get("id"), str):
            continue
        model = s.get("model")
        services.append(ServiceInfo(
            id=s["id"], name=str(s.get("name") or s["id"]), running=s.get("running") is True,
            ram_mb=_int(s.get("ram_mb")),
            model=str(model).strip() if isinstance(model, str) and model.strip() else None))
    game = data.get("game_running")
    return PcStatus(
        host=str(data.get("host") or ""),
        uptime_s=_int(data.get("uptime_s")),
        logged_on=data.get("logged_on") is True,
        ram_used_mb=_int(data.get("ram_used_mb")),
        ram_total_mb=_int(data.get("ram_total_mb")),
        disk_free_gb=_int(data.get("disk_c_free_gb")),
        disk_total_gb=_int(data.get("disk_c_total_gb")),
        gpu=gpu,
        game_running=game if isinstance(game, bool) else None,
        models=_str_list(data.get("models_loaded")),
        services=tuple(services),
        error=str(data.get("error") or ""),
    )


# ─── AI Mission Control's summary ───────────────────────────────

_CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_MAX_ITEMS = 24


@dataclass(frozen=True)
class McModel:
    name: str
    context: int | None
    processor: str


@dataclass(frozen=True)
class McService:
    id: str
    name: str
    running: bool
    remote: bool                     # not on the PC (NetSentry itself)
    port: int | None
    model: str


@dataclass(frozen=True)
class McPage:
    id: str
    name: str
    label: str
    port: int | None
    available: bool                  # something answers behind it on the PC
    local_url: str
    tailscale_shared: bool
    tailscale_url: str
    reach: str
    sign: str

    @property
    def opens(self) -> bool:
        """The Tailscale link opens from the owner's phone right now."""
        return self.available and self.tailscale_shared and bool(self.tailscale_url)


@dataclass(frozen=True)
class McLastAction:
    summary: str
    state: str                       # running | ok | failed | "" (unknown)
    reason: str
    ended: str


@dataclass(frozen=True)
class McSummary:
    version: str
    time: str
    game: str
    vram_used_mib: int | None
    vram_total_mib: int | None
    ram_free_percent: float | None
    ram_free_mb: int | None
    ram_total_mb: int | None
    models: tuple[McModel, ...]
    services: tuple[McService, ...]
    pages: tuple[McPage, ...]
    last_action: McLastAction | None

    @property
    def usable(self) -> bool:
        return bool(self.version or self.services or self.pages)


def _text(value: Any, limit: int = 80) -> str:
    """One line of text from the PC: control and direction characters out,
    whitespace collapsed, cut to ``limit``; "" for anything that isn't text."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    return " ".join(_CONTROL_RE.sub(" ", str(value)).split())[:limit]


def _url(value: Any) -> str:
    text = _text(value, 200)
    return text if text.startswith(("https://", "http://")) and " " not in text else ""


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def _whole(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _records(value: Any) -> list[dict[str, Any]]:
    # Windows PowerShell 5.1 writes a one-element array as the bare element.
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, dict)][:_MAX_ITEMS]


def parse_summary(data: Any) -> McSummary:
    """A :class:`McSummary` from AI Mission Control's ``summary`` JSON.

    The PC side only ever adds fields, so unknown ones are ignored; missing,
    null or oddly typed ones become None/empty. Never raises."""
    data = data if isinstance(data, dict) else {}
    models = tuple(McModel(name=_text(m.get("Name")), context=_whole(m.get("Context")),
                           processor=_text(m.get("Processor"), 40))
                   for m in _records(data.get("Models")) if _text(m.get("Name")))
    services = []
    for s in _records(data.get("Services")):
        sid = _text(s.get("Id"), 40)
        if sid:
            services.append(McService(
                id=sid, name=_text(s.get("Name"), 40) or sid, running=s.get("Running") is True,
                remote=s.get("Remote") is True, port=_whole(s.get("Port")),
                model=_text(s.get("Model"))))
    pages = []
    for g in _records(data.get("Pages")):
        name = _text(g.get("Name"), 40)
        if name:
            pages.append(McPage(
                id=_text(g.get("Id")), name=name, label=_text(g.get("Label"), 40),
                port=_whole(g.get("Port")), available=g.get("Available") is True,
                local_url=_url(g.get("LocalUrl")),
                tailscale_shared=g.get("TailscaleShared") is True,
                tailscale_url=_url(g.get("TailscaleUrl")), reach=_text(g.get("Reach"), 20),
                sign=_text(g.get("Sign"))))
    raw_last = data.get("LastAction")
    last = None
    if isinstance(raw_last, dict) and _text(raw_last.get("Summary")):
        state = _text(raw_last.get("State"), 12).lower()
        last = McLastAction(summary=_text(raw_last.get("Summary"), 120),
                            state=state if state in ("running", "ok", "failed") else "",
                            reason=_text(raw_last.get("Reason"), 160),
                            ended=_text(raw_last.get("Ended"), 40))
    return McSummary(
        version=_text(data.get("Version"), 20), time=_text(data.get("Time"), 40),
        game=_text(data.get("Game")),
        vram_used_mib=_whole(data.get("VramUsedMiB")),
        vram_total_mib=_whole(data.get("VramTotalMiB")),
        ram_free_percent=_number(data.get("RamFreePercent")),
        ram_free_mb=_whole(data.get("RamFreeMB")), ram_total_mb=_whole(data.get("RamTotalMB")),
        models=models, services=tuple(services), pages=tuple(pages), last_action=last)


# ─── the client ─────────────────────────────────────────────────

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class PcAgent:
    """Runs one allowed action on the PC and says what came of it."""

    def __init__(self, host: str, user: str, ssh_key: str, *, port: int = 22,
                 services: Iterable[str] = DEFAULT_SERVICES,
                 connect_timeout: int = 8, ssh_bin: str = "ssh",
                 runner: Runner = subprocess.run) -> None:
        host, user, ssh_key = str(host or "").strip(), str(user or "").strip(), \
            str(ssh_key or "").strip()
        if not _HOST_RE.fullmatch(host) or host.startswith("-"):
            raise AgentConfigError(f"not a host name or address: {host!r}")
        if not _USER_RE.fullmatch(user):
            raise AgentConfigError(f"not a user name: {user!r}")
        if not ssh_key or ssh_key.startswith("-") or "\n" in ssh_key:
            raise AgentConfigError("ssh_key must be the path of a private key file")
        if not 1 <= int(port) <= 65535:
            raise AgentConfigError(f"port out of range: {port}")
        ids = tuple(dict.fromkeys(str(s).strip() for s in services))
        bad = [s for s in ids if not _SERVICE_ID_RE.fullmatch(s)]
        if bad:
            raise AgentConfigError(f"not a service id: {bad[0]!r}")
        self.host, self.user, self.key, self.port = host, user, ssh_key, int(port)
        self.services = ids
        self._connect_timeout = max(2, int(connect_timeout))
        self._ssh = ssh_bin
        self._run = runner
        self.allowed = frozenset(_FIXED_ACTIONS) | frozenset(
            f"{verb} {s}" for s in ids for verb in ("start", "stop"))

    # ─── the actions ─────────────────────────────────────────────

    def status(self) -> tuple[AgentReply, PcStatus | None]:
        reply = self.run("status")
        if not reply.ok:
            return reply, None
        try:
            return reply, parse_status(reply.data)
        except Exception:                       # never let a strange answer crash a screen
            log.exception("PC agent status could not be parsed")
            return AgentReply(FAULT, detail="the status answer could not be read"), None

    def summary(self) -> tuple[AgentReply, McSummary | None]:
        """AI Mission Control's picture of the PC. OFF stays OFF and a
        connection fault stays that fault; anything else that goes wrong — the
        agent failed, its answer is unreadable or has nothing in it — is
        :data:`SUMMARY_UNUSABLE`, which is how an AI Mission Control too old
        for this shows."""
        return self._summary_from(self.run("summary"))

    def _summary_from(self, reply: AgentReply) -> tuple[AgentReply, McSummary | None]:
        unusable = AgentReply(FAULT, detail=SUMMARY_UNUSABLE)
        if reply.outcome == OFF or reply.detail in (_KEY_REFUSED, _NO_SSH):
            return reply, None
        if not reply.ok:
            return unusable, None
        try:
            summary = parse_summary(reply.data)
        except Exception:                       # never let a strange answer crash a screen
            log.exception("PC agent summary could not be parsed")
            return unusable, None
        if not summary.usable:
            log.error("PC agent summary has nothing in it (keys %s)", sorted(reply.data)[:10])
            return unusable, None
        return reply, summary

    def share(self, slug: str, on: bool) -> tuple[AgentReply, McSummary | None]:
        """Share one page over Tailscale (or stop sharing it); the answer is the
        summary after the change, so the screen and its "Last action" line show
        whether it worked and why not."""
        action = f"share {slug} {'on' if on else 'off'}"
        if not _SHARE_RE.fullmatch(action):
            return AgentReply(FAULT, detail="that is not a page id"), None
        return self._summary_from(self.run(action))

    def start(self, service_id: str) -> AgentReply:
        return self.run(f"start {service_id}")

    def stop(self, service_id: str) -> AgentReply:
        return self.run(f"stop {service_id}")

    def run(self, action: str) -> AgentReply:
        """Run ``action`` if — and only if — it is on the list."""
        if action not in self.allowed and not _SHARE_RE.fullmatch(action):
            log.error("PC agent: refused to send %r, it is not on the list", action[:40])
            return AgentReply(FAULT, detail="that action is not on NetSentry's list")
        verb = action.split(" ", 1)[0]
        timeout = self._connect_timeout + _TIMEOUTS.get(verb, 30)
        try:
            proc = self._run(self._argv(action), capture_output=True, text=True,  # nosec B603 - fixed argv, action is from self.allowed
                             timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            if verb in _DROPS_CONNECTION:
                return AgentReply(OK, {"ok": True}, "the PC went to sleep under the connection",
                                  dropped=True)
            return AgentReply(OFF, detail=f"no answer within {timeout} s")
        except OSError as e:
            log.error("PC agent: could not start ssh: %s", e)
            return AgentReply(FAULT, detail=_NO_SSH)
        return self._judge(verb, proc.returncode, proc.stdout or "", proc.stderr or "")

    # ─── how ─────────────────────────────────────────────────────

    def _argv(self, action: str) -> list[str]:
        return [self._ssh, "-i", self.key, "-p", str(self.port),
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={self._connect_timeout}",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
                "-o", "IdentitiesOnly=yes", "-T",
                f"{self.user}@{self.host}", action]

    def _judge(self, verb: str, rc: int, out: str, err: str) -> AgentReply:
        data = _json_object(out)
        if verb in _DROPS_CONNECTION and data.get("ok") is True:
            return AgentReply(OK, data, dropped=rc != 0)
        if rc == 255:                           # ssh itself failed
            lowered = err.lower()
            if any(s in lowered for s in _TURNED_AWAY):
                log.error("PC agent: the PC turned the key away: %s", _first_line(err))
                return AgentReply(FAULT, detail=_KEY_REFUSED)
            if verb in _DROPS_CONNECTION and any(s in lowered for s in _DROPPED):
                return AgentReply(OK, {"ok": True}, "the connection dropped as the PC "
                                  "went to sleep", dropped=True)
            log.info("PC agent: no answer (%s)", _first_line(err) or "ssh exit 255")
            return AgentReply(OFF, detail="the PC did not answer")
        if rc == 64:
            log.error("PC agent refused %r: %s", verb, _first_line(err))
            return AgentReply(FAULT, detail="the agent on the PC refused the action — "
                                            "its list differs from NetSentry's")
        if rc != 0:
            log.error("PC agent %r failed (exit %d): %s", verb, rc, _first_line(err))
            return AgentReply(FAULT, detail=f"the agent on the PC failed (exit {rc})")
        if not data:
            log.error("PC agent %r: unreadable answer %r", verb, out[:200])
            return AgentReply(FAULT, detail="the agent's answer could not be read")
        return AgentReply(OK, data)


def page_slug(page_id: str) -> str:
    """The id a page goes by in ``share <page> on|off`` — the same rule as the
    agent's: lower case, every run of other characters one ``-``."""
    return re.sub(r"[^a-z0-9]+", "-", str(page_id or "").lower()).strip("-")[:40]


def _json_object(text: str) -> dict[str, Any]:
    """The JSON object in the agent's output ({} when there is none).

    The last line that parses wins: a login banner or a PowerShell warning
    above it must not make a good answer unreadable.
    """
    for line in reversed([ln.strip() for ln in text.splitlines() if ln.strip()]):
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            return value if isinstance(value, dict) else {}
    return {}


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:160]
