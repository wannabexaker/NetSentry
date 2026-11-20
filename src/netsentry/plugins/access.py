"""
access — everything needed to reach and manage NetSentry from another computer.

`/access` opens one screen, edited in place on Refresh: this host's name, model
and OS, its Tailscale and LAN addresses, the ssh line to copy, the systemd unit
with the commands to check, restart and follow it, where the code, config,
vault, state and backups live, and whether the router (and, when configured,
the gaming PC and the HIDway relay) answer from here. Buttons open the
dashboard and reuse /health, /snapshot and /restart when those are loaded.
`➕ New computer` lists the steps to give another computer ssh access.

What it never shows: keys, tokens, passwords, vault values, chat ids, the
content of any config file, or the dashboard link as text (that link carries a
login token, so it is only ever a URL button). NetSentry never adds an ssh key
itself and takes none through Telegram: whoever held the Telegram account could
then give themselves a shell on the host.

Every fact is discovered at run time. Commands run with fixed arguments and
short timeouts, in parallel, so the screen appears within a few seconds even
when the router does not answer; nothing typed by a user is ever executed.

Config keys (all optional; the plugin works with none):
    service    the systemd unit shown (default netsentry.service)
    repo_url   the repository shown (default: the code folder's git remote)
    ssh_host   the host shown in the ssh line (default: the Tailscale address,
               else the LAN address) — e.g. a MagicDNS name
"""

from __future__ import annotations

import getpass
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..core import hostinfo, ui
from ..core.config import _default_config_path
from ..core.plugin import Plugin
from ..core.router import local_address_towards
from ..core.vault import _default_dir as _default_vault_dir

ICON = "🔑"
_DEFAULT_UNIT = "netsentry.service"
_ROUTER_TIMEOUT_S = 4.0
_KEY_PLACEHOLDER = "PASTE-THE-NEW-PUBLIC-KEY-HERE"
_HOST_PLACEHOLDER = "HOST-ADDRESS"
# What a config value may look like before it is shown or put in a command line.
_UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,80}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")

_PC_STATE = {"on": f"{ui.OK} on", "off": "😴 off or asleep",
             "fault": f"{ui.ATTENTION} answers, but something is wrong",
             "unknown": f"{ui.WORKING} not checked yet"}


@dataclass
class Facts:
    """Everything the screen shows — addresses, names and paths only."""
    hostname: str = ""
    model: str = ""
    os: str = ""
    tailscale: str = ""
    lan: str = ""
    user: str = ""
    ssh_host: str = ""
    ssh_host_set: bool = False          # ssh_host came from the config
    unit: str = _DEFAULT_UNIT
    version: str = __version__
    up_s: float = 0.0
    code: str = ""
    config: str = ""
    vault: str = ""
    state: str = ""
    backups: list[str] = field(default_factory=list)
    repo: str = ""
    router_host: str = ""
    router: str = ""                    # "ok" | "down" | "slow" | "" (not checked)
    pc: tuple[str, str] | None = None   # (name, state) when the workstation is configured
    relay: bool | None = None           # None = remote_keyboard not configured


class AccessPlugin(Plugin):
    COMMANDS = [
        {"command": "access", "description": f"{ICON} How to reach and manage NetSentry"},
    ]

    def on_load(self) -> None:
        unit = str(self.cfg.get("service") or _DEFAULT_UNIT).strip()
        self._unit = unit if _UNIT_RE.match(unit) else _DEFAULT_UNIT
        host = str(self.cfg.get("ssh_host") or "").strip()
        self._ssh_host = host if _HOST_RE.match(host) else ""
        self._repo_url = hostinfo.readable_remote(str(self.cfg.get("repo_url") or ""))
        self._router_timeout_s = _ROUTER_TIMEOUT_S
        self._repo_cache: str | None = None
        # Injectable for tests: no real commands, files or clocks.
        self._tailscale: Callable[[], str | None] = hostinfo.tailscale_ipv4
        self._git_remote: Callable[[Path], str] = hostinfo.git_remote
        self._host_facts: Callable[[], tuple[str, str, str]] = lambda: (
            hostinfo.host_name(), hostinfo.host_model(), hostinfo.os_name())
        self._local_address: Callable[[str], str] = local_address_towards
        self._code_folder: Callable[[], Path] = hostinfo.code_folder
        self._started = hostinfo.process_started()
        self._now = time.time
        self._user = _service_user

    # ─── Telegram ────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/access":
            self._show(chat_id, None, *self._main_screen(self.gather()))

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # access:r (refresh) | access:new (new computer) | access:v (back to the screen)
        verb = data.partition(":")[2]
        answer = getattr(self.notifier, "answer_callback", None)
        if answer:
            answer(callback_id, "Refreshed" if verb == "r" else "")
        if verb == "new":
            tailscale = self._tailscale() or ""
            lan = self._lan_address(self._router_host())
            self._show(chat_id, message_id,
                       *self._new_computer_screen(self._user(), self._target(tailscale, lan)))
        else:
            self._show(chat_id, message_id, *self._main_screen(self.gather()))

    def _show(self, chat_id: int, message_id: int | None, text: str, rows: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=rows, html=True)
        else:
            self.notifier.send_to(chat_id, text, buttons=rows or None, html=True)

    # ─── gathering the facts ─────────────────────────────────────

    def gather(self) -> Facts:
        """Collect every fact; the slow ones in parallel, each bounded."""
        router_host = self._router_host()
        slow = {"tailscale": _Background(self._tailscale)}
        if router_host:
            slow["router"] = _Background(self.router.uptime_seconds)
        if self._repo_url:
            self._repo_cache = self._repo_url
        elif self._repo_cache is None:          # the remote does not change while we run
            slow["repo"] = _Background(lambda: self._git_remote(self._code_folder()))
        deadline = time.monotonic() + self._router_timeout_s

        hostname, model, os_name = self._host_facts()
        facts = Facts(hostname=hostname, model=model, os=os_name, user=self._user(),
                      unit=self._unit, up_s=max(0.0, self._now() - self._started),
                      router_host=router_host)
        facts.lan = self._lan_address(router_host)
        self._paths(facts)
        facts.pc = self._pc_line()
        facts.relay = self._relay_running()

        for job in slow.values():
            job.wait(deadline)
        facts.tailscale = str(slow["tailscale"].value or "")
        if "repo" in slow and slow["repo"].finished:
            self._repo_cache = str(slow["repo"].value or "")
        facts.repo = self._repo_cache or ""
        if "router" in slow:
            job = slow["router"]
            facts.router = ("slow" if not job.finished else
                            "ok" if not job.failed and _positive(job.value) else "down")
        facts.ssh_host_set = bool(self._ssh_host)
        facts.ssh_host = self._target(facts.tailscale, facts.lan)
        return facts

    def _router_host(self) -> str:
        host = getattr(self.router, "host", "")
        return host.strip() if isinstance(host, str) else ""

    def _lan_address(self, router_host: str) -> str:
        """This host's address on the network that leads to the router."""
        if not router_host:
            return ""
        try:
            return self._local_address(router_host) or ""
        except Exception:
            return ""

    def _target(self, tailscale: str, lan: str) -> str:
        return self._ssh_host or tailscale or lan

    def _paths(self, facts: Facts) -> None:
        facts.code = hostinfo.home_short(self._code_folder())
        facts.config = hostinfo.home_short(self.ctx.config_path or _default_config_path())
        vault_file = getattr(self.vault, "vault_path", None)
        vault_dir = Path(vault_file).parent if isinstance(vault_file, (str, Path)) \
            else _default_vault_dir()
        facts.vault = hostinfo.home_short(vault_dir)
        facts.state = hostinfo.home_short(Path(self.ctx.state_dir).parent)
        for name in ("self_backup", "config_backup"):
            folder = getattr(ui.plugin_named(self.ctx, name), "backup_dir", None)
            if isinstance(folder, (str, Path)):
                facts.backups.append(hostinfo.home_short(folder))

    def _pc_line(self) -> tuple[str, str] | None:
        """The workstation plugin's last reading (it never waits for ssh)."""
        pc = ui.plugin_named(self.ctx, "workstation")
        try:
            status = pc.api_status() if pc is not None else None
        except Exception:
            self.log.exception("access: workstation status unreadable")
            return None
        if not isinstance(status, dict):
            return None
        return str(status.get("name") or "PC"), str(status.get("state") or "unknown")

    def _relay_running(self) -> bool | None:
        """Whether HIDway's relay runs (read from its state file; sends nothing)."""
        remote = ui.plugin_named(self.ctx, "remote_keyboard")
        if remote is None or not getattr(remote, "configured", False):
            return None
        try:
            return remote.api_status().get("relay") == "running"
        except Exception:
            self.log.exception("access: remote keyboard status unreadable")
            return False

    # ─── the screens ─────────────────────────────────────────────

    def _main_screen(self, f: Facts) -> tuple[str, list]:
        text = ui.lines(
            ui.b(ui.header(ICON, "Access", "how to reach NetSentry")), ui.RULE,
            *self._host_lines(f), "",
            *self._ssh_lines(f), "",
            *self._service_lines(f), "",
            *self._path_lines(f),
            *self._reach_lines(f))
        return text, self._main_rows()

    @staticmethod
    def _host_lines(f: Facts) -> list[Any]:
        about = ", ".join(x for x in (f.model, f.os) if x)
        host = f.hostname or "this host"
        addresses = [ui.concat(label, ": ", ui.code(value))
                     for label, value in (("Tailscale", f.tailscale), ("LAN", f.lan)) if value]
        return [f"🖥 Host: {host}" + (f" ({about})" if about else ""),
                ui.concat("   ", ui.Safe(" · ".join(addresses))) if addresses
                else "   No address found for this host."]

    @staticmethod
    def _ssh_lines(f: Facts) -> list[Any]:
        if not f.ssh_host:
            return ["SSH: no address found for this host."]
        if f.tailscale or f.ssh_host_set:
            need = "needs your key and Tailscale"
        else:
            need = "needs your key; Tailscale is not running here, so from home only"
        return [f"SSH ({need}):", ui.concat("   ", ui.code(f"ssh {f.user}@{f.ssh_host}"))]

    @staticmethod
    def _service_lines(f: Facts) -> list[Any]:
        unit = f.unit
        return [ui.concat("⚙️ Service: ", ui.code(unit), f" · v{f.version} · up ",
                          ui.duration(f.up_s)),
                ui.concat("   ", ui.code(f"sudo systemctl status {unit}")),
                ui.concat("   ", ui.code(f"sudo systemctl restart {unit}")),
                ui.concat("   ", ui.code(f"journalctl -u {unit} -f"))]

    @staticmethod
    def _path_lines(f: Facts) -> list[Any]:
        out = [ui.concat("📁 Code: ", ui.code(f.code)),
               ui.concat("   Config: ", ui.code(f.config)),
               ui.concat("   Vault: ", ui.code(f.vault)),
               ui.concat("   State: ", ui.code(f.state))]
        if f.backups:
            out.append(ui.concat("   Backups: ",
                                 ui.Safe(" · ".join(ui.code(b) for b in f.backups))))
        if f.repo:
            out.append(ui.concat("   Repo: ", ui.code(f.repo)))
        return out

    @staticmethod
    def _reach_lines(f: Facts) -> list[Any]:
        lines: list[Any] = []
        if f.router_host:
            said = {"ok": f"{ui.OK} answering",
                    "slow": f"{ui.ATTENTION} not answering (no reply within seconds)",
                    }.get(f.router, f"{ui.ATTENTION} not answering")
            lines.append(ui.concat("   Router ", ui.code(f.router_host), " — ", said))
        if f.pc is not None:
            name, state = f.pc
            lines.append(f"   {name} — {_PC_STATE.get(state, _PC_STATE['unknown'])}")
        if f.relay is not None:
            lines.append("   HIDway relay — " + (f"{ui.OK} running" if f.relay
                                                  else f"{ui.ATTENTION} not running"))
        return ["", "🔗 From here it reaches:", *lines] if lines else []

    def _main_rows(self) -> list:
        name = self.ctx.name
        cells: list[dict[str, str]] = []
        dash = ui.plugin_named(self.ctx, "lan_dashboard")
        link = ""
        try:
            link = dash.deep_link() if dash is not None else ""
        except Exception:
            self.log.exception("access: dashboard link unavailable")
        if isinstance(link, str) and link.startswith(("https://", "http://")):
            cells.append(ui.url_button("🖥 Dashboard", link))
        if ui.plugin_named(self.ctx, "self_check") is not None:
            cells.append(ui.button("🩺 Health", "self_check:full"))
        cells += ui.command_row(self.ctx, ("🗄 Back up now", "/snapshot"),
                                ("🔁 Restart…", "/restart"))
        cells += [ui.button("➕ New computer", f"{name}:new"), ui.refresh_button(f"{name}:r")]
        return [cells[i:i + 2] for i in range(0, len(cells), 2)] + [ui.nav_row()]

    def _new_computer_screen(self, user: str, host: str) -> tuple[str, list]:
        host = host or _HOST_PLACEHOLDER
        login = f"{user}@{host}"
        add_key = (f'ssh {login} "mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
                   f"echo '{_KEY_PLACEHOLDER}' >> ~/.ssh/authorized_keys && "
                   'chmod 600 ~/.ssh/authorized_keys"')
        text = ui.lines(
            ui.b(ui.header("➕", "New computer", "give it access")), ui.RULE,
            "1. Install Tailscale on the new computer and sign in to the same "
            "Tailscale account as this host.",
            "",
            "2. Make a key on the new computer (Enter accepts the defaults):",
            ui.concat("   ", ui.code("ssh-keygen -t ed25519")),
            "",
            "3. From a computer that already has access, add the new computer's "
            "public key (the one line in ~/.ssh/id_ed25519.pub on it) — replace "
            f"{_KEY_PLACEHOLDER} with that line:",
            ui.concat("   ", ui.code(add_key)),
            "",
            "4. Test it from the new computer:",
            ui.concat("   ", ui.code(f"ssh {login}")),
            "",
            "NetSentry never adds a key itself and takes none through Telegram: "
            "whoever got hold of this Telegram account could then give themselves "
            "access to the host.")
        return text, [ui.nav_row(f"{self.ctx.name}:v")]


class _Background:
    """One slow fact fetched on a daemon thread, so a call that hangs can be
    abandoned instead of holding up the screen."""

    def __init__(self, func: Callable[[], Any]) -> None:
        self.value: Any = None
        self.failed = False
        self._done = threading.Event()
        threading.Thread(target=self._run, args=(func,), daemon=True,
                         name="access-fact").start()

    def _run(self, func: Callable[[], Any]) -> None:
        try:
            self.value = func()
        except Exception:
            self.failed = True
        finally:
            self._done.set()

    @property
    def finished(self) -> bool:
        return self._done.is_set()

    def wait(self, deadline: float) -> None:
        self._done.wait(max(0.0, deadline - time.monotonic()))


def _positive(value: Any) -> bool:
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def _service_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "user"


PLUGIN = AccessPlugin
