"""/access: how to reach and manage NetSentry from another computer."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from netsentry import __version__
from netsentry.core import hostinfo, ui
from netsentry.core.plugin import PluginContext
from netsentry.plugins.access import AccessPlugin

CHAT = 42
TOKEN = "s3cr3t-dashboard-token-123"


class FakeNotifier:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str, list | None, bool]] = []
        self.edited: list[tuple[int, int, str, list | None, bool]] = []
        self.answered: list[tuple[str, str]] = []

    def send_to(self, chat_id, text, *, buttons=None, html=False, **_):
        self.sent.append((chat_id, text, buttons, html))
        return True

    def edit_message(self, chat_id, message_id, text, buttons=None, *, html=False):
        self.edited.append((chat_id, message_id, text, buttons, html))

    def answer_callback(self, callback_id, text=""):
        self.answered.append((callback_id, text))


class FakeRouter:
    def __init__(self, host: str = "192.0.2.1", uptime=lambda: 86400) -> None:
        self.host = host
        self._uptime = uptime

    def uptime_seconds(self) -> int:
        return self._uptime()


def _other(name: str, commands: tuple[str, ...] = (), **attrs) -> SimpleNamespace:
    """A stand-in for another loaded plugin, found by name like the real ones."""
    return SimpleNamespace(ctx=SimpleNamespace(name=name),
                           COMMANDS=[{"command": c, "description": "x"} for c in commands],
                           **attrs)


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


def _access(home: Path, *, config: dict | None = None, router=None, others=(),
            vault=None, tailscale: str | None = "100.64.0.10",
            repo: str = "https://example.com/user/NetSentry",
            lan: str = "192.0.2.10",
            host=("pi.example", "Raspberry Pi 4 Model B", "Debian GNU/Linux 13 (trixie)"),
            ) -> AccessPlugin:
    state = home / ".local" / "share" / "netsentry" / "access"
    state.mkdir(parents=True, exist_ok=True)
    ctx = PluginContext(
        name="access", config=config or {}, router=router or FakeRouter(),
        notifier=FakeNotifier(),
        vault=vault or SimpleNamespace(vault_path=home / ".config" / "netsentry" / "secrets.enc"),
        logger=logging.getLogger("test.access"), state_dir=str(state),
        config_path=str(home / ".config" / "netsentry" / "config.yaml"))
    plugin = AccessPlugin(ctx)
    plugin.on_load()
    plugin._tailscale = lambda: tailscale
    plugin._git_remote = lambda folder: repo
    plugin._host_facts = lambda: host
    plugin._local_address = lambda router_host: lan
    plugin._code_folder = lambda: home / "NetSentry"
    plugin._user = lambda: "user"
    plugin._started = 1000.0
    plugin._now = lambda: 1000.0 + 3 * 3600
    ctx._all_plugins = [plugin, *others]  # type: ignore[attr-defined]
    return plugin


def _everything(home: Path) -> list:
    return [
        _other("menu", ("menu",)),
        _other("self_check", ("health",)),
        _other("self_backup", ("snapshot",), backup_dir=home / "backups" / "netsentry"),
        _other("config_backup", ("backup",), backup_dir=home / "backups" / "router"),
        _other("power", ("restart",)),
        _other("lan_dashboard", ("dashboard",),
               deep_link=lambda path="/": f"https://pi.example/auth?token={TOKEN}&next={path}"),
        _other("workstation", ("pc",),
               api_status=lambda: {"name": "Gaming PC", "state": "on", "checked_ts": 1.0}),
        _other("remote_keyboard", configured=True,
               api_status=lambda: {"configured": True, "relay": "running"}),
    ]


def _keys(rows) -> list[dict]:
    return [k for row in (rows or []) for k in row]


def _open(plugin: AccessPlugin) -> tuple[str, list]:
    plugin.on_command("/access", "", CHAT)
    _, text, rows, html = plugin.notifier.sent[-1]
    assert html is True
    return text, rows


EXPECTED = f"""<b>🔑 Access — how to reach NetSentry</b>
━━━━━━━━━━━━━━━━━
🖥 Host: pi.example (Raspberry Pi 4 Model B, Debian GNU/Linux 13 (trixie))
   Tailscale: <code>100.64.0.10</code> · LAN: <code>192.0.2.10</code>

SSH (needs your key and Tailscale):
   <code>ssh user@100.64.0.10</code>

⚙️ Service: <code>netsentry.service</code> · v{__version__} · up 3 h
   <code>sudo systemctl status netsentry.service</code>
   <code>sudo systemctl restart netsentry.service</code>
   <code>journalctl -u netsentry.service -f</code>

📁 Code: <code>~/NetSentry</code>
   Config: <code>~/.config/netsentry/config.yaml</code>
   Vault: <code>~/.config/netsentry</code>
   State: <code>~/.local/share/netsentry</code>
   Backups: <code>~/backups/netsentry</code> · <code>~/backups/router</code>
   Repo: <code>https://example.com/user/NetSentry</code>

🔗 From here it reaches:
   Router <code>192.0.2.1</code> — ✅ answering
   Gaming PC — ✅ on
   HIDway relay — ✅ running"""


# ─── the screen ──────────────────────────────────────────────────

def test_the_screen_shows_every_way_in_when_everything_is_available(home: Path) -> None:
    text, rows = _open(_access(home, others=_everything(home)))
    assert text == EXPECTED
    labels = [[k["text"] for k in row] for row in rows]
    assert labels == [["🖥 Dashboard", "🩺 Health"], ["🗄 Back up now", "🔁 Restart…"],
                      ["➕ New computer", "🔄 Refresh"], ["🏠 Menu"]]
    keys = _keys(rows)
    assert keys[0]["url"].startswith("https://pi.example/auth?token=")
    assert {k.get("callback_data") for k in keys[1:]} == {
        "self_check:full", "menu:r:/snapshot", "menu:r:/restart", "access:new",
        "access:r", "menu:h"}


def test_the_plain_text_fallback_still_reads_well(home: Path) -> None:
    text, _ = _open(_access(home, others=_everything(home)))
    plain = ui.strip_html(text)
    assert "<" not in plain.replace("<code>", "")
    assert "   ssh user@100.64.0.10" in plain
    assert "   sudo systemctl restart netsentry.service" in plain


def test_without_tailscale_git_dashboard_or_other_plugins_lines_and_buttons_go(
        home: Path) -> None:
    text, rows = _open(_access(home, tailscale=None, repo=""))
    assert "Tailscale" in text and "100.64" not in text      # only the hint that it's missing
    assert "   LAN: <code>192.0.2.10</code>" in text
    assert "<code>ssh user@192.0.2.10</code>" in text
    assert "Repo" not in text and "Backups" not in text
    assert "Gaming PC" not in text and "HIDway" not in text
    assert "Router <code>192.0.2.1</code> — ✅ answering" in text
    assert [[k["text"] for k in row] for row in rows] == [
        ["➕ New computer", "🔄 Refresh"], ["🏠 Menu"]]


def test_no_router_address_and_no_host_facts_do_not_crash(home: Path) -> None:
    plugin = _access(home, router=SimpleNamespace(), tailscale=None, lan="", repo="",
                     host=("", "", ""))
    text, _ = _open(plugin)
    assert "🖥 Host: this host\n   No address found for this host." in text
    assert "SSH: no address found for this host." in text
    assert "From here it reaches" not in text


def test_command_buttons_need_the_menu_runner_and_the_command(home: Path) -> None:
    # self_backup and power are loaded, but no menu plugin to run commands with.
    others = [_other("self_backup", ("snapshot",), backup_dir=home / "b"),
              _other("power", ("restart",)), _other("self_check", ("health",))]
    _, rows = _open(_access(home, others=others))
    texts = [k["text"] for k in _keys(rows)]
    assert "🩺 Health" in texts                     # its own callback, no menu needed
    assert "🗄 Back up now" not in texts and "🔁 Restart…" not in texts
    # The menu is there, but /restart is not.
    others = [_other("menu", ("menu",)), _other("self_backup", ("snapshot",), backup_dir=home)]
    _, rows = _open(_access(home, others=others))
    texts = [k["text"] for k in _keys(rows)]
    assert "🗄 Back up now" in texts and "🔁 Restart…" not in texts and "🩺 Health" not in texts


def test_the_pc_and_relay_say_plainly_when_they_are_not_there(home: Path) -> None:
    others = [_other("workstation", api_status=lambda: {"name": "Desk <PC>", "state": "off"}),
              _other("remote_keyboard", configured=True,
                     api_status=lambda: {"relay": "not running"})]
    text, _ = _open(_access(home, others=others, router=FakeRouter(uptime=lambda: 0)))
    assert "Router <code>192.0.2.1</code> — ⚠️ not answering" in text
    assert "   Desk &lt;PC&gt; — 😴 off or asleep" in text
    assert "   HIDway relay — ⚠️ not running" in text


def test_an_unconfigured_pc_or_relay_has_no_line(home: Path) -> None:
    others = [_other("workstation", api_status=lambda: None),
              _other("remote_keyboard", configured=False, api_status=lambda: {})]
    text, _ = _open(_access(home, others=others))
    assert "Gaming PC" not in text and "HIDway" not in text


def test_config_keys_change_the_unit_the_ssh_host_and_the_repo(home: Path) -> None:
    plugin = _access(home, repo="", config={
        "service": "netsentry-dev.service", "ssh_host": "pi.example",
        "repo_url": "https://user:ghp_token@example.com/user/NetSentry.git"})
    text, _ = _open(plugin)
    assert "<code>ssh user@pi.example</code>" in text
    assert "<code>journalctl -u netsentry-dev.service -f</code>" in text
    assert "Repo: <code>https://example.com/user/NetSentry</code>" in text
    assert "ghp_token" not in text


def test_hostile_config_values_are_refused_not_shown(home: Path) -> None:
    plugin = _access(home, config={"service": "x; rm -rf /", "ssh_host": "a b<c>"})
    text, _ = _open(plugin)
    assert "rm -rf" not in text and "a b<c>" not in text
    assert "<code>sudo systemctl status netsentry.service</code>" in text
    assert "<code>ssh user@100.64.0.10</code>" in text


def test_a_hostile_hostname_and_path_are_escaped(home: Path) -> None:
    plugin = _access(home, host=("<b>evil</b>&co", "", ""))
    plugin._code_folder = lambda: home / "a<i>b&c"
    text, _ = _open(plugin)
    assert "🖥 Host: &lt;b&gt;evil&lt;/b&gt;&amp;co" in text
    assert "<code>~/a&lt;i&gt;b&amp;c</code>" in text
    assert "<b>evil" not in text and "<i>" not in text


def test_no_secret_ever_reaches_the_text(home: Path) -> None:
    secrets = ["123456:AAH-telegram-bot-token", "hunter2-router-password",
               "gAAAAAB-vault-value", "987654321", TOKEN]
    vault = SimpleNamespace(vault_path=home / ".config" / "netsentry" / "secrets.enc",
                            get=lambda key: secrets[2])
    plugin = _access(home, vault=vault, others=_everything(home), config={
        "token": secrets[0], "password": secrets[1], "chat_id": secrets[3],
        "allowed_chats": [int(secrets[3])]})
    plugin.router.password = secrets[1]
    text, rows = _open(plugin)
    plugin.on_callback("access:new", CHAT, 7, "cb")
    new_text = plugin.notifier.edited[-1][2]
    for shown in (text, ui.strip_html(text), new_text):
        for secret in secrets:
            assert secret not in shown
    # the dashboard link only exists as a URL button
    assert any(TOKEN in k.get("url", "") for k in _keys(rows))


def test_every_callback_fits_in_64_bytes(home: Path) -> None:
    plugin = _access(home, others=_everything(home))
    _, rows = _open(plugin)
    plugin.on_callback("access:new", CHAT, 7, "cb")
    for key in _keys(rows) + _keys(plugin.notifier.edited[-1][3]):
        assert len(key.get("callback_data", "").encode()) <= 64


# ─── refresh, new computer, back ─────────────────────────────────

def test_refresh_redraws_the_same_message(home: Path) -> None:
    plugin = _access(home, others=_everything(home))
    plugin.on_callback("access:r", CHAT, 7, "cb")
    assert plugin.notifier.sent == []
    chat, message_id, text, rows, html = plugin.notifier.edited[-1]
    assert (chat, message_id, html) == (CHAT, 7, True) and text == EXPECTED
    assert plugin.notifier.answered == [("cb", "Refreshed")]


def test_new_computer_lists_the_steps_and_back_returns(home: Path) -> None:
    plugin = _access(home)
    plugin.on_callback("access:new", CHAT, 7, "cb")
    _, message_id, text, rows, html = plugin.notifier.edited[-1]
    assert message_id == 7 and html
    assert text.startswith("<b>➕ New computer — give it access</b>\n" + ui.RULE)
    assert "<code>ssh-keygen -t ed25519</code>" in text
    assert ("<code>ssh user@100.64.0.10 \"mkdir -p ~/.ssh &amp;&amp; chmod 700 ~/.ssh "
            "&amp;&amp; echo 'PASTE-THE-NEW-PUBLIC-KEY-HERE' &gt;&gt; ~/.ssh/authorized_keys "
            "&amp;&amp; chmod 600 ~/.ssh/authorized_keys\"</code>") in text
    assert "   <code>ssh user@100.64.0.10</code>" in text
    assert "takes none through Telegram" in text
    assert [k["callback_data"] for k in _keys(rows)] == ["access:v", "menu:h"]
    plugin.on_callback("access:v", CHAT, 7, "cb2")
    assert plugin.notifier.edited[-1][2].startswith("<b>🔑 Access")


def test_new_computer_without_any_address_uses_a_marked_placeholder(home: Path) -> None:
    plugin = _access(home, tailscale=None, lan="")
    plugin.on_callback("access:new", CHAT, 7, "cb")
    assert "<code>ssh user@HOST-ADDRESS</code>" in plugin.notifier.edited[-1][2]


# ─── never hangs ─────────────────────────────────────────────────

def test_a_hanging_router_does_not_hold_up_the_screen(home: Path) -> None:
    release = threading.Event()
    plugin = _access(home, router=FakeRouter(uptime=lambda: release.wait(30) and 1))
    plugin._router_timeout_s = 0.2
    try:
        started = time.monotonic()
        text, _ = _open(plugin)
        assert time.monotonic() - started < 2.0
        assert "Router <code>192.0.2.1</code> — ⚠️ not answering" in text
        assert "<code>ssh user@100.64.0.10</code>" in text
    finally:
        release.set()


def test_a_router_that_raises_is_not_answering(home: Path) -> None:
    def boom() -> int:
        raise OSError("ssh refused")
    text, _ = _open(_access(home, router=FakeRouter(uptime=boom)))
    assert "— ⚠️ not answering" in text and "ssh refused" not in text


def test_the_git_remote_is_read_once(home: Path) -> None:
    plugin = _access(home)
    calls = []
    plugin._git_remote = lambda folder: calls.append(folder) or "https://example.com/u/r"
    plugin.gather()
    plugin.gather()
    assert len(calls) == 1


# ─── host facts ──────────────────────────────────────────────────

@pytest.mark.parametrize(("remote", "shown"), [
    ("git@github.com:user/NetSentry.git", "https://github.com/user/NetSentry"),
    ("ssh://git@example.com:2222/user/repo.git", "https://example.com/user/repo"),
    ("https://user:ghp_secret@example.com/user/repo.git?x=1#y", "https://example.com/user/repo"),
    ("http://example.com:8080/repo", "http://example.com:8080/repo"),
    ("file:///srv/repo.git", ""),
    ("", ""),
    ("not a url", ""),
])
def test_git_remotes_are_shown_readable_and_without_credentials(remote: str, shown: str) -> None:
    assert hostinfo.readable_remote(remote) == shown


def test_host_facts_degrade_when_the_files_are_missing(tmp_path: Path) -> None:
    assert hostinfo.host_model(str(tmp_path / "nope")) == ""
    assert hostinfo.os_name(str(tmp_path / "nope"))           # platform's answer instead
    release = tmp_path / "os-release"
    release.write_text('NAME="X"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n', encoding="utf-8")
    assert hostinfo.os_name(str(release)) == "Debian GNU/Linux 13 (trixie)"
    model = tmp_path / "model"
    model.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
    assert hostinfo.host_model(str(model)) == "Raspberry Pi 4 Model B Rev 1.5"
    assert hostinfo.process_started() <= time.time()


def test_home_paths_are_shown_with_a_tilde(home: Path) -> None:
    assert hostinfo.home_short(home / ".config" / "netsentry") == "~/.config/netsentry"
    assert hostinfo.home_short(home) == "~"


def test_tailscale_missing_means_no_address(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*args, **kwargs):
        raise FileNotFoundError("tailscale")
    monkeypatch.setattr("netsentry.core.hostinfo.subprocess.run", missing)
    assert hostinfo.tailscale_ipv4() is None
    monkeypatch.setattr("netsentry.core.hostinfo.subprocess.run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout="100.64.0.10\n"))
    assert hostinfo.tailscale_ipv4() == "100.64.0.10"
