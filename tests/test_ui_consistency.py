"""One voice across the Telegram side: dates, lists, headers, buttons instead
of typed syntax or raw links, and old buttons that keep working."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from netsentry.core import ui
from netsentry.core.plugin import Plugin, PluginContext
from netsentry.plugins.access import AccessPlugin
from netsentry.plugins.ai_control import AiControlPlugin
from netsentry.plugins.channel_scan import ChannelScanPlugin
from netsentry.plugins.config_backup import ConfigBackupPlugin
from netsentry.plugins.github_explorer import GithubExplorerPlugin
from netsentry.plugins.guest_wifi_rotator import GuestWifiRotatorPlugin
from netsentry.plugins.lan_dashboard import LanDashboardPlugin
from netsentry.plugins.lan_scanner import LanScannerPlugin
from netsentry.plugins.locator import LocatorPlugin
from netsentry.plugins.maintenance import MaintenancePlugin
from netsentry.plugins.menu import MenuPlugin, _button_label
from netsentry.plugins.morning_briefing import MorningBriefingPlugin
from netsentry.plugins.pihole_stats import PiholeStatsPlugin
from netsentry.plugins.power import PowerPlugin
from netsentry.plugins.router_info import RouterInfoPlugin
from netsentry.plugins.security_actions import SecurityActionsPlugin
from netsentry.plugins.self_backup import SelfBackupPlugin
from netsentry.plugins.self_check import SelfCheckPlugin
from netsentry.plugins.settings import SettingsPlugin
from netsentry.plugins.site_watch import SiteWatchPlugin
from netsentry.plugins.speedtest import SpeedtestPlugin
from netsentry.plugins.telegram_bot import TelegramBotPlugin
from netsentry.plugins.threat_detector import ThreatDetectorPlugin
from netsentry.plugins.traffic_report import TrafficReportPlugin
from netsentry.plugins.who_asked import WhoAskedPlugin
from netsentry.plugins.wifi_monitor import WifiMonitorPlugin
from netsentry.plugins.workstation import WorkstationPlugin
from netsentry.plugins.youtube_bookmarks import YoutubeBookmarksPlugin

CHAT = 42
ALL_PLUGIN_CLASSES = [
    AccessPlugin, AiControlPlugin, ChannelScanPlugin, ConfigBackupPlugin, GithubExplorerPlugin,
    GuestWifiRotatorPlugin,
    LanDashboardPlugin, LanScannerPlugin, LocatorPlugin, MaintenancePlugin, MenuPlugin,
    PiholeStatsPlugin,
    PowerPlugin,
    RouterInfoPlugin, SecurityActionsPlugin, SelfBackupPlugin, SelfCheckPlugin,
    SettingsPlugin, SiteWatchPlugin, SpeedtestPlugin, TelegramBotPlugin, ThreatDetectorPlugin,
    WhoAskedPlugin, WifiMonitorPlugin, WorkstationPlugin, YoutubeBookmarksPlugin,
]


def _ctx(name: str, tmp_path: Path, **kw) -> PluginContext:
    (tmp_path / name).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        name=name, config=kw.pop("config", {}), router=kw.pop("router", Mock()),
        notifier=kw.pop("notifier", Mock()), vault=Mock(),
        logger=logging.getLogger(f"test.{name}"), state_dir=str(tmp_path / name), **kw)


def _keys(buttons) -> list[dict]:
    return [b for row in (buttons or []) for b in row]


# ─── ui helpers ─────────────────────────────────────────────────

def test_dates_are_english_24h_and_drop_the_current_year() -> None:
    now = datetime(2026, 11, 20, 12, 0)
    assert ui.fmt_when(datetime(2026, 11, 23, 9, 0), now) == "Mon 23 Nov 09:00"
    assert ui.fmt_when(datetime(2025, 1, 5, 21, 7), now) == "Sun 5 Jan 2025 21:07"
    assert ui.fmt_day(datetime(2026, 2, 1), now) == "Sun 1 Feb"


def test_fmt_when_does_not_follow_the_host_locale(monkeypatch) -> None:
    # %a / %b would follow LC_TIME; the helper must not use them for names.
    real = datetime.strftime

    def localised(self, fmt):           # what a Greek locale would give for %a/%b
        return real(self, fmt.replace("%a", "Δευ").replace("%b", "Νοε"))

    class Shim(datetime):
        strftime = localised

        def __format__(self, fmt):
            return localised(self, fmt)

    when = Shim(2026, 11, 23, 9, 0)
    assert ui.fmt_when(when, datetime(2026, 11, 20)) == "Mon 23 Nov 09:00"


def test_when_text_says_ago_under_a_day_and_the_date_after() -> None:
    now = datetime(2026, 11, 20, 12, 0)
    assert ui.when_text(now - timedelta(minutes=14), now) == "14 min ago"
    assert ui.when_text("2026-11-18T09:00:00", now) == "Wed 18 Nov 09:00"
    assert ui.when_text("not a date", now, default="never") == "never"
    assert ui.when_text(now + timedelta(days=1), now) == "Sat 21 Nov 12:00"   # future: a date


def test_list_helpers_lead_with_the_name_and_count_the_rest() -> None:
    assert ui.item("Kitchen plug", "IoT", "", "192.0.2.8", None, "-32 dBm") == \
        "Kitchen plug — IoT · 192.0.2.8 · -32 dBm"
    assert ui.item("Alone") == "Alone"
    assert ui.first_few(["a", "b", "c", "d", "e"]) == "a, b, c +2 more"
    assert ui.first_few(["a"]) == "a"
    assert ui.size(512) == "512 B" and ui.size(12 * 1024 * 1024) == "12.0 MB"
    assert ui.size(150 * 1024) == "150 KB"


def test_login_failure_lines_read_like_sentences() -> None:
    line = "jan/02 12:34:56 system,error,critical login failure for user admin from " \
           "192.0.2.5 via ssh"
    assert ui.login_failure(line) == "admin from 192.0.2.5 (ssh) — jan/02 12:34:56"
    assert ui.login_failure("something else") == "something else"


def test_replace_button_keeps_the_rest_of_the_keyboard() -> None:
    keyboard = [[{"text": "✅ Trust a.com", "callback_data": "td:allow:a.com"},
                 {"text": "🔎 Who asked?", "callback_data": "who_asked:q:a.com"}],
                [{"text": "🏠 Menu", "callback_data": "menu:h"}]]
    out = ui.replace_button(keyboard, "td:allow:a.com", ui.button("✔ Trusted", "td:noop:"))
    assert out[0][0]["text"] == "✔ Trusted" and out[0][1] == keyboard[0][1]
    assert out[1] == keyboard[1]
    assert ui.replace_button(keyboard, "nope", ui.button("x", "y")) is None


# ─── command descriptions ───────────────────────────────────────

def _all_commands() -> list[dict]:
    return [c for cls in ALL_PLUGIN_CLASSES for c in cls.COMMANDS]


def test_every_command_has_a_short_plain_description_with_its_own_emoji() -> None:
    commands = _all_commands()
    emoji = [c["description"].split(" ", 1)[0] for c in commands]
    assert len(emoji) == len(set(emoji)), emoji                     # one emoji per command
    for c in commands:
        desc = c["description"]
        text = desc.split(" ", 1)[1]
        assert len(text) <= 36, desc
        assert "/" not in text and "<" not in text and "|" not in text, desc   # no syntax
        assert ":" not in desc, desc                     # the menu cuts at ":"
        assert _button_label(f"/{c['command']}", desc) == desc
        assert desc.split(" ", 1)[0] not in ui.STATE_EMOJI, desc   # state emoji mean states


def test_help_is_the_one_place_with_typed_syntax(tmp_path: Path) -> None:
    bot = TelegramBotPlugin(_ctx("telegram_bot", tmp_path))
    bot._tg = Mock()
    who = WhoAskedPlugin(_ctx("who_asked", tmp_path))
    plugins = [bot, who]
    for p in plugins:
        p.ctx._all_plugins = plugins  # type: ignore[attr-defined]
    bot._command_map = {"/who": who, "/help": bot}
    bot._send_help(CHAT)
    text = bot._tg.send_to.call_args.args[1]
    assert text.startswith("❔ NetSentry commands — 2")
    assert "/who — 🔎 Which device asks for a domain\n   ⌨ /who <domain>" in text


# ─── threat report and screens ──────────────────────────────────

def _threat(tmp_path: Path, dashboard_url: str = "") -> ThreatDetectorPlugin:
    p = ThreatDetectorPlugin(_ctx("threat_detector", tmp_path))
    p.on_load()
    dash = Mock()
    dash.ctx = SimpleNamespace(name="lan_dashboard")
    dash.deep_link.return_value = dashboard_url
    dash.explain_url.return_value = dashboard_url and dashboard_url + "/explain"
    bot = Mock(spec=["keyboard_of", "ctx"])
    bot.ctx = SimpleNamespace(name="telegram_bot")
    p.ctx._all_plugins = [p, dash, bot]  # type: ignore[attr-defined]
    p._device_names = lambda: {"192.0.2.5": "Phone"}  # type: ignore[method-assign]
    p.router.arp_table.return_value = []
    return p


def _record(p: ThreatDetectorPlugin, kind: str, subjects: list[str]) -> None:
    for s in subjects:
        p._record_alert(kind, "alert", {"subject": s, "detail": "x", "severity": "warning",
                                        "clients": ["192.0.2.5"]})


def test_report_opens_with_the_verdict_and_caps_each_kind_at_three(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    _record(p, "suspicious_tld", ["a.top", "b.top", "c.top", "d.top", "e.top"])
    p.on_command("/report", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    assert text.startswith("🛡 Report — ⚠️ 5 to review")
    assert "⚠️ Suspicious TLD (5): a.top, b.top, c.top +2 more — from Phone (192.0.2.5)" in text
    assert "Homelab" not in text and "/allow" not in text and "/note" not in text
    keys = _keys(p.notifier.send_to.call_args.kwargs["buttons"])
    assert any(k["text"] == "✅ Trust a.top" for k in keys)
    assert keys[-1] == {"text": "🏠 Menu", "callback_data": "menu:h"}
    assert not any("url" in k for k in keys)                # no dashboard address: no link


def test_quiet_report_says_nothing_to_review(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    p.send_report()
    kind, text = p.notifier.notify.call_args.args
    assert kind == "report" and text.startswith("🛡 Daily report — ✅ nothing to review")


def test_dashboard_links_are_buttons_never_text(tmp_path: Path) -> None:
    url = "https://dash.example/auth?token=SECRET&next=/threats"
    p = _threat(tmp_path, dashboard_url=url)
    _record(p, "suspicious_tld", ["a.top"])
    p.on_command("/report", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    assert "SECRET" not in text and "https://" not in text
    keys = _keys(p.notifier.send_to.call_args.kwargs["buttons"])
    assert {"text": "🖥 Open in dashboard", "url": url} in keys


def test_trust_turns_its_button_into_a_record(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    data = "threat_detector:allow:a.top"
    keyboard = [[{"text": "✅ Trust a.top", "callback_data": data}],
                [{"text": "🏠 Menu", "callback_data": "menu:h"}]]
    bot = next(x for x in p.ctx._all_plugins if hasattr(x, "keyboard_of"))  # type: ignore[attr-defined]
    bot.keyboard_of.return_value = keyboard
    p.on_callback(data, CHAT, 7, "cb")
    assert "a.top" in p._state()["allowed_domains"]
    chat, message, buttons = p.notifier.edit_buttons.call_args.args
    assert (chat, message) == (CHAT, 7)
    assert buttons[0] == [{"text": "✔ Trusted a.top", "callback_data": "threat_detector:noop:"}]
    assert buttons[1] == keyboard[1]
    p.on_callback("threat_detector:noop:", CHAT, 7, "cb")              # tapping the record
    p.notifier.answer_callback.assert_called_with("cb", "Already done")


def test_bare_deny_and_note_open_something_useful(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    p.api_set_allow("cdn.example.net", True)
    p.on_command("/deny", "", CHAT)
    assert "Trusted domains" in p.notifier.send_to.call_args.args[1]
    assert "wasn't in your trusted list" not in p.notifier.send_to.call_args.args[1]
    p.on_command("/deny", "never.example", CHAT)
    assert "never.example wasn't on your trusted list" in p.notifier.send_to.call_args.args[1]
    p.on_command("/note", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    assert "Usage" not in text and "To label a domain" in text


def test_threat_screens_end_with_the_standard_last_row(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    for command in ("/scans", "/audit", "/allow", "/threats", "/intel"):
        p.notifier.reset_mock()
        p.on_command(command, "", CHAT)
        rows = p.notifier.send_to.call_args.kwargs["buttons"]
        assert rows[-1][-1] == {"text": "🏠 Menu", "callback_data": "menu:h"}, command


def test_old_threat_callbacks_still_work(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    p.on_callback("threat_detector:allow:old.example", CHAT, 7, "cb")
    p.on_callback("threat_detector:deny:old.example", CHAT, 7, "cb")
    p.on_callback("threat_detector:audit:1", CHAT, 7, "cb")
    p.on_callback("threat_detector:scan:new_domain", CHAT, 7, "cb")
    assert "old.example" not in p._state().get("allowed_domains", [])
    assert p._state().get("audit_until")


# ─── the bot hands a plugin the keyboard it is answering ────────

def test_bot_shows_the_tapped_keyboard_only_during_the_callback(tmp_path: Path) -> None:
    bot = TelegramBotPlugin(_ctx("telegram_bot", tmp_path))
    bot._tg = Mock(allowed_chats={CHAT})
    bot._cp_lock, bot._keyboards = threading.Lock(), {}
    seen = []

    class _Target(Plugin):
        def on_callback(self, data, chat_id, message_id, callback_id):
            seen.append(bot.keyboard_of(chat_id, message_id))

    target = _Target(_ctx("target", tmp_path))
    bot.ctx._all_plugins = [bot, target]  # type: ignore[attr-defined]
    keyboard = [[{"text": "x", "callback_data": "target:x"}]]
    bot._handle_callback({"id": "cb", "data": "target:x", "from": {"id": CHAT},
                          "message": {"chat": {"id": CHAT}, "message_id": 9,
                                      "reply_markup": {"inline_keyboard": keyboard}}})
    assert seen == [keyboard]
    assert bot.keyboard_of(CHAT, 9) is None


# ─── lists lead with the name ───────────────────────────────────

def test_clients_lead_with_the_name_and_skip_column_padding(tmp_path: Path) -> None:
    router = Mock()
    router.wifi_clients.return_value = [SimpleNamespace(
        mac="AA:BB:CC:DD:EE:01", ssid="IoT", signal_dbm=-32, band="2ghz-n")]
    router.ethernet_clients.return_value = []
    router.dhcp_leases.return_value = [SimpleNamespace(
        mac="AA:BB:CC:DD:EE:01", ip="192.0.2.8", hostname="plug-1")]
    p = RouterInfoPlugin(_ctx("router_info", tmp_path, router=router))
    p.ctx._all_plugins = [p]  # type: ignore[attr-defined]
    p.on_command("/clients", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    assert "• plug-1 — 192.0.2.8 · -32 dBm · 2ghz-n" in text
    assert "  " not in text.split("\n", 2)[2]                 # no alignment padding
    p.on_callback("router_info:r:clients", CHAT, 7, "cb")      # 🔄 Refresh: in place
    assert p.notifier.edit_message.call_args.args[:2] == (CHAT, 7)


# ─── leftovers of the previous pass ─────────────────────────────

def test_morning_briefing_ends_in_buttons_not_typed_commands(tmp_path: Path) -> None:
    router = Mock()
    router.stats.return_value = SimpleNamespace(
        uptime_seconds=3 * 86400, cpu_load_pct=3, free_memory_bytes=50,
        total_memory_bytes=100, free_disk_bytes=50 * 1024 * 1024)
    router.wifi_clients.return_value = []
    p = MorningBriefingPlugin(_ctx("morning_briefing", tmp_path, router=router))
    checker = Mock()
    checker.ctx = SimpleNamespace(name="self_check")
    checker.summary_line.return_value = "🩺 Health: all 9 checks OK"
    p.ctx._all_plugins = [p, checker]  # type: ignore[attr-defined]
    p._sql = lambda q: ""  # type: ignore[method-assign]
    p.on_load()
    p.send_briefing()
    kind, text = p.notifier.notify.call_args.args
    assert kind == "report" and text.startswith("☀️ Good morning — ")
    assert "/health" not in text and "/status" not in text
    keys = _keys(p.notifier.notify.call_args.kwargs["buttons"])
    assert {"text": "🩺 Full check", "callback_data": "self_check:full"} in keys


def test_traffic_report_is_english(tmp_path: Path) -> None:
    today = datetime.now()
    hour = {"date": {"year": today.year, "month": today.month, "day": today.day},
            "time": {"hour": 9}, "rx": 2048, "tx": 1024, "timestamp": 0}
    day = {"date": {"year": today.year, "month": today.month, "day": today.day},
           "rx": 2048, "tx": 1024}
    p = TrafficReportPlugin(_ctx("traffic_report", tmp_path))
    p.on_load()
    p._vnstat = lambda mode: {"interfaces": [{"traffic": {"hour": [hour], "day": [day]}}]}  # type: ignore[method-assign]
    p.send_report()
    text = p.notifier.notify.call_args.args[1]
    assert text.startswith("📈 Traffic today — 3.0 KB")
    assert not any("Ͱ" <= ch <= "Ͽ" for ch in text)         # no Greek left


def test_settings_opens_the_rotation_in_place_with_back_to_settings(tmp_path: Path) -> None:
    settings = SettingsPlugin(_ctx("settings", tmp_path))
    rotator = GuestWifiRotatorPlugin(_ctx("guest_wifi_rotator", tmp_path,
                                          config={"ssid": "Guest"}))
    rotator.ctx.scheduler = None
    rotator.on_load()
    rotator.notifier = settings.notifier
    plugins = [settings, rotator]
    for p in plugins:
        p.ctx._all_plugins = plugins  # type: ignore[attr-defined]
    settings.on_callback("settings:rot", CHAT, 7, "cb")              # the old button
    call = settings.notifier.edit_message.call_args
    assert call.args[:2] == (CHAT, 7) and "password schedule" in call.args[2]
    rows = call.kwargs["buttons"]
    assert rows[-1][0] == {"text": "⬅ Back", "callback_data": "settings:h"}
