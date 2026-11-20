"""Everything reachable by tapping — the owner should never have to remember
a sub-command or an argument format."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import Plugin, PluginContext
from netsentry.plugins.menu import MenuPlugin, _button_label
from netsentry.plugins.telegram_bot import TelegramBotPlugin
from netsentry.plugins.threat_detector import ThreatDetectorPlugin, threat_intel


def _ctx(name: str, tmp_path: Path, **kw) -> PluginContext:
    (tmp_path / name).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        name=name, config=kw.pop("config", {}), router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger(f"test.{name}"),
        state_dir=str(tmp_path / name), **kw)


class _Recorder(Plugin):
    """A stand-in plugin that just records the commands it is asked to run."""

    def __init__(self, ctx: PluginContext, commands: list[dict]) -> None:
        super().__init__(ctx)
        self.COMMANDS = commands
        self.ran: list[tuple[str, str, int]] = []

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        self.ran.append((command, args, chat_id))


def _wired(tmp_path: Path):
    """A bot + menu + two feature plugins, wired the way the runtime does it."""
    bot = TelegramBotPlugin(_ctx("telegram_bot", tmp_path))
    bot._tg = Mock()
    bot._command_map = {}
    bot._confirm_cmds = {"/rotate"}
    bot._pending, bot._pending_ttl_s = {}, 120.0
    import threading
    bot._cp_lock = threading.Lock()
    info = _Recorder(_ctx("router_info", tmp_path), [
        {"command": "status", "description": "📊 Network dashboard"},
        {"command": "log", "description": "📋 Last router log entries"}])
    guest = _Recorder(_ctx("guest_wifi_rotator", tmp_path), [
        {"command": "rotate", "description": "🔄 Rotate guest WiFi password + QR"}])
    extra = _Recorder(_ctx("brand_new_plugin", tmp_path), [
        {"command": "shiny", "description": "✨ Something new: /shiny <x>"}])
    menu = MenuPlugin(_ctx("menu", tmp_path))
    plugins = [bot, info, guest, extra, menu]
    for p in plugins:
        p.ctx._all_plugins = plugins  # type: ignore[attr-defined]
    bot._build_dispatch_table(plugins)
    return bot, menu, info, guest, extra


def _buttons(call) -> list[dict]:
    return [k for row in call.kwargs["buttons"] for k in row]


def _tap(menu: MenuPlugin, label_part: str) -> None:
    call = menu.notifier.edit_message.call_args or menu.notifier.send_to.call_args
    key = next(k for k in _buttons(call) if label_part in k["text"])
    menu.on_callback(key["callback_data"], 42, 7, "cb")


def test_menu_lists_areas_and_runs_a_command_by_tapping(tmp_path: Path) -> None:
    bot, menu, info, _, _ = _wired(tmp_path)

    menu.on_command("/menu", "", 42)
    labels = [k["text"] for k in _buttons(menu.notifier.send_to.call_args)]
    assert any("Network" in t for t in labels) and any("Guest WiFi" in t for t in labels)

    _tap(menu, "Network")
    _tap(menu, "Network dashboard")

    assert info.ran == [("/status", "", 42)]


def test_new_plugins_show_up_without_touching_the_menu(tmp_path: Path) -> None:
    _, menu, _, _, extra = _wired(tmp_path)
    menu.on_command("/menu", "", 42)

    _tap(menu, "Other")
    _tap(menu, "Something new")

    assert extra.ran == [("/shiny", "", 42)]


def test_risky_command_from_the_menu_still_asks_first(tmp_path: Path) -> None:
    bot, menu, _, guest, _ = _wired(tmp_path)
    menu.on_command("/menu", "", 42)

    _tap(menu, "Guest WiFi")
    _tap(menu, "Rotate guest WiFi")

    assert guest.ran == []                                # not run yet…
    assert "Run /rotate?" in bot._tg.send_to.call_args.args[1]  # …a confirmation was asked


def test_menu_back_and_forged_callbacks(tmp_path: Path) -> None:
    _, menu, info, _, _ = _wired(tmp_path)
    menu.on_command("/menu", "", 42)
    _tap(menu, "Network")
    _tap(menu, "Back")
    assert "NetSentry menu" in menu.notifier.edit_message.call_args.args[2]

    menu.on_callback("menu:r:/does-not-exist", 42, 7, "cb")
    menu.on_callback("menu:c:nope", 42, 7, "cb")           # unknown area → home
    assert info.ran == []


def test_every_menu_button_fits_telegram_limits(tmp_path: Path) -> None:
    _, menu, _, _, _ = _wired(tmp_path)
    menu.on_command("/menu", "", 42)
    keys = _buttons(menu.notifier.send_to.call_args)
    for group in menu._grouped():
        menu._show_category(42, 7, group[0])
        keys += _buttons(menu.notifier.edit_message.call_args)
    assert all(len(k["callback_data"].encode()) <= 64 for k in keys)


def test_button_label_drops_usage_hints() -> None:
    assert _button_label("/allow", "✅ Trust a domain (stop alerting): /allow <domain>") == \
        "✅ Trust a domain (stop alerting)"
    assert _button_label("/domains", "📇 Domain history (/domains <search>)") == "📇 Domain history"


# ─── threat_detector: choices as buttons ─────────────────────────

def _threat(tmp_path: Path) -> ThreatDetectorPlugin:
    p = ThreatDetectorPlugin(_ctx("threat_detector", tmp_path))
    p.on_load()
    return p


def test_detectors_toggle_by_tapping(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    assert p._enabled()["new_domain"] is False

    p.on_callback("threat_detector:scan:new_domain", 42, 7, "cb")
    assert p._enabled()["new_domain"] is True
    redraw = [k["text"] for k in _buttons(p.notifier.edit_message.call_args)]
    assert any(t.startswith("✅") and "New domain" in t for t in redraw)

    p.on_callback("threat_detector:scan:new_domain", 42, 7, "cb")
    assert p._enabled()["new_domain"] is False
    p.on_callback("threat_detector:scan:not_a_detector", 42, 7, "cb")   # ignored
    assert "scans_enabled" in p._state() and "not_a_detector" not in p._state()["scans_enabled"]


def test_audit_is_buttons_and_bare_command_no_longer_switches_it_on(tmp_path: Path) -> None:
    p = _threat(tmp_path)

    p.on_command("/audit", "", 42)
    assert "audit_until" not in p._state()                 # just showed the choices
    labels = [k["text"] for k in _buttons(p.notifier.send_to.call_args)]
    assert labels[:3] == ["1 hour", "6 hours", "24 hours"]
    assert "⏹ Turn off" not in labels                      # nothing to turn off yet
    assert labels[-1] == "🏠 Menu"

    p.on_callback("threat_detector:audit:6", 42, 7, "cb")
    assert p._enabled()["new_domain"] is True and "on until" in p.notifier.edit_message.call_args.args[2]
    assert "⏹ Turn off" in [k["text"] for k in _buttons(p.notifier.edit_message.call_args)]
    p.on_callback("threat_detector:audit:off", 42, 7, "cb")
    assert "audit_until" not in p._state()
    p.on_callback("threat_detector:audit:9999", 42, 7, "cb")            # not offered → ignored
    assert "audit_until" not in p._state()


def test_trusted_list_has_a_remove_button_per_domain(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    p.api_set_allow("cdn.example.net", True)
    p.api_set_allow("games.example.org", True)

    p.on_command("/allow", "", 42)
    keys = _buttons(p.notifier.send_to.call_args)
    assert [k["text"] for k in keys] == ["↩️ Stop trusting cdn.example.net",
                                         "↩️ Stop trusting games.example.org", "🏠 Menu"]

    p.on_callback(keys[0]["callback_data"], 42, 7, "cb")
    assert p._state()["allowed_domains"] == ["games.example.org"]


def test_trust_buttons_offer_only_untrusted_domains_and_fit(tmp_path: Path) -> None:
    p = _threat(tmp_path)
    p.api_set_allow("already.example", True)
    long_fqdn = "a" * 60 + ".tracking.vendor.example"

    rows = p._trust_buttons(["flagged.example", "x.already.example", long_fqdn,
                             "flagged.example"])

    labels = [r[0]["text"] for r in rows]
    assert labels == ["✅ Trust flagged.example", "✅ Trust tracking.vendor.example"]
    assert all(len(r[0]["callback_data"].encode()) <= 64 for r in rows)

    p.on_callback(rows[0][0]["callback_data"], 42, 7, "cb")
    assert "flagged.example" in p._state()["allowed_domains"]


# ─── feeds ───────────────────────────────────────────────────────

def test_feed_failure_keeps_that_feeds_previous_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "feeds.json"
    feeds = [("A", "https://a.example/list"), ("B", "https://b.example/list")]
    lists = {"https://a.example/list": {f"a{i}.bad.example" for i in range(200)},
             "https://b.example/list": {f"b{i}.bad.example" for i in range(300)}}
    monkeypatch.setattr(threat_intel, "_fetch", lambda url, timeout: lists[url])
    assert threat_intel.refresh(cache, feeds=feeds) == (500, True)

    def b_is_down(url: str, timeout: int) -> set[str]:
        if "b.example" in url:
            raise OSError("HTTP Error 410: Gone")
        return {f"a{i}.bad.example" for i in range(210)}

    monkeypatch.setattr(threat_intel, "_fetch", b_is_down)
    count, ok = threat_intel.refresh(cache, feeds=feeds)

    assert ok and count == 510                             # A grew, B's 300 were kept
    status = threat_intel.feed_status(cache)
    assert status["A"]["ok"] is True and status["B"]["ok"] is False
    assert "410" in status["B"]["error"] and status["B"]["last_ok"]
    assert threat_intel.load(cache)[0]["b7.bad.example"] == "B"


def test_total_failure_leaves_the_cache_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "feeds.json"
    monkeypatch.setattr(threat_intel, "_fetch",
                        lambda url, timeout: {f"x{i}.bad.example" for i in range(150)})
    threat_intel.refresh(cache, feeds=[("A", "https://a.example/l")])
    before = cache.read_text(encoding="utf-8")

    def down(url: str, timeout: int) -> set[str]:
        raise OSError("unreachable")

    monkeypatch.setattr(threat_intel, "_fetch", down)
    assert threat_intel.refresh(cache, feeds=[("A", "https://a.example/l")])[1] is False
    assert cache.read_text(encoding="utf-8") == before


def test_an_error_page_is_not_mistaken_for_a_blocklist(monkeypatch: pytest.MonkeyPatch) -> None:
    page = b"<html><head><title>410 Gone</title></head><body>moved to example.com</body></html>"

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n: int = -1) -> bytes:
            return page

    monkeypatch.setattr(threat_intel.urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(ValueError, match="not a blocklist"):
        threat_intel._fetch("https://feeds.example/list", 5)


def test_plain_domain_and_hosts_formats_both_parse() -> None:
    text = "# Title: x\n! comment\nbad.example\n0.0.0.0 worse.example\n127.0.0.1 localhost\n"
    assert threat_intel._parse_hostfile(text) == {"bad.example", "worse.example"}
