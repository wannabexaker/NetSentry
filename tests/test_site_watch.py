from __future__ import annotations

import json
import logging
import types
import urllib.error
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from netsentry.core import notify
from netsentry.core.plugin import PluginContext
from netsentry.plugins import site_watch
from netsentry.plugins.site_watch import SiteWatchPlugin

CHAT = 42
T0 = datetime(2026, 11, 21, 14, 5).timestamp()

APP = {"name": "App", "url": "https://app.example.com/healthz"}
SHOP = {"name": "Shop", "url": "https://shop.example.com/healthz",
        "fallback_url": "https://shop.example.com/api/health"}
DEMO = {"name": "Demo", "url": "https://demo.example.com/healthz", "paused": True}

HEALTHY = (200, b'{"ok":true,"status":"ok","version":"0.1.0","commit":"013a590"}',
           "application/json")


class FakeWeb:
    """url → answer (status, body, content type) or an exception to raise."""

    def __init__(self, **answers) -> None:
        self.answers: dict[str, object] = {}
        self.asked: list[str] = []
        for url, answer in answers.items():
            self.answers[url] = answer

    def set(self, url: str, answer: object) -> None:
        self.answers[url] = answer

    def __call__(self, url: str, timeout: float):
        self.asked.append(url)
        answer = self.answers.get(url, (404, b"not found", "text/plain"))
        if isinstance(answer, BaseException):
            raise answer
        return answer


def _plugin(tmp_path: Path, *sites: dict, watchdog: bool = False, **config) -> SiteWatchPlugin:
    config.setdefault("fail_after", 2)
    config["sites"] = list(sites)
    ctx = PluginContext(name="site_watch", config=config, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger("test.site_watch"),
                        state_dir=str(tmp_path / "site_watch"))
    p = SiteWatchPlugin(ctx)
    p.on_load()
    p._fetch = FakeWeb()
    p._clock = lambda: p.now                       # type: ignore[attr-defined]
    p.now = T0                                     # type: ignore[attr-defined]
    p._spawn = lambda func, *args: func(*args)     # run "in the background" inline
    others = [types.SimpleNamespace(ctx=types.SimpleNamespace(name="self_check"))] \
        if watchdog else []
    ctx._all_plugins = [p, *others]  # type: ignore[attr-defined]
    return p


def _run(p: SiteWatchPlugin, minutes: float = 5) -> None:
    p.run_checks()
    p.now += minutes * 60                          # type: ignore[attr-defined]


def _sent(p: SiteWatchPlugin) -> list[tuple[str, str]]:
    return [c.args for c in p.notifier.notify.call_args_list]


# ─── judging one answer ──────────────────────────────────────────

def test_good_json_records_version_commit_and_time(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP)
    p._fetch.set(APP["url"], HEALTHY)
    r = p.check_site(p._sites[0])
    assert r.ok and r.via == "healthz" and r.kind == "json"
    assert (r.version, r.commit) == ("0.1.0", "013a590")
    assert not r.no_healthz


def test_good_html_page_is_up_without_health_data() -> None:
    r = site_watch.evaluate(200, b"<!doctype html><html>hi</html>", "text/html; charset=utf-8")
    assert r.ok and r.kind == "html" and r.no_healthz and not r.version


def test_404_falls_back_and_says_which_one_answered(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SHOP)
    p._fetch.set(SHOP["fallback_url"],
                 (200, b'{"status":"ok","db":"ok","redis":"ok"}', "application/json"))
    r = p.check_site(p._sites[0])
    assert p._fetch.asked == [SHOP["url"], SHOP["fallback_url"]]
    assert r.ok and r.via == "fallback" and r.no_healthz


def test_503_is_bad_and_names_the_failing_part() -> None:
    r = site_watch.evaluate(
        503, b'{"ok":false,"status":"error","checks":{"database":false,"storage":true}}',
        "application/json")
    assert not r.ok and r.severe
    assert r.reason == "HTTP 503, database not ok"


def test_json_ok_false_on_200_is_bad() -> None:
    r = site_watch.evaluate(200, b'{"ok":false,"db":"down"}', "application/json")
    assert not r.ok and not r.severe and r.reason == "db not ok"
    r = site_watch.evaluate(200, b'{"status":"degraded"}', "application/json")
    assert not r.ok and "degraded" in r.reason
    assert site_watch.evaluate(200, b'{"status":"Healthy"}', "application/json").ok


def test_no_answer_is_a_severe_reading_with_a_plain_reason(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, timeout_s=10)
    p._fetch.set(APP["url"], urllib.error.URLError(TimeoutError("timed out")))
    r = p.check_site(p._sites[0])
    assert not r.ok and r.severe and r.reason == "timeout after 10 s"
    p._fetch.set(APP["url"], urllib.error.URLError(ConnectionRefusedError()))
    assert p.check_site(p._sites[0]).reason == "connection refused"


def test_a_static_page_without_a_health_route_gets_no_healthz_note(tmp_path: Path) -> None:
    page = {"name": "Page", "url": "https://page.example.com/"}
    p = _plugin(tmp_path, page)
    p._fetch.set(page["url"], (200, b"<!doctype html><html>hi</html>", "text/html"))
    r = p.check_site(p._sites[0])
    assert r.ok and r.via == "page" and not r.no_healthz


def test_a_site_without_an_http_url_is_skipped(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, {"name": "Odd", "url": "file:///etc/passwd"}, {"url": "x"})
    assert [s["name"] for s in p._sites] == ["App"]


# ─── alerts ──────────────────────────────────────────────────────

def test_alert_only_after_fail_after_and_never_repeated(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, fail_after=2)
    p._fetch.set(APP["url"], (503, b'{"ok":false,"status":"error"}', "application/json"))
    _run(p)
    assert not p.notifier.notify.called           # one bad reading: no alert yet
    _run(p)
    assert len(_sent(p)) == 1
    kind, text = _sent(p)[0]
    assert kind == notify.ATTENTION                # demos: worth knowing, not urgent
    assert text.startswith("⚠️ App — down\nHTTP 503 since 14:05 · 2 checks in a row.")
    for _ in range(3):
        _run(p)
    assert len(_sent(p)) == 1                     # still down: nothing more


def test_a_4xx_is_attention_not_urgent(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, fail_after=1)
    p._fetch.set(APP["url"], (403, b"forbidden", "text/plain"))
    _run(p)
    kind, text = _sent(p)[0]
    assert kind == notify.ATTENTION and text.startswith("⚠️ App — not healthy")


def test_recovery_says_how_long_it_was_down(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, fail_after=2)
    p._fetch.set(APP["url"], urllib.error.URLError(ConnectionRefusedError()))
    for _ in range(5):                            # 14:05 … 14:25 bad
        _run(p)
    p._fetch.set(APP["url"], HEALTHY)
    _run(p)                                       # 14:30 good
    kind, text = _sent(p)[-1]
    assert kind == notify.RECOVERY
    assert text == "✅ Back to normal: App (down 25 min)"
    _run(p)
    assert len(_sent(p)) == 2                     # alert + recovery, nothing else


def test_paused_site_never_alerts_but_is_checked(tmp_path: Path) -> None:
    p = _plugin(tmp_path, DEMO, fail_after=1)
    p._fetch.set(DEMO["url"], (502, b"bad gateway", "text/html"))
    for _ in range(4):
        _run(p)
    assert not p.notifier.notify.called
    assert p._state["sites"]["Demo"]["streak"] == 4
    assert p.health() == []                       # not a health check either


def test_version_change_gives_one_fyi_but_not_on_the_first_reading(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP)
    p._fetch.set(APP["url"], HEALTHY)
    _run(p)
    _run(p)
    assert not p.notifier.notify.called
    p._fetch.set(APP["url"], (200, b'{"ok":true,"status":"ok","version":"0.2.0",'
                                   b'"commit":"abc1234"}', "application/json"))
    _run(p)
    _run(p)
    assert _sent(p) == [(notify.INFO, "ℹ️ App now runs v0.2.0 (abc1234)")]


def test_with_the_watchdog_the_plugin_alerts_once_and_hands_it_over(
        tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, watchdog=True, fail_after=2)
    events = Mock()
    p.ctx.events = events
    assert p.health()[0].ok and p.health()[0].detail == "not checked yet"
    p._fetch.set(APP["url"], (503, b'{"ok":false,"status":"error"}', "application/json"))
    _run(p)
    assert p.health()[0].ok                       # one bad reading is not "down" yet
    _run(p)
    _run(p)
    assert len(_sent(p)) == 1                     # the plugin's own alert, once
    handed = [c.args[1] for c in events.publish.call_args_list]
    assert handed == [{"check": "Site: App"}]     # so the watchdog sends no second one
    check = p.health()[0]
    assert check.name == "Site: App" and not check.ok
    assert check.detail == "HTTP 503 since 14:05"
    p._fetch.set(APP["url"], HEALTHY)
    _run(p)
    assert len(_sent(p)) == 1                     # the watchdog announces the recovery
    assert p.health()[0].detail.startswith("ok · v0.1.0 · 013a590 · ")


# ─── /sites ──────────────────────────────────────────────────────

def test_sites_screen_shows_fallback_only_and_paused_sites(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, SHOP, DEMO)
    p._fetch.set(APP["url"], HEALTHY)
    p._fetch.set(SHOP["fallback_url"], (200, b'{"status":"ok"}', "application/json"))
    p._fetch.set(DEMO["url"], (502, b"bad gateway", "text/html"))
    p.on_command("/sites", "", CHAT)              # never checked: checks first
    text = p.notifier.send_to.call_args.args[1]
    lines = text.splitlines()
    assert lines[0] == "🛰 Sites — ✅ all 2 up"
    assert lines[2].startswith("✅ App — v0.1.0 · 013a590 · ") and lines[2].endswith(
        " s · up since 14:05")
    assert "✅ Shop — " in text and "no /healthz yet · up since 14:05" in text
    assert "⏸ Demo — paused · HTTP 502 · failing since 14:05" in text
    assert lines[-1] == "Checked 14:05 · every 5 min"
    buttons = p.notifier.send_to.call_args.kwargs["buttons"]
    datas = [b["callback_data"] for row in buttons for b in row]
    assert datas[0] == "site_watch:c" and "site_watch:d:2" in datas
    assert all(len(d.encode()) < 64 for d in datas)


def test_check_now_edits_the_same_message(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP)
    p._fetch.set(APP["url"], HEALTHY)
    p.on_callback("site_watch:c", CHAT, 7, "cb")
    edits = p.notifier.edit_message.call_args_list
    assert edits[0].args[2].startswith("⏳ Checking 1 site")
    assert edits[-1].args[:2] == (CHAT, 7) and "✅ App" in edits[-1].args[2]


def test_detail_screen_and_briefing_line(tmp_path: Path) -> None:
    p = _plugin(tmp_path, APP, SHOP, DEMO, fail_after=1)
    p._fetch.set(APP["url"], HEALTHY)
    p._fetch.set(SHOP["url"], urllib.error.URLError(TimeoutError("timed out")))
    _run(p)
    p.on_callback("site_watch:d:1", CHAT, 7, "cb")
    detail = p.notifier.edit_message.call_args.args[2]
    assert "⚠️ timeout after 10 s since 14:05" in detail
    assert "Answered by: the health address · no answer" in detail
    assert p.summary_line() == "🛰 Sites: ⚠️ Shop not ok · 1 up · 1 paused"


def test_damaged_state_file_is_kept_aside(tmp_path: Path) -> None:
    state = tmp_path / "site_watch" / "state.json"
    state.parent.mkdir(parents=True)
    state.write_text("{not json", encoding="utf-8")
    p = _plugin(tmp_path, APP)
    assert p._state == {}
    assert (state.parent / "state.json.corrupt").read_text(encoding="utf-8") == "{not json"
    p._fetch.set(APP["url"], HEALTHY)
    _run(p)
    assert json.loads(state.read_text(encoding="utf-8"))["sites"]["App"]["last"]["ok"]
