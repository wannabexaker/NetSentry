from __future__ import annotations

import io
import json
import logging
import sqlite3
import time
import types
import urllib.error
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from netsentry.core.pihole import PiholeAPI, PiholeError, deny_regex_for, domain_of_regex
from netsentry.core.plugin import PluginContext
from netsentry.core.router import (
    JoinEvent,
    MikroTikRouter,
    TraceHit,
    parse_join_events,
    parse_trace_hits,
)
from netsentry.plugins.who_asked import WhoAskedPlugin, needle_for

ROUTER_IP = "192.0.2.1"
PHONE = "02:BB:34:A6:FB:CA"

# Lines as RouterOS 7 prints them (addresses replaced with documentation ranges).
TRACE_LOG = """\
 2026-11-19 21:36:14 system,info mangle rule added by ssh-cmd:svc@192.0.2.10 (*4 = /ip firewall mangle add action=log chain=prerouting comment="netsentry-trace ab12cd" content=probe dst-port=53 log-prefix=NSTRACE-ab12cd protocol=udp)
 2026-11-19 21:36:14 firewall,info NSTRACE-ab12cd prerouting: in:bridge out:(unknown 0), connection-state:new src-mac 02:bb:34:a6:fb:ca, proto UDP, 192.0.2.233:60239->192.0.2.1:53, len 93
 2026-11-19 21:36:16 firewall,info NSTRACE-ab12cd prerouting: in:ether1 out:(unknown 0), connection-state:new src-mac E4:5F:01:F5:F1:45, proto UDP, 192.0.2.10:38382->192.0.2.1:53, len 70
"""
JOIN_LOG = """\
 2026-11-18 20:34:07 wireless,info 02:BB:34:A6:FB:CA@wifi1(Home) connected, signal strength -53
 2026-11-19 19:03:42 wireless,info 02:BB:34:A6:FB:CA@wifi2(Home) connected, signal strength -75
 2026-11-19 19:03:43 dhcp,info defconf assigned 192.0.2.233 for 02:BB:34:A6:FB:CA Phone
 2026-11-19 19:04:21 wireless,info 02:BB:34:A6:FB:CA@wifi2(Home) disconnected, connection lost, signal strength -85
 2026-11-19 19:48:43 wireless,info F2:27:2C:5C:A9:1A@wifi4(Guest) connected, signal strength -72
 2026-11-19 19:49:13 wireless,info 02:BB:34:A6:FB:CA@wifi1(Home) connected, signal strength -79
"""


def _ts(text: str) -> float:
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").timestamp()


# ─── router log parsing ──────────────────────────────────────────

def test_trace_hits_are_parsed_and_the_rule_added_line_is_ignored() -> None:
    hits = parse_trace_hits(TRACE_LOG)
    assert hits == [
        TraceHit(datetime(2026, 11, 19, 21, 36, 14), PHONE, "192.0.2.233", "bridge"),
        TraceHit(datetime(2026, 11, 19, 21, 36, 16), "E4:5F:01:F5:F1:45", "192.0.2.10", "ether1"),
    ]


def test_join_events_cover_wifi_connects_and_dhcp_but_not_disconnects() -> None:
    events = parse_join_events(JOIN_LOG)
    assert len(events) == 5
    assert events[2] == JoinEvent(datetime(2026, 11, 19, 19, 3, 43), PHONE, name="Phone")
    assert events[0].network == "Home"
    assert all("disconnected" not in str(e) for e in events)


def test_log_line_without_a_date_means_today() -> None:
    line = " 19:03:42 wireless,info 02:BB:34:A6:FB:CA@wifi2(Home) connected, signal strength -75"
    assert parse_join_events(line)[0].when.date() == datetime.now().date()


def test_trace_rule_commands_are_validated_and_quoted() -> None:
    router = MikroTikRouter("router.invalid", "svc", "key")
    sent: list[str] = []

    def fake_ssh(command: str, timeout: int = 10) -> tuple[int, str]:
        sent.append(command)
        return 0, "1\n" if "mangle add" in command else "0\n"

    router._ssh = fake_ssh  # type: ignore[method-assign]

    assert router.dns_trace_add("ab12cd", "example-label") is True
    assert 'content="example-label"' in sent[0] and "action=log" in sent[0]
    assert "chain=prerouting" in sent[0] and 'comment="netsentry-trace ab12cd"' in sent[0]
    assert router.dns_trace_remove("ab12cd") is True

    sent.clear()
    for bad_id, bad_needle in (("ab12cd", 'x"; /system reset-configuration'),
                               ("../../x", "label"), ("ab12cd", "a b"), ("AB", "label")):
        assert router.dns_trace_add(bad_id, bad_needle) is False
    assert router.dns_trace_remove('x"; /user remove [find]') is False
    assert router.dns_trace_hits("nope; /quit") == []
    assert sent == []                                    # nothing ever reached the router


def test_needle_is_the_most_distinctive_label() -> None:
    assert needle_for("www.goooooooooogle.com") == "goooooooooogle"
    assert needle_for("media.getintopc.com") == "getintopc"
    assert needle_for("a.b.co") is None                  # nothing long enough to match on
    assert len(needle_for("x" * 60 + ".example.net")) == 40


# ─── the plugin ──────────────────────────────────────────────────

class FakePihole:
    """Stands in for PiholeAPI: remembers NetSentry's blocks."""

    def __init__(self) -> None:
        self.blocks: list[str] = []
        self.calls: list[tuple[str, str]] = []
        self.refuse = ""

    def netsentry_blocks(self) -> list[str]:
        return list(self.blocks)

    def block(self, domain: str) -> None:
        self.calls.append(("block", domain))
        if self.refuse:
            raise PiholeError(self.refuse)
        self.blocks.append(domain)

    def unblock(self, domain: str) -> None:
        self.calls.append(("unblock", domain))
        self.blocks.remove(domain)


def _plugin(tmp_path: Path, lookups: list[tuple[str, str, str]]) -> WhoAskedPlugin:
    db = tmp_path / "ftl.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE queries (timestamp REAL, domain TEXT, client TEXT)")
    con.executemany("INSERT INTO queries VALUES (?,?,?)",
                    [(_ts(t), d, c) for t, d, c in lookups])
    con.commit()
    con.close()
    router = Mock()
    router.host = ROUTER_IP
    router.join_events.return_value = parse_join_events(JOIN_LOG)
    router.dhcp_leases.return_value = [
        types.SimpleNamespace(mac=PHONE, ip="192.0.2.233", hostname="Phone")]
    router.dns_trace_add.return_value = True
    router.dns_trace_remove.return_value = True
    router.dns_trace_hits.return_value = []
    (tmp_path / "who").mkdir()
    ctx = PluginContext(
        name="who_asked",
        config={"ftl_db_path": str(db), "lookback_days": 36500},
        router=router, notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.who"), state_dir=str(tmp_path / "who"),
        events=Mock())
    p = WhoAskedPlugin(ctx)
    p.on_load()
    p._pihole = FakePihole()  # type: ignore[assignment]
    p._background = lambda func, *args: func(*args)  # searches run inline in tests
    ctx._all_plugins = [p]  # type: ignore[attr-defined]
    return p


PROBE = "www.goooooooooogle.com"
VIA_ROUTER = [
    ("2026-11-18 20:34:10", PROBE, ROUTER_IP),
    ("2026-11-19 19:03:46", PROBE, ROUTER_IP),
    ("2026-11-19 19:49:17", PROBE, ROUTER_IP),
]


def test_direct_askers_are_named(tmp_path: Path) -> None:
    p = _plugin(tmp_path, [("2026-11-19 10:00:00", "media.example.org", "192.0.2.233"),
                           ("2026-11-19 10:05:00", "example.org", "192.0.2.233"),
                           ("2026-11-19 11:00:00", "notexample.org", "192.0.2.50")])
    p.on_command("/who", "example.org", 42)

    text = p.notifier.send_to.call_args.args[1]
    assert "2 lookups" in text and "Phone — 2×" in text       # sub-domains count, look-alikes don't
    keys = [k for row in p.notifier.send_to.call_args.kwargs["buttons"] for k in row]
    assert [k["text"] for k in keys] == [                      # no trace offered
        "⛔ Block example.org", "⬅ Back", "🏠 Menu"]
    p.router.join_events.assert_not_called()                   # no router involved, no guessing


def test_lookups_through_the_router_are_pinned_on_the_device_that_just_joined(
    tmp_path: Path,
) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.on_command("/who", PROBE, 42)

    text = p.notifier.send_to.call_args.args[1]
    assert "A device behind the router" in text
    assert f"Phone — 3 of 3 lookups · {PHONE}" in text
    assert "likely source" in text
    button = p.notifier.send_to.call_args.kwargs["buttons"][0][0]
    assert button["callback_data"] == f"who_asked:t:{PROBE}"


def test_very_long_domain_still_gets_working_buttons(tmp_path: Path) -> None:
    # Telegram rejects callback data over 64 bytes, and real probe names exceed that.
    long_name = "www.g" + "o" * 57 + "gle.com"
    p = _plugin(tmp_path, [(t, long_name, c) for t, _, c in VIA_ROUTER])

    p.on_command("/who", long_name, 42)

    button = p.notifier.send_to.call_args.kwargs["buttons"][0][0]
    assert len(button["callback_data"].encode()) <= 64
    p.on_callback(button["callback_data"], 42, 7, "cb")
    assert p.router.dns_trace_add.call_args.args[1] == ("g" + "o" * 57 + "gle")[:40]
    assert next(iter(p._traces().values()))["domain"] == long_name


def test_timing_that_proves_nothing_says_so(tmp_path: Path) -> None:
    p = _plugin(tmp_path, [("2026-11-19 12:00:00", PROBE, ROUTER_IP)])
    p.on_command("/who", PROBE, 42)
    text = p.notifier.send_to.call_args.args[1]
    assert "doesn't give it away" in text and "likely source" not in text


def test_unknown_or_malformed_domain(tmp_path: Path) -> None:
    p = _plugin(tmp_path, [])
    p.on_command("/who", "never-seen.example", 42)
    assert "nobody asked" in p.notifier.send_to.call_args.args[1]
    p.on_command("/who", "not a domain; drop table", 42)
    assert "doesn't look like a domain" in p.notifier.send_to.call_args.args[1]


def test_trace_catches_the_device_then_cleans_up_after_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.on_callback(f"who_asked:t:{PROBE}", 42, 7, "cb")

    tid, needle = p.router.dns_trace_add.call_args.args
    assert needle == "goooooooooogle" and "Listening" in p.notifier.send_to.call_args.args[1]
    p.ctx.events.publish.assert_called_with(
        "router.config.expected_change", {"source": "who_asked"})

    p.poll()                                                    # nothing yet: stay quiet
    p.notifier.notify.assert_not_called()

    p.router.dns_trace_hits.return_value = parse_trace_hits(TRACE_LOG)[:1]
    p.poll()
    kind, caught = p.notifier.notify.call_args.args
    assert kind == "attention" and p.notifier.notify.call_args.kwargs["chat_id"] == 42
    assert "asked by Phone" in caught and PHONE in caught
    p.poll()                                                    # same device again: no repeat
    assert p.notifier.notify.call_count == 1
    p.router.dns_trace_remove.assert_not_called()               # still listening for a while

    monkeypatch.setattr(time, "time", lambda: time.monotonic() + 10**10)
    p.poll()
    p.router.dns_trace_remove.assert_called_once_with(tid)
    assert p._traces() == {}


def test_trace_that_never_fires_expires_and_removes_its_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.start_trace(PROBE, 42)
    real = time.time()
    monkeypatch.setattr(time, "time", lambda: real + 8 * 86400)

    p.poll()

    p.router.dns_trace_remove.assert_called_once()
    assert p.notifier.notify.call_args.args[0] == "info"
    assert "nobody asked" in p.notifier.notify.call_args.args[1]
    assert p._traces() == {}


def test_router_refusal_leaves_no_trace_behind(tmp_path: Path) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.router.dns_trace_add.return_value = False
    assert "refused" in p.start_trace(PROBE, 42)
    assert p._traces() == {}


def test_no_duplicate_traces_and_stop_button(tmp_path: Path) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.start_trace(PROBE, 42)
    assert "Already listening" in p.start_trace(PROBE, 42)
    assert p.router.dns_trace_add.call_count == 1

    p.on_command("/who", "", 42)
    rows = p.notifier.send_to.call_args.kwargs["buttons"]
    stop = next(k for row in rows for k in row if k["text"].startswith("⏹"))
    p.on_callback(stop["callback_data"], 42, 7, "cb")
    p.router.dns_trace_remove.assert_called_once()
    assert p._traces() == {}


def test_home_screen_offers_recently_flagged_domains(tmp_path: Path) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    det = Mock()
    det.ctx = types.SimpleNamespace(name="threat_detector")
    det.api_findings.return_value = [
        {"subject": PROBE}, {"subject": "aa:bb:cc:dd:ee:ff"},   # a MAC is not a domain
        {"subject": "flagged.example"}, {"subject": PROBE}]
    p.ctx._all_plugins = [p, det]  # type: ignore[attr-defined]

    p.on_command("/who", "", 42)

    labels = [k["text"] for row in p.notifier.send_to.call_args.kwargs["buttons"] for k in row]
    assert labels == ["🔎 Search", f"🔎 {PROBE}", "🔎 flagged.example", "🏠 Menu"]


# ─── search ──────────────────────────────────────────────────────

SEARCHABLE = [
    ("2026-08-12 10:00:00", "baidu.com", ROUTER_IP),
    ("2026-11-19 10:00:00", "baidu.com", ROUTER_IP),
    ("2026-11-19 10:01:00", "baidu.com", ROUTER_IP),
    ("2026-11-19 10:02:00", "baidu.com", "192.0.2.233"),
    ("2026-11-19 11:00:00", "www.baidu.com", "192.0.2.50"),
    ("2026-11-19 12:00:00", "example.org", ROUTER_IP),
]


def _texts(p: WhoAskedPlugin) -> list[str]:
    out = [c.args[1] for c in p.notifier.send_to.call_args_list]
    return out + [c.args[2] for c in p.notifier.edit_message.call_args_list]


def _last_edit(p: WhoAskedPlugin) -> tuple[str, list]:
    call = p.notifier.edit_message.call_args
    return call.args[2], call.kwargs["buttons"]


def test_search_finds_domains_most_asked_first_with_names(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    hits, more = p.search("baidu")
    assert [(h.domain, h.count) for h in hits] == [("baidu.com", 4), ("www.baidu.com", 1)]
    assert hits[0].first == _ts("2026-08-12 10:00:00") and not more
    assert hits[0].clients == {ROUTER_IP: 3, "192.0.2.233": 1}

    p.on_command("/who", "Baidu", 42)                          # not a full domain → search
    texts = [c.args[1] for c in p.notifier.send_to.call_args_list]
    assert texts[0].startswith("⏳ Searching")
    answer = texts[1]
    assert "1. baidu.com — 4×" in answer and "2. www.baidu.com — 1×" in answer
    assert "via the router — every device behind it (3×)" in answer
    assert "Phone (1×)" in answer and "example.org" not in answer
    rows = p.notifier.send_to.call_args.kwargs["buttons"]
    assert rows[0][0] == {"text": "🔎 baidu.com", "callback_data": "who_asked:q:baidu.com"}
    assert all(len(k["callback_data"].encode()) <= 64 for row in rows for k in row
               if "callback_data" in k)


def test_search_on_a_pihole_v6_database(tmp_path: Path) -> None:
    p = _plugin(tmp_path, [])
    db = tmp_path / "v6.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT);
        CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT, name TEXT);
        CREATE TABLE query_storage (id INTEGER PRIMARY KEY, timestamp INTEGER,
                                    domain INTEGER, client INTEGER);
        INSERT INTO domain_by_id VALUES (1, 'baidu.com'), (2, 'example.org');
        INSERT INTO client_by_id VALUES (1, '192.0.2.1', ''), (2, '192.0.2.233', '');
        INSERT INTO query_storage (timestamp, domain, client) VALUES
            (100, 1, 1), (200, 1, 1), (300, 1, 2), (400, 2, 1);
    """)
    con.commit()
    con.close()
    p._ftl_db = str(db)
    hits, _ = p.search("baidu")
    assert len(hits) == 1 and hits[0].count == 3
    assert (hits[0].first, hits[0].last) == (100, 300)
    assert hits[0].clients == {ROUTER_IP: 2, "192.0.2.233": 1}


def test_search_treats_like_wildcards_literally(tmp_path: Path) -> None:
    p = _plugin(tmp_path, [("2026-11-19 10:00:00", "one.example", "192.0.2.5"),
                           ("2026-11-19 10:00:00", "o_e.example", "192.0.2.5"),
                           ("2026-11-19 10:00:00", "abc.example", "192.0.2.5")])
    assert [h.domain for h in p.search("o_e")[0]] == ["o_e.example"]
    assert p.search("a%")[0] == []
    p.on_command("/who", "a%c", 42)                         # never reaches the database
    assert "doesn't look like a domain" in p.notifier.send_to.call_args.args[1]


def test_search_shows_at_most_fifteen(tmp_path: Path) -> None:
    rows = [("2026-11-19 10:00:00", f"n{i:02d}.example", "192.0.2.5")
            for i in range(20) for _ in range(i + 1)]
    p = _plugin(tmp_path, rows)
    p.on_command("/who", "example", 42)
    answer = p.notifier.send_to.call_args.args[1]
    assert answer.index("n19.example") < answer.index("n18.example")
    assert "Showing 15 of 20" in answer and "n04.example" not in answer
    domain_rows = [r for r in p.notifier.send_to.call_args.kwargs["buttons"]
                   if r[0]["text"].startswith("🔎 n")]
    assert len(domain_rows) == 15


def test_search_with_no_match_says_so(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p.on_command("/who", "nomatch", 42)
    assert "nothing matched" in p.notifier.send_to.call_args.args[1]


def test_search_button_then_a_typed_word(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p.on_callback("who_asked:s", 42, 7, "cb")
    text, buttons = _last_edit(p)
    assert text == "🔎 Send part of a domain name, e.g. baidu"
    assert buttons[0][0]["text"] == "✖ Cancel"

    p._on_text({"chat_id": 99, "text": "baidu"})               # someone else's chat
    p._on_text({"chat_id": 42, "text": "/status"})             # a command is not the word
    assert p.notifier.edit_message.call_count == 1

    p._on_text({"chat_id": 42, "text": "baidu"})
    first, answer = [c.args for c in p.notifier.edit_message.call_args_list[1:]]
    assert first[1] == 7 and first[2].startswith("⏳ Searching")
    assert answer[1] == 7 and "1. baidu.com — 4×" in answer[2]

    p._on_text({"chat_id": 42, "text": "baidu"})               # one word per prompt
    assert p.notifier.edit_message.call_count == 3


def test_a_bad_word_asks_again(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p.on_callback("who_asked:s", 42, 7, "cb")
    p._on_text({"chat_id": 42, "text": "bai du"})
    assert "2–63 letters" in _last_edit(p)[0]
    p._on_text({"chat_id": 42, "text": "baidu"})
    assert "baidu.com — 4×" in _last_edit(p)[0]


def test_a_command_or_cancel_ends_the_wait(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p.on_callback("who_asked:s", 42, 7, "cb")
    p._on_any_command({"chat_id": 42, "command": "/status"})
    p._on_text({"chat_id": 42, "text": "baidu"})
    assert p.notifier.edit_message.call_count == 1

    p.on_callback("who_asked:s", 42, 7, "cb")
    p.on_callback("who_asked:h", 42, 7, "cb")                  # ✖ Cancel
    p._on_text({"chat_id": 42, "text": "baidu"})
    assert "Searching" not in " ".join(_texts(p))


def test_the_search_prompt_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p.on_callback("who_asked:s", 42, 7, "cb")
    real = time.time()
    monkeypatch.setattr(time, "time", lambda: real + 3600)
    p._on_text({"chat_id": 42, "text": "baidu"})
    assert p.notifier.edit_message.call_count == 1


def test_telegram_publishes_commands_so_prompts_can_end() -> None:
    from netsentry.plugins.telegram_bot import TelegramBotPlugin
    bot = TelegramBotPlugin.__new__(TelegramBotPlugin)
    bot.ctx = types.SimpleNamespace(events=Mock())
    bot.log = logging.getLogger("test.tg")
    bot._is_authorized = lambda chat_id: True             # type: ignore[method-assign]
    bot._rate_ok = lambda chat_id: True                    # type: ignore[method-assign]
    bot.dispatch_command = Mock(return_value=True)         # type: ignore[method-assign]
    bot._handle_update({"message": {"chat": {"id": 42}, "text": "/status"}})
    bot.ctx.events.publish.assert_called_once_with(
        "telegram.command", {"chat_id": 42, "command": "/status"})


# ─── find the device ─────────────────────────────────────────────

def test_find_button_and_a_running_trace(tmp_path: Path) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.on_command("/who", PROBE, 42)
    text = p.notifier.send_to.call_args.args[1]
    assert "within a minute or two" in text
    assert p.notifier.send_to.call_args.kwargs["buttons"][0][0]["text"] == "🎯 Find the device"

    p.start_trace(PROBE, 42)
    p.on_command("/who", PROBE, 42)
    text = p.notifier.send_to.call_args.args[1]
    assert "Already listening" in text
    stop = p.notifier.send_to.call_args.kwargs["buttons"][0][0]
    assert stop["text"] == "⏹ Stop listening"
    p.on_callback(stop["callback_data"], 42, 7, "cb")
    assert p._traces() == {}


# ─── block / unblock ─────────────────────────────────────────────

def test_block_needs_the_confirmation(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p.on_command("/who", "baidu.com", 42)
    block = next(k for row in p.notifier.send_to.call_args.kwargs["buttons"] for k in row
                 if k["text"].startswith("⛔"))
    assert block["text"] == "⛔ Block baidu.com"

    p.on_callback(block["callback_data"], 42, 7, "cb")
    text, buttons = _last_edit(p)
    assert "baidu.com and its subdomains for every device at home" in text
    assert "may think it is offline" in text
    assert [k["text"] for k in buttons[0]] == ["✔ Yes, block", "✖ Cancel"]
    assert p._pihole.calls == []                               # nothing yet

    p.on_callback(buttons[0][1]["callback_data"], 42, 7, "cb")  # cancel
    assert p._pihole.calls == [] and "baidu.com" in _last_edit(p)[0]

    p.on_callback(buttons[0][0]["callback_data"], 42, 7, "cb")  # yes
    assert p._pihole.calls == [("block", "baidu.com")]
    text, buttons = _last_edit(p)
    assert "✅ Blocked baidu.com" in text and "⛔ Blocked by NetSentry" in text
    unblock = next(k for row in buttons for k in row if k["text"].startswith("↩️"))
    assert unblock["text"] == "↩️ Unblock"

    p.on_command("/who", "www.baidu.com", 42)                  # a subdomain is covered
    assert "(as part of baidu.com)" in p.notifier.send_to.call_args.args[1]

    p.on_callback(unblock["callback_data"], 42, 7, "cb")
    assert p._pihole.calls[-1] == ("unblock", "baidu.com")
    assert "✅ Unblocked baidu.com" in _last_edit(p)[0]


def test_pihole_refusing_is_one_plain_line(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p._pihole.refuse = "Regex validation failed"
    p.on_callback("who_asked:B:baidu.com", 42, 7, "cb")
    text = _last_edit(p)[0]
    assert text.startswith("❌ Pi-hole did not accept it: Regex validation failed")
    assert "Blocked by NetSentry" not in text


def test_home_lists_netsentry_blocks_with_unblock(tmp_path: Path) -> None:
    p = _plugin(tmp_path, SEARCHABLE)
    p._pihole.blocks = ["baidu.com"]
    p.on_command("/who", "", 42)
    assert "• baidu.com (and its subdomains)" in p.notifier.send_to.call_args.args[1]
    rows = p.notifier.send_to.call_args.kwargs["buttons"]
    unblock = next(k for row in rows for k in row if k["text"].startswith("↩️"))
    assert unblock["text"] == "↩️ Unblock baidu.com"
    p.on_callback(unblock["callback_data"], 42, 7, "cb")
    assert p._pihole.blocks == [] and "✅ Unblocked" in _last_edit(p)[0]


# ─── the Pi-hole API client ──────────────────────────────────────

SID = "s3cr3t-sid-value"
PASSWORD = "cli-password-for-tests"


class FakeOpener:
    """Records requests; answers like Pi-hole v6."""

    def __init__(self, entries: list[dict] | None = None) -> None:
        self.sent: list[tuple[str, str, dict | None, str | None]] = []
        self.entries = entries or []
        self.post_status = 201
        self.post_body: dict = {"processed": {"success": [], "errors": []}}

    def __call__(self, req, timeout: float):
        body = json.loads(req.data) if req.data else None
        path = req.full_url.replace("http://127.0.0.1", "")
        method = req.get_method()
        self.sent.append((method, path, body, req.get_header("X-ftl-sid")))
        if path == "/api/auth" and method == "POST":
            if body == {"password": PASSWORD}:
                status, out = 200, {"session": {"valid": True, "sid": SID, "validity": 1800}}
            else:
                status, out = 401, {"session": {"valid": False, "sid": None}}
        elif method == "GET":
            status, out = 200, {"domains": self.entries}
        elif method == "POST":
            status, out = self.post_status, self.post_body
        else:
            status, out = 204, None
        raw = json.dumps(out).encode() if out is not None else b""
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(raw))
        resp = MagicMock()
        resp.status = status
        resp.read.return_value = raw
        resp.__enter__.return_value = resp
        return resp


def _api(tmp_path: Path, opener: FakeOpener, password: str = PASSWORD) -> PiholeAPI:
    pw = tmp_path / "cli_pw"
    pw.write_text(password + "\n", encoding="utf-8")
    return PiholeAPI("http://127.0.0.1", str(pw), opener=opener)


def test_block_sends_the_regex_and_logs_out(tmp_path: Path, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    opener = FakeOpener()
    _api(tmp_path, opener).block("baidu.com")
    assert opener.sent == [
        ("POST", "/api/auth", {"password": PASSWORD}, None),
        ("POST", "/api/domains/deny/regex",
         {"domain": r"(\.|^)baidu\.com$", "comment": "netsentry"}, SID),
        ("DELETE", "/api/auth", None, SID),
    ]
    assert PASSWORD not in caplog.text and SID not in caplog.text


def test_unblock_deletes_only_netsentry_entries(tmp_path: Path, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    entries = [{"domain": r"(\.|^)baidu\.com$", "comment": "netsentry"},
               {"domain": r"(\.|^)other\.example$", "comment": "added by hand"},
               {"domain": r"^ads?\..*", "comment": "netsentry"}]   # not our shape
    opener = FakeOpener(entries)
    api = _api(tmp_path, opener)
    assert api.netsentry_blocks() == ["baidu.com"]

    opener.sent.clear()
    api.unblock("baidu.com")
    assert opener.sent[2] == (
        "DELETE", "/api/domains/deny/regex/%28%5C.%7C%5E%29baidu%5C.com%24", None, SID)
    assert opener.sent[-1] == ("DELETE", "/api/auth", None, SID)

    opener.sent.clear()
    with pytest.raises(PiholeError, match="no NetSentry block"):
        api.unblock("other.example")
    assert [m for m, *_ in opener.sent] == ["POST", "GET", "DELETE"]  # auth, list, logout
    assert PASSWORD not in caplog.text and SID not in caplog.text


def test_pihole_errors_become_one_line(tmp_path: Path) -> None:
    opener = FakeOpener()
    opener.post_status = 400
    opener.post_body = {"error": {"key": "regex_error", "message": "Regex validation failed",
                                  "hint": "Missing ']'"}}
    with pytest.raises(PiholeError, match=r"^Regex validation failed \(Missing '\]'\)$"):
        _api(tmp_path, opener).block("baidu.com")
    assert opener.sent[-1][0:2] == ("DELETE", "/api/auth")     # still logged out

    opener = FakeOpener()
    opener.post_body = {"processed": {"success": [], "errors": [
        {"item": "x", "error": "The item is already present"}]}}
    _api(tmp_path, opener).block("baidu.com")                  # already there = done

    with pytest.raises(PiholeError, match="login refused"):
        _api(tmp_path, FakeOpener(), password="wrong").block("baidu.com")
    with pytest.raises(PiholeError, match="password file"):
        PiholeAPI(password_file=str(tmp_path / "missing"),
                  opener=FakeOpener()).block("a.example")


def test_regex_round_trip() -> None:
    assert deny_regex_for("baidu.com") == r"(\.|^)baidu\.com$"
    assert domain_of_regex(deny_regex_for("cdn-1.baidu.com")) == "cdn-1.baidu.com"
    assert domain_of_regex(r"(\.|^)baidu\.com$|evil") is None
