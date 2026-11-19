from __future__ import annotations

import logging
import sqlite3
import time
import types
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

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
    assert p.notifier.send_to.call_args.kwargs["buttons"] is None
    p.router.join_events.assert_not_called()                   # no router involved, no guessing


def test_lookups_through_the_router_are_pinned_on_the_device_that_just_joined(
    tmp_path: Path,
) -> None:
    p = _plugin(tmp_path, VIA_ROUTER)
    p.on_command("/who", PROBE, 42)

    text = p.notifier.send_to.call_args.args[1]
    assert "through the router" in text
    assert f"Phone ({PHONE}) — 3 of 3 lookups" in text
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
    assert "Nobody has asked" in p.notifier.send_to.call_args.args[1]
    p.on_command("/who", "not a domain; drop table", 42)
    assert "doesn't look like a domain" in p.notifier.send_to.call_args_list[-2].args[1]


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
    assert p.notifier.send_to.call_count == 1

    p.router.dns_trace_hits.return_value = parse_trace_hits(TRACE_LOG)[:1]
    p.poll()
    caught = p.notifier.send_to.call_args.args[1]
    assert "Caught it" in caught and "Phone" in caught and PHONE in caught
    p.poll()                                                    # same device again: no repeat
    assert p.notifier.send_to.call_count == 2
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
    assert "Nothing asked" in p.notifier.send_to.call_args.args[1]
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
    assert labels == [f"🔎 {PROBE}", "🔎 flagged.example"]
