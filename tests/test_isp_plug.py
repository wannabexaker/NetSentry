"""Restarting the ISP router through a smart plug: the Shelly client, the one
narrow router forward that reaches it, and the Telegram flow around both."""

from __future__ import annotations

import io
import json
import logging
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from netsentry.core.events import EventBus
from netsentry.core.plugin import PluginContext
from netsentry.core.router import MikroTikRouter
from netsentry.core.shelly import PlugError, PlugState, ShellyPlug
from netsentry.plugins.power import PowerPlugin

CHAT = 42
URLOPEN = "netsentry.core.shelly.urllib.request.urlopen"


# ─── the plug ────────────────────────────────────────────────────

class _FakePlugHttp:
    """Answers Shelly RPC calls from a small in-memory device."""

    def __init__(self, output=True, apower=7.4, initial_state="restore_last"):
        self.device = {"output": output, "apower": apower, "initial_state": initial_state}
        self.urls: list[str] = []

    def __call__(self, url, timeout=None):
        self.urls.append(url)
        method = url.split("/rpc/")[1].split("?")[0]
        query = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
        if method == "Switch.GetStatus":
            body = {"id": 0, "output": self.device["output"], "apower": self.device["apower"]}
        elif method == "Switch.GetConfig":
            body = {"id": 0, "initial_state": self.device["initial_state"]}
        elif method == "Switch.Set":
            body = {"was_on": self.device["output"]}
            self.device["output"] = query["on"] == "true"
        elif method == "Switch.SetConfig":
            import urllib.error
            from urllib.parse import unquote
            if "+" in url:          # a real plug does not read "+" as a space
                raise urllib.error.HTTPError(url, 500, "Internal Server Error", None, None)
            self.device.update(json.loads(unquote(query["config"])))
            body = {"restart_required": False}
        else:
            raise AssertionError(f"unexpected call {method}")
        response = Mock()
        response.read.return_value = json.dumps(body).encode()
        response.__enter__ = lambda s: s
        response.__exit__ = lambda *a: False
        return response


def test_plug_state_and_cycle() -> None:
    http = _FakePlugHttp()
    with patch(URLOPEN, side_effect=http):
        plug = ShellyPlug("http://192.0.2.50")
        assert plug.state() == PlugState(on=True, watts=7.4, after_power_cut="restore_last")
        plug.cycle(10)
    assert http.urls[-1] == "http://192.0.2.50/rpc/Switch.Set?id=0&on=false&toggle_after=10"


@pytest.mark.parametrize("asked, sent", [(10, 10), (0, 3), (-5, 3), (99999, 120)])
def test_off_time_is_kept_within_sane_bounds(asked: int, sent: int) -> None:
    http = _FakePlugHttp()
    with patch(URLOPEN, side_effect=http):
        ShellyPlug("http://192.0.2.50:8108", switch=1).cycle(asked)
    assert http.urls[-1].endswith(f"/rpc/Switch.Set?id=1&on=false&toggle_after={sent}")


@pytest.mark.parametrize("state, ok", [("on", True), ("restore_last", True),
                                       ("off", False), ("match_input", False), ("", False)])
def test_only_some_plugs_power_up_again_after_a_power_cut(state: str, ok: bool) -> None:
    assert PlugState(True, 5.0, state).comes_back_by_itself is ok


def test_fixing_the_power_cut_behaviour() -> None:
    http = _FakePlugHttp(initial_state="off")
    with patch(URLOPEN, side_effect=http):
        plug = ShellyPlug("http://192.0.2.50")
        plug.come_back_on_after_power_cut()
        assert plug.state().after_power_cut == "on"
    # Exactly the form a real Plug S G3 accepted; with a "+" in it, it answers 500.
    assert http.urls[0] == ("http://192.0.2.50/rpc/Switch.SetConfig"
                            "?id=0&config=%7B%22initial_state%22%3A%22on%22%7D")


@pytest.mark.parametrize("address", [
    "https://192.0.2.50", "http://192.0.2.50/admin", "http://192.0.2.50?x=1",
    "ftp://192.0.2.50", "192.0.2.50", "http://user:pw@192.0.2.50", "http://",
    "file:///etc/passwd", "http://192.0.2.50:80/../x",
])
def test_only_plain_http_addresses_are_accepted(address: str) -> None:
    with pytest.raises(PlugError):
        ShellyPlug(address)


def test_plug_failures_become_readable_messages() -> None:
    plug = ShellyPlug("http://192.0.2.50")
    with patch(URLOPEN, side_effect=urllib.error.URLError("timed out")):
        with pytest.raises(PlugError, match="did not answer"):
            plug.state()
    unauthorized = urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b""))
    with patch(URLOPEN, side_effect=unauthorized):
        with pytest.raises(PlugError, match="asks for a password"):
            plug.state()
    html = Mock()
    html.read.return_value = b"<html>router login</html>"
    html.__enter__ = lambda s: s
    html.__exit__ = lambda *a: False
    with patch(URLOPEN, return_value=html):
        with pytest.raises(PlugError, match="not understood"):
            plug.state()


# ─── the router forward ──────────────────────────────────────────

def _router(answer: str, host: str = "192.0.2.1"):
    router = MikroTikRouter(host, "netsentry", "key")
    router._ssh = Mock(return_value=(0, answer))  # type: ignore[method-assign]
    return router


def test_forward_is_added_once_and_is_as_narrow_as_possible() -> None:
    router = _router("FORWARD 0 1\n")
    assert router.port_forward_ensure("isp-plug", "192.0.2.10", 8108, "198.51.100.8") == "added"
    command = router._ssh.call_args.args[0]
    assert ("chain=dstnat action=dst-nat protocol=tcp src-address=192.0.2.10 "
            "dst-address=192.0.2.1 dst-port=8108 to-addresses=198.51.100.8 to-ports=80") in command
    assert 'comment="netsentry-forward isp-plug"' in command
    assert _router("FORWARD 1 1\n").port_forward_ensure(
        "isp-plug", "192.0.2.10", 8108, "198.51.100.8") == "exists"


def test_forward_failures_are_reported() -> None:
    assert _router("failure: something\n").port_forward_ensure(
        "isp-plug", "192.0.2.10", 8108, "198.51.100.8") == "failed"
    assert _router("FORWARD 0 0\n").port_forward_ensure(
        "isp-plug", "192.0.2.10", 8108, "198.51.100.8") == "failed"
    assert _router("").port_forward_ensure(
        "isp-plug", "192.0.2.10", 8108, "198.51.100.8") == "failed"


@pytest.mark.parametrize("name, src, port, to", [
    ("isp-plug", "192.0.2.10; /system reset", 8108, "198.51.100.8"),
    ("isp-plug", "192.0.2.10", 8108, 'x" comment="y'),
    ('x" ; /user add', "192.0.2.10", 8108, "198.51.100.8"),
    ("isp-plug", "192.0.2.10", 0, "198.51.100.8"),
    ("isp-plug", "192.0.2.10", 70000, "198.51.100.8"),
    ("isp-plug", "", 8108, "198.51.100.8"),
])
def test_forward_rejects_anything_that_is_not_plain_addresses(name, src, port, to) -> None:
    router = _router("FORWARD 0 1\n")
    assert router.port_forward_ensure(name, src, port, to) == "failed"
    router._ssh.assert_not_called()


def test_forward_needs_the_router_by_address_and_can_be_removed() -> None:
    by_name = _router("FORWARD 0 1\n", host="router.invalid")
    assert by_name.port_forward_ensure("isp-plug", "192.0.2.10", 8108, "198.51.100.8") == "failed"
    router = _router("0\n")
    assert router.port_forward_remove("isp-plug") is True
    assert 'remove [find comment="netsentry-forward isp-plug"]' in router._ssh.call_args.args[0]
    assert router.port_forward_remove("bad name!") is False


# ─── the Telegram flow ───────────────────────────────────────────

def _power(tmp_path: Path, plug: dict | None = None, **device) -> tuple[PowerPlugin, _FakePlugHttp]:
    config = {"isp_plug": plug} if plug is not None else {}
    router = Mock()
    router.host = "192.0.2.1"
    router.port_forward_ensure.return_value = "exists"
    ctx = PluginContext(
        name="power", config=config, router=router, notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.power"), state_dir=str(tmp_path), events=EventBus())
    p = PowerPlugin(ctx)
    p._after = Mock()  # type: ignore[method-assign]  (no real timers in tests)
    p.on_load()
    return p, _FakePlugHttp(**device)


def _press(p: PowerPlugin, http: _FakePlugHttp, data: str) -> tuple[str, list[dict]]:
    p.notifier.edit_message.reset_mock()
    with patch(URLOPEN, side_effect=http):
        p.on_callback(data, CHAT, 7, "cb1")
    call = p.notifier.edit_message.call_args
    return call.args[2], [b for row in (call.kwargs.get("buttons") or []) for b in row]


def test_the_button_only_exists_when_a_plug_is_configured(tmp_path: Path) -> None:
    without, _ = _power(tmp_path / "a")
    without.on_command("/restart", "", CHAT)
    labels = [b["text"] for row in without.notifier.send_to.call_args.kwargs["buttons"] for b in row]
    assert not any("Internet router" in t for t in labels)
    without.on_callback("power:isp:go", CHAT, 7, "cb")        # crafted callback: ignored
    assert not (tmp_path / "a" / "pending.json").exists()

    with_plug, _ = _power(tmp_path / "b", {"host": "192.0.2.50"})
    with_plug.on_command("/restart", "", CHAT)
    labels = [b["text"] for row in with_plug.notifier.send_to.call_args.kwargs["buttons"] for b in row]
    assert "🌐 Internet router (smart plug)" in labels


def test_looking_first_then_restarting(tmp_path: Path) -> None:
    p, http = _power(tmp_path, {"host": "192.0.2.50", "off_seconds": 12})
    text, buttons = _press(p, http, "power:isp:look")
    assert "— power on" in text and "7.4 W" in text and "12 seconds" in text
    assert not any("Switch.Set" in u for u in http.urls)                # looking changes nothing
    go = next(b["callback_data"] for b in buttons if "Restart it now" in b["text"])

    text, buttons = _press(p, http, go)
    assert "off for 12 s" in text and buttons == []
    assert http.urls[-1].endswith("Switch.Set?id=0&on=false&toggle_after=12")
    assert json.loads((tmp_path / "pending.json").read_text("utf-8"))["target"] == "isp"
    delay, func, chat, started = p._after.call_args.args
    assert delay == 32 and func == p._wait_for_internet and chat == CHAT


def test_a_plug_that_would_stay_off_after_a_power_cut_must_be_fixed_first(tmp_path: Path) -> None:
    p, http = _power(tmp_path, {"host": "192.0.2.50"}, initial_state="off")
    text, buttons = _press(p, http, "power:isp:look")
    assert "stays OFF" in text
    assert not any("Restart it now" in b["text"] for b in buttons)
    # a stale "go" button from an earlier screen does not get around it
    text, _ = _press(p, http, "power:isp:go")
    assert "Not restarted" in text and http.device["output"] is True
    assert not (tmp_path / "pending.json").exists()

    text, buttons = _press(p, http, "power:isp:fix")
    assert http.device["initial_state"] == "on"
    assert any("Restart it now" in b["text"] for b in buttons)


def test_a_plug_that_is_off_offers_to_switch_on(tmp_path: Path) -> None:
    p, http = _power(tmp_path, {"host": "192.0.2.50"}, output=False, apower=0.0)
    text, buttons = _press(p, http, "power:isp:look")
    assert "— power off" in text and not any("Restart it now" in b["text"] for b in buttons)
    text, buttons = _press(p, http, "power:isp:on")
    assert http.device["output"] is True and "— power on" in text


def test_nothing_plugged_in_is_pointed_out(tmp_path: Path) -> None:
    p, http = _power(tmp_path, {"host": "192.0.2.50"}, apower=0.0)
    text, buttons = _press(p, http, "power:isp:look")
    assert "Nothing seems to be drawing power" in text
    assert any("Restart it now" in b["text"] for b in buttons)          # still allowed


def test_unreachable_plug_switches_nothing(tmp_path: Path) -> None:
    p, _ = _power(tmp_path, {"host": "192.0.2.50"})
    p.notifier.edit_message.reset_mock()
    with patch(URLOPEN, side_effect=urllib.error.URLError("no route")):
        p.on_callback("power:isp:go", CHAT, 7, "cb1")
    text = p.notifier.edit_message.call_args.args[2]
    assert "did not answer" in text and "Nothing was switched" in text
    assert not (tmp_path / "pending.json").exists()


def test_plug_behind_the_router_is_reached_through_one_forward(tmp_path: Path) -> None:
    p, http = _power(tmp_path, {"host": "198.51.100.8", "via_router_port": 8108})
    p.router.port_forward_ensure.return_value = "added"
    events: list = []
    p.ctx.events.subscribe("router.config.expected_change", events.append)
    with patch("netsentry.plugins.power._own_address_towards", return_value="192.0.2.10"):
        _press(p, http, "power:isp:look")
    p.router.port_forward_ensure.assert_called_once_with(
        "isp-plug", "192.0.2.10", 8108, "198.51.100.8", 80)
    assert http.urls[0].startswith("http://192.0.2.1:8108/rpc/")       # via the router
    assert len(events) == 1                                            # our own change, announced

    p.router.port_forward_ensure.return_value = "failed"
    with patch("netsentry.plugins.power._own_address_towards", return_value="192.0.2.10"):
        text, _ = _press(p, http, "power:isp:look")
    assert "would not set up the path" in text


def test_internet_back_is_reported_when_telegram_answers_again(tmp_path: Path) -> None:
    import time
    p, _ = _power(tmp_path, {"host": "192.0.2.50"})
    p._remember("isp", CHAT)
    p.notifier.api_get.side_effect = [None, None, {"ok": True}]
    with patch("netsentry.plugins.power.time.sleep"):
        p._wait_for_internet(CHAT, time.time() - 150)
    assert p.notifier.api_get.call_count == 3
    kind, text = p.notifier.notify.call_args.args
    assert kind == "recovery" and p.notifier.notify.call_args.kwargs["chat_id"] == CHAT
    assert "internet is back — 2 min after" in text
    assert not (tmp_path / "pending.json").exists()


def test_giving_up_waiting_is_logged_not_looped_forever(tmp_path: Path, caplog) -> None:
    import time
    p, _ = _power(tmp_path, {"host": "192.0.2.50"})
    p.notifier.api_get.return_value = None
    with caplog.at_level(logging.ERROR):
        p._wait_for_internet(CHAT, time.time() - 10_000)               # already past the limit
    p.notifier.send_to.assert_not_called()
    assert "did not come back" in caplog.text


def test_a_restart_of_netsentry_meanwhile_still_reports_the_router(tmp_path: Path) -> None:
    p, _ = _power(tmp_path, {"host": "192.0.2.50"})
    p._remember("isp", CHAT)
    p._announce_back()
    assert "The internet router is back" in p.notifier.notify.call_args.args[1]
