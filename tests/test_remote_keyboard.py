"""Remote keyboard and mouse: the rules (core/remote_input.py), the plugin, the
dashboard's /remote page and API, and the /pc button. Offline, fake transport."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core import hid_keys
from netsentry.core.ai import DisabledAI
from netsentry.core.plugin import PluginContext
from netsentry.core.remote_input import Frame, RelayView, RemoteError, RemoteInput
from netsentry.plugins.lan_dashboard import LanDashboardPlugin, _safe_next
from netsentry.plugins.remote_keyboard import RemoteKeyboardPlugin
from netsentry.plugins.workstation import WorkstationPlugin

TOKEN = "test-token-remote"
SECRET = "Hunter2!Zq"                      # stands in for a Windows password
SHIFT, CTRL, ALT = hid_keys.MOD_SHIFT, hid_keys.MOD_CTRL, hid_keys.MOD_ALT
U = hid_keys.KEYS


class FakeTransport:
    def __init__(self) -> None:
        self.bursts: list[list[Frame]] = []
        self.calls: list[str] = []
        self.answer = True
        self.reply = ""
        self.view_state = RelayView(running=True, serial_open=True, target="on",
                                    encrypted=True, control="none")
        self.raise_on_send: Exception | None = None
        self.on_send = None

    def view(self) -> RelayView:
        return self.view_state

    def start(self) -> None:
        self.calls.append("start")

    def probe(self) -> bool:
        self.calls.append("probe")
        return self.answer

    def send(self, frames, cancel: threading.Event) -> str:
        self.calls.append("send")
        if self.on_send:
            self.on_send(cancel)
        if self.raise_on_send:
            raise self.raise_on_send
        self.bursts.append(list(frames))
        return "cancelled" if cancel.is_set() else self.reply

    def release(self) -> None:
        self.calls.append("release")

    def stop(self) -> None:
        self.calls.append("stop")


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def _remote(**kw) -> tuple[RemoteInput, FakeTransport, Clock]:
    t, c = FakeTransport(), Clock()
    kw.setdefault("logger", logging.getLogger("test.remote"))
    return RemoteInput(t, clock=c, **kw), t, c


def _held(burst: list[Frame]) -> list[tuple[int, set[int]]]:
    return [(f.mods, set(f.keys)) for f in burst]


# ─── the armed window ────────────────────────────────────────────

def test_disarmed_sends_nothing() -> None:
    r, t, _ = _remote()
    for call in (lambda: r.press_key("enter"), lambda: r.type_text("abc"),
                 lambda: r.mouse(dx=5)):
        with pytest.raises(RemoteError) as err:
            call()
        assert err.value.code == "not_armed"
    assert t.bursts == [] and "send" not in t.calls
    assert r.status()["armed"] is False


def test_arming_needs_an_answer_from_the_relay() -> None:
    r, t, _ = _remote()
    t.answer = False
    with pytest.raises(RemoteError) as err:
        r.arm()
    assert err.value.code == "no_answer" and err.value.status == 503
    assert not r.status()["armed"] and t.calls == ["start", "probe", "stop"]


def test_a_socket_error_on_arming_is_a_clear_refusal() -> None:
    r, t, _ = _remote()

    def broken() -> None:
        raise OSError("Cannot assign requested address")

    t.start = broken                            # type: ignore[method-assign]
    with pytest.raises(RemoteError) as err:
        r.arm()
    assert err.value.code == "relay_unusable" and err.value.status == 503
    assert not r.status()["armed"] and t.calls == ["stop"]


def test_arming_is_refused_while_the_hidway_client_has_control_or_the_relay_is_down() -> None:
    r, t, _ = _remote()
    t.view_state = RelayView(running=True, control="other")
    with pytest.raises(RemoteError) as err:
        r.arm()
    assert err.value.code == "in_use" and "start" not in t.calls
    t.view_state = RelayView(running=False, problem="The HIDway relay is not running.")
    with pytest.raises(RemoteError) as err:
        r.arm()
    assert err.value.code == "relay_unusable" and err.value.status == 503


def test_the_window_closes_by_itself_and_input_keeps_it_open() -> None:
    r, t, clock = _remote(idle_timeout_s=60)
    r.arm()
    assert r.status()["armed_left_s"] == 60
    clock.t += 50
    r.press_key("tab")                         # activity: another 60 s
    clock.t += 50
    assert r.status()["armed"] is True
    clock.t += 11
    assert r.status()["armed"] is False
    assert t.calls[-2:] == ["release", "stop"]
    with pytest.raises(RemoteError):
        r.press_key("tab")


def test_disarm_releases_and_ends_the_session() -> None:
    r, t, _ = _remote()
    r.arm()
    state = r.disarm()
    assert state["armed"] is False and t.calls[-2:] == ["release", "stop"]


# ─── keys and text ───────────────────────────────────────────────

def test_named_keys_and_combinations() -> None:
    r, t, _ = _remote()
    r.arm()
    r.press_key("delete", ["ctrl", "alt"])
    assert _held(t.bursts[-1]) == [(0, set()), (CTRL | ALT, set()),
                                   (CTRL | ALT, {U["delete"]}), (CTRL | ALT, set()), (0, set())]
    r.press_key("win")                         # the Start menu: the modifier alone
    assert _held(t.bursts[-1]) == [(0, set()), (hid_keys.MOD_WIN, set()), (0, set())]
    r.press_key("f5")
    assert _held(t.bursts[-1]) == [(0, set()), (0, {0x3E}), (0, set()), (0, set())]


@pytest.mark.parametrize("key,mods", [("rm -rf", None), ("ENTER", None), (None, None),
                                      ("enter", ["hyper"]), ("enter", "ctrl"),
                                      ("enter", ["ctrl"] * 5), (["enter"], None)])
def test_keys_and_modifiers_off_the_list_are_refused(key, mods) -> None:
    r, t, _ = _remote()
    r.arm()
    with pytest.raises(RemoteError) as err:
        r.press_key(key, mods)
    assert err.value.code == "bad_key" and err.value.status == 400
    assert t.bursts == []


def test_text_maps_to_us_keys_with_shift_and_ends_with_nothing_held() -> None:
    r, t, _ = _remote()
    r.arm()
    r.type_text("aA!", enter=True)
    assert _held(t.bursts[-1]) == [
        (0, set()),
        (0, {U["a"]}), (0, set()),                     # a
        (SHIFT, set()), (SHIFT, {U["a"]}), (SHIFT, set()),   # A
        (SHIFT, {U["1"]}), (SHIFT, set()),             # ! = Shift+1, Shift stays down
        (0, set()), (0, {U["enter"]}), (0, set()),     # Enter
        (0, set()),                                    # everything up
    ]
    assert t.calls[-1] == "release"


def test_us_layout_table_covers_printable_ascii_and_nothing_else() -> None:
    printable = [chr(c) for c in range(0x20, 0x7F)]
    strokes = hid_keys.text_strokes("".join(printable))
    assert strokes is not None and len(strokes) == len(printable)
    shifted = {ch for ch, s in zip(printable, strokes) if s.mods == SHIFT}
    assert set('~!@#$%^&*()_+{}|:"<>?') <= shifted and "Q" in shifted
    assert not shifted & set("q1-=[];',./`\\ ")
    for ch in ("é", "α", "\n", "\t", "€", "😀", "\x00"):
        assert hid_keys.text_strokes("ab" + ch) is None


def test_untypeable_or_too_long_text_types_nothing() -> None:
    r, t, _ = _remote(max_text=8)
    r.arm()
    for text, code in (("καλημέρα", "untypeable"), ("a\nb", "untypeable"),
                       ("x" * 9, "too_long"), ("", "bad_text"), (42, "bad_text")):
        with pytest.raises(RemoteError) as err:
            r.type_text(text)
        assert err.value.code == code and err.value.status == 400
    assert t.bursts == []


def test_every_key_is_released_even_when_sending_fails() -> None:
    r, t, _ = _remote()
    r.arm()
    t.raise_on_send = OSError("boom")
    with pytest.raises(RemoteError) as err:
        r.type_text(SECRET)
    assert err.value.code == "no_answer" and err.value.status == 502
    assert t.calls[-2:] == ["send", "release"]
    assert SECRET not in err.value.message
    t.raise_on_send = None
    t.reply = "no_answer"
    with pytest.raises(RemoteError):
        r.press_key("enter")
    assert t.calls[-1] == "release"


def test_disarming_mid_word_stops_and_releases() -> None:
    r, t, _ = _remote()
    r.arm()
    t.on_send = lambda cancel: r.disarm()        # the page disarms while typing
    with pytest.raises(RemoteError) as err:
        r.type_text("abcdef")
    assert err.value.code == "cancelled"
    assert "release" in t.calls[t.calls.index("send"):] and t.calls[-1] == "stop"
    assert r.status()["armed"] is False


def test_the_hidway_client_taking_control_disarms_this_page() -> None:
    r, t, _ = _remote()
    r.arm()
    t.view_state = RelayView(running=True, control="other")
    with pytest.raises(RemoteError) as err:
        r.press_key("enter")
    assert err.value.code == "in_use" and t.bursts == []
    assert r.status()["armed"] is False


def test_rate_limit() -> None:
    r, t, clock = _remote(rate_per_s=3)
    r.arm()
    for _ in range(3):
        r.press_key("up")
    with pytest.raises(RemoteError) as err:
        r.press_key("up")
    assert err.value.code == "slow_down" and err.value.status == 429
    assert len(t.bursts) == 3
    clock.t += 1.0
    r.press_key("up")
    assert len(t.bursts) == 4


# ─── mouse ───────────────────────────────────────────────────────

def test_mouse_moves_are_clamped_cumulative_and_start_from_a_baseline() -> None:
    r, t, _ = _remote(max_step=100)
    r.arm()
    r.mouse(dx=30, dy=-10)
    assert [(f.x, f.y) for f in t.bursts[-1]] == [(0, 0), (30, (-10) & 0xFFFFFFFF)]
    r.mouse(dx=5000, dy=0)                      # clamped to 100
    assert [f.x for f in t.bursts[-1]] == [30, 130]
    r.mouse(wheel=99)                           # clamped to max_wheel (10)
    assert [f.wheel for f in t.bursts[-1]] == [0, 10]
    assert all(f.buttons == 0 and not f.keys for b in t.bursts for f in b)


def test_clicks_press_and_release_the_button() -> None:
    r, t, _ = _remote()
    r.arm()
    r.mouse(click="right")
    assert [f.buttons for f in t.bursts[-1]] == [0, 2, 0]
    r.mouse(click="left", double=True)
    assert [f.buttons for f in t.bursts[-1]] == [0, 1, 0, 1, 0]


@pytest.mark.parametrize("kw", [{"dx": "5"}, {"dy": None}, {"wheel": float("nan")},
                                {"dx": True}, {"click": "back"}, {}])
def test_bad_mouse_input_is_refused(kw) -> None:
    r, t, _ = _remote()
    r.arm()
    with pytest.raises(RemoteError) as err:
        r.mouse(**kw)
    assert err.value.code == "bad_mouse" and t.bursts == []


def test_configured_limits_cannot_exceed_the_hard_caps() -> None:
    r, _, _ = _remote(max_text=10_000, max_step=10**9, rate_per_s=10_000, idle_timeout_s=1)
    assert r.max_text == 256 and r.max_step == 2000 and r.rate_per_s == 60
    assert r.idle_timeout_s == 15


# ─── the plugin ──────────────────────────────────────────────────

def _plugin(tmp_path: Path, **config) -> RemoteKeyboardPlugin:
    ctx = PluginContext(name="remote_keyboard", config=config, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger("test.remote_keyboard"),
                        state_dir=str(tmp_path))
    p = RemoteKeyboardPlugin(ctx)
    p.on_load()
    return p


def test_off_unless_configured(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    assert not p.configured and p.api_status() == {"configured": False} and p.health() == []


def test_without_a_key_nothing_is_set_up_unless_plaintext_is_allowed(tmp_path: Path) -> None:
    p = _plugin(tmp_path, relay_host="192.0.2.10")
    assert not p.configured
    assert p.health()[0].ok is False and "no key" in p.health()[0].detail
    state = tmp_path / "state"
    state.write_text("link=down\nserial=open\ncrypto=off\n", encoding="utf-8")
    p = _plugin(tmp_path, relay_host="192.0.2.10", allow_plaintext=True,
                relay_state_file=str(state))
    assert p.configured and p.health()[0].ok


def test_a_bad_key_is_a_fault_that_never_shows_the_key(tmp_path: Path, caplog) -> None:
    bad = "cafe" * 15 + "zz"                    # 62 hex + junk
    with caplog.at_level(logging.INFO):
        p = _plugin(tmp_path, relay_host="192.0.2.10", key=bad)
    check = p.health()[0]
    assert not p.configured and check.ok is False and "64 hex" in check.detail
    assert bad not in check.detail and bad not in caplog.text


def test_health_is_a_fault_only_when_the_relay_cannot_be_used(tmp_path: Path) -> None:
    state = tmp_path / "state"
    p = _plugin(tmp_path, relay_host="192.0.2.10", key="ab" * 32, relay_state_file=str(state))
    check = p.health()[0]                       # no state file: the relay does not run
    assert check.ok is False and "not running" in check.detail
    state.write_text("link=down\nserial=closed\ncrypto=on\n", encoding="utf-8")
    check = p.health()[0]
    assert check.ok is True and "Pico not connected" in check.detail
    state.write_text("link=down\nserial=open\ncrypto=off\n", encoding="utf-8")
    assert p.health()[0].ok is False             # key here, plaintext relay


def test_transport_settings(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.write_text("link=down\nserial=open\ncrypto=on\nlocal_socket=off\n", encoding="utf-8")
    p = _plugin(tmp_path, relay_host="192.0.2.10", key="ab" * 32, relay_state_file=str(state))
    transport = p.remote.transport
    assert transport.mode == "auto" and transport.local_socket == "/run/hidway/inject.sock"
    assert p.health()[0].detail == "relay running (udp), Pico connected"
    assert p.api_status()["transport"] == "udp"

    # socket only: no relay_host and no key needed, and never UDP
    p = _plugin(tmp_path, transport="local", relay_state_file=str(state))
    assert p.configured and not p.remote.transport.udp_configured
    assert p.health()[0].ok is False and "local socket is off" in p.health()[0].detail
    state.write_text("link=down\nserial=open\ncrypto=on\nlocal_socket=on\n", encoding="utf-8")
    assert p.health()[0].detail == "relay running (local), Pico connected"

    p = _plugin(tmp_path, relay_host="192.0.2.10", key="ab" * 32, transport="pigeon")
    assert not p.configured and "transport must be" in p.health()[0].detail
    p = _plugin(tmp_path, transport="local", local_socket="relative.sock")
    assert not p.configured and "absolute path" in p.health()[0].detail


# ─── the dashboard ───────────────────────────────────────────────

class _RemotePlugin:
    def __init__(self, remote: RemoteInput | None) -> None:
        self.ctx = Mock()
        self.ctx.name = "remote_keyboard"
        self.remote = remote
        self.configured = remote is not None


def _dash(tmp_path: Path, remote: RemoteInput | None, logger_name: str = "test.dash.remote"):
    ctx = PluginContext(name="lan_dashboard", config={}, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger(logger_name),
                        state_dir=str(tmp_path))
    ctx._all_plugins = [_RemotePlugin(remote)]  # type: ignore[attr-defined]
    plugin = LanDashboardPlugin(ctx)
    plugin._token = TOKEN
    plugin._public_base_url = "https://dash.example"
    app = plugin._build_app()
    app.config["TESTING"] = True
    return app.test_client(), plugin


@pytest.fixture()
def remote_client(tmp_path: Path):
    r, t, clock = _remote()
    client, plugin = _dash(tmp_path, r)
    return client, r, t, clock


ROUTES = [("get", "/remote"), ("get", "/api/remote/status"), ("post", "/api/remote/arm"),
          ("post", "/api/remote/disarm"), ("post", "/api/remote/key"),
          ("post", "/api/remote/text"), ("post", "/api/remote/mouse")]


def test_every_remote_route_needs_the_session_cookie(remote_client) -> None:
    client, _, t, _ = remote_client
    for method, path in ROUTES:
        resp = getattr(client, method)(path, json={"key": "enter", "text": SECRET, "dx": 4})
        assert resp.status_code == 403, path
        assert resp.headers["Cache-Control"].startswith("no-store"), path
    assert t.calls == []


def test_not_configured_means_no_page_no_api_and_no_tab(tmp_path: Path) -> None:
    client, _ = _dash(tmp_path, None)
    client.get("/auth?token=" + TOKEN)
    for method, path in ROUTES:
        assert getattr(client, method)(path, json={}).status_code == 404, path
    assert "tab--remote" not in client.get("/").get_data(as_text=True)


def test_page_renders_private_and_the_tab_shows(remote_client) -> None:
    client, _, _, _ = remote_client
    client.get("/auth?token=" + TOKEN)
    resp = client.get("/remote")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"].startswith("no-store")
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    for attr in ('type="password"', 'autocomplete="off"', 'autocapitalize="off"',
                 'spellcheck="false"', "remote.js", 'id="armBtn"', 'id="pageStatus"'):
        assert attr in html, attr
    assert 'class="tab tab--remote"' in html
    assert 'class="tab tab--remote"' in client.get("/system").get_data(as_text=True)
    assert "innerHTML" not in html
    assert _safe_next("/remote") == "/remote"


def test_flow_arm_type_disarm_with_nothing_echoed_or_logged(remote_client, caplog) -> None:
    client, _, t, _ = remote_client
    client.get("/auth?token=" + TOKEN)
    with caplog.at_level(logging.DEBUG):
        assert client.post("/api/remote/text", json={"text": SECRET}).status_code == 409
        assert t.bursts == []                                   # disarmed: nothing sent
        arm = client.post("/api/remote/arm", json={})
        assert arm.status_code == 200 and arm.get_json()["state"]["armed"] is True
        typed = client.post("/api/remote/text", json={"text": SECRET, "enter": True})
        bad = client.post("/api/remote/text", json={"text": SECRET + "é"})
        long = client.post("/api/remote/text", json={"text": SECRET * 30})
        key = client.post("/api/remote/key", json={"key": "enter", "mods": ["ctrl"]})
        client.post("/api/remote/disarm", data="", content_type="text/plain")   # sendBeacon
    assert typed.status_code == 200 and typed.get_json()["ok"] is True
    assert bad.status_code == 400 and long.status_code == 400 and key.status_code == 200
    for resp in (typed, bad, long, key):
        assert SECRET not in resp.get_data(as_text=True)
        assert resp.headers["Cache-Control"].startswith("no-store")
    assert SECRET not in caplog.text and "Hunter" not in caplog.text
    assert len(t.bursts) == 2                                   # the text and the key
    assert client.get("/api/remote/status").get_json()["state"]["armed"] is False


def test_input_must_be_json(remote_client) -> None:
    client, r, t, _ = remote_client
    client.get("/auth?token=" + TOKEN)
    r.arm()
    resp = client.post("/api/remote/text", data="text=abc",
                       content_type="application/x-www-form-urlencoded")
    assert resp.status_code == 415 and t.bursts == []


def test_server_side_window_applies_to_the_api(remote_client) -> None:
    client, _, t, clock = remote_client
    client.get("/auth?token=" + TOKEN)
    client.post("/api/remote/arm", json={})
    clock.t += 181
    resp = client.post("/api/remote/key", json={"key": "enter"})
    assert resp.status_code == 409 and resp.get_json()["error"] == "not_armed"
    assert t.bursts == []


def test_mouse_api_and_rate_limit(remote_client) -> None:
    client, r, t, _ = remote_client
    client.get("/auth?token=" + TOKEN)
    client.post("/api/remote/arm", json={})
    assert client.post("/api/remote/mouse", json={"dx": 12, "dy": 3}).status_code == 200
    assert client.post("/api/remote/mouse", json={"click": "left"}).status_code == 200
    codes = [client.post("/api/remote/mouse", json={"dx": 1}).status_code for _ in range(40)]
    assert 429 in codes
    assert client.post("/api/remote/mouse", json={"dx": "x"}).status_code in (400, 429)


# ─── /pc: the "Open remote keyboard" button ──────────────────────

def _workstation(tmp_path: Path, plugins: list, **config) -> WorkstationPlugin:
    cfg = {"host": "192.0.2.40", "user": "pcuser", "ssh_key": "/keys/pc"}
    cfg.update(config)
    ctx = PluginContext(name="workstation", config=cfg, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger("test.ws.remote"),
                        state_dir=str(tmp_path), ai=DisabledAI())
    ctx._all_plugins = plugins  # type: ignore[attr-defined]
    p = WorkstationPlugin(ctx)
    p.on_load()
    return p


def test_pc_screens_offer_the_remote_page_when_it_is_configured(tmp_path: Path) -> None:
    r, _, _ = _remote()
    _, dash = _dash(tmp_path, r)
    remote = _RemotePlugin(r)
    p = _workstation(tmp_path, [remote, dash])
    link = p._keyboard_link()
    assert link == f"https://dash.example/auth?token={TOKEN}&next=/remote"

    remote.configured = False
    assert p._keyboard_link() == ""
    remote.configured = True
    dash._public_base_url = ""                 # no phone-reachable dashboard: no button
    assert p._keyboard_link() == ""

    p = _workstation(tmp_path, [remote, dash], remote_keyboard_url="https://keyboard.example/")
    assert p._keyboard_link() == "https://keyboard.example/"   # an explicit URL wins


def test_the_login_screen_shows_the_button_by_itself(tmp_path: Path) -> None:
    from test_workstation import _FakePc, _press
    from test_workstation import _plugin as workstation_plugin

    p, pc = workstation_plugin(tmp_path, _FakePc(on=False, logged_on=False))
    r, t, _ = _remote()
    _, dash = _dash(tmp_path, r)
    p.ctx._all_plugins = [_RemotePlugin(r), dash]  # type: ignore[attr-defined]
    text, buttons = _press(p, "workstation:go:hermes")
    assert text.startswith("⚠️ Gaming PC — on, nobody logged in")
    assert {"text": "⌨️ Open remote keyboard",
            "url": f"https://dash.example/auth?token={TOKEN}&next=/remote"} in buttons
    assert t.calls == []                       # a link only: nothing reaches the PC
