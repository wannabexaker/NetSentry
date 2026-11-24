"""The gaming PC: Wake-on-LAN, the PC-agent client, the LM Studio tunnel and
AI provider, and the /pc screens, cold start, watcher, health and dashboard
picture built on them."""

from __future__ import annotations

import io
import json
import logging
import socket
import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core import notify, ui, wol
from netsentry.core.ai import DisabledAI, OpenAICompatibleClient, build_ai
from netsentry.core.pc_agent import (
    FAULT,
    OFF,
    OK,
    AgentConfigError,
    SUMMARY_UNUSABLE,
    PcAgent,
    parse_status,
    parse_summary,
)
from netsentry.core.plugin import PluginContext
from netsentry.core.tunnel import FIRST_BACKOFF_S, TunnelKeeper
from netsentry.plugins.workstation import WorkstationPlugin, summary_text

CHAT = 42
MAC = "AA:BB:CC:DD:EE:FF"

# AI Mission Control's `summary` answer (a real one, host replaced).
MC_SUMMARY = {
    "Version": "0.5.0", "Time": "2026-11-24T11:04:55", "Game": "",
    "VramUsedMiB": 1585, "VramTotalMiB": 16303, "RamFreePercent": 41.8, "RamFreeMB": 13336,
    "RamTotalMB": 31895, "Models": [],
    "Services": [
        {"Id": "lmstudio", "Name": "LM Studio", "Running": True, "Remote": False, "Port": 1234,
         "Model": None},
        {"Id": "hermes", "Name": "Hermes", "Running": True, "Remote": False, "Port": None,
         "Model": "huihui-qwen3.5-35b-a3b-abliterated"},
        {"Id": "openclaw", "Name": "OpenClaw", "Running": False, "Remote": False, "Port": 18789,
         "Model": "gpt-oss-20b"},
        {"Id": "opencode", "Name": "OpenCode", "Running": False, "Remote": False, "Port": 4096,
         "Model": "gpt-oss-20b"},
        {"Id": "netsentry", "Name": "NetSentry", "Running": True, "Remote": True, "Port": 22,
         "Model": None}],
    "Pages": [
        {"Id": "hermes/Dashboard", "Name": "Hermes", "Label": "Dashboard", "Port": 9119,
         "Available": False, "LocalUrl": "http://127.0.0.1:9119/", "TailscaleShared": False,
         "TailscaleUrl": "https://pc.example.ts.net:9119/", "Reach": "off",
         "Sign": "config, keys and sessions"},
        {"Id": "openclaw/Web UI", "Name": "OpenClaw", "Label": "Web UI", "Port": 18789,
         "Available": False, "LocalUrl": "http://127.0.0.1:18789/", "TailscaleShared": False,
         "TailscaleUrl": "https://pc.example.ts.net:18789/", "Reach": "off",
         "Sign": "asks for the gateway token"},
        {"Id": "opencode/Web UI", "Name": "OpenCode", "Label": "Web UI", "Port": 4096,
         "Available": False, "LocalUrl": "http://127.0.0.1:4096/", "TailscaleShared": False,
         "TailscaleUrl": "https://pc.example.ts.net:4096/", "Reach": "off",
         "Sign": "coding agent in the browser"}],
    "LastAction": {"Summary": "Hermes is running", "State": "ok", "Reason": "",
                   "Ended": "2026-11-24T10:52:23"},
}


# ─── a pretend PC behind the restricted key ─────────────────────

def _done(argv, rc: int, out: str = "", err: str = ""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class _FakePc:
    """Answers the agent's actions like tools/pc-agent/pc-agent.ps1 would."""

    def __init__(self, *, on: bool = True, logged_on: bool = True, temp: int = 41,
                 load: int = 0, disk: int = 760, models=("gpt-oss-20b",),
                 game: bool = False) -> None:
        self.on, self.logged_on = on, logged_on
        self.temp, self.load, self.disk, self.models, self.game = temp, load, disk, \
            list(models), game
        self.running = {"lmstudio": True, "hermes": False, "openclaw": False}
        self.actions: list[str] = []
        self.boot_after: int | None = None    # status polls until a woken PC answers
        self.refuse_key = False
        self.start_fails = False
        self.sleeps = True                    # "sleep" really switches it off
        self.summary_out = json.dumps(MC_SUMMARY)    # AI Mission Control 0.5.0+
        self.summary_rc = 0

    def wake(self, polls: int) -> None:
        if not self.on:
            self.boot_after = polls

    def __call__(self, argv, **kw):
        action = argv[-1]
        self.actions.append(action)
        assert kw.get("timeout") and kw.get("capture_output")
        if not self.on:
            if self.boot_after is not None:
                self.boot_after -= 1
                if self.boot_after <= 0:
                    self.on, self.boot_after = True, None
            return _done(argv, 255, "", "ssh: connect to host 192.0.2.40 port 22: "
                                        "Connection timed out")
        if self.refuse_key:
            return _done(argv, 255, "", "pcuser@192.0.2.40: Permission denied (publickey).")
        if action == "status":
            return _done(argv, 0, json.dumps(self.status()))
        verb, _, sid = action.partition(" ")
        if verb == "start":
            if sid != "lmstudio" and not self.logged_on:
                return _done(argv, 0, json.dumps({"ok": False, "id": sid, "running": False,
                                                  "reason": "nobody is logged in on the PC"}))
            if not self.start_fails:
                self.running[sid] = True
            return _done(argv, 0, json.dumps({"ok": self.running[sid], "id": sid,
                                              "running": self.running[sid], "reported": True}))
        if verb == "stop":
            self.running[sid] = False
            return _done(argv, 0, json.dumps({"ok": True, "id": sid, "running": False,
                                              "reported": True}))
        if action == "free-vram":
            return _done(argv, 0, json.dumps({"ok": True, "gpu": {"vram_used_mb": 1200,
                                                                  "vram_total_mb": 16303}}))
        if action in ("shutdown", "restart"):
            return _done(argv, 0, json.dumps({"ok": True, "in_seconds": 15}))
        if action == "cancel":
            return _done(argv, 0, json.dumps({"ok": True}))
        if action == "summary":
            return _done(argv, self.summary_rc, self.summary_out)
        if verb == "share":                   # share <page slug> on|off -> the summary after it
            slug, _, flag = sid.partition(" ")
            data = json.loads(self.summary_out)
            hit = [g for g in data["Pages"]
                   if "-".join("".join(c if c.isalnum() else " " for c in g["Id"].lower()).split())
                   == slug]
            if not hit:
                return _done(argv, 64, "", "netsentry-pc-agent: that action is not on the list")
            hit[0]["TailscaleShared"] = flag == "on"
            data["LastAction"] = {"Summary": f"{hit[0]['Name']} "
                                  + ("shared over Tailscale" if flag == "on" else
                                     "no longer shared over Tailscale"),
                                  "State": "ok", "Reason": "", "Ended": "2026-11-24T11:20:00"}
            self.summary_out = json.dumps(data)
            return _done(argv, 0, self.summary_out)
        if action in ("sleep", "hibernate"):
            if self.sleeps:
                self.on = False
            return _done(argv, 255, '{"ok":true}\n', "Connection to 192.0.2.40 closed by "
                                                    "remote host.")
        raise AssertionError(f"unexpected action {action!r}")

    def status(self) -> dict:
        return {
            "host": "PC-EXAMPLE", "time": "2026-11-20T12:00:00", "uptime_s": 178893,
            "logged_on": self.logged_on, "ram_used_mb": 26064, "ram_total_mb": 31895,
            "disk_c_free_gb": self.disk, "disk_c_total_gb": 1862,
            "gpu": {"name": "Example GPU", "temp_c": self.temp, "load_pct": self.load,
                    "vram_used_mb": 14234, "vram_total_mb": 16303, "power_w": 41},
            "game_running": self.game, "models_loaded": list(self.models),
            "services": [
                {"id": "lmstudio", "name": "LM Studio", "running": self.running["lmstudio"],
                 "ram_mb": 14828, "model": None},
                {"id": "hermes", "name": "Hermes", "running": self.running["hermes"],
                 "ram_mb": 327, "model": "gpt-oss-20b"},
                {"id": "openclaw", "name": "OpenClaw", "running": self.running["openclaw"],
                 "ram_mb": 0, "model": "gpt-oss-20b"},
            ],
        }


class _Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def _agent(pc, **kw) -> PcAgent:
    return PcAgent("192.0.2.40", "pcuser", "/keys/pc", runner=pc, **kw)


# ─── Wake-on-LAN ─────────────────────────────────────────────────

def test_magic_packet_is_six_ff_then_the_mac_sixteen_times() -> None:
    packet = wol.magic_packet(MAC)
    assert len(packet) == 102
    assert packet[:6] == b"\xff" * 6
    assert packet[6:] == bytes.fromhex("AABBCCDDEEFF") * 16


@pytest.mark.parametrize("mac", ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff",
                                 "aabb.ccdd.eeff", "aabbccddeeff"])
def test_usual_mac_spellings_are_accepted(mac: str) -> None:
    assert wol.parse_mac(mac) == bytes.fromhex("aabbccddeeff")


@pytest.mark.parametrize("mac", ["", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:GG", "AA:BB-CC:DD:EE:FF",
                                 "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "AA:BB:CC:DD:EE:FF; x"])
def test_anything_else_is_not_a_mac(mac: str) -> None:
    with pytest.raises(wol.WakeError):
        wol.parse_mac(mac)


@pytest.mark.parametrize("target, expected", [
    ("192.0.2.1", ("192.0.2.1", 9)), ("192.0.2.255:7", ("192.0.2.255", 7)),
    ("router.example:9", ("router.example", 9))])
def test_wake_target_is_host_and_optional_port(target, expected) -> None:
    assert wol.parse_target(target) == expected


@pytest.mark.parametrize("target", ["", "-oProxyCommand=x", "http://192.0.2.1", "192.0.2.1:0",
                                    "192.0.2.1:99999", "192.0.2.1:x", "a b", "999.1.1.1"])
def test_wake_target_refuses_anything_but_an_address(target: str) -> None:
    with pytest.raises(wol.WakeError):
        wol.parse_target(target)


class _FakeSocket:
    def __init__(self, *args, fail: bool = False) -> None:
        self.sent: list[tuple[bytes, tuple]] = []
        self.options: list[tuple] = []
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, *a) -> bool:
        return False

    def setsockopt(self, *option) -> None:
        self.options.append(option)

    def sendto(self, data: bytes, address: tuple) -> None:
        if self.fail:
            raise OSError(101, "Network is unreachable")
        self.sent.append((data, address))


def test_wake_packet_goes_three_times_to_the_relay() -> None:
    sock = _FakeSocket()
    assert wol.send_magic_packet(MAC, "192.0.2.1:9", sock_factory=lambda *a: sock) == 3
    assert sock.sent == [(wol.magic_packet(MAC), ("192.0.2.1", 9))] * 3
    assert (socket.SOL_SOCKET, socket.SO_BROADCAST, 1) in sock.options


def test_a_wake_packet_that_cannot_leave_says_so() -> None:
    with pytest.raises(wol.WakeError, match="could not be sent"):
        wol.send_magic_packet(MAC, "192.0.2.1", sock_factory=lambda *a: _FakeSocket(fail=True))


# ─── the agent client ────────────────────────────────────────────

def test_the_list_is_fixed_and_ssh_runs_without_a_shell() -> None:
    pc = _FakePc()
    agent = _agent(pc)
    assert agent.allowed == {"status", "summary", "free-vram", "sleep", "hibernate", "shutdown", "restart",
                             "cancel", "start lmstudio", "stop lmstudio", "start hermes",
                             "stop hermes", "start openclaw", "stop openclaw"}
    seen = {}

    def runner(argv, **kw):
        seen.update(argv=argv, kw=kw)
        return pc(argv, **kw)

    _agent(runner, port=2222).status()
    argv = seen["argv"]
    assert argv[0] == "ssh" and argv[-2:] == ["pcuser@192.0.2.40", "status"]
    for option in ("BatchMode=yes", "StrictHostKeyChecking=accept-new", "ConnectTimeout=8"):
        assert option in argv
    assert argv[argv.index("-p") + 1] == "2222" and argv[argv.index("-i") + 1] == "/keys/pc"
    assert "shell" not in seen["kw"]


@pytest.mark.parametrize("action", ["status; reboot", "start notepad", "", "STATUS",
                                    "start  hermes", "stop hermes && x", "status\n"])
def test_an_action_not_on_the_list_never_reaches_ssh(action: str) -> None:
    pc = _FakePc()
    reply = _agent(pc).run(action)
    assert reply.outcome == FAULT and pc.actions == []


@pytest.mark.parametrize("host, user, key, services", [
    ("-oProxyCommand=x", "pcuser", "/k", None), ("192.0.2.40", "pc user", "/k", None),
    ("192.0.2.40", "-l", "/k", None), ("192.0.2.40", "pcuser", "-oX", None),
    ("192.0.2.40", "pcuser", "", None), ("192.0.2.40", "pcuser", "/k", ["Bad Id"]),
    ("192.0.2.40", "pcuser", "/k", ["x; reboot"]), ("", "pcuser", "/k", None)])
def test_config_that_could_become_ssh_options_is_refused(host, user, key, services) -> None:
    with pytest.raises(AgentConfigError):
        PcAgent(host, user, key, services=services or ["hermes"], runner=_FakePc())


def test_status_answer_is_read_into_small_records() -> None:
    reply, st = _agent(_FakePc()).status()
    assert reply.ok and st is not None
    assert st.logged_on and st.uptime_s == 178893 and st.disk_free_gb == 760
    assert st.gpu.temp_c == 41 and st.gpu.vram_total_mb == 16303
    assert st.models == ("gpt-oss-20b",)
    assert [(s.id, s.running) for s in st.services] == [
        ("lmstudio", True), ("hermes", False), ("openclaw", False)]
    assert st.service("lmstudio").model is None and st.service("hermes").ram_mb == 327


def test_missing_or_null_fields_do_not_break_the_reading() -> None:
    st = parse_status({"host": "PC", "gpu": None, "game_running": None,
                       "models_loaded": "only-one", "logged_on": "yes",
                       "services": {"id": "hermes", "name": "Hermes", "running": True}})
    assert st.gpu is None and st.game_running is None and st.uptime_s is None
    assert st.models == ("only-one",)                       # PowerShell's bare one-element array
    assert st.logged_on is False                            # only a real true counts
    assert [s.id for s in st.services] == ["hermes"] and st.services[0].ram_mb is None
    empty = parse_status({})
    assert empty.services == () and empty.models == () and empty.disk_free_gb is None


@pytest.mark.parametrize("result, outcome", [
    (subprocess.TimeoutExpired("ssh", 38), OFF),
    (_done([], 255, "", "ssh: connect to host x port 22: Connection timed out"), OFF),
    (_done([], 255, "", "ssh: connect to host x port 22: No route to host"), OFF),
    (_done([], 255, "", "pcuser@x: Permission denied (publickey)."), FAULT),
    (_done([], 255, "", "Host key verification failed."), FAULT),
    (_done([], 64, "", "netsentry-pc-agent: that action is not on the list"), FAULT),
    (_done([], 1, "", "netsentry-pc-agent: status failed"), FAULT),
    (_done([], 0, "<html>not json</html>", ""), FAULT),
    (_done([], 0, "", ""), FAULT),
    (_done([], 0, 'Welcome!\n{"host":"PC","services":[]}\n', ""), OK),
])
def test_off_is_told_apart_from_a_fault(result, outcome) -> None:
    def runner(argv, **kw):
        if isinstance(result, Exception):
            raise result
        return result
    reply = _agent(runner).run("status")
    assert reply.outcome == outcome
    if outcome == FAULT:
        assert "Permission" not in reply.detail and "netsentry-pc-agent" not in reply.detail


@pytest.mark.parametrize("result", [
    subprocess.TimeoutExpired("ssh", 28),
    _done([], 255, "", "Connection to x closed by remote host."),
    _done([], 255, '{"ok":true}\n', "client_loop: send disconnect: Broken pipe"),
    _done([], 0, '{"ok":true}', ""),
])
def test_a_dropped_connection_after_sleep_is_success(result) -> None:
    def runner(argv, **kw):
        if isinstance(result, Exception):
            raise result
        return result
    assert _agent(runner).run("sleep").ok
    assert _agent(runner).run("hibernate").ok


def test_sleep_turned_away_is_still_a_fault() -> None:
    reply = _agent(lambda argv, **kw: _done(argv, 255, "", "Permission denied (publickey)."))\
        .run("sleep")
    assert reply.outcome == FAULT


# ─── the AI provider ─────────────────────────────────────────────

class _FakeHttp:
    def __init__(self, models=("gpt-oss-20b",), answer="Hello.", fail=None) -> None:
        self.models, self.answer, self.fail = models, answer, fail
        self.requests: list = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        if self.fail:
            raise self.fail
        if req.full_url.endswith("/models"):
            body = {"object": "list", "data": [{"id": m} for m in self.models]}
        else:
            body = {"choices": [{"message": {"role": "assistant", "content": self.answer}}]}
        return io.BytesIO(json.dumps(body).encode())


def test_openai_client_probes_models_and_chats() -> None:
    http = _FakeHttp()
    ai = OpenAICompatibleClient("http://127.0.0.1:11234/v1", "gpt-oss-20b",
                                api_key="test-key", opener=http)
    assert ai.is_available() and ai.models() == ["gpt-oss-20b"]
    assert ai.complete("Hi", system="Be brief.") == "Hello."
    req = http.requests[-1]
    assert req.full_url == "http://127.0.0.1:11234/v1/chat/completions"
    body = json.loads(req.data)
    assert body["model"] == "gpt-oss-20b" and body["stream"] is False
    assert body["messages"] == [{"role": "system", "content": "Be brief."},
                                {"role": "user", "content": "Hi"}]
    assert req.get_header("Authorization") == "Bearer test-key"


def test_openai_client_failures_are_plain_and_never_carry_the_key() -> None:
    down = OpenAICompatibleClient("http://127.0.0.1:11234/v1",
                                  opener=_FakeHttp(fail=urllib.error.URLError("refused")))
    assert down.is_available() is False
    refused = urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b""))
    ai = OpenAICompatibleClient("http://127.0.0.1:1234/v1", api_key="test-key",
                                opener=_FakeHttp(fail=refused))
    with pytest.raises(RuntimeError) as e:
        ai.complete("Hi")
    assert "401" in str(e.value) and "test-key" not in str(e.value)
    with pytest.raises(RuntimeError, match="empty"):
        OpenAICompatibleClient(opener=_FakeHttp(answer="  ")).complete("Hi")


def test_a_closed_tunnel_makes_the_ai_unavailable_without_a_request() -> None:
    http = _FakeHttp()
    ai = OpenAICompatibleClient("http://127.0.0.1:11234/v1", opener=http)
    ai.attach_tunnel(lambda: False)
    assert ai.is_available() is False and http.requests == []
    with pytest.raises(RuntimeError, match="not reachable"):
        ai.complete("Hi")


def test_build_ai_knows_the_openai_provider() -> None:
    ai = build_ai({"provider": "openai", "config": {"base_url": "http://127.0.0.1:11234/v1",
                                                     "model": "m"}})
    assert isinstance(ai, OpenAICompatibleClient) and ai.endpoint() == ("127.0.0.1", 11234)
    assert isinstance(build_ai({"provider": "lmstudio", "config": {"base_url": "file:///x"}}),
                      DisabledAI)


# ─── the tunnel ──────────────────────────────────────────────────

class _FakeProc:
    def __init__(self, exits: bool = False) -> None:
        self.code = 255 if exits else None
        self.terminated = False

    def poll(self):
        return self.code

    def terminate(self) -> None:
        self.terminated = True
        self.code = -15

    def wait(self, timeout=None):
        return self.code

    def kill(self) -> None:
        self.code = -9


class _FakeSsh:
    """Spawns pretend ssh processes; a live one 'listens' on the local port."""

    def __init__(self, pc_on: bool = True) -> None:
        self.pc_on = pc_on
        self.procs: list[_FakeProc] = []

    def spawn(self, argv, **kw) -> _FakeProc:
        assert "shell" not in kw
        self.procs.append(_FakeProc(exits=not self.pc_on))
        return self.procs[-1]

    def probe(self, port: int) -> bool:
        return any(p.poll() is None for p in self.procs)


def _keeper(ssh: _FakeSsh, clock: _Clock) -> TunnelKeeper:
    return TunnelKeeper(host="192.0.2.40", user="pcuser", ssh_key="/keys/pc", local_port=11234,
                        spawn=ssh.spawn, probe=ssh.probe, clock=clock, sleep=clock.sleep)


def test_tunnel_is_started_once_reused_and_bound_to_loopback() -> None:
    ssh, clock = _FakeSsh(), _Clock()
    keeper = _keeper(ssh, clock)
    assert keeper.ensure() and keeper.ensure() and keeper.ensure()
    assert len(ssh.procs) == 1
    argv = keeper.argv
    assert argv[argv.index("-L") + 1] == "127.0.0.1:11234:127.0.0.1:1234"
    assert "-N" in argv and "BatchMode=yes" in argv and "ExitOnForwardFailure=yes" in argv
    keeper.stop()
    assert ssh.procs[0].terminated and not keeper.alive()


def test_tunnel_backs_off_while_the_pc_is_off() -> None:
    ssh, clock = _FakeSsh(pc_on=False), _Clock()
    keeper = _keeper(ssh, clock)
    assert keeper.ensure() is False and len(ssh.procs) == 1
    for _ in range(5):
        assert keeper.ensure() is False                       # no new ssh meanwhile
    assert len(ssh.procs) == 1
    clock.t += FIRST_BACKOFF_S
    assert keeper.ensure() is False and len(ssh.procs) == 2
    clock.t += FIRST_BACKOFF_S                                  # backoff doubled: not yet
    assert keeper.ensure() is False and len(ssh.procs) == 2
    ssh.pc_on = True
    clock.t += FIRST_BACKOFF_S
    assert keeper.ensure() is True and len(ssh.procs) == 3


def test_a_dead_tunnel_is_replaced_when_next_asked() -> None:
    ssh, clock = _FakeSsh(), _Clock()
    keeper = _keeper(ssh, clock)
    assert keeper.ensure()
    ssh.procs[0].code = 255                                     # the PC went to sleep
    assert keeper.ensure() and len(ssh.procs) == 2


# ─── the plugin ──────────────────────────────────────────────────

def _plugin(tmp_path: Path, pc: _FakePc | None = None, ai=None, **config):
    pc = pc or _FakePc()
    cfg = {"host": "192.0.2.40", "user": "pcuser", "ssh_key": "/keys/pc",
           "mac": MAC, "wake_to": "192.0.2.1:9", "wake_and_start": ["hermes"],
           "links": {"hermes": "https://t.me/example_agent_bot"}}
    cfg.update(config)
    ctx = PluginContext(name="workstation", config=cfg, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger("test.workstation"),
                        state_dir=str(tmp_path), ai=ai or DisabledAI())
    p = WorkstationPlugin(ctx)
    p.on_load()
    if p._agent is not None:
        p._agent._run = pc
    clock = _Clock()
    p._clock = p._now = clock
    p._sleep = clock.sleep
    p._spawn = lambda func, *args: func(*args)           # no threads in tests
    wakes: list[tuple[str, str]] = []

    def send_wake(mac: str, target: str) -> int:
        wakes.append((mac, target))
        pc.wake(3)
        return 3

    p._send_wake = send_wake
    p.test_clock, p.test_wakes = clock, wakes  # type: ignore[attr-defined]
    return p, pc


def _last(p) -> tuple[str, list[dict]]:
    call = p.notifier.edit_message.call_args or p.notifier.send_to.call_args
    return call.args[2] if p.notifier.edit_message.call_args else call.args[1], \
        [b for row in (call.kwargs.get("buttons") or []) for b in row]


def _press(p, data: str) -> tuple[str, list[dict]]:
    p.notifier.edit_message.reset_mock()
    p.on_callback(data, CHAT, 7, "cb")
    return _last(p)


def _edits(p) -> list[str]:
    return [c.args[2] for c in p.notifier.edit_message.call_args_list]


def _labels(buttons) -> list[str]:
    return [b["text"] for b in buttons]


def test_screen_of_a_pc_that_is_on(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path)
    p.on_command("/pc", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    rows = p.notifier.send_to.call_args.kwargs["buttons"]
    assert text.startswith("🖥 Gaming PC — ✅ on\n" + ui.RULE)
    assert "🎮 GPU — 41 °C · 0% load · VRAM 13.9 GB / 15.9 GB · 41 W" in text
    assert "💽 Disk C — 760 GB free of 1862 GB" in text and "👤 Someone is logged in" in text
    assert "🕹 No game running" in text and "🤖 Model loaded — gpt-oss-20b" in text
    assert "🟢 LM Studio — running · 14.5 GB RAM" in text
    assert "⚪ Hermes — stopped · gpt-oss-20b" in text
    labels = _labels(b for row in rows for b in row)
    for label in ("⏹ Stop LM Studio", "▶ Start Hermes", "▶ Start OpenClaw", "🧹 Free VRAM",
                  "😴 Sleep", "⏻ Shut down", "🔁 Restart", "🔄 Refresh"):
        assert label in labels
    assert rows[-1] == ui.nav_row()
    assert all(len(b["callback_data"].encode()) <= 64 for row in rows for b in row
               if "callback_data" in b)


def test_screen_of_a_pc_that_is_off_offers_wake_and_one_tap_start(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path, _FakePc(on=False))
    p.on_command("/pc", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    labels = _labels(b for row in p.notifier.send_to.call_args.kwargs["buttons"] for b in row)
    assert text.startswith("🖥 Gaming PC — 😴 off or asleep")
    assert "⚡ Wake" in labels and "🤖 Start Hermes" in labels
    assert "🤖 Start OpenClaw" not in labels and "😴 Sleep" not in labels


def test_screen_of_a_pc_that_refuses_the_key(tmp_path: Path) -> None:
    pc = _FakePc()
    pc.refuse_key = True
    p, _ = _plugin(tmp_path, pc)
    p.on_command("/pc", "", CHAT)
    text = p.notifier.send_to.call_args.args[1]
    assert text.startswith("🖥 Gaming PC — ⚠️ not answering as expected")
    assert "refused NetSentry's key" in text and "Permission denied" not in text


def test_without_config_the_plugin_does_nothing(tmp_path: Path) -> None:
    ctx = PluginContext(name="workstation", config={}, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger("t"), state_dir=str(tmp_path),
                        ai=DisabledAI())
    p = WorkstationPlugin(ctx)
    p.on_load()
    assert p.scheduled_tasks() == [] and p.health() == [] and p.api_status() is None
    p.on_command("/pc", "", CHAT)
    assert "— not set up" in p.notifier.send_to.call_args.args[1]
    p.on_callback("workstation:do:shutdown", CHAT, 7, "cb")    # an old button: nothing happens
    assert "— not set up" in p.notifier.edit_message.call_args.args[2]


def test_a_broken_config_is_a_health_problem(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path, host="-oProxyCommand=evil")
    assert p._agent is None
    (check,) = p.health()
    assert not check.ok and "not usable" in check.detail


def test_start_and_stop_are_one_tap(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    text, _ = _press(p, "workstation:start:hermes")
    assert "start hermes" in pc.actions and pc.running["hermes"]
    assert text.startswith("✅ Hermes is running.\n\n🖥 Gaming PC — ✅ on")
    assert _edits(p)[0] == "⏳ Starting Hermes on Gaming PC…"
    text, buttons = _press(p, "workstation:stop:hermes")
    assert text.startswith("⏹ Stopped Hermes.") and not pc.running["hermes"]
    assert "▶ Start Hermes" in _labels(buttons)


def test_a_start_refused_because_nobody_is_logged_in_says_so(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(logged_on=False))
    text, _ = _press(p, "workstation:start:hermes")
    assert text.startswith("⚠️ Hermes was NOT started — nobody is logged in on the PC.")
    pc.logged_on, pc.start_fails = True, True
    text, _ = _press(p, "workstation:start:openclaw")
    assert text.startswith("❌ OpenClaw was NOT started")


def test_a_crafted_service_button_never_reaches_the_pc(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, services=["hermes"])
    p.on_callback("workstation:start:notepad", CHAT, 7, "cb")
    p.on_callback("workstation:start:openclaw", CHAT, 7, "cb")
    p.on_callback("workstation:go:openclaw", CHAT, 7, "cb")     # not wake_and_start
    assert pc.actions == []


def test_free_vram(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    text, _ = _press(p, "workstation:vram")
    assert "free-vram" in pc.actions
    assert text.startswith("🧹 Freed the graphics memory. VRAM is now 1.2 GB / 15.9 GB.")


def test_a_pc_without_its_launcher_says_what_it_cannot_do(tmp_path: Path) -> None:
    pc = _FakePc()

    def no_launcher(argv, **kw):
        action = argv[-1]
        if action == "status":
            return pc(argv, **kw)
        pc.actions.append(action)
        return _done(argv, 0, json.dumps({"ok": False, "id": "hermes", "running": False,
                                          "reported": False,
                                          "reason": "not available on this PC"}))

    p, _ = _plugin(tmp_path, pc)
    p._agent._run = no_launcher
    text, _ = _press(p, "workstation:vram")
    assert text.startswith("❌ Nothing was freed — the PC can't do that")
    text, _ = _press(p, "workstation:start:hermes")
    assert text.startswith("❌ Hermes was NOT started — the PC can't start services")
    text, _ = _press(p, "workstation:stop:lmstudio")
    assert text.startswith("❌ LM Studio was NOT stopped — the PC can't stop services")


def test_sleep_takes_two_taps_and_is_confirmed_by_silence(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    text, buttons = _press(p, "workstation:ask:sleep")
    assert text.startswith("⚠️ Put Gaming PC to sleep?") and "⚡ Wake brings it back" in text
    assert _labels(buttons) == ["😴 Yes, sleep", "✖ Cancel"] and pc.actions == []
    text, buttons = _press(p, "workstation:do:sleep")
    assert pc.actions == ["sleep", "status"]
    assert text == "😴 Gaming PC is asleep — it no longer answers."
    assert "⚡ Wake" in _labels(buttons)


def test_a_pc_that_will_not_sleep_is_reported(tmp_path: Path) -> None:
    pc = _FakePc()
    pc.sleeps = False
    p, _ = _plugin(tmp_path, pc)
    text, _ = _press(p, "workstation:do:sleep")
    assert pc.actions.count("status") == 3
    assert "still answers" in text


def test_shutdown_can_be_cancelled_during_its_15_seconds(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    text, buttons = _press(p, "workstation:ask:shutdown")
    assert "switches off in 15 s" in text and _labels(buttons) == ["⏻ Yes, shut down", "✖ Cancel"]
    no = next(b["callback_data"] for b in buttons if b["text"] == "✖ Cancel")
    text, _ = _press(p, no)
    assert text.startswith(ui.NOTHING_CHANGED) and pc.actions == ["status"]

    text, buttons = _press(p, "workstation:do:shutdown")
    assert text == "⏳ Gaming PC shuts down in 15 s." and pc.actions[-1] == "shutdown"
    abort = next(b["callback_data"] for b in buttons if b["text"] == "✖ Cancel")
    text, _ = _press(p, abort)
    assert pc.actions[-1] == "cancel" and text == "✖ Cancelled — Gaming PC stays on."


def test_restart_needs_the_second_tap_too(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    text, _ = _press(p, "workstation:ask:restart")
    assert text.startswith("⚠️ Restart Gaming PC?") and pc.actions == []
    text, _ = _press(p, "workstation:do:restart")
    assert text == "⏳ Gaming PC restarts in 15 s." and pc.actions == ["restart"]


def test_power_button_on_a_pc_that_is_already_off_sends_nothing(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(on=False))
    text, _ = _press(p, "workstation:do:shutdown")
    assert text.startswith("✖ Gaming PC did not answer")


# ─── one tap from a cold PC to a running agent ──────────────────

def test_cold_pc_is_woken_and_the_agent_started(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(on=False))
    text, buttons = _press(p, "workstation:go:hermes")
    assert p.test_wakes == [(MAC, "192.0.2.1:9")]
    assert any(t.startswith("⏳ Gaming PC — waking…") for t in _edits(p))
    assert "start hermes" in pc.actions and pc.running["hermes"]
    assert text.startswith("✅ Gaming PC is awake — it took 40 s.\n✅ Hermes is running.")
    assert {"text": "💬 Open Hermes", "url": "https://t.me/example_agent_bot"} in buttons
    assert (tmp_path / "watch.json").exists()                 # remembered: our own wake


def test_a_pc_that_never_wakes_starts_nothing(tmp_path: Path) -> None:
    pc = _FakePc(on=False)
    p, _ = _plugin(tmp_path, pc)
    p._send_wake = lambda mac, target: 3                      # the packet goes nowhere
    text, buttons = _press(p, "workstation:go:hermes")
    assert text.startswith("❌ Gaming PC — did not wake")
    assert "No answer within 4 min of the wake signal, so Hermes was NOT started." in text
    assert not any(a.startswith("start") for a in pc.actions)
    assert "🔁 Try again" in _labels(buttons)
    assert p.test_clock.t - 1_800_000_000.0 >= 240
    waits = [t for t in _edits(p) if "waking" in t]
    assert len(waits) == len(set(waits)) <= 5                  # edited only when it changes


def test_a_pc_that_wakes_to_the_login_screen_stops_there(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(on=False, logged_on=False),
                    remote_keyboard_url="https://keyboard.example/")
    text, buttons = _press(p, "workstation:go:hermes")
    assert text.startswith("⚠️ Gaming PC — on, nobody logged in")
    assert "Log in on the PC, then tap Start Hermes again." in text
    assert not any(a.startswith("start") for a in pc.actions)
    assert {"text": "⌨️ Open remote keyboard", "url": "https://keyboard.example/"} in buttons
    assert "🤖 Start Hermes" in _labels(buttons)


def test_no_keyboard_button_without_its_url(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path, _FakePc(on=False, logged_on=False))
    _, buttons = _press(p, "workstation:go:hermes")
    assert "⌨️ Open remote keyboard" not in _labels(buttons)


def test_a_start_that_fails_after_waking_says_what_did_not_happen(tmp_path: Path) -> None:
    pc = _FakePc(on=False)
    pc.start_fails = True
    p, _ = _plugin(tmp_path, pc)
    text, buttons = _press(p, "workstation:go:hermes")
    assert "❌ Hermes was NOT started" in text and "— ✅ on" in text
    assert "💬 Open Hermes" not in _labels(buttons)


def test_a_pc_that_is_already_on_is_not_woken(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    text, _ = _press(p, "workstation:go:hermes")
    assert p.test_wakes == [] and text.startswith("✅ Hermes is running.")
    text, _ = _press(p, "workstation:go:hermes")
    assert text.startswith("✅ Hermes is already running.")
    text, _ = _press(p, "workstation:wake")
    assert text.startswith("✅ Gaming PC is already on.") and p.test_wakes == []


def test_plain_wake(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(on=False))
    text, _ = _press(p, "workstation:wake")
    assert text.startswith("✅ Gaming PC is awake") and "— ✅ on" in text
    assert not any(a.startswith("start") for a in pc.actions)


def test_wake_without_wake_on_lan_config(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path, _FakePc(on=False), mac="", wake_to="")
    text, _ = _press(p, "workstation:wake")
    assert "can't be woken — Wake-on-LAN is not set up" in text and p.test_wakes == []


def test_one_wake_at_a_time(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(on=False))
    p._busy = True
    p.on_callback("workstation:go:hermes", CHAT, 7, "cb")
    p.notifier.answer_callback.assert_called_with("cb", "Already waking the PC")
    assert pc.actions == [] and p.test_wakes == []


# ─── watching ────────────────────────────────────────────────────

def _notes(p) -> list[tuple[str, str]]:
    return [(c.args[0], c.args[1]) for c in p.notifier.notify.call_args_list]


def test_a_pc_that_comes_on_by_itself_is_mentioned_once(tmp_path: Path) -> None:
    pc = _FakePc(on=False)
    p, _ = _plugin(tmp_path, pc)
    p.watch()                                  # first look: just remembered
    pc.on = True
    p.watch()
    p.watch()
    assert len(_notes(p)) == 1
    kind, text = _notes(p)[0]
    assert kind == notify.INFO and text.startswith("ℹ️ Gaming PC — came on")
    buttons = p.notifier.notify.call_args.kwargs["buttons"]
    assert buttons[0][0]["callback_data"] == "workstation:new"


def test_a_pc_that_netsentry_woke_is_not_news(tmp_path: Path) -> None:
    pc = _FakePc(on=False)
    p, _ = _plugin(tmp_path, pc)
    p.watch()
    _press(p, "workstation:wake")
    p.watch()
    assert _notes(p) == []


def test_first_look_after_start_says_nothing(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path)
    p.watch()
    assert _notes(p) == []


def test_a_hot_gpu_needs_two_readings_and_recovers_once(tmp_path: Path) -> None:
    pc = _FakePc(temp=90)
    p, _ = _plugin(tmp_path, pc)
    p.watch()
    assert _notes(p) == []
    p.watch()
    p.watch()
    assert _notes(p) == [(notify.ATTENTION, "⚠️ Gaming PC GPU — hot, 90 °C\nOver 85 °C on two "
                          "checks in a row at 0% load. Worth checking the fans and airflow.")]
    pc.temp = 60
    p.watch()
    p.watch()
    assert _notes(p)[1:] == [(notify.RECOVERY, "✅ Gaming PC GPU — back to 60 °C")]


def test_one_hot_reading_between_cool_ones_is_ignored(tmp_path: Path) -> None:
    pc = _FakePc(temp=90)
    p, _ = _plugin(tmp_path, pc, gpu_temp_alert_c=80)
    p.watch()
    pc.temp = 70
    p.watch()
    pc.temp = 90
    p.watch()
    assert _notes(p) == []


def test_low_disk_is_said_once(tmp_path: Path) -> None:
    pc = _FakePc(disk=12)
    p, _ = _plugin(tmp_path, pc)
    p.watch()
    p.watch()
    assert [k for k, _ in _notes(p)] == [notify.ATTENTION]
    assert _notes(p)[0][1].startswith("⚠️ Gaming PC disk C — 12 GB free\nUnder 20 GB.")
    pc.disk = 50
    p.watch()
    assert _notes(p)[-1] == (notify.RECOVERY, "✅ Gaming PC disk C — 50 GB free again")


def test_an_idle_pc_is_mentioned_once_with_a_sleep_button(tmp_path: Path) -> None:
    pc = _FakePc(models=())
    p, _ = _plugin(tmp_path, pc, idle_hours=1)
    for _ in range(13):                        # every 5 min for an hour
        p.watch()
        p.test_clock.t += 300
    assert len(_notes(p)) == 1
    kind, text = _notes(p)[0]
    assert kind == notify.INFO and text.startswith("ℹ️ Gaming PC — idle for 1 h")
    assert "stays on unless you tap Sleep" in text
    assert p.notifier.notify.call_args.kwargs["buttons"] == [
        [ui.button("😴 Sleep", "workstation:ask:sleep")]]
    assert "sleep" not in pc.actions                            # never by itself


def test_activity_resets_the_idle_clock(tmp_path: Path) -> None:
    pc = _FakePc(models=())
    p, _ = _plugin(tmp_path, pc, idle_hours=1)
    for i in range(13):
        pc.game = i == 6                        # a game at half-time
        p.watch()
        p.test_clock.t += 300
    assert _notes(p) == []


def test_watching_an_off_pc_is_silent(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path, _FakePc(on=False), idle_hours=1)
    for _ in range(20):
        p.watch()
        p.test_clock.t += 300
    assert _notes(p) == [] and set(pc.actions) == {"status"}
    assert p.scheduled_tasks()[0].cron == "*/5 * * * *"


# ─── health ──────────────────────────────────────────────────────

def test_off_is_healthy_and_a_refused_key_is_not(tmp_path: Path) -> None:
    pc = _FakePc(on=False)
    p, _ = _plugin(tmp_path, pc)
    assert p.health()[0].ok and "not checked yet" in p.health()[0].detail
    p.watch()
    (check,) = p.health()
    assert check.ok and "off or asleep" in check.detail and check.name == "Gaming PC agent"
    pc.on, pc.refuse_key = True, True
    p.watch()
    (check,) = p.health()
    assert not check.ok and "refused NetSentry's key" in check.detail
    assert _notes(p) == []                       # the watchdog alerts, not this plugin
    pc.refuse_key = False
    p.watch()
    assert p.health()[0].ok


# ─── AI tunnel wiring ────────────────────────────────────────────

def test_the_ai_reaches_lm_studio_through_the_plugins_tunnel(tmp_path: Path) -> None:
    ai = OpenAICompatibleClient("http://127.0.0.1:11234/v1", opener=_FakeHttp())
    p, _ = _plugin(tmp_path, ai=ai, ai_tunnel_port=11234)
    assert p._tunnel is not None and ai._ensure == p._tunnel.ensure
    assert p._tunnel.argv[-1] == "pcuser@192.0.2.40"
    stopped = []
    p._tunnel.stop = lambda: stopped.append(True)
    p.on_unload()
    assert stopped == [True]


def test_no_tunnel_when_the_ai_points_elsewhere(tmp_path: Path) -> None:
    ai = OpenAICompatibleClient("http://192.0.2.99:1234/v1", opener=_FakeHttp())
    p, _ = _plugin(tmp_path, ai=ai, ai_tunnel_port=11234)
    assert p._tunnel is None and ai._ensure is None
    p2, _ = _plugin(tmp_path / "b", ai=DisabledAI(), ai_tunnel_port=11234)
    assert p2._tunnel is None


# ─── the dashboard picture ───────────────────────────────────────

def test_dashboard_picture_never_waits_and_is_cached(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    started: list = []
    p._spawn = lambda func, *args: started.append(func)          # hold the refresh
    first = p.api_status()
    assert first == {"name": "Gaming PC", "state": "unknown", "checked_ts": None}
    assert len(started) == 1 and pc.actions == []
    p.api_status()
    assert len(started) == 1                                     # one refresh in flight
    started[0]()                                                 # it finishes
    data = p.api_status()
    assert data["state"] == "on" and data["gpu"]["temp_c"] == 41
    assert data["services"][0] == {"name": "LM Studio", "running": True, "model": None,
                                   "ram_mb": 14828}
    assert pc.actions == ["status"] and len(started) == 1        # fresh: no new ssh
    p.test_clock.t += 61
    p.api_status()
    assert len(started) == 2


def test_dashboard_picture_of_an_off_or_broken_pc(tmp_path: Path) -> None:
    pc = _FakePc(on=False)
    p, _ = _plugin(tmp_path, pc)
    p.watch()
    assert p.api_status()["state"] == "off" and "gpu" not in p.api_status()
    pc.on, pc.refuse_key = True, True
    p.watch()
    data = p.api_status()
    assert data["state"] == "fault" and "refused" in data["problem"]



# ─── /aicontrol: AI Mission Control's summary (read-only) ────────

def test_summary_is_parsed_into_small_records() -> None:
    s = parse_summary(MC_SUMMARY)
    assert (s.version, s.time, s.game) == ("0.5.0", "2026-11-24T11:04:55", "")
    assert (s.vram_used_mib, s.vram_total_mib, s.ram_free_mb, s.ram_total_mb) == \
        (1585, 16303, 13336, 31895)
    assert s.ram_free_percent == 41.8 and s.models == ()
    assert [v.id for v in s.services] == ["lmstudio", "hermes", "openclaw", "opencode",
                                          "netsentry"]
    hermes = s.services[1]
    assert hermes.running and not hermes.remote and hermes.port is None
    assert hermes.model == "huihui-qwen3.5-35b-a3b-abliterated"
    assert s.services[0].model == "" and s.services[4].remote
    page = s.pages[0]
    assert (page.name, page.label, page.port, page.available, page.tailscale_shared) == \
        ("Hermes", "Dashboard", 9119, False, False)
    assert page.tailscale_url == "https://pc.example.ts.net:9119/" and not page.opens
    assert s.last_action is not None and s.last_action.state == "ok"
    assert s.last_action.summary == "Hermes is running" and s.usable


@pytest.mark.parametrize("data", [None, [], "garbage", 42, {}, {"ok": False},
                                  {"Version": None, "Services": "x", "Pages": 7}])
def test_an_odd_summary_never_raises_and_is_not_usable(data) -> None:
    s = parse_summary(data)
    assert not s.usable and s.services == () and s.pages == () and s.last_action is None
    assert s.vram_used_mib is None and s.ram_free_percent is None


def test_odd_fields_become_empty_and_text_is_cleaned() -> None:
    s = parse_summary({
        "Version": 5, "Time": ["x"], "Game": "Some\x1b[31m Game‮\n",
        "VramUsedMiB": True, "VramTotalMiB": float("nan"), "RamFreePercent": "41",
        "RamFreeMB": float("inf"), "RamTotalMB": 31895.7,
        "Models": {"Name": "qwen" + "x" * 500, "Context": 32768, "Processor": "100% GPU"},
        "Services": [{"Id": "hermes", "Running": "yes", "Port": "1234", "Model": {"a": 1}},
                     {"Name": "no id"}, "junk", None],
        "Pages": [{"Name": "Hermes", "Available": 1, "TailscaleShared": True,
                   "TailscaleUrl": "javascript:alert(1)"},
                  {"Label": "no name"}],
        "LastAction": {"Summary": "Start OpenClaw", "State": "BOOM", "Reason": None},
        "SomethingNew": {"deep": [1, 2]},
    })
    assert s.version == "5" and s.time == "" and s.game == "Some [31m Game"
    assert s.vram_used_mib is None and s.vram_total_mib is None
    assert s.ram_free_percent is None and s.ram_free_mb is None and s.ram_total_mb == 31895
    assert len(s.models) == 1 and len(s.models[0].name) == 80
    assert s.models[0].context == 32768 and s.models[0].processor == "100% GPU"
    assert len(s.services) == 1
    svc = s.services[0]
    assert (svc.name, svc.running, svc.port, svc.model) == ("hermes", False, None, "")
    assert len(s.pages) == 1 and not s.pages[0].available and s.pages[0].tailscale_url == ""
    assert s.last_action is not None and s.last_action.state == "" and \
        s.last_action.reason == ""


def test_summary_text_of_the_sample() -> None:
    assert summary_text(parse_summary(MC_SUMMARY)) == "\n".join([
        "🤖 AI Mission Control 0.5.0 — 11:04",
        ui.RULE,
        "VRAM 1.5 / 15.9 GB · RAM 18.1 / 31.1 GB (42% free)",
        "Model loaded: none",
        "Game: none",
        "",
        "Services",
        "🟢 LM Studio",
        "🟢 Hermes — huihui-qwen3.5-35b-a3b-abliterated",
        "⚪ OpenClaw — gpt-oss-20b",
        "⚪ OpenCode — gpt-oss-20b",
        "",
        "Pages",
        "⚪ Hermes Dashboard — closed · Tailscale off · link won't open now",
        "   https://pc.example.ts.net:9119/",
        "⚪ OpenClaw Web UI — closed · Tailscale off · link won't open now",
        "   https://pc.example.ts.net:18789/",
        "⚪ OpenCode Web UI — closed · Tailscale off · link won't open now",
        "   https://pc.example.ts.net:4096/",
        "",
        "Last action: ✅ Hermes is running (10:52)",
    ])


def test_summary_text_marks_which_links_open_and_lists_models() -> None:
    data = json.loads(json.dumps(MC_SUMMARY))
    data["Pages"][0].update(Available=True, TailscaleShared=True)
    data["Pages"][1].update(Available=True)
    data["Pages"][2].update(TailscaleShared=True)
    data["Models"] = [{"Name": "gpt-oss-20b", "Context": 32768, "Processor": "100% GPU"}]
    data["Game"] = "Example Game"
    data["LastAction"] = {"Summary": "Start OpenClaw failed", "State": "failed",
                          "Reason": "port 18789 is in use", "Ended": "2026-11-24T10:58:00"}
    text = summary_text(parse_summary(data))
    assert "🟢 Hermes Dashboard — open · Tailscale on\n   https://pc.example.ts.net:9119/" in text
    assert "🟡 OpenClaw Web UI — open · Tailscale off · link won't open now" in text
    assert "⚪ OpenCode Web UI — closed · Tailscale on · link won't open now" in text
    assert "Model loaded: gpt-oss-20b — 32768 context · 100% GPU" in text
    assert "Game: Example Game" in text and "NetSentry" not in text
    assert "Last action: ❌ Start OpenClaw failed — port 18789 is in use (10:58)" in text
    data["LastAction"] = {"Summary": "Starting Hermes", "State": "running"}
    assert summary_text(parse_summary(data)).endswith("Last action: ⏳ Starting Hermes")


def _sent(p) -> list[str]:
    return [c.args[1] for c in p.notifier.send_to.call_args_list]


def test_aicontrol_asks_first_then_answers_read_only(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    seen: dict = {}

    def runner(argv, **kw):
        seen.update(kw)
        return pc(argv, **kw)

    p._agent._run = runner
    p.on_command("/aicontrol", "", CHAT)
    first, answer = _sent(p)
    assert first == "⏳ Asking the PC…" and pc.actions == ["summary"]
    assert seen["timeout"] == 28                       # 20 s + the connect timeout
    assert answer.startswith("🤖 AI Mission Control 0.5.0 — 11:04")
    assert "https://pc.example.ts.net:18789/" in answer and "NetSentry" not in answer
    rows = p.notifier.send_to.call_args.kwargs["buttons"]
    buttons = [b for row in rows for b in row]
    assert _labels(buttons) == ["🔗 Share Hermes Dashboard on Tailscale",
                                "🔗 Share OpenClaw Web UI on Tailscale",
                                "🔗 Share OpenCode Web UI on Tailscale",
                                "🔄 Refresh", "⬅ PC", "🏠 Menu"]
    assert [b["callback_data"] for b in buttons] == [
        "workstation:sh:hermes-dashboard:1", "workstation:sh:openclaw-web-ui:1",
        "workstation:sh:opencode-web-ui:1", "workstation:ai", "workstation:v", "menu:h"]
    assert not any(w in label for label in _labels(buttons)    # share switches only
                   for w in ("Start", "Sleep", "Shut", "Restart", "Wake"))


def test_aicontrol_from_the_pc_screen_edits_that_message(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    p.on_command("/pc", "", CHAT)
    labels = _labels(b for row in p.notifier.send_to.call_args.kwargs["buttons"] for b in row)
    assert "🤖 AI Mission Control" in labels
    text, _ = _press(p, "workstation:ai")
    assert _edits(p)[0] == "⏳ Asking the PC…"
    assert text.startswith("🤖 AI Mission Control 0.5.0") and pc.actions[-1] == "summary"
    _press(p, "workstation:ai")                            # Refresh asks again
    assert pc.actions.count("summary") == 2
    text, _ = _press(p, "workstation:v")                   # ⬅ PC
    assert text.startswith("🖥 Gaming PC — ✅ on")


def test_aicontrol_with_the_pc_off_says_so_plainly(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path, _FakePc(on=False))
    p.on_command("/aicontrol", "", CHAT)
    text = _sent(p)[-1]
    assert "💤 The PC isn't answering — it may be asleep or off." in text
    labels = _labels(b for row in p.notifier.send_to.call_args.kwargs["buttons"] for b in row)
    assert labels == ["⚡ Wake", "🔄 Refresh", "⬅ PC", "🏠 Menu"]
    p2, _ = _plugin(tmp_path, _FakePc(on=False), mac="", wake_to="")
    p2.on_command("/aicontrol", "", CHAT)
    labels = _labels(b for row in p2.notifier.send_to.call_args.kwargs["buttons"] for b in row)
    assert "⚡ Wake" not in labels


@pytest.mark.parametrize("rc, out", [
    (64, ""),                                   # the PC's list has no `summary` yet
    (1, ""),                                    # AI Mission Control without the function
    (0, "Get-McSummary : not recognized\n"),    # garbage
    (0, '{"ok":false,"reason":"not available"}'),
    (0, "[1, 2]"),
])
def test_an_unusable_summary_says_too_old_and_shows_nothing_stale(tmp_path: Path, rc,
                                                                  out) -> None:
    p, pc = _plugin(tmp_path)
    p.on_command("/aicontrol", "", CHAT)                    # a good answer first
    pc.summary_rc, pc.summary_out = rc, out
    reply, summary = p._agent.summary()
    assert summary is None and reply.detail == SUMMARY_UNUSABLE
    p.on_command("/aicontrol", "", CHAT)
    text = _sent(p)[-1]
    assert "too old for this (needs 0.5.0 or newer)" in text
    assert "pc.example.ts.net" not in text and "LM Studio" not in text


def test_aicontrol_with_a_refused_key_is_a_connection_problem(tmp_path: Path) -> None:
    pc = _FakePc()
    pc.refuse_key = True
    p, _ = _plugin(tmp_path, pc)
    p.on_command("/aicontrol", "", CHAT)
    text = _sent(p)[-1]
    assert "refused NetSentry's key" in text and "too old" not in text
    assert "Permission denied" not in text


def test_aicontrol_never_leaves_asking_standing(tmp_path: Path) -> None:
    p, _ = _plugin(tmp_path)

    def broken():
        raise RuntimeError("boom")

    p._agent.summary = broken
    p.on_callback("workstation:ai", CHAT, 7, "cb")
    text = _edits(p)[-1]
    assert text.startswith("❌ That did not finish") and "boom" not in text


def test_aicontrol_is_registered_next_to_pc_and_not_set_up_is_said(tmp_path: Path) -> None:
    cmds = [c["command"] for c in WorkstationPlugin.COMMANDS]
    assert cmds[cmds.index("pc") + 1] == "aicontrol"
    ctx = PluginContext(name="workstation", config={}, router=Mock(), notifier=Mock(),
                        vault=Mock(), logger=logging.getLogger("t"), state_dir=str(tmp_path),
                        ai=DisabledAI())
    p = WorkstationPlugin(ctx)
    p.on_load()
    p.on_command("/aicontrol", "", CHAT)
    assert "— not set up" in p.notifier.send_to.call_args.args[1]


# ─── sharing a page over Tailscale ───────────────────────────────

def test_page_slug_matches_the_agents_rule() -> None:
    from netsentry.core.pc_agent import page_slug
    assert page_slug("hermes/Dashboard") == "hermes-dashboard"
    assert page_slug("openclaw/Web UI") == "openclaw-web-ui"
    assert page_slug("  ??  ") == ""


def test_share_switch_turns_a_page_on_then_off_and_shows_the_result(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    p.on_callback("workstation:sh:opencode-web-ui:1", CHAT, 7, "cb")
    assert pc.actions[-1] == "share opencode-web-ui on"
    text = p.notifier.edit_message.call_args.args[2]
    assert "OpenCode shared over Tailscale" in text and "https://pc.example.ts.net:4096/" in text
    labels = _labels(b for row in p.notifier.edit_message.call_args.kwargs["buttons"] for b in row)
    assert "🚫 Stop sharing OpenCode Web UI" in labels
    p.on_callback("workstation:sh:opencode-web-ui:0", CHAT, 7, "cb")
    assert pc.actions[-1] == "share opencode-web-ui off"
    assert "no longer shared" in p.notifier.edit_message.call_args.args[2]


def test_share_of_an_unknown_page_says_so_and_sends_nothing_odd(tmp_path: Path) -> None:
    p, pc = _plugin(tmp_path)
    p.on_callback("workstation:sh:no-such-page:1", CHAT, 7, "cb")
    assert pc.actions[-1] == "share no-such-page on"            # the PC decides, and refuses
    assert "Traceback" not in p.notifier.edit_message.call_args.args[2]
    before = list(pc.actions)
    p.on_callback("workstation:sh:Bad Page;rm:1", CHAT, 7, "cb")  # never leaves NetSentry
    assert pc.actions == before


def test_agent_accepts_only_well_formed_share_actions() -> None:
    pc = _FakePc()
    agent = _agent(pc)
    assert agent.run("share hermes-dashboard on").ok
    assert not agent.run("share hermes-dashboard maybe").ok
    assert not agent.run("share ../x on").ok
    assert pc.actions == ["share hermes-dashboard on"]
