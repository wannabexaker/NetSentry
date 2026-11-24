"""AI Mission Control from Telegram (`/aicontrol`, the ai_control plugin): the
`mc …` client calls and their checks, the summary and model-list parsers, and
the main / Models / Pages screens with their button flows."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core import ui
from netsentry.core.ai import DisabledAI
from netsentry.core.pc_agent import (
    FAULT,
    SUMMARY_UNUSABLE,
    PcAgent,
    page_slug,
    parse_models,
    parse_summary,
)
from netsentry.core.plugin import PluginContext
from netsentry.plugins.ai_control import AiControlPlugin, summary_text
from netsentry.plugins.menu import MenuPlugin
from netsentry.plugins.workstation import WorkstationPlugin

CHAT = 42
MAC = "AA:BB:CC:DD:EE:FF"
CHANGED = "ℹ️ The list changed — nothing was done. Pick again."
K20, K27, K35 = "gpt-oss-20b", "huihui-qwen3.5-27b-abliterated", "huihui-qwen3.5-35b-a3b-abliterated"

# AI Mission Control's `summary` answer (a real one, host replaced).
MC_SUMMARY = {
    "Version": "0.5.0", "Time": "2026-11-24T11:04:55", "Game": "",
    "VramUsedMiB": 1585, "VramTotalMiB": 16303, "RamFreePercent": 41.8, "RamFreeMB": 13336,
    "RamTotalMB": 31895, "Models": [],
    "Services": [
        {"Id": "lmstudio", "Name": "LM Studio", "Running": True, "Remote": False, "Port": 1234,
         "Model": None},
        {"Id": "hermes", "Name": "Hermes", "Running": True, "Remote": False, "Port": None,
         "Model": K35},
        {"Id": "openclaw", "Name": "OpenClaw", "Running": False, "Remote": False, "Port": 18789,
         "Model": K20},
        {"Id": "opencode", "Name": "OpenCode", "Running": False, "Remote": False, "Port": 4096,
         "Model": K20},
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


def _done(argv, rc: int, out: str = "", err: str = ""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class _FakeAmc:
    """The PC agent with AI Mission Control behind it, as pc-agent.ps1 answers."""

    def __init__(self, *, on: bool = True) -> None:
        self.on = on
        self.actions: list[str] = []
        self.timeouts: list[int] = []
        self.data = json.loads(json.dumps(MC_SUMMARY))
        self.catalog = [{"Key": K20, "SizeMB": 11549}, {"Key": K27, "SizeMB": 15774},
                        {"Key": K35, "SizeMB": 20774}]
        self.game = True
        self.fail = ""                       # the next action fails with this reason
        self.summary_rc, self.summary_out = 0, None
        self.refuse_key = False

    def __call__(self, argv, **kw):
        action = argv[-1]
        self.actions.append(action)
        self.timeouts.append(kw["timeout"])
        if not self.on:
            return _done(argv, 255, "", "ssh: connect to host 192.0.2.40 port 22: timed out")
        if self.refuse_key:
            return _done(argv, 255, "", "pcuser@192.0.2.40: Permission denied (publickey).")
        if action == "status":                # what /pc reads
            return _done(argv, 0, json.dumps({"host": "PC-EXAMPLE", "logged_on": True,
                                              "services": []}))
        if action == "summary":
            out = self.summary_out if self.summary_out is not None else json.dumps(self.data)
            return _done(argv, self.summary_rc, out)
        if action == "mc models":
            keys = [m["Key"] for m in self.catalog]
            return _done(argv, 0, json.dumps({
                "Models": self.catalog, "GameAutoFree": self.game,
                "Agents": {s["Id"]: keys for s in self._services() if s["Id"] != "lmstudio"}}))
        words = action.split(" ")
        if words[0] == "share":
            hit = [g for g in self.data["Pages"] if page_slug(g["Id"]) == words[1]]
            if not hit:
                return self._refuse(argv)
            hit[0]["TailscaleShared"] = words[2] == "on"
            return self._answer(argv, f"{hit[0]['Name']} "
                                + ("shared over Tailscale" if words[2] == "on"
                                   else "no longer shared over Tailscale"))
        if words[0] != "mc":
            raise AssertionError(f"unexpected action {action!r}")
        return self._mc(argv, words[1:])

    def _services(self) -> list[dict]:
        return [s for s in self.data["Services"] if not s["Remote"]]

    def _service(self, sid: str) -> dict | None:
        return next((s for s in self._services() if s["Id"] == sid), None)

    def _key(self, key: str) -> bool:
        return any(m["Key"] == key for m in self.catalog)

    def _refuse(self, argv):
        return _done(argv, 64, "", "netsentry-pc-agent: that action is not on the list")

    def _answer(self, argv, what: str):
        reason, self.fail = self.fail, ""
        self.data["LastAction"] = {"Summary": what + (" failed" if reason else ""),
                                   "State": "failed" if reason else "ok", "Reason": reason,
                                   "Ended": "2026-11-24T11:20:00"}
        return _done(argv, 0, json.dumps(self.data))

    def _mc(self, argv, words: list[str]):
        if words[0] == "svc":
            svc = self._service(words[1])
            if svc is None:
                return self._refuse(argv)
            if not self.fail:
                svc["Running"] = words[2] != "stop"
            return self._answer(argv, f"{words[2].capitalize()} {svc['Name']}")
        if words[0] == "all":
            if not self.fail:
                for s in self._services():
                    s["Running"] = words[1] == "start"
                if words[1] == "stop":
                    self.data["Models"] = []
            return self._answer(argv, f"{words[1].capitalize()} all")
        if words[0] == "load":
            if not self._key(words[1]):
                return self._refuse(argv)
            self.data["Models"] = [{"Name": words[1], "Context": 32768, "Processor": "100% GPU"}]
            return self._answer(argv, f"Load {words[1]}")
        if words[0] == "unload":
            self.data["Models"] = []
            return self._answer(argv, "Unload")
        if words[0] == "use":
            svc = self._service(words[1])
            if svc is None or not self._key(words[2]) or words[1] == "lmstudio":
                return self._refuse(argv)
            svc["Model"] = words[2]
            return self._answer(argv, f"Switch {svc['Name']} to {words[2]}")
        if words[0] == "game":
            self.game = words[1] == "on"
            return self._answer(argv, f"Game mode {words[1]}")
        return self._refuse(argv)


def _ctx(name: str, config: dict, notifier, tmp_path: Path) -> PluginContext:
    (tmp_path / name).mkdir(parents=True, exist_ok=True)
    return PluginContext(name=name, config=config, router=Mock(), notifier=notifier,
                         vault=Mock(), logger=logging.getLogger(f"test.{name}"),
                         state_dir=str(tmp_path / name), ai=DisabledAI())


def _setup(tmp_path: Path, amc: _FakeAmc | None = None, *, workstation: bool = True,
           **config):
    amc = amc or _FakeAmc()
    notifier = Mock()
    cfg = {"host": "192.0.2.40", "user": "pcuser", "ssh_key": "/keys/pc", "mac": MAC,
           "wake_to": "192.0.2.1:9"}
    cfg.update(config)
    plugins: list = []
    ws = None
    if workstation:
        ws = WorkstationPlugin(_ctx("workstation", cfg, notifier, tmp_path))
        ws.on_load()
        if ws._agent is not None:
            ws._agent._run = amc
        plugins.append(ws)
    p = AiControlPlugin(_ctx("ai_control", {}, notifier, tmp_path))
    p.on_load()
    p._spawn = lambda func, *args: func(*args)           # no threads in tests
    plugins.append(p)
    for x in plugins:
        x.ctx._all_plugins = plugins  # type: ignore[attr-defined]
    return p, ws, amc


def _flat(rows) -> list[dict]:
    return [b for row in (rows or []) for b in row]


def _labels(buttons) -> list[str]:
    return [b["text"] for b in buttons]


def _last(p) -> tuple[str, list[dict]]:
    if p.notifier.edit_message.call_args is None and p.notifier.send_to.call_args is None:
        return "", []
    if p.notifier.edit_message.call_args:
        call = p.notifier.edit_message.call_args
        return call.args[2], _flat(call.kwargs.get("buttons"))
    call = p.notifier.send_to.call_args
    return call.args[1], _flat(call.kwargs.get("buttons"))


def _press(p, data: str) -> tuple[str, list[dict]]:
    p.notifier.edit_message.reset_mock()
    p.notifier.answer_callback.reset_mock()
    p.on_callback(data, CHAT, 7, "cb")
    return _last(p)


def _edits(p) -> list[str]:
    return [c.args[2] for c in p.notifier.edit_message.call_args_list]


def _data(buttons, label: str) -> str:
    return next(b["callback_data"] for b in buttons if b["text"] == label)


def _mc_actions(amc: _FakeAmc) -> list[str]:
    return [a for a in amc.actions if a.startswith(("mc ", "share ")) and a != "mc models"]


def _open(p) -> tuple[str, list[dict]]:
    p.on_command("/aicontrol", "", CHAT)
    return _last(p)


# ─── the client ──────────────────────────────────────────────────

def _agent(runner) -> PcAgent:
    return PcAgent("192.0.2.40", "pcuser", "/keys/pc", runner=runner)


@pytest.mark.parametrize("call", [
    lambda a: a.mc_service("Bad Id", "start"), lambda a: a.mc_service("hermes", "kill"),
    lambda a: a.mc_service("hermes; reboot", "stop"), lambda a: a.mc_service("x" * 33, "start"),
    lambda a: a.mc_load("Model/../x"), lambda a: a.mc_load("a" * 81), lambda a: a.mc_load(""),
    lambda a: a.mc_use("lmstudio", K20), lambda a: a.mc_use("hermes", "bad key!"),
    lambda a: a.mc_use("Hermes", K20), lambda a: a.mc_load(f"{K20} && whoami"),
])
def test_a_bad_service_or_model_name_is_never_sent(call) -> None:
    amc = _FakeAmc()
    reply, summary = call(_agent(amc))
    assert reply.outcome == FAULT and summary is None and amc.actions == []


@pytest.mark.parametrize("action", ["mc svc hermes start; reboot", "mc load ../x", "mc all",
                                    "mc game maybe", "mc", "mc unload now", "mc svc hermes",
                                    "MC models", "mc use hermes", "mc models\n"])
def test_run_accepts_mc_actions_only_when_they_fully_match(action: str) -> None:
    amc = _FakeAmc()
    assert _agent(amc).run(action).outcome == FAULT and amc.actions == []


def test_mc_actions_answer_with_the_summary_and_wait_long_enough() -> None:
    amc = _FakeAmc()
    agent = _agent(amc)
    reply, summary = agent.mc_load(K20)
    assert reply.ok and summary.models[0].name == K20 and summary.last_action.state == "ok"
    reply, models = agent.mc_models()
    assert reply.ok and [m.key for m in models.models] == [K20, K27, K35]
    assert amc.actions == [f"mc load {K20}", "mc models"]
    assert amc.timeouts == [158, 28]          # a model load may take 90 s; the list is quick
    for call, sent in [(lambda: agent.mc_service("hermes", "restart"), "mc svc hermes restart"),
                       (lambda: agent.mc_all(False), "mc all stop"),
                       (agent.mc_unload, "mc unload"),
                       (lambda: agent.mc_use("hermes", K27), f"mc use hermes {K27}"),
                       (lambda: agent.mc_game(False), "mc game off")]:
        assert call()[0].ok and amc.actions[-1] == sent


def test_a_refusal_by_the_pc_stays_a_refusal_not_too_old() -> None:
    reply, summary = _agent(_FakeAmc()).mc_service("nosuch", "start")
    assert reply.outcome == FAULT and summary is None and reply.detail != SUMMARY_UNUSABLE
    assert "refused" in reply.detail


def test_model_list_is_parsed_tolerantly() -> None:
    m = parse_models({
        "Models": {"Key": K20, "SizeMB": 11549.6},            # PowerShell's bare one-element array
        "Agents": {"hermes": K20, "lmstudio": [K20], "Bad Id": [K20],
                   "openclaw": [K20, "Bad Key", K20, 7, None]},
        "GameAutoFree": "yes"})
    assert [(x.key, x.size_mb) for x in m.models] == [(K20, 11549)]
    assert m.agents == (("hermes", (K20,)), ("openclaw", (K20,)))
    assert m.agent_models("openclaw") == (K20,) and m.agent_models("nobody") == ()
    assert m.game_auto_free is None
    for junk in (None, [], "x", {"Models": 5, "Agents": [1]}, {"Models": [{"Key": "../x"}]}):
        assert parse_models(junk).models == () and parse_models(junk).agents == ()


# ─── AI Mission Control's summary ───────────────────────────────

def test_summary_is_parsed_into_small_records() -> None:
    s = parse_summary(MC_SUMMARY)
    assert (s.version, s.time, s.game) == ("0.5.0", "2026-11-24T11:04:55", "")
    assert (s.vram_used_mib, s.vram_total_mib, s.ram_free_mb, s.ram_total_mb) == \
        (1585, 16303, 13336, 31895)
    assert s.ram_free_percent == 41.8 and s.models == ()
    assert [v.id for v in s.services] == ["lmstudio", "hermes", "openclaw", "opencode",
                                          "netsentry"]
    hermes = s.services[1]
    assert hermes.running and not hermes.remote and hermes.port is None and hermes.model == K35
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
        f"🟢 Hermes — {K35}",
        f"⚪ OpenClaw — {K20}",
        f"⚪ OpenCode — {K20}",
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
    data["Models"] = [{"Name": K20, "Context": 32768, "Processor": "100% GPU"}]
    data["Game"] = "Example Game"
    data["LastAction"] = {"Summary": "Start OpenClaw failed", "State": "failed",
                          "Reason": "port 18789 is in use", "Ended": "2026-11-24T10:58:00"}
    text = summary_text(parse_summary(data))
    assert "🟢 Hermes Dashboard — open · Tailscale on\n   https://pc.example.ts.net:9119/" in text
    assert "🟡 OpenClaw Web UI — open · Tailscale off · link won't open now" in text
    assert "⚪ OpenCode Web UI — closed · Tailscale on · link won't open now" in text
    assert f"Model loaded: {K20} — 32k context · 100% GPU" in text
    assert "Game: Example Game" in text and "NetSentry" not in text
    assert "Last action: ❌ Start OpenClaw failed — port 18789 is in use (10:58)" in text
    data["LastAction"] = {"Summary": "Starting Hermes", "State": "running"}
    assert summary_text(parse_summary(data)).endswith("Last action: ⏳ Starting Hermes")


def test_page_slug_matches_the_agents_rule() -> None:
    assert page_slug("hermes/Dashboard") == "hermes-dashboard"
    assert page_slug("openclaw/Web UI") == "openclaw-web-ui"
    assert page_slug("  ??  ") == ""


# ─── the main screen ─────────────────────────────────────────────

def test_aicontrol_asks_first_then_shows_the_main_screen(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    text, buttons = _open(p)
    assert p.notifier.send_to.call_args_list[0].args[1] == "⏳ Asking the PC…"
    assert amc.actions == ["summary", "mc models"]
    assert text.startswith("🤖 AI Mission Control 0.5.0 — 11:04\n" + ui.RULE)
    assert "Game mode: on — frees the GPU when a game starts" in text
    assert f"🟢 Hermes — {K35}" in text and "NetSentry" not in text
    assert "https://pc.example.ts.net:9119/" in text          # full links on the main screen
    assert text.endswith("Last action: ✅ Hermes is running (10:52)")
    assert _labels(buttons) == ["⏹ LM Studio", "⏹ Hermes", "▶ OpenClaw", "▶ OpenCode",
                                "▶ Start all", "⏹ Stop all", "🧠 Models", "🔗 Pages",
                                "🎮 Game mode: on", "🔄 Refresh", "⬅ PC", "🏠 Menu"]
    assert _data(buttons, "▶ OpenClaw") == "ai_control:s:openclaw:1"
    assert _data(buttons, "⬅ PC") == "workstation:v"
    assert all(len(b["callback_data"].encode()) <= 64 for b in buttons)


def test_a_service_toggle_edits_the_same_message_and_shows_the_last_action(tmp_path) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    text, buttons = _press(p, "ai_control:s:openclaw:1")
    assert _edits(p)[0] == "⏳ Starting OpenClaw…"
    assert {c.args[:2] for c in p.notifier.edit_message.call_args_list} == {(CHAT, 7)}
    assert _mc_actions(amc) == ["mc svc openclaw start"]
    assert "🟢 OpenClaw" in text and "Last action: ✅ Start OpenClaw (11:20)" in text
    assert "⏹ OpenClaw" in _labels(buttons)
    text, buttons = _press(p, "ai_control:s:hermes:0")
    assert _edits(p)[0] == "⏳ Stopping Hermes…" and "▶ Hermes" in _labels(buttons)


def test_a_failed_action_shows_why(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    amc.fail = "port 18789 is in use"
    text, buttons = _press(p, "ai_control:s:openclaw:1")
    assert "Last action: ❌ Start OpenClaw failed — port 18789 is in use" in text
    assert "▶ OpenClaw" in _labels(buttons)


def test_a_service_the_pc_no_longer_knows_is_its_refusal(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    amc.data["Services"] = [s for s in amc.data["Services"] if s["Id"] != "hermes"]
    text, _ = _press(p, "ai_control:s:hermes:0")
    assert "❌ Hermes was NOT stopped — the agent on the PC refused" in text
    assert "too old" not in text


def test_crafted_or_stale_service_buttons_send_nothing(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    for data in ("ai_control:s:hermes:1",):               # nothing read yet: just re-show
        text, _ = _press(p, data)
        assert text.startswith(CHANGED)
    _open(p)
    for data in ("ai_control:s:notepad:1", "ai_control:s:netsentry:0",
                 "ai_control:s:Bad;rm:1", "ai_control:s:hermes:2", "ai_control:s:"):
        text, _ = _press(p, data)
        assert text.startswith(CHANGED), data
    assert _mc_actions(amc) == []


def test_stop_all_needs_a_confirm_and_start_all_does_not(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    text, buttons = _press(p, "ai_control:xa")
    assert text.startswith("⚠️ Stop all AI services?") and "unloads the model" in text
    assert _labels(buttons) == ["⏹ Yes, stop all", "✖ Cancel"] and _mc_actions(amc) == []
    text, _ = _press(p, _data(buttons, "✖ Cancel"))
    assert text.startswith("🤖 AI Mission Control") and _mc_actions(amc) == []
    amc.data["Models"] = [{"Name": K20}]
    text, buttons = _press(p, "ai_control:xy")
    assert _edits(p)[0].startswith("⏳ Stopping everything and unloading the model")
    assert _mc_actions(amc) == ["mc all stop"] and "Model loaded: none" in text
    assert "Last action: ✅ Stop all" in text
    assert [x for x in _labels(buttons) if x.startswith(("▶", "⏹"))][:4] == \
        ["▶ LM Studio", "▶ Hermes", "▶ OpenClaw", "▶ OpenCode"]
    text, _ = _press(p, "ai_control:sa")
    assert "minute" in _edits(p)[0] and _mc_actions(amc)[-1] == "mc all start"
    assert "Last action: ✅ Start all" in text


def test_game_mode_toggles(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _, buttons = _open(p)
    text, buttons = _press(p, _data(buttons, "🎮 Game mode: on"))
    assert _edits(p)[0] == "⏳ Turning game mode off…" and _mc_actions(amc) == ["mc game off"]
    assert "Game mode: off" in text and "🎮 Game mode: off" in _labels(buttons)
    _press(p, _data(buttons, "🎮 Game mode: off"))
    assert _mc_actions(amc)[-1] == "mc game on"


def test_one_action_at_a_time(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    p._busy = True
    p.on_callback("ai_control:sa", CHAT, 7, "cb")
    p.notifier.answer_callback.assert_called_with("cb", "Still busy with the last action")
    assert _mc_actions(amc) == []


# ─── models ──────────────────────────────────────────────────────

def test_models_screen_loads_and_unloads(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    text, buttons = _press(p, "ai_control:m")
    assert text.startswith("🤖 AI Mission Control — models") and "Loaded: none" in text
    assert f"⚪ {K20} — 11.3 GB" in text and f"Hermes — {K35}" in text
    assert _labels(buttons) == [f"Load {K20}", f"Load {K27}", f"Load {K35}", "🔁 Agent models",
                                "🔄 Refresh", "⬅ Back", "🏠 Menu"]
    text, buttons = _press(p, _data(buttons, f"Load {K20}"))
    assert _edits(p)[0].startswith(f"⏳ Loading {K20}…") and "minute" in _edits(p)[0]
    assert _mc_actions(amc) == [f"mc load {K20}"]
    assert f"🟢 {K20} — 11.3 GB" in text and f"Last action: ✅ Load {K20}" in text
    assert _labels(buttons)[:2] == ["⏏ Unload", f"✔ {K20} (loaded)"]
    _press(p, _data(buttons, f"✔ {K20} (loaded)"))          # loading it again: nothing
    p.notifier.answer_callback.assert_called_with("cb", "Already loaded")
    assert _mc_actions(amc) == [f"mc load {K20}"]
    text, buttons = _press(p, "ai_control:ul")
    assert _edits(p)[0] == "⏳ Unloading the model…" and _mc_actions(amc)[-1] == "mc unload"
    assert "Loaded: none" in text and "⏏ Unload" not in _labels(buttons)


def test_agent_model_picker_works_by_index(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _press(p, "ai_control:m")
    text, buttons = _press(p, "ai_control:am")
    assert text.startswith("🤖 AI Mission Control — agent models")
    assert _labels(buttons)[:3] == [f"Hermes · {K35}", f"OpenClaw · {K20}", f"OpenCode · {K20}"]
    text, buttons = _press(p, _data(buttons, f"Hermes · {K35}"))
    assert text.startswith("🤖 AI Mission Control — Hermes model") and f"Now: {K35}" in text
    assert _labels(buttons) == [K20, K27, f"✔ {K35} (now)", "⬅ Back", "🏠 Menu"]
    assert all(len(b["callback_data"].encode()) <= 64 for b in buttons)
    _press(p, _data(buttons, f"✔ {K35} (now)"))
    p.notifier.answer_callback.assert_called_with("cb", "Already using it")
    text, _ = _press(p, _data(buttons, K20))
    assert _edits(p)[0].startswith(f"⏳ Switching Hermes to {K20}…")
    assert _mc_actions(amc) == [f"mc use hermes {K20}"]
    assert text.startswith("🤖 AI Mission Control — models") and f"Hermes — {K20}" in text
    assert f"Last action: ✅ Switch Hermes to {K20}" in text


def test_a_changed_or_forgotten_list_is_shown_again_not_acted_on(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _, models = _press(p, "ai_control:m")
    _, agents = _press(p, "ai_control:am")
    _, picks = _press(p, _data(agents, f"Hermes · {K35}"))
    _, pages = _press(p, "ai_control:p")
    load, use = _data(models, f"Load {K27}"), _data(picks, K20)
    share = _data(pages, "🔗 Share Hermes Dashboard on Tailscale")
    amc.catalog = amc.catalog[1:]                           # a model was removed on the PC
    amc.data["Pages"] = amc.data["Pages"][1:]
    _press(p, "ai_control:m")
    _press(p, "ai_control:p")
    for data, screen in ((load, "models"), (use, "agent models"), (share, "pages")):
        text, _ = _press(p, data)
        assert text.startswith(f"{CHANGED}\n\n🤖 AI Mission Control — {screen}"), data
    assert _mc_actions(amc) == []
    for i, data in enumerate((load, use, share, "ai_control:ag:1:0", "ai_control:ld:x:y",
                              "ai_control:us::0:0")):
        fresh, _, amc2 = _setup(tmp_path / f"fresh{i}")     # e.g. after a restart
        text, _ = _press(fresh, data)
        assert text.startswith(CHANGED), data
        assert _mc_actions(amc2) == []


# ─── pages ───────────────────────────────────────────────────────

def test_pages_screen_shows_full_links_and_share_switches(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    text, buttons = _press(p, "ai_control:p")
    assert text.startswith("🤖 AI Mission Control — pages")
    for port in (9119, 18789, 4096):
        assert f"   https://pc.example.ts.net:{port}/" in text
    assert _labels(buttons) == ["🔗 Share Hermes Dashboard on Tailscale",
                                "🔗 Share OpenClaw Web UI on Tailscale",
                                "🔗 Share OpenCode Web UI on Tailscale",
                                "🔄 Refresh", "⬅ Back", "🏠 Menu"]
    text, buttons = _press(p, _data(buttons, "🔗 Share OpenCode Web UI on Tailscale"))
    assert _edits(p)[0] == "⏳ Telling the PC…"
    assert _mc_actions(amc) == ["share opencode-web-ui on"]
    assert "Last action: ✅ OpenCode shared over Tailscale" in text
    assert "https://pc.example.ts.net:4096/" in text
    text, _ = _press(p, _data(buttons, "🚫 Stop sharing OpenCode Web UI"))
    assert _mc_actions(amc)[-1] == "share opencode-web-ui off" and "no longer shared" in text


# ─── when the PC is off, odd or missing ──────────────────────────

def test_with_the_pc_off_it_says_so_plainly(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path, _FakeAmc(on=False))
    text, buttons = _open(p)
    assert "💤 The PC isn't answering — it may be asleep or off." in text
    assert _labels(buttons) == ["⚡ Wake", "🔄 Refresh", "⬅ PC", "🏠 Menu"]
    assert _data(buttons, "⚡ Wake") == "workstation:wake"
    p2, _, _ = _setup(tmp_path / "b", _FakeAmc(on=False), mac="", wake_to="")
    _, buttons = _open(p2)
    assert "⚡ Wake" not in _labels(buttons)


def test_an_action_on_a_pc_that_went_off_says_what_did_not_happen(tmp_path: Path) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    amc.on = False
    text, buttons = _press(p, "ai_control:sa")
    assert text.startswith("❌ Nothing was started — the PC stopped answering.")
    assert "💤 The PC isn't answering" in text and "⚡ Wake" in _labels(buttons)


def test_without_a_pc_it_says_not_set_up(tmp_path: Path) -> None:
    for p, _, amc in (_setup(tmp_path / "a", workstation=False),
                      _setup(tmp_path / "b", host="", user="", ssh_key="")):
        text, _ = _open(p)
        assert text.startswith("🤖 AI Mission Control — not set up") and "workstation" in text
        text, _ = _press(p, "ai_control:sa")
        assert "— not set up" in text and amc.actions == []


@pytest.mark.parametrize("rc, out", [
    (64, ""),                                   # the PC's list has no `summary` yet
    (1, ""),                                    # AI Mission Control without the function
    (0, "Get-McSummary : not recognized\n"),    # garbage
    (0, '{"ok":false,"reason":"not available"}'),
    (0, "[1, 2]"),
])
def test_an_unusable_summary_says_too_old_and_shows_nothing_stale(tmp_path: Path, rc,
                                                                  out) -> None:
    p, _, amc = _setup(tmp_path)
    _open(p)
    amc.summary_rc, amc.summary_out = rc, out
    text, _ = _open(p)
    assert "too old for this (needs 0.5.0 or newer)" in text
    assert "pc.example.ts.net" not in text and "LM Studio" not in text


def test_a_refused_key_is_a_connection_problem(tmp_path: Path) -> None:
    amc = _FakeAmc()
    amc.refuse_key = True
    p, _, _ = _setup(tmp_path, amc)
    text, _ = _open(p)
    assert "refused NetSentry's key" in text and "too old" not in text
    assert "Permission denied" not in text


def test_it_never_leaves_asking_standing(tmp_path: Path) -> None:
    p, ws, _ = _setup(tmp_path)

    def broken():
        raise RuntimeError("boom")

    ws._agent.summary = broken
    text, _ = _press(p, "ai_control:h")
    assert text.startswith("❌ That did not finish") and "boom" not in text
    ws._agent.mc_all = lambda start: broken()
    text, _ = _press(p, "ai_control:sa")
    assert text.startswith("❌ That did not finish") and not p._busy


# ─── /pc and /menu ───────────────────────────────────────────────

def test_pc_screen_opens_ai_control_and_old_buttons_only_open_it(tmp_path: Path) -> None:
    p, ws, amc = _setup(tmp_path)
    ws.on_command("/pc", "", CHAT)
    buttons = _flat(ws.notifier.send_to.call_args.kwargs["buttons"])
    assert _data(buttons, "🤖 AI Mission Control") == "ai_control:h"
    text, _ = _press(p, "ai_control:h")
    assert _edits(p)[0] == "⏳ Asking the PC…" and text.startswith("🤖 AI Mission Control 0.5.0")
    ws.notifier.edit_message.reset_mock()
    ws.on_callback("workstation:ai", CHAT, 7, "cb")                 # a button from 0.32/0.33
    assert _last(p)[0].startswith("🤖 AI Mission Control 0.5.0")
    ws.on_callback("workstation:sh:hermes-dashboard:1", CHAT, 7, "cb")
    assert _last(p)[0].startswith("🤖 AI Mission Control — pages")
    assert _mc_actions(amc) == []


def test_aicontrol_is_listed_next_to_pc_in_the_menu(tmp_path: Path) -> None:
    assert [c["command"] for c in AiControlPlugin.COMMANDS] == ["aicontrol"]
    assert "aicontrol" not in [c["command"] for c in WorkstationPlugin.COMMANDS]
    menu = MenuPlugin(_ctx("menu", {}, Mock(), tmp_path))
    bot = Mock()
    bot.command_catalog.return_value = [
        ("/aicontrol", AiControlPlugin.COMMANDS[0]["description"], "ai_control"),
        ("/pc", WorkstationPlugin.COMMANDS[0]["description"], "workstation")]
    menu._bot = lambda: bot  # type: ignore[method-assign]
    system = next(cmds for key, _, cmds in menu._grouped() if key == "sys")
    assert [c for c, _ in system] == ["/pc", "/aicontrol"]


def test_context_is_said_once_when_the_processor_field_repeats_it() -> None:
    from netsentry.core.pc_agent import McModel
    from netsentry.plugins.ai_control import _model_bits
    assert _model_bits(McModel(name="m", context=65536, processor="ctx 64k")) == ("64k context", "")
    assert _model_bits(McModel(name="m", context=32768, processor="100% GPU")) == ("32k context", "100% GPU")
    assert _model_bits(McModel(name="m", context=5000, processor="")) == ("5000 context", "")


# ─── AI Mission Control 0.5.1: GameAutoFree and Placement in the summary ─────

def test_game_mode_from_the_summary_needs_no_second_call(tmp_path: Path) -> None:
    amc = _FakeAmc()
    amc.data["GameAutoFree"] = False
    p, _, amc = _setup(tmp_path, amc)
    text, buttons = _open(p)
    assert amc.actions == ["summary"]                       # no "mc models" any more
    assert "Game mode: off" in text
    assert "🎮 Game mode: off" in _labels_of(buttons)


def test_placement_is_shown_instead_of_the_processor_field() -> None:
    from netsentry.core.pc_agent import parse_summary
    from netsentry.plugins.ai_control import summary_text
    data = json.loads(json.dumps(MC_SUMMARY))
    data["Models"] = [{"Name": "gpt-oss-20b", "Key": "gpt-oss-20b", "Context": 65536,
                       "Processor": "ctx 64k", "Placement": "100% GPU"}]
    s = parse_summary(data)
    assert s.models[0].key == "gpt-oss-20b" and s.models[0].placement == "100% GPU"
    assert "Model loaded: gpt-oss-20b — 64k context · 100% GPU" in summary_text(s)
    assert "ctx 64k" not in summary_text(s)


def _labels_of(buttons) -> list[str]:
    return [b["text"] for b in (buttons or [])]             # _open gives a flat list
