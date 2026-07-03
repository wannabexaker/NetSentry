from __future__ import annotations

import logging
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

from netsentry.core.plugin import PluginContext
from netsentry.plugins.lan_dashboard import _COOKIE_NAME, LanDashboardPlugin

TOKEN = "test-token-abc123"


@pytest.fixture()
def client(tmp_path: Path):
    ctx = PluginContext(
        name="lan_dashboard",
        config={},
        router=Mock(),
        notifier=Mock(),
        vault=Mock(),
        logger=logging.getLogger("test.dashboard"),
        state_dir=str(tmp_path),
    )
    plugin = LanDashboardPlugin(ctx)  # __init__ only — on_load()/threads not started
    plugin._token = TOKEN
    app = plugin._build_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_auth_rejects_wrong_token(client) -> None:
    assert client.get("/auth?token=wrong").status_code == 403


def test_auth_sets_httponly_lax_cookie_and_redirects(client) -> None:
    resp = client.get("/auth?token=" + TOKEN)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert _COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    # Lax so the Telegram-link login survives the /auth→/ redirect; mutating
    # endpoints are POST, which Lax still shields from cross-site CSRF.
    assert "SameSite=Lax" in set_cookie


def test_secure_flag_set_behind_tls_proxy(client) -> None:
    resp = client.get("/auth?token=" + TOKEN, headers={"X-Forwarded-Proto": "https"})
    assert "Secure" in resp.headers.get("Set-Cookie", "")


def test_index_requires_session_cookie(client) -> None:
    # No cookie, no token in URL -> denied.
    assert client.get("/").status_code == 403
    # A wrong cookie is still denied.
    client.set_cookie(_COOKIE_NAME, "nope")
    assert client.get("/").status_code == 403


def test_token_in_url_is_not_accepted_for_pages(client) -> None:
    # The old behaviour (token in the page URL) must no longer authorize.
    assert client.get("/?token=" + TOKEN).status_code == 403


def test_full_flow_auth_then_cookie_grants_access(client) -> None:
    client.get("/auth?token=" + TOKEN)  # test client keeps the cookie jar
    assert client.get("/").status_code == 200
    # API endpoints authorize off the same cookie, no token in the body.
    assert client.post("/tag", json={"mac": "AA:BB:CC:DD:EE:FF"}).status_code != 403


def test_api_denied_without_cookie(client) -> None:
    assert client.post("/tag", json={"mac": "AA:BB:CC:DD:EE:FF", "token": TOKEN}).status_code == 403


def _dash_plugin(state_dir: Path) -> LanDashboardPlugin:
    ctx = PluginContext(
        name="lan_dashboard",
        config={},
        router=Mock(),
        notifier=Mock(),
        vault=Mock(),
        logger=logging.getLogger("test.dashboard"),
        state_dir=str(state_dir),
    )
    return LanDashboardPlugin(ctx)


def test_token_persists_across_restarts(tmp_path: Path) -> None:
    # A fresh token is created and written owner-only...
    p1 = _dash_plugin(tmp_path)
    tok = p1._load_or_create_token()
    token_file = tmp_path / "dashboard_token"
    assert token_file.read_text(encoding="utf-8").strip() == tok
    assert tok

    # ...and a subsequent process (same state dir) reuses it, so a deploy or
    # reboot does not invalidate the owner's cookie / last /auth link.
    p2 = _dash_plugin(tmp_path)
    assert p2._load_or_create_token() == tok


class _FakeThreat:
    """Stand-in for the threat_detector plugin, wired via ctx._all_plugins."""

    def __init__(self) -> None:
        self.ctx = types.SimpleNamespace(name="threat_detector")
        self.calls: list = []

    def api_domains(self) -> list[dict]:
        return [{"domain": "x.example.com", "clients": ["phone"], "first_seen": "2026-07-01",
                 "last_seen": "2026-07-03", "count": 3, "note": "", "allowed": False}]

    def api_scans(self) -> list[dict]:
        return [{"key": "dns_tunnel", "enabled": True, "label": "DNS tunnel",
                 "severity": "attack", "means": "x"}]

    def api_intel(self) -> dict:
        return {"count": 42, "updated": "2026-07-03T11:00:00"}

    def api_findings(self, limit: int = 50) -> list[dict]:
        return []

    def api_set_allow(self, domain: str, on: bool) -> None:
        self.calls.append(("allow", domain, on))

    def api_set_note(self, domain: str, text: str) -> None:
        self.calls.append(("note", domain, text))

    def api_set_scan(self, key: str, on: bool) -> bool:
        self.calls.append(("scan", key, on))
        return True

    def refresh_feeds(self) -> None:
        self.calls.append(("refresh",))


@pytest.fixture()
def threat_client(tmp_path: Path):
    ctx = PluginContext(
        name="lan_dashboard",
        config={},
        router=Mock(),
        notifier=Mock(),
        vault=Mock(),
        logger=logging.getLogger("test.dashboard"),
        state_dir=str(tmp_path),
    )
    fake = _FakeThreat()
    ctx._all_plugins = [fake]  # type: ignore[attr-defined]
    plugin = LanDashboardPlugin(ctx)
    plugin._token = TOKEN
    app = plugin._build_app()
    app.config["TESTING"] = True
    return app.test_client(), fake


def test_threats_routes_require_cookie(threat_client) -> None:
    client, _ = threat_client
    assert client.get("/threats").status_code == 403
    assert client.get("/api/threats/domains").status_code == 403
    assert client.post("/api/threats/allow", json={"domain": "x", "on": True}).status_code == 403


def test_threats_routes_delegate_to_detector(threat_client) -> None:
    client, fake = threat_client
    client.get("/auth?token=" + TOKEN)  # cookie jar

    assert client.get("/threats").status_code == 200
    assert client.get("/api/threats/domains").get_json()[0]["domain"] == "x.example.com"

    summary = client.get("/api/threats/summary").get_json()
    assert summary["intel"]["count"] == 42
    assert summary["scans"][0]["key"] == "dns_tunnel"

    client.post("/api/threats/allow", json={"domain": "ads.example.com", "on": True})
    client.post("/api/threats/note", json={"domain": "ads.example.com", "text": "ad server"})
    client.post("/api/threats/scan", json={"key": "dns_tunnel", "on": False})
    client.post("/api/threats/intel-refresh", json={})
    assert ("allow", "ads.example.com", True) in fake.calls
    assert ("note", "ads.example.com", "ad server") in fake.calls
    assert ("scan", "dns_tunnel", False) in fake.calls
    assert ("refresh",) in fake.calls


def test_threats_summary_without_detector(client) -> None:
    # The base fixture has no threat_detector wired in -> graceful empty payloads.
    client.get("/auth?token=" + TOKEN)
    assert client.get("/api/threats/domains").get_json() == []
    assert client.get("/api/threats/summary").get_json() == {"scans": [], "intel": {}, "findings": []}


class _FakeYt:
    def __init__(self) -> None:
        self.ctx = types.SimpleNamespace(name="youtube_bookmarks")

    def api_bookmarks(self) -> list[dict]:
        return [{"title": "V", "url": "https://youtu.be/x", "channel": "C",
                 "duration": "1:00", "watched": False, "tags": [], "video_id": "x",
                 "saved_at": ""}]


class _FakeGh:
    def __init__(self) -> None:
        self.ctx = types.SimpleNamespace(name="github_explorer")

    def api_repos(self) -> list[dict]:
        return [{"owner": "o", "repo": "r", "url": "https://github.com/o/r",
                 "languages": ["Python"], "file_count": 3, "manifests": [], "tags": [],
                 "cloned_at": ""}]


@pytest.fixture()
def lib_client(tmp_path: Path):
    ctx = PluginContext(
        name="lan_dashboard", config={}, router=Mock(), notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.dashboard"), state_dir=str(tmp_path),
    )
    ctx._all_plugins = [_FakeYt(), _FakeGh()]  # type: ignore[attr-defined]
    plugin = LanDashboardPlugin(ctx)
    plugin._token = TOKEN
    app = plugin._build_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_library_requires_cookie(lib_client) -> None:
    assert lib_client.get("/library").status_code == 403
    assert lib_client.get("/api/library/youtube").status_code == 403
    assert lib_client.get("/api/library/github").status_code == 403


def test_library_delegates_to_plugins(lib_client) -> None:
    lib_client.get("/auth?token=" + TOKEN)
    assert lib_client.get("/library").status_code == 200  # renders base+library
    assert lib_client.get("/api/library/youtube").get_json()[0]["url"] == "https://youtu.be/x"
    assert lib_client.get("/api/library/github").get_json()[0]["repo"] == "r"


def test_library_without_plugins(client) -> None:
    client.get("/auth?token=" + TOKEN)
    assert client.get("/api/library/youtube").get_json() == []
    assert client.get("/api/library/github").get_json() == []
