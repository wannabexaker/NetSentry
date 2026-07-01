from __future__ import annotations

import logging
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


def test_auth_sets_httponly_strict_cookie_and_redirects(client) -> None:
    resp = client.get("/auth?token=" + TOKEN)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert _COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie


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
