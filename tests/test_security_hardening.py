from __future__ import annotations

import re
from unittest.mock import Mock

import pytest
from flask import Flask
from werkzeug.exceptions import Forbidden

from netsentry.plugins.github_explorer import _parse_repo
from netsentry.plugins.guest_wifi_rotator import DICEWARE_WORDS, GuestWifiRotatorPlugin
from netsentry.plugins.lan_dashboard import LanDashboardPlugin
from netsentry.plugins.youtube_bookmarks import _is_allowed_youtube_url


def test_github_repo_allowlist_accepts_supported_shapes_only() -> None:
    assert _parse_repo("https://github.com/example/project.git") == ("example", "project")
    assert _parse_repo("example/project") == ("example", "project")
    assert _parse_repo("git@github.com:example/project.git") is None
    assert _parse_repo("--upload-pack=malicious") is None
    assert _parse_repo("https://example.invalid/example/project") is None


def test_youtube_url_allowlist_rejects_options_and_lookalike_hosts() -> None:
    assert _is_allowed_youtube_url("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    assert _is_allowed_youtube_url("https://youtu.be/dQw4w9WgXcQ")
    assert not _is_allowed_youtube_url("--config-location=/tmp/file")
    assert not _is_allowed_youtube_url(
        "https://youtube.com.example.invalid/watch?v=dQw4w9WgXcQ"
    )


def test_generated_guest_password_keeps_compatible_format() -> None:
    plugin = object.__new__(GuestWifiRotatorPlugin)
    plugin.cfg = {"password_prefix": "guest"}

    value = plugin._generate_passphrase(4, 4)

    assert re.fullmatch(r"guest(?:-[a-z]+){4}-\d{4}", value)
    assert all(word in DICEWARE_WORDS for word in value.split("-")[1:5])


def test_dashboard_token_uses_constant_time_comparison(monkeypatch) -> None:
    plugin = object.__new__(LanDashboardPlugin)
    plugin._token = "expected-token"
    compare = Mock(return_value=False)
    monkeypatch.setattr("netsentry.plugins.lan_dashboard.secrets.compare_digest", compare)
    app = Flask(__name__)

    with app.test_request_context("/?token=wrong-token"):
        with pytest.raises(Forbidden):
            plugin._require_token()

    compare.assert_called_once_with("wrong-token", "expected-token")


def test_dashboard_auto_bind_prefers_tailscale_then_loopback() -> None:
    plugin = object.__new__(LanDashboardPlugin)
    plugin._tailscale_ipv4 = Mock(return_value="100.64.0.10")  # type: ignore[method-assign]
    assert plugin._resolve_bind_host("auto") == "100.64.0.10"

    plugin._tailscale_ipv4 = Mock(return_value=None)  # type: ignore[method-assign]
    assert plugin._resolve_bind_host("auto") == "127.0.0.1"
