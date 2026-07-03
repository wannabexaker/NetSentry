from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import Mock

from netsentry.core.plugin import PluginContext
from netsentry.plugins.github_explorer import GithubExplorerPlugin
from netsentry.plugins.youtube_bookmarks import YoutubeBookmarksPlugin


def _yt(tmp_path: Path) -> YoutubeBookmarksPlugin:
    ctx = PluginContext(
        name="youtube_bookmarks", config={}, router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger("test.yt"), state_dir=str(tmp_path),
    )
    p = YoutubeBookmarksPlugin(ctx)
    p.on_load()
    return p


def _gh(tmp_path: Path) -> GithubExplorerPlugin:
    ctx = PluginContext(
        name="github_explorer", config={"base_dir": str(tmp_path / "repos")},
        router=Mock(), notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.gh"), state_dir=str(tmp_path),
    )
    p = GithubExplorerPlugin(ctx)
    p.on_load()
    return p


def test_youtube_api_bookmarks_newest_first(tmp_path: Path) -> None:
    p = _yt(tmp_path)
    (tmp_path / "bookmarks.json").write_text(json.dumps([
        {"id": "a", "url": "https://youtu.be/aaaaaaaaaaa", "video_id": "aaaaaaaaaaa",
         "title": "First", "channel": "Chan", "duration_s": 75, "watched": False,
         "tags": ["x"], "saved_at": "2026-07-01"},
        {"id": "b", "url": "https://youtu.be/bbbbbbbbbbb", "video_id": "bbbbbbbbbbb",
         "title": "Second", "channel": "Chan2", "duration_s": 3661, "watched": True,
         "tags": [], "saved_at": "2026-07-02"},
    ]), encoding="utf-8")

    rows = p.api_bookmarks()
    assert [r["title"] for r in rows] == ["Second", "First"]  # newest first
    assert rows[0]["duration"] == "1:01:01"
    assert rows[0]["watched"] is True
    assert rows[1]["duration"] == "1:15"
    assert rows[1]["tags"] == ["x"]
    assert rows[1]["url"] == "https://youtu.be/aaaaaaaaaaa"


def test_youtube_api_bookmarks_empty(tmp_path: Path) -> None:
    assert _yt(tmp_path).api_bookmarks() == []


def test_github_api_repos(tmp_path: Path) -> None:
    p = _gh(tmp_path)
    (tmp_path / "repos.json").write_text(json.dumps([
        {"owner": "torvalds", "repo": "linux", "path": "/x", "cloned_at": "2026-06-01",
         "tags": ["kernel"], "context_summary": {
             "languages": [["C", 1000], ["Assembly", 50]],
             "manifests": ["Makefile"], "file_count": 5000}},
    ]), encoding="utf-8")

    rows = p.api_repos()
    assert rows[0]["url"] == "https://github.com/torvalds/linux"
    assert rows[0]["languages"] == ["C", "Assembly"]
    assert rows[0]["file_count"] == 5000
    assert rows[0]["tags"] == ["kernel"]


def test_github_api_repos_empty(tmp_path: Path) -> None:
    assert _gh(tmp_path).api_repos() == []


def test_fetch_meta_falls_back_to_oembed(tmp_path: Path) -> None:
    p = _yt(tmp_path)
    p._ytdlp_metadata = lambda url: None  # type: ignore[method-assign]  # broken yt-dlp
    p._oembed_metadata = lambda url: {"title": "Real Title", "channel": "Chan"}  # type: ignore[method-assign]

    meta = p._fetch_meta("https://youtu.be/aaaaaaaaaaa")
    assert meta["title"] == "Real Title"
    assert meta["channel"] == "Chan"
    assert meta["duration_s"] is None  # oEmbed has no duration


def test_fetch_meta_prefers_ytdlp(tmp_path: Path) -> None:
    p = _yt(tmp_path)
    p._ytdlp_metadata = lambda url: {  # type: ignore[method-assign]
        "title": "Rich", "channel": "C", "duration": 90, "upload_date": "20260101"}
    p._oembed_metadata = lambda url: {"title": "NOPE", "channel": "X"}  # type: ignore[method-assign]

    meta = p._fetch_meta("https://youtu.be/aaaaaaaaaaa")
    assert meta == {"title": "Rich", "channel": "C",
                    "duration_s": 90, "upload_date": "20260101"}


def test_refresh_backfills_unknown_titles(tmp_path: Path) -> None:
    p = _yt(tmp_path)
    (tmp_path / "bookmarks.json").write_text(json.dumps([
        {"id": "a", "url": "https://youtu.be/aaaaaaaaaaa", "video_id": "aaaaaaaaaaa",
         "title": "(unknown title)", "channel": "?", "duration_s": None,
         "watched": False, "tags": [], "saved_at": "2026-07-01"},
        {"id": "b", "url": "https://youtu.be/bbbbbbbbbbb", "video_id": "bbbbbbbbbbb",
         "title": "Already fine", "channel": "Chan", "duration_s": 60,
         "watched": False, "tags": [], "saved_at": "2026-07-02"},
    ]), encoding="utf-8")
    p._ytdlp_metadata = lambda url: None  # type: ignore[method-assign]
    p._oembed_metadata = lambda url: {"title": "Fixed via oEmbed", "channel": "RealChan"}  # type: ignore[method-assign]

    p.on_command("/yt", "refresh", 42)

    rows = p._load()
    assert rows[0]["title"] == "Fixed via oEmbed"
    assert rows[0]["channel"] == "RealChan"
    assert rows[1]["title"] == "Already fine"  # untouched
    # And the confirmation went out.
    texts = [c.args[1] for c in p.notifier.send_to.call_args_list]
    assert any("Updated 1/1" in t for t in texts)
