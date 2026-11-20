"""youtube_bookmarks: saving links (typed or just pasted), the button library,
transcripts, and keeping the library safe on disk."""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from netsentry.core.events import EventBus
from netsentry.core.plugin import PluginContext
from netsentry.plugins.youtube_bookmarks import (
    YoutubeBookmarksPlugin,
    _extract_video_id,
    _fmt_dur,
    _is_allowed_youtube_url,
    _safe_filename,
)

CHAT = 42
VID_A, VID_B = "aaaaaaaaaaa", "bbbbbbbbbbb"
URL_A = f"https://www.youtube.com/watch?v={VID_A}"
URL_B = f"https://youtu.be/{VID_B}?si=tracking"
META = {"title": "How routers work", "channel": "NetChan", "duration_s": 754,
        "upload_date": "20260102"}


def _plugin(tmp_path: Path, **config) -> YoutubeBookmarksPlugin:
    ctx = PluginContext(
        name="youtube_bookmarks", config=config, router=Mock(), notifier=Mock(),
        vault=Mock(), logger=logging.getLogger("test.yt"), state_dir=str(tmp_path),
        events=EventBus(),
    )
    p = YoutubeBookmarksPlugin(ctx)
    p.on_load()
    return p


def _saved(tmp_path: Path) -> list[dict]:
    return json.loads((tmp_path / "bookmarks.json").read_text(encoding="utf-8"))


def _seed(p: YoutubeBookmarksPlugin, count: int, watched: tuple[int, ...] = ()) -> list[dict]:
    """``count`` bookmarks, oldest first; ``watched`` are 1-based positions."""
    entries = [{
        "id": f"id{i:06d}", "url": f"https://youtu.be/{i:011d}", "video_id": f"{i:011d}",
        "title": f"Video {i}", "channel": "Chan", "duration_s": 60 * i,
        "upload_date": "20260102", "saved_at": f"2026-07-{i:02d}T10:00:00",
        "watched": i in watched, "watched_at": None, "tags": [],
    } for i in range(1, count + 1)]
    p._save(entries)
    return entries


def _sent(p: YoutubeBookmarksPlugin) -> list[str]:
    return [c.args[1] for c in p.notifier.send_to.call_args_list]


def _last_buttons(mock_call) -> list[dict]:
    return [b for row in (mock_call.kwargs.get("buttons") or []) for b in row]


def _press(p: YoutubeBookmarksPlugin, data: str) -> tuple[str, list[dict]]:
    """Tap a button; returns the screen the message was edited to."""
    p.notifier.edit_message.reset_mock()
    p.on_callback(data, CHAT, 7, "cb1")
    if not p.notifier.edit_message.called:
        return "", []
    call = p.notifier.edit_message.call_args
    return call.args[2], _last_buttons(call)


def _data(buttons: list[dict], label: str) -> str:
    return next(b["callback_data"] for b in buttons if label in b["text"])


# ─── recognising links ───────────────────────────────────────────

@pytest.mark.parametrize("url", [
    f"https://www.youtube.com/watch?v={VID_A}",
    f"https://youtube.com/watch?v={VID_A}&t=42s",
    f"https://www.youtube.com/watch?feature=share&v={VID_A}",
    f"https://m.youtube.com/watch?v={VID_A}",
    f"https://music.youtube.com/watch?v={VID_A}",
    f"https://youtu.be/{VID_A}?si=AbC-123_x",
    f"https://www.youtube.com/shorts/{VID_A}",
    f"https://www.youtube.com/live/{VID_A}?feature=share",
    f"http://www.youtube.com/embed/{VID_A}",
])
def test_every_common_link_shape_is_recognised(url: str) -> None:
    assert _is_allowed_youtube_url(url)
    assert _extract_video_id(url) == VID_A


@pytest.mark.parametrize("text", [
    "", "hello", "kitchen-cam", f"watch this {URL_A}", f"{URL_A} lol",
    f"https://evil.example/watch?v={VID_A}", f"https://youtube.com.evil.example/watch?v={VID_A}",
    f"ftp://youtube.com/watch?v={VID_A}", f"youtube.com/watch?v={VID_A}",
    "https://www.youtube.com/@somechannel",
])
def test_everything_else_is_not_a_link_to_save(text: str) -> None:
    assert not _is_allowed_youtube_url(text)


def test_small_formatters() -> None:
    assert _fmt_dur(None) == "?" and _fmt_dur(0) == "?"
    assert _fmt_dur(75) == "1:15" and _fmt_dur(3725.9) == "1:02:05"
    assert _safe_filename("Ένα βίντεο: part/1?") == "part_1"
    assert _safe_filename("///") == "untitled"
    assert len(_safe_filename("x" * 200, 40)) == 40


# ─── saving ──────────────────────────────────────────────────────

def test_save_by_command(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch.object(p, "_fetch_meta", return_value=dict(META)):
        p.on_command("/yt", URL_A, CHAT)
    (entry,) = _saved(tmp_path)
    assert entry["video_id"] == VID_A and entry["title"] == "How routers work"
    assert entry["watched"] is False and entry["tags"] == []
    done = p.notifier.send_to.call_args_list[-1]
    assert "Saved #1" in done.args[1] and "12:34" in done.args[1]
    assert "/yt get" not in done.args[1]                 # buttons instead of a hint to type
    labels = [b["text"] for b in _last_buttons(done)]
    assert any("transcript" in t for t in labels) and any("watched" in t for t in labels)


def test_a_pasted_link_is_saved_without_any_command(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch.object(p, "_fetch_meta", return_value=dict(META)):
        p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": f"  {URL_B}  "})
    assert [e["video_id"] for e in _saved(tmp_path)] == [VID_B]


def test_ordinary_messages_are_not_mistaken_for_links(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch.object(p, "_fetch_meta") as fetch:
        for text in ("kitchen-cam", f"look at {URL_A}", "https://example.org/watch?v=x"):
            p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": text})
        p.ctx.events.publish("telegram.text", {"text": URL_A})          # no chat
    fetch.assert_not_called()
    assert _saved(tmp_path) == [] and _sent(p) == []


def test_pasted_links_can_be_switched_off(tmp_path: Path) -> None:
    p = _plugin(tmp_path, save_pasted_links=False)
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": URL_A})
    assert _saved(tmp_path) == []


def test_the_same_video_is_not_saved_twice(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch.object(p, "_fetch_meta", return_value=dict(META)) as fetch:
        p.on_command("/yt", URL_A, CHAT)
        p.on_command("/yt", f"https://youtu.be/{VID_A}", CHAT)          # other shape, same video
    assert fetch.call_count == 1 and len(_saved(tmp_path)) == 1
    assert "Already saved" in _sent(p)[-1]


def test_two_saves_at_once_both_land(tmp_path: Path) -> None:
    """Commands run on worker threads: neither save may overwrite the other."""
    p = _plugin(tmp_path)
    gate = threading.Barrier(2, timeout=5)

    def slow_meta(url: str) -> dict:
        gate.wait()                                      # both are mid-lookup together
        return dict(META)

    with patch.object(p, "_fetch_meta", side_effect=slow_meta):
        threads = [threading.Thread(target=p.on_command, args=("/yt", url, CHAT))
                   for url in (URL_A, URL_B)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
    assert {e["video_id"] for e in _saved(tmp_path)} == {VID_A, VID_B}


def test_not_a_link_and_not_a_subcommand(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/yt", "frobnicate", CHAT)
    assert "Not a YouTube URL" in _sent(p)[-1]
    p.on_command("/yt", f"youtu.be/{VID_A}", CHAT)        # no scheme
    assert "full http(s) YouTube URL" in _sent(p)[-1]
    assert _saved(tmp_path) == []


# ─── metadata lookups ────────────────────────────────────────────

def test_missing_yt_dlp_falls_back_instead_of_crashing(tmp_path: Path) -> None:
    """Regression: with yt-dlp not installed, subprocess raised and took the
    whole /yt command down before the keyless fallback was ever tried."""
    p = _plugin(tmp_path)
    with patch("netsentry.plugins.youtube_bookmarks.subprocess.run",
               side_effect=FileNotFoundError("yt-dlp")), \
         patch.object(p, "_oembed_metadata",
                      return_value={"title": "From oEmbed", "channel": "C"}):
        p.on_command("/yt", URL_A, CHAT)
    assert _saved(tmp_path)[0]["title"] == "From oEmbed"


def test_metadata_failures_are_tolerated(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    run = "netsentry.plugins.youtube_bookmarks.subprocess.run"
    with patch(run, return_value=SimpleNamespace(returncode=1, stdout="", stderr="boom")):
        assert p._ytdlp_metadata(URL_A) is None
    with patch(run, return_value=SimpleNamespace(returncode=0, stdout="not json", stderr="")):
        assert p._ytdlp_metadata(URL_A) is None
    with patch(run, side_effect=subprocess.TimeoutExpired("yt-dlp", 30)):
        assert p._ytdlp_metadata(URL_A) is None
    with patch(run, return_value=SimpleNamespace(
            returncode=0, stderr="", stdout=json.dumps({"title": "T", "uploader": "U",
                                                        "duration": 9}))):
        assert p._fetch_meta(URL_A) == {"title": "T", "channel": "U", "duration_s": 9,
                                        "upload_date": None}
    with patch.object(p, "_ytdlp_metadata", return_value=None), \
         patch.object(p, "_oembed_metadata", return_value=None):
        assert p._fetch_meta(URL_A)["title"] == "(unknown title)"


def test_oembed_lookup(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    response = Mock()
    response.read.return_value = json.dumps({"title": " A title ", "author_name": "Ch"}).encode()
    response.__enter__ = lambda s: s
    response.__exit__ = lambda *a: False
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        assert p._oembed_metadata(URL_A) == {"title": "A title", "channel": "Ch"}
    assert urlopen.call_args.args[0].full_url.startswith("https://www.youtube.com/oembed?")
    with patch("urllib.request.urlopen", side_effect=OSError("offline")):
        assert p._oembed_metadata(URL_A) is None


# ─── the button library ──────────────────────────────────────────

def test_bare_command_opens_the_library(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/yt", "", CHAT)
    assert "Nothing saved yet" in _sent(p)[-1] and "paste its YouTube link" in _sent(p)[-1]
    _seed(p, 3, watched=(2,))
    p.on_command("/yt", "", CHAT)
    home = p.notifier.send_to.call_args_list[-1]
    assert "3 saved · 2 still to watch" in home.args[1]
    labels = [b["text"] for b in _last_buttons(home)]
    assert "📥 To watch (2)" in labels and "📚 All (3)" in labels
    assert not any("missing titles" in t for t in labels)
    p.on_command("/yt", "help", CHAT)
    assert "what you can type" in _sent(p)[-1]


def test_list_screens_are_newest_first_and_paged(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 8, watched=(8,))
    text, buttons = _press(p, "youtube_bookmarks:l:a:0")
    assert "All videos (8)" in text and "Page 1 of 2" in text
    titles = [b["text"] for b in buttons if ":s:" in b.get("callback_data", "")]
    assert titles == ["✓ Video 8", "• Video 7", "• Video 6", "• Video 5", "• Video 4", "• Video 3"]
    text, buttons = _press(p, _data(buttons, "Older"))
    assert "Page 2 of 2" in text
    assert [b["text"] for b in buttons if ":s:" in b.get("callback_data", "")] == [
        "• Video 2", "• Video 1"]
    assert any("Newer" in b["text"] for b in buttons)
    text, buttons = _press(p, "youtube_bookmarks:l:u:0")
    assert "To watch (7)" in text and not any("Video 8" in b["text"] for b in buttons)
    text, _ = _press(p, "youtube_bookmarks:l:a:99")       # a page that no longer exists
    assert "Page 2 of 2" in text


def test_every_button_fits_telegrams_limit(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 30)
    entries = p._load()
    entries[-1]["title"] = "Ω" * 300                       # long, multi-byte title
    p._save(entries)
    screens = [p._home_screen(), p._list_screen("a", 4), p._list_screen("u", 0),
               p._item_screen(entries[-1], "a", 4),
               p._item_screen(entries[-1], "a", 4, confirm_delete=True)]
    for _text, rows in screens:
        for button in (b for row in rows for b in row):
            assert len(button.get("callback_data", "").encode()) <= 64
            assert len(button["text"]) <= 64


def test_open_mark_watched_and_back(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 2)
    _, buttons = _press(p, "youtube_bookmarks:l:u:0")
    text, buttons = _press(p, _data(buttons, "Video 2"))
    assert "📺 Video 2" in text and "Watched: not yet" in text
    assert next(b for b in buttons if "Open on YouTube" in b["text"])["url"].startswith("https://")
    text, buttons = _press(p, _data(buttons, "Mark as watched"))
    assert "Watched: yes" in text
    assert _saved(tmp_path)[1]["watched"] is True and _saved(tmp_path)[1]["watched_at"]
    p.notifier.answer_callback.assert_called_with("cb1", "Marked as watched")
    text, buttons = _press(p, _data(buttons, "Mark as not watched"))
    assert _saved(tmp_path)[1]["watched"] is False and _saved(tmp_path)[1]["watched_at"] is None
    text, _ = _press(p, _data(buttons, "Back"))
    assert "To watch (2)" in text


def test_delete_needs_a_second_tap(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 2)
    _, buttons = _press(p, "youtube_bookmarks:s:id000001:a:0")
    text, buttons = _press(p, _data(buttons, "Delete"))
    assert "Delete this bookmark?" in text and len(_saved(tmp_path)) == 2
    kept_text, _ = _press(p, _data(buttons, "Cancel"))
    assert "Delete this bookmark?" not in kept_text and len(_saved(tmp_path)) == 2
    text, _ = _press(p, _data(buttons, "Yes, delete"))
    assert [e["id"] for e in _saved(tmp_path)] == ["id000002"]
    assert "All videos (1)" in text


def test_a_button_for_a_bookmark_that_is_gone(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 1)
    text, _ = _press(p, "youtube_bookmarks:w:nosuchid:a:0")
    p.notifier.answer_callback.assert_called_with("cb1", "That bookmark is no longer saved")
    assert "All videos (1)" in text and _saved(tmp_path)[0]["watched"] is False


def test_garbage_callbacks_land_on_the_home_screen(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 1)
    for data in ("youtube_bookmarks", "youtube_bookmarks:", "youtube_bookmarks:zz:1:2:3",
                 "youtube_bookmarks:l", "youtube_bookmarks:l:a:notanumber"):
        text, _ = _press(p, data)
        assert "YouTube bookmarks" in text or "All videos" in text or "To watch" in text, data


def test_fix_missing_titles_button(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    entries = _seed(p, 2)
    entries[0]["title"], entries[0]["channel"] = "(unknown title)", "?"
    p._save(entries)
    _, rows = p._home_screen()
    assert any("Fix missing titles (1)" in b["text"] for row in rows for b in row)
    with patch.object(p, "_fetch_meta", return_value=dict(META)) as fetch:
        _press(p, "youtube_bookmarks:r")
    fetch.assert_called_once_with(entries[0]["url"])
    assert _saved(tmp_path)[0]["title"] == "How routers work"
    assert _saved(tmp_path)[1]["title"] == "Video 2"


# ─── transcripts ─────────────────────────────────────────────────

VTT = """WEBVTT
Kind: captions
Language: en

00:00:00.000 --> 00:00:02.000
<c>Hello</c> there

00:00:02.000 --> 00:00:04.000
Hello there

00:00:04.000 --> 00:00:06.000
General <00:00:05.000>Kenobi
"""


def test_captions_are_cleaned_of_timing_and_repeats() -> None:
    assert YoutubeBookmarksPlugin._clean_vtt(VTT) == "Hello there\nGeneral Kenobi"


def test_transcript_is_sent_as_a_document(tmp_path: Path) -> None:
    p = _plugin(tmp_path, max_transcript_chars=20)
    _seed(p, 1)
    seen: dict = {}

    def send_document(chat_id, path, caption="", filename=None):
        seen.update(chat=chat_id, body=Path(path).read_text(encoding="utf-8"),
                    name=filename, path=Path(path))
        return True

    p.notifier.send_document.side_effect = send_document
    with patch.object(p, "_ytdlp_transcript", return_value=("word " * 50, "en")):
        _press(p, "youtube_bookmarks:t:id000001")
    assert seen["chat"] == CHAT and seen["name"].endswith(".txt")
    assert "# Video 1" in seen["body"] and "Captions: en" in seen["body"]
    assert "[truncated at 20 chars]" in seen["body"]
    assert not seen["path"].exists()                      # the temp file is cleaned up


def test_transcript_falls_back_to_messages_when_upload_fails(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 1)
    p.notifier.send_document.return_value = False
    with patch.object(p, "_ytdlp_transcript", return_value=("line one\nline two", "el")):
        p.on_command("/yt", "get 1", CHAT)
    assert any("line one" in t for t in _sent(p))


def test_no_transcript_is_explained(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 1)
    with patch("netsentry.plugins.youtube_bookmarks.subprocess.run",
               side_effect=FileNotFoundError("yt-dlp")):
        p.on_command("/yt", "get 1", CHAT)                # yt-dlp missing: no crash either
    assert "No transcript available" in _sent(p)[-1]
    p.on_command("/yt", "get 9", CHAT)
    assert "Not found" in _sent(p)[-1]
    p.on_command("/yt", "get", CHAT)
    assert "type /yt get and its number" in _sent(p)[-1]


def test_transcript_tries_each_language_in_order(tmp_path: Path) -> None:
    p = _plugin(tmp_path, lang_priority=["el", "en"])
    asked: list[str] = []

    def fake_run(cmd, **kwargs):
        lang = cmd[cmd.index("--sub-lang") + 1]
        asked.append(lang)
        if lang == "en":
            out = Path(cmd[cmd.index("-o") + 1]).parent / f"{VID_A}.en.vtt"
            out.write_text(VTT, encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="no subs")

    with patch("netsentry.plugins.youtube_bookmarks.subprocess.run", side_effect=fake_run):
        assert p._ytdlp_transcript(URL_A) == ("Hello there\nGeneral Kenobi", "en")
    assert asked == ["el", "en"]


# ─── typed commands ──────────────────────────────────────────────

def test_typed_list_views(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/yt", "list", CHAT)
    assert "No bookmarks yet" in _sent(p)[-1]
    _seed(p, 12, watched=(12,))
    p.on_command("/yt", "list", CHAT)
    assert "last 10 of 12" in _sent(p)[-1] and "12 ✓ Video 12" in _sent(p)[-1]
    p.on_command("/yt", "list 0", CHAT)                   # 0 used to mean "all of them"
    assert "last 1 of 12" in _sent(p)[-1]
    p.on_command("/yt", "unwatched", CHAT)
    assert "Unwatched (11)" in _sent(p)[-1]
    p.on_command("/yt", "remind", CHAT)
    assert "11 unwatched bookmarks" in _sent(p)[-1]


def test_typed_watched_tag_search_delete(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 3)
    p.on_command("/yt", "watched 2", CHAT)
    assert _saved(tmp_path)[1]["watched"] is True
    p.on_command("/yt", "unwatch id000002", CHAT)         # by id works as well as by number
    assert _saved(tmp_path)[1]["watched"] is False
    p.on_command("/yt", "tag 1 Networking, How To", CHAT)
    assert _saved(tmp_path)[0]["tags"] == ["networking", "how_to"]
    p.on_command("/yt", "search how_to", CHAT)
    assert "1 matches" in _sent(p)[-1] and "Video 1" in _sent(p)[-1]
    p.on_command("/yt", "search zzz", CHAT)
    assert "No matches" in _sent(p)[-1]
    p.on_command("/yt", "show 1", CHAT)
    assert "#networking #how_to" in _sent(p)[-1] and "Uploaded: 2026-01-02" in _sent(p)[-1]
    p.on_command("/yt", "rm 3", CHAT)
    assert [e["id"] for e in _saved(tmp_path)] == ["id000001", "id000002"]
    for args in ("watched 9", "tag 9 x", "delete 9", "show 9", "refresh 9"):
        p.on_command("/yt", args, CHAT)
        assert "Not found" in _sent(p)[-1], args
    for args, usage in (("watched", "type /yt watched"), ("tag 1", "type /yt tag"),
                        ("delete", "type /yt delete"), ("search", "type /yt search")):
        p.on_command("/yt", args, CHAT)
        assert usage in _sent(p)[-1]


def test_export_sends_one_markdown_file(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/yt", "export", CHAT)
    assert "Nothing to export" in _sent(p)[-1]
    _seed(p, 2, watched=(1,))
    bodies: list[str] = []
    p.notifier.send_document.side_effect = (
        lambda chat, path, caption="", filename=None:
        bodies.append(Path(path).read_text(encoding="utf-8")) or True)
    _press(p, "youtube_bookmarks:x")
    assert "## 1. [x] Video 1" in bodies[0] and "## 2. [ ] Video 2" in bodies[0]


# ─── the library file ────────────────────────────────────────────

def test_a_damaged_library_is_kept_not_overwritten(tmp_path: Path, caplog) -> None:
    """Regression: an unreadable file used to count as "no bookmarks", and the
    next save then wrote the empty list over everything."""
    p = _plugin(tmp_path)
    _seed(p, 3)
    library = tmp_path / "bookmarks.json"
    library.write_text(library.read_text(encoding="utf-8")[:120], encoding="utf-8")   # cut short
    with caplog.at_level(logging.ERROR):
        with patch.object(p, "_fetch_meta", return_value=dict(META)):
            p.on_command("/yt", URL_A, CHAT)
    assert "damaged" in caplog.text
    assert "id000001" in (tmp_path / "bookmarks.json.corrupt").read_text(encoding="utf-8")
    assert [e["video_id"] for e in _saved(tmp_path)] == [VID_A]


def test_a_library_of_the_wrong_shape_is_also_kept(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    (tmp_path / "bookmarks.json").write_text('{"not": "a list"}', encoding="utf-8")
    assert p._load() == []
    assert (tmp_path / "bookmarks.json.corrupt").exists()


def test_saving_leaves_no_half_written_file(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _seed(p, 2)
    with patch("netsentry.core.jsonstore.os.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            p._save([])
    assert len(_saved(tmp_path)) == 2                     # the old library is untouched
