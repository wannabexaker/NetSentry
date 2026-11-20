"""
youtube_bookmarks — Save YouTube URLs, organise them, export transcripts.

No video downloads, no AI calls. The plugin focuses on three jobs:

1. Bookmark a URL with metadata (title, channel, duration).
2. Help you organise your queue (tags, search, watched/unwatched, remind).
3. Export the transcript as a plain .txt file so you can paste it into
   ChatGPT (or any external tool) yourself.

Nothing to memorise: paste a YouTube link into the chat and it is saved;
`/yt` opens the library as buttons (to watch / all / export), and each video
has its own buttons (open, mark watched, transcript, delete). The typed forms
below keep working.

Commands
--------
/yt                         The library, as buttons
/yt <URL>                   Save URL with metadata
/yt list [N]                Last N bookmarks (default 10)
/yt unwatched               Pending bookmarks only
/yt get <idx>               Send transcript as .txt document to Telegram
/yt show <idx>              Show metadata + URL (no transcript)
/yt watched <idx>           Mark as watched
/yt unwatch <idx>           Mark as unwatched
/yt tag <idx> <tag,...>     Set comma-separated tags
/yt search <text>           Search title/channel/tag substrings
/yt remind                  Telegram digest of unwatched
/yt delete <idx>            Remove a bookmark
/yt refresh [idx]           Re-fetch metadata for entries missing a title
/yt export                  Send full library as a .md file

Storage
-------
~/.local/share/netsentry/youtube_bookmarks/bookmarks.json
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import threading
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core import ui
from ..core.jsonstore import read_json, write_json
from ..core.plugin import Plugin


_YT_URL_RE = re.compile(
    r"(?:https?://)?(?:(?:www|m|music)\.)?"
    r"(?:youtube\.com/(?:watch\?(?:[^#\s]*&)?v=|shorts/|live/|embed/|v/)|youtu\.be/)"
    r"([A-Za-z0-9_-]{11})"
)
_YT_ALLOWED_URL_RE = re.compile(
    r"^https?://(?:(?:www|m|music)\.)?"
    r"(?:youtube\.com/(?:watch\?[^ \t\r\n]*v=|shorts/|live/|embed/|v/)|youtu\.be/)"
    r"[A-Za-z0-9_?&=./%-]+$"
)
_PAGE = 6                   # videos per button page
_UNTITLED = ("", "(unknown title)")


def _extract_video_id(text: str) -> str | None:
    m = _YT_URL_RE.search(text or "")
    return m.group(1) if m else None


def _is_allowed_youtube_url(text: str) -> bool:
    return bool(_YT_ALLOWED_URL_RE.fullmatch((text or "").strip()))


def _hash_id(url: str) -> str:
    # Non-security digest: a short, stable id for a bookmark URL.
    return hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()[:8]


def _fmt_dur(secs: int | float | None) -> str:
    if not secs:
        return "?"
    secs = int(secs)
    h, secs = divmod(secs, 3600)
    m, s = divmod(secs, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def _safe_filename(s: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._-")
    return s[:maxlen] or "untitled"


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _int(text: str, default: int = 0) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


class YoutubeBookmarksPlugin(Plugin):
    """URL-only YouTube bookmarks with transcript export."""

    COMMANDS = [
        {"command": "yt",
         "description": "📺 Saved YouTube videos",
         "usage": "/yt <URL> · /yt list|unwatched|search <text>|get|show|watched|tag|"
                  "remind|delete|export"},
    ]

    # ─── lifecycle ──────────────────────────────────────────────

    def on_load(self) -> None:
        self._state_path = Path(self.ctx.state_dir) / "bookmarks.json"
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._state_path.exists():
            self._state_path.write_text("[]", encoding="utf-8")
        self._yt_dlp_bin = self.cfg.get("yt_dlp_bin", "yt-dlp")
        self._max_transcript_chars = int(self.cfg.get("max_transcript_chars", 250_000))
        self._lang_priority = self.cfg.get("lang_priority", ["el", "en"])
        # Commands run on several worker threads; one load→change→save at a time.
        self._lock = threading.RLock()
        # A YouTube link pasted into the chat (no command) is saved as-is.
        if self.ctx.events and self.cfg.get("save_pasted_links", True):
            self.ctx.events.subscribe("telegram.text", self._on_text)

    # ─── state ──────────────────────────────────────────────────

    def _load(self) -> list[dict[str, Any]]:
        # A damaged file is moved aside (bookmarks.json.corrupt), never treated
        # as "no bookmarks" — the next save would otherwise erase the library.
        entries = read_json(self._state_path, [])
        return [e for e in entries if isinstance(e, dict)]

    def _save(self, entries: list[dict[str, Any]]) -> None:
        write_json(self._state_path, entries)

    def _resolve(self, entries: list[dict], hint: str) -> dict | None:
        hint = hint.strip()
        if hint.isdigit():
            i = int(hint)
            if 1 <= i <= len(entries):
                return entries[i - 1]
            return None
        vid = _extract_video_id(hint)
        if vid:
            for e in entries:
                if e.get("video_id") == vid:
                    return e
        for e in entries:
            if e.get("id") == hint or e.get("url") == hint:
                return e
        return None

    # ─── yt-dlp wrappers (no video download) ────────────────────

    def _ytdlp_metadata(self, url: str) -> dict | None:
        try:
            r = subprocess.run(
                [self._yt_dlp_bin, "-J", "--no-warnings",
                 "--skip-download", "--no-playlist", "--", url],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                self.log.warning("yt-dlp metadata failed: %s", r.stderr[-300:])
                return None
            return json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            # OSError: yt-dlp is not installed (or not runnable) — oEmbed takes over.
            self.log.warning("yt-dlp metadata error: %s", e)
            return None

    def _oembed_metadata(self, url: str) -> dict | None:
        """Title/channel via YouTube's keyless oEmbed endpoint.

        Fallback for when yt-dlp is missing or broken (its extractors go stale
        quickly); oEmbed is a stable public API and needs no key. It has no
        duration/upload_date, but a real title beats "(unknown title)".
        """
        q = urllib.parse.urlencode({"url": url, "format": "json"})
        req = urllib.request.Request(
            f"https://www.youtube.com/oembed?{q}",
            headers={"User-Agent": "NetSentry"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            self.log.warning("oEmbed lookup failed: %s", e)
            return None
        title = str(data.get("title", "")).strip()
        if not title:
            return None
        return {"title": title, "channel": str(data.get("author_name", "")) or "?"}

    def _fetch_meta(self, url: str) -> dict:
        """Best-effort metadata: yt-dlp first (rich), oEmbed as fallback."""
        meta = self._ytdlp_metadata(url)
        if meta and meta.get("title"):
            return {
                "title":       meta.get("title", "(unknown title)"),
                "channel":     meta.get("channel") or meta.get("uploader") or "?",
                "duration_s":  meta.get("duration"),
                "upload_date": meta.get("upload_date"),
            }
        oe = self._oembed_metadata(url)
        if oe:
            return {"title": oe["title"], "channel": oe["channel"],
                    "duration_s": None, "upload_date": None}
        return {"title": "(unknown title)", "channel": "?",
                "duration_s": None, "upload_date": None}

    def _ytdlp_transcript(self, url: str) -> tuple[str | None, str | None]:
        """Returns (transcript_text, language_code) or (None, None)."""
        with tempfile.TemporaryDirectory() as tmp:
            for lang in self._lang_priority:
                try:
                    r = subprocess.run(
                        [self._yt_dlp_bin, "--skip-download", "--no-warnings",
                         "--write-auto-sub", "--sub-format", "vtt",
                         "--sub-lang", lang, "--no-playlist",
                         "-o", str(Path(tmp) / "%(id)s.%(ext)s"), "--", url],
                        capture_output=True, text=True, timeout=45,
                    )
                except subprocess.TimeoutExpired:
                    continue
                except OSError as e:
                    self.log.warning("yt-dlp is not runnable: %s", e)
                    return None, None
                if r.returncode != 0:
                    continue
                for f in Path(tmp).glob("*.vtt"):
                    return self._clean_vtt(f.read_text(encoding="utf-8")), lang
        return None, None

    @staticmethod
    def _clean_vtt(vtt: str) -> str:
        lines: list[str] = []
        last = ""
        for line in vtt.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(("WEBVTT", "Kind:", "Language:", "NOTE")):
                continue
            if re.match(r"^\d{2}:\d{2}", line):
                continue
            line = re.sub(r"<[^>]+>", "", line).strip()
            if line and line != last:
                lines.append(line)
                last = line
        return "\n".join(lines)

    # ─── public API (consumed by the web dashboard) ─────────────

    def api_bookmarks(self) -> list[dict[str, Any]]:
        """Saved videos as rows for the web Library page (newest first)."""
        out: list[dict[str, Any]] = []
        for e in self._load():
            out.append({
                "id":       e.get("id", ""),
                "title":    e.get("title", ""),
                "channel":  e.get("channel", ""),
                "url":      e.get("url", ""),
                "video_id": e.get("video_id", ""),
                "duration": _fmt_dur(e.get("duration_s")),
                "watched":  bool(e.get("watched")),
                "tags":     e.get("tags", []),
                "saved_at": e.get("saved_at", ""),
            })
        out.reverse()
        return out

    # ─── dispatch ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/yt":
            return
        args = args.strip()

        if not args:
            self._show(chat_id, None, *self._home_screen())
            return

        # Subcommand parsing — keyword first
        kw, _, rest = args.partition(" ")
        kw = kw.lower()
        rest = rest.strip()

        handlers = {
            "help":      lambda c, _r: self._send_help(c),
            "list":      self._cmd_list,
            "unwatched": self._cmd_unwatched,
            "get":       self._cmd_get,
            "show":      self._cmd_show,
            "watched":   self._cmd_watched,
            "unwatch":   self._cmd_unwatch,
            "tag":       self._cmd_tag,
            "search":    self._cmd_search,
            "remind":    self._cmd_remind,
            "delete":    self._cmd_delete,
            "rm":        self._cmd_delete,
            "export":    self._cmd_export,
            "refresh":   self._cmd_refresh,
        }
        if kw in handlers:
            handlers[kw](chat_id, rest)
            return

        # Otherwise treat as a URL save
        vid = _extract_video_id(args)
        if vid:
            if not _is_allowed_youtube_url(args):
                self._send(chat_id, "❓ Send a full http(s) YouTube URL from youtube.com or youtu.be.")
                return
            self._cmd_save(chat_id, args, vid)
            return

        self._send(chat_id, "❓ Not a YouTube URL nor a known subcommand. Paste a YouTube "
                            "link, or open the library.", buttons=self._library_row())

    # ─── subcommands ────────────────────────────────────────────

    def _cmd_save(self, chat_id: int, url: str, video_id: str) -> None:
        existing = next((e for e in self._load() if e.get("video_id") == video_id), None)
        if existing:
            self._send(chat_id, f"📺 Already saved: {existing.get('title','?')[:80]}",
                       buttons=self._saved_buttons(existing))
            return

        self._send(chat_id, f"{ui.WORKING} Looking the video up…")
        meta = self._fetch_meta(url)          # slow: outside the lock
        title = meta["title"]

        entry = {
            "id":          _hash_id(url),
            "url":         url,
            "video_id":    video_id,
            "title":       title,
            "channel":     meta["channel"],
            "duration_s":  meta["duration_s"],
            "upload_date": meta["upload_date"],
            "saved_at":    datetime.now().isoformat(timespec="seconds"),
            "watched":     False,
            "watched_at":  None,
            "tags":        [],
        }
        with self._lock:
            entries = self._load()
            if any(e.get("video_id") == video_id for e in entries):
                self._send(chat_id, f"📺 Already saved: {title[:80]}")
                return
            entries.append(entry)
            self._save(entries)
            number = len(entries)

        self._send(
            chat_id,
            f"📺 Saved #{number} — {title[:90]}\n"
            + ui.item(meta["channel"], f"⏱ {_fmt_dur(meta['duration_s'])}"),
            buttons=self._saved_buttons(entry),
        )

    def _cmd_list(self, chat_id: int, rest: str) -> None:
        n = max(1, int(rest)) if rest.isdigit() else 10
        entries = self._load()
        if not entries:
            self._send(chat_id, "📺 No bookmarks yet. Paste a YouTube link here to save it.")
            return
        slice_ = entries[-n:]
        lines = [ui.title("📺", "Saved videos", f"last {len(slice_)} of {len(entries)}")]
        for i, e in enumerate(slice_, start=len(entries) - len(slice_) + 1):
            lines.append(self._list_line(i, e))
        lines.append("\n✓ = watched · • = still to watch")
        self._send(chat_id, "\n".join(lines), buttons=self._library_row())

    def _cmd_unwatched(self, chat_id: int, rest: str) -> None:
        entries = self._load()
        pending = [(i + 1, e) for i, e in enumerate(entries) if not e.get("watched")]
        if not pending:
            self._send(chat_id, "📺 Everything watched. Your queue is empty.")
            return
        lines = [ui.title("📥", f"Unwatched ({len(pending)})")]
        for i, e in pending:
            lines.append(self._list_line(i, e))
        self._send(chat_id, "\n".join(lines), buttons=self._library_row())

    @staticmethod
    def _list_line(i: int, e: dict) -> str:
        """``3 ✓ Title #tag — Channel · ⏱ 12:34``."""
        mark = "✓" if e.get("watched") else "•"
        tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
        return f"{i} {mark} " + ui.item(f"{e['title'][:55]}{tags}",
                                       e.get("channel", "?")[:25],
                                       f"⏱ {_fmt_dur(e.get('duration_s'))}")

    def _library_row(self) -> list:
        return [[{"text": "📚 Library", "callback_data": f"{self.ctx.name}:h"}, *ui.nav_row()]]

    def _which(self, chat_id: int, verb: str) -> None:
        """A typed form without its number: say plainly what to do instead."""
        self._send(chat_id, f"📺 Which video? Tap it in the library — or type "
                            f"/yt {verb} and its number.", buttons=self._library_row())

    def _cmd_show(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._which(chat_id, "show")
            return
        entries = self._load()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        self._show(chat_id, None, *self._item_screen(e, "a", 0))

    def _details(self, e: dict) -> str:
        tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
        date = str(e.get("upload_date") or "")
        date_fmt = f"{date[:4]}-{date[4:6]}-{date[6:8]}" if len(date) >= 8 else "?"
        watched = (("yes — " + ui.when_text(e.get("watched_at"), default="?"))
                   if e.get("watched") else "not yet")
        # The link is the ▶ Open on YouTube button, not text.
        return (
            f"📺 {e.get('title', '?')}{tags}\n"
            f"🎙 Channel: {e.get('channel','?')}\n"
            f"⏱ Duration: {_fmt_dur(e.get('duration_s'))}\n"
            f"📅 Uploaded: {date_fmt}\n"
            f"💾 Saved: {ui.when_text(e.get('saved_at'), default='?')}\n"
            f"👁 Watched: {watched}")

    def _cmd_get(self, chat_id: int, rest: str) -> None:
        """Fetch transcript and ship as .txt document."""
        if not rest:
            self._which(chat_id, "get")
            return
        entries = self._load()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        self._send_transcript(chat_id, e)

    def _send_transcript(self, chat_id: int, e: dict) -> None:
        self._send(chat_id, f"{ui.WORKING} Fetching the transcript…")
        transcript, lang = self._ytdlp_transcript(e["url"])
        if not transcript:
            self._send(chat_id,
                "❌ No transcript available — the video has no captions, or YouTube "
                "didn't hand them out. Nothing was sent.")
            return

        truncated = ""
        if len(transcript) > self._max_transcript_chars:
            transcript = transcript[: self._max_transcript_chars]
            truncated = f"\n\n… [truncated at {self._max_transcript_chars:,} chars]"

        header = (
            f"# {e['title']}\n"
            f"Channel:  {e.get('channel','?')}\n"
            f"Duration: {_fmt_dur(e.get('duration_s'))}\n"
            f"URL:      {e['url']}\n"
            f"Captions: {lang}\n"
            f"Saved:    {e.get('saved_at','?')}\n"
            f"{'─' * 60}\n\n"
        )
        full = header + transcript + truncated

        # Write to a tempfile and upload as a document
        tmp = Path(tempfile.gettempdir()) / f"yt-{e['video_id']}-{_safe_filename(e['title'], 40)}.txt"
        tmp.write_text(full, encoding="utf-8")
        ok = False
        if hasattr(self.notifier, "send_document"):
            ok = self.notifier.send_document(
                chat_id, str(tmp),
                caption=f"📺 {e['title'][:120]}",
                filename=tmp.name,
            )
        try:
            tmp.unlink()
        except OSError:
            pass

        if not ok:
            # Fallback: stream the transcript as text chunks
            self._send(chat_id, header)
            for chunk in _chunk(transcript + truncated, 3900):
                self._send(chat_id, chunk)

    def _cmd_watched(self, chat_id: int, rest: str) -> None:
        self._toggle_watched(chat_id, rest, True)

    def _cmd_unwatch(self, chat_id: int, rest: str) -> None:
        self._toggle_watched(chat_id, rest, False)

    def _toggle_watched(self, chat_id: int, hint: str, mark: bool) -> None:
        if not hint:
            self._which(chat_id, "watched" if mark else "unwatch")
            return
        with self._lock:
            entries = self._load()
            e = self._resolve(entries, hint)
            if not e:
                self._send(chat_id, f"❌ Not found: {hint}")
                return
            self._set_watched(e, mark)
            self._save(entries)
        verb = "✓ marked watched" if mark else "• marked unwatched"
        self._send(chat_id, f"{verb}: {e['title'][:80]}")

    def _cmd_tag(self, chat_id: int, rest: str) -> None:
        parts = rest.split(maxsplit=1)
        if len(parts) < 2:
            self._send(chat_id, "🏷 To tag a video, type /yt tag, its number and the "
                                "tags — e.g. /yt tag 3 networking,how to",
                       buttons=self._library_row())
            return
        idx_or_url, raw_tags = parts
        tags = [t.strip().lower().replace(" ", "_") for t in raw_tags.split(",") if t.strip()]
        with self._lock:
            entries = self._load()
            e = self._resolve(entries, idx_or_url)
            if not e:
                self._send(chat_id, f"❌ Not found: {idx_or_url}")
                return
            e["tags"] = tags
            self._save(entries)
            number = entries.index(e) + 1
        self._send(chat_id, f"🏷 Tags for #{number}: {', '.join(tags) or '(none)'}")

    def _cmd_search(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "🔍 To search, type /yt search and a word from the title, "
                                "channel or tags.", buttons=self._library_row())
            return
        q = rest.lower()
        entries = self._load()
        hits = []
        for i, e in enumerate(entries, start=1):
            blob = " ".join([
                e.get("title", ""), e.get("channel", ""),
                " ".join(e.get("tags", [])),
            ]).lower()
            if q in blob:
                hits.append((i, e))
        if not hits:
            self._send(chat_id, f"🔍 No matches for “{rest}”.", buttons=self._library_row())
            return
        lines = [ui.title("🔍", f"{len(hits)} matches for “{rest}”")]
        for i, e in hits[:30]:
            lines.append(self._list_line(i, e))
        if len(hits) > 30:
            lines.append(ui.more(30, len(hits)))
        self._send(chat_id, "\n".join(lines), buttons=self._library_row())

    def _cmd_remind(self, chat_id: int, rest: str) -> None:
        entries = self._load()
        pending = [(i + 1, e) for i, e in enumerate(entries) if not e.get("watched")]
        if not pending:
            self._send(chat_id, "📺 Inbox zero. Nothing pending.")
            return
        lines = [ui.title("📥", f"You have {len(pending)} unwatched bookmarks")]
        for i, e in pending[:25]:
            lines.append(f"{i} • {e['title'][:55]}")
        if len(pending) > 25:
            lines.append(ui.more(25, len(pending)))
        name = self.ctx.name
        self._send(chat_id, "\n".join(lines),
                   buttons=[[{"text": f"📥 To watch ({len(pending)})",
                              "callback_data": f"{name}:l:u:0"}, *ui.nav_row()]])

    def _cmd_delete(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._which(chat_id, "delete")
            return
        with self._lock:
            entries = self._load()
            e = self._resolve(entries, rest)
            if not e:
                self._send(chat_id, f"❌ Not found: {rest}")
                return
            entries.remove(e)
            self._save(entries)
        self._send(chat_id, f"🗑 Deleted: {e['title'][:80]}")

    def _cmd_refresh(self, chat_id: int, rest: str) -> None:
        """Re-fetch metadata for entries with a missing title (or one entry)."""
        entries = self._load()
        if rest:
            e = self._resolve(entries, rest)
            if not e:
                self._send(chat_id, f"❌ Not found: {rest}")
                return
            targets = [e]
        else:
            targets = [e for e in entries if _needs_refresh(e)]
        if not targets:
            self._send(chat_id, "📺 All bookmarks already have titles.")
            return

        self._send(chat_id, f"{ui.WORKING} Looking up {ui.plural(len(targets), 'title')}…")
        # Look everything up first (slow, network), then apply it in one short
        # step to whatever the library looks like by then.
        found: dict[str, dict] = {}
        for e in targets:
            meta = self._fetch_meta(e["url"])
            if meta["title"] != "(unknown title)":
                found[self._key(e)] = meta
        with self._lock:
            entries = self._load()
            for e in entries:
                meta = found.get(self._key(e))
                if not meta:
                    continue
                e["title"] = meta["title"]
                if meta["channel"] != "?":
                    e["channel"] = meta["channel"]
                if meta["duration_s"]:
                    e["duration_s"] = meta["duration_s"]
                if meta["upload_date"]:
                    e["upload_date"] = meta["upload_date"]
            self._save(entries)
        self._send(chat_id, f"✅ Updated {len(found)}/{len(targets)} — titles found for "
                            f"{ui.plural(len(found), 'video')}.", buttons=self._library_row())

    def _cmd_export(self, chat_id: int, rest: str) -> None:
        """Dump the whole library as one Markdown document."""
        entries = self._load()
        if not entries:
            self._send(chat_id, "📺 Nothing to export.")
            return

        lines = [
            "# YouTube bookmarks — NetSentry export",
            f"_Generated {datetime.now().isoformat(timespec='seconds')} — {len(entries)} entries_",
            "",
        ]
        for i, e in enumerate(entries, start=1):
            mark = "[x]" if e.get("watched") else "[ ]"
            tags = (" `#" + "` `#".join(e.get("tags", [])) + "`") if e.get("tags") else ""
            lines.append(f"## {i}. {mark} {e['title']}{tags}")
            lines.append(f"- **Channel:** {e.get('channel','?')}")
            lines.append(f"- **Duration:** {_fmt_dur(e.get('duration_s'))}")
            date = e.get("upload_date")
            if date and len(date) >= 8:
                lines.append(f"- **Uploaded:** {date[:4]}-{date[4:6]}-{date[6:8]}")
            lines.append(f"- **Saved:** {e.get('saved_at','?')}")
            if e.get("watched_at"):
                lines.append(f"- **Watched:** {e['watched_at']}")
            lines.append(f"- **URL:** {e['url']}")
            lines.append("")
        text = "\n".join(lines)

        tmp = Path(tempfile.gettempdir()) / f"netsentry-yt-library-{datetime.now():%Y%m%d-%H%M}.md"
        tmp.write_text(text, encoding="utf-8")
        ok = False
        if hasattr(self.notifier, "send_document"):
            ok = self.notifier.send_document(
                chat_id, str(tmp),
                caption=f"📺 YouTube bookmarks export ({len(entries)} entries)",
                filename=tmp.name,
            )
        try:
            tmp.unlink()
        except OSError:
            pass

        if not ok:
            for chunk in _chunk(text, 3900):
                self._send(chat_id, chunk)

    # ─── button screens ─────────────────────────────────────────

    def _key(self, e: dict) -> str:
        """Short stable id of a bookmark, small enough for a button."""
        return str(e.get("id") or _hash_id(str(e.get("url", ""))))

    @staticmethod
    def _set_watched(e: dict, mark: bool) -> None:
        e["watched"] = mark
        e["watched_at"] = datetime.now().isoformat(timespec="seconds") if mark else None

    def _saved_buttons(self, e: dict) -> list:
        name, key = self.ctx.name, self._key(e)
        url = str(e.get("url", ""))
        return ui.rows(
            ui.url_row(("▶ Open on YouTube", url if url.startswith(("http://", "https://"))
                        else "")),
            [{"text": "📄 Send the transcript", "callback_data": f"{name}:t:{key}"}],
            [{"text": "✓ Mark as watched", "callback_data": f"{name}:w:{key}:u:0"},
             {"text": "📚 Library", "callback_data": f"{name}:h"}],
        ) or []

    def _home_screen(self) -> tuple[str, list]:
        entries = self._load()
        head = ui.title("📺", "YouTube bookmarks") + "\n"
        how = "To save a video, paste its YouTube link here as a message."
        if not entries:
            return head + "Nothing saved yet.\n\n" + how, [ui.nav_row()]
        name = self.ctx.name
        pending = sum(1 for e in entries if not e.get("watched"))
        rows = [
            [{"text": f"📥 To watch ({pending})", "callback_data": f"{name}:l:u:0"},
             {"text": f"📚 All ({len(entries)})", "callback_data": f"{name}:l:a:0"}],
            [{"text": "📤 Export the list", "callback_data": f"{name}:x"}],
        ]
        untitled = sum(1 for e in entries if _needs_refresh(e))
        if untitled:
            rows.append([{"text": f"🔧 Fix missing titles ({untitled})",
                          "callback_data": f"{name}:r"}])
        rows.append(ui.nav_row())
        return (head + f"{len(entries)} saved · {pending} still to watch\n\n" + how, rows)

    def _list_screen(self, view: str, page: int) -> tuple[str, list]:
        """Newest first; ``view`` is "u" (still to watch) or "a" (all)."""
        items = [e for e in reversed(self._load()) if view == "a" or not e.get("watched")]
        pages = max(1, -(-len(items) // _PAGE))
        page = min(max(page, 0), pages - 1)
        name = self.ctx.name
        icon, title = ("📚", "All videos") if view == "a" else ("📥", "To watch")
        if not items:
            body = "Nothing saved yet." if view == "a" else "Everything watched. 🎉"
        else:
            body = "Newest first. Tap a video to open it."
            if pages > 1:
                body += f"\nPage {page + 1} of {pages}"
        rows = []
        for e in items[page * _PAGE:(page + 1) * _PAGE]:
            mark = "✓" if e.get("watched") else "•"
            rows.append([{"text": _clip(f"{mark} {e.get('title', '?')}", 56),
                          "callback_data": f"{name}:s:{self._key(e)}:{view}:{page}"}])
        nav = []
        if page > 0:
            nav.append({"text": "◀ Newer", "callback_data": f"{name}:l:{view}:{page - 1}"})
        if page < pages - 1:
            nav.append({"text": "Older ▶", "callback_data": f"{name}:l:{view}:{page + 1}"})
        if nav:
            rows.append(nav)
        rows.append(ui.nav_row(f"{name}:h"))
        return ui.title(icon, f"{title} ({len(items)})") + "\n" + body, rows

    def _item_screen(self, e: dict, view: str, page: int,
                     confirm_delete: bool = False) -> tuple[str, list]:
        name, key, where = self.ctx.name, self._key(e), f"{view}:{page}"
        if confirm_delete:
            return (self._details(e) + "\n\n🗑 Delete this bookmark? It can't be undone.",
                    ui.confirm_rows("🗑", "delete", f"{name}:D:{key}:{where}",
                                    f"{name}:s:{key}:{where}"))
        rows = []
        url = str(e.get("url", ""))
        if url.startswith(("http://", "https://")):
            rows.append([{"text": "▶ Open on YouTube", "url": url}])
        rows += [
            [{"text": "↩ Mark as not watched" if e.get("watched") else "✓ Mark as watched",
              "callback_data": f"{name}:w:{key}:{where}"}],
            [{"text": "📄 Send the transcript", "callback_data": f"{name}:t:{key}"}],
            [{"text": "🗑 Delete", "callback_data": f"{name}:d:{key}:{where}"}],
            ui.nav_row(f"{name}:l:{where}"),
        ]
        return self._details(e), rows

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # <plugin>:h | l:<view>:<page> | x | r
        # <plugin>:<s|w|d|D>:<key>:<view>:<page> | t:<key>
        parts = data.split(":")
        verb, args = (parts[1] if len(parts) > 1 else ""), parts[2:]
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        def show(screen: tuple[str, list]) -> None:
            self._show(chat_id, message_id, *screen)

        if verb == "l":
            ack()
            show(self._list_screen("a" if args[:1] == ["a"] else "u",
                                   _int(args[1]) if len(args) > 1 else 0))
            return
        if verb == "x":
            ack("Exporting…")
            self._cmd_export(chat_id, "")
            return
        if verb == "r":
            ack("Looking the titles up…")
            self._cmd_refresh(chat_id, "")
            show(self._home_screen())
            return
        if verb not in ("s", "w", "d", "D", "t"):
            ack()
            show(self._home_screen())
            return

        key = args[0] if args else ""
        view = "a" if args[1:2] == ["a"] else "u"
        page = _int(args[2]) if len(args) > 2 else 0
        with self._lock:
            entries = self._load()
            e = next((x for x in entries if self._key(x) == key), None)
            if e is None:
                ack("That bookmark is no longer saved")
                show(self._list_screen(view, page))
                return
            if verb == "w":
                self._set_watched(e, not e.get("watched"))
                self._save(entries)
            elif verb == "D":
                entries.remove(e)
                self._save(entries)

        if verb == "t":
            ack("Fetching the transcript…")
            self._send_transcript(chat_id, e)
        elif verb == "D":
            ack("Deleted")
            show(self._list_screen(view, page))
        elif verb == "w":
            ack("Marked as watched" if e.get("watched") else "Marked as not watched")
            show(self._item_screen(e, view, page))
        else:
            ack()
            show(self._item_screen(e, view, page, confirm_delete=(verb == "d")))

    def _on_text(self, payload: dict) -> None:
        """A message that is nothing but a YouTube link: save it."""
        chat_id = payload.get("chat_id")
        text = str(payload.get("text") or "").strip()
        if not chat_id or not _is_allowed_youtube_url(text):
            return
        video_id = _extract_video_id(text)
        if video_id:
            self._cmd_save(chat_id, text, video_id)

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self._send(chat_id, text, buttons=buttons or None)

    # ─── helpers ────────────────────────────────────────────────

    def _send_help(self, chat_id: int) -> None:
        self._send(chat_id, "\n".join([
            ui.title("📺", "YouTube bookmarks", "what you can type"),
            "The library is buttons; paste a link to save a video. Typed forms:",
            "• /yt list [how many] · /yt unwatched · /yt remind",
            "• /yt show|get|watched|unwatch|delete <number>",
            "• /yt tag <number> <tag1,tag2>",
            "• /yt search <text>",
            "• /yt refresh [number] · /yt export",
        ]), buttons=self._library_row())

    def _send(self, chat_id: int, text: str, buttons: list | None = None) -> None:
        """Send ``text`` (split if long); ``buttons`` go under the last part."""
        chunks = list(_chunk(text, 3900))
        for i, chunk in enumerate(chunks):
            extra = {"buttons": buttons} if buttons and i == len(chunks) - 1 else {}
            if hasattr(self.notifier, "send_to"):
                self.notifier.send_to(chat_id, chunk, **extra)
            else:
                self.notifier.send(chunk, **extra)


def _needs_refresh(e: dict) -> bool:
    return e.get("title") in _UNTITLED or e.get("channel") in ("", "?")


def _chunk(text: str, n: int):
    for i in range(0, len(text), n):
        yield text[i:i + n]
