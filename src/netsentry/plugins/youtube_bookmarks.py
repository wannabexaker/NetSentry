"""
youtube_bookmarks — Save YouTube URLs, organise them, export transcripts.

No video downloads, no AI calls. The plugin focuses on three jobs:

1. Bookmark a URL with metadata (title, channel, duration).
2. Help you organise your queue (tags, search, watched/unwatched, remind).
3. Export the transcript as a plain .txt file so you can paste it into
   ChatGPT (or any external tool) yourself.

Commands
--------
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
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.plugin import Plugin


_YT_URL_RE = re.compile(
    r"(?:https?://)?(?:(?:www|m|music)\.)?"
    r"(?:youtube\.com/(?:watch\?v=|shorts/|embed/|v/)|youtu\.be/)"
    r"([A-Za-z0-9_-]{11})"
)
_YT_ALLOWED_URL_RE = re.compile(
    r"^https?://(?:(?:www|m|music)\.)?"
    r"(?:youtube\.com/(?:watch\?[^ \t\r\n]*v=|shorts/|embed/|v/)|youtu\.be/)"
    r"[A-Za-z0-9_?&=./%-]+$"
)


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


class YoutubeBookmarksPlugin(Plugin):
    """URL-only YouTube bookmarks with transcript export."""

    COMMANDS = [
        {"command": "yt",
         "description": "📺 YouTube bookmark: /yt <URL>|list|unwatched|get|show|watched|tag|search|remind|delete|export"},
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

    # ─── state ──────────────────────────────────────────────────

    def _load(self) -> list[dict[str, Any]]:
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save(self, entries: list[dict[str, Any]]) -> None:
        self._state_path.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
        )

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
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            self.log.warning("yt-dlp metadata error: %s", e)
            return None

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
            self._send_help(chat_id)
            return

        # Subcommand parsing — keyword first
        kw, _, rest = args.partition(" ")
        kw = kw.lower()
        rest = rest.strip()

        handlers = {
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

        self._send(chat_id, "❓ Not a YouTube URL nor a known subcommand. Try /yt for help.")

    # ─── subcommands ────────────────────────────────────────────

    def _cmd_save(self, chat_id: int, url: str, video_id: str) -> None:
        entries = self._load()
        existing = next((e for e in entries if e.get("video_id") == video_id), None)
        if existing:
            self._send(chat_id, f"📺 Already saved: {existing.get('title','?')[:80]}")
            return

        self._send(chat_id, "📺 Fetching metadata…")
        meta = self._ytdlp_metadata(url)
        title = (meta or {}).get("title", "(unknown title)")
        channel = (meta or {}).get("channel") or (meta or {}).get("uploader") or "?"
        duration = (meta or {}).get("duration")
        upload_date = (meta or {}).get("upload_date")

        entry = {
            "id":          _hash_id(url),
            "url":         url,
            "video_id":    video_id,
            "title":       title,
            "channel":     channel,
            "duration_s":  duration,
            "upload_date": upload_date,
            "saved_at":    datetime.now().isoformat(timespec="seconds"),
            "watched":     False,
            "watched_at":  None,
            "tags":        [],
        }
        entries.append(entry)
        self._save(entries)

        self._send(
            chat_id,
            f"📺 Saved #{len(entries)} — {title[:90]}\n"
            f"   📺 {channel}  ⏱ {_fmt_dur(duration)}\n"
            f"   {url}\n\n"
            f"Next: /yt get {len(entries)}  to download the transcript."
        )

    def _cmd_list(self, chat_id: int, rest: str) -> None:
        n = int(rest) if rest.isdigit() else 10
        entries = self._load()
        if not entries:
            self._send(chat_id, "📺 No bookmarks yet. Send a YouTube URL with /yt <URL>.")
            return
        slice_ = entries[-n:]
        lines = [f"📺 Bookmarks (last {len(slice_)} of {len(entries)})", "─" * 25]
        for i, e in enumerate(slice_, start=len(entries) - len(slice_) + 1):
            mark = "✓" if e.get("watched") else "•"
            tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
            lines.append(f"{i:>2} {mark} {e['title'][:55]}{tags}")
            lines.append(f"     📺 {e.get('channel','?')[:25]}  ⏱ {_fmt_dur(e.get('duration_s'))}")
        lines.append("\n✓ = watched, • = pending")
        self._send(chat_id, "\n".join(lines))

    def _cmd_unwatched(self, chat_id: int, rest: str) -> None:
        entries = self._load()
        pending = [(i + 1, e) for i, e in enumerate(entries) if not e.get("watched")]
        if not pending:
            self._send(chat_id, "📺 Everything watched. Your queue is empty.")
            return
        lines = [f"📺 Unwatched ({len(pending)})", "─" * 25]
        for i, e in pending:
            tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
            lines.append(f"{i:>2} • {e['title'][:55]}{tags}")
            lines.append(f"     📺 {e.get('channel','?')[:25]}  ⏱ {_fmt_dur(e.get('duration_s'))}")
        self._send(chat_id, "\n".join(lines))

    def _cmd_show(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /yt show <idx>")
            return
        entries = self._load()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
        date = e.get("upload_date")
        date_fmt = f"{date[:4]}-{date[4:6]}-{date[6:8]}" if date and len(date) >= 8 else "?"
        self._send(chat_id,
            f"📺 {e['title']}{tags}\n"
            f"📺 Channel: {e.get('channel','?')}\n"
            f"⏱ Duration: {_fmt_dur(e.get('duration_s'))}\n"
            f"📅 Uploaded: {date_fmt}\n"
            f"💾 Saved: {e.get('saved_at','?')}\n"
            f"👁 Watched: {'yes — ' + (e.get('watched_at') or '?') if e.get('watched') else 'no'}\n"
            f"🔗 {e['url']}\n\n"
            f"/yt get {entries.index(e) + 1}  to fetch transcript as .txt")

    def _cmd_get(self, chat_id: int, rest: str) -> None:
        """Fetch transcript and ship as .txt document."""
        if not rest:
            self._send(chat_id, "Usage: /yt get <idx>")
            return
        entries = self._load()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return

        self._send(chat_id, "📺 Fetching transcript…")
        transcript, lang = self._ytdlp_transcript(e["url"])
        if not transcript:
            self._send(chat_id,
                "❌ No transcript available (video has no auto-captions, "
                "or yt-dlp failed). Try the URL in a browser to verify.")
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
            self._send(chat_id, f"Usage: /yt {'watched' if mark else 'unwatch'} <idx>")
            return
        entries = self._load()
        e = self._resolve(entries, hint)
        if not e:
            self._send(chat_id, f"❌ Not found: {hint}")
            return
        e["watched"] = mark
        e["watched_at"] = datetime.now().isoformat(timespec="seconds") if mark else None
        self._save(entries)
        verb = "✓ marked watched" if mark else "• marked unwatched"
        self._send(chat_id, f"{verb}: {e['title'][:80]}")

    def _cmd_tag(self, chat_id: int, rest: str) -> None:
        parts = rest.split(maxsplit=1)
        if len(parts) < 2:
            self._send(chat_id, "Usage: /yt tag <idx> <tag1,tag2,...>")
            return
        idx_or_url, raw_tags = parts
        entries = self._load()
        e = self._resolve(entries, idx_or_url)
        if not e:
            self._send(chat_id, f"❌ Not found: {idx_or_url}")
            return
        tags = [t.strip().lower().replace(" ", "_") for t in raw_tags.split(",") if t.strip()]
        e["tags"] = tags
        self._save(entries)
        self._send(chat_id, f"🏷 Tags for #{entries.index(e) + 1}: {', '.join(tags) or '(none)'}")

    def _cmd_search(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /yt search <text>")
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
            self._send(chat_id, f"🔍 No matches for '{rest}'")
            return
        lines = [f"🔍 {len(hits)} matches for '{rest}'", "─" * 25]
        for i, e in hits[:30]:
            mark = "✓" if e.get("watched") else "•"
            lines.append(f"{i:>2} {mark} {e['title'][:55]}")
            lines.append(f"     📺 {e.get('channel','?')[:25]}")
        if len(hits) > 30:
            lines.append(f"\n… +{len(hits) - 30} more")
        self._send(chat_id, "\n".join(lines))

    def _cmd_remind(self, chat_id: int, rest: str) -> None:
        entries = self._load()
        pending = [(i + 1, e) for i, e in enumerate(entries) if not e.get("watched")]
        if not pending:
            self._send(chat_id, "📺 Inbox zero. Nothing pending.")
            return
        lines = [f"📺 You have {len(pending)} unwatched bookmarks:", ""]
        for i, e in pending[:25]:
            lines.append(f"  /yt get {i}  — {e['title'][:55]}")
        if len(pending) > 25:
            lines.append(f"\n… +{len(pending) - 25} more. /yt unwatched  to see all.")
        self._send(chat_id, "\n".join(lines))

    def _cmd_delete(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /yt delete <idx>")
            return
        entries = self._load()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        entries.remove(e)
        self._save(entries)
        self._send(chat_id, f"🗑 Deleted: {e['title'][:80]}")

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

    # ─── helpers ────────────────────────────────────────────────

    def _send_help(self, chat_id: int) -> None:
        self._send(chat_id,
            "📺 /yt usage:\n"
            "  /yt <URL>           Save URL\n"
            "  /yt list [N]        Last N bookmarks\n"
            "  /yt unwatched       Pending only\n"
            "  /yt get <idx>       Send transcript as .txt\n"
            "  /yt show <idx>      Metadata + URL\n"
            "  /yt watched <idx>   Mark watched\n"
            "  /yt unwatch <idx>   Mark unwatched\n"
            "  /yt tag <idx> a,b   Set tags\n"
            "  /yt search <text>   Search title/channel/tag\n"
            "  /yt remind          Digest of unwatched\n"
            "  /yt delete <idx>    Remove\n"
            "  /yt export          Full library as .md")

    def _send(self, chat_id: int, text: str) -> None:
        for chunk in _chunk(text, 3900):
            if hasattr(self.notifier, "send_to"):
                self.notifier.send_to(chat_id, chunk)
            else:
                self.notifier.send(chunk)


def _chunk(text: str, n: int):
    for i in range(0, len(text), n):
        yield text[i:i + n]
