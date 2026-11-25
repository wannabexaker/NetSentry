"""
who_asked — "which device is asking for this domain?"

Pi-hole knows who asked only when a device talks to it directly. Devices behind
the router show up as the router itself, so a flagged domain can't be pinned on
anyone. `/who` answers in three steps, each needing less luck than the last:

  1. Pi-hole's own record — the devices that asked directly, by name.
  2. If the router asked on someone's behalf: line the lookup times up with the
     router's log of devices joining the network. A lookup that always happens
     seconds after the same device connects gives that device away at once.
  3. "Catch it": a passive, temporary logging rule on the router records the
     sender of the next lookup. You are told as soon as it fires; the rule
     removes itself afterwards (and after `trace_days` at the latest).

Everything is reachable by buttons: `/who` lists the recently flagged domains,
a `🔎 Search` over Pi-hole's whole history (only the search word is typed), and
the domains NetSentry blocked. A domain's answer offers `⛔ Block` — a regex deny
entry in Pi-hole for the domain and its subdomains, after a confirmation — and
`↩️ Unblock` for NetSentry's own entries.

Config keys:
    ftl_db_path        Pi-hole FTL database (default /etc/pihole/pihole-FTL.db)
    lookback_days      how far back to read Pi-hole (default 30)
    join_window_s      "seconds after joining" that counts as a match (default 15)
    trace_days         a trace gives up and removes its rule after this (default 7)
    pihole_api         Pi-hole web API base URL (default http://127.0.0.1)
    cli_pw_path        Pi-hole's CLI password file (default /etc/pihole/cli_pw)
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..core import notify, ui
from ..core.pihole import PiholeAPI, PiholeError
from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)[a-z0-9_]([a-z0-9_-]{0,62}\.)+[a-z0-9-]{2,63}$")
_TERM_RE = re.compile(r"[a-z0-9.-]{2,63}")
_KEEP_AFTER_HIT_S = 3600        # keep listening a little after the first catch
_SEARCH_WAIT_S = 300            # how long the search prompt waits for a word
_SEARCH_TIMEOUT_S = 20.0        # a search that takes longer is stopped
_SEARCH_SHOWN = 15              # domains in a search answer
_SEARCH_DOMAINS = 500           # matching domain names considered at most
_ROUTER_CLIENTS = "via the router — every device behind it"


def search_term(text: str) -> str | None:
    """The search word the owner sent, or None if it can't be one."""
    term = text.strip().lower()
    return term if _TERM_RE.fullmatch(term) else None


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@dataclass
class DomainHit:
    """One domain found by a search: how often, when, and who asked."""
    domain: str
    count: int = 0
    first: float = 0.0
    last: float = 0.0
    clients: Counter = field(default_factory=Counter)


class SearchError(Exception):
    """The search could not run; ``str()`` is one plain line."""


def _start_thread(func: Callable[..., None], *args: object) -> None:
    threading.Thread(target=func, args=args, daemon=True, name="who-search").start()


def needle_for(domain: str) -> str | None:
    """The text a DNS packet for ``domain`` is sure to contain.

    On the wire a name is sent label by label, so the dots are not there — the
    longest label is the most distinctive substring to look for.
    """
    labels = [lab for lab in domain.lower().split(".")[:-1]
              if re.fullmatch(r"[a-z0-9_-]{4,}", lab)]
    if not labels:
        return None
    return max(labels, key=len)[:40]


class WhoAskedPlugin(Plugin):
    COMMANDS = [
        {"command": "who", "description": "🔎 Which device asks for a domain",
         "usage": "/who <domain> · /who <part of a name>"},
    ]

    def on_load(self) -> None:
        self._ftl_db = self.cfg.get("ftl_db_path") or "/etc/pihole/pihole-FTL.db"
        self._lookback_days = int(self.cfg.get("lookback_days", 30))
        self._join_window_s = int(self.cfg.get("join_window_s", 15))
        self._trace_s = int(self.cfg.get("trace_days", 7)) * 86400
        self._file = Path(self.ctx.state_dir) / "traces.json"
        self._lock = threading.RLock()
        # Telegram caps callback data at 64 bytes; a longer domain travels as a
        # short reference instead (kept in memory — a stale button just reopens
        # the menu).
        self._refs: dict[str, str] = {}
        try:
            self._pihole: PiholeAPI | None = PiholeAPI(
                self.cfg.get("pihole_api") or "http://127.0.0.1",
                self.cfg.get("cli_pw_path") or "/etc/pihole/cli_pw")
        except ValueError as e:
            self.log.warning("who_asked: blocking is off — %s", e)
            self._pihole = None
        # chat → (message that holds the search prompt, deadline)
        self._search_wait: dict[int, tuple[int | None, float]] = {}
        self._background: Callable[..., None] = _start_thread
        if self.ctx.events:
            self.ctx.events.subscribe("telegram.text", self._on_text)
            self.ctx.events.subscribe("telegram.command", self._on_any_command)

    def scheduled_tasks(self) -> list[ScheduledTask]:
        return [ScheduledTask(cron="*/5 * * * *", func=self.poll, name="poll")]

    # ─── commands & buttons ──────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/who":
            return
        self._search_wait.pop(chat_id, None)
        text = args.strip().lower().strip(".")
        if not text:
            self._show_home(chat_id, None)
        elif _DOMAIN_RE.match(text):
            self._answer(chat_id, text)
        elif search_term(text):
            self._start_search(chat_id, None, text)
        else:
            self._show_home(chat_id, None,
                            note=f"❌ “{text[:60]}” doesn't look like a domain name "
                                 "or a search word (letters, digits, dots, dashes).")

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # <plugin>:q:<domain> ask | :t:<domain> start a trace | :x:<id> stop | :h home
        # :s search prompt | :f:<word> search | :b:<domain> block? | :B:<domain> block
        # :c:<domain> answer in place | :u:<domain> unblock | :U:<domain> unblock, home
        _, verb, arg = (data.split(":", 2) + ["", ""])[:3]
        arg = self._refs.get(arg, arg)
        answer = getattr(self.notifier, "answer_callback", None)
        if verb != "s":
            self._search_wait.pop(chat_id, None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "q" and _DOMAIN_RE.match(arg):
            ack("Looking…")
            self._answer(chat_id, arg)
        elif verb == "c" and _DOMAIN_RE.match(arg):
            ack()
            self._answer(chat_id, arg, message_id)
        elif verb == "t" and _DOMAIN_RE.match(arg):
            ack()
            self.notifier.send_to(chat_id, self.start_trace(arg, chat_id),
                                  buttons=[ui.nav_row(f"{self.ctx.name}:h")])
        elif verb == "x":
            ack("Stopped" if self.stop_trace(arg) else "Already gone")
            self._show_home(chat_id, message_id)
        elif verb == "s":
            ack()
            self._search_wait[chat_id] = (message_id, time.time() + _SEARCH_WAIT_S)
            self._show(chat_id, message_id,
                       "🔎 Send part of a domain name, e.g. baidu",
                       [[ui.button(f"{ui.CANCELLED} Cancel", f"{self.ctx.name}:h")]])
        elif verb == "f" and search_term(arg):
            ack("Searching…")
            self._start_search(chat_id, message_id, arg)
        elif verb == "b" and _DOMAIN_RE.match(arg):
            ack()
            self._show(chat_id, message_id, "\n".join([
                ui.title("⛔", f"Block {arg}?"),
                f"Blocks {arg} and its subdomains for every device at home.",
                "A device that uses it to check for internet may think it is offline.",
                "↩️ Unblock undoes it at any time."]),
                ui.confirm_rows("✔", "block", self._key("B", arg), self._key("c", arg)))
        elif verb == "B" and _DOMAIN_RE.match(arg):
            ack("Blocking…")
            note = self._change_block(arg, block=True)
            self._answer(chat_id, arg, message_id, note=note)
        elif verb in ("u", "U") and _DOMAIN_RE.match(arg):
            ack("Unblocking…")
            note = self._change_block(arg, block=False)
            if verb == "U":
                self._show_home(chat_id, message_id, note=note)
            else:
                self._answer(chat_id, arg, message_id, note=note)
        else:
            ack()
            self._show_home(chat_id, message_id)

    def _key(self, verb: str, arg: str) -> str:
        data = f"{self.ctx.name}:{verb}:{arg}"
        if len(data.encode()) <= 64:
            return data
        ref = next((r for r, d in self._refs.items() if d == arg), None)
        if ref is None:
            ref = "#" + secrets.token_hex(4)
            self._refs[ref] = arg
            for old in list(self._refs)[:-200]:
                self._refs.pop(old)
        return f"{self.ctx.name}:{verb}:{ref}"

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list | None) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons or None)

    def _show_home(self, chat_id: int, message_id: int | None, note: str = "") -> None:
        flagged = self._flagged_domains()
        lines = ([note, ""] if note else []) + [
            ui.title("🔎", "Who asked for a domain?"),
            ("Tap a domain from a recent finding, or search. " if flagged
             else "Search Pi-hole for a domain. ")
            + "For a full domain name, send /who and the name."]
        rows = [[ui.button("🔎 Search", f"{self.ctx.name}:s")]]
        rows += [[{"text": f"🔎 {d}"[:60], "callback_data": self._key("q", d)}]
                 for d in flagged]
        traces = self._traces()
        if traces:
            lines.append("\n🎯 Listening on the router for")
            for tid, t in traces.items():
                seen = ", ".join(t.get("seen", {}).values()) or "nobody yet"
                lines.append("• " + ui.item(t["domain"], f"caught: {seen}"))
                rows.append([{"text": f"⏹ Stop listening for {t['domain']}"[:60],
                              "callback_data": self._key("x", tid)}])
        blocked = self._blocked_domains()
        if blocked:
            lines.append("\n⛔ Blocked in Pi-hole by NetSentry")
            for d in blocked:
                lines.append(f"• {d} (and its subdomains)")
                rows.append([{"text": f"↩️ Unblock {d}"[:60],
                              "callback_data": self._key("U", d)}])
        rows.append(ui.nav_row())
        self._show(chat_id, message_id, "\n".join(lines), rows)

    def _flagged_domains(self, limit: int = 8) -> list[str]:
        """Domain subjects of recent findings, newest first."""
        det = self._plugin("threat_detector")
        if det is None:
            return []
        out: list[str] = []
        try:
            findings = det.api_findings(limit=80)
        except Exception:
            return []
        for f in findings:
            d = str(f.get("subject", "")).lower().strip(".")
            if _DOMAIN_RE.match(d) and d not in out:
                out.append(d)
            if len(out) >= limit:
                break
        return out

    # ─── answering ───────────────────────────────────────────────

    def _answer(self, chat_id: int, domain: str, message_id: int | None = None,
                note: str = "") -> None:
        head = [note, ""] if note else []
        footer = self._block_footer(domain)
        lookups = self.lookups(domain)
        if not lookups:
            lines = head + [f"🔎 {domain} — nobody asked\nNo lookup in the last "
                            f"{self._lookback_days} days, as far as Pi-hole saw."]
            buttons = [[ui.button(f"🔎 Search for “{domain[:30]}”",
                                  self._key("f", domain[:63]))]]
            self._show(chat_id, message_id, "\n".join(lines + footer[0]),
                       buttons + footer[1] + [ui.nav_row(f"{self.ctx.name}:h")])
            return
        names = self._names_by_ip()
        router_ip = str(getattr(self.router, "host", ""))
        per_client = Counter(c for _, c in lookups)
        last = {c: max(t for t, cc in lookups if cc == c) for c in per_client}
        lines = head + [ui.title("🔎", domain, ui.plural(len(lookups), "lookup")),
                        f"In the last {self._lookback_days} days, asked by:"]
        via_router = False
        for client, n in per_client.most_common(8):
            when = ui.when_text(datetime.fromtimestamp(last[client]))
            if client == router_ip:
                via_router = True
                lines.append("📡 " + ui.item("A device behind the router", f"{n}×",
                                            f"last {when}"))
                lines.append("   Pi-hole can't see which one — see below.")
            else:
                who = names.get(client) or client
                lines.append("💻 " + ui.item(who, f"{n}×", f"last {when}"))

        buttons: list = []
        if via_router:
            times = sorted(t for t, c in lookups if c == router_ip)[-60:]
            suspects, considered = self.join_suspects(times)
            if suspects:
                lines.append("\nJoined the network just before those lookups:")
                macs = [mac for (mac, _hint), _hits in suspects[:4]]
                labels = ui.device_names(self.ctx, self.router, macs,
                                         fallback={mac: hint for (mac, hint), _ in suspects})
                for (mac, _hint), hits in suspects[:4]:
                    who = labels.get(mac, mac)
                    extra = mac if who != mac else ""
                    lines.append("👉 " + ui.item(who, f"{hits} of {considered} lookups", extra))
                top = suspects[0][1]
                if considered >= 3 and top * 2 > considered:
                    lines.append("That pattern makes the first one the likely source.")
            else:
                lines.append("\nNo device joined the network right before those "
                             "lookups, so the timing doesn't give it away.")
            if needle_for(domain):
                running = next(((tid, t) for tid, t in self._traces().items()
                                if t["domain"] == domain), None)
                if running:
                    tid, t = running
                    seen = ", ".join(t.get("seen", {}).values()) or "nobody yet"
                    lines.append(f"\n🎯 Already listening on the router — caught: {seen}.")
                    buttons.append([{"text": "⏹ Stop listening",
                                     "callback_data": self._key("x", tid)}])
                else:
                    lines.append("\n🎯 Find the device: a passive router rule notes who "
                                 "sends the next lookup. Asked every minute? Caught "
                                 "within a minute or two; you hear within 5.")
                    buttons.append([{"text": "🎯 Find the device",
                                     "callback_data": self._key("t", domain)}])
        self._show(chat_id, message_id, "\n".join(lines + footer[0]),
                   buttons + footer[1] + [ui.nav_row(f"{self.ctx.name}:h")])

    # ─── search ──────────────────────────────────────────────────

    def _on_text(self, payload: dict) -> None:
        """The one plain message the search prompt waits for."""
        chat_id = payload.get("chat_id")
        text = str(payload.get("text") or "").strip()
        if not chat_id or not text or text.startswith("/"):
            return
        wait = self._search_wait.pop(chat_id, None)
        if wait is None:
            return
        message_id, deadline = wait
        if time.time() > deadline:
            return
        term = search_term(text)
        if term is None:
            self._search_wait[chat_id] = wait
            self._show(chat_id, message_id,
                       "❌ Send 2–63 letters, digits, dots or dashes, e.g. baidu",
                       [[ui.button(f"{ui.CANCELLED} Cancel", f"{self.ctx.name}:h")]])
            return
        self._start_search(chat_id, message_id, term)

    def _on_any_command(self, payload: dict) -> None:
        """A command while the search prompt waits: stop waiting."""
        self._search_wait.pop(payload.get("chat_id"), None)

    def _start_search(self, chat_id: int, message_id: int | None, term: str) -> None:
        self._show(chat_id, message_id, f"⏳ Searching Pi-hole for “{term}”…", None)
        self._background(self._run_search, chat_id, message_id, term)

    def _run_search(self, chat_id: int, message_id: int | None, term: str) -> None:
        again = [ui.button("🔎 Search again", f"{self.ctx.name}:s")]
        nav = ui.nav_row(f"{self.ctx.name}:h")
        try:
            hits, more = self.search(term)
        except SearchError as e:
            self._show(chat_id, message_id, f"❌ Search for “{term}” failed: {e}",
                       [again, nav])
            return
        if not hits:
            self._show(chat_id, message_id,
                       f"🔎 “{term}” — nothing matched\nNo domain with “{term}” in "
                       "Pi-hole's history.", [again, nav])
            return
        names = self._names_by_ip()
        router_ip = str(getattr(self.router, "host", ""))
        shown = hits[:_SEARCH_SHOWN]
        lines = [ui.title("🔎", f"“{term}”", ui.plural(len(hits), "domain")
                          + ("+" if more else "")),
                 "Most asked first, whole Pi-hole history:"]
        for n, h in enumerate(shown, 1):
            who = []
            for client, count in h.clients.most_common(3):
                label = _ROUTER_CLIENTS if client == router_ip else (names.get(client) or client)
                who.append(f"{label} ({count:,}×)")
            if len(h.clients) > 3:
                who.append(f"+{len(h.clients) - 3} more")
            lines += [f"\n{n}. {h.domain} — {h.count:,}×",
                      f"   first {ui.when_text(h.first)} · last {ui.when_text(h.last)}",
                      f"   👥 {', '.join(who)}"]
        if len(hits) > len(shown) or more:
            lines.append(f"\nShowing {len(shown)} of {len(hits)}{'+' if more else ''}. "
                         "A longer word narrows it.")
        rows = [[{"text": f"🔎 {h.domain}"[:60], "callback_data": self._key("q", h.domain)}]
                for h in shown]
        self._show(chat_id, message_id, "\n".join(lines), rows + [again, nav])

    def search(self, term: str) -> tuple[list[DomainHit], bool]:
        """Domains containing ``term`` over Pi-hole's whole history, most asked first.

        Returns ``(hits, more)``; ``more`` is True when there were more matching
        names than were looked at. Raises :class:`SearchError`.
        """
        term = term.lower()
        if not 2 <= len(term) <= 63:
            raise SearchError("the word must be 2–63 characters")
        like = f"%{_like_escape(term)}%"
        deadline = time.monotonic() + _SEARCH_TIMEOUT_S
        try:
            con = sqlite3.connect(f"file:{self._ftl_db}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error as e:
            raise SearchError("Pi-hole's database can't be opened") from e
        # Returning non-zero aborts the running statement ("interrupted").
        con.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        try:
            tables = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")}
            if {"query_storage", "domain_by_id", "client_by_id"} <= tables:
                rows, more = self._search_v6(con, like)
            else:
                rows = con.execute(
                    "SELECT domain, client, COUNT(*), MIN(timestamp), MAX(timestamp) "
                    "FROM queries WHERE domain LIKE ? ESCAPE '\\' "
                    "GROUP BY domain, client LIMIT 5000", (like,)).fetchall()
                more = len(rows) >= 5000
        except sqlite3.OperationalError as e:
            if "interrupt" in str(e):
                raise SearchError(f"it took longer than {int(_SEARCH_TIMEOUT_S)} s — "
                                  "try a longer word") from e
            self.log.warning("who_asked: search failed: %s", e)
            raise SearchError("Pi-hole's database could not be read") from e
        except sqlite3.Error as e:
            self.log.warning("who_asked: search failed: %s", e)
            raise SearchError("Pi-hole's database could not be read") from e
        finally:
            con.close()
        found: dict[str, DomainHit] = {}
        for domain, client, n, first, last in rows:
            h = found.setdefault(str(domain), DomainHit(str(domain), first=float(first)))
            h.count += int(n)
            h.first = min(h.first, float(first))
            h.last = max(h.last, float(last))
            h.clients[str(client)] += int(n)
        return sorted(found.values(), key=lambda h: (-h.count, h.domain)), more

    @staticmethod
    def _search_v6(con: sqlite3.Connection, like: str) -> tuple[list, bool]:
        """Pi-hole v6 keeps names in side tables: match the (small) name table
        first, then count only those ids in the big one — no per-row lookups."""
        more = con.execute("SELECT COUNT(*) FROM (SELECT 1 FROM domain_by_id WHERE domain "
                           "LIKE ? ESCAPE '\\' LIMIT ?)",
                           (like, _SEARCH_DOMAINS + 1)).fetchone()[0] > _SEARCH_DOMAINS
        rows = con.execute(
            "SELECT d.domain, COALESCE(c.ip, q.client), COUNT(*), MIN(q.timestamp), "
            "MAX(q.timestamp) FROM query_storage q "
            "JOIN domain_by_id d ON d.id = q.domain "
            "LEFT JOIN client_by_id c ON c.id = q.client "
            "WHERE q.domain IN (SELECT id FROM domain_by_id WHERE domain LIKE ? "
            "ESCAPE '\\' LIMIT ?) GROUP BY q.domain, q.client",
            (like, _SEARCH_DOMAINS)).fetchall()
        return rows, more

    # ─── blocking ────────────────────────────────────────────────

    def _blocked_domains(self) -> list[str] | None:
        """NetSentry's own blocks in Pi-hole; None when Pi-hole can't be asked."""
        if self._pihole is None:
            return None
        try:
            return self._pihole.netsentry_blocks()
        except PiholeError as e:
            self.log.warning("who_asked: Pi-hole block list unavailable: %s", e)
            return None

    def _block_footer(self, domain: str) -> tuple[list[str], list]:
        """Lines and buttons for a domain's block state."""
        if self._pihole is None:
            return [], []
        blocked = self._blocked_domains() or []
        cover = next((b for b in blocked if domain == b or domain.endswith("." + b)), None)
        if cover:
            part = f" (as part of {cover})" if cover != domain else ""
            return ([f"\n⛔ Blocked by NetSentry{part}"],
                    [[{"text": f"↩️ Unblock {cover}"[:60] if part else "↩️ Unblock",
                       "callback_data": self._key("u", cover)}]])
        return [], [[{"text": f"⛔ Block {domain}"[:60],
                      "callback_data": self._key("b", domain)}]]

    def _change_block(self, domain: str, *, block: bool) -> str:
        if self._pihole is None:
            return "❌ Pi-hole did not accept it: pihole_api is not a valid URL"
        try:
            if block:
                self._pihole.block(domain)
            else:
                self._pihole.unblock(domain)
        except PiholeError as e:
            return f"❌ Pi-hole did not accept it: {e}"
        return (f"✅ Blocked {domain} in Pi-hole." if block
                else f"✅ Unblocked {domain} in Pi-hole.")

    def lookups(self, domain: str) -> list[tuple[float, str]]:
        """``(timestamp, client)`` for every Pi-hole query of ``domain`` or below it."""
        since = time.time() - self._lookback_days * 86400
        like = "%." + domain.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        try:
            con = sqlite3.connect(f"file:{self._ftl_db}?mode=ro", uri=True, timeout=5)
            try:
                rows = con.execute(
                    "SELECT timestamp, client FROM queries WHERE timestamp > ? AND "
                    "(domain = ? OR domain LIKE ? ESCAPE '\\') "
                    "ORDER BY timestamp DESC LIMIT 5000",
                    (since, domain, like)).fetchall()
            finally:
                con.close()
        except sqlite3.Error as e:
            self.log.warning("who_asked: Pi-hole database read failed: %s", e)
            return []
        return [(float(t), str(c)) for t, c in rows]

    def join_suspects(self, times: list[float]) -> tuple[list[tuple[tuple[str, str], int]], int]:
        """Devices that joined within ``join_window_s`` before the lookups.

        Returns ``([((mac, name-hint), matching lookups)], lookups considered)``;
        lookups older than the router's log are not considered.
        """
        try:
            events = self.router.join_events()
        except Exception:
            self.log.exception("who_asked: could not read join events")
            return [], 0
        if not events:
            return [], 0
        oldest = min(e.when for e in events).timestamp()
        usable = [t for t in times if t >= oldest]
        hints: dict[str, str] = {}
        for e in events:
            if e.name or e.network:
                hints.setdefault(e.mac, e.name or "")
                hints[e.mac] = hints[e.mac] or e.name
        tally: Counter[str] = Counter()
        for t in usable:
            joined = {e.mac for e in events
                      if 0 <= t - e.when.timestamp() <= self._join_window_s}
            tally.update(joined)
        ranked = [((mac, hints.get(mac, "")), n) for mac, n in tally.most_common()]
        return ranked, len(usable)

    # ─── tracing ─────────────────────────────────────────────────

    def start_trace(self, domain: str, chat_id: int) -> str:
        needle = needle_for(domain)
        if needle is None:
            return f"❌ {domain} has no part distinctive enough to listen for."
        with self._lock:
            traces = self._traces()
            if any(t["domain"] == domain for t in traces.values()):
                return f"🎯 Already listening for {domain}."
            if len(traces) >= 5:
                return "❌ Not started — five traces are already running. Stop one first."
            tid = secrets.token_hex(3)
            self._expected_change()
            if not self.router.dns_trace_add(tid, needle):
                return "❌ The router refused the logging rule; nothing was changed."
            traces[tid] = {"domain": domain, "needle": needle, "chat_id": chat_id,
                           "started": time.time(), "first_hit": 0.0, "seen": {}}
            self._save(traces)
        self.log.info("who_asked: tracing %s (rule %s)", domain, tid)
        return (f"🎯 Listening for {domain}.\n"
                "A passive rule on the router now notes who sends the next lookup "
                "— it blocks nothing. You'll get a message the moment it fires; the "
                f"rule removes itself afterwards, or after {self._trace_s // 86400} "
                "days if nothing asks.")

    def stop_trace(self, tid: str) -> bool:
        with self._lock:
            traces = self._traces()
            if tid not in traces:
                return False
            self._expected_change()
            if not self.router.dns_trace_remove(tid):
                self.log.warning("who_asked: could not remove router rule %s", tid)
                return False
            traces.pop(tid)
            self._save(traces)
        return True

    def poll(self) -> None:
        """Collect what the trace rules caught; report new devices; expire rules."""
        with self._lock:
            traces = self._traces()
            if not traces:
                return
            now = time.time()
            for tid, t in list(traces.items()):
                try:
                    hits = self.router.dns_trace_hits(tid)
                except Exception:
                    self.log.exception("who_asked: reading trace %s failed", tid)
                    continue
                for h in hits:
                    if h.mac in t["seen"]:
                        continue
                    who = ui.device_names(self.ctx, self.router, [h.mac]).get(h.mac, h.mac)
                    t["seen"][h.mac] = who if who != h.mac else "unnamed device"
                    t["first_hit"] = t["first_hit"] or now
                    # Unprompted, but the answer to a question the owner asked:
                    # "attention" (sound in normal mode, never dropped).
                    self._tell(t, notify.ATTENTION,
                               f"🎯 {t['domain']} — asked by {who}\n"
                               + ui.item(f"IP {h.ip}", f"MAC {h.mac}" if who != h.mac else "",
                                         f"via {h.interface}") + "\n"
                               f"At {ui.fmt_when(h.when)}")
                done = t["first_hit"] and now - t["first_hit"] > _KEEP_AFTER_HIT_S
                expired = now - t["started"] > self._trace_s
                if done or expired:
                    self._expected_change()
                    if not self.router.dns_trace_remove(tid):
                        continue                      # try again next round
                    traces.pop(tid)
                    if expired and not t["seen"]:
                        self._tell(t, notify.INFO,
                                   f"🎯 {t['domain']} — nobody asked\n"
                                   f"No lookup in {self._trace_s // 86400} days, so "
                                   "NetSentry stopped listening and removed the router rule.")
            self._save(traces)

    def health(self) -> list[HealthCheck]:
        overdue = [t["domain"] for t in self._traces().values()
                   if time.time() - t["started"] > self._trace_s + 86400]
        if overdue:
            return [HealthCheck("DNS trace rules", False,
                                "could not be removed from the router: " + ", ".join(overdue))]
        return []

    # ─── helpers ─────────────────────────────────────────────────

    def _tell(self, trace: dict, kind: str, text: str) -> None:
        try:
            self.notifier.notify(kind, text, chat_id=trace["chat_id"],
                                 buttons=[ui.nav_row(f"{self.ctx.name}:h")])
        except Exception:
            self.log.exception("who_asked: could not notify")

    def _expected_change(self) -> None:
        """Adding/removing our rule is our own router change, not tampering."""
        if self.ctx.events:
            self.ctx.events.publish("router.config.expected_change",
                                    {"source": "who_asked"})

    def _plugin(self, name: str) -> Plugin | None:
        return next((p for p in getattr(self.ctx, "_all_plugins", [])
                     if p.ctx.name == name), None)

    def _names_by_ip(self) -> dict[str, str]:
        det = self._plugin("threat_detector")
        try:
            if det is not None:
                return dict(det._device_names())
            return {lease.ip: lease.hostname for lease in self.router.dhcp_leases() or []
                    if lease.ip and lease.hostname}
        except Exception:
            return {}

    def _names_by_mac(self) -> dict[str, str]:
        try:
            return {lease.mac.upper(): lease.hostname
                    for lease in self.router.dhcp_leases() or []
                    if lease.mac and lease.hostname}
        except Exception:
            return {}

    def _traces(self) -> dict[str, dict]:
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, traces: dict[str, dict]) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(traces), encoding="utf-8")
        tmp.replace(self._file)
