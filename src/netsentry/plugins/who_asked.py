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

Everything is reachable by buttons: `/who` lists the recently flagged domains.

Config keys:
    ftl_db_path        Pi-hole FTL database (default /etc/pihole/pihole-FTL.db)
    lookback_days      how far back to read Pi-hole (default 30)
    join_window_s      "seconds after joining" that counts as a match (default 15)
    trace_days         a trace gives up and removes its rule after this (default 7)
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from ..core.plugin import HealthCheck, Plugin, ScheduledTask

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)[a-z0-9_]([a-z0-9_-]{0,62}\.)+[a-z0-9-]{2,63}$")
_KEEP_AFTER_HIT_S = 3600        # keep listening a little after the first catch


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
        {"command": "who", "description": "🔎 Which device asks for a domain: /who <domain>"},
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

    def scheduled_tasks(self) -> list[ScheduledTask]:
        return [ScheduledTask(cron="*/5 * * * *", func=self.poll, name="poll")]

    # ─── commands & buttons ──────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/who":
            return
        domain = args.strip().lower().strip(".")
        if not domain:
            self._show_home(chat_id, None)
        elif not _DOMAIN_RE.match(domain):
            self.notifier.send_to(chat_id, "❌ That doesn't look like a domain name.")
            self._show_home(chat_id, None)
        else:
            self._answer(chat_id, domain)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # <plugin>:q:<domain> ask | :t:<domain> start a trace | :x:<id> stop | :h home
        _, verb, arg = (data.split(":", 2) + ["", ""])[:3]
        arg = self._refs.get(arg, arg)
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "q" and _DOMAIN_RE.match(arg):
            ack("Looking…")
            self._answer(chat_id, arg)
        elif verb == "t" and _DOMAIN_RE.match(arg):
            ack()
            self.notifier.send_to(chat_id, self.start_trace(arg, chat_id))
        elif verb == "x":
            ack("Stopped" if self.stop_trace(arg) else "Already gone")
            self._show_home(chat_id, message_id)
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

    def _show_home(self, chat_id: int, message_id: int | None) -> None:
        lines = ["🔎 Which device is asking for a domain?",
                 "━━━━━━━━━━━━━━━━━",
                 "Tap a recently flagged domain, or type /who example.com"]
        rows = [[{"text": f"🔎 {d}"[:60], "callback_data": self._key("q", d)}]
                for d in self._flagged_domains()]
        traces = self._traces()
        if traces:
            lines.append("\nListening on the router for:")
            for tid, t in traces.items():
                seen = ", ".join(t.get("seen", {})) or "nothing yet"
                lines.append(f"  🎯 {t['domain']} — {seen}")
                rows.append([{"text": f"⏹ Stop listening for {t['domain']}"[:60],
                              "callback_data": self._key("x", tid)}])
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, "\n".join(lines), buttons=rows)
        else:
            self.notifier.send_to(chat_id, "\n".join(lines), buttons=rows or None)

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

    def _answer(self, chat_id: int, domain: str) -> None:
        lookups = self.lookups(domain)
        if not lookups:
            self.notifier.send_to(
                chat_id, f"🔎 {domain}\nNobody has asked for it in the last "
                         f"{self._lookback_days} days (as far as Pi-hole saw).")
            return
        names = self._names_by_ip()
        router_ip = str(getattr(self.router, "host", ""))
        per_client = Counter(c for _, c in lookups)
        last = {c: max(t for t, cc in lookups if cc == c) for c in per_client}
        lines = [f"🔎 {domain}",
                 f"{len(lookups)} lookups in the last {self._lookback_days} days",
                 "━━━━━━━━━━━━━━━━━"]
        via_router = False
        for client, n in per_client.most_common(8):
            when = datetime.fromtimestamp(last[client]).strftime("%d %b %H:%M")
            if client == router_ip:
                via_router = True
                lines.append(f"📡 through the router — {n}×, last {when}\n"
                             "     (a device behind it; Pi-hole can't see which)")
            else:
                who = names.get(client) or client
                lines.append(f"💻 {who} — {n}×, last {when}")

        buttons: list = []
        if via_router:
            times = sorted(t for t, c in lookups if c == router_ip)[-60:]
            suspects, considered = self.join_suspects(times)
            if suspects:
                lines.append("\nWho joined the network just before those lookups:")
                mac_names = self._names_by_mac()
                for (mac, hint), hits in suspects[:4]:
                    who = mac_names.get(mac) or hint or "unnamed device"
                    lines.append(f"  👉 {who} ({mac}) — {hits} of {considered} lookups")
                top = suspects[0][1]
                if considered >= 3 and top * 2 > considered:
                    lines.append("That pattern makes the first one the likely source.")
            else:
                lines.append("\nNo device joined the network right before those "
                             "lookups, so the timing doesn't give it away.")
            if needle_for(domain):
                lines.append("To be certain, catch the sender red-handed:")
                buttons.append([{"text": "🎯 Catch it on its next request",
                                 "callback_data": self._key("t", domain)}])
        self.notifier.send_to(chat_id, "\n".join(lines), buttons=buttons or None)

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
                return "❌ Five traces are already running — stop one first (/who)."
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
            names = self._names_by_mac()
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
                    who = names.get(h.mac) or "unnamed device"
                    t["seen"][h.mac] = who
                    t["first_hit"] = t["first_hit"] or now
                    self._tell(t, f"🎯 Caught it: {t['domain']}\n"
                                  f"was requested by {who}\n"
                                  f"  MAC {h.mac} · IP {h.ip} · via {h.interface}\n"
                                  f"  at {h.when:%d %b %H:%M:%S}")
                done = t["first_hit"] and now - t["first_hit"] > _KEEP_AFTER_HIT_S
                expired = now - t["started"] > self._trace_s
                if done or expired:
                    self._expected_change()
                    if not self.router.dns_trace_remove(tid):
                        continue                      # try again next round
                    traces.pop(tid)
                    if expired and not t["seen"]:
                        self._tell(t, f"🎯 Nothing asked for {t['domain']} in "
                                      f"{self._trace_s // 86400} days — stopped "
                                      "listening and removed the router rule.")
            self._save(traces)

    def health(self) -> list[HealthCheck]:
        overdue = [t["domain"] for t in self._traces().values()
                   if time.time() - t["started"] > self._trace_s + 86400]
        if overdue:
            return [HealthCheck("DNS trace rules", False,
                                "could not be removed from the router: " + ", ".join(overdue))]
        return []

    # ─── helpers ─────────────────────────────────────────────────

    def _tell(self, trace: dict, text: str) -> None:
        try:
            self.notifier.send_to(trace["chat_id"], text)
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
