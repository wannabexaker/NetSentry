"""threat_detector · turning findings into messages.

The per-scan digest (one message instead of one per finding) and the delivered
report (scheduled, and on demand with ``/report``). Both lead with the verdict,
give one line per kind of finding (three subjects at most) and put links and
next steps on buttons, never in the text.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from ...core import notify, ui
from .detectors import Finding
from .taxonomy import _SCANS, _SEV_ICON, _label

SHIELD = "🛡"


class ReportsMixin:
    """Report building for :class:`ThreatDetectorPlugin` (mixed into it)."""

    # ─── shared pieces ──────────────────────────────────────────

    def _kind_line(self, kind: str, subjects: list[str], clients: list[str],
                   names: dict[str, str]) -> str:
        """``🚨 DNS tunnel / DGA (2): a.com, b.com — from Phone (192.0.2.5)``."""
        icon = _SEV_ICON.get(_SCANS.get(kind, {}).get("severity", ""), "•")
        unique = list(dict.fromkeys(s for s in subjects if s))
        line = f"{icon} {_label(kind)} ({len(subjects)}): {ui.first_few(unique, 3)}"
        who = list(dict.fromkeys(self._label_client(c, names) for c in clients if c))
        if who:
            line += f" — from {ui.first_few(who, 2)}"
        return line

    def _new_domains_line(self, count: int, per_device: dict[str, int],
                          names: dict[str, str], examples: list[str]) -> list[str]:
        top = sorted(per_device.items(), key=lambda kv: kv[1], reverse=True)[:3]
        most = ", ".join(f"{self._label_client(ip, names) if ip != '?' else 'unknown'} "
                         f"({n})" for ip, n in top)
        out = [f"ℹ️ {ui.plural(count, 'new domain')}" + (f" — most from {most}" if most else "")]
        if examples:
            out.append(f"   e.g. {ui.first_few(examples, 3)}")
        return out

    def _audit_line(self) -> str | None:
        audit_until = self._state().get("audit_until")
        if audit_until and datetime.now().isoformat() < audit_until:
            return (f"📋 Audit mode is on until {ui.when_text(audit_until)} — every new "
                    "domain is recorded, so a high count is expected.")
        return None

    def _view_row(self, *views: tuple[str, str]) -> list[dict[str, str]]:
        """Buttons that open one of this plugin's screens as a new message."""
        return [ui.button(text, f"{self.ctx.name}:v:{view}") for text, view in views]

    def _link_rows(self, kinds: list[str]) -> list[list[dict[str, str]]]:
        """URL buttons to the dashboard (only when it has a public address)."""
        dash = self._dashboard()
        if dash is None:
            return []
        cells = ui.url_row(("🖥 Open in dashboard", dash.deep_link("/threats")))
        for kind in kinds[:3]:
            nsid = _SCANS.get(kind, {}).get("id", "")
            cells += ui.url_row((f"❓ {_label(kind)}"[:40], dash.explain_url(nsid) if nsid else ""))
        return [cells[i:i + 2] for i in range(0, len(cells), 2)]

    # ─── /threats digest (and the opt-in instant attack push) ───

    def _build_digest(
        self,
        findings: list[Finding],
        domain_clients: dict[str, set[str]],
        names: dict[str, str],
        headline: str | None = None,
    ) -> str:
        """One plain-text message: the verdict, then one line per kind."""
        if not findings:
            return ""
        alerts = [f for f in findings if f.kind != "new_domain"]
        new = [f for f in findings if f.kind == "new_domain"]
        verdict = (f"{ui.ATTENTION} {ui.plural(len(alerts), 'finding')}" if alerts
                   else f"{ui.OK} nothing to review")
        lines = [headline or ui.header(SHIELD, "Live check", verdict),
                 f"Last {self._window_min} min · {ui.fmt_when(datetime.now())}", ui.RULE]

        by_kind: dict[str, list[Finding]] = defaultdict(list)
        for f in alerts:
            by_kind[f.kind].append(f)
        for kind in _SCANS:  # severity/display order
            group = by_kind.get(kind)
            if not group:
                continue
            clients: list[str] = []
            for f in group:
                clients += sorted(self._clients_for(f, domain_clients))
            lines.append(self._kind_line(kind, [f.subject for f in group], clients, names))

        if new:
            per_device: dict[str, int] = defaultdict(int)
            for f in new:
                for c in self._clients_for(f, domain_clients) or {"?"}:
                    per_device[c] += 1
            lines += self._new_domains_line(len(new), per_device, names,
                                            [f.subject for f in new])
        return "\n".join(lines)

    def _digest_buttons(self, findings: list[Finding]) -> list:
        trust = self._trust_buttons(
            [f.subject for f in findings
             if f.kind in self._DOMAIN_KINDS and f.kind != "new_domain"])
        kinds = list(dict.fromkeys(f.kind for f in findings if f.kind != "new_domain"))
        return (trust
                + [self._view_row(("📜 Finding log", "log"), ("🎛 Detectors", "scans"))]
                + self._link_rows(kinds)
                + [[ui.refresh_button(f"{self.ctx.name}:v:threats"), *ui.nav_row()]])

    def _dashboard(self):
        """The lan_dashboard sibling plugin, for building deep-links."""
        return ui.plugin_named(self.ctx, "lan_dashboard")

    def _explain_link(self, kind: str) -> str:
        """Telegram→dashboard explainer link for a finding kind ('' when none)."""
        dash = self._dashboard()
        nsid = _SCANS.get(kind, {}).get("id", "")
        return dash.explain_url(nsid) if (dash and nsid) else ""

    # ─── the report ─────────────────────────────────────────────

    def _build_report(self, since_iso: str, title: str) -> str:
        alerts = self._alerts_since(since_iso)
        journal = self._journal()
        new_doms = [
            (d, m) for d, m in journal.items() if m.get("first_seen", "") >= since_iso
        ]
        names = self._device_names()
        by_kind: dict[str, list[dict]] = defaultdict(list)
        for e in alerts:
            by_kind[e.get("type", "")].append(e)
        real = {k: v for k, v in by_kind.items() if k != "new_domain"}
        total_alerts = sum(len(v) for v in real.values())

        verdict = (f"{ui.ATTENTION} {total_alerts} to review" if total_alerts
                   else f"{ui.OK} nothing to review")
        lines = [ui.header(SHIELD, title, verdict),
                 f"Since {ui.when_text(since_iso, default='the start')}", ui.RULE]

        for kind in _SCANS:
            group = real.get(kind)
            if not group:
                continue
            subjects = [e.get("details", {}).get("subject", "") for e in group]
            clients = [c for e in group for c in (e.get("details", {}).get("clients") or [])]
            lines.append(self._kind_line(kind, subjects, clients, names))
        if not total_alerts:
            lines.append("No findings — your network looked normal.")

        if new_doms:
            per_device: dict[str, int] = defaultdict(int)
            for _d, m in new_doms:
                for c in m.get("clients", []) or ["?"]:
                    per_device[c] += 1
            lines += self._new_domains_line(len(new_doms), per_device, names,
                                            [d for d, _ in new_doms])
        audit = self._audit_line()
        if audit:
            lines.append(audit)
        if total_alerts:
            lines.append("")
            lines.append("Something you recognise? Tap ✅ Trust below and it won't be "
                         "flagged again.")
        return "\n".join(lines)

    def _report_buttons(self, since_iso: str) -> list:
        kinds = list(dict.fromkeys(
            e.get("type", "") for e in self._alerts_since(since_iso)
            if e.get("type") and e.get("type") != "new_domain"))
        return (self._report_trust_buttons(since_iso)
                + [self._view_row(("📇 Domains", "domains"), ("🎛 Detectors", "scans"))]
                + self._link_rows(kinds)
                + [ui.nav_row()])

    def _report_title(self, scheduled: bool) -> str:
        if not scheduled:
            return "Report"
        fields = self._report_cron.split()
        return "Daily report" if len(fields) == 5 and fields[2:] == ["*", "*", "*"] \
            else "Scheduled report"

    def send_report(self) -> None:
        """Scheduled delivery: report since the last report, then advance."""
        state = self._state()
        since = state.get("last_report_ts") or (
            datetime.now() - timedelta(days=1)
        ).isoformat(timespec="seconds")
        report = self._build_report(since, self._report_title(True))
        try:
            self.notifier.notify(notify.REPORT, report, buttons=self._report_buttons(since))
        except Exception:
            self.log.exception("scheduled report send failed")
        with self._state_lock:
            state = self._state()
            state["last_report_ts"] = datetime.now().isoformat(timespec="seconds")
            self._save(state)
