"""threat_detector · turning findings into messages.

The per-scan digest (one message instead of one per finding) and the delivered
report (scheduled, and on demand with ``/report``).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .detectors import Finding
from .taxonomy import _SCANS, _SEV_ICON, _label


class ReportsMixin:
    """Report building for :class:`ThreatDetectorPlugin` (mixed into it)."""

    def _build_digest(
        self,
        findings: list[Finding],
        domain_clients: dict[str, set[str]],
        names: dict[str, str],
    ) -> str:
        """One clear, plain-text message: what happened, why it matters, who."""
        if not findings:
            return ""
        alerts = [f for f in findings if f.kind != "new_domain"]
        new = [f for f in findings if f.kind == "new_domain"]

        header_bits = []
        if alerts:
            header_bits.append(f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}")
        if new:
            header_bits.append(f"{len(new)} new domain{'s' if len(new) != 1 else ''}")
        lines = [
            "🛡 Homelab Monitor — " + (" · ".join(header_bits) or "all clear"),
            datetime.now().strftime("%Y-%m-%d %H:%M"),
        ]

        by_kind: dict[str, list[Finding]] = defaultdict(list)
        for f in alerts:
            by_kind[f.kind].append(f)
        for kind in _SCANS:  # severity/display order
            group = by_kind.get(kind)
            if not group:
                continue
            icon = _SEV_ICON.get(_SCANS[kind]["severity"], "•")
            nsid = _SCANS[kind]["id"]
            lines.append("")
            lines.append(f"{icon} {_label(kind)} ({len(group)})  [{nsid}]")
            lines.append(f"  ↳ {_SCANS[kind]['means']}")
            for f in group[: self._max_alert_lines]:
                who = ", ".join(
                    self._label_client(c, names)
                    for c in sorted(self._clients_for(f, domain_clients))[:3]
                )
                lines.append(
                    f"  • {f.subject} — {f.detail}" + (f"  ·  {who}" if who else "")
                )
            if len(group) > self._max_alert_lines:
                lines.append(f"  … +{len(group) - self._max_alert_lines} more")
            action = _SCANS[kind].get("action")
            if action:
                lines.append(f"  👉 {action}")
            link = self._explain_link(kind)
            if link:
                lines.append(f"  🔎 Explain {nsid}: {link}")

        if new:
            per_device: dict[str, int] = defaultdict(int)
            for f in new:
                for c in self._clients_for(f, domain_clients) or {"?"}:
                    per_device[c] += 1
            top = sorted(per_device.items(), key=lambda kv: kv[1], reverse=True)
            lines.append("")
            lines.append(f"ℹ️ New domains ({len(new)}) — by device:")
            for ip, count in top[:6]:
                lines.append(f"  • {self._label_client(ip, names)}: {count}")
            lines.append(
                "  e.g. " + ", ".join(f.subject for f in new[: self._max_new_examples])
            )

        lines.append("")
        lines.append("↳ /threats live · /threatlog history · /scans on·off")
        return "\n".join(lines)

    def _dashboard(self):
        """The lan_dashboard sibling plugin, for building deep-links."""
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(getattr(p, "ctx", None), "name", "") == "lan_dashboard":
                return p
        return None

    def _explain_link(self, kind: str) -> str:
        """One-click Telegram→dashboard explainer link for a finding kind."""
        dash = self._dashboard()
        nsid = _SCANS.get(kind, {}).get("id", "")
        return dash.explain_url(nsid) if (dash and nsid) else ""

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

        lines = [f"🛡 {title}", f"since {since_iso[:16].replace('T', ' ')}", ""]

        # Verdict first — tell the operator whether anything needs them.
        if total_alerts == 0:
            lines.append("✅ Nothing needs your attention.")
        else:
            lines.append(f"⚠️ {total_alerts} item(s) to review — actions are below each one.")
        dash = self._dashboard()
        home = dash.deep_link("/threats") if dash else ""
        if home:
            lines.append(f"🔎 Open dashboard: {home}")

        # Audit context — explain a high new-domain count is expected, not scary.
        audit_until = self._state().get("audit_until")
        if audit_until and datetime.now().isoformat() < audit_until:
            lines.append(
                f"📋 Audit mode is ON (until {audit_until[:16].replace('T', ' ')}): "
                "every new domain is being *recorded*, not alerted — a high count "
                "here is expected and normal."
            )

        for kind in _SCANS:
            group = real.get(kind)
            if not group:
                continue
            icon = _SEV_ICON.get(_SCANS[kind]["severity"], "•")
            nsid = _SCANS[kind]["id"]
            lines.append(f"\n{icon} {_label(kind)} ({len(group)})  [{nsid}]")
            lines.append(f"  ↳ {_SCANS[kind]['means']}")
            for e in group[: self._max_alert_lines]:
                d = e.get("details", {})
                who = ", ".join(
                    self._label_client(c, names) for c in (d.get("clients") or [])[:3]
                )
                lines.append(
                    f"  • {d.get('subject', '')} — {d.get('detail', '')}"
                    + (f"  ·  {who}" if who else "")
                )
            action = _SCANS[kind].get("action")
            if action:
                lines.append(f"  👉 {action}")
            link = dash.explain_url(nsid) if dash else ""
            if link:
                lines.append(f"  🔎 Explain {nsid}: {link}")

        if new_doms:
            per_device: dict[str, int] = defaultdict(int)
            for _d, m in new_doms:
                for c in m.get("clients", []) or ["?"]:
                    per_device[c] += 1
            lines.append(f"\nℹ️ New domains ({len(new_doms)}) — by device:")
            for ip, count in sorted(per_device.items(), key=lambda kv: -kv[1])[:8]:
                lines.append(f"  • {self._label_client(ip, names)}: {count}")
            lines.append(
                "  e.g. " + ", ".join(d for d, _ in new_doms[: self._max_new_examples])
            )
            lines.append(
                "  ↳ These are records, not alarms. Browse /domains, label /note."
            )

        lines.append("\n── What you can do ──")
        lines.append("✅ /allow <domain>  — trust it, stop the alert (e.g. false alarms)")
        lines.append("📝 /note <domain> <text>  — label it so you remember what it is")
        lines.append("📇 /domains <search>  — full history  ·  🎛 /scans  — detectors on/off")
        return "\n".join(lines)

    def send_report(self) -> None:
        """Scheduled delivery: report since the last report, then advance."""
        state = self._state()
        since = state.get("last_report_ts") or (
            datetime.now() - timedelta(days=1)
        ).isoformat(timespec="seconds")
        report = self._build_report(since, "Homelab Monitor — periodic report")
        try:
            self.notifier.send(report, buttons=self._report_trust_buttons(since) or None)
        except Exception:
            self.log.exception("scheduled report send failed")
        with self._state_lock:
            state = self._state()
            state["last_report_ts"] = datetime.now().isoformat(timespec="seconds")
            self._save(state)
