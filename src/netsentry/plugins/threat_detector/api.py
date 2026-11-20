"""threat_detector · the API other plugins call.

The web dashboard reads and changes detector settings through the ``api_*``
methods; ``record_finding`` is how another plugin (the WiFi monitor) hands in a
finding of its own so it is logged, reported and explained like the rest.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from ...core import notify, ui
from . import threat_intel
from .taxonomy import _ID_TO_KIND, _SCANS, _SEV_ICON, _label


class ApiMixin:
    """Programmatic API of :class:`ThreatDetectorPlugin` (mixed into it)."""

    def api_domains(self) -> list[dict]:
        """The domain journal as rows for the web UI."""
        journal = self._journal()
        names = self._device_names()
        allow = self._effective_allow_suffixes()

        def is_allowed(d: str) -> bool:
            return any(d == a or d.endswith("." + a) for a in allow)

        rows = []
        for d, m in journal.items():
            rows.append({
                "domain": d,
                "first_seen": m.get("first_seen", ""),
                "last_seen": m.get("last_seen", ""),
                "count": int(m.get("count", 0)),
                "clients": [self._label_client(c, names) for c in m.get("clients", [])],
                "note": m.get("note", ""),
                "allowed": is_allowed(d),
            })
        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        return rows

    def api_set_allow(self, domain: str, on: bool) -> None:
        domain = (domain or "").strip().lower().strip(".")
        if not domain:
            return
        with self._state_lock:
            state = self._state()
            cur = state.get("allowed_domains", [])
            if on and domain not in cur:
                cur.append(domain)
                state["allowed_domains"] = cur
                state["alerted"] = [
                    a for a in state.get("alerted", []) if not a.endswith(":" + domain)
                ]
                self._save(state)
            elif not on and domain in cur:
                cur.remove(domain)
                state["allowed_domains"] = cur
                self._save(state)

    def api_set_note(self, domain: str, text: str) -> None:
        domain = (domain or "").strip().lower().strip(".")
        if not domain:
            return
        journal = self._journal()
        entry = journal.get(domain)
        if entry is None:
            now = datetime.now().isoformat(timespec="seconds")
            entry = {"first_seen": now, "last_seen": now, "clients": [], "count": 0}
            journal[domain] = entry
        entry["note"] = (text or "")[:200]
        self._save_journal(journal)

    def api_scans(self) -> list[dict]:
        enabled = self._enabled()
        return [
            {"key": k, "id": _SCANS[k]["id"], "enabled": enabled[k],
             "label": _SCANS[k]["label"], "severity": _SCANS[k]["severity"],
             "means": _SCANS[k]["means"]}
            for k in _SCANS
        ]

    _DOMAIN_KINDS = frozenset(
        {"known_malicious", "dns_tunnel", "suspicious_tld", "new_domain"}
    )
    def api_taxonomy(self) -> list[dict]:
        """The full finding catalogue (one row per NS id), for a reference page."""
        enabled = self._enabled()
        out = []
        for k, s in _SCANS.items():
            out.append({
                "id": s["id"], "kind": k, "label": s["label"],
                "severity": s["severity"], "confidence": s.get("confidence", ""),
                "mitre": s.get("mitre", "-"), "enabled": enabled.get(k, False),
            })
        return out

    def api_explainer(self, nsid: str) -> dict | None:
        """Everything about one finding type + its recent live instances.

        Powers the Telegram deep-link target (``/finding/<id>``): what it is,
        why it matters, the common false positives, what to do, and the actual
        matches on this network right now.
        """
        kind = _ID_TO_KIND.get((nsid or "").strip().upper())
        if not kind:
            return None
        s = _SCANS[kind]
        instances = [f for f in self.api_findings(500) if f.get("type") == kind][:50]
        return {
            "id": s["id"], "kind": kind, "label": s["label"],
            "severity": s["severity"], "confidence": s.get("confidence", ""),
            "mitre": s.get("mitre", "-"),
            "means": s.get("means", ""), "fp": s.get("fp", ""),
            "action": s.get("action", ""), "needs": s.get("needs", ""),
            "enabled": self._enabled().get(kind, False),
            "domain_subject": kind in self._DOMAIN_KINDS,
            "instances": instances,
        }

    def explain_id(self, kind: str) -> str:
        """The NS id for a finding kind (empty if unknown)."""
        return _SCANS.get(kind, {}).get("id", "")

    def record_finding(self, kind: str, subject: str, detail: str, *,
                       clients: list[str] | None = None, immediate: bool = False) -> bool:
        """Ingest a finding produced by another plugin (e.g. wifi_monitor) into
        the unified pipeline: dedup by (kind, subject), record to the audit log
        so it shows in the dashboard / reports / explainer, and optionally push
        it right away with its NS id + explain deep-link. Returns True if newly
        recorded.
        """
        if kind not in _SCANS or not subject:
            return False
        if not self._enabled().get(kind, True):
            return False
        key = f"{kind}:{subject}"
        with self._state_lock:
            state = self._state()
            alerted = set(state.get("alerted", []))
            if key in alerted:
                return False
            alerted.add(key)
            state["alerted"] = sorted(alerted)[-40000:]
            self._save(state)
        sev = _SCANS[kind]["severity"]
        self._record_alert(kind, "alert", {
            "subject": subject, "detail": detail, "severity": sev,
            "clients": clients or [],
        })
        if immediate or self._immediate_attacks:
            nsid = _SCANS[kind]["id"]
            msg = "\n".join([
                ui.header(_SEV_ICON.get(sev, ui.INFO), _label(kind), subject),
                detail,
                f"What to do: {_SCANS[kind].get('action', '')}",
                f"Finding {nsid}",
            ])
            buttons = ui.rows(ui.url_row((f"❓ About {nsid}", self._explain_link(kind))),
                              ui.nav_row())
            # How loud follows the finding: an attack is urgent, a warning needs
            # the owner, an info finding is FYI (not sent in relaxed mode).
            kind = {"attack": notify.URGENT, "warning": notify.ATTENTION}.get(sev, notify.INFO)
            try:
                self.notifier.notify(kind, msg, buttons=buttons)
            except Exception:
                self.log.exception("record_finding push failed")
        return True

    def api_set_scan(self, key: str, on: bool) -> bool:
        if key not in _SCANS:
            return False
        with self._state_lock:
            state = self._state()
            overrides = state.get("scans_enabled", {})
            overrides[key] = bool(on)
            state["scans_enabled"] = overrides
            self._save(state)
        return True

    def api_intel(self) -> dict:
        feed_map, ts = threat_intel.load(self._intel_file)
        return {"count": len(feed_map), "updated": ts}

    def api_findings(self, limit: int = 50) -> list[dict]:
        out = []
        for e in self._alerts_since("")[-limit:][::-1]:
            d = e.get("details", {})
            kind = e.get("type", "")
            out.append({
                "ts": e.get("ts", ""), "type": kind,
                "id": _SCANS.get(kind, {}).get("id", ""),
                "label": _label(kind), "severity": d.get("severity", ""),
                "subject": d.get("subject", ""), "detail": d.get("detail", ""),
                "clients": d.get("clients", []),
            })
        return out

    def api_recent_findings(self, warn_hours: int = 24, attack_hours: int = 168) -> list[dict]:
        """Findings relevant *now* for the at-a-glance verdict.

        Filters the accumulated ``alerts.jsonl`` audit history down to what a
        human should actually act on, so the banner is not permanently pinned:

        * ``new_domain`` is dropped — that is domain *discovery*, already shown
          in the Threats domain table; it is not a threat verdict input.
        * subjects the operator has trusted (allow-list) are dropped.
        * attack-severity is kept for ``attack_hours`` (default 7d), everything
          else for ``warn_hours`` (default 24h).
        """
        now = datetime.now()
        warn_cut = now - timedelta(hours=warn_hours)
        attack_cut = now - timedelta(hours=attack_hours)
        allow = self._effective_allow_suffixes()

        def is_trusted(subject: str) -> bool:
            s = (subject or "").lower().strip(".")
            return any(s == a or s.endswith("." + a) for a in allow)

        out: list[dict] = []
        for f in self.api_findings(500):
            if f.get("type") == "new_domain" or is_trusted(f.get("subject", "")):
                continue
            try:
                when = datetime.fromisoformat(f.get("ts", ""))
            except ValueError:
                continue
            cut = attack_cut if f.get("severity") == "attack" else warn_cut
            if when >= cut:
                out.append(f)
        return out
