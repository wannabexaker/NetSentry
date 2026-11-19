"""threat_detector · what is kept on disk.

Three files in the plugin's state folder:

* ``state.json``   — baselines, the allow-list, detector switches, audit window
* ``alerts.jsonl`` — append-only log of every finding
* ``domains.json`` — the domain journal (first/last seen, who asked, your notes)

Several threads read-modify-write ``state.json`` (the scan, the daily report,
the WiFi monitor, the Telegram commands), so every access goes through
``_state_lock`` and every write is atomic.
"""

from __future__ import annotations

import json
import os
from datetime import datetime


# State keys a detection cycle computes itself. Everything else in the state
# file (allow-list, detector toggles, audit window, report timestamp) belongs to
# other threads and is never written back from a cycle's stale copy.
_CYCLE_KEYS = (
    "initialized", "known_domains", "ip_mac",
    "drift_ts", "config_baseline", "exposure_ts", "exposure_baseline",
)


class StoreMixin:
    """Persistence for :class:`ThreatDetectorPlugin` (mixed into it)."""

    def _state(self) -> dict:
        with self._state_lock:
            try:
                text = self._state_file.read_text(encoding="utf-8")
            except FileNotFoundError:
                return {}
            except OSError:
                self.log.exception("threat_detector: state file unreadable")
                return {}
            try:
                data = json.loads(text)
                if not isinstance(data, dict):
                    raise ValueError("state is not a JSON object")
                return data
            except ValueError:
                # Never silently start over on top of a damaged file: keep it
                # for inspection, say so loudly, then re-baseline.
                aside = self._state_file.with_suffix(".json.corrupt")
                try:
                    os.replace(self._state_file, aside)
                except OSError:
                    pass
                self.log.error(
                    "threat_detector: state file was corrupt - kept as %s and "
                    "starting from a fresh baseline (allow-list and detector "
                    "toggles must be re-applied)", aside.name)
                return {}

    def _save(self, s: dict) -> None:
        """Atomic replace, so a reader (or a crash) never sees a half-written file."""
        with self._state_lock:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(s, indent=2), encoding="utf-8")
            os.replace(tmp, self._state_file)

    def _record_alert(self, kind: str, event: str, details: dict) -> None:
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": kind,
            "event": event,
            "details": details,
        }
        self._alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with self._alerts_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def _journal(self) -> dict:
        try:
            return json.loads(self._journal_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_journal(self, j: dict) -> None:
        # Keep the newest 15k domains by last_seen to bound the file.
        if len(j) > 15000:
            keep = sorted(j.items(), key=lambda kv: kv[1].get("last_seen", ""))[-15000:]
            j = dict(keep)
        self._journal_file.parent.mkdir(parents=True, exist_ok=True)
        self._journal_file.write_text(json.dumps(j, indent=1, sort_keys=True))

    def _update_journal(self, domain_clients: dict[str, set[str]], now_iso: str) -> dict:
        """Record first/last-seen + which client(s) asked, per domain."""
        j = self._journal()
        for dom, clients in domain_clients.items():
            entry = j.get(dom)
            if entry is None:
                j[dom] = {
                    "first_seen": now_iso, "last_seen": now_iso,
                    "clients": sorted(clients), "count": 1, "note": "",
                }
            else:
                entry["last_seen"] = now_iso
                entry["clients"] = sorted(set(entry.get("clients", [])) | clients)
                entry["count"] = int(entry.get("count", 0)) + 1
        self._save_journal(j)
        return j

    def _alerts_since(self, since_iso: str) -> list[dict]:
        out: list[dict] = []
        try:
            for line in self._alerts_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("event") == "alert" and e.get("ts", "") >= since_iso:
                    out.append(e)
        except Exception:
            pass
        return out
