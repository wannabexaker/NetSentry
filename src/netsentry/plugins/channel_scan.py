"""
channel_scan — Weekly WiFi neighbor scan + /scan command.

Triggers a passive scan on the 5 GHz radio, parses neighbors, scores
candidate channels, suggests cleanest channel via Telegram. Does NOT
auto-apply channel changes.
"""

from __future__ import annotations

import re
import threading

from ..core.plugin import Plugin, ScheduledTask


CANDIDATE_CHANNELS = [
    (5180, 36, "UNII-1"),  (5200, 40, "UNII-1"),  (5220, 44, "UNII-1"),  (5240, 48, "UNII-1"),
    (5260, 52, "UNII-2A DFS"), (5280, 56, "UNII-2A DFS"),
    (5300, 60, "UNII-2A DFS"), (5320, 64, "UNII-2A DFS"),
    (5500,100, "UNII-2C DFS"), (5520,104, "UNII-2C DFS"),
    (5540,108, "UNII-2C DFS"), (5660,132, "UNII-2C DFS"),
    (5680,136, "UNII-2C DFS"), (5700,140, "UNII-2C DFS"),
    (5745,149, "UNII-3"),  (5765,153, "UNII-3"),
    (5785,157, "UNII-3"),  (5805,161, "UNII-3"),
]


class ChannelScanPlugin(Plugin):
    COMMANDS = [
        {"command": "scan", "description": "📡 Trigger WiFi neighbor scan now"},
    ]

    def on_load(self) -> None:
        self._iface = self.cfg.get("scan_interface", "wifi1")
        self._duration = int(self.cfg.get("scan_duration_seconds", 10))
        self._save_file = "wifi-scan-netsentry"
        self._lock = threading.Lock()

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("cron", "30 4 * * 0")
        return [ScheduledTask(cron=cron, func=self.run_scan, name="weekly")]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/scan":
            return
        if not self._lock.locked():
            self.notifier.send_state_to(chat_id, "scanning",
                f"📡 Triggering scan (~{self._duration}s, brief 5GHz disruption)…")
        # Run in background so we don't block the bot loop
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self) -> None:
        if not self._lock.acquire(blocking=False):
            self.log.info("Scan already running, skipping")
            return
        try:
            ok = self.router.scan_wifi(self._iface, self._duration, self._save_file)
            if not ok:
                self.notifier.send_state("warning", "⚠️ WiFi scan command failed.")
                return
            # Read the CSV file from router
            rc, contents = self.router._ssh(
                f":put [/file get {self._save_file} contents]"
            ) if hasattr(self.router, "_ssh") else (1, "")
            self.router.delete_file(self._save_file)
            if rc != 0 or not contents:
                self.notifier.send_state("warning", "⚠️ Couldn't read scan file.")
                return
            aps = self._parse(contents)
            if not aps:
                self.notifier.send_state("warning", "⚠️ Scan returned no APs.")
                return
            self._report(aps)
        except Exception as e:
            self.log.exception("Scan failed: %s", e)
            self.notifier.send_state("warning", f"❌ Scan crashed: {e}")
        finally:
            self._lock.release()

    # ─── parse + report ─────────────────────────────────────────

    def _parse(self, csv: str) -> list[dict]:
        aps = []
        for line in csv.splitlines():
            line = line.strip()
            if not line or not re.match(r"^[0-9A-F]{2}:", line):
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            m = re.match(r"(\d{4})/(\S+)", parts[2])
            if not m:
                continue
            try:
                sig = int(parts[4])
            except ValueError:
                continue
            aps.append({
                "mac": parts[0], "ssid": parts[1] or "(hidden)",
                "freq": int(m.group(1)), "mode": m.group(2),
                "signal": sig,
            })
        return aps

    def _score(self, aps: list[dict], freq: int) -> float:
        score = 0.0
        for ap in aps:
            df = abs(ap["freq"] - freq)
            if df > 40:
                continue
            weight = max(0, 100 + ap["signal"] + 50)
            adj = 1.0 if df == 0 else 0.8 if df <= 20 else 0.4
            score += weight * adj
        return score

    def _report(self, aps: list[dict]) -> None:
        # Current channel
        rc, out = self.router._ssh(":put [/interface wifi get wifi1 channel.frequency]") \
            if hasattr(self.router, "_ssh") else (1, "")
        cur_freq = int(out.strip()) if rc == 0 and out.strip().isdigit() else 0
        cur_ch = (cur_freq - 5000) // 5 if cur_freq else "?"

        scored = sorted(
            ((self._score(aps, f), f, ch, band) for f, ch, band in CANDIDATE_CHANNELS),
            key=lambda x: x[0],
        )
        top3 = scored[:3]
        cur_score = next((s for s, f, c, b in scored if f == cur_freq), None)

        lines = [
            "📡 WiFi Scan (5 GHz)",
            "━━━━━━━━━━━━━━━━━",
            f"📍 Current: ch {cur_ch} ({cur_freq} MHz)"
            + (f"  score {cur_score:.0f}" if cur_score else ""),
            f"🔍 Neighbors: {len(aps)}",
            "",
            "🧹 Cleanest channels:",
        ]
        for s, f, c, b in top3:
            mark = " ← current" if f == cur_freq else ""
            lines.append(f"  • ch {c:>3} ({b})  score {s:.0f}{mark}")

        strongest = sorted(aps, key=lambda a: -a["signal"])[:5]
        lines.append("\n💪 Top neighbors:")
        for ap in strongest:
            ch = (ap["freq"] - 5000) // 5
            lines.append(f"  {ap['signal']:>4}dBm  ch{ch:<3} {ap['ssid'][:22]}")

        best_score, best_freq, best_ch, best_band = top3[0]
        if cur_freq == best_freq:
            lines.append("\n✅ Already on the cleanest channel.")
        elif cur_score and cur_score - best_score < 30:
            lines.append("\n➡️ Current is within 30 of optimal — no change needed.")
        else:
            lines.append(f"\n💡 Suggest switching to ch {best_ch} ({best_band}).")
            lines.append(
                f"   /interface wifi set wifi1 channel.frequency={best_freq}"
            )

        self.notifier.send_state("protected", "\n".join(lines))
