"""
channel_scan — Weekly WiFi neighbor scan + /scan command.

Triggers a passive scan on the 5 GHz radio, parses neighbors, scores
candidate channels, suggests cleanest channel via Telegram. Does NOT
auto-apply channel changes.
"""

from __future__ import annotations

import re
import threading

from ..core import notify, ui
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
        {"command": "scan", "description": "📻 Scan WiFi channels now"},
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
        if self._lock.locked():
            self.notifier.send_to(chat_id, f"{ui.WORKING} A WiFi scan is already running.")
            return
        self.notifier.send_to(
            chat_id, f"{ui.WORKING} Scanning WiFi channels (~{self._duration} s, "
                     "5 GHz WiFi drops for a moment)…")
        # Run in background so we don't block the bot loop
        threading.Thread(target=self.run_scan, args=(chat_id,), daemon=True).start()

    def run_scan(self, chat_id: int | None = None) -> None:
        """One scan. ``chat_id`` = asked for with /scan (the result is a reply);
        without it this is the weekly run, so the result is a report."""
        if not self._lock.acquire(blocking=False):
            self.log.info("Scan already running, skipping")
            return
        failed = (f"{ui.header(ui.FAILED, 'WiFi channel scan', 'no result')}\n"
                  "{why} Nothing was changed on the router.")
        try:
            # The scan re-provisions the radio; tell the config-drift detector
            # this churn is ours so it doesn't raise a tamper alarm.
            if self.ctx.events:
                self.ctx.events.publish("router.config.expected_change",
                                        {"source": "channel_scan"})
            ok = self.router.scan_wifi(self._iface, self._duration, self._save_file)
            if not ok:
                self._say(chat_id, notify.ATTENTION,
                          failed.format(why="The router didn't run the scan."))
                return
            # Read the CSV file from router
            rc, contents = self.router._ssh(
                f":put [/file get {self._save_file} contents]"
            ) if hasattr(self.router, "_ssh") else (1, "")
            self.router.delete_file(self._save_file)
            if rc != 0 or not contents:
                self._say(chat_id, notify.ATTENTION,
                          failed.format(why="The scan result couldn't be read."))
                return
            aps = self._parse(contents)
            if not aps:
                self._say(chat_id, notify.ATTENTION,
                          failed.format(why="The scan found no access points at all."))
                return
            self._report(aps, chat_id)
        except Exception as e:
            self.log.exception("Scan failed: %s", e)
            self._say(chat_id, notify.ATTENTION,
                      failed.format(why="The scan stopped on an internal error "
                                        "(details are in the log)."))
        finally:
            self._lock.release()

    def _say(self, chat_id: int | None, kind: str, text: str) -> None:
        if chat_id is not None:
            self.notifier.send_to(chat_id, text)
        else:
            self.notifier.notify(kind, text)

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

    def _report(self, aps: list[dict], chat_id: int | None = None) -> None:
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

        best_score, best_freq, best_ch, best_band = top3[0]
        if cur_freq == best_freq:
            verdict, advice = f"{ui.OK} already the cleanest", None
        elif cur_score and cur_score - best_score < 30:
            verdict, advice = f"{ui.OK} fine as it is", (
                "Your channel is close to the best one — no change needed.")
        else:
            verdict, advice = f"💡 channel {best_ch} is cleaner", (
                f"Switching to channel {best_ch} ({best_band}) would help. NetSentry "
                "doesn't change it by itself; on the router run:\n"
                f"/interface wifi set wifi1 channel.frequency={best_freq}")

        lines = [
            ui.title("📻", "WiFi channels (5 GHz)", verdict),
            f"📍 Yours: channel {cur_ch}" + (f" ({cur_freq} MHz)" if cur_freq else "")
            + (f" · score {cur_score:.0f}" if cur_score else ""),
            f"🔍 Neighbouring networks: {len(aps)}",
            "",
            "🧹 Cleanest channels (lower score = less crowded)",
        ]
        for s, f, c, b in top3:
            lines.append("• " + ui.item(f"Channel {c}", b, f"score {s:.0f}",
                                        "yours" if f == cur_freq else ""))

        strongest = sorted(aps, key=lambda a: -a["signal"])[:5]
        lines.append("\n💪 Strongest neighbours")
        for ap in strongest:
            ch = (ap["freq"] - 5000) // 5
            lines.append("• " + ui.item(ap["ssid"][:22], f"channel {ch}",
                                        f"{ap['signal']} dBm"))
        if advice:
            lines.append("\n" + advice)

        self._say(chat_id, notify.REPORT, "\n".join(lines))
