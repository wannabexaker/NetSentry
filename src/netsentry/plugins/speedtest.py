"""speedtest — /speedtest command via Ookla speedtest-cli."""

from __future__ import annotations

import re
import subprocess
import threading

from ..core import ui
from ..core.plugin import Plugin


class SpeedtestPlugin(Plugin):
    COMMANDS = [
        {"command": "speedtest", "description": "🚀 Test the internet speed"},
    ]

    def on_load(self) -> None:
        self._lock = threading.Lock()

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/speedtest":
            return
        if not self._lock.acquire(blocking=False):
            self.notifier.send_to(chat_id, f"{ui.WORKING} A speed test is already running — "
                                           "the result follows in a moment.")
            return
        try:
            self.notifier.send_to(chat_id, f"{ui.WORKING} Testing the internet speed (about 30 s)…")
            try:
                r = subprocess.run(
                    ["speedtest-cli", "--simple", "--secure"],
                    capture_output=True, text=True, timeout=90,
                )
                if r.returncode != 0:
                    self.log.warning("speedtest-cli failed (rc=%s): %s",
                                     r.returncode, r.stderr[-400:])
                    self.notifier.send_to(
                        chat_id, "❌ Speedtest didn't finish — the speed test server "
                                 "couldn't be used. Nothing was measured; try again later.")
                    return
                m_ping = re.search(r"Ping:\s+([\d.]+)\s*ms", r.stdout)
                m_down = re.search(r"Download:\s+([\d.]+)\s*Mbit/s", r.stdout)
                m_up = re.search(r"Upload:\s+([\d.]+)\s*Mbit/s", r.stdout)
                ping_ms = float(m_ping.group(1)) if m_ping else 0
                down = float(m_down.group(1)) if m_down else 0
                up = float(m_up.group(1)) if m_up else 0
                msg = (
                    ui.title("🚀", "Internet speed", f"{down:.0f} Mbps down") + "\n"
                    f"⬇️ Download: {down:.1f} Mbps\n"
                    f"⬆️ Upload: {up:.1f} Mbps\n"
                    f"📶 Ping: {ping_ms:.0f} ms"
                )
                isp = self.cfg.get("isp_nominal_mbps")
                if isp and down:
                    msg += f"\n📊 {down/isp*100:.0f}% of the {isp} Mbps you pay for"
                self.notifier.send_to(chat_id, msg, buttons=ui.rows(
                    ui.command_row(self.ctx, ("🔁 Test again", "/speedtest")), ui.nav_row()))
            except subprocess.TimeoutExpired:
                self.notifier.send_to(chat_id, "❌ The speed test didn't finish within 90 s. "
                                           "Nothing was measured; try again later.")
            except FileNotFoundError:
                self.log.error("speedtest-cli is not installed (apt install speedtest-cli)")
                self.notifier.send_to(chat_id,
                    "❌ No speed test — the speed-test tool isn't installed on the Pi. "
                    "Details are in the log.")
        finally:
            self._lock.release()
