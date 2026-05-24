"""speedtest — /speedtest command via Ookla speedtest-cli."""

from __future__ import annotations

import re
import subprocess
import threading

from ..core.plugin import Plugin


class SpeedtestPlugin(Plugin):
    COMMANDS = [
        {"command": "speedtest", "description": "🚀 Internet speedtest (~30s)"},
    ]

    def on_load(self) -> None:
        self._lock = threading.Lock()

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/speedtest":
            return
        if not self._lock.acquire(blocking=False):
            self.notifier.send_to(chat_id, "⏳ Already running, wait…")
            return
        try:
            self.notifier.send_to(chat_id, "🚀 Running speedtest (~30s)…")
            try:
                r = subprocess.run(
                    ["speedtest-cli", "--simple", "--secure"],
                    capture_output=True, text=True, timeout=90,
                )
                if r.returncode != 0:
                    self.notifier.send_to(chat_id, f"❌ Speedtest failed:\n{r.stderr[-400:]}")
                    return
                m_ping = re.search(r"Ping:\s+([\d.]+)\s*ms", r.stdout)
                m_down = re.search(r"Download:\s+([\d.]+)\s*Mbit/s", r.stdout)
                m_up = re.search(r"Upload:\s+([\d.]+)\s*Mbit/s", r.stdout)
                ping_ms = float(m_ping.group(1)) if m_ping else 0
                down = float(m_down.group(1)) if m_down else 0
                up = float(m_up.group(1)) if m_up else 0
                msg = (
                    "🚀 Speedtest result\n"
                    "━━━━━━━━━━━━━━━━━\n"
                    f"⬇️  Download: {down:.1f} Mbps\n"
                    f"⬆️  Upload:   {up:.1f} Mbps\n"
                    f"📶 Ping:     {ping_ms:.0f} ms"
                )
                isp = self.cfg.get("isp_nominal_mbps")
                if isp and down:
                    msg += f"\n📊 {down/isp*100:.0f}% of ISP nominal {isp} Mbps"
                self.notifier.send_to(chat_id, msg)
            except subprocess.TimeoutExpired:
                self.notifier.send_to(chat_id, "❌ Speedtest timed out (90s)")
            except FileNotFoundError:
                self.notifier.send_to(chat_id,
                    "❌ speedtest-cli not installed. apt install speedtest-cli")
        finally:
            self._lock.release()
