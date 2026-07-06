"""
router_info — Information commands about the router and connected clients.

Commands: /status /clients /wan /services /log
"""

from __future__ import annotations

import re
import subprocess

from .. import __version__
from ..core.plugin import Plugin


class RouterInfoPlugin(Plugin):
    COMMANDS = [
        {"command": "status",   "description": "📊 Network dashboard"},
        {"command": "clients",  "description": "👥 All connected clients (WiFi+Ether)"},
        {"command": "wan",      "description": "🌐 Public IP + WAN health"},
        {"command": "services", "description": "🛠 Services listening on this Pi"},
        {"command": "log",      "description": "📋 Last router log entries"},
    ]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        getattr(self, f"_cmd{command.replace('/', '_')}", lambda *_: None)(chat_id, args)

    # ─── /status ─────────────────────────────────────────────────

    def _cmd_status(self, chat_id: int, args: str) -> None:
        stats = self.router.stats()
        if stats is None:
            self.notifier.send_to(chat_id, "⚠️ Router unreachable over SSH. Status unavailable.")
            return
        wifi = self.router.wifi_clients()
        ether = self.router.ethernet_clients()
        public_ip = self.router.public_ip() or "?"
        wan_up = self.router.wan_running()

        # Internet ping
        internet = "?"
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "2", "1.1.1.1"],
                               capture_output=True, text=True, timeout=4)
            if r.returncode == 0:
                m = re.search(r"time=([\d.]+)\s*ms", r.stdout)
                internet = f"✅ {m.group(1) if m else '?'}ms"
            else:
                internet = "❌ DOWN"
        except Exception:
            pass

        # Group WiFi by SSID
        by_ssid: dict[str, int] = {}
        for c in wifi:
            by_ssid[c.ssid] = by_ssid.get(c.ssid, 0) + 1

        mem_pct = (1 - stats.free_memory_bytes / stats.total_memory_bytes) * 100
        free_disk_mb = stats.free_disk_bytes / 1024 / 1024
        total = len(wifi) + len(ether)

        lines = [
            "📊 Network Status",
            "━━━━━━━━━━━━━━━━━",
            f"⏱ {_human_dur(stats.uptime_seconds)}  💻 {stats.cpu_load_pct}%  💾 {mem_pct:.0f}%  💿 {free_disk_mb:.0f}M",
            f"📡 WAN: {'UP' if wan_up else 'DOWN'}  🌐 {public_ip}",
            f"🌍 Internet: {internet}",
            "",
            f"👥 Clients ({total})",
        ]
        for ssid in sorted(by_ssid):
            lines.append(f"  📶 {ssid:<14} {by_ssid[ssid]}")
        if ether:
            lines.append(f"  🔌 Ethernet       {len(ether)}")
        if total == 0:
            lines.append("  (none)")
        lines.append(f"\n🛡 NetSentry v{__version__}")
        self.notifier.send_to(chat_id, "\n".join(lines))

    # ─── /clients ────────────────────────────────────────────────

    def _cmd_clients(self, chat_id: int, args: str) -> None:
        wifi = self.router.wifi_clients()
        ether = self.router.ethernet_clients()
        leases = {lease.mac: lease for lease in self.router.dhcp_leases()}

        if not wifi and not ether:
            self.notifier.send_to(chat_id, "📶 No active clients.")
            return

        total = len(wifi) + len(ether)
        lines = [f"👥 All clients ({total})", "━━━━━━━━━━━━━━━━━"]

        # WiFi by SSID
        by_ssid: dict[str, list] = {}
        for c in wifi:
            by_ssid.setdefault(c.ssid, []).append(c)
        for ssid in sorted(by_ssid):
            cs = sorted(by_ssid[ssid], key=lambda x: -x.signal_dbm)
            lines.append(f"\n📶 {ssid} ({len(cs)})")
            for c in cs:
                lease = leases.get(c.mac)
                label = (lease.hostname or lease.ip or c.mac) if lease else c.mac
                lines.append(f"  {c.signal_dbm:>4}dBm  {c.band:<8}  {label[:30]}")

        if ether:
            lines.append(f"\n🔌 Ethernet ({len(ether)})")
            for c in sorted(ether, key=lambda x: (x.port, x.mac)):
                lease = leases.get(c.mac)
                label = (lease.hostname or lease.ip or c.mac) if lease else c.mac
                lines.append(f"  {c.port:<8}  {label[:30]}")

        self.notifier.send_to(chat_id, _trim("\n".join(lines)))

    # ─── /wan ───────────────────────────────────────────────────

    def _cmd_wan(self, chat_id: int, args: str) -> None:
        public_ip = self.router.public_ip() or "?"
        wan_up = self.router.wan_running()
        # Detect change
        state_file = self.ctx.state_dir + "/last_public_ip"
        try:
            from pathlib import Path
            prev = Path(state_file).read_text().strip()
        except Exception:
            prev = ""
        change = ""
        if prev and prev != public_ip:
            change = f"\n🔄 Changed from {prev}"
        try:
            from pathlib import Path
            Path(state_file).write_text(public_ip)
        except Exception:
            pass

        # External ping
        try:
            r = subprocess.run(["ping", "-c", "2", "-W", "2", "1.1.1.1"],
                               capture_output=True, text=True, timeout=6)
            m = re.search(r"min/avg/max[^=]*=\s*[\d.]+/([\d.]+)", r.stdout)
            ext = f"{float(m.group(1)):.1f} ms" if m else "fail"
        except Exception:
            ext = "fail"

        lines = [
            "🌐 WAN Status",
            "━━━━━━━━━━━━━━━━━",
            f"📡 ether1: {'UP' if wan_up else 'DOWN'}",
            f"🌍 Public IP: {public_ip}{change}",
            f"⏱ Latency to 1.1.1.1: {ext}",
        ]
        self.notifier.send_to(chat_id, "\n".join(lines))

    # ─── /services ──────────────────────────────────────────────

    def _cmd_services(self, chat_id: int, args: str) -> None:
        try:
            tcp = subprocess.run(["ss", "-tlnH"], capture_output=True,
                                 text=True, timeout=5).stdout
            udp = subprocess.run(["ss", "-ulnH"], capture_output=True,
                                 text=True, timeout=5).stdout
        except Exception as e:
            self.notifier.send_to(chat_id, f"❌ {e}")
            return

        services_map = {
            22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
            67: "DHCP", 123: "NTP", 8080: "HTTP-alt", 3000: "Grafana",
            8123: "Home Assistant", 1883: "MQTT", 51820: "WireGuard",
            41641: "Tailscale", 4747: "Pi-hole FTL",
        }
        ports: set[tuple[int, str, str]] = set()
        for proto, txt in (("tcp", tcp), ("udp", udp)):
            for line in txt.strip().splitlines():
                cols = line.split()
                if len(cols) < 4:
                    continue
                m = re.search(r":(\d+)$", cols[3])
                if not m:
                    continue
                port = int(m.group(1))
                scope = "🌍" if cols[3].startswith(("0.0.0.0", "*", "[::]")) else "🏠"  # nosec B104
                ports.add((port, proto, scope))

        lines = ["🛠 Services listening on Pi", "━━━━━━━━━━━━━━━━━"]
        for port, proto, scope in sorted(ports):
            name = services_map.get(port, "")
            lines.append(f"  {scope} {proto.upper()} {port:<6} {name}".rstrip())
        self.notifier.send_to(chat_id, "\n".join(lines)[:4000])

    # ─── /log ────────────────────────────────────────────────────

    def _cmd_log(self, chat_id: int, args: str) -> None:
        n = 25
        topic_filter = None
        if args:
            parts = args.split(maxsplit=1)
            try:
                n = max(1, min(int(parts[0]), 100))
                if len(parts) > 1:
                    topic_filter = parts[1]
            except ValueError:
                topic_filter = args
        lines = self.router.log_tail(n=n, topic_filter=topic_filter)
        if not lines:
            self.notifier.send_to(chat_id, "ℹ️ No log entries match.")
            return
        header = f"📋 Last {len(lines)} router log entries"
        if topic_filter:
            header += f" (filter: {topic_filter})"
        msg = header + "\n━━━━━━━━━━━━━━━━━\n" + "\n".join(lines)
        self.notifier.send_to(chat_id, _trim(msg))


def _human_dur(secs: int) -> str:
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m, _ = divmod(secs, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _trim(s: str, limit: int = 4000) -> str:
    return s if len(s) <= limit else s[: limit - 10] + "\n…(trimmed)"
