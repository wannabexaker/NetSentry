"""
router_info — Information commands about the router and connected clients.

Commands: /status /clients /wan /services /log
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .. import __version__
from ..core import ui
from ..core.plugin import Plugin


class RouterInfoPlugin(Plugin):
    COMMANDS = [
        {"command": "status",   "description": "📊 Network at a glance"},
        {"command": "clients",  "description": "👥 Devices connected now"},
        {"command": "wan",      "description": "🌐 Internet connection and public IP"},
        {"command": "services", "description": "🔌 Services listening on the Pi"},
        {"command": "log",      "description": "📋 Latest router log",
         "usage": "/log [how many] [topic], e.g. /log 50 dhcp"},
    ]

    _REFRESHABLE = ("status", "clients", "wan")

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        getattr(self, f"_cmd{command.replace('/', '_')}", lambda *_: None)(chat_id, args)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # router_info:r:<status|clients|wan> — 🔄 Refresh, redrawn in place
        _, verb, arg = (data.split(":", 2) + ["", ""])[:3]
        answer = getattr(self.notifier, "answer_callback", None)
        if answer:
            answer(callback_id, "")
        if verb == "r" and arg in self._REFRESHABLE:
            getattr(self, f"_cmd_{arg}")(chat_id, "", message_id)

    def _reply(self, chat_id: int, message_id: int | None, text: str, view: str) -> None:
        """Send a screen with [🔄 Refresh] [🏠 Menu], or redraw it in place."""
        buttons = [[ui.refresh_button(f"{self.ctx.name}:r:{view}"), *ui.nav_row()]]
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons)

    # ─── /status ─────────────────────────────────────────────────

    def _cmd_status(self, chat_id: int, args: str, message_id: int | None = None) -> None:
        stats = self.router.stats()
        if stats is None:
            self._reply(chat_id, message_id,
                        f"{ui.header(ui.ATTENTION, 'Router', 'not answering')}\n"
                        "NetSentry can't reach it over SSH, so there is no status right now.",
                        "status")
            return
        wifi = self.router.wifi_clients()
        ether = self.router.ethernet_clients()
        public_ip = self.router.public_ip() or "unknown"
        wan_up = self.router.wan_running()
        ping_ms = _ping_ms(count=1)

        # Group WiFi by SSID
        by_ssid: dict[str, int] = {}
        for c in wifi:
            by_ssid[c.ssid] = by_ssid.get(c.ssid, 0) + 1

        mem_pct = (1 - stats.free_memory_bytes / stats.total_memory_bytes) * 100
        total = len(wifi) + len(ether)
        online = ping_ms is not None
        verdict = f"{ui.OK} online" if online else f"{ui.ATTENTION} internet down"
        internet = (f"up · {ping_ms:.0f} ms" if ping_ms is not None
                    else ("down" if wan_up is False else "not answering"))
        groups = [f"{ssid} {n}" for ssid, n in sorted(by_ssid.items())]
        if ether:
            groups.append(f"Ethernet {len(ether)}")

        lines = [
            ui.title("📊", "Network", verdict),
            f"🌍 Internet: {internet}",
            f"🌐 Public IP: {public_ip}",
            f"📡 WAN port: {'up' if wan_up else 'down'}",
            f"👥 {ui.item(ui.plural(total, 'device'), *groups)}",
            f"🖥 Router: up {ui.duration(stats.uptime_seconds)} · CPU {stats.cpu_load_pct}% · "
            f"memory {mem_pct:.0f}% · {ui.size(stats.free_disk_bytes)} free",
            "",
            f"NetSentry v{__version__}",
        ]
        self._reply(chat_id, message_id, "\n".join(lines), "status")

    # ─── /clients ────────────────────────────────────────────────

    def _cmd_clients(self, chat_id: int, args: str, message_id: int | None = None) -> None:
        wifi = self.router.wifi_clients()
        ether = self.router.ethernet_clients()
        leases = {lease.mac: lease for lease in self.router.dhcp_leases()}

        if not wifi and not ether:
            self._reply(chat_id, message_id, "👥 No devices are connected right now.",
                        "clients")
            return

        names = ui.device_names(self.ctx, self.router,
                                [c.mac for c in wifi] + [c.mac for c in ether])
        total = len(wifi) + len(ether)
        lines = [ui.title("👥", "Connected devices", str(total))]

        def ip_of(mac: str) -> str:
            lease = leases.get(mac)
            return getattr(lease, "ip", "") or "" if lease else ""

        # WiFi by SSID, strongest signal first
        by_ssid: dict[str, list] = {}
        for c in wifi:
            by_ssid.setdefault(c.ssid, []).append(c)
        for ssid in sorted(by_ssid):
            cs = sorted(by_ssid[ssid], key=lambda x: -x.signal_dbm)
            lines.append(f"\n📶 {ssid} ({len(cs)})")
            for c in cs:
                lines.append("• " + ui.item(names.get(c.mac, c.mac), ip_of(c.mac),
                                            f"{c.signal_dbm} dBm", c.band))

        if ether:
            lines.append(f"\n🔌 Ethernet ({len(ether)})")
            for c in sorted(ether, key=lambda x: (x.port, x.mac)):
                lines.append("• " + ui.item(names.get(c.mac, c.mac), ip_of(c.mac), c.port))

        self._reply(chat_id, message_id, _trim("\n".join(lines)), "clients")

    # ─── /wan ───────────────────────────────────────────────────

    def _cmd_wan(self, chat_id: int, args: str, message_id: int | None = None) -> None:
        public_ip = self.router.public_ip() or "unknown"
        wan_up = self.router.wan_running()
        # Detect change
        state_file = Path(self.ctx.state_dir) / "last_public_ip"
        try:
            prev = state_file.read_text().strip()
        except Exception:
            prev = ""
        try:
            state_file.write_text(public_ip)
        except Exception:
            pass

        ping_ms = _ping_ms(count=2)
        verdict = f"{ui.OK} up" if ping_ms is not None else f"{ui.ATTENTION} down"
        lines = [
            ui.title("🌐", "Internet", verdict),
            f"Public IP: {public_ip}",
            f"Changed from {prev}" if prev and prev != public_ip else None,
            f"Latency to 1.1.1.1: {f'{ping_ms:.1f} ms' if ping_ms is not None else 'no answer'}",
            f"WAN port (ether1): {'up' if wan_up else 'down'}",
        ]
        self._reply(chat_id, message_id, "\n".join(x for x in lines if x is not None), "wan")

    # ─── /services ──────────────────────────────────────────────

    def _cmd_services(self, chat_id: int, args: str) -> None:
        try:
            tcp = subprocess.run(["ss", "-tlnH"], capture_output=True,
                                 text=True, timeout=5).stdout
            udp = subprocess.run(["ss", "-ulnH"], capture_output=True,
                                 text=True, timeout=5).stdout
        except Exception:
            self.log.exception("could not list listening services")
            self.notifier.send_to(chat_id, f"{ui.FAILED} Couldn't list the Pi's services — "
                                           "details are in the log.")
            return

        services_map = {
            22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
            67: "DHCP", 123: "NTP", 8080: "HTTP-alt", 3000: "Grafana",
            8123: "Home Assistant", 1883: "MQTT", 51820: "WireGuard",
            41641: "Tailscale", 4747: "Pi-hole FTL",
        }
        ports: set[tuple[int, str, bool]] = set()
        for proto, txt in (("tcp", tcp), ("udp", udp)):
            for line in txt.strip().splitlines():
                cols = line.split()
                if len(cols) < 4:
                    continue
                m = re.search(r":(\d+)$", cols[3])
                if not m:
                    continue
                port = int(m.group(1))
                public = cols[3].startswith(("0.0.0.0", "*", "[::]"))  # nosec B104
                ports.add((port, proto, public))

        lines = [ui.title("🔌", "Services on the Pi", str(len(ports))),
                 "🌍 = reachable from the network · 🏠 = this Pi only"]
        for port, proto, public in sorted(ports):
            name = services_map.get(port, "")
            where = "🌍" if public else "🏠"
            label = f"{name} — {proto.upper()} {port}" if name else f"{proto.upper()} {port}"
            lines.append(f"{where} {label}")
        self.notifier.send_to(chat_id, _trim("\n".join(lines)), buttons=[ui.nav_row()])

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
            self.notifier.send_to(chat_id, f"{ui.INFO} No router log entries match.")
            return
        verdict = f"last {len(lines)}" + (f" matching \"{topic_filter}\"" if topic_filter else "")
        msg = ui.title("📋", "Router log", verdict) + "\n" + "\n".join(lines)
        self.notifier.send_to(chat_id, _trim(msg), buttons=[ui.nav_row()])


def _ping_ms(count: int = 1) -> float | None:
    """Average round trip to 1.1.1.1 in ms, or None when there is no answer."""
    try:
        r = subprocess.run(["ping", "-c", str(count), "-W", "2", "1.1.1.1"],
                           capture_output=True, text=True, timeout=2 + 2 * count)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    m = (re.search(r"min/avg/max[^=]*=\s*[\d.]+/([\d.]+)", r.stdout)
         or re.search(r"time=([\d.]+)\s*ms", r.stdout))
    try:
        return float(m.group(1)) if m else None
    except ValueError:
        return None


def _trim(s: str, limit: int = 4000) -> str:
    return s if len(s) <= limit else s[: limit - 10] + "\n…(trimmed)"
