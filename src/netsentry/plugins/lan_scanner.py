"""
lan_scanner — IP inventory + MAC tagging.

Pulls every device the router has seen recently (ARP + DHCP + WiFi
registration), enriches with vendor lookup, and lets you assign a
friendly name to any MAC. The tags persist across runs and are reused
by other plugins (notably health_monitor's new-client alerts).

Everything is reachable by tapping: `/lan` shows the device list with buttons
for the other views, and the "not named yet" view has one button per device —
tap it and reply with a name. The typed forms below keep working.

Commands
--------
/lan                          Full device list grouped by interface
/lan known                    Only tagged devices
/lan unknown                  Only untagged devices
/lan tag <MAC> <name>         Assign or update a friendly name
/lan untag <MAC>              Remove a tag
/lan search <text>            Search IP / MAC / name / interface
/lan vendor <MAC>             OUI vendor lookup (offline + online fallback)
/lan ping [CIDR]              Optional: ping-sweep of a subnet from the Pi.
                              If CIDR omitted, falls back to the Pi's own
                              default-gateway subnet via `ip route`.

Storage
-------
~/.local/share/netsentry/lan_scanner/tags.json
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..core import ui
from ..core.plugin import Plugin
from ..core.tag_store import TagStore


_MAX_NAME_BUTTONS = 30      # Telegram caps an inline keyboard at 100 buttons


def _norm_mac(s: str) -> str | None:
    return TagStore.normalize_mac(s)


class LanScannerPlugin(Plugin):
    COMMANDS = [
        {"command": "lan", "description": "🗂 All devices and their names",
         "usage": "/lan known|unknown · /lan search <text> · /lan tag <MAC> <name> · "
                  "/lan untag <MAC> · /lan vendor <MAC> · /lan ping [network] · "
                  "/lan watch <name1>,<name2> · /lan dashboard"},
    ]

    # ─── lifecycle ──────────────────────────────────────────────

    def on_load(self) -> None:
        self._tags_path = Path(self.ctx.state_dir) / "tags.json"
        self._tag_store = TagStore(self._tags_path)
        self._tag_store.snapshot()
        self._oui_cache_path = Path(self.ctx.state_dir) / "oui_cache.json"
        self._oui_cache = self._load_json(self._oui_cache_path, default={})
        self._pending_tag_for_chat: dict[int, str] = {}

        # Listen for plain-text replies after a tagprompt callback
        if self.ctx.events:
            self.ctx.events.subscribe(
                "telegram.text",
                lambda p: self.on_event("telegram.text", p),
            )

        # /lan watch — interactive identifier state
        self._watch_lock = threading.Lock()
        self._watch_thread: threading.Thread | None = None
        self._watch_stop = threading.Event()
        self._watch_state: dict | None = None
        self._watch_idle_threshold_ms = int(
            self.cfg.get("watch_idle_threshold_ms", 1500)
        )
        self._watch_poll_seconds = float(self.cfg.get("watch_poll_seconds", 1.5))
        self._watch_cooldown_seconds = float(
            self.cfg.get("watch_cooldown_seconds", 12)
        )

        # Built-in OUI hints (cheap shortcut for very common vendors).
        self._oui_builtin = {
            "78:8B:2A": "Xiaomi",
            "60:7E:A4": "Xiaomi",
            "44:23:7C": "Espressif/ESP",
            "44:F7:70": "Espressif/ESP",
            "54:EF:44": "Espressif/Sonoff",
            "50:EC:50": "Espressif/Tuya",
            "14:EA:63": "Tuya/Hi-Flying",
            "CC:8C:BF": "Espressif/Generic",
            "28:37:2F": "Shelly (Allterco)",
            "04:F4:1C": "MikroTik",
            "10:6F:D9": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "E4:5F:01": "Raspberry Pi",
            "D8:3A:DD": "Raspberry Pi",
            "08:8A:F1": "Tenda",
            "F4:23:9C": "Vodafone CPE",
        }
        self._allow_online_oui = bool(self.cfg.get("online_oui_lookup", True))

    # ─── tags ───────────────────────────────────────────────────

    def _load_json(self, path: Path, default):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    def _save_json(self, path: Path, data) -> None:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                        encoding="utf-8")

    def _tags(self) -> dict[str, Any]:
        return self._tag_store.snapshot()

    def _save_tags(self, tags: dict[str, Any]) -> None:
        self._tag_store.replace(tags)

    # ─── vendor lookup ──────────────────────────────────────────

    def _oui_lookup(self, mac: str, *, online: bool = True) -> str:
        prefix = mac.upper()[:8]
        if _is_private_mac(mac):
            # Randomised by the device for privacy: the prefix names no maker,
            # so looking it up online would only waste the daily quota.
            return "private address (a phone, tablet or laptop hiding its maker)"
        if prefix in self._oui_builtin:
            return self._oui_builtin[prefix]
        if prefix in self._oui_cache:
            return self._oui_cache[prefix]
        if not (online and self._allow_online_oui):
            return ""
        # macvendors.com — free, no key, ~150 req/day. We cache.
        try:
            req = urllib.request.Request(
                f"https://api.macvendors.com/{mac}",
                headers={"User-Agent": "NetSentry/0.2"},
            )
            with urllib.request.urlopen(req, timeout=3) as r:  # nosec B310
                body = r.read().decode("utf-8", errors="replace").strip()
                if r.status == 200 and body and "errors" not in body.lower():
                    vendor = body[:60]
                    self._oui_cache[prefix] = vendor
                    self._save_json(self._oui_cache_path, self._oui_cache)
                    return vendor
        except (urllib.error.URLError, socket.timeout, OSError):
            pass
        return ""

    # ─── inventory build ────────────────────────────────────────

    def _build_inventory(self) -> list[dict[str, Any]]:
        """Merge router ARP + DHCP + WiFi tables into a per-MAC inventory."""
        tags = self._tags()
        leases = {lease.mac: lease for lease in self.router.dhcp_leases()}
        wifi = {w.mac: w for w in self.router.wifi_clients()}
        try:
            ether = {e.mac: e for e in self.router.ethernet_clients()}
        except Exception:
            ether = {}
        try:
            arp = {a.mac: a for a in self.router.arp_table()}
        except Exception:
            arp = {}

        all_macs = set(arp) | set(leases) | set(wifi) | set(ether)
        items: list[dict[str, Any]] = []
        for mac in sorted(all_macs):
            lease = leases.get(mac)
            wc = wifi.get(mac)
            ec = ether.get(mac)
            ae = arp.get(mac)
            ip = (ae.ip if ae else "") or (lease.ip if lease else "")
            iface = (
                f"WiFi:{wc.ssid}" if wc else
                f"Ethernet:{ec.port}" if ec else
                (ae.interface if ae else "?")
            )
            tag_name, tag_retired = TagStore.tag_info_from_snapshot(mac, tags)
            tag_entry = TagStore.entry_from_snapshot(mac, tags, include_retired=True) or {}
            items.append({
                "mac": mac,
                "ip": ip or "?",
                "iface": iface,
                "hostname": lease.hostname if lease else "",
                "signal": wc.signal_dbm if wc else None,
                "tagged_name": tag_name,
                "tag_retired": tag_retired,
                "active_tagged": TagStore.has_active_in_snapshot(mac, tags),
                "tagged_at": tag_entry.get("tagged_at", ""),
            })
        return items

    # ─── dispatch ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/lan":
            return
        args = args.strip()
        kw, _, rest = args.partition(" ")
        kw_l = kw.lower()
        rest = rest.strip()

        handlers = {
            "":         lambda c, _r: self._cmd_list(c, mode="all"),
            "known":    lambda c, _r: self._cmd_list(c, mode="known"),
            "unknown":  lambda c, _r: self._cmd_list(c, mode="unknown"),
            "tag":      self._cmd_tag,
            "untag":    self._cmd_untag,
            "search":   self._cmd_search,
            "vendor":   self._cmd_vendor,
            "ping":     self._cmd_ping,
            "watch":    self._cmd_watch,
            "dashboard": self._cmd_dashboard,
            "help":     lambda c, _r: self._send_help(c),
        }
        h = handlers.get(kw_l)
        if h is None:
            self._send_help(chat_id)
            return
        h(chat_id, rest)

    # ─── handlers ───────────────────────────────────────────────

    def _cmd_list(self, chat_id: int, mode: str = "all") -> None:
        items = self._build_inventory()
        if mode == "known":
            items = [i for i in items if i["active_tagged"]]
        elif mode == "unknown":
            items = [i for i in items if not i["active_tagged"]]
        if not items:
            self._send(chat_id, "🗂 No devices found." if mode == "all"
                       else "🗂 Nothing in that view right now.",
                       buttons=self._view_buttons(mode))
            return

        # Group by interface family for readability
        groups: dict[str, list[dict]] = {}
        for it in items:
            family = (
                "WiFi" if it["iface"].startswith("WiFi:") else
                "Ethernet" if it["iface"].startswith("Ethernet:") else
                "Bridges"
            )
            groups.setdefault(family, []).append(it)

        title = {"all": ("🗂", "Devices"), "known": ("🏷", "Named devices"),
                 "unknown": ("❓", "Unnamed devices")}[mode]
        lines = [ui.title(title[0], title[1], str(len(items)))]
        for family, label in (("WiFi", "📶 WiFi"), ("Ethernet", "🔌 Ethernet"),
                              ("Bridges", "🌉 Other (router tables)")):
            block = groups.get(family) or []
            if not block:
                continue
            lines.append(f"\n{label} ({len(block)})")
            for it in sorted(block, key=_sort_key):
                lines.append(_device_line(it))

        self._send(chat_id, "\n".join(lines), buttons=self._view_buttons(mode))
        if mode == "unknown":
            self._send_name_buttons(chat_id, items)

    def _view_buttons(self, current: str) -> list:
        """The other views of the list, plus the two actions, as buttons."""
        name = self.ctx.name
        views = [("all", "🗂 All devices"), ("unknown", "❓ Unnamed"),
                 ("known", "🏷 Named")]
        return [
            [{"text": label, "callback_data": f"{name}:view:{key}"}
             for key, label in views if key != current],
            [{"text": "🛰 Ping sweep", "callback_data": f"{name}:ping:-"},
             {"text": "🖥 Dashboard", "callback_data": f"{name}:dash:-"}],
            ui.nav_row(),
        ]

    def _send_name_buttons(self, chat_id: int, items: list[dict[str, Any]]) -> None:
        """One button per unnamed device: tap, then reply with a name."""
        shown = items[:_MAX_NAME_BUTTONS]
        rows = []
        for it in shown:
            hint = it["hostname"] or it["mac"]
            ip = f" · {it['ip']}" if it["ip"] != "?" else ""
            rows.append([{
                "text": f"🏷 {hint}{ip}"[:60],
                "callback_data": f"{self.ctx.name}:tagprompt:{it['mac']}",
            }])
        more = (f"\nShowing the first {len(shown)} of {len(items)}."
                if len(items) > len(shown) else "")
        self._send(chat_id, "🏷 Tap a device to name it." + more, buttons=rows)

    def _cmd_tag(self, chat_id: int, rest: str) -> None:
        parts = rest.split(maxsplit=1)
        if len(parts) < 2:
            self._send_help(chat_id)
            return
        mac = _norm_mac(parts[0])
        name = parts[1].strip()
        if not mac:
            self._send(chat_id, f"❌ “{parts[0]}” isn't a MAC address "
                                "(like AA:BB:CC:DD:EE:FF). Nothing changed.")
            return
        if not name:
            self._send(chat_id, "❌ The name can't be empty. Nothing changed.")
            return
        prev = (self.set_tag(mac, name) or {}).get("name", "")
        msg = f"🏷 Named {mac} “{name}”"
        if prev:
            msg += f" (was “{prev}”)"
        self._send(chat_id, msg + ".")

    def _cmd_untag(self, chat_id: int, rest: str) -> None:
        mac = _norm_mac(rest)
        if not mac:
            self._send_help(chat_id)
            return
        old = self.remove_tag(mac)
        if old:
            self._send(chat_id, f"🗑 Removed the name “{old.get('name', '')}” from {mac}. "
                                "It's unnamed now.")
        else:
            self._send(chat_id, f"ℹ️ {mac} had no name. Nothing changed.")

    def _cmd_search(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send_help(chat_id)
            return
        q = rest.lower()
        items = self._build_inventory()
        hits = [it for it in items if any(
            q in (it.get(k) or "").lower() for k in
            ("ip", "mac", "iface", "hostname", "tagged_name")
        )]
        if not hits:
            self._send(chat_id, f"🔍 No device matches “{rest}”.",
                       buttons=self._view_buttons("search"))
            return
        lines = [ui.title("🔍", f"Devices matching “{rest}”", str(len(hits)))]
        lines += [_device_line(it, with_place=True) for it in hits[:40]]
        if len(hits) > 40:
            lines.append(ui.more(40, len(hits)))
        self._send(chat_id, "\n".join(lines), buttons=self._view_buttons("search"))

    def _cmd_vendor(self, chat_id: int, rest: str) -> None:
        mac = _norm_mac(rest)
        if not mac:
            self._send_help(chat_id)
            return
        vendor = self._oui_lookup(mac) or "unknown maker"
        self._send(chat_id, f"🏭 {mac} — {vendor}")

    def _cmd_dashboard(self, chat_id: int, rest: str) -> None:
        dashboard = self._find_dashboard()
        if dashboard and hasattr(dashboard, "send_dashboard_link"):
            dashboard.send_dashboard_link(chat_id)
            return
        self._send(chat_id, "ℹ️ The dashboard isn't switched on in this install "
                            "(the lan_dashboard plugin is not loaded).")

    # ─── /lan ping <CIDR> — direct subnet sweep from the Pi ─────

    def _cmd_ping(self, chat_id: int, rest: str) -> None:
        cidr = rest.strip()
        if not cidr:
            cidr = self._default_gateway_cidr()
            if not cidr:
                self._send(chat_id, "❌ No sweep — NetSentry couldn't work out the Pi's "
                                    "network. Type /lan ping and a network, "
                                    "e.g. /lan ping 192.168.1.0/24")
                return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            self._send(chat_id, f"❌ “{cidr}” isn't a network like 192.168.1.0/24. "
                                "Nothing was scanned.")
            return
        if net.num_addresses > 1024:
            self._send(chat_id, "❌ That network is too big to sweep (more than 1024 "
                                "addresses). Nothing was scanned.")
            return

        hosts = [str(h) for h in net.hosts()]
        self._send(chat_id, f"{ui.WORKING} Pinging every address on {cidr} "
                            f"({ui.plural(len(hosts), 'address', 'addresses')})…")
        alive: list[tuple[str, str]] = []  # (ip, mac)
        ping_bin = "ping"

        def _ping(host: str) -> str | None:
            try:
                r = subprocess.run(
                    [ping_bin, "-c", "1", "-W", "1", host],
                    capture_output=True, text=True, timeout=2,
                )
                return host if r.returncode == 0 else None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=64) as ex:
            for ok in ex.map(_ping, hosts):
                if ok:
                    alive.append((ok, ""))

        # Resolve MACs from `ip neighbor` (Linux)
        ip_to_mac = self._read_ip_neighbor()
        alive = [(ip, ip_to_mac.get(ip, "")) for ip, _ in alive]

        if not alive:
            self._send(chat_id, f"🛰 Ping sweep — nobody answered on {cidr}.",
                       buttons=self._view_buttons("ping"))
            return
        tags = self._tags()
        lines = [ui.title("🛰", "Ping sweep",
                          f"{ui.plural(len(alive), 'device')} answered on {cidr}")]
        for ip, mac in sorted(alive, key=lambda t: ipaddress.ip_address(t[0])):
            mac = mac.upper() if mac else ""
            tag, retired = TagStore.tag_info_from_snapshot(mac, tags)
            suffix = " (retired)" if tag and retired else ""
            name = f"🏷 {tag}{suffix}" if tag else (mac or "no MAC known")
            lines.append(ui.item(name[:50], ip))
        self._send(chat_id, "\n".join(lines), buttons=self._view_buttons("ping"))

    @staticmethod
    def _default_gateway_cidr() -> str | None:
        try:
            r = subprocess.run(["ip", "-4", "route", "show", "default"],
                               capture_output=True, text=True, timeout=2)
            m = re.search(r"default via (\S+) dev (\S+)", r.stdout)
            if not m:
                return None
            dev = m.group(2)
            # Get the device's address + prefix
            r2 = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", dev],
                                capture_output=True, text=True, timeout=2)
            m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", r2.stdout)
            if not m2:
                return None
            net = ipaddress.ip_network(m2.group(1), strict=False)
            return str(net)
        except Exception:
            return None

    @staticmethod
    def _read_ip_neighbor() -> dict[str, str]:
        try:
            r = subprocess.run(["ip", "neighbor"], capture_output=True,
                               text=True, timeout=3)
            out: dict[str, str] = {}
            for line in r.stdout.splitlines():
                # 203.0.113.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                m = re.match(r"^(\S+)\s.*lladdr\s+([0-9a-f:]{17})", line, re.I)
                if m:
                    out[m.group(1)] = m.group(2).upper()
            return out
        except Exception:
            return {}

    # ─── /lan watch — interactive timing-based identifier ───────

    def _cmd_watch(self, chat_id: int, rest: str) -> None:
        """Usage:
            /lan watch start <name1>,<name2>,...   begin
            /lan watch <name1>,<name2>,...         shorthand (skip "start")
            /lan watch stop                        stop
            /lan watch status                      what is the watcher doing
        """
        rest = rest.strip()
        verb, _, params = rest.partition(" ")
        verb_l = verb.lower()

        if verb_l == "stop":
            self._stop_watch(chat_id)
            return
        if verb_l == "status":
            self._watch_status(chat_id)
            return

        # Accept both "start Low,Mid,High" and just "Low,Mid,High"
        if verb_l == "start":
            names_raw = params.strip()
        elif "," in rest or (rest and rest.lower() not in ("stop", "status")):
            names_raw = rest
        else:
            names_raw = ""

        if not names_raw:
            self._send(chat_id,
                "🛰 Name devices by switching them on — type the names you want "
                "to hand out, e.g. /lan watch Lamp,Fan,Heater\n"
                "Then switch ONE device on or off and NetSentry asks which one it was.")
            return
        names = [n.strip() for n in names_raw.split(",") if n.strip()]
        if not names:
            self._send(chat_id, "❌ No names given — nothing to hand out. Nothing started.")
            return
        self._start_watch(chat_id, names)

    def _start_watch(self, chat_id: int, names: list[str]) -> None:
        with self._watch_lock:
            if self._watch_thread and self._watch_thread.is_alive():
                self._send(chat_id, "⚠️ A watch is already running — stop it first.",
                           buttons=[[ui.button("🛑 Stop watch", f"{self.ctx.name}:watchstop:-")]])
                return
            # Snapshot baseline activity per untagged MAC
            tags = self._tags()
            baseline = {}
            for w in self.router.wifi_clients():
                if TagStore.has_active_in_snapshot(w.mac, tags):
                    continue
                baseline[w.mac] = w.last_activity_ms
            self._watch_state = {
                "chat_id": chat_id,
                "pending_names": list(names),
                "tagged_in_session": [],
                "baseline": baseline,
                "last_alert_ts": 0.0,
                "awaiting_pick": None,   # MAC currently shown in the picker
            }
            self._watch_stop.clear()
            self._watch_thread = threading.Thread(
                target=self._watch_loop, daemon=True, name="lan_scanner.watch",
            )
            self._watch_thread.start()
        self._send(chat_id,
            f"🛰 Watching {ui.plural(len(baseline), 'unnamed WiFi device')}.\n"
            f"Names to hand out: {', '.join(names)}\n\n"
            "Now switch ONE device on or off. When it shows up, NetSentry asks "
            "which one it was.",
            buttons=[[ui.button("🛑 Stop watch", f"{self.ctx.name}:watchstop:-")]])

    def _stop_watch(self, chat_id: int) -> None:
        with self._watch_lock:
            if not (self._watch_thread and self._watch_thread.is_alive()):
                self._send(chat_id, "ℹ️ No watch is running.")
                self._watch_state = None
                return
            self._watch_stop.set()
        # Wait briefly outside the lock
        if self._watch_thread:
            self._watch_thread.join(timeout=3)
        with self._watch_lock:
            self._watch_thread = None
            state = self._watch_state
            self._watch_state = None
        if state and state["tagged_in_session"]:
            tagged = ", ".join(state["tagged_in_session"])
            self._send(chat_id, f"🛰 Watch stopped. Named this time: {tagged}")
        else:
            self._send(chat_id, "🛰 Watch stopped. Nothing was named.")

    def _watch_status(self, chat_id: int) -> None:
        with self._watch_lock:
            s = self._watch_state
            alive = bool(self._watch_thread and self._watch_thread.is_alive())
        if not alive or not s:
            self._send(chat_id, "ℹ️ No watch is running.")
            return
        self._send(chat_id,
            f"🛰 Watch running — {ui.plural(len(s['baseline']), 'unnamed device')} watched\n"
            f"Names left: {', '.join(s['pending_names']) or 'none'}\n"
            f"Named so far: {', '.join(s['tagged_in_session']) or 'none'}",
            buttons=[[ui.button("🛑 Stop watch", f"{self.ctx.name}:watchstop:-")]])

    def _watch_loop(self) -> None:
        """Polling worker. Detects 'lowest last-activity' transitions."""
        try:
            while not self._watch_stop.is_set():
                self._watch_stop.wait(self._watch_poll_seconds)
                if self._watch_stop.is_set():
                    return
                with self._watch_lock:
                    s = self._watch_state
                    if s is None:
                        return
                    if s.get("awaiting_pick"):
                        # Waiting on the user to answer; don't fire again
                        continue
                    if not s["pending_names"]:
                        # All names used — auto-stop
                        chat_id = s["chat_id"]
                        self._watch_stop.set()
                        self._send(chat_id, "✅ Every name is handed out. Watch stopped.")
                        return
                    if time.time() - s["last_alert_ts"] < self._watch_cooldown_seconds:
                        continue

                try:
                    clients = self.router.wifi_clients()
                except Exception as e:
                    self.log.warning("watch poll failed: %s", e)
                    continue

                tags = self._tags()
                target = None
                with self._watch_lock:
                    s = self._watch_state
                    if s is None:
                        return
                    baseline = s["baseline"]
                    # Find ANY untagged candidate whose last_activity just
                    # transitioned from idle (>threshold) to active
                    # (≤threshold). Constantly-active devices (cameras) are
                    # filtered because their prev sample is also ≤threshold.
                    thr = self._watch_idle_threshold_ms
                    transitions = []
                    for c in clients:
                        if c.mac not in baseline or TagStore.has_active_in_snapshot(c.mac, tags):
                            continue
                        prev = baseline.get(c.mac, 0)
                        if c.last_activity_ms <= thr and prev > thr:
                            transitions.append((c, prev))
                    # Update baseline for next round
                    for c in clients:
                        if c.mac in baseline:
                            baseline[c.mac] = c.last_activity_ms
                    if not transitions:
                        continue
                    # If multiple transitioned at once, pick the one with
                    # the *largest* prev → "was sleeping the longest", most
                    # likely the device the user just woke up.
                    transitions.sort(key=lambda t: t[1], reverse=True)
                    target = transitions[0][0]
                    s["awaiting_pick"] = target.mac
                    s["last_alert_ts"] = time.time()
                    chat_id = s["chat_id"]
                    pending = list(s["pending_names"])

                if target is not None:
                    self._send_watch_picker(chat_id, target, pending)
        except Exception as e:
            self.log.exception("watch loop crashed: %s", e)

    def _send_watch_picker(self, chat_id: int, target, pending: list[str]) -> None:
        # Build inline keyboard with each candidate name as a button
        # callback_data = "lan_scanner:watchpick:<MAC>:<name_index>"
        rows = []
        for i, name in enumerate(pending):
            rows.append([{
                "text": f"🏷 {name}",
                "callback_data": f"lan_scanner:watchpick:{target.mac}:{i}",
            }])
        rows.append([
            {"text": "⏭ Skip this one",
             "callback_data": f"lan_scanner:watchpick:{target.mac}:-1"},
            {"text": "🛑 Stop watch",
             "callback_data": "lan_scanner:watchstop:-"},
        ])
        tg = self.ctx.notifiers_by_id.get("tg")
        tag_name, tag_retired = self.tag_info(target.mac)
        tag_line = (
            f"Name: {tag_name}{' (retired)' if tag_retired else ''}\n"
            if tag_name else ""
        )
        text = (
            f"🛰 A device just woke up — which one was it?\n"
            f"{tag_line}"
            f"{ui.item(target.mac, target.ssid, f'{target.signal_dbm} dBm', target.interface)}"
        )
        if tg and hasattr(tg, "api_post"):
            tg.api_post("sendMessage", {
                "chat_id": chat_id,
                "text": text,
                "reply_markup": json.dumps({"inline_keyboard": rows}),
            })
        else:
            self._send(chat_id, text + "\n" + ", ".join(pending))

    # ─── callback flow: 🏷 Tag button + watch picker ────────────

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # Expected formats (a MAC has colons of its own, so only the first two
        # separators are structural):
        #   lan_scanner:tagprompt:<MAC>
        #   lan_scanner:watchpick:<MAC>:<index>   (index -1 = skip)
        #   lan_scanner:watchstop:-
        #   lan_scanner:view:<all|known|unknown>   lan_scanner:ping:-   lan_scanner:dash:-
        prefix, _, tail = data.partition(":")
        verb, _, arg = tail.partition(":")
        if prefix != self.ctx.name or not verb:
            return
        tg = self.ctx.notifiers_by_id.get("tg") or self.notifier

        def ack(text: str = "") -> None:
            if hasattr(tg, "answer_callback"):
                tg.answer_callback(callback_id, text)

        if verb == "view":
            ack()
            self._cmd_list(chat_id, mode=arg if arg in ("known", "unknown") else "all")
            return
        if verb == "ping":
            ack("Sweeping…")
            self._cmd_ping(chat_id, "")
            return
        if verb == "dash":
            ack()
            self._cmd_dashboard(chat_id, "")
            return

        if verb == "tagprompt":
            mac = _norm_mac(arg)
            if not mac:
                ack("That device is no longer listed")
                return
            self._pending_tag_for_chat[chat_id] = mac
            tag_name, tag_retired = self.tag_info(mac)
            tag_line = (
                f"\nCurrent name: {tag_name}{' (retired)' if tag_retired else ''}"
                if tag_name else ""
            )
            vendor = self._oui_lookup(mac, online=False)
            vendor_line = f"\nMade by: {vendor}" if vendor else ""
            # A new message, not an edit: the button may sit under an alert
            # whose text should stay readable.
            self._send(chat_id,
                       f"🏷 What should {mac} be called?{vendor_line}{tag_line}\n"
                       "Send the name as your next message, e.g. Kitchen camera")
            ack("Send a name")
            return

        if verb == "watchstop":
            if tg and hasattr(tg, "answer_callback"):
                tg.answer_callback(callback_id, "Stopping…")
            if tg and hasattr(tg, "edit_message"):
                tg.edit_message(chat_id, message_id, "🛑 Stop requested.")
            self._stop_watch(chat_id)
            return

        if verb == "watchpick":
            mac, _, raw_idx = arg.rpartition(":")
            try:
                idx = int(raw_idx)
            except ValueError:
                idx = -1
            with self._watch_lock:
                s = self._watch_state
                if not s or s.get("awaiting_pick") != mac:
                    if tg and hasattr(tg, "answer_callback"):
                        tg.answer_callback(callback_id, "Stale")
                    return
                if idx == -1:
                    # Skip — clear awaiting and let cooldown start fresh
                    s["awaiting_pick"] = None
                    s["last_alert_ts"] = time.time()
                    chosen_name = None
                else:
                    pending = s["pending_names"]
                    if 0 <= idx < len(pending):
                        chosen_name = pending.pop(idx)
                    else:
                        chosen_name = None
                    s["awaiting_pick"] = None
                    s["last_alert_ts"] = time.time()
                    if chosen_name:
                        self.set_tag(mac, chosen_name)
                        s["tagged_in_session"].append(f"{chosen_name}={mac}")
                        # Remove from baseline so we don't re-prompt for same MAC
                        s["baseline"].pop(mac, None)

            if tg and hasattr(tg, "answer_callback"):
                tg.answer_callback(callback_id, "Got it")
            if tg and hasattr(tg, "edit_message"):
                if chosen_name:
                    remaining = ", ".join(s["pending_names"]) if s else "(none)"
                    tg.edit_message(
                        chat_id, message_id,
                        f"🏷 Named {mac} “{chosen_name}”.\n"
                        f"Names left: {remaining or 'none'}"
                    )
                else:
                    tg.edit_message(chat_id, message_id,
                                     f"⏭ Skipped {mac}. Switch another device on or off.")
            return

    def on_event(self, event: str, payload: dict) -> None:
        # Capture plain-text replies that follow a tagprompt
        if event != "telegram.text":
            return
        chat_id = payload.get("chat_id")
        text = (payload.get("text") or "").strip()
        if not chat_id or not text or text.startswith("/"):
            return
        pending = getattr(self, "_pending_tag_for_chat", {})
        mac = pending.pop(chat_id, None) if pending else None
        if not mac:
            return
        try:
            self.set_tag(mac, text[:60])
        except ValueError:
            self.log.exception("could not name %s", mac)
            self._send(chat_id, f"❌ {mac} was NOT named — that name couldn't be saved. "
                                "Tap the name button again to retry.")
            return
        self._send(chat_id, f"🏷 Named {mac} “{text[:60]}”.")

    # ─── public helper for other plugins ────────────────────────

    def tags_snapshot(self) -> dict[str, Any]:
        """Return a copy of the MAC tag store for read-only consumers."""
        return self._tag_store.snapshot()

    def set_tag(self, mac: str, name: str) -> dict[str, Any] | None:
        """Assign or update a friendly name for a MAC address."""
        return self._tag_store.set(mac, name, source="lan_scanner")

    def remove_tag(self, mac: str) -> dict[str, Any] | None:
        """Remove active and retired tag data for a MAC address."""
        return self._tag_store.remove(mac)

    def retire_tag(self, mac: str) -> dict[str, Any]:
        """Mark a MAC tag as retired while keeping its historical name."""
        return self._tag_store.retire(mac)

    def tag_for(self, mac: str) -> str | None:
        """Return the friendly name for a MAC, or None if untagged."""
        return self._tag_store.name_for(mac, include_retired=True)

    def has_active_tag(self, mac: str) -> bool:
        """Return True when a MAC has a non-retired tag."""
        return self._tag_store.has_active(mac)

    def tag_label(self, mac: str, ip: str = "", hostname: str = "") -> str:
        """Return a label that includes the MAC tag whenever one exists."""
        return self._tag_store.label_for(mac, ip=ip, hostname=hostname)

    def tag_info(self, mac: str) -> tuple[str, bool]:
        """Return (name, retired) for a MAC tag."""
        return self._tag_store.tag_info(mac)

    # ─── helpers ────────────────────────────────────────────────

    def _find_dashboard(self):
        """Locate the lan_dashboard plugin for the /lan dashboard subcommand."""
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(p, "__class__", None).__name__ == "LanDashboardPlugin":
                return p
        return None

    def _send_help(self, chat_id: int) -> None:
        self._send(chat_id, "\n".join([
            ui.title("🗂", "Devices", "what you can type"),
            "The buttons below cover the lists. Typed forms:",
            "• /lan search <text> — find a device by name, IP or MAC",
            "• /lan tag <MAC> <name> — name a device",
            "• /lan untag <MAC> — remove a name",
            "• /lan vendor <MAC> — who made it",
            "• /lan ping <network> — ping every address (default: the Pi's network)",
            "• /lan watch <name1>,<name2> — name devices by switching them on",
        ]), buttons=self._view_buttons("help"))

    def _send(self, chat_id: int, text: str, buttons: list | None = None) -> None:
        """Send ``text`` (split if long); ``buttons`` go under the last part."""
        chunks = list(_chunk(text, 3900))
        for i, chunk in enumerate(chunks):
            extra = {"buttons": buttons} if buttons and i == len(chunks) - 1 else {}
            if hasattr(self.notifier, "send_to"):
                self.notifier.send_to(chat_id, chunk, **extra)
            else:
                self.notifier.send(chunk, **extra)


def _sort_key(it: dict[str, Any]) -> tuple:
    """Named devices first (by name), then the rest by what they're called."""
    tag = it.get("tagged_name") or ""
    return (0 if tag else 1, (tag or it.get("hostname") or it["mac"]).lower())


def _device_line(it: dict[str, Any], *, with_place: bool = False) -> str:
    """``🏷 Kitchen plug — IoT · 192.0.2.8 · -32 dBm``: the name first; the MAC
    only for a device without a name of its own (always in search results,
    where the owner may have searched for it)."""
    tag = it.get("tagged_name")
    if tag:
        name = f"🏷 {tag}" + (" (retired)" if it.get("tag_retired") else "")
        mac = it["mac"] if with_place else ""
    else:
        name = it.get("hostname") or it["mac"]
        mac = it["mac"] if it.get("hostname") else ""
    iface = it.get("iface") or ""
    kind, _, place = iface.partition(":")
    where = (f"{kind} {place}" if with_place else place) if place else iface
    ip = it["ip"] if it.get("ip") not in ("", "?") else ""
    signal = f"{it['signal']} dBm" if it.get("signal") is not None else ""
    return ui.item(name[:60], where if where != "?" else "", ip, signal, mac)


def _is_private_mac(mac: str) -> bool:
    """True for a locally administered (randomised) address: second hex digit 2/6/A/E."""
    return len(mac) >= 2 and mac[1].upper() in "26AE"


def _chunk(text: str, n: int):
    for i in range(0, len(text), n):
        yield text[i:i + n]
