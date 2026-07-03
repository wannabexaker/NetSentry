"""
Router abstraction layer.

Plugins call methods on an abstract Router; the actual implementation is
swappable. Today: MikroTik via SSH. Future: OpenWrt, pfSense, UniFi, etc.

The interface is intentionally **small** — only operations that NetSentry
plugins need. Vendor-specific commands stay in the concrete implementation.
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class WifiClient:
    mac: str
    ssid: str
    interface: str
    signal_dbm: int
    band: str
    auth_type: str
    last_activity_ms: int = 0      # ms since last frame from this client


@dataclass(frozen=True)
class WifiTraffic:
    mac: str
    tx_bytes: int
    rx_bytes: int
    last_activity_ms: int


def _parse_routeros_duration(s: str) -> int:
    """Convert RouterOS time strings ("36s10ms", "1m20s", "1d4h5m") to ms.
    Returns 0 if it can't parse."""
    if not s:
        return 0
    s = s.strip().lower()
    # Already a plain integer (ms)
    if s.isdigit():
        return int(s)
    total = 0
    units = {"w": 604800_000, "d": 86400_000, "h": 3600_000,
             "m": 60_000, "s": 1000, "ms": 1}
    # Walk through pairs of digits + unit suffix; do longest-suffix first
    # so "ms" beats "s".
    cur = ""
    i = 0
    while i < len(s):
        ch = s[i]
        if ch.isdigit():
            cur += ch
            i += 1
            continue
        # Match unit
        if s[i:i + 2] == "ms":
            unit = "ms"
            i += 2
        else:
            unit = ch
            i += 1
        if cur and unit in units:
            total += int(cur) * units[unit]
        cur = ""
    return total


def _parse_routeros_int(s: str) -> int:
    """Parse RouterOS integer-like byte fields."""
    value = re.sub(r"\s+", "", (s or "").strip().replace(",", ""))
    if not value:
        return 0
    if value.isdigit():
        return int(value)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgt]?i?b?|b)?", value, re.IGNORECASE)
    if not m:
        return 0
    number = float(m.group(1))
    unit = (m.group(2) or "").lower()
    scale = {
        "k": 1000,
        "kb": 1000,
        "m": 1000 ** 2,
        "mb": 1000 ** 2,
        "g": 1000 ** 3,
        "gb": 1000 ** 3,
        "t": 1000 ** 4,
        "tb": 1000 ** 4,
        "ki": 1024,
        "kib": 1024,
        "mi": 1024 ** 2,
        "mib": 1024 ** 2,
        "gi": 1024 ** 3,
        "gib": 1024 ** 3,
        "ti": 1024 ** 4,
        "tib": 1024 ** 4,
        "b": 1,
    }.get(unit, 1)
    return int(number * scale)


def _parse_routeros_int_pair(value: str) -> tuple[int, int] | None:
    """Parse RouterOS list-like integer pairs such as bytes=123,456."""
    text = (value or "").strip().strip('"')
    parts = [part.strip() for part in text.split(",")]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return _parse_routeros_int(parts[0]), _parse_routeros_int(parts[1])


@dataclass(frozen=True)
class EtherClient:
    mac: str
    port: str          # e.g. "ether4"
    bridge: str


@dataclass(frozen=True)
class DhcpLease:
    mac: str
    ip: str
    hostname: str
    comment: str = ""


@dataclass(frozen=True)
class ArpEntry:
    mac: str
    ip: str
    interface: str    # e.g. "bridge", "bridge-guest", "ether1"
    complete: bool    # true if the entry has a valid MAC; stale otherwise


@dataclass
class SystemStats:
    uptime_seconds: int
    cpu_load_pct: int
    free_memory_bytes: int
    total_memory_bytes: int
    free_disk_bytes: int
    total_disk_bytes: int
    board_name: str
    routeros_version: str


class Router(ABC):
    """Abstract router. Implementations: MikroTikRouter, OpenWrtRouter (future)."""

    # --- system ----------------------------------------------------

    @abstractmethod
    def stats(self) -> SystemStats | None: ...

    @abstractmethod
    def uptime_seconds(self) -> int: ...

    @abstractmethod
    def reboot(self) -> None: ...

    # --- network ---------------------------------------------------

    @abstractmethod
    def public_ip(self) -> str | None: ...

    @abstractmethod
    def wan_running(self) -> bool: ...

    @abstractmethod
    def wifi_clients(self) -> list[WifiClient]: ...

    @abstractmethod
    def wifi_traffic(self) -> list[WifiTraffic]:
        """Return WiFi registration-table byte counters per client."""
        ...

    @abstractmethod
    def ethernet_clients(self) -> list[EtherClient]: ...

    @abstractmethod
    def dhcp_leases(self) -> list[DhcpLease]: ...

    @abstractmethod
    def arp_table(self) -> list[ArpEntry]: ...

    @abstractmethod
    def ip_accounting_snapshot(self) -> dict[str, tuple[int, int]]:
        """Return IP accounting deltas as IP -> (tx_bytes, rx_bytes)."""
        ...

    # --- security actions ------------------------------------------

    @abstractmethod
    def disconnect_mac(self, mac: str) -> bool: ...

    @abstractmethod
    def block_mac(self, mac: str, comment: str = "") -> bool: ...

    @abstractmethod
    def unblock_mac(self, mac: str) -> bool: ...

    def blocked_macs(self) -> set[str]:
        """MACs currently blocked (reject access-list). Best-effort; default none."""
        return set()

    # --- WiFi config -----------------------------------------------

    @abstractmethod
    def set_wifi_passphrase(self, security_profile: str, passphrase: str) -> bool: ...

    @abstractmethod
    def get_wifi_passphrase(self, security_profile: str) -> str | None: ...

    # --- diagnostics -----------------------------------------------

    @abstractmethod
    def log_tail(self, n: int = 50, topic_filter: str | None = None) -> list[str]: ...

    @abstractmethod
    def export_config(self, remote_filename: str) -> bool: ...

    @abstractmethod
    def fetch_file(self, remote_path: str, local_path: str) -> bool: ...

    @abstractmethod
    def delete_file(self, remote_path: str) -> bool: ...

    @abstractmethod
    def scan_wifi(self, interface: str, duration_seconds: int, save_file: str) -> bool: ...


# ════════════════════════════════════════════════════════════════════
#  MikroTik implementation (SSH-based, RouterOS v7 wifi-qcom)
# ════════════════════════════════════════════════════════════════════

class MikroTikRouter(Router):
    """RouterOS v7+ implementation, communicates over SSH key auth."""

    def __init__(self, host: str, user: str, ssh_key: str, port: int = 22):
        self.host = host
        self.user = user
        self.ssh_key = ssh_key
        self.port = port
        # SSH connection multiplexing: one TCP+SSH session is shared
        # across all router queries via OpenSSH ControlMaster. Without
        # this, every plugin call opens a fresh session which spams
        # the router auth log (we observed ~150 logins/min). Socket
        # path is per-(user, host, port) to be safe across multi-router
        # setups. ControlPersist keeps the master alive for 5 min of
        # idle time, then a new login happens automatically.
        socket_id = f"{user}-{host}-{port}".replace("/", "_").replace(" ", "_")
        # /tmp keeps the ControlMaster path under the 108-char sun_path limit;
        # the service runs with systemd PrivateTmp=yes (private /tmp) and ssh
        # refuses a control socket it does not own with 0600 perms.
        self._ssh_socket = f"/tmp/netsentry-ssh-{socket_id}"  # nosec B108
        self._write_lock = threading.RLock()

    # ─── SSH plumbing ─────────────────────────────────────────────

    def _ssh(self, command: str, timeout: int = 10) -> tuple[int, str]:
        rc, out, _ = self._ssh_with_stderr(command, timeout)
        return rc, out

    def _ssh_with_stderr(self, command: str, timeout: int = 10) -> tuple[int, str, str]:
        try:
            r = subprocess.run(
                ["ssh",
                 "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5",
                 "-o", "ControlMaster=auto",
                 "-o", f"ControlPath={self._ssh_socket}",
                 "-o", "ControlPersist=300",
                 "-p", str(self.port), "-i", self.ssh_key,
                 f"{self.user}@{self.host}", command],
                capture_output=True, text=True, timeout=timeout,
            )
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return -1, "", ""

    def _ssh_kv(self, command: str, timeout: int = 10) -> dict[str, str]:
        """Run a command that outputs `KEY=value` lines; parse to dict."""
        rc, out = self._ssh(command, timeout)
        if rc != 0:
            return {}
        return {
            line.split("=", 1)[0].strip(): line.split("=", 1)[1].strip()
            for line in out.strip().splitlines() if "=" in line
        }

    # ─── system ───────────────────────────────────────────────────

    def stats(self) -> SystemStats | None:
        d = self._ssh_kv(
            ':put ("UPTIME=" . [/system resource get uptime]);'
            ':put ("CPU=" . [/system resource get cpu-load]);'
            ':put ("FREEMEM=" . [/system resource get free-memory]);'
            ':put ("TOTMEM=" . [/system resource get total-memory]);'
            ':put ("FREEDISK=" . [/system resource get free-hdd-space]);'
            ':put ("TOTDISK=" . [/system resource get total-hdd-space]);'
            ':put ("BOARD=" . [/system resource get board-name]);'
            ':put ("VERSION=" . [/system resource get version])'
        )
        if not d:
            log.warning("Router stats unavailable: SSH query returned no data")
            return None
        return SystemStats(
            uptime_seconds=_parse_uptime(d.get("UPTIME", "")),
            cpu_load_pct=int(d.get("CPU", "0") or 0),
            free_memory_bytes=int(d.get("FREEMEM", "0") or 0),
            total_memory_bytes=int(d.get("TOTMEM", "1") or 1),
            free_disk_bytes=int(d.get("FREEDISK", "0") or 0),
            total_disk_bytes=int(d.get("TOTDISK", "1") or 1),
            board_name=d.get("BOARD", "?"),
            routeros_version=d.get("VERSION", "?"),
        )

    def uptime_seconds(self) -> int:
        rc, out = self._ssh(":put [/system resource get uptime]")
        return _parse_uptime(out) if rc == 0 else 0

    def reboot(self) -> None:
        with self._write_lock:
            self._ssh("/system reboot", timeout=5)

    # ─── network ──────────────────────────────────────────────────

    def public_ip(self) -> str | None:
        rc, out = self._ssh(":put [/ip cloud get public-address]")
        return out.strip() or None if rc == 0 else None

    def wan_running(self) -> bool:
        rc, out = self._ssh(":put [/interface get ether1 running]")
        return rc == 0 and out.strip() == "true"

    def wifi_clients(self) -> list[WifiClient]:
        # `as-value` is unreliable on RouterOS 7.22.1 — use pretty-print.
        # Columns: INTERFACE  SSID  MAC  UPTIME  LAST-ACTIVITY  SIGNAL  AUTH-TYPE
        # (the BAND column is no longer emitted on recent firmwares; we infer
        #  it from the interface name when callers need it).
        rc, out = self._ssh("/interface wifi registration-table print")
        if rc != 0:
            return []
        line_re = re.compile(
            r"^\s*\d+\s+(?:[A-Z]\s+)?"
            r"(\S+)\s+"                              # interface
            r"(\S+)\s+"                              # ssid
            r"([0-9A-F:]{17})\s+"                    # mac
            r"\S+\s+"                                # uptime
            r"(\S+)\s+"                              # last-activity
            r"(-?\d+)\s+"                            # signal
            r"(\S+)",                                # auth-type
            re.IGNORECASE,
        )
        result = []
        for line in out.splitlines():
            m = line_re.match(line)
            if not m:
                continue
            iface, ssid, mac, last_act, sig, auth = m.groups()
            band = "5ghz" if iface in ("wifi1",) else "2.4ghz"
            result.append(WifiClient(
                mac=mac.upper(), ssid=ssid, interface=iface,
                signal_dbm=int(sig), band=band, auth_type=auth,
                last_activity_ms=_parse_routeros_duration(last_act),
            ))
        return result

    def wifi_traffic(self) -> list[WifiTraffic]:
        """Read WiFi registration-table byte counters using pretty output."""
        rc, out = self._ssh("/interface wifi registration-table print detail")
        if rc != 0:
            return []

        result: list[WifiTraffic] = []
        seen: set[str] = set()

        # Be tolerant of detail-style pretty output if an operator aliases the
        # command; do not use RouterOS as-value because it is broken on 7.22.1.
        for record in _routeros_records(out):
            traffic = _wifi_traffic_from_fields(_routeros_fields(record))
            if traffic is None:
                continue
            result.append(traffic)
            seen.add(traffic.mac)

        header: list[str] = []
        for line in out.splitlines():
            cols = line.strip().split()
            upper = [c.upper() for c in cols]
            if (
                "MAC-ADDRESS" in upper
                and (
                    "BYTES" in upper
                    or ("TX-BYTES" in upper and "RX-BYTES" in upper)
                    or ("TX-BYTE" in upper and "RX-BYTE" in upper)
                )
            ):
                header = [c.lower() for c in cols if c != "#"]
                continue
            if not re.match(r"^\s*\d+\s+", line):
                continue
            data = cols[1:]
            if data and re.fullmatch(r"[A-Z]+", data[0]) and ":" not in data[0]:
                data = data[1:]
            mac_i = next(
                (i for i, token in enumerate(data)
                 if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", token, re.I)),
                -1,
            )
            if mac_i < 0:
                continue
            mac = data[mac_i].upper()
            if mac in seen:
                continue

            tx_i = rx_i = bytes_i = last_i = None
            if header:
                try:
                    offset = mac_i - header.index("mac-address")
                    bytes_header_i = _index_any(header, "bytes")
                    if bytes_header_i >= 0:
                        bytes_i = bytes_header_i + offset
                    else:
                        tx_header_i = _index_any(header, "tx-bytes", "tx-byte")
                        rx_header_i = _index_any(header, "rx-bytes", "rx-byte")
                        if tx_header_i >= 0 and rx_header_i >= 0:
                            tx_i = tx_header_i + offset
                            rx_i = rx_header_i + offset
                    last_header_i = _index_any(header, "last-activity")
                    if last_header_i >= 0:
                        last_i = last_header_i + offset
                except ValueError:
                    tx_i = rx_i = bytes_i = last_i = None

            if bytes_i is not None and 0 <= bytes_i < len(data):
                pair = _parse_routeros_int_pair(data[bytes_i])
                if pair is None:
                    continue
                tx_bytes, rx_bytes = pair
            elif (
                tx_i is not None and rx_i is not None
                and 0 <= tx_i < len(data) and 0 <= rx_i < len(data)
            ):
                tx_bytes = _parse_routeros_int(data[tx_i])
                rx_bytes = _parse_routeros_int(data[rx_i])
            else:
                continue
            last_activity = (
                _parse_routeros_duration(data[last_i])
                if last_i is not None and 0 <= last_i < len(data)
                else 0
            )
            result.append(WifiTraffic(
                mac=mac,
                tx_bytes=tx_bytes,
                rx_bytes=rx_bytes,
                last_activity_ms=last_activity,
            ))
        return result

    def ethernet_clients(self) -> list[EtherClient]:
        # Columns: MAC-ADDRESS  ON-INTERFACE  BRIDGE
        rc, out = self._ssh(
            '/interface bridge host print where on-interface~"^ether" and local=no'
        )
        if rc != 0:
            return []
        host_re = re.compile(
            r"^\s*\d+\s+\S*\s*"
            r"([0-9A-F:]{17})\s+"     # mac
            r"(ether\d+)\s+"          # on-interface (port)
            r"(\S+)",                 # bridge
            re.IGNORECASE,
        )
        result = []
        for line in out.splitlines():
            m = host_re.match(line)
            if m:
                mac, port, bridge = m.groups()
                result.append(EtherClient(mac=mac.upper(), port=port, bridge=bridge))
        return result

    def ip_accounting_snapshot(self) -> dict[str, tuple[int, int]]:
        """Take and parse an IP accounting snapshot.

        Values are byte deltas since the previous RouterOS accounting snapshot,
        folded into per-IP transmit and receive totals.

        On RouterOS 7.x the legacy /ip accounting menu may be absent
        entirely. On the first failed call we detect that and disable
        further calls for the life of this Router instance, so we
        don't spam the router log with `bad command name accounting`
        once every poll cycle.
        """
        if getattr(self, "_accounting_unavailable", False):
            return {}
        rc, out, err = self._ssh_with_stderr(
            "/ip accounting snapshot take; /ip accounting snapshot print detail"
        )
        # RouterOS sshd often returns rc=0 even when the script fails;
        # rely on the stderr signature to detect a missing menu.
        if rc != 0 or "bad command name" in err.lower() or "no such item" in err.lower():
            self._accounting_unavailable = True
            return {}

        totals: dict[str, list[int]] = {}
        for record in _routeros_records(out):
            fields = _routeros_fields(record)
            src = fields.get("src-address") or fields.get("src")
            dst = fields.get("dst-address") or fields.get("dst")
            if not src or not dst or "bytes" not in fields:
                continue
            byte_count = _parse_routeros_int(fields["bytes"])
            src_totals = totals.setdefault(src, [0, 0])
            dst_totals = totals.setdefault(dst, [0, 0])
            src_totals[0] += byte_count
            dst_totals[1] += byte_count

        line_re = re.compile(
            r"^\s*\d+\s+(?:[A-Z]+\s+)?"
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"\d+\s+"
            r"(\S+)\s*$"
        )
        for line in out.splitlines():
            m = line_re.match(line)
            if not m:
                continue
            src, dst, byte_s = m.groups()
            byte_count = _parse_routeros_int(byte_s)
            src_totals = totals.setdefault(src, [0, 0])
            dst_totals = totals.setdefault(dst, [0, 0])
            src_totals[0] += byte_count
            dst_totals[1] += byte_count
        return {ip: (v[0], v[1]) for ip, v in totals.items()}

    def dhcp_leases(self) -> list[DhcpLease]:
        # `as-value` returns empty on RouterOS 7.22.1 — parse pretty-print.
        # Columns: ADDRESS  MAC-ADDRESS  HOST-NAME  SERVER
        # Note: `;;;` lines are comments; we don't fold them into entries.
        rc, out = self._ssh("/ip dhcp-server lease print")
        if rc != 0:
            return []
        line_re = re.compile(
            r"^\s*\d+\s+\S*\s*"
            r"(\d+\.\d+\.\d+\.\d+)\s+"               # ip
            r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})"       # mac
            r"(?:\s+(\S.*?))?"                        # hostname (optional)
            r"\s+(\S+)\s*$",                          # server
            re.IGNORECASE,
        )
        result = []
        for line in out.splitlines():
            m = line_re.match(line)
            if not m:
                continue
            ip, mac, hostname, _server = m.groups()
            result.append(DhcpLease(
                mac=mac.upper(),
                ip=ip,
                hostname=(hostname or "").strip(),
            ))
        return result

    def arp_table(self) -> list[ArpEntry]:
        # `as-value` returns empty on at least RouterOS 7.22.1 for /ip arp,
        # so parse the pretty-print output instead.
        rc, out = self._ssh("/ip arp print")
        if rc != 0:
            return []
        # Line shape:  N FLAGS IP MAC IFACE VRF STATUS
        line_re = re.compile(
            r"^\s*\d+\s+([A-Z]*)\s+"           # flags column (may be empty)
            r"(\d+\.\d+\.\d+\.\d+)\s+"          # IP
            r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})\s+"  # MAC
            r"(\S+)",                            # interface
            re.IGNORECASE,
        )
        result: list[ArpEntry] = []
        for line in out.splitlines():
            m = line_re.match(line)
            if not m:
                continue
            flags, ip, mac, iface = m.groups()
            complete = "C" in (flags or "").upper()
            result.append(ArpEntry(
                mac=mac.upper(),
                ip=ip,
                interface=iface,
                complete=complete,
            ))
        return result

    # ─── security ─────────────────────────────────────────────────

    def disconnect_mac(self, mac: str) -> bool:
        m = _valid_mac(mac)
        if m is None:
            log.error("Refusing disconnect: invalid MAC address %r", mac)
            return False
        with self._write_lock:
            rc, _ = self._ssh(
                f'/interface wifi registration-table remove [find mac-address={m}]'
            )
        return rc == 0

    def block_mac(self, mac: str, comment: str = "") -> bool:
        m = _valid_mac(mac)
        if m is None:
            log.error("Refusing block: invalid MAC address %r", mac)
            return False
        c = f' comment={_routeros_quote(comment)}' if comment else ""
        with self._write_lock:
            rc, _ = self._ssh(
                f'/interface wifi access-list add mac-address={m} action=reject{c};'
                f'/interface wifi registration-table remove [find mac-address={m}]'
            )
        return rc == 0

    def unblock_mac(self, mac: str) -> bool:
        m = _valid_mac(mac)
        if m is None:
            log.error("Refusing unblock: invalid MAC address %r", mac)
            return False
        with self._write_lock:
            rc, _ = self._ssh(
                f'/interface wifi access-list remove [find mac-address={m}]'
            )
        return rc == 0

    def blocked_macs(self) -> set[str]:
        """Set of upper-case MACs on a reject access-list entry (best-effort)."""
        rc, out = self._ssh(
            "/interface wifi access-list print where action=reject"
        )
        if rc != 0 or not out:
            return set()
        return {m.upper() for m in re.findall(r"mac-address=([0-9A-Fa-f:]{17})", out)}

    # ─── WiFi config ──────────────────────────────────────────────

    def set_wifi_passphrase(self, security_profile: str, passphrase: str) -> bool:
        if not security_profile:
            log.error("Cannot set WiFi passphrase: empty security profile")
            return False

        profile_q = _routeros_quote(security_profile)
        passphrase_q = _routeros_quote(passphrase)

        with self._write_lock:
            rc, out = self._ssh(
                f'/interface wifi security set [find name={profile_q}] '
                f'passphrase={passphrase_q}; :put OK'
            )
            if rc != 0 or "OK" not in out:
                log.error("Failed to set WiFi security profile %s", security_profile)
                return False

            interfaces = self._wifi_interfaces_for_security_profile(security_profile)
            if interfaces is None:
                return False
            write_ok = True
            for iface_id, iface_name in interfaces:
                rc, out = self._ssh(
                    f'/interface wifi set {iface_id} '
                    f'security.passphrase={passphrase_q}; :put OK'
                )
                if rc != 0 or "OK" not in out:
                    log.error(
                        "Failed to set inline passphrase on interface %s (%s)",
                        iface_name,
                        iface_id,
                    )
                    write_ok = False

            verify_ok = self._verify_wifi_passphrase(
                security_profile,
                passphrase,
                [name for _, name in interfaces],
            )
            return write_ok and verify_ok

    def get_wifi_passphrase(self, security_profile: str) -> str | None:
        profile_q = _routeros_quote(security_profile)
        rc, out = self._ssh(
            f':put [/interface wifi security get [find name={profile_q}] passphrase]'
        )
        return out.strip() if rc == 0 and out.strip() else None

    def _wifi_interfaces_for_security_profile(
        self,
        security_profile: str,
    ) -> list[tuple[str, str]] | None:
        profile_q = _routeros_quote(security_profile)
        rc, out = self._ssh(
            f':put [/interface wifi find where security={profile_q}]'
        )
        if rc != 0:
            log.error(
                "Failed to discover WiFi interfaces for security profile %s",
                security_profile,
            )
            return None

        interfaces: list[tuple[str, str]] = []
        for iface_id in _parse_routeros_find_ids(out):
            rc_name, name_out = self._ssh(f':put [/interface wifi get {iface_id} name]')
            iface_name = name_out.strip() if rc_name == 0 else ""
            if not iface_name:
                log.error("Failed to read WiFi interface name for RouterOS id %s", iface_id)
                return None
            interfaces.append((iface_id, iface_name))
        return interfaces

    def _verify_wifi_passphrase(
        self,
        security_profile: str,
        passphrase: str,
        interface_names: list[str],
    ) -> bool:
        ok = True
        profile_value = self.get_wifi_passphrase(security_profile)
        if profile_value != passphrase:
            log.error("WiFi passphrase verify failed for profile %s", security_profile)
            ok = False

        for iface_name in interface_names:
            iface_q = _routeros_quote(iface_name)
            rc, out = self._ssh(
                f':put [/interface wifi get [find name={iface_q}] security.passphrase]'
            )
            iface_value = out.strip() if rc == 0 else None
            if iface_value != passphrase:
                log.error("WiFi passphrase verify failed for interface %s", iface_name)
                ok = False
        return ok

    # ─── diagnostics ──────────────────────────────────────────────

    def log_tail(self, n: int = 50, topic_filter: str | None = None) -> list[str]:
        cmd = "/log print"
        if topic_filter:
            cmd += f' where topics~"{topic_filter}"'
        rc, out = self._ssh(cmd)
        if rc != 0:
            return []
        lines = out.strip().splitlines()
        return lines[-n:]

    def export_config(self, remote_filename: str) -> bool:
        with self._write_lock:
            rc, _ = self._ssh(f'/export file={_routeros_quote(remote_filename)}')
        return rc == 0

    def fetch_file(self, remote_path: str, local_path: str) -> bool:
        try:
            r = subprocess.run(
                ["scp", "-o", "BatchMode=yes", "-i", self.ssh_key,
                 f"{self.user}@{self.host}:{remote_path}", local_path],
                capture_output=True, text=True, timeout=60,
            )
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def delete_file(self, remote_path: str) -> bool:
        with self._write_lock:
            rc, _ = self._ssh(f'/file remove [find name={_routeros_quote(remote_path)}]')
        return rc == 0

    def scan_wifi(self, interface: str, duration_seconds: int, save_file: str) -> bool:
        rc, _ = self._ssh(
            f'/interface wifi scan {interface} duration={duration_seconds}s '
            f'save-file={save_file}',
            timeout=duration_seconds + 15,
        )
        return rc == 0


# ─── helpers ─────────────────────────────────────────────────────

_ROUTEROS_ID_RE = re.compile(r"^\*[A-Fa-f0-9]+$|^\d+$")
_UPTIME_RE = re.compile(r'(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d+):(\d+)')
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _routeros_quote(value: str) -> str:
    """Return a RouterOS double-quoted string literal."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _valid_mac(mac: str) -> str | None:
    """Normalise a MAC to upper-case colon form, or return None if malformed.

    Defence-in-depth for the router command sinks: only `[0-9A-F:]` can reach
    the SSH command, so a value containing `;`/quotes/spaces can never inject a
    second RouterOS command even if an untrusted MAC ever reaches these methods.
    """
    if not mac:
        return None
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        return None
    return mac.upper().replace("-", ":")


def _parse_routeros_find_ids(out: str) -> list[str]:
    """Parse RouterOS `find` output into validated internal ids."""
    ids: list[str] = []
    for token in re.split(r"[\s;]+", out.strip()):
        if not token:
            continue
        if _ROUTEROS_ID_RE.fullmatch(token):
            ids.append(token)
        else:
            log.warning("Ignoring unexpected RouterOS interface id token: %r", token)
    return ids


def _routeros_records(out: str) -> list[str]:
    """Group RouterOS pretty-print continuation lines into records."""
    records: list[str] = []
    current: list[str] = []
    for line in out.splitlines():
        if re.match(r"^\s*\d+\s+", line):
            if current:
                records.append(" ".join(current))
            current = [line.strip()]
        elif current and "=" in line:
            current.append(line.strip())
    if current:
        records.append(" ".join(current))
    return records


def _routeros_fields(record: str) -> dict[str, str]:
    """Parse key=value tokens from RouterOS detail-style pretty output."""
    return {
        key.lower(): value.strip('"')
        for key, value in re.findall(r'(\S+)=("[^"]*"|\S+)', record)
    }


def _wifi_traffic_from_fields(fields: dict[str, str]) -> WifiTraffic | None:
    """Build a WiFi traffic row from RouterOS registration-table fields."""
    mac = fields.get("mac-address") or fields.get("mac")
    if not mac:
        return None

    pair = None
    if "bytes" in fields:
        pair = _parse_routeros_int_pair(fields["bytes"])
    if pair is not None:
        tx_bytes, rx_bytes = pair
    elif "tx-bytes" in fields and "rx-bytes" in fields:
        tx_bytes = _parse_routeros_int(fields["tx-bytes"])
        rx_bytes = _parse_routeros_int(fields["rx-bytes"])
    elif "tx-byte" in fields and "rx-byte" in fields:
        tx_bytes = _parse_routeros_int(fields["tx-byte"])
        rx_bytes = _parse_routeros_int(fields["rx-byte"])
    else:
        return None

    return WifiTraffic(
        mac=mac.upper(),
        tx_bytes=tx_bytes,
        rx_bytes=rx_bytes,
        last_activity_ms=_parse_routeros_duration(fields.get("last-activity", "0")),
    )


def _index_any(items: list[str], *names: str) -> int:
    """Return the first matching index from a list, or -1."""
    for name in names:
        try:
            return items.index(name)
        except ValueError:
            continue
    return -1


def _parse_uptime(s: str) -> int:
    s = s.strip()
    m = _UPTIME_RE.fullmatch(s)
    if not m:
        return 0
    w, d, h, mn, sc = (int(x or 0) for x in m.groups())
    return w * 604800 + d * 86400 + h * 3600 + mn * 60 + sc


# ─── factory ─────────────────────────────────────────────────────

def build_router(cfg: dict) -> Router:
    """Construct the right Router subclass based on `cfg['type']`."""
    t = cfg.get("type", "mikrotik")
    if t == "mikrotik":
        return MikroTikRouter(
            host=cfg["host"], user=cfg["user"],
            ssh_key=cfg["ssh_key"], port=cfg.get("ssh_port", 22),
        )
    raise ValueError(f"Unknown router type: {t}")
