"""
Router abstraction layer.

Plugins call methods on an abstract Router; the actual implementation is
swappable. Today: MikroTik via SSH. Future: OpenWrt, pfSense, UniFi, etc.

The interface is intentionally **small** — only operations that NetSentry
plugins need. Vendor-specific commands stay in the concrete implementation.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

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
class TraceHit:
    """One DNS lookup caught by a trace rule: who sent it, and from where."""
    when: datetime
    mac: str
    ip: str
    interface: str


@dataclass(frozen=True)
class JoinEvent:
    """A device joining the network, as the router logged it."""
    when: datetime
    mac: str
    name: str = ""             # DHCP hostname, when the event carried one
    network: str = ""          # SSID, when the event carried one


_TRACE_ID_RE = re.compile(r"^[a-z0-9]{4,12}$")
_FORWARD_NAME_RE = re.compile(r"^[a-z0-9-]{3,24}$")
_KEEP_COMMENT = "netsentry-keep"
_FILE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
_ANY_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_WIFI_TABLE_RE = re.compile(
    r"^\s*\d+\s+(?:[A-Z]\s+)?"
    r"(\S+)\s+"                              # interface
    r"(\S+)\s+"                              # ssid
    r"([0-9A-F:]{17})\s+"                    # mac
    r"\S+\s+"                                # uptime
    r"(\S+)\s+"                              # last-activity
    r"(-?\d+)"                               # signal
    r"(?:\s+(\S+))?",                        # auth-type, when it fits the line
    re.IGNORECASE,
)
_TRACE_NEEDLE_RE = re.compile(r"^[a-z0-9_-]{4,40}$")
_LOG_TIME_RE = re.compile(r"^\s*(?:(\d{4}-\d{2}-\d{2}) )?(\d{2}:\d{2}:\d{2}) ")
_TRACE_HIT_RE = re.compile(
    r"firewall,info .*?in:(\S+?)[ ,].*?src-mac ([0-9A-Fa-f:]{17}).*?"
    r"(\d+\.\d+\.\d+\.\d+):\d+->")
_WIFI_JOIN_RE = re.compile(
    r"wireless,info ([0-9A-Fa-f:]{17})@\S+?\(([^)]*)\) connected")
_DHCP_JOIN_RE = re.compile(
    r"dhcp,info \S+ assigned \S+ (?:for|to) ([0-9A-Fa-f:]{17})(?: (\S+))?")


def _log_time(line: str) -> datetime | None:
    """Timestamp of a RouterOS log line (today's lines may omit the date)."""
    m = _LOG_TIME_RE.match(line)
    if not m:
        return None
    day = m.group(1) or datetime.now().strftime("%Y-%m-%d")
    try:
        return datetime.strptime(f"{day} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse_wifi_clients(out: str) -> list[WifiClient]:
    """WiFi clients from ``registration-table print detail`` (key=value records).

    Falls back to the column table for a router that prints that instead; there
    the trailing AUTH-TYPE column is optional, because RouterOS leaves out
    whatever does not fit the line.
    """
    clients: list[WifiClient] = []
    for record in _routeros_records(out):
        fields = _routeros_fields(record)
        mac = _valid_mac(fields.get("mac-address", ""))
        signal = fields.get("signal", "")
        if not mac or not re.fullmatch(r"-?\d+", signal):
            continue
        iface = fields.get("interface", "")
        band = fields.get("band", "")
        clients.append(WifiClient(
            mac=mac, ssid=fields.get("ssid", ""), interface=iface,
            signal_dbm=int(signal),
            band="5ghz" if band.startswith("5") or (not band and iface == "wifi1") else "2.4ghz",
            auth_type=fields.get("auth-type", ""),
            last_activity_ms=_parse_routeros_duration(fields.get("last-activity", "")),
        ))
    if clients:
        return clients
    for line in out.splitlines():
        m = _WIFI_TABLE_RE.match(line)
        if not m:
            continue
        iface, ssid, mac, last_act, sig, auth = m.groups()
        clients.append(WifiClient(
            mac=mac.upper(), ssid=ssid, interface=iface, signal_dbm=int(sig),
            band="5ghz" if iface == "wifi1" else "2.4ghz", auth_type=auth or "",
            last_activity_ms=_parse_routeros_duration(last_act),
        ))
    return clients


def parse_trace_hits(log_text: str) -> list[TraceHit]:
    """Trace-rule log lines → hits. Other lines mentioning the prefix are skipped."""
    out: list[TraceHit] = []
    for line in log_text.splitlines():
        m = _TRACE_HIT_RE.search(line)
        when = _log_time(line)
        if m and when:
            out.append(TraceHit(when, m.group(2).upper(), m.group(3), m.group(1)))
    return out


def parse_join_events(log_text: str) -> list[JoinEvent]:
    """WiFi-connect and DHCP-assign log lines → join events."""
    out: list[JoinEvent] = []
    for line in log_text.splitlines():
        when = _log_time(line)
        if not when:
            continue
        m = _WIFI_JOIN_RE.search(line)
        if m:
            out.append(JoinEvent(when, m.group(1).upper(), network=m.group(2)))
            continue
        m = _DHCP_JOIN_RE.search(line)
        if m:
            out.append(JoinEvent(when, m.group(1).upper(), name=m.group(2) or ""))
    return out


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

    def export_text(self) -> str:
        """The running config as text for drift detection. Default: unavailable."""
        return ""

    # --- "who asked for this domain?" (optional capability) ---------

    def dns_trace_add(self, trace_id: str, needle: str) -> bool:
        """Start logging the sender of every DNS query containing ``needle``."""
        return False

    def dns_trace_remove(self, trace_id: str) -> bool:
        return False

    def dns_trace_hits(self, trace_id: str) -> list[TraceHit]:
        return []

    def dns_trace_ids(self) -> list[str]:
        """Ids of trace rules currently installed on the router."""
        return []

    def join_events(self) -> list[JoinEvent]:
        """Recent WiFi-connect / DHCP-assign events still in the router log."""
        return []

    # --- reaching one device behind the router (optional capability) ---

    def port_forward_ensure(self, name: str, src_ip: str, port: int,
                            to_ip: str, to_port: int = 80) -> str:
        """Let ``src_ip`` (and only it) reach ``to_ip:to_port`` through the router.

        For a NetSentry host that sits on the router's WAN side and so cannot
        talk to a device on the inner networks. Returns ``"added"``,
        ``"exists"`` or ``"failed"``.
        """
        return "failed"

    def port_forward_remove(self, name: str) -> bool:
        return False

    # --- one WiFi device that keeps its own password (optional capability) ---

    def keep_wifi_passphrase(self, mac: str, ssid: str, label: str = "",
                             isolate: bool = True) -> str:
        """Let one device keep the password it is connected to ``ssid`` with.

        From then on that device (and only it) joins with that password, whatever
        the network's password is changed to later. The device has to be
        connected at the time, so that "the password it has" is known. The
        password is copied on the router and never leaves it.

        Returns ``"added"``, ``"exists"``, ``"not-connected"`` or ``"failed"``.
        """
        return "failed"

    def release_wifi_passphrase(self, mac: str) -> bool:
        """Undo :meth:`keep_wifi_passphrase`: the device follows the network again."""
        return False

    def kept_wifi_passphrases(self) -> dict[str, str] | None:
        """``{MAC: label}`` of the devices keeping their password; None if unreadable."""
        return {}

    def table_counts(self) -> dict[str, int] | None:
        """How many entries the router itself has: ``{"wifi", "dhcp", "arp"}``.

        Counted by the router, not parsed from its listings — so it can be held
        against what the listing parsers return. ``{}`` when the backend cannot
        say, None when the router did not answer.
        """
        return {}

    def backup_save(self, name: str) -> bool:
        """Write a full backup file ``<name>.backup`` on the router.

        True only when the file is really there afterwards — a router account
        without the permission is refused, and that must not pass as success.
        """
        return False

    def files_with_prefix(self, prefix: str) -> list[str] | None:
        """Names of the router's files that start with ``prefix``; None if unreadable."""
        return None

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
        # `as-value` is unreliable on RouterOS 7.22.1 — use pretty-print, and
        # the *detail* form: the table form drops columns that do not fit the
        # (non-interactive, 80-column) width. Once a client's uptime grew to
        # "19w5d12h26m24s" the AUTH-TYPE column vanished, the table parser
        # matched nothing, and every caller silently saw zero WiFi clients.
        rc, out = self._ssh(
            "/interface wifi registration-table print detail without-paging")
        if rc != 0:
            return []
        clients = parse_wifi_clients(out)
        if not clients and _ANY_MAC_RE.search(out):
            # Never again fail silently: addresses are listed, yet none was read.
            log.error("The router lists WiFi clients but none could be read — "
                      "its output format may have changed")
        return clients

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

        On RouterOS 7.x the legacy /ip accounting menu is often absent
        entirely. When that happens we disable further calls for the life
        of this Router instance, so we don't spam the router log with
        `bad command name accounting` once every poll cycle.

        Detection is deliberately belt-and-suspenders because RouterOS is
        awkward here: its sshd returns rc=0 even when the script fails, and
        it prints the error to the *session output* (stdout) — or only to
        its own log — rather than a real stderr channel. So we scan both
        streams for a failure signature, and, as a final safety net,
        disable after a few consecutive empty snapshots (the log-only case).
        """
        if getattr(self, "_accounting_unavailable", False):
            return {}
        rc, out, err = self._ssh_with_stderr(
            "/ip accounting snapshot take; /ip accounting snapshot print detail"
        )
        combined = f"{out}\n{err}".lower()
        if rc != 0 or any(
            sig in combined
            for sig in (
                "bad command name",
                "no such item",
                "syntax error",
                "expected end of command",
                "failure:",
            )
        ):
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

        if not totals:
            # No signature on the SSH channel but nothing parsed either:
            # the router may be logging the failure only to its own log.
            # Give up after a few empty polls so we stop hitting it.
            self._accounting_empty_polls = getattr(self, "_accounting_empty_polls", 0) + 1
            if self._accounting_empty_polls >= 3:
                self._accounting_unavailable = True
            return {}
        self._accounting_empty_polls = 0
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
        # First matching rule wins, so the block goes to the top: appended, it
        # would sit below any rule that accepts the device's whole network.
        add = f'/interface wifi access-list add mac-address={m} action=reject{c}'
        with self._write_lock:
            rc, _ = self._ssh(
                ':local all [/interface wifi access-list find]; '
                f':if ([:len $all] > 0) do={{ {add} place-before=($all->0) }} else={{ {add} }}; '
                f'/interface wifi registration-table remove [find mac-address={m}]'
            )
        return rc == 0

    def unblock_mac(self, mac: str) -> bool:
        m = _valid_mac(mac)
        if m is None:
            log.error("Refusing unblock: invalid MAC address %r", mac)
            return False
        with self._write_lock:
            rc, _ = self._ssh(         # only the block — not other rules for this device
                f'/interface wifi access-list remove [find mac-address={m} action=reject]'
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

    # ─── DNS tracing ──────────────────────────────────────────────
    # A mangle rule with action=log is passive: it only writes a log line (with
    # the sender's MAC) for DNS packets whose payload contains the needle. It
    # sits in prerouting so it sees queries addressed to the router's own
    # resolver as well as ones merely passing through.

    def dns_trace_add(self, trace_id: str, needle: str) -> bool:
        if not _TRACE_ID_RE.match(trace_id) or not _TRACE_NEEDLE_RE.match(needle):
            return False
        comment = _routeros_quote(f"netsentry-trace {trace_id}")
        with self._write_lock:
            rc, out = self._ssh(
                "/ip firewall mangle add chain=prerouting protocol=udp dst-port=53 "
                f"content={_routeros_quote(needle)} action=log "
                f"log-prefix={_routeros_quote('NSTRACE-' + trace_id)} comment={comment}; "
                f":put [:len [/ip firewall mangle find comment={comment}]]"
            )
        return rc == 0 and out.strip().endswith("1")

    def dns_trace_remove(self, trace_id: str) -> bool:
        if not _TRACE_ID_RE.match(trace_id):
            return False
        comment = _routeros_quote(f"netsentry-trace {trace_id}")
        with self._write_lock:
            rc, out = self._ssh(
                f"/ip firewall mangle remove [find comment={comment}]; "
                f":put [:len [/ip firewall mangle find comment={comment}]]"
            )
        return rc == 0 and out.strip().endswith("0")

    def dns_trace_hits(self, trace_id: str) -> list[TraceHit]:
        if not _TRACE_ID_RE.match(trace_id):
            return []
        rc, out = self._ssh(
            f'/log print without-paging where message~"NSTRACE-{trace_id} "')
        return parse_trace_hits(out) if rc == 0 else []

    def dns_trace_ids(self) -> list[str]:
        rc, out = self._ssh(
            ':foreach r in=[/ip firewall mangle find comment~"^netsentry-trace "] '
            'do={:put [/ip firewall mangle get $r comment]}')
        if rc != 0:
            return []
        return [line.split()[-1] for line in out.splitlines()
                if line.startswith("netsentry-trace ")]

    def join_events(self) -> list[JoinEvent]:
        rc, out = self._ssh(
            '/log print without-paging where (topics~"wireless" or topics~"dhcp")',
            timeout=20)
        return parse_join_events(out) if rc == 0 else []

    # ─── one narrow port forward ──────────────────────────────────
    # A dst-nat rule that matches a single source address, the router's own
    # address and one port, and leads to one inner device. Nothing else on the
    # outside can use it, and it opens nothing in the other direction.

    def port_forward_ensure(self, name: str, src_ip: str, port: int,
                            to_ip: str, to_port: int = 80) -> str:
        try:
            src, dst, to = (str(ipaddress.IPv4Address(a)) for a in (src_ip, self.host, to_ip))
        except ValueError:
            return "failed"                 # also when the router is configured by name
        if not (_FORWARD_NAME_RE.match(name) and 1 <= int(port) <= 65535
                and 1 <= int(to_port) <= 65535):
            return "failed"
        comment = _routeros_quote(f"netsentry-forward {name}")
        spec = (f"chain=dstnat action=dst-nat protocol=tcp src-address={src} "
                f"dst-address={dst} dst-port={int(port)} "
                f"to-addresses={to} to-ports={int(to_port)}")
        with self._write_lock:
            rc, out = self._ssh(
                f":local had [:len [/ip firewall nat find comment={comment}]]; "
                f":if ($had = 0) do={{ /ip firewall nat add {spec} comment={comment} }} "
                f"else={{ /ip firewall nat set [find comment={comment}] {spec} disabled=no }}; "
                f':put ("FORWARD " . $had . " " . '
                f"[:len [/ip firewall nat find comment={comment}]])")
        answer = out.strip().splitlines()[-1].split() if out.strip() else []
        if rc != 0 or len(answer) != 3 or answer[0] != "FORWARD" or answer[2] != "1":
            return "failed"
        return "added" if answer[1] == "0" else "exists"

    def port_forward_remove(self, name: str) -> bool:
        if not _FORWARD_NAME_RE.match(name):
            return False
        comment = _routeros_quote(f"netsentry-forward {name}")
        with self._write_lock:
            rc, out = self._ssh(
                f"/ip firewall nat remove [find comment={comment}]; "
                f":put [:len [/ip firewall nat find comment={comment}]]")
        return rc == 0 and out.strip().endswith("0")

    # ─── a device that keeps its own WiFi password ────────────────
    # One access-list rule per device, carrying its own passphrase. RouterOS
    # applies the first rule that matches a joining station, so the rule goes
    # to the top of the list — above any rule that covers the whole network.

    def keep_wifi_passphrase(self, mac: str, ssid: str, label: str = "",
                             isolate: bool = True) -> str:
        m = _valid_mac(mac)
        if m is None or not 1 <= len(ssid) <= 32 or any(ord(ch) < 32 for ch in ssid):
            return "failed"
        acl = "/interface wifi access-list"
        mine = f'[{acl} find mac-address={m} comment~"^{_KEEP_COMMENT}"]'
        comment = _routeros_quote(f"{_KEEP_COMMENT} {_keep_label(label)}".strip())
        rule = (f"mac-address={m} ssid-regexp={_routeros_quote(_exact_regexp(ssid))} "
                f"action=accept client-isolation={'yes' if isolate else 'no'} "
                f"passphrase=$pass comment={comment}")
        with self._write_lock:
            rc, out = self._ssh(
                ':local st "failed"; '
                f':if ([:len {mine}] > 0) do={{ :set st "exists" }} else={{ '
                f":local reg [/interface wifi registration-table find mac-address={m} "
                f"ssid={_routeros_quote(ssid)}]; "
                ':if ([:len $reg] = 0) do={ :set st "not-connected" } else={ '
                ":local ifc [/interface wifi registration-table get ($reg->0) interface]; "
                ":local pass [:tostr [/interface wifi get [find name=$ifc] security.passphrase]]; "
                ":if ([:len $pass] < 8) do={ :do { :set pass [:tostr [/interface wifi security get "
                "[/interface wifi get [find name=$ifc] security] passphrase]] } on-error={} }; "
                ":if ([:len $pass] >= 8) do={ "
                f":local all [{acl} find]; "
                f":if ([:len $all] > 0) do={{ {acl} add {rule} place-before=($all->0) }} "
                f"else={{ {acl} add {rule} }}; "
                ':set st "added" } } }; '
                ":local n 0; :local p 0; "
                f":foreach r in={mine} do={{ :set n ($n + 1); "
                f":set p [:len [:tostr [{acl} get $r passphrase]]] }}; "
                ':put ("KEEP " . $st . " " . $n . " " . $p)',
                timeout=15)
        answer = out.strip().splitlines()[-1].split() if out.strip() else []
        if rc != 0 or len(answer) != 4 or answer[0] != "KEEP":
            return "failed"
        _, state, rules, passphrase_len = answer
        if state == "not-connected":
            return state
        if state not in ("added", "exists") or rules != "1" or not passphrase_len.isdigit() \
                or int(passphrase_len) < 8:
            log.error("Keeping the WiFi password of %s did not verify (%s)", m, " ".join(answer))
            return "failed"
        return state

    def release_wifi_passphrase(self, mac: str) -> bool:
        m = _valid_mac(mac)
        if m is None:
            return False
        mine = f'[/interface wifi access-list find mac-address={m} comment~"^{_KEEP_COMMENT}"]'
        with self._write_lock:
            rc, out = self._ssh(f"/interface wifi access-list remove {mine}; "
                                f':put ("KEEP " . [:len {mine}])')
        return rc == 0 and out.strip().endswith("KEEP 0")

    def kept_wifi_passphrases(self) -> dict[str, str] | None:
        acl = "/interface wifi access-list"
        rc, out = self._ssh(
            f':foreach r in=[{acl} find comment~"^{_KEEP_COMMENT}"] do={{ '
            f':put ("KEEP " . [{acl} get $r mac-address] . " " . [{acl} get $r comment]) }}; '
            ':put "KEEP-END"')
        if rc != 0 or "KEEP-END" not in out:
            return None
        kept: dict[str, str] = {}
        for line in out.splitlines():
            parts = line.strip().split(" ", 3)
            if len(parts) >= 3 and parts[0] == "KEEP" and parts[2] == _KEEP_COMMENT:
                m = _valid_mac(parts[1])
                if m:
                    kept[m] = parts[3].strip() if len(parts) == 4 else ""
        return kept

    def export_config(self, remote_filename: str) -> bool:
        with self._write_lock:
            rc, _ = self._ssh(f'/export file={_routeros_quote(remote_filename)}')
        return rc == 0

    def export_text(self) -> str:
        """Running config to stdout via ``/export terse`` (sensitive values are
        hidden by RouterOS unless ``show-sensitive`` is passed — we never pass
        it). Terse = one command per line, which diffs cleanly."""
        rc, out = self._ssh("/export terse")
        return out if rc == 0 else ""

    def table_counts(self) -> dict[str, int] | None:
        rc, out = self._ssh(
            ':put ("COUNTS wifi=" . [:len [/interface wifi registration-table find]] '
            '. " dhcp=" . [:len [/ip dhcp-server lease find]] '
            '. " arp=" . [:len [/ip arp find where complete]])')
        m = re.search(r"COUNTS wifi=(\d+) dhcp=(\d+) arp=(\d+)", out or "")
        if rc != 0 or not m:
            return None
        return {"wifi": int(m.group(1)), "dhcp": int(m.group(2)), "arp": int(m.group(3))}

    def backup_save(self, name: str) -> bool:
        if not _FILE_NAME_RE.match(name):
            return False
        with self._write_lock:
            # RouterOS answers a refused command with exit status 0, so the
            # only proof is the file itself.
            self._ssh(f"/system backup save name={_routeros_quote(name)} dont-encrypt=yes",
                      timeout=30)
            rc, out = self._ssh(
                f':put ("BACKUP " . [:len [/file find name={_routeros_quote(name + ".backup")}]])')
        return rc == 0 and out.strip().endswith("BACKUP 1")

    def files_with_prefix(self, prefix: str) -> list[str] | None:
        if not _FILE_NAME_RE.match(prefix):
            return None
        rc, out = self._ssh(
            f':foreach f in=[/file find name~"^{prefix}"] do={{ '
            ':put ("FILE " . [/file get $f name]) }; :put "FILE-END"')
        if rc != 0 or "FILE-END" not in out:
            return None
        return [line.strip()[5:] for line in out.splitlines() if line.strip().startswith("FILE ")]

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


def local_address_towards(host: str) -> str:
    """This machine's own address on the network that leads to ``host``."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect((host, 9))            # a UDP connect sends no packet
            return s.getsockname()[0]
        except OSError:
            return ""


def _routeros_quote(value: str) -> str:
    """Return a RouterOS double-quoted string literal.

    ``$`` is escaped too: inside double quotes RouterOS would read ``$name`` as
    a variable and silently drop it from the value.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def _exact_regexp(text: str) -> str:
    """A regular expression that matches exactly ``text`` and nothing else."""
    return "^" + re.sub(r"([\\.\[\]()*+?^$|{}])", r"\\\1", text) + "$"


def _keep_label(label: str) -> str:
    """A device name reduced to what is safe and readable in a rule comment."""
    return re.sub(r"\s+", " ", re.sub(r"[^A-Za-z0-9 ._-]", "", label or "")).strip()[:32]


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
