"""threat_detector · where the raw observations come from.

Pi-hole's FTL database (who asked for which domain), the router (ARP table,
DHCP leases, firewall log) and a short DHCP probe from this machine. Nothing
here decides whether something is a threat — see ``detectors.py`` for that.
"""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict


class SourcesMixin:
    """Data gathering for :class:`ThreatDetectorPlugin` (mixed into it)."""

    def _recent_domain_clients(self) -> dict[str, set[str]]:
        """Map each recently-queried domain -> the client IP(s) that asked.

        Pi-hole v6 exposes `queries` as a view that already resolves both the
        domain and the client to strings.
        """
        try:
            r = subprocess.run(
                [
                    "sqlite3",
                    "-noheader",
                    "-separator",
                    "|",
                    self._ftl_db,
                    "SELECT DISTINCT domain, client FROM queries "
                    f"WHERE timestamp > strftime('%s','now','-{self._window_min} minutes') "
                    "AND domain IS NOT NULL AND domain != '' "
                    "LIMIT 40000;",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode != 0:
                self.log.warning("FTL query failed: %s", r.stderr[-160:])
                return {}
        except Exception as exc:
            self.log.warning("FTL read failed: %s", exc)
            return {}
        mapping: dict[str, set[str]] = defaultdict(set)
        for line in r.stdout.splitlines():
            domain, _, client = line.strip().partition("|")
            domain = domain.strip().lower()
            # Skip reverse-DNS lookups and Pi-hole pseudo-entries — pure noise.
            if (
                not domain
                or domain.endswith(".arpa")
                or "." not in domain
                or any(ch in domain for ch in "*+ ")
            ):
                continue
            mapping[domain].add(client)
        return mapping

    def _recent_domains(self) -> list[str]:
        return list(self._recent_domain_clients().keys())

    def _device_names(self) -> dict[str, str]:
        """Best-effort IP -> friendly name (DHCP hostnames + Tailscale names)."""
        names: dict[str, str] = {}
        try:
            for lease in self.router.dhcp_leases() or []:
                ip = getattr(lease, "ip", "")
                host = getattr(lease, "hostname", "") or ""
                if ip and host:
                    names[ip] = host
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["tailscale", "status"], capture_output=True, text=True, timeout=4
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith("100.") and parts[0].count(".") == 3:
                        names.setdefault(parts[0], parts[1])
        except Exception:
            pass
        return names

    def _label_client(self, ip: str, names: dict[str, str]) -> str:
        name = names.get(ip)
        return f"{name} ({ip})" if name else (ip or "?")

    def _arp_pairs(self) -> list[tuple[str, str]]:
        try:
            entries = self.router.arp_table()
        except Exception as exc:
            self.log.warning("ARP read failed: %s", exc)
            return []
        pairs: list[tuple[str, str]] = []
        for e in entries or []:
            ip = getattr(e, "ip", "")
            mac = getattr(e, "mac", "")
            if ip and mac:
                pairs.append((ip, mac))
        return pairs

    def _dhcp_servers_seen(self) -> list[tuple[str, str]]:
        """DHCP servers the router flagged as UNKNOWN — as (mac, ip) pairs.

        RouterOS `/ip dhcp-server alert` (with a `valid-server` set) records a
        detected rogue in the entry's `unknown-server` field and logs it under
        topic `dhcp`. We read both; returns [] until a rogue is actually seen,
        so the check is inert on a healthy network.
        """
        servers: list[tuple[str, str]] = []
        ssh = getattr(self.router, "_ssh", None)
        if ssh is not None:
            try:
                rc, out = ssh("/ip dhcp-server alert print detail")
                if rc == 0:
                    for m in re.finditer(r"unknown-server=([0-9A-Fa-f:,]+)", out or ""):
                        for mac in m.group(1).split(","):
                            if mac.strip():
                                servers.append((mac.strip(), ""))
            except Exception:
                pass
        try:
            for line in self.router.log_tail(n=300, topic_filter="dhcp") or []:
                if "unknown dhcp server" not in line.lower():
                    continue
                mac_m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if mac_m:
                    servers.append((mac_m.group(1), ip_m.group(1) if ip_m else ""))
        except Exception:
            pass
        best: dict[str, tuple[str, str]] = {}
        for mac, ip in servers:
            key = mac.upper()
            if key not in best or (ip and not best[key][1]):
                best[key] = (mac, ip)
        return list(best.values())

    def _port_scanners(self) -> list[str]:
        """IPs the router's PSD firewall rules tagged into `port-scanners`.

        Needs the `psd` add-src-to-address-list rules on the router; returns []
        (list absent = no scans) so the check is inert until a scan is caught.
        """
        ssh = getattr(self.router, "_ssh", None)
        if ssh is None:
            return []
        try:
            rc, out = ssh(
                "/ip firewall address-list print terse where list=port-scanners"
            )
        except Exception:
            return []
        ips: list[str] = []
        if rc == 0:
            for line in (out or "").splitlines():
                for tok in line.split():
                    if tok.startswith("address="):
                        ips.append(tok.split("=", 1)[1])
        return ips
