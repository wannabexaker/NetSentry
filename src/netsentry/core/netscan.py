"""Safe nmap wrapper — active host discovery + service detection.

Shared by ``threat_detector`` (scheduled discovery / exposure) and
``lan_dashboard`` (on-demand per-IP scan). Everything runs unprivileged (TCP
connect scan), so no extra sudo is required.

Two safety rules, enforced here so callers can't get them wrong:
  * every target is validated as a private IPv4 address or CIDR before it can
    reach the subprocess (no shell, fixed argv);
  * scans are bounded by an explicit timeout.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess  # nosec B404 - fixed argv, validated args, no shell
import urllib.request
from dataclasses import dataclass

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def valid_ip(value: str) -> str | None:
    """Return a private/loopback IPv4 string, or None if it isn't one."""
    if not _IPV4_RE.fullmatch(value or ""):
        return None
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback:
        return str(ip)
    return None


def valid_cidr(value: str) -> str | None:
    """Return a private IPv4 CIDR (host bits cleared), or None."""
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return None
    if net.is_private and net.num_addresses <= 4096:
        return str(net)
    return None


@dataclass(frozen=True)
class Service:
    port: int
    proto: str
    service: str
    version: str


def _run(args: list[str], timeout: int) -> str:
    try:
        proc = subprocess.run(  # nosec B603 - fixed bin, validated argv, no shell
            args, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    return proc.stdout or ""


def parse_hosts_up(text: str) -> list[str]:
    """IPs reported ``Status: Up`` in ``nmap -sn -oG`` output."""
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                out.append(m.group(1))
    return out


def parse_ports(text: str) -> dict[str, list[int]]:
    """``{ip: [open tcp ports]}`` from ``nmap --open -oG`` output."""
    out: dict[str, list[int]] = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue
        ports = sorted({
            int(p) for p in re.findall(r"(\d+)/open/tcp", line.split("Ports:", 1)[1])
        })
        if ports:
            out[m.group(1)] = ports
    return out


def parse_services(text: str) -> dict[str, list[Service]]:
    """``{ip: [Service…]}`` from ``nmap -sV --open -oG`` output.

    The grepable Ports field is ``port/state/proto/owner/service/rpc/version/``.
    """
    out: dict[str, list[Service]] = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue
        svcs: list[Service] = []
        for chunk in line.split("Ports:", 1)[1].split(","):
            f = chunk.strip().split("/")
            if len(f) >= 5 and f[1] == "open":
                svcs.append(Service(
                    port=int(f[0]), proto=f[2] or "tcp",
                    service=(f[4] or "").strip(),
                    version=(f[6].strip() if len(f) >= 7 else "").replace("|", " "),
                ))
        if svcs:
            out[m.group(1)] = svcs
    return out


def discover(subnets: list[str], *, timeout: int = 300, nmap_bin: str = "nmap") -> list[str]:
    """Active host discovery (ping/TCP sweep) over the given private subnets."""
    cidrs = [c for c in (valid_cidr(s) for s in subnets) if c]
    if not cidrs:
        return []
    text = _run([nmap_bin, "-sn", "-T4", "-n", "-oG", "-", *cidrs], timeout)
    return parse_hosts_up(text)


def scan_ports(ips: list[str], *, ports_arg: str = "--top-ports 100",
               timeout: int = 600, nmap_bin: str = "nmap") -> dict[str, list[int]]:
    """Open-TCP-port scan of already-validated-ish IPs (revalidated here)."""
    targets = [ip for ip in (valid_ip(i) for i in ips) if ip]
    if not targets:
        return {}
    text = _run(
        [nmap_bin, "-Pn", "-T4", "-n", "--open", "-oG", "-", *ports_arg.split(), *targets],
        timeout,
    )
    return parse_ports(text)


def http_probe(ip: str, ports: list[int], *, timeout: int = 5) -> str:
    """Best-effort short HTTP body sample from a host's web port, for the
    default-credential heuristic. HTTP only (no TLS surface); private IPs only."""
    target = valid_ip(ip)
    if not target:
        return ""
    for port in ports:
        if port not in (80, 8080, 8888):
            continue
        try:
            req = urllib.request.Request(
                f"http://{target}:{port}/", headers={"User-Agent": "NetSentry"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - fixed http scheme, private IP
                # Login pages put the default-password warning well down the
                # body (the OpenWrt/LuCI notice is ~tens of KB in), so read a
                # generous slice — this only runs for a handful of web hosts.
                return r.read(262_144).decode("utf-8", "replace")
        except Exception:
            continue
    return ""


def scan_ip_detail(ip: str, *, ports_arg: str = "--top-ports 200",
                   timeout: int = 180, nmap_bin: str = "nmap") -> dict:
    """On-demand service/version scan of one IP. Returns a JSON-friendly dict."""
    target = valid_ip(ip)
    if not target:
        return {"ip": ip, "ok": False, "error": "not a private IPv4 address"}
    text = _run(
        [nmap_bin, "-Pn", "-T4", "-n", "-sV", "--version-light", "--open",
         "-oG", "-", *ports_arg.split(), target],
        timeout,
    )
    services = parse_services(text).get(target, [])
    return {
        "ip": target,
        "ok": True,
        "open_count": len(services),
        "services": [
            {"port": s.port, "proto": s.proto, "service": s.service,
             "version": s.version} for s in services
        ],
    }
