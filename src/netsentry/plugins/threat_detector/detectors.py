"""Pure, side-effect-free detection heuristics.

Each detector takes plain data (already gathered by the plugin) and returns a
list of :class:`Finding`. Keeping them pure makes them trivial to unit-test
offline with no router, DB, or network.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str      # dns_tunnel | new_domain | arp_conflict | arp_change
    severity: str  # "warning" | "attack"
    subject: str   # the domain / ip that triggered it
    detail: str


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character (0 for empty)."""
    if not text:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _significant_label(domain: str) -> str:
    """The longest sub-domain label, ignoring the registrable domain + TLD."""
    parts = [p for p in domain.lower().strip(".").split(".") if p]
    labels = parts[:-2] if len(parts) > 2 else parts[:1]
    return max(labels, key=len) if labels else ""


def _registrable(domain: str) -> str:
    """The last two labels — a cheap stand-in for the registrable domain."""
    parts = [p for p in domain.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def normalize_export(text: str) -> list[str]:
    """A RouterOS ``/export`` reduced to comparable lines.

    Drops the volatile header (comment lines: date, RouterOS version, ``by``)
    and blank lines, so a diff reflects real config changes, not the timestamp
    that changes on every export.
    """
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def _config_section(line: str) -> str:
    """The RouterOS menu path a config line belongs to (e.g. ``/ip firewall filter``)."""
    m = re.match(r"(/[\w -]+?)\s+(?:add|set|remove|:)", line)
    if m:
        return m.group(1).strip()
    return line.split(" ", 1)[0] if line.startswith("/") else "(root)"


def config_drift_findings(
    old_lines: list[str], new_lines: list[str],
) -> list[Finding]:
    """One finding when the router config changed vs. the last baseline.

    The detail names the affected sections and counts, not the raw lines, so
    it stays short and never leaks config values into alerts/Telegram.
    """
    old, new = set(old_lines), set(new_lines)
    added = [ln for ln in new_lines if ln not in old]
    removed = [ln for ln in old_lines if ln not in new]
    if not added and not removed:
        return []
    sections = sorted({_config_section(ln) for ln in (*added, *removed)})
    shown = ", ".join(sections[:6]) + (" …" if len(sections) > 6 else "")
    detail = f"+{len(added)} / -{len(removed)} config lines — sections: {shown}"
    return [Finding(
        kind="config_drift",
        severity="warning",
        subject="Router configuration changed",
        detail=detail,
    )]


def parse_nmap_grepable(text: str) -> dict[str, list[int]]:
    """Parse ``nmap -oG -`` output into ``{ip: [open tcp ports]}``."""
    out: dict[str, list[int]] = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue
        ip = m.group(1)
        ports = sorted({
            int(p) for p in re.findall(r"(\d+)/open/tcp", line.split("Ports:", 1)[1])
        })
        if ports:
            out[ip] = ports
    return out


# Plaintext / remote-admin services that shouldn't be casually exposed on a LAN.
WEAK_PORTS: dict[int, str] = {
    21: "ftp", 23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh",
    2323: "telnet", 3389: "rdp", 5900: "vnc", 5901: "vnc",
}
_DEFAULT_CRED_RE = re.compile(
    r"default (?:password|login|credential)|password is the default|"
    r"change it immediately|admin/admin|default.{0,20}admin",
    re.IGNORECASE,
)


def weak_service_findings(
    port_map: dict[str, list[int]], banners: dict[str, str] | None = None,
) -> list[Finding]:
    """Flag hosts exposing a plaintext admin service or a default-cred web panel.

    ``banners`` maps ip -> a short HTTP body sample (best-effort) for the
    default-credential check; port matches work without it.
    """
    banners = banners or {}
    out: list[Finding] = []
    for ip in sorted(port_map):
        reasons = [f"{WEAK_PORTS[p]}/{p}" for p in sorted(port_map[ip]) if p in WEAK_PORTS]
        body = banners.get(ip, "")
        if body and _DEFAULT_CRED_RE.search(body):
            reasons.append("default-credential web panel")
        if reasons:
            out.append(Finding(
                kind="weak_service", severity="attack", subject=ip,
                detail="exposed: " + ", ".join(reasons),
            ))
    return out


def exposure_findings(
    current: dict[str, list[int]], baseline: dict[str, list[int]],
) -> list[Finding]:
    """One finding per host that opened a TCP port not in its baseline."""
    out: list[Finding] = []
    for ip, ports in current.items():
        base = set(baseline.get(ip, []))
        new = [p for p in ports if p not in base]
        if new:
            out.append(Finding(
                kind="exposure",
                severity="warning",
                subject=ip,
                detail="newly-open TCP port(s): " + ", ".join(str(p) for p in new),
            ))
    return out


def dns_tunnel_findings(
    domains: list[str],
    *,
    min_label_len: int = 20,
    entropy_bits: float = 3.6,
    min_random_subdomains: int = 5,
    max_total_len: int = 80,
    allow_suffixes: tuple[str, ...] = (),
) -> list[Finding]:
    """Flag DNS tunnelling / DGA.

    A single long, high-entropy label is a *weak* signal (legit CDNs do it), so
    the primary trigger is aggregation: one registrable parent accumulating many
    distinct high-entropy sub-domains — the tell-tale of tunnelling/DGA. An
    individually absurd (very long) FQDN is also flagged on its own.
    """
    findings: list[Finding] = []
    randoms_by_parent: dict[str, set[str]] = defaultdict(set)
    seen: set[str] = set()
    for raw in domains:
        d = raw.lower().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        if any(d == s or d.endswith("." + s) for s in allow_suffixes):
            continue
        if len(d) > max_total_len:
            findings.append(
                Finding("dns_tunnel", "attack", d, f"very long FQDN (len={len(d)})")
            )
            continue
        label = _significant_label(d)
        if len(label) >= min_label_len and shannon_entropy(label) >= entropy_bits:
            randoms_by_parent[_registrable(d)].add(d)

    for parent, subs in sorted(randoms_by_parent.items()):
        if len(subs) >= min_random_subdomains:
            findings.append(
                Finding(
                    "dns_tunnel",
                    "attack",
                    parent,
                    f"{len(subs)} high-entropy sub-domains (tunnel/DGA pattern)",
                )
            )
    return findings


# TLDs disproportionately used for malware/phishing (free or cheap, weak abuse
# handling). Not proof of badness — a low-severity signal worth surfacing.
DEFAULT_SUSPICIOUS_TLDS: tuple[str, ...] = (
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work",
    "country", "kim", "science", "party", "gdn", "review", "zip", "mov",
)


def suspicious_tld_findings(
    domains: list[str],
    *,
    bad_tlds: tuple[str, ...] = DEFAULT_SUSPICIOUS_TLDS,
    allow_suffixes: tuple[str, ...] = (),
) -> list[Finding]:
    """Flag domains under high-abuse top-level domains."""
    bad = {t.lower().lstrip(".") for t in bad_tlds}
    out: list[Finding] = []
    seen: set[str] = set()
    for raw in domains:
        d = raw.lower().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        if any(d == s or d.endswith("." + s) for s in allow_suffixes):
            continue
        tld = d.rsplit(".", 1)[-1] if "." in d else ""
        if tld in bad:
            out.append(Finding("suspicious_tld", "warning", d, f".{tld} (high-abuse TLD)"))
    return out


# Big CDN / telemetry parents whose churn of random-looking sub-domains is
# benign — suppressed by default so they don't drown real signals (e.g. Meta's
# `<uuid>-netseer-ipaddr-assoc.*.fbcdn.net`). Operators can extend/override.
DEFAULT_ALLOW_SUFFIXES: tuple[str, ...] = (
    # CDNs
    "fbcdn.net", "whatsapp.net", "akamaiedge.net", "akadns.net", "edgekey.net",
    "cloudfront.net", "1e100.net", "googleusercontent.com", "googleapis.com",
    "gvt1.com", "gvt2.com", "ytimg.com", "gstatic.com", "fastly.net",
    "fastlylb.net", "llnwd.net", "cdn77.org",
    # video/streaming — random per-server sub-domains are normal here
    "googlevideo.com", "ttvnw.net", "nflxvideo.net", "nflximg.net",
    "aiv-cdn.net", "aiv-delivery.net", "dssott.com", "spotifycdn.com",
)


def _is_allowed(domain: str, allow_suffixes: tuple[str, ...]) -> bool:
    return any(domain == s or domain.endswith("." + s) for s in allow_suffixes)


def new_domains(
    recent: list[str],
    baseline: set[str],
    *,
    allow_suffixes: tuple[str, ...] = (),
) -> list[Finding]:
    """Domains queried now but never seen in the baseline window."""
    base = {b.lower() for b in baseline}
    fresh = {
        d.lower().strip(".")
        for d in recent
        if d.strip(".") and not _is_allowed(d.lower().strip("."), allow_suffixes)
    } - base
    return [Finding("new_domain", "warning", d, "first seen") for d in sorted(fresh)]


def known_malicious_findings(
    domains: list[str],
    feed_map: dict[str, str],
) -> list[Finding]:
    """Flag domains present on a downloaded malware/C2/phishing blocklist.

    `feed_map` maps a known-bad domain to its source feed. A queried domain
    matches if it, or any of its parent domains, is on a list — confirmed bad,
    not a heuristic guess.
    """
    if not feed_map:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for raw in domains:
        d = (raw or "").lower().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        parts = d.split(".")
        for i in range(len(parts) - 1):
            source = feed_map.get(".".join(parts[i:]))
            if source:
                out.append(
                    Finding("known_malicious", "attack", d, f"on the {source} blocklist")
                )
                break
    return out


def rogue_dhcp_findings(
    servers: list[tuple[str, str]],
    allowed: set[str],
) -> list[Finding]:
    """Flag DHCP servers the router flagged as unknown on the LAN.

    `servers` is a list of ``(server_mac, server_ip)`` pairs the router reported
    as *unknown* via `/ip dhcp-server alert` (the router already excludes its own
    `valid-server`). `allowed` is an extra NetSentry-side MAC allow-list (usually
    empty). MAC-keyed, because that is what the RouterOS alert reports.
    """
    allow = {a.upper() for a in allowed}
    out: list[Finding] = []
    seen: set[str] = set()
    for mac, ip in servers:
        m = (mac or "").upper()
        if not m or m in allow or m in seen:
            continue
        seen.add(m)
        detail = f"unexpected DHCP server (mac={m}" + (f", ip={ip}" if ip else "") + ")"
        out.append(Finding("rogue_dhcp", "attack", ip or m, detail))
    return out


def port_scan_findings(scanners: list[str]) -> list[Finding]:
    """Flag hosts the router's port-scan detector (PSD) caught.

    `scanners` is the list of source IPs the RouterOS `psd` firewall rules
    tagged into the `port-scanners` address-list — the router does the
    distinct-port counting, so NetSentry just reports each offender once.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    for raw in scanners:
        ip = (raw or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append(
            Finding("port_scan", "attack", ip, "flagged by router port-scan detector")
        )
    return out


def arp_conflicts(entries: list[tuple[str, str]]) -> list[Finding]:
    """One IP claimed by more than one MAC — a spoofing / takeover signature."""
    by_ip: dict[str, set[str]] = defaultdict(set)
    for ip, mac in entries:
        if ip and mac:
            by_ip[ip].add(mac.upper())
    return [
        Finding("arp_conflict", "attack", ip, f"{len(macs)} MACs: {sorted(macs)}")
        for ip, macs in by_ip.items()
        if len(macs) > 1
    ]


def arp_mac_changes(
    current: dict[str, str],
    baseline: dict[str, str],
) -> list[Finding]:
    """An IP whose MAC changed vs the baseline — possible MITM / takeover."""
    out: list[Finding] = []
    for ip, mac in current.items():
        old = baseline.get(ip)
        if old and mac and old.upper() != mac.upper():
            out.append(Finding("arp_change", "attack", ip, f"{old} -> {mac}"))
    return out
