"""Pure, side-effect-free detection heuristics.

Each detector takes plain data (already gathered by the plugin) and returns a
list of :class:`Finding`. Keeping them pure makes them trivial to unit-test
offline with no router, DB, or network.
"""

from __future__ import annotations

import math
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
    "fbcdn.net", "whatsapp.net", "akamaiedge.net", "akadns.net", "edgekey.net",
    "cloudfront.net", "1e100.net", "googleusercontent.com", "gvt1.com",
    "gvt2.com", "ytimg.com", "gstatic.com",
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
