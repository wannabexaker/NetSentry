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


def dns_tunnel_findings(
    domains: list[str],
    *,
    min_label_len: int = 20,
    entropy_bits: float = 3.6,
    max_depth: int = 6,
    max_total_len: int = 80,
    allow_suffixes: tuple[str, ...] = (),
) -> list[Finding]:
    """Flag domains that look like DNS tunnelling / DGA.

    A long, high-entropy sub-domain label, an excessive label depth, or an
    unusually long FQDN are classic exfil/tunnel signatures.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for raw in domains:
        d = raw.lower().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        if any(d == s or d.endswith("." + s) for s in allow_suffixes):
            continue
        label = _significant_label(d)
        depth = d.count(".") + 1
        entropy = shannon_entropy(label)
        if (
            (len(label) >= min_label_len and entropy >= entropy_bits)
            or depth > max_depth
            or len(d) > max_total_len
        ):
            findings.append(
                Finding(
                    "dns_tunnel",
                    "attack",
                    d,
                    f"label_len={len(label)} entropy={entropy:.2f} depth={depth}",
                )
            )
    return findings


def new_domains(recent: list[str], baseline: set[str]) -> list[Finding]:
    """Domains queried now but never seen in the baseline window."""
    fresh = {d.lower().strip(".") for d in recent if d.strip(".")} - {
        b.lower() for b in baseline
    }
    return [Finding("new_domain", "warning", d, "first seen") for d in sorted(fresh)]


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
