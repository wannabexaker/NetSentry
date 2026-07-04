"""Pure 802.11 frame parsing + attack heuristics (no radio, no I/O except the
tiny baseline file). Kept separate from the plugin so it is trivially testable
against real ``tcpdump -e`` output.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from ..threat_detector.detectors import Finding

_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
_BSSID_RE = re.compile(rf"BSSID:({_MAC})")
_SA_RE = re.compile(rf"SA:({_MAC})")
_DA_RE = re.compile(rf"DA:({_MAC})")
_AP_RE = re.compile(r"(?:Beacon|Probe Response) \(([^)]*)\)")


def _oui(mac: str) -> str:
    """Vendor prefix (first 3 octets) of a MAC — same-vendor BSSIDs share it."""
    return mac.lower()[:8]


def parse_capture(text: str) -> tuple[dict[str, set[str]], list[tuple[str, str, str]]]:
    """Parse ``tcpdump -e ... type mgt`` output.

    Returns ``(ssid -> {BSSIDs}, [(src, dst, bssid) for each deauth/disassoc])``.
    """
    ssid_bssids: dict[str, set[str]] = defaultdict(set)
    deauths: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        bm = _BSSID_RE.search(line)
        bssid = bm.group(1).lower() if bm else ""
        ap = _AP_RE.search(line)
        if ap is not None:
            ssid = ap.group(1)
            if ssid and bssid:               # ignore hidden/empty SSIDs
                ssid_bssids[ssid].add(bssid)
            continue
        if "DeAuthentication" in line or "Disassociation" in line:
            sm, dm = _SA_RE.search(line), _DA_RE.search(line)
            deauths.append((
                sm.group(1).lower() if sm else "",
                dm.group(1).lower() if dm else "",
                bssid,
            ))
    return dict(ssid_bssids), deauths


def rogue_ap_findings(
    ssid_bssids: dict[str, set[str]], baseline: dict[str, list[str]],
    protect: list[str], allow_bssids: frozenset[str] = frozenset(),
) -> list[Finding]:
    """NS-WIFI-002 — a protected SSID broadcast by a BSSID whose *vendor* isn't
    one of your access points'. Same-vendor BSSIDs (your other band / mesh node)
    are treated as legitimate; a different-OUI impersonator is flagged.
    """
    protect_set = set(protect)
    allow = {b.lower() for b in allow_bssids}
    out: list[Finding] = []
    for ssid, bssids in ssid_bssids.items():
        if ssid not in protect_set:
            continue
        legit = set(baseline.get(ssid, []))
        if not legit:
            continue                          # still learning this SSID
        legit_ouis = {_oui(b) for b in legit}
        for b in sorted(bssids):
            if b in legit or b in allow or _oui(b) in legit_ouis:
                continue
            out.append(Finding(
                kind="rogue_ap", severity="attack", subject=b,
                detail=f"AP {b} is broadcasting your SSID '{ssid}' from an "
                       "unknown vendor — possible evil-twin",
            ))
    return out


def deauth_flood_findings(
    deauths: list[tuple[str, str, str]], *, threshold: int = 20,
) -> list[Finding]:
    """NS-WIFI-001 — a source sending an abnormal burst of deauth/disassoc."""
    by_src = Counter(sa for sa, _da, _b in deauths if sa)
    out: list[Finding] = []
    for src, n in by_src.items():
        if n >= threshold:
            out.append(Finding(
                kind="deauth_flood", severity="attack", subject=src,
                detail=f"{n} deauth/disassoc frames from {src} — devices are "
                       "being forced off Wi-Fi (jamming / evil-twin setup)",
            ))
    return out


def learn_baseline(
    ssid_bssids: dict[str, set[str]], baseline: dict[str, list[str]],
    protect: list[str],
) -> dict[str, list[str]]:
    """Trust the first-seen BSSIDs of each protected SSID, and thereafter extend
    only with same-vendor BSSIDs (your other bands/mesh)."""
    protect_set = set(protect)
    out: dict[str, set[str]] = {k: set(v) for k, v in baseline.items()}
    for ssid, bssids in ssid_bssids.items():
        if ssid not in protect_set:
            continue
        cur = out.setdefault(ssid, set())
        if not cur:
            cur |= bssids                     # clean-start assumption
        else:
            ouis = {_oui(b) for b in cur}
            cur |= {b for b in bssids if _oui(b) in ouis}
    return {k: sorted(v) for k, v in out.items()}


def load_baseline(path: str | Path) -> dict[str, list[str]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {str(k): list(v) for k, v in data.items()}
    except Exception:
        return {}


def save_baseline(path: str | Path, baseline: dict[str, list[str]]) -> None:
    try:
        Path(path).write_text(
            json.dumps({k: sorted(v) for k, v in baseline.items()}),
            encoding="utf-8",
        )
    except OSError:
        pass
