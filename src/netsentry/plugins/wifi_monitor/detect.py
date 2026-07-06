"""Pure 802.11 frame parsing + attack heuristics (no radio, no I/O except the
tiny baseline file). Kept separate from the plugin so it is trivially testable
against real ``tcpdump -e`` output.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from ..threat_detector.detectors import Finding

_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
_BSSID_RE = re.compile(rf"BSSID:({_MAC})")
_SA_RE = re.compile(rf"SA:({_MAC})")
_DA_RE = re.compile(rf"DA:({_MAC})")
_AP_RE = re.compile(r"(?:Beacon|Probe Response) \(([^)]*)\)")


_SIGNAL_RE = re.compile(r"(-\d+)dBm")


def _oui(mac: str) -> str:
    """Vendor prefix (first 3 octets) of a MAC — same-vendor BSSIDs share it."""
    return mac.lower()[:8]


def parse_capture(
    text: str,
) -> tuple[dict[str, set[str]], list[tuple[str, str, str, int]]]:
    """Parse ``tcpdump -e ... type mgt`` output.

    Returns ``(ssid -> {BSSIDs},
    [(src, dst, bssid, signal_dBm) for each deauth/disassoc])``. ``signal`` is 0
    when the radiotap header didn't carry one.
    """
    ssid_bssids: dict[str, set[str]] = defaultdict(set)
    deauths: list[tuple[str, str, str, int]] = []
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
            sig = _SIGNAL_RE.search(line)
            deauths.append((
                sm.group(1).lower() if sm else "",
                dm.group(1).lower() if dm else "",
                bssid,
                int(sig.group(1)) if sig else 0,
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


def _proximity(dbm: int) -> str:
    """Rough distance hint from RSSI, to help physically locate the source."""
    if dbm >= -45:
        return "very close / same room"
    if dbm >= -65:
        return "nearby / next room"
    if dbm >= -80:
        return "in/around the building"
    return "far / weak"


def deauth_flood_findings(
    deauths: list[tuple[str, str, str, int]],
    own_bssids: frozenset[str] | set[str] = frozenset(), *,
    threshold: int = 20,
) -> list[Finding]:
    """Deauth/disassoc floods, split by whether they hit **your** APs.

    Frames whose BSSID belongs to your access points (matched by vendor OUI, so
    every band/radio of your router counts) become **NS-WIFI-001** attacks.
    Frames aimed at *some other* AP on the same channel — the big false-positive
    source — are no longer silently dropped: they surface as **NS-WIFI-003**, a
    calm info notice that says plainly "seen nearby, but NOT your network". Both
    name the target BSSID and the strongest signal, so you can tell whose it is
    and roughly how close the source is.

    With no baseline yet (``own_bssids`` empty) we can't tell whose AP is whose,
    so everything counts toward the attack path (fail-safe) and nothing is
    reported as "not yours".
    """
    own_ouis = {b.lower()[:8] for b in own_bssids}
    on: dict[str, dict] = {}          # aimed at YOUR APs
    off: dict[str, dict] = {}         # aimed at another network
    for sa, _da, bssid, sig in deauths:
        if not sa:
            continue
        if not own_ouis or bssid[:8] in own_ouis:
            bucket = on               # yours, or no baseline yet (fail-safe)
        elif bssid:
            bucket = off              # a real BSSID that isn't yours
        else:
            continue                  # baseline known but no BSSID -> ambiguous
        s = bucket.setdefault(sa, {"n": 0, "targets": set(), "peak": None})
        s["n"] += 1
        if bssid:
            s["targets"].add(bssid)
        if sig and (s["peak"] is None or sig > s["peak"]):
            s["peak"] = sig

    def _where(s: dict) -> str:
        return (f", strongest signal {s['peak']} dBm ({_proximity(s['peak'])})"
                if s["peak"] is not None else "")

    out: list[Finding] = []
    for sa, s in on.items():
        if s["n"] < threshold:
            continue
        target = ", ".join(sorted(s["targets"])) or "your network"
        out.append(Finding(
            kind="deauth_flood", severity="attack", subject=sa,
            detail=(f"{s['n']} deauth/disassoc frames from {sa} against your AP "
                    f"{target}{_where(s)} — devices are being forced off Wi-Fi"),
        ))
    for sa, s in off.items():
        if s["n"] < threshold:
            continue
        if sa in on and on[sa]["n"] >= threshold:
            continue                  # already reported as attacking you
        target = ", ".join(sorted(s["targets"]))
        out.append(Finding(
            kind="deauth_nearby", severity="info", subject=sa,
            detail=(f"{s['n']} deauth/disassoc frames from {sa} seen nearby"
                    f"{_where(s)}, but aimed at another network ({target}) — "
                    "this was NOT your Wi-Fi, nothing to do"),
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
