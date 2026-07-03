"""Local threat-intelligence feeds (abuse.ch) — fetched and matched on-device.

No API key, no rate limit, and *your* domains never leave the network: we
download public malware/C2/phishing blocklists to the Pi and match locally.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime
from pathlib import Path

# Free, keyless, frequently-updated abuse.ch blocklists (hosts format).
FEEDS: list[tuple[str, str]] = [
    ("URLhaus", "https://urlhaus.abuse.ch/downloads/hostfile/"),
    ("ThreatFox", "https://threatfox.abuse.ch/downloads/hostfile/"),
]


# Sink IPs / hostnames that appear in hosts-format lists but aren't real IOCs.
_SKIP_HOSTS = {"localhost", "0.0.0.0", "broadcasthost"}  # nosec B104


def _parse_hostfile(text: str) -> set[str]:
    """Extract hostnames from an /etc/hosts-style blocklist."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        host = (parts[1] if len(parts) >= 2 else parts[0]).strip().lower().strip(".")
        if host and "." in host and host not in _SKIP_HOSTS:
            out.add(host)
    return out


def refresh(cache_file: Path, *, timeout: int = 30) -> tuple[int, bool]:
    """Download every feed and cache the combined domain→source map.

    Keeps the previous cache on total failure. Returns (domain_count, ok).
    """
    combined: dict[str, str] = {}
    ok = False
    for name, url in FEEDS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetSentry"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
                text = r.read().decode("utf-8", "replace")
            for domain in _parse_hostfile(text):
                combined.setdefault(domain, name)
            ok = True
        except Exception:
            continue
    if ok:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            json.dumps({"ts": datetime.now().isoformat(timespec="seconds"),
                        "domains": combined})
        )
    return len(combined), ok


def load(cache_file: Path) -> tuple[dict[str, str], str]:
    """Return (domain→source map, last-refresh timestamp)."""
    try:
        data = json.loads(cache_file.read_text())
        return data.get("domains", {}), data.get("ts", "")
    except Exception:
        return {}, ""
