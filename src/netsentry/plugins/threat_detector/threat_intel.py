"""Local threat-intelligence feeds — fetched and matched on-device.

No API key, no account, and *your* domains never leave the network: public
malware / C2 / phishing blocklists are downloaded to the Pi and matched locally.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime
from pathlib import Path

# Free, keyless, frequently-updated domain blocklists (plain-domain or hosts
# format). abuse.ch retired its own keyless host files in 2026 (HTTP 410), so
# URLhaus now comes through the malware-filter mirror.
FEEDS: list[tuple[str, str]] = [
    ("URLhaus (malware-filter)",
     "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt"),
    ("HaGeZi Threat Intelligence (mini)",
     "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
     "tif.mini-onlydomains.txt"),
    ("Phishing Army",
     "https://phishing.army/download/phishing_army_blocklist.txt"),
]

# Sink IPs / hostnames that appear in hosts-format lists but aren't real IOCs.
_SKIP_HOSTS = {"localhost", "0.0.0.0", "broadcasthost"}  # nosec B104

# A real feed has thousands of entries. Far fewer means we were served an error
# page or an emptied file — never let that replace a good list.
_MIN_ENTRIES = 100
_MAX_BYTES = 64 * 1024 * 1024

# Parsed cache, keyed by file identity: a detection cycle runs every few minutes
# and re-reading a multi-megabyte JSON each time would be wasted work.
_loaded: dict[str, tuple[tuple[int, int], dict[str, str], str, dict]] = {}


def _parse_hostfile(text: str) -> set[str]:
    """Extract hostnames from a plain-domain or /etc/hosts-style blocklist."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!<":
            continue
        parts = line.split()
        host = (parts[1] if len(parts) >= 2 else parts[0]).strip().lower().strip(".")
        if host and "." in host and host not in _SKIP_HOSTS:
            out.add(host)
    return out


def _fetch(url: str, timeout: int) -> set[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "NetSentry"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
        text = r.read(_MAX_BYTES).decode("utf-8", "replace")
    domains = _parse_hostfile(text)
    if len(domains) < _MIN_ENTRIES:
        raise ValueError(f"only {len(domains)} entries — not a blocklist")
    return domains


def refresh(cache_file: Path, *, timeout: int = 60,
            feeds: list[tuple[str, str]] | None = None) -> tuple[int, bool]:
    """Download every feed and cache the combined domain→source map.

    A feed that fails keeps the entries it contributed last time, so one source
    having a bad day doesn't shrink coverage. The cache is only rewritten when
    at least one feed succeeded. Returns ``(domain_count, ok)``.
    """
    previous, _, before = _read(cache_file)
    now = datetime.now().isoformat(timespec="seconds")
    combined: dict[str, str] = {}
    status: dict[str, dict] = {}
    ok = False
    for name, url in (feeds if feeds is not None else FEEDS):
        try:
            domains = _fetch(url, timeout)
        except Exception as e:
            kept = [d for d, src in previous.items() if src == name]
            for domain in kept:
                combined.setdefault(domain, name)
            status[name] = {"ok": False, "count": len(kept),
                            "error": f"{type(e).__name__}: {e}"[:160], "ts": now,
                            "last_ok": (before.get(name) or {}).get("last_ok", "")}
            continue
        for domain in domains:
            combined.setdefault(domain, name)
        status[name] = {"ok": True, "count": len(domains), "ts": now, "last_ok": now}
        ok = True
    if ok:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"ts": now, "domains": combined, "feeds": status}),
                       encoding="utf-8")
        tmp.replace(cache_file)
    return len(combined), ok


def _read(cache_file: Path) -> tuple[dict[str, str], str, dict]:
    try:
        st = cache_file.stat()
    except OSError:
        return {}, "", {}
    key = (st.st_mtime_ns, st.st_size)
    hit = _loaded.get(str(cache_file))
    if hit and hit[0] == key:
        return hit[1], hit[2], hit[3]
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        domains, ts, feeds = data.get("domains", {}), data.get("ts", ""), data.get("feeds", {})
    except Exception:
        return {}, "", {}
    _loaded[str(cache_file)] = (key, domains, ts, feeds)
    return domains, ts, feeds


def load(cache_file: Path) -> tuple[dict[str, str], str]:
    """Return ``({domain: source}, last_updated_iso)`` from the local cache."""
    domains, ts, _ = _read(cache_file)
    return domains, ts


def feed_status(cache_file: Path) -> dict[str, dict]:
    """Per-feed result of the last refresh: ``{name: {ok, count, ts[, error]}}``."""
    return _read(cache_file)[2]
