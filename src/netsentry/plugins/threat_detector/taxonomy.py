"""threat_detector · the finding taxonomy (NS-XXX-NNN).

One table describes every kind of finding: its permanent id, label, severity,
what it means, what usually causes a false alarm and what to do about it.
Detectors, reports, the dashboard and the explainer pages all read it.
"""

from __future__ import annotations

# Single source of truth for every finding type = the NetSentry taxonomy.
# Each entry carries a STABLE id (NS-XXX-NNN, cite it like a CVE), label,
# severity, detection confidence, a plain-language meaning ("means"), the
# common false-positive causes ("fp" — the anxiety-killer), what to do
# ("action"), a MITRE ATT&CK technique, and any prerequisite. Order = display.
# IDs are permanent: never renumber, only append.
_SCANS: dict[str, dict] = {
    "known_malicious": {
        "id": "NS-MAL-001", "confidence": "high", "mitre": "T1071.004",
        "label": "Known-malicious domain", "severity": "attack", "default": True,
        "means": "A domain on a downloaded malware/C2/phishing blocklist "
                 "(abuse.ch URLhaus/ThreatFox) — CONFIRMED bad, not a guess.",
        "fp": "Rare. A blocklist can occasionally flag a shared CDN/hoster. If "
              "it's a mainstream service, verify before panic; otherwise real.",
        "action": "Real threat. See who queried it (/domains <domain>), isolate/"
                  "kick that device, and scan it for malware.",
    },
    "dns_tunnel": {
        "id": "NS-DNS-001", "confidence": "medium", "mitre": "T1071.004",
        "label": "DNS tunnel / DGA", "severity": "attack", "default": True,
        "means": "A device made many random-looking sub-domain lookups under one "
                 "domain — a classic sign of data exfiltration or malware C2.",
        "fp": "The most common false alarm. Streaming/CDN/API providers (YouTube, "
              "Twitch, Netflix, Google APIs, Facebook) use many random sub-domains. "
              "If the parent is one of those, it's benign → Trust it.",
        "action": "If the device was streaming or using a known app (YouTube, "
                  "Twitch, Netflix…), it's a false alarm → tap /allow <domain>. "
                  "If you don't recognise it, check that device (/kick to cut it).",
    },
    "suspicious_tld": {
        "id": "NS-DNS-002", "confidence": "low", "mitre": "T1568",
        "label": "Suspicious TLD", "severity": "warning", "default": True,
        "means": "A lookup to a TLD frequently abused by malware/phishing "
                 "(.tk, .top, .zip, .mov…).",
        "fp": "Legit businesses do use .top/.xyz/.io/.zip. A single lookup is not "
              "proof — check the domain before acting.",
        "action": "Look up the domain. If you know it's fine → /allow <domain>. "
                  "If not, treat the device as suspect.",
    },
    "arp_conflict": {
        "id": "NS-ARP-001", "confidence": "medium", "mitre": "T1557.002",
        "label": "ARP conflict", "severity": "attack", "default": True,
        "means": "One IP is claimed by two MAC addresses — possible ARP spoofing "
                 "/ device impersonation on the LAN.",
        "fp": "A device with two interfaces (WiFi+Ethernet) on one IP, or fast "
              "DHCP-lease reuse, can trigger this. Confirm both MACs are "
              "unexpected before acting.",
        "action": "Serious. Identify both devices (/lan). If one is unexpected, "
                  "/kick or /block its MAC and power-cycle the network.",
    },
    "arp_change": {
        "id": "NS-ARP-002", "confidence": "medium", "mitre": "T1557",
        "label": "ARP / MAC change", "severity": "attack", "default": True,
        "means": "A device's IP↔MAC mapping changed since baseline — possible "
                 "man-in-the-middle, or simply a replaced device.",
        "fp": "Normal if you swapped/rebooted a device or it got a new NIC. Only "
              "worry if the IP is a gateway or a critical host.",
        "action": "If you just swapped/added a device, ignore. Otherwise "
                  "investigate that IP — possible MITM.",
    },
    "new_domain": {
        "id": "NS-DNS-003", "confidence": "info", "mitre": "-",
        "label": "New domain", "severity": "info", "default": False,
        "means": "A domain never seen on your network before. Normal while "
                 "browsing — OFF by default; turn on for an audit.",
        "fp": "Everything is 'new' the first time seen. Pure discovery — expect "
              "hundreds while browsing. Not a threat, excluded from the verdict.",
        "action": "Informational — a catalogue of what your devices fetch. Browse "
                  "with /domains, label with /note, trust noise with /allow.",
    },
    "rogue_dhcp": {
        "id": "NS-DHCP-001", "confidence": "high", "mitre": "T1557",
        "label": "Rogue DHCP server", "severity": "attack", "default": False,
        "means": "A DHCP server on your LAN other than the router — can hijack "
                 "all traffic.",
        "fp": "A second router/AP not in bridge mode, or a VM host, can answer "
              "DHCP. Confirm it isn't your own gear before unplugging.",
        "action": "Serious. Find and unplug the device at that MAC/IP — nothing "
                  "but your router should hand out addresses.",
        "needs": "router: /ip dhcp-server alert",
    },
    "port_scan": {
        "id": "NS-SCAN-001", "confidence": "medium", "mitre": "T1046",
        "label": "Port scan", "severity": "attack", "default": False,
        "means": "One source probed many hosts/ports — reconnaissance.",
        "fp": "Your own scans (this tool's exposure scan, a vuln scanner) and "
              "mDNS/UPnP discovery trigger it. Ignore if the source is you.",
        "action": "If it's a scanner you ran yourself, ignore. Otherwise the "
                  "device at that IP may be compromised — investigate / /kick.",
        "needs": "router: firewall drop-logging",
    },
    "config_drift": {
        "id": "NS-CFG-001", "confidence": "high", "mitre": "T1601",
        "label": "Router config change", "severity": "warning", "default": True,
        "means": "The router's configuration changed since the last check — a "
                 "new firewall rule, user, port-forward, or service. If it "
                 "wasn't you, the router may have been tampered with.",
        "fp": "Fires on ANY change you make yourself — a firmware update or you "
              "adding a rule. If it was you, it's fine; the new state becomes the "
              "baseline automatically.",
        "action": "Did you (or an update) change the router? If yes, ignore — "
                  "the new state becomes the baseline. If not, log in and review "
                  "the changed sections, then /backup.",
        "needs": "router: /export (read)",
    },
    "exposure": {
        "id": "NS-EXP-001", "confidence": "high", "mitre": "T1046",
        "label": "New open port", "severity": "warning", "default": False,
        "means": "A device on your LAN started listening on a TCP port it "
                 "wasn't before (e.g. an IoT gadget opened telnet after an "
                 "update) — new attack surface.",
        "fp": "A device you just installed or updated may legitimately open a new "
              "port. Check whether the change was expected for that host.",
        "action": "If you just installed/changed that device, ignore. Otherwise "
                  "investigate why it's exposing a service — it may be "
                  "compromised or misconfigured.",
        "needs": "Pi: nmap installed",
    },
    "weak_service": {
        "id": "NS-EXP-002", "confidence": "high", "mitre": "T1210",
        "label": "Weak / default-cred service", "severity": "attack", "default": False,
        "means": "A device exposes a plaintext admin service (telnet, ftp, "
                 "rlogin, VNC, RDP) or a web panel still on its DEFAULT "
                 "PASSWORD — an easy way in for anyone on the network.",
        "fp": "A device you intentionally run with telnet/VNC on a trusted LAN "
              "may be expected. The default-credential check only fires when a "
              "page actually leaks its creds (admin/admin, etc.) — a login page "
              "that merely reminds you to change the default password (Huawei "
              "and many ISP routers do) is NOT flagged.",
        "action": "Disable the plaintext service or put it behind the firewall; "
                  "for a default password, log in and change it immediately.",
        "needs": "Pi: nmap installed",
    },
    "deauth_flood": {
        "id": "NS-WIFI-001", "confidence": "high", "mitre": "T1498",
        "label": "WiFi deauth attack", "severity": "attack", "default": True,
        "means": "A burst of 802.11 deauthentication/disassociation frames aimed "
                 "at YOUR AP is kicking devices off your WiFi — jamming, or the "
                 "setup for an evil-twin / handshake-capture attack.",
        "fp": "Now only counts deauths whose BSSID is your own AP (matched by "
              "vendor), so a neighbour's deauth noise on the same channel is "
              "filtered out — a flood reported here is very likely real.",
        "action": "The real fix is 802.11w / PMF: switch your AP to WPA3 (or "
                  "WPA2/WPA3 mixed) — protected devices then IGNORE spoofed "
                  "deauths and the attack simply stops working. Blocking the "
                  "source MAC does NOT help (it's spoofed and over-the-air, not "
                  "on your network). Use the reported signal to locate the source.",
        "needs": "monitor-mode WiFi adapter",
    },
    "rogue_ap": {
        "id": "NS-WIFI-002", "confidence": "medium", "mitre": "T1557.004",
        "label": "Rogue AP / evil-twin", "severity": "attack", "default": True,
        "means": "One of YOUR network names (SSID) is being broadcast by an "
                 "access point that isn't yours — an evil-twin trying to lure "
                 "your devices into connecting to it.",
        "fp": "A mesh node / second AP of yours from a different vendor could "
              "trip this. If it's your gear, add its BSSID to allow_bssids.",
        "action": "Don't connect to WiFi until resolved. Locate the flagged "
                  "BSSID, and make sure your devices only trust your real AP. "
                  "WPA3 / 802.11w helps here too.",
        "needs": "monitor-mode WiFi adapter",
    },
    "deauth_nearby": {
        "id": "NS-WIFI-003", "confidence": "high", "mitre": "T1498",
        "label": "Deauth nearby — not your network", "severity": "info",
        "default": True,
        "means": "Deauthentication/disassociation frames were seen over the air, "
                 "but they target another access point — NOT one of yours. "
                 "Someone nearby (usually a neighbour's router) is generating "
                 "them; your devices are not the target.",
        "fp": "This is the calm counterpart to NS-WIFI-001: deauth frames whose "
              "BSSID isn't your AP surface here as info instead of raising an "
              "attack alert, so you're told plainly it wasn't against you.",
        "action": "Nothing to do — your Wi-Fi is not being attacked. This is "
                  "shown only so you know the deauth activity was not aimed at "
                  "your devices.",
        "needs": "monitor-mode WiFi adapter",
    },
}

# Reverse index: NS id -> kind. Built once; ids are unique and permanent.
_ID_TO_KIND: dict[str, str] = {v["id"]: k for k, v in _SCANS.items()}

_SEV_ICON = {"attack": "🚨", "warning": "⚠️", "info": "ℹ️"}


def _label(kind: str) -> str:
    return _SCANS.get(kind, {}).get("label", kind)
