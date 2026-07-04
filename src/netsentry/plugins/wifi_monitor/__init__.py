"""wifi_monitor — passive 802.11 attack detection off a monitor-mode adapter.

Uses a dedicated USB Wi-Fi adapter (e.g. RTL8821AU as ``wlan1``) put into
monitor mode to watch management frames and flag two classic attacks:

* **NS-WIFI-001 deauth/disassoc flood** — someone spraying deauthentication
  frames to kick your devices off Wi-Fi (jamming, or a prelude to an evil-twin
  / handshake-capture attack);
* **NS-WIFI-002 rogue AP / evil-twin** — one of *your* SSIDs being broadcast by
  an access point whose BSSID isn't yours.

The radio + capture live here; the detection is pure (``detect.py``) and the
findings are handed to ``threat_detector`` so they show up in the dashboard,
reports, and one-click explainers like every other NS-… finding.
"""

from __future__ import annotations

import subprocess  # nosec B404 - fixed argv, no shell
import threading
from collections import Counter
from pathlib import Path

from ...core.plugin import Plugin
from . import detect


class WifiMonitorPlugin(Plugin):
    COMMANDS = [
        {"command": "wifi", "description": "📡 WiFi monitor status"},
    ]

    def on_load(self) -> None:
        self._iface = str(self.cfg.get("interface", "wlan1"))
        self._protect = [str(s) for s in (self.cfg.get("protect_ssids", []) or [])]
        self._allow_bssids = {
            b.lower() for b in (self.cfg.get("allow_bssids", []) or [])
        }
        self._channels = [int(c) for c in (self.cfg.get("channels", [1, 6, 11]) or [1, 6, 11])]
        self._hop_seconds = max(3, int(self.cfg.get("hop_seconds", 8)))
        self._deauth_threshold = int(self.cfg.get("deauth_threshold", 20))
        # Default: run iw/ip/tcpdump directly, relying on the service's
        # AmbientCapabilities (CAP_NET_ADMIN + CAP_NET_RAW). The systemd unit
        # sets NoNewPrivileges, so sudo can't escalate anyway.
        self._sudo = bool(self.cfg.get("use_sudo", False))
        self._state_file = Path(self.ctx.state_dir) / "wifi_baseline.json"

        self._stop = threading.Event()
        self._status = "starting"
        self._last_seen: dict[str, int] = {}
        # The loader only instantiates this plugin when it's enabled, so start
        # monitoring straight away (the adapter is dedicated to this).
        self._thread: threading.Thread | None = threading.Thread(
            target=self._loop, name="wifi_monitor", daemon=True)
        self._thread.start()

    def on_unload(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._iface_down()

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/wifi":
            return
        base = detect.load_baseline(self._state_file)
        lines = [
            "📡 WiFi monitor",
            f"  interface: {self._iface}  ·  status: {self._status}",
            f"  protecting SSIDs: {', '.join(self._protect) or '(none)'}",
            f"  APs seen last cycle: {len(self._last_seen)}",
            f"  baselined SSIDs: {', '.join(sorted(base)) or '(learning)'}",
        ]
        if hasattr(self.notifier, "send_to"):
            self.notifier.send_to(chat_id, "\n".join(lines))
        else:
            self.notifier.send("\n".join(lines))

    # ─── radio ──────────────────────────────────────────────────

    def _sx(self, *args: str) -> tuple[int, str]:
        cmd = (["sudo", "-n", *args] if self._sudo else list(args))
        try:
            p = subprocess.run(  # nosec B603 - fixed argv, no shell
                cmd, capture_output=True, text=True, timeout=15)
            return p.returncode, (p.stderr or "")
        except (subprocess.SubprocessError, OSError) as e:
            return 1, str(e)

    def _iface_up_monitor(self) -> bool:
        self._sx("rfkill", "unblock", "all")
        self._sx("ip", "link", "set", self._iface, "down")
        rc, err = self._sx("iw", "dev", self._iface, "set", "type", "monitor")
        if rc != 0:
            self.log.warning("wifi_monitor: monitor mode failed on %s: %s", self._iface, err)
            return False
        rc, err = self._sx("ip", "link", "set", self._iface, "up")
        if rc != 0:
            self.log.warning("wifi_monitor: could not bring %s up: %s", self._iface, err)
            return False
        return True

    def _iface_down(self) -> None:
        self._sx("ip", "link", "set", self._iface, "down")
        self._sx("iw", "dev", self._iface, "set", "type", "managed")

    def _set_channel(self, ch: int) -> None:
        self._sx("iw", "dev", self._iface, "set", "channel", str(ch))

    def _capture(self, seconds: int) -> str:
        cmd = (["sudo", "-n"] if self._sudo else []) + [
            "tcpdump", "-i", self._iface, "-e", "-s", "256", "-nn", "-l",
            "type", "mgt",
        ]
        try:
            p = subprocess.run(  # nosec B603 - fixed argv, no shell
                cmd, capture_output=True, text=True, timeout=seconds)
            return p.stdout or ""
        except subprocess.TimeoutExpired as e:
            return e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        except (subprocess.SubprocessError, OSError) as exc:
            self.log.warning("wifi_monitor: capture failed: %s", exc)
            return ""

    # ─── loop ───────────────────────────────────────────────────

    def _loop(self) -> None:
        if not self._iface_up_monitor():
            self._status = "monitor-mode unavailable"
            return
        self._status = "monitoring"
        self.log.info("wifi_monitor: monitoring on %s (protect: %s)",
                      self._iface, ", ".join(self._protect) or "-")
        ci = 0
        while not self._stop.is_set():
            ch = self._channels[ci % len(self._channels)]
            ci += 1
            self._set_channel(ch)
            text = self._capture(self._hop_seconds)
            try:
                self._analyse(text)
            except Exception:
                self.log.exception("wifi_monitor: analyse failed")
            self._stop.wait(0.2)

    def _analyse(self, text: str) -> None:
        ssid_bssids, deauths = detect.parse_capture(text)
        self._last_seen = dict(Counter(
            b for bs in ssid_bssids.values() for b in bs))

        baseline = detect.load_baseline(self._state_file)
        # Rogue-AP: only our protected SSIDs, vs the learned baseline.
        rogue = detect.rogue_ap_findings(
            ssid_bssids, baseline, self._protect, self._allow_bssids)
        # Learn/extend the baseline for protected SSIDs we now trust.
        baseline = detect.learn_baseline(ssid_bssids, baseline, self._protect)
        detect.save_baseline(self._state_file, baseline)

        deauth = detect.deauth_flood_findings(deauths, threshold=self._deauth_threshold)

        det = self._threat()
        for f in (*rogue, *deauth):
            if det is not None:
                det.record_finding(f.kind, f.subject, f.detail, immediate=True)
            else:
                self.log.warning("wifi_monitor finding (no threat_detector): %s %s",
                                 f.kind, f.subject)

    def _threat(self):
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(getattr(p, "ctx", None), "name", "") == "threat_detector":
                return p
        return None
